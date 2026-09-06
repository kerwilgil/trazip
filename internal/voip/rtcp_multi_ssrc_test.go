package voip

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"trazip/internal/protocol/rtcp"
	"trazip/internal/protocol/rtp"
)

// --- raw RTCP wire builders (RFC 3550 §6.4), test-only ---
//
// internal/protocol/rtcp only parses; nothing in production code needs to
// build RTCP bytes, so these exist solely to construct the exact wire format
// a real endpoint sends, decoded through the real rtcp.ParseCompound rather
// than hand-built rtcp.Packet structs — the same fixture-building convention
// writeCallPCAP already uses for SIP.

func reportBlockBytes(ssrc uint32, fractionLost8 byte, cumulativeLost int32, highestSeq, jitterTicks, lsr, dlsr uint32) []byte {
	b := make([]byte, 24)
	binary.BigEndian.PutUint32(b[0:4], ssrc)
	b[4] = fractionLost8
	b[5], b[6], b[7] = byte(cumulativeLost>>16), byte(cumulativeLost>>8), byte(cumulativeLost)
	binary.BigEndian.PutUint32(b[8:12], highestSeq)
	binary.BigEndian.PutUint32(b[12:16], jitterTicks)
	binary.BigEndian.PutUint32(b[16:20], lsr)
	binary.BigEndian.PutUint32(b[20:24], dlsr)
	return b
}

// srBytes builds a Sender Report for senderSSRC's own outgoing stream, with
// the given blocks (reception reports about OTHER SSRCs it's listening to —
// none, here, since these fixtures give each sender a one-way stream).
func srBytes(senderSSRC uint32, ntpSec, ntpFrac, rtpTS, packetCount, octetCount uint32, blocks ...[]byte) []byte {
	fixed := make([]byte, 24)
	binary.BigEndian.PutUint32(fixed[0:4], senderSSRC)
	binary.BigEndian.PutUint32(fixed[4:8], ntpSec)
	binary.BigEndian.PutUint32(fixed[8:12], ntpFrac)
	binary.BigEndian.PutUint32(fixed[12:16], rtpTS)
	binary.BigEndian.PutUint32(fixed[16:20], packetCount)
	binary.BigEndian.PutUint32(fixed[20:24], octetCount)
	body := fixed
	for _, blk := range blocks {
		body = append(body, blk...)
	}
	header := make([]byte, 4)
	header[0] = 0x80 | byte(len(blocks))
	header[1] = byte(rtcp.TypeSR)
	binary.BigEndian.PutUint16(header[2:4], uint16((4+len(body))/4-1))
	return append(header, body...)
}

// rrBytes builds a Receiver Report from reporterSSRC — a party that is not
// itself the subject of any of these blocks, only reporting on what it
// received of OTHER SSRCs' streams.
func rrBytes(reporterSSRC uint32, blocks ...[]byte) []byte {
	fixed := make([]byte, 4)
	binary.BigEndian.PutUint32(fixed, reporterSSRC)
	body := fixed
	for _, blk := range blocks {
		body = append(body, blk...)
	}
	header := make([]byte, 4)
	header[0] = 0x80 | byte(len(blocks))
	header[1] = byte(rtcp.TypeRR)
	binary.BigEndian.PutUint16(header[2:4], uint16((4+len(body))/4-1))
	return append(header, body...)
}

// ntpOf mirrors ntpShortFromTime's own full-precision fraction encoding (not
// a truncated stand-in) so a whole-second offset between two times produces
// an exact, predictable NTP-short delta — the same property
// TestNTPShortRoundTripsWholeSeconds already relies on.
func ntpOf(t time.Time) (sec, frac uint32) {
	sec = uint32(t.Unix() + ntpUnixEpochDeltaSec)
	frac = uint32((uint64(t.Nanosecond()) << 32) / 1_000_000_000)
	return sec, frac
}

func parseOneRTCP(t *testing.T, raw []byte) rtcp.Packet {
	t.Helper()
	pkts, err := rtcp.ParseCompound(raw)
	if err != nil || len(pkts) != 1 {
		t.Fatalf("ParseCompound: %v (%d packets)", err, len(pkts))
	}
	return pkts[0]
}

func streamBySSRC(t *testing.T, streams []StreamInfo, ssrc uint32) StreamInfo {
	t.Helper()
	for _, s := range streams {
		if s.SSRC == ssrc {
			return s
		}
	}
	t.Fatalf("no stream found with SSRC %#x among %d streams", ssrc, len(streams))
	return StreamInfo{}
}

// buildTwoRTPStreams gives attachStreams two independent RTP legs, same IP
// pair, different ports and SSRCs — mirroring what the RTP pass of Analyze
// would have built for the scenario this file tests.
//
// Stream 2 is given a genuine LOCAL RTP loss (one dropped sequence out of
// five, 20%) that stream 1 doesn't have, so worstStream() — which scores by
// each stream's own locally-observed RTP quality, not by what RTCP reports
// about it — deterministically picks stream 2 as "the worse direction". Tying
// them at 0% loss each would leave the pick to Go's randomized map iteration
// order, which is exactly the kind of test flakiness that would mask a real
// mixup instead of catching one.
func buildTwoRTPStreams(t *testing.T, ssrc1, ssrc2 uint32, ipA, ipB string) (map[string]*rtp.Stream, map[string]*streamCtx) {
	t.Helper()
	mk := func(ssrc uint32, seqs []uint16) *rtp.Stream {
		st := rtp.NewStream(ssrc, 8000)
		for _, seq := range seqs {
			h := rtp.Header{Version: 2, SeqNum: seq, Timestamp: uint32(seq) * 160, SSRC: ssrc}
			st.Add(rtp.Sample{Header: h, Arrival: time.Now().Add(time.Duration(seq) * 20 * time.Millisecond)})
		}
		return st
	}
	streams := map[string]*rtp.Stream{
		"s1": mk(ssrc1, []uint16{0, 1, 2, 3, 4}), // clean, 0% loss
		"s2": mk(ssrc2, []uint16{0, 1, 3, 4}),    // seq 2 missing: 1/5 = 20% loss
	}
	meta := map[string]*streamCtx{
		"s1": {src: ipA + ":40000", dst: ipB + ":40002", payloadType: 0},
		"s2": {src: ipA + ":40010", dst: ipB + ":40012", payloadType: 0},
	}
	return streams, meta
}

// TestAttachStreamsMultiSSRCSameIPPair is the gate's central regression: two
// RTP streams (SSRC1, SSRC2) between the exact same two IP addresses, whose
// RTCP is deliberately entangled the way a real capture produces it —
//   - each stream's own sender emits its own SR, so PacketCount/OctetCount
//     are per-SSRC facts that must never cross over;
//   - the far end reports on BOTH incoming streams in ONE compound RR
//     datagram carrying two Report Blocks, one per SSRC — the case that
//     defeats grouping by IP pair alone, since both blocks share not just
//     the IP pair but the exact same packet.
//
// Stream 1 is given genuinely different loss/jitter/counts than Stream 2,
// and their RTT-relevant SR timestamps/DLSR are offset by a distinctive
// amount, so any cross-SSRC mixup produces a visibly wrong number rather
// than an accidental match.
//
// Drives attachStreams directly (not the full Analyze — these fixtures
// carry no SIP, so the streams would never attach to a Call, the same
// limitation every RTP/RTCP-only test in this package works around, see
// TestAttachStreamsExposesRTCPReports above) with rtcp.Packet values decoded
// through the real rtcp.ParseCompound rather than hand-built structs, so
// ParseCompound → rtcpObservation → attachStreams → StreamInfo is genuinely
// exercised end to end, per item 3's explicit ask not to fix this only in
// the view.
func TestAttachStreamsMultiSSRCSameIPPair(t *testing.T) {
	const (
		ssrc1      = 0x11111111
		ssrc2      = 0x22222222
		reporterID = 0xB0000001 // B's own reporter identity — not an RTP SSRC in this fixture
		ipA, ipB   = "198.51.100.10", "198.51.100.20"
	)
	// Whole-second offsets from a zero-nanosecond base keep the NTP-short
	// arithmetic exact (same property TestNTPShortRoundTripsWholeSeconds
	// verifies): SR1 at t=0s, SR2 at t=1s (offset on purpose, so reusing the
	// wrong stream's SR would shift the result by a clean, obvious 1s), the
	// shared RR observed at t=5s. RTT1 = (5-0)-2 = 3000ms; RTT2 = (5-1)-3 =
	// 1000ms — both positive, both distinct, both hand-verifiable.
	base := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	sr1At, sr2At, rrAt := 0*time.Second, 1*time.Second, 5*time.Second
	sr1Sec, sr1Frac := ntpOf(base.Add(sr1At))
	sr2Sec, sr2Frac := ntpOf(base.Add(sr2At))
	lsr1, lsr2 := ntpShort(sr1Sec, sr1Frac), ntpShort(sr2Sec, sr2Frac)

	sr1 := parseOneRTCP(t, srBytes(ssrc1, sr1Sec, sr1Frac, 800, 1000, 160000))
	sr2 := parseOneRTCP(t, srBytes(ssrc2, sr2Sec, sr2Frac, 800, 9000, 1440000))
	block1 := reportBlockBytes(ssrc1, 3, 5, 1000, 80, lsr1, 2*65536)    // ~1.2% loss, DLSR=2s
	block2 := reportBlockBytes(ssrc2, 20, 50, 9000, 800, lsr2, 3*65536) // ~7.8% loss, DLSR=3s
	rr := parseOneRTCP(t, rrBytes(reporterID, block1, block2))

	rtcpReports := map[string][]rtcpObservation{
		ipA + "-" + ipB: {
			{Packet: sr1, Arrival: base.Add(sr1At)},
			{Packet: sr2, Arrival: base.Add(sr2At)},
		},
		ipB + "-" + ipA: {
			{Packet: rr, Arrival: base.Add(rrAt)},
		},
	}

	rtpStreams, meta := buildTwoRTPStreams(t, ssrc1, ssrc2, ipA, ipB)
	calls := map[string]*Call{"call": {CallID: "call"}}
	addrToCall := map[string]string{ipB + ":40002": "call", ipB + ":40012": "call"}
	attachStreams(calls, addrToCall, nil, nil, rtpStreams, meta, rtcpReports, nil)

	got := calls["call"].Streams
	if len(got) != 2 {
		t.Fatalf("expected 2 streams attached, got %d: %+v", len(got), got)
	}
	s1 := streamBySSRC(t, got, ssrc1)
	s2 := streamBySSRC(t, got, ssrc2)

	// --- Stream 1 must show ONLY Stream 1's numbers ---
	if s1.RTCP == nil || s1.RTCP.Receiver == nil {
		t.Fatal("stream 1: RTCP.Receiver is nil")
	}
	r1, snd1 := s1.RTCP.Receiver, s1.RTCP.Sender
	if want := float64(3) / 256 * 100; r1.FractionLostPct < want-0.01 || r1.FractionLostPct > want+0.01 {
		t.Errorf("stream 1: FractionLostPct = %v, want ~%v (its own block, not stream 2's)", r1.FractionLostPct, want)
	}
	if r1.CumulativeLost != 5 {
		t.Errorf("stream 1: CumulativeLost = %d, want 5", r1.CumulativeLost)
	}
	if r1.HighestSeq != 1000 {
		t.Errorf("stream 1: HighestSeq = %d, want 1000", r1.HighestSeq)
	}
	if r1.JitterTicks != 80 {
		t.Errorf("stream 1: JitterTicks = %d, want 80 (stream 2's is 800 — a mixup would be obvious)", r1.JitterTicks)
	}
	if snd1 == nil || snd1.PacketCount != 1000 || snd1.OctetCount != 160000 {
		t.Errorf("stream 1: Sender.PacketCount/OctetCount = %+v, want 1000/160000 (stream 2's SR values are 9000/1440000)", snd1)
	}
	if s1.RTCP.EstimatedRTTMs == nil {
		t.Error("stream 1: expected a computable RTT (its own SR/RR pair is valid)")
	} else if *s1.RTCP.EstimatedRTTMs < 2999 || *s1.RTCP.EstimatedRTTMs > 3001 {
		// (rrAt 5s - sr1At 0s) - DLSR1 2s = 3000ms, exactly (whole-second
		// NTP-short arithmetic, no rounding slack needed).
		t.Errorf("stream 1: EstimatedRTTMs = %v, want 3000 (its own SR/DLSR, not stream 2's)", *s1.RTCP.EstimatedRTTMs)
	}

	// --- Stream 2 must show ONLY Stream 2's numbers ---
	if s2.RTCP == nil || s2.RTCP.Receiver == nil {
		t.Fatal("stream 2: RTCP.Receiver is nil")
	}
	r2, snd2 := s2.RTCP.Receiver, s2.RTCP.Sender
	if want := float64(20) / 256 * 100; r2.FractionLostPct < want-0.01 || r2.FractionLostPct > want+0.01 {
		t.Errorf("stream 2: FractionLostPct = %v, want ~%v (its own block, not stream 1's)", r2.FractionLostPct, want)
	}
	if r2.CumulativeLost != 50 {
		t.Errorf("stream 2: CumulativeLost = %d, want 50", r2.CumulativeLost)
	}
	if r2.HighestSeq != 9000 {
		t.Errorf("stream 2: HighestSeq = %d, want 9000", r2.HighestSeq)
	}
	if r2.JitterTicks != 800 {
		t.Errorf("stream 2: JitterTicks = %d, want 800", r2.JitterTicks)
	}
	if snd2 == nil || snd2.PacketCount != 9000 || snd2.OctetCount != 1440000 {
		t.Errorf("stream 2: Sender.PacketCount/OctetCount = %+v, want 9000/1440000", snd2)
	}
	if s2.RTCP.EstimatedRTTMs == nil {
		t.Error("stream 2: expected a computable RTT")
	} else if *s2.RTCP.EstimatedRTTMs < 999 || *s2.RTCP.EstimatedRTTMs > 1001 {
		// (rrAt 5s - sr2At 1s) - DLSR2 3s = 1000ms, exactly.
		t.Errorf("stream 2: EstimatedRTTMs = %v, want 1000 (its own SR/DLSR, not stream 1's)", *s2.RTCP.EstimatedRTTMs)
	}

	if s1.RTCP.EstimatedRTTMs != nil && s2.RTCP.EstimatedRTTMs != nil && *s1.RTCP.EstimatedRTTMs == *s2.RTCP.EstimatedRTTMs {
		t.Error("stream 1 and stream 2 produced the identical RTT — looks like they shared an SR/DLSR pair that should have stayed separate")
	}

	// --- Raw RTCPReports must not leak the other stream's data either —
	// item 3 explicitly asks that this not be fixed only in the view. ---
	assertNoForeignSSRC := func(name string, reports []rtcp.Packet, ownSSRC, foreignSSRC uint32) {
		for _, p := range reports {
			for _, blk := range p.Reports {
				if blk.SSRC == foreignSSRC {
					t.Errorf("%s's filtered RTCPReports contains a block for the OTHER stream's SSRC %#x: %+v", name, foreignSSRC, blk)
				}
				if blk.SSRC != 0 && blk.SSRC != ownSSRC {
					t.Errorf("%s's filtered RTCPReports contains a block for an unrelated SSRC %#x: %+v", name, blk.SSRC, blk)
				}
			}
			if p.Type == rtcp.TypeSR && p.SSRC == foreignSSRC {
				t.Errorf("%s's filtered RTCPReports contains the OTHER stream's own SR: %+v", name, p)
			}
		}
	}
	assertNoForeignSSRC("stream 1", s1.RTCPReports, ssrc1, ssrc2)
	assertNoForeignSSRC("stream 2", s2.RTCPReports, ssrc2, ssrc1)

	// --- Diagnose() must cite the worse stream's own numbers, not a blend ---
	call := *calls["call"]
	call.Established = true
	d := Diagnose(call)
	foundReceiverLoss := false
	for _, e := range d.Evidence {
		if e.Type != "rtcp_receiver_loss" {
			continue
		}
		foundReceiverLoss = true
		// worstStream() picks stream 2 (worse MOS/loss from its RTP stats),
		// so the single rtcp_receiver_loss entry must cite stream 2's ~7.8%,
		// never stream 1's ~1.2%.
		if !strings.Contains(e.Value, "7.") {
			t.Errorf("Diagnose rtcp_receiver_loss = %q, want it to reflect stream 2's own ~7.8%%, not a blend or stream 1's ~1.2%%", e.Value)
		}
	}
	if !foundReceiverLoss {
		t.Error("expected an rtcp_receiver_loss evidence entry")
	}
}

// --- item 3 (narrower unit coverage): filterObservationsForSSRC itself ---

func TestFilterObservationsForSSRCSplitsASharedCompoundPacket(t *testing.T) {
	const ssrc1, ssrc2 = uint32(0x11111111), uint32(0x22222222)
	block1 := reportBlockBytes(ssrc1, 3, 5, 1000, 80, 0, 0)
	block2 := reportBlockBytes(ssrc2, 20, 50, 9000, 800, 0, 0)
	rr := parseOneRTCP(t, rrBytes(0xB0000001, block1, block2))
	obs := []rtcpObservation{{Packet: rr, Arrival: time.Now()}}

	for _, ssrc := range []uint32{ssrc1, ssrc2} {
		filtered := filterObservationsForSSRC(obs, ssrc)
		if len(filtered) != 1 {
			t.Fatalf("ssrc %#x: filtered to %d observations, want 1", ssrc, len(filtered))
		}
		if len(filtered[0].Packet.Reports) != 1 {
			t.Fatalf("ssrc %#x: filtered packet has %d report blocks, want exactly 1", ssrc, len(filtered[0].Packet.Reports))
		}
		if filtered[0].Packet.Reports[0].SSRC != ssrc {
			t.Errorf("ssrc %#x: filtered block SSRC = %#x, want %#x", ssrc, filtered[0].Packet.Reports[0].SSRC, ssrc)
		}
	}
}

func TestFilterObservationsForSSRCDropsAForeignSR(t *testing.T) {
	const ssrc1, ssrc2 = uint32(0x11111111), uint32(0x22222222)
	sr2 := parseOneRTCP(t, srBytes(ssrc2, 0, 0, 0, 9000, 1440000))
	obs := []rtcpObservation{{Packet: sr2, Arrival: time.Now()}}

	filtered := filterObservationsForSSRC(obs, ssrc1)
	if len(filtered) != 0 {
		t.Fatalf("an SR entirely about a different SSRC must be dropped, got %+v", filtered)
	}
}

func TestFilterObservationsForSSRCKeepsOwnSRWithoutForeignBlocks(t *testing.T) {
	const ssrc1, ssrc2 = uint32(0x11111111), uint32(0x22222222)
	block2 := reportBlockBytes(ssrc2, 20, 50, 9000, 800, 0, 0)
	// A compound SR from ssrc1's own sender that (unusually) also carries a
	// report block about ssrc2 — ssrc1's SR fields must survive, ssrc2's
	// block must not.
	sr1 := parseOneRTCP(t, srBytes(ssrc1, 111, 222, 800, 1000, 160000, block2))
	obs := []rtcpObservation{{Packet: sr1, Arrival: time.Now()}}

	filtered := filterObservationsForSSRC(obs, ssrc1)
	if len(filtered) != 1 {
		t.Fatalf("got %d observations, want 1", len(filtered))
	}
	p := filtered[0].Packet
	if p.Type != rtcp.TypeSR || p.SSRC != ssrc1 || p.PacketCount != 1000 || p.OctetCount != 160000 {
		t.Errorf("own SR fields were not preserved: %+v", p)
	}
	for _, blk := range p.Reports {
		if blk.SSRC != ssrc1 {
			t.Errorf("filtered SR still carries a foreign report block: %+v", blk)
		}
	}
}
