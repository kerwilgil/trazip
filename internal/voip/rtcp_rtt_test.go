package voip

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"trazip/internal/model"
	"trazip/internal/protocol/rtcp"
)

// t0 is a fixed instant with no fractional seconds, so ntpShortFromTime's
// fraction component is exactly zero and the arithmetic below is exact
// integer math instead of something that needs a tolerance.
var t0 = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func TestNTPShortRoundTripsWholeSeconds(t *testing.T) {
	got := ntpShortFromTime(t0)
	want := ntpShort(uint32(t0.Unix()+ntpUnixEpochDeltaSec), 0)
	if got != want {
		t.Fatalf("ntpShortFromTime(t0) = %#x, want %#x", got, want)
	}
	plus3 := ntpShortFromTime(t0.Add(3 * time.Second))
	if plus3-got != 3*65536 {
		t.Fatalf("3s later - t0 = %d NTP-short units, want %d", plus3-got, 3*65536)
	}
}

// SR at t0 (NTP=ntp0), the peer's RR echoes LSR=ntp0 and DLSR=2s, and the RR
// itself arrives (per this capture's own timestamp) 3s after t0. Per RFC 3550
// §6.4.1, RTT = A - LSR - DLSR = (ntp0+3s) - ntp0 - 2s = 1s exactly.
func TestEstimateRTTValidPair(t *testing.T) {
	const ssrc = 0xAABBCCDD
	ntp0 := ntpShortFromTime(t0)
	sr := rtcp.Packet{Type: rtcp.TypeSR, SSRC: ssrc, NTPSeconds: uint32(t0.Unix() + ntpUnixEpochDeltaSec), NTPFraction: 0}
	rr := rtcp.Packet{Type: rtcp.TypeRR, SSRC: 0x11223344, Reports: []rtcp.ReportBlock{
		{SSRC: ssrc, LSR: ntp0, DLSR: 2 * 65536},
	}}
	obs := []rtcpObservation{
		{Packet: sr, Arrival: t0},
		{Packet: rr, Arrival: t0.Add(3 * time.Second)},
	}
	rtt, reason := estimateRTT(obs, ssrc)
	if rtt == nil {
		t.Fatalf("expected a computed RTT, got none: reason=%q", reason)
	}
	if *rtt < 999.5 || *rtt > 1000.5 {
		t.Errorf("RTT = %v ms, want ~1000", *rtt)
	}
	if reason != "" {
		t.Errorf("reason should be empty on success, got %q", reason)
	}
}

func TestEstimateRTTNoMatchingSR(t *testing.T) {
	const ssrc = 0xAABBCCDD
	rr := rtcp.Packet{Type: rtcp.TypeRR, SSRC: 0x11223344, Reports: []rtcp.ReportBlock{
		{SSRC: ssrc, LSR: 0x12345678, DLSR: 65536},
	}}
	obs := []rtcpObservation{{Packet: rr, Arrival: t0}}
	rtt, reason := estimateRTT(obs, ssrc)
	if rtt != nil {
		t.Fatalf("RTT should be unavailable without a matching SR, got %v", *rtt)
	}
	if reason == "" {
		t.Error("an unavailable RTT must always carry a reason")
	}
}

func TestEstimateRTTZeroLSRIsSkipped(t *testing.T) {
	const ssrc = 0xAABBCCDD
	sr := rtcp.Packet{Type: rtcp.TypeSR, SSRC: ssrc, NTPSeconds: uint32(t0.Unix() + ntpUnixEpochDeltaSec)}
	rr := rtcp.Packet{Type: rtcp.TypeRR, Reports: []rtcp.ReportBlock{
		{SSRC: ssrc, LSR: 0, DLSR: 65536}, // LSR=0 means "this receiver never got an SR yet" (RFC 3550 §6.4.1)
	}}
	obs := []rtcpObservation{{Packet: sr, Arrival: t0}, {Packet: rr, Arrival: t0.Add(time.Second)}}
	rtt, reason := estimateRTT(obs, ssrc)
	if rtt != nil {
		t.Fatalf("LSR=0 must never produce a computed RTT, got %v", *rtt)
	}
	if reason == "" {
		t.Error("expected a reason for the unavailable RTT")
	}
}

// Gate v0.7.3 (independent audit, third gate, item 8): RFC 3550 defines no
// sentinel value for DLSR the way it does for LSR (LSR==0 means "no SR
// received yet") — an extreme DLSR like 0xFFFFFFFF (~18.2h) isn't rejected
// because "0xFFFFFFFF is invalid", it's rejected because subtracting it from
// a normal-sized A-LSR difference drives the result deeply negative, which
// the generic out-of-range bounds check (rtt<=0 || rtt>maxSaneRTTNTP) already
// catches on its own — no separate DLSR sentinel needed.
func TestEstimateRTTExtremeDLSRIsRejectedByBoundsNotBySentinel(t *testing.T) {
	const ssrc = 0xAABBCCDD
	ntp0 := ntpShortFromTime(t0)
	sr := rtcp.Packet{Type: rtcp.TypeSR, SSRC: ssrc, NTPSeconds: uint32(t0.Unix() + ntpUnixEpochDeltaSec)}
	rr := rtcp.Packet{Type: rtcp.TypeRR, Reports: []rtcp.ReportBlock{{SSRC: ssrc, LSR: ntp0, DLSR: 0xFFFFFFFF}}}
	obs := []rtcpObservation{{Packet: sr, Arrival: t0}, {Packet: rr, Arrival: t0.Add(time.Second)}}
	rtt, reason := estimateRTT(obs, ssrc)
	if rtt != nil {
		t.Fatalf("DLSR=0xFFFFFFFF (~18.2h) against a 1s real gap must not produce a computed RTT, got %v", *rtt)
	}
	if reason == "" {
		t.Error("expected a reason")
	}
}

// Gate v0.7.3 (independent audit, third gate, item 8): DLSR==0 is a real,
// valid value (the receiver generated its report immediately after getting
// the SR) — it must NOT be treated as a sentinel for "missing/invalid" the
// way an earlier version of this function did.
func TestEstimateRTTValidZeroDLSR(t *testing.T) {
	const ssrc = 0xAABBCCDD
	ntp0 := ntpShortFromTime(t0)
	sr := rtcp.Packet{Type: rtcp.TypeSR, SSRC: ssrc, NTPSeconds: uint32(t0.Unix() + ntpUnixEpochDeltaSec)}
	rr := rtcp.Packet{Type: rtcp.TypeRR, Reports: []rtcp.ReportBlock{{SSRC: ssrc, LSR: ntp0, DLSR: 0}}}
	obs := []rtcpObservation{{Packet: sr, Arrival: t0}, {Packet: rr, Arrival: t0.Add(time.Second)}}
	rtt, reason := estimateRTT(obs, ssrc)
	if rtt == nil {
		t.Fatalf("DLSR=0 with a valid LSR and observed SR must produce a real RTT, got none: reason=%q", reason)
	}
	// A - LSR - 0 = 1s exactly.
	if *rtt < 999 || *rtt > 1001 {
		t.Errorf("RTT = %v ms, want ~1000 (DLSR=0 contributes nothing)", *rtt)
	}
}

// Gate v0.7.3 (independent audit, third gate, item 9): a report block's LSR
// names whichever SR the RECEIVER last actually got — not necessarily the
// most recent SR this capture happened to see. SR2 observed between SR1 and
// the report block (e.g. it hadn't reached the receiver yet, or was lost)
// must not invalidate a report that correctly references the OLDER SR1.
func TestEstimateRTTReferencingAnOlderSRThanTheLatestOneSeen(t *testing.T) {
	const ssrc = 0xAABBCCDD
	ntp1 := ntpShortFromTime(t0)
	sr1 := rtcp.Packet{Type: rtcp.TypeSR, SSRC: ssrc, NTPSeconds: uint32(t0.Unix() + ntpUnixEpochDeltaSec)}
	t2 := t0.Add(2 * time.Second)
	sr2 := rtcp.Packet{Type: rtcp.TypeSR, SSRC: ssrc, NTPSeconds: uint32(t2.Unix() + ntpUnixEpochDeltaSec)}
	rr := rtcp.Packet{Type: rtcp.TypeRR, Reports: []rtcp.ReportBlock{
		{SSRC: ssrc, LSR: ntp1, DLSR: 65536}, // references SR1, not the more recent SR2; DLSR=1s
	}}
	obs := []rtcpObservation{
		{Packet: sr1, Arrival: t0},
		{Packet: sr2, Arrival: t2},
		{Packet: rr, Arrival: t0.Add(3 * time.Second)}, // observed after BOTH SRs
	}
	rtt, reason := estimateRTT(obs, ssrc)
	if rtt == nil {
		t.Fatalf("expected a computed RTT referencing the older SR1 (not just the latest SR2), got none: reason=%q", reason)
	}
	// A = t0+3s. RTT = A - LSR(SR1@t0) - DLSR(1s) = 3s - 0s - 1s = 2s = 2000ms.
	if *rtt < 1999 || *rtt > 2001 {
		t.Errorf("RTT = %v ms, want ~2000 (using SR1, not SR2)", *rtt)
	}
}

// secondsUntilNTPShortWrap returns how many whole seconds must be added to t
// so it lands exactly on a 16-bit NTP-short seconds rollover boundary (where
// ntpShortFromTime's upper 16 bits become 0x0000).
func secondsUntilNTPShortWrap(t time.Time) int64 {
	sec := uint32(t.Unix()+ntpUnixEpochDeltaSec) & 0xFFFF
	if sec == 0 {
		return 0
	}
	return int64(0x10000 - sec)
}

// Gate v0.7.3 (independent audit, item 6): the NTP-short seconds field is
// only 16 bits, wrapping every 65536s (~18.2h). A SR sent just before that
// wrap and a RR arriving a bit after it (per this capture's own clock,
// already past the wrap) must still produce the correct small positive RTT —
// a naive int64(A)-int64(LSR) would instead see A as a huge NEGATIVE
// difference from LSR's pre-wrap value and reject the whole result as
// "out of range" (TestEstimateRTTNeverReturnsZeroForBadData's failure mode),
// even though the true elapsed time is small. Runs the real, end-to-end
// estimateRTT — not just the ntpShortSub primitive — with a SR/RR pair
// straddling a real rollover boundary.
func TestEstimateRTTAcrossNTPShortSecondsRollover(t *testing.T) {
	const ssrc = 0xAABBCCDD
	wrapAt := t0.Add(time.Duration(secondsUntilNTPShortWrap(t0)) * time.Second)
	lsrTime := wrapAt.Add(-500 * time.Millisecond)    // 0.5s before the wrap
	arrivalTime := wrapAt.Add(500 * time.Millisecond) // 0.5s after the wrap
	const dlsrSeconds = 0.25

	lsr := ntpShortFromTime(lsrTime)
	// NTPFraction is the full 32-bit NTP fraction (not the NTP-short 16-bit
	// one) — 0.5s of a second is exactly 0x80000000 of 2^32, matching how
	// lsrTime was constructed (500ms before the wrap).
	sr := rtcp.Packet{
		Type: rtcp.TypeSR, SSRC: ssrc,
		NTPSeconds:  uint32(lsrTime.Unix() + ntpUnixEpochDeltaSec),
		NTPFraction: 0x80000000,
	}
	if got := ntpShort(sr.NTPSeconds, sr.NTPFraction); got != lsr {
		t.Fatalf("test setup: ntpShort(SR fields) = %#x, want %#x (ntpShortFromTime(lsrTime)) — SR fields don't encode lsrTime as intended", got, lsr)
	}

	rr := rtcp.Packet{Type: rtcp.TypeRR, Reports: []rtcp.ReportBlock{
		{SSRC: ssrc, LSR: lsr, DLSR: uint32(dlsrSeconds * 65536)},
	}}
	obs := []rtcpObservation{
		{Packet: sr, Arrival: lsrTime},
		{Packet: rr, Arrival: arrivalTime},
	}

	rtt, reason := estimateRTT(obs, ssrc)
	if rtt == nil {
		t.Fatalf("expected a computed RTT crossing the rollover, got none: reason=%q", reason)
	}
	// True elapsed real time lsrTime -> arrivalTime is exactly 1.0s
	// (0.5s to the wrap + 0.5s past it), minus 0.25s DLSR = 0.75s = 750ms.
	if *rtt < 749 || *rtt > 751 {
		t.Errorf("rollover-crossing RTT = %.2fms, want ~750ms", *rtt)
	}

	// Document exactly what this fix prevents: the same LSR/arrival pair
	// through the naive (pre-fix) plain-int64 subtraction comes out hugely
	// negative instead of ~750ms — confirming this scenario really does
	// cross the rollover, not just happens to still work either way.
	arrivalNtp := ntpShortFromTime(arrivalTime)
	naive := int64(arrivalNtp) - int64(lsr) - int64(dlsrSeconds*65536)
	if naive > 0 {
		t.Fatalf("test setup error: expected the naive (unfixed) computation to demonstrate the rollover bug (go negative), got %d — the scenario doesn't actually cross a rollover", naive)
	}
}

// A negative RTT (RR observed before the matching SR could plausibly have
// round-tripped) must degrade to unavailable, never to a fabricated 0ms.
func TestEstimateRTTNeverReturnsZeroForBadData(t *testing.T) {
	const ssrc = 0xAABBCCDD
	ntp0 := ntpShortFromTime(t0)
	sr := rtcp.Packet{Type: rtcp.TypeSR, SSRC: ssrc, NTPSeconds: uint32(t0.Unix() + ntpUnixEpochDeltaSec)}
	// DLSR claims 10s of remote delay, but the RR arrived only 1s after the SR
	// per this capture — A - LSR - DLSR goes negative.
	rr := rtcp.Packet{Type: rtcp.TypeRR, Reports: []rtcp.ReportBlock{{SSRC: ssrc, LSR: ntp0, DLSR: 10 * 65536}}}
	obs := []rtcpObservation{{Packet: sr, Arrival: t0}, {Packet: rr, Arrival: t0.Add(time.Second)}}
	rtt, reason := estimateRTT(obs, ssrc)
	if rtt != nil {
		t.Fatalf("out-of-range RTT must not be reported, got %v", *rtt)
	}
	if reason == "" {
		t.Error("expected a reason")
	}
}

// --- Gate v0.7.3, item 2: this value must never be presentable as an exact
// measurement, in the type, the JSON contract, or the Diagnose evidence it
// feeds. These tests exist specifically so a future refactor that quietly
// drops "Estimated" from a name, or restores model.ProvObserved, or bumps the
// confidence back up, fails loudly here instead of shipping. ---

// The struct field itself must carry the caveat in its name — grepping for
// "RTT" without any other context must still land on "Estimated".
func TestRTCPSummaryRTTFieldIsNamedEstimated(t *testing.T) {
	rt := reflect.TypeOf(RTCPSummary{})
	if _, ok := rt.FieldByName("EstimatedRTTMs"); !ok {
		t.Error(`RTCPSummary has no "EstimatedRTTMs" field — the estimated-not-measured caveat must live in the field name, not just a comment`)
	}
	if _, ok := rt.FieldByName("RTTMs"); ok {
		t.Error(`RTCPSummary still has a bare "RTTMs" field — that name alone reads as an exact measurement`)
	}
}

// The JSON contract Wails ships to the frontend must say "estimated" too —
// this is what a future frontend read of stream.rtcp.* actually sees, so the
// field's Go name alone isn't enough.
func TestRTCPSummaryRTTJSONTagSaysEstimated(t *testing.T) {
	field, ok := reflect.TypeOf(RTCPSummary{}).FieldByName("EstimatedRTTMs")
	if !ok {
		t.Fatal("EstimatedRTTMs field not found")
	}
	tag := field.Tag.Get("json")
	if !strings.Contains(strings.ToLower(tag), "estimated") {
		t.Errorf(`json tag = %q, want it to contain "estimated" — the wire contract must carry the caveat, not just the Go identifier`, tag)
	}
}

// Diagnose must never treat a computed RTT as directly observed fact, and its
// confidence must sit well below the evidence built from things TRAZIP
// actually counted itself (local RTP loss) or the peer stated outright over
// RTCP (remote loss) — both asserted here as a concrete ceiling, not just "is
// it lower than before".
func TestDiagnoseRTTEvidenceIsInferredWithLowConfidence(t *testing.T) {
	s := goodStream()
	rtt := 42.0
	s.RTCPSeen = true
	s.RTCP = &RTCPSummary{Receiver: &RTCPReceiverSummary{FractionLostPct: 0.5}, EstimatedRTTMs: &rtt}
	d := Diagnose(Call{Established: true, Streams: []StreamInfo{s}})

	var found *model.Evidence
	for i := range d.Evidence {
		if d.Evidence[i].Type == "rtcp_rtt_estimated" {
			found = &d.Evidence[i]
		}
	}
	if found == nil {
		t.Fatal("expected an rtcp_rtt_estimated evidence entry")
	}
	if found.Provenance != model.ProvInferred {
		t.Errorf("Provenance = %q, want %q — an RTT built from a capture-point substitution is inferred, not directly observed", found.Provenance, model.ProvInferred)
	}
	if found.Confidence >= 70 {
		t.Errorf("Confidence = %d, want < 70 — must sit below directly-observed local counts and RTCP-reported values", found.Confidence)
	}
	if !strings.Contains(found.Explain, "estimad") { // matches "estimado"/"estimada"/"Estimado"
		t.Errorf("Explain = %q, must say it's an estimate, not present the number as measured", found.Explain)
	}
	if !strings.Contains(found.Explain, "punto de captura") {
		t.Errorf("Explain = %q, must name the capture-point caveat: precision depends on where the capture sits relative to the endpoint", found.Explain)
	}
	if strings.Contains(found.Value, "ms") && !strings.HasPrefix(found.Value, "~") {
		t.Errorf("Value = %q, want a visibly approximate value (e.g. prefixed with '~'), not a bare number that reads as exact", found.Value)
	}
}

// No RTT evidence at all when there's nothing to estimate — must not
// fabricate a value or a caveat about a number that doesn't exist.
func TestDiagnoseNoRTTEvidenceWhenUnavailable(t *testing.T) {
	s := goodStream()
	s.RTCPSeen = true
	s.RTCP = &RTCPSummary{Receiver: &RTCPReceiverSummary{FractionLostPct: 0.5}, EstimatedRTTUnavailableReason: "no se observó un par SR/RR válido para este stream"}
	d := Diagnose(Call{Established: true, Streams: []StreamInfo{s}})
	for _, e := range d.Evidence {
		if e.Type == "rtcp_rtt_estimated" {
			t.Errorf("unexpected RTT evidence when EstimatedRTTMs is nil: %+v", e)
		}
	}
}

// --- Gate v0.7.3, independent audit item 3 (BLOQUEO): a Sender Report seen
// for this SSRC must never, by itself, cause Receiver-side metrics to exist
// at all — let alone as fabricated zeros that read as "the receiver reported
// 0% loss and 0 jitter" when in truth no Report Block for this SSRC was ever
// observed. See buildRTCPSummary's and RTCPSummary's own doc comments for
// the mechanism this protects. ---

func TestRTCPStreamSummarySenderReportOnlyDoesNotFabricateReceiverMetrics(t *testing.T) {
	const ssrc = 0xAABBCCDD
	sr := rtcp.Packet{
		Type: rtcp.TypeSR, SSRC: ssrc,
		NTPSeconds: uint32(t0.Unix() + ntpUnixEpochDeltaSec), NTPFraction: 0,
		PacketCount: 1234, OctetCount: 197440,
	}
	obs := []rtcpObservation{{Packet: sr, Arrival: t0}}

	got := buildRTCPSummary(obs, ssrc, 8000, false)
	if got == nil {
		t.Fatal("expected a non-nil summary — a Sender Report for this SSRC WAS observed")
	}
	if got.Sender == nil {
		t.Fatal("expected Sender to be populated from the observed Sender Report")
	}
	if got.Sender.PacketCount != 1234 || got.Sender.OctetCount != 197440 {
		t.Errorf("Sender = %+v, want PacketCount=1234 OctetCount=197440", got.Sender)
	}
	if got.Receiver != nil {
		t.Fatalf("Receiver must be nil — no Report Block for this SSRC was ever observed, but got %+v (this is exactly the fabricated-zero bug: a Sender Report alone must never manufacture Receiver-side loss/jitter/cumulative-lost data)", got.Receiver)
	}
	if got.EstimatedRTTMs != nil {
		t.Errorf("EstimatedRTTMs must be nil without any Report Block/LSR to correlate against, got %v", *got.EstimatedRTTMs)
	}
}

// The mirror case: a Report Block naming this SSRC was observed, but this
// SSRC's own Sender Report never was (e.g. a receive-only leg that never
// sends RTP itself, so it never emits a SR of its own).
func TestRTCPStreamSummaryReceiverReportOnlyDoesNotFabricateSenderMetrics(t *testing.T) {
	const ssrc = 0xAABBCCDD
	rr := rtcp.Packet{Type: rtcp.TypeRR, SSRC: 0x11223344, Reports: []rtcp.ReportBlock{
		{SSRC: ssrc, FractionLost: 1.5, CumulativeLost: 3, HighestSeq: 500, JitterTicks: 40},
	}}
	obs := []rtcpObservation{{Packet: rr, Arrival: t0}}

	got := buildRTCPSummary(obs, ssrc, 8000, false)
	if got == nil {
		t.Fatal("expected a non-nil summary — a Report Block for this SSRC WAS observed")
	}
	if got.Receiver == nil {
		t.Fatal("expected Receiver to be populated from the observed Report Block")
	}
	if got.Receiver.FractionLostPct != 1.5 || got.Receiver.CumulativeLost != 3 || got.Receiver.HighestSeq != 500 || got.Receiver.JitterTicks != 40 {
		t.Errorf("Receiver = %+v, want FractionLostPct=1.5 CumulativeLost=3 HighestSeq=500 JitterTicks=40", got.Receiver)
	}
	if got.Sender != nil {
		t.Fatalf("Sender must be nil — this SSRC's own Sender Report was never observed, but got %+v (fabricating PacketCount/OctetCount/NTP* here would misattribute a receive-only party's traffic)", got.Sender)
	}
}

// buildRTCPSummary must return nil entirely when this SSRC was never named
// in any RTCP report at all — not an empty-but-non-nil summary.
func TestRTCPStreamSummaryNilWhenSSRCNeverObserved(t *testing.T) {
	const ssrc = 0xAABBCCDD
	rr := rtcp.Packet{Type: rtcp.TypeRR, Reports: []rtcp.ReportBlock{{SSRC: 0x99999999, FractionLost: 5}}}
	obs := []rtcpObservation{{Packet: rr, Arrival: t0}}
	if got := buildRTCPSummary(obs, ssrc, 8000, false); got != nil {
		t.Fatalf("expected nil when ssrc was never named in any report, got %+v", got)
	}
}

// Gate v0.7.3 (independent audit, gate of closure, item 9): seenSR must keep
// tracking correlation correctly even when the SAME 16-bit-truncated
// NTP-short value is seen from two DIFFERENT SR occurrences (the seconds
// field wraps every ~65536s, ~18.2h) — the report must still correlate
// against the most recent PRIOR one, never a later one, and must still
// produce a valid RTT rather than being confused by the collision.
//
// The two SR occurrences here share an identical NTP-short value by
// construction (NTPSeconds chosen 65536 apart, which truncates to the same
// 16 bits) — deliberately, to prove this without needing a real ~18.2h
// capture. The RTT this produces is numerically the same regardless of
// which of the two occurrences "matched": LSR is the 32-bit truncated value
// carried directly in the report block and used as a plain scalar in the
// A-LSR-DLSR subtraction (RFC 3550 §6.4.1), not a reference to a specific
// packet — so this test's job is only to confirm the collision doesn't
// cause a false rejection, not to distinguish "used the earlier one" from
// "used the later one" (there is no arithmetic difference to distinguish).
func TestEstimateRTTToleratesRepeatedNTPShortValue(t *testing.T) {
	const ssrc = 0xAABBCCDD
	const wrapSeconds = 0x10000 // 65536s: one full NTP-short seconds cycle

	baseSec := uint32(t0.Unix() + ntpUnixEpochDeltaSec)
	srEarly := rtcp.Packet{Type: rtcp.TypeSR, SSRC: ssrc, NTPSeconds: baseSec, NTPFraction: 0}
	srLate := rtcp.Packet{Type: rtcp.TypeSR, SSRC: ssrc, NTPSeconds: baseSec + wrapSeconds, NTPFraction: 0}
	lsrEarly := ntpShort(srEarly.NTPSeconds, srEarly.NTPFraction)
	lsrLate := ntpShort(srLate.NTPSeconds, srLate.NTPFraction)
	if lsrEarly != lsrLate {
		t.Fatalf("test setup: expected both SRs to truncate to the same NTP-short value, got %#x and %#x", lsrEarly, lsrLate)
	}

	rr := rtcp.Packet{Type: rtcp.TypeRR, Reports: []rtcp.ReportBlock{
		{SSRC: ssrc, LSR: lsrEarly, DLSR: 65536}, // 1s DLSR
	}}
	obs := []rtcpObservation{
		{Packet: srEarly, Arrival: t0},
		{Packet: srLate, Arrival: t0.Add(time.Second)},
		{Packet: rr, Arrival: t0.Add(3 * time.Second)},
	}
	rtt, reason := estimateRTT(obs, ssrc)
	if rtt == nil {
		t.Fatalf("expected a computed RTT despite the NTP-short collision, got none: reason=%q", reason)
	}
	// A = t0+3s, LSR names t0 (whichever SR occurrence), DLSR = 1s.
	// RTT = 3s - 0s - 1s = 2s = 2000ms, regardless of which SR "matched".
	if *rtt < 1999 || *rtt > 2001 {
		t.Errorf("RTT = %v ms, want ~2000", *rtt)
	}
}
