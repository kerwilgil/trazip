package voip

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// ─────────────────────────────────────────────────────────────────────────────
// Self-contained PCAP builder for the v1.4 VoIP-audio closure contract.
//
// It writes a full INVITE(offer) → 200 OK(answer) → ACK → RTP → BYE dialog per
// call so correlation produces SDPOffer AND SDPAnswer (media direction depends
// on the answer), supports per-packet SSRC/PT/payload/direction/timestamp, and
// takes an explicit media proto so RTP/SAVP(F) fixtures are possible.
// ─────────────────────────────────────────────────────────────────────────────

type e2ePkt struct {
	fromCaller bool
	onSecond   bool // route on the call's 2nd audio m= section, not the 1st
	seq        uint16
	ts         uint32
	pt         uint8
	ssrc       uint32
	payload    []byte
	at         time.Duration // relative to call base
}

type e2eCall struct {
	callID             string
	callerIP, calleeIP string
	callerPort         uint16 // media
	calleePort         uint16 // media
	proto              string // "RTP/AVP" | "RTP/SAVP" | "RTP/SAVPF"
	rtpmap             []string
	pts                string // m= payload-type list, e.g. "0" or "18" or "101"
	ptime              int
	base               time.Duration // dialog start, relative to capture t0
	byeAt              time.Duration // BYE offset from base; 0 → default 3s
	second             *e2eMedia     // optional 2nd audio m= section in the SAME dialog
	pkts               []e2ePkt
}

// e2eMedia is an additional audio m= line inside one dialog (a session with
// two negotiated audio media, e.g. one RTP/AVP and one RTP/SAVPF).
type e2eMedia struct {
	callerPort uint16
	calleePort uint16
	proto      string
	rtpmap     []string
	pts        string
}

func writeE2EPCAP(t *testing.T, calls []e2eCall) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "e2e.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	macA := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	macB := net.HardwareAddr{0x02, 0, 0, 0, 0, 2}

	put := func(src, dst net.IP, sMAC, dMAC net.HardwareAddr, sp, dp uint16, body []byte, at time.Duration) {
		eth := &layers.Ethernet{SrcMAC: sMAC, DstMAC: dMAC, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src, DstIP: dst}
		udp := &layers.UDP{SrcPort: layers.UDPPort(sp), DstPort: layers.UDPPort(dp)}
		_ = udp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			eth, ip, udp, gopacket.Payload(body)); err != nil {
			t.Fatal(err)
		}
		d := buf.Bytes()
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: t0.Add(at), CaptureLength: len(d), Length: len(d)}, d); err != nil {
			t.Fatal(err)
		}
	}

	for _, c := range calls {
		aIP, bIP := net.ParseIP(c.callerIP), net.ParseIP(c.calleeIP)
		ptime := ""
		if c.ptime > 0 {
			ptime = fmt.Sprintf("a=ptime:%d\r\n", c.ptime)
		}
		mediaBlock := func(port uint16, proto, pts string, rtpmap []string, withPtime bool) string {
			s := fmt.Sprintf("m=audio %d %s %s\r\n", port, proto, pts)
			for _, l := range rtpmap {
				s += l + "\r\n"
			}
			if withPtime {
				s += ptime
			}
			return s + "a=sendrecv\r\n"
		}
		sdpBody := func(originIP string, p1 uint16, p2 uint16) string {
			body := fmt.Sprintf("v=0\r\no=x 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n", originIP, originIP)
			body += mediaBlock(p1, c.proto, c.pts, c.rtpmap, true)
			if c.second != nil {
				body += mediaBlock(p2, c.second.proto, c.second.pts, c.second.rtpmap, false)
			}
			return body
		}
		var oP2, aP2 uint16
		if c.second != nil {
			oP2, aP2 = c.second.callerPort, c.second.calleePort
		}
		offer := sdpBody(c.callerIP, c.callerPort, oP2)
		answer := sdpBody(c.calleeIP, c.calleePort, aP2)

		sip := func(start string, withBody string, extra ...string) []byte {
			lines := []string{
				start,
				"Via: SIP/2.0/UDP " + c.callerIP + ";branch=z9hG4bK-" + c.callID,
				"From: Alice <sip:alice@" + c.callerIP + ">;tag=af-" + c.callID,
				"To: Bob <sip:bob@" + c.calleeIP + ">",
				"Call-ID: " + c.callID,
				"CSeq: 1 INVITE",
			}
			lines = append(lines, extra...)
			if withBody != "" {
				lines = append(lines, "Content-Type: application/sdp",
					fmt.Sprintf("Content-Length: %d", len(withBody)), "", withBody)
			} else {
				lines = append(lines, "Content-Length: 0", "")
			}
			s := ""
			for _, l := range lines {
				s += l + "\r\n"
			}
			return []byte(s)
		}
		toTag := "bt-" + c.callID
		put(aIP, bIP, macA, macB, 5060, 5060, sip("INVITE sip:bob@"+c.calleeIP+" SIP/2.0", offer), c.base)
		put(bIP, aIP, macB, macA, 5060, 5060, sip("SIP/2.0 100 Trying", "", "To: Bob <sip:bob@"+c.calleeIP+">"), c.base+30*time.Millisecond)
		put(bIP, aIP, macB, macA, 5060, 5060, sip("SIP/2.0 200 OK", answer, "To: Bob <sip:bob@"+c.calleeIP+">;tag="+toTag, "Contact: <sip:bob@"+c.calleeIP+":5060>"), c.base+300*time.Millisecond)
		put(aIP, bIP, macA, macB, 5060, 5060, sip("ACK sip:bob@"+c.calleeIP+" SIP/2.0", "", "To: Bob <sip:bob@"+c.calleeIP+">;tag="+toTag, "CSeq: 1 ACK"), c.base+330*time.Millisecond)

		for _, p := range c.pkts {
			raw := make([]byte, 12+len(p.payload))
			raw[0] = 0x80
			raw[1] = p.pt
			binary.BigEndian.PutUint16(raw[2:4], p.seq)
			binary.BigEndian.PutUint32(raw[4:8], p.ts)
			binary.BigEndian.PutUint32(raw[8:12], p.ssrc)
			copy(raw[12:], p.payload)
			cp, ep := c.callerPort, c.calleePort
			if p.onSecond && c.second != nil {
				cp, ep = c.second.callerPort, c.second.calleePort
			}
			if p.fromCaller {
				put(aIP, bIP, macA, macB, cp, ep, raw, c.base+p.at)
			} else {
				put(bIP, aIP, macB, macA, ep, cp, raw, c.base+p.at)
			}
		}
		bye := c.byeAt
		if bye == 0 {
			bye = 3 * time.Second
		}
		put(aIP, bIP, macA, macB, 5060, 5060, sip("BYE sip:bob@"+c.calleeIP+" SIP/2.0", "", "To: Bob <sip:bob@"+c.calleeIP+">;tag="+toTag, "CSeq: 2 BYE"), c.base+bye)
	}
	return path
}

// g711Payload builds n bytes of a single repeated µ-law/A-law octet so a
// decoded track is a flat, checkable constant.
func g711Payload(b byte, n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = b
	}
	return p
}

func streamByCodec(c Call, codec string) *StreamInfo {
	for i := range c.Streams {
		if c.Streams[i].CodecName == codec {
			return &c.Streams[i]
		}
	}
	return nil
}

// ── PART 6 (P0): same SSRC reused across two calls, no cross-contamination ────

func TestE2ESameSSRCCrossCallIsolation(t *testing.T) {
	const ssrc = 0x5A5A5A5A
	rtp := func(fromCaller bool, seq uint16, ts uint32, b byte, at time.Duration) e2ePkt {
		return e2ePkt{fromCaller: fromCaller, seq: seq, ts: ts, pt: 0, ssrc: ssrc, payload: g711Payload(b, 160), at: at}
	}
	var aPkts, bPkts []e2ePkt
	for i := 0; i < 25; i++ {
		aPkts = append(aPkts, rtp(true, uint16(i), uint32(i)*160, 0x11, 1100*time.Millisecond+time.Duration(i)*20*time.Millisecond))
		bPkts = append(bPkts, rtp(true, uint16(i), uint32(i)*160, 0x22, 1100*time.Millisecond+time.Duration(i)*20*time.Millisecond))
	}
	// Same caller/callee IPs AND same media ports; the ONLY discriminator is the
	// 5-minute time gap — the hardest form of SSRC-reuse isolation.
	calls := []e2eCall{
		{callID: "call-A@x", callerIP: "10.9.0.1", calleeIP: "10.9.0.2", callerPort: 6000, calleePort: 6002,
			proto: "RTP/AVP", rtpmap: []string{"a=rtpmap:0 PCMU/8000"}, pts: "0", ptime: 20, base: 0, pkts: aPkts},
		{callID: "call-B@x", callerIP: "10.9.0.1", calleeIP: "10.9.0.2", callerPort: 6000, calleePort: 6002,
			proto: "RTP/AVP", rtpmap: []string{"a=rtpmap:0 PCMU/8000"}, pts: "0", ptime: 20, base: 5 * time.Minute, pkts: bPkts},
	}
	path := writeE2EPCAP(t, calls)
	r, err := Analyze(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.TotalCalls != 2 {
		t.Fatalf("calls=%d, want 2", r.TotalCalls)
	}
	wantA, wantB := ulaw2linear(0x11), ulaw2linear(0x22)
	for _, want := range []struct {
		id     string
		sample int16
		other  int16
	}{{"call-A@x", wantA, wantB}, {"call-B@x", wantB, wantA}} {
		var call *Call
		for i := range r.Calls {
			if r.Calls[i].CallID == want.id {
				call = &r.Calls[i]
			}
		}
		if call == nil {
			t.Fatalf("%s not correlated", want.id)
		}
		st := streamByCodec(*call, "PCMU")
		if st == nil {
			t.Fatalf("%s: no PCMU stream in %+v", want.id, call.Streams)
		}
		if st.SSRC != ssrc {
			t.Fatalf("%s: ssrc=%08x", want.id, st.SSRC)
		}
		if st.Stats.Received != 25 {
			t.Fatalf("%s: packets=%d, want 25 (cross-call bleed)", want.id, st.Stats.Received)
		}
		res, err := ReconstructCallAudio(context.Background(), path, *call, AudioModeMono)
		if err != nil {
			t.Fatalf("%s reconstruct: %v", want.id, err)
		}
		samples := decodeWAVData(t, res.WAV)
		if len(samples) != 25*160 {
			t.Fatalf("%s: samples=%d, want %d", want.id, len(samples), 25*160)
		}
		for i, s := range samples {
			if s != want.sample {
				t.Fatalf("%s: sample[%d]=%d, want %d (pattern isolation)", want.id, i, s, want.sample)
			}
			if s == want.other {
				t.Fatalf("%s: sample[%d] carries the OTHER call's pattern", want.id, i)
			}
		}
	}
}

// ── PART 7: G.729 end-to-end from PCAP (static PT18, dynamic PT96, ptimes) ────

func TestE2EG729StaticDynamicAndPtime(t *testing.T) {
	cases := []struct {
		name          string
		pt            uint8
		pts           string
		rtpmap        string
		ptime         int
		frameBytes    int
		frames        int
		dropFrameIdx  int // -1 = none
		wantSamples   int
		wantDegraded  bool
	}{
		{"static_pt18_ptime10", 18, "18", "a=rtpmap:18 G729/8000", 10, 10, 20, -1, 20 * 80, false},
		{"dynamic_pt96_ptime10", 96, "96", "a=rtpmap:96 G729/8000", 10, 10, 15, -1, 15 * 80, false},
		{"ptime20_160samples", 18, "18", "a=rtpmap:18 G729/8000", 20, 20, 10, -1, 10 * 160, false},
		{"loss_preserves_timeline", 18, "18", "a=rtpmap:18 G729/8000", 10, 10, 12, 5, 12 * 80, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pkts []e2ePkt
			samplesPerFrame := uint32(tc.frameBytes * 8) // 10B→80, 20B→160 (G.729 8kHz)
			for i := 0; i < tc.frames; i++ {
				if i == tc.dropFrameIdx {
					continue
				}
				pkts = append(pkts, e2ePkt{
					fromCaller: true, seq: uint16(i), ts: uint32(i) * samplesPerFrame, pt: tc.pt,
					ssrc: 0x0729, payload: make([]byte, tc.frameBytes),
					at: 1100*time.Millisecond + time.Duration(i)*time.Duration(tc.ptime)*time.Millisecond,
				})
			}
			path := writeE2EPCAP(t, []e2eCall{{
				callID: "g729@x", callerIP: "10.7.0.1", calleeIP: "10.7.0.2", callerPort: 7000, calleePort: 7002,
				proto: "RTP/AVP", rtpmap: []string{tc.rtpmap}, pts: tc.pts, ptime: tc.ptime, base: 0, pkts: pkts,
			}})
			r, err := Analyze(context.Background(), path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if r.TotalCalls != 1 {
				t.Fatalf("calls=%d", r.TotalCalls)
			}
			st := streamByCodec(r.Calls[0], "G729")
			if st == nil {
				t.Fatalf("no G729 stream: %+v", r.Calls[0].Streams)
			}
			if st.AudioStatus != AudioStatusReconstructable && st.AudioStatus != AudioStatusUnknownDirection {
				t.Fatalf("audioStatus=%s", st.AudioStatus)
			}
			res, err := ReconstructCallAudio(context.Background(), path, r.Calls[0], AudioModeMono)
			if err != nil {
				t.Fatalf("reconstruct: %v", err)
			}
			got := len(decodeWAVData(t, res.WAV))
			if got != tc.wantSamples {
				t.Fatalf("samples=%d, want %d (RTP timestamp is the timeline authority)", got, tc.wantSamples)
			}
			if res.Degraded != tc.wantDegraded {
				t.Fatalf("degraded=%v, want %v", res.Degraded, tc.wantDegraded)
			}
		})
	}
}

// ── PART 8: bidirectional mono/stereo timelines, 500ms offset, loss ──────────

func TestE2EBidirectionalMonoStereoTimeline(t *testing.T) {
	const callerSSRC, calleeSSRC = 0xCA11E7, 0xCA11EE
	var pkts []e2ePkt
	// caller: 30 packets from t=1100ms, pattern 0x11, drop seq 7
	for i := 0; i < 30; i++ {
		if i == 7 {
			continue
		}
		pkts = append(pkts, e2ePkt{fromCaller: true, seq: uint16(i), ts: uint32(i) * 160, pt: 0, ssrc: callerSSRC,
			payload: g711Payload(0x11, 160), at: 1100*time.Millisecond + time.Duration(i)*20*time.Millisecond})
	}
	// callee: 20 packets starting +500ms, pattern 0x22
	for i := 0; i < 20; i++ {
		pkts = append(pkts, e2ePkt{fromCaller: false, seq: uint16(i), ts: uint32(i) * 160, pt: 0, ssrc: calleeSSRC,
			payload: g711Payload(0x22, 160), at: 1600*time.Millisecond + time.Duration(i)*20*time.Millisecond})
	}
	path := writeE2EPCAP(t, []e2eCall{{
		callID: "bidi@x", callerIP: "10.8.0.1", calleeIP: "10.8.0.2", callerPort: 8000, calleePort: 8002,
		proto: "RTP/AVP", rtpmap: []string{"a=rtpmap:0 PCMU/8000"}, pts: "0", ptime: 20, base: 0, pkts: pkts,
	}})
	r, err := Analyze(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	call := r.Calls[0]
	var caller, callee *StreamInfo
	for i := range call.Streams {
		switch call.Streams[i].Direction {
		case "caller":
			caller = &call.Streams[i]
		case "callee":
			callee = &call.Streams[i]
		}
	}
	if caller == nil || callee == nil {
		t.Fatalf("directions not resolved: %+v", call.Streams)
	}
	a, b := ulaw2linear(0x11), ulaw2linear(0x22)

	// STEREO: L = caller only, R = callee only, silence on R before the 500ms offset.
	st, err := ReconstructCallAudio(context.Background(), path, call, AudioModeStereo)
	if err != nil {
		t.Fatalf("stereo: %v", err)
	}
	if st.Channels != 2 {
		t.Fatalf("channels=%d", st.Channels)
	}
	inter := decodeWAVData(t, st.WAV)
	var left, right []int16
	for i := 0; i+1 < len(inter); i += 2 {
		left = append(left, inter[i])
		right = append(right, inter[i+1])
	}
	// 500ms @ 8kHz = 4000 samples of callee silence up front.
	for i := 0; i < 4000 && i < len(right); i++ {
		if right[i] != 0 {
			t.Fatalf("right[%d]=%d, want 0 before caller/callee 500ms offset", i, right[i])
		}
	}
	if right[4001] != b {
		t.Fatalf("right[4001]=%d, want callee pattern %d", right[4001], b)
	}
	for i, v := range left {
		if v != a && v != 0 { // 0 only at the single dropped-packet gap
			t.Fatalf("left[%d]=%d contains non-caller audio", i, v)
		}
		if v == b {
			t.Fatalf("left[%d] carries callee pattern (channel bleed)", i)
		}
	}
	// Final length must be the max of both timelines, never caller+callee concatenated.
	callerSamples, calleeSamples := 30*160, 20*160
	wantLen := callerSamples
	if 4000+calleeSamples > wantLen {
		wantLen = 4000 + calleeSamples
	}
	if len(left) != wantLen || len(right) != wantLen {
		t.Fatalf("stereo len L=%d R=%d, want %d (max timeline, not concatenation)", len(left), len(right), wantLen)
	}

	// MONO: overlapping region carries the summed patterns; a concatenation would
	// show pure-A then pure-B with total length = callerSamples+calleeSamples.
	mono, err := ReconstructCallAudio(context.Background(), path, call, AudioModeMono)
	if err != nil {
		t.Fatalf("mono: %v", err)
	}
	ms := decodeWAVData(t, mono.WAV)
	if len(ms) == callerSamples+calleeSamples {
		t.Fatalf("mono length %d == caller+callee: timelines were concatenated, not mixed", len(ms))
	}
	if len(ms) != wantLen {
		t.Fatalf("mono length=%d, want %d", len(ms), wantLen)
	}
	sum := clamp16(int(a) + int(b))
	overlapFound := false
	for i := 4000; i < callerSamples; i++ {
		if ms[i] == sum {
			overlapFound = true
			break
		}
	}
	if !overlapFound {
		t.Fatal("mono mix never shows caller+callee summed in the overlap window")
	}
}

func clamp16(v int) int16 {
	if v > 32767 {
		return 32767
	}
	if v < -32768 {
		return -32768
	}
	return int16(v)
}

// ── PART 9 & 10: SRTP and DTMF must never reach a decoder ────────────────────

func TestE2ESRTPAndDTMFNeverReachDecoder(t *testing.T) {
	var decoderCalls int
	orig := decoderForStream
	decoderForStream = func(s StreamInfo) (audioDecoder, error) {
		decoderCalls++
		return orig(s)
	}
	defer func() { decoderForStream = orig }()

	clear := g711Payload(0xFF, 160)
	enc := g711Payload(0x00, 160)
	dtmf := []byte{0x05, 0x8A, 0x03, 0x20} // digit "5", end-of-event set

	var avpPkts, savpPkts, dtmfPkts []e2ePkt
	for i := 0; i < 15; i++ {
		at := 1100*time.Millisecond + time.Duration(i)*20*time.Millisecond
		avpPkts = append(avpPkts, e2ePkt{fromCaller: true, seq: uint16(i), ts: uint32(i) * 160, pt: 0, ssrc: 0xA0A0, payload: clear, at: at})
		savpPkts = append(savpPkts, e2ePkt{fromCaller: true, seq: uint16(i), ts: uint32(i) * 160, pt: 0, ssrc: 0xB0B0, payload: enc, at: at})
		dtmfPkts = append(dtmfPkts, e2ePkt{fromCaller: true, seq: uint16(i), ts: uint32(i) * 160, pt: 101, ssrc: 0xD1D1, payload: dtmf, at: at})
	}
	path := writeE2EPCAP(t, []e2eCall{
		{callID: "avp@x", callerIP: "10.1.0.1", calleeIP: "10.1.0.2", callerPort: 9000, calleePort: 9002,
			proto: "RTP/AVP", rtpmap: []string{"a=rtpmap:0 PCMU/8000"}, pts: "0", ptime: 20, base: 0, pkts: avpPkts},
		{callID: "savp@x", callerIP: "10.2.0.1", calleeIP: "10.2.0.2", callerPort: 9100, calleePort: 9102,
			proto: "RTP/SAVP", rtpmap: []string{"a=rtpmap:0 PCMU/8000"}, pts: "0", ptime: 20, base: time.Minute, pkts: savpPkts},
		{callID: "dtmf@x", callerIP: "10.3.0.1", calleeIP: "10.3.0.2", callerPort: 9200, calleePort: 9202,
			proto: "RTP/AVP", rtpmap: []string{"a=rtpmap:101 telephone-event/8000"}, pts: "101", ptime: 20, base: 2 * time.Minute, pkts: dtmfPkts},
	})
	r, err := Analyze(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Call{}
	for _, c := range r.Calls {
		byID[c.CallID] = c
	}

	// AVP: reconstructs, decoder runs exactly once for its single stream.
	before := decoderCalls
	avpRes, err := ReconstructCallAudio(context.Background(), path, byID["avp@x"], AudioModeMono)
	if err != nil {
		t.Fatalf("AVP reconstruct: %v", err)
	}
	if decoderCalls-before != 1 {
		t.Fatalf("AVP decoder calls=%d, want 1", decoderCalls-before)
	}
	if len(decodeWAVData(t, avpRes.WAV)) != 15*160 {
		t.Fatalf("AVP samples=%d", len(decodeWAVData(t, avpRes.WAV)))
	}

	// SAVP: encrypted → controlled error, decoder count unchanged.
	before = decoderCalls
	if _, err := ReconstructCallAudio(context.Background(), path, byID["savp@x"], AudioModeMono); err == nil {
		t.Fatal("SAVP: expected an encrypted/not-reconstructible error")
	}
	savpStream := byID["savp@x"].Streams
	if len(savpStream) == 0 || (savpStream[0].AudioStatus != AudioStatusEncryptedUnavailable && savpStream[0].AudioStatus != AudioStatusSRTPDetected) {
		t.Fatalf("SAVP status=%+v", savpStream)
	}
	if decoderCalls != before {
		t.Fatalf("SAVP decoder calls=%d, want 0", decoderCalls-before)
	}

	// DTMF: telephone-event → digits captured as metadata, no voice reconstruction,
	// decoder count unchanged.
	before = decoderCalls
	dcall := byID["dtmf@x"]
	var teStream *StreamInfo
	for i := range dcall.Streams {
		if dcall.Streams[i].PayloadType == 101 {
			teStream = &dcall.Streams[i]
		}
	}
	if teStream == nil {
		t.Fatalf("no PT101 stream: %+v", dcall.Streams)
	}
	if teStream.CodecName != "telephone-event" {
		t.Fatalf("PT101 codec=%q, want telephone-event", teStream.CodecName)
	}
	if teStream.DTMFDigits == "" {
		t.Fatalf("DTMF digits not captured as metadata")
	}
	if _, err := ReconstructCallAudio(context.Background(), path, dcall, AudioModeMono); err == nil {
		t.Fatal("DTMF-only call: expected no reconstructible voice audio")
	}
	if decoderCalls != before {
		t.Fatalf("DTMF decoder calls=%d, want 0 (telephone-event is not voice)", decoderCalls-before)
	}
}

// ── PART 12: adversarial RTP timestamp / mix offset → controlled, no panic ───

func TestReconstructTimestampAndOffsetAttacks(t *testing.T) {
	mk := func(frames []struct {
		seq uint16
		ts  uint32
	}) string {
		path := filepath.Join(t.TempDir(), "attack.pcap")
		f, _ := os.Create(path)
		defer f.Close()
		w := pcapgo.NewWriter(f)
		_ = w.WriteFileHeader(65535, layers.LinkTypeEthernet)
		t0 := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
		for i, fr := range frames {
			raw := make([]byte, 12+160)
			raw[0] = 0x80
			binary.BigEndian.PutUint16(raw[2:4], fr.seq)
			binary.BigEndian.PutUint32(raw[4:8], fr.ts)
			binary.BigEndian.PutUint32(raw[8:12], 0x00ACC0DE)
			eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
			ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}}
			udp := &layers.UDP{SrcPort: 5000, DstPort: 5002}
			_ = udp.SetNetworkLayerForChecksum(ip)
			buf := gopacket.NewSerializeBuffer()
			_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(raw))
			d := buf.Bytes()
			_ = w.WritePacket(gopacket.CaptureInfo{Timestamp: t0.Add(time.Duration(i) * 20 * time.Millisecond), CaptureLength: len(d), Length: len(d)}, d)
		}
		return path
	}
	stream := StreamInfo{SSRC: 0x00ACC0DE, Src: "10.0.0.1:5000", PayloadType: 0, CodecName: "PCMU", ClockRate: 8000, AudioStatus: AudioStatusReconstructable}

	// (a) second frame's timestamp is ~1.07e9 samples ahead → offset far past the
	//     30-minute ceiling → controlled error BEFORE any proportional allocation.
	pathFar := mk([]struct {
		seq uint16
		ts  uint32
	}{{0, 1000}, {1, 1000 + 0x40000000}})
	if _, err := reconstructStream(context.Background(), pathFar, stream); err == nil {
		t.Fatal("far-ahead timestamp: expected a controlled error, got success")
	}

	// (b) 32-bit timestamp wrap between consecutive frames is normal and must
	//     reconstruct: uint32 delta keeps the offset small (512 samples).
	pathWrap := mk([]struct {
		seq uint16
		ts  uint32
	}{{0, 0xFFFFFF00}, {1, 0x00000100}})
	tr, err := reconstructStream(context.Background(), pathWrap, stream)
	if err != nil {
		t.Fatalf("timestamp wrap should reconstruct: %v", err)
	}
	if len(tr.samples) != 512+160 {
		t.Fatalf("wrap samples=%d, want %d", len(tr.samples), 512+160)
	}
}

// TestE2EExtremeMixOffsetRejected drives a bidirectional call whose callee leg
// starts ~40 minutes after the caller leg. The mix offset (~19.2M samples)
// exceeds the timeline ceiling, so ReconstructCallAudio must return a
// controlled resource-limit error rather than allocate a ~40MB silence run.
func TestE2EExtremeMixOffsetRejected(t *testing.T) {
	var pkts []e2ePkt
	for i := 0; i < 10; i++ {
		pkts = append(pkts, e2ePkt{fromCaller: true, seq: uint16(i), ts: uint32(i) * 160, pt: 0, ssrc: 0xC0FFEE,
			payload: g711Payload(0x11, 160), at: 1100*time.Millisecond + time.Duration(i)*20*time.Millisecond})
	}
	for i := 0; i < 10; i++ {
		pkts = append(pkts, e2ePkt{fromCaller: false, seq: uint16(i), ts: uint32(i) * 160, pt: 0, ssrc: 0xDECAFF,
			payload: g711Payload(0x22, 160), at: 40*time.Minute + time.Duration(i)*20*time.Millisecond})
	}
	path := writeE2EPCAP(t, []e2eCall{{
		callID: "farmix@x", callerIP: "10.6.0.1", calleeIP: "10.6.0.2", callerPort: 6600, calleePort: 6602,
		proto: "RTP/AVP", rtpmap: []string{"a=rtpmap:0 PCMU/8000"}, pts: "0", ptime: 20, base: 0,
		byeAt: 41 * time.Minute, pkts: pkts,
	}})
	r, err := Analyze(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReconstructCallAudio(context.Background(), path, r.Calls[0], AudioModeStereo); err == nil {
		t.Fatal("extreme mix offset: expected a controlled resource-limit error")
	}
}

// ── PART 11: MAX / MAX+1 boundaries on the exported-audio ceilings ───────────

func TestExportedAudioBoundaries(t *testing.T) {
	// WAV sample-count ceiling (int32 data-size headroom).
	maxWavSamples := (int(^uint32(0)) - 36) / 2
	if WriteWAVChannels(8000, 1, make([]int16, 8)) == nil {
		t.Fatal("small WAV rejected")
	}
	if got := WriteWAVChannels(8000, 1, make([]int16, maxWavSamples+1)); got != nil {
		t.Fatal("WAV over the int32 data ceiling must be rejected (MAX+1)")
	}

	// Duration ceiling: maxAudioSamples is exactly 30:00 of 8kHz mono, and the
	// ceiling is on TOTAL reconstructed length (silent gap + the frame's own
	// 160 samples). A run that totals exactly 30:00 is allowed; one sample more
	// is rejected — with a controlled error, never a panic or a huge alloc.
	const frameSamples = 160
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	writeTwo := func(ts1 uint32) string {
		path := filepath.Join(t.TempDir(), "dur.pcap")
		f, _ := os.Create(path)
		defer f.Close()
		w := pcapgo.NewWriter(f)
		_ = w.WriteFileHeader(65535, layers.LinkTypeEthernet)
		for i, ts := range []uint32{0, ts1} {
			raw := make([]byte, 12+160)
			raw[0] = 0x80
			binary.BigEndian.PutUint16(raw[2:4], uint16(i))
			binary.BigEndian.PutUint32(raw[4:8], ts)
			binary.BigEndian.PutUint32(raw[8:12], 0x0D0D)
			eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
			ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}}
			udp := &layers.UDP{SrcPort: 5000, DstPort: 5002}
			_ = udp.SetNetworkLayerForChecksum(ip)
			buf := gopacket.NewSerializeBuffer()
			_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(raw))
			d := buf.Bytes()
			_ = w.WritePacket(gopacket.CaptureInfo{Timestamp: base.Add(time.Duration(i) * 20 * time.Millisecond), CaptureLength: len(d), Length: len(d)}, d)
		}
		return path
	}
	stream := StreamInfo{SSRC: 0x0D0D, Src: "10.0.0.1:5000", PayloadType: 0, CodecName: "PCMU", ClockRate: 8000, AudioStatus: AudioStatusReconstructable}
	if _, err := reconstructStream(context.Background(), writeTwo(uint32(maxAudioSamples-frameSamples)), stream); err != nil {
		t.Fatalf("total == 30:00 ceiling must be allowed: %v", err)
	}
	if _, err := reconstructStream(context.Background(), writeTwo(uint32(maxAudioSamples-frameSamples+1)), stream); err == nil {
		t.Fatal("total one sample past the 30:00 ceiling must be rejected (MAX+1)")
	}
}

// decodeWAVData parses a canonical 44-byte RIFF/WAVE/PCM16 header and returns
// the interleaved sample body. It fails the test on any structural problem so
// WAV-shape assertions are centralised.
func decodeWAVData(t *testing.T, wav []byte) []int16 {
	t.Helper()
	if len(wav) < 44 {
		t.Fatalf("WAV too short: %d bytes", len(wav))
	}
	if string(wav[0:4]) != "RIFF" || string(wav[8:12]) != "WAVE" || string(wav[12:16]) != "fmt " || string(wav[36:40]) != "data" {
		t.Fatalf("WAV header chunks: %q %q %q %q", wav[0:4], wav[8:12], wav[12:16], wav[36:40])
	}
	if binary.LittleEndian.Uint16(wav[20:22]) != 1 {
		t.Fatal("WAV is not PCM")
	}
	if binary.LittleEndian.Uint32(wav[24:28]) != 8000 {
		t.Fatalf("sample rate=%d, want 8000", binary.LittleEndian.Uint32(wav[24:28]))
	}
	if binary.LittleEndian.Uint16(wav[34:36]) != 16 {
		t.Fatal("bits/sample != 16")
	}
	dataLen := binary.LittleEndian.Uint32(wav[40:44])
	if int(dataLen) != len(wav)-44 {
		t.Fatalf("data size %d != body %d", dataLen, len(wav)-44)
	}
	out := make([]int16, dataLen/2)
	for i := range out {
		out[i] = int16(binary.LittleEndian.Uint16(wav[44+2*i:]))
	}
	return out
}
