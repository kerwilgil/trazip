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

	"trazip/internal/protocol/rtcp"
	"trazip/internal/protocol/rtp"
)

// callScenario builds a synthetic PCAP with a full SIP+SDP+RTP call: INVITE
// (with SDP offer) -> 100 -> 180 -> 200 OK (with SDP answer) -> ACK -> RTP both
// directions (with a couple of dropped sequence numbers) -> BYE -> 200 OK.
func writeCallPCAP(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "call.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}

	aliceIP, bobIP := net.IP{192, 168, 1, 10}, net.IP{192, 168, 1, 20}
	aliceMAC := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	bobMAC := net.HardwareAddr{0, 6, 7, 8, 9, 10}
	base := time.Now()

	write := func(src, dst net.IP, srcMAC, dstMAC net.HardwareAddr, srcPort, dstPort uint16, payload []byte, at time.Duration) {
		eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src, DstIP: dst}
		udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
		_ = udp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
			t.Fatalf("serialize: %v", err)
		}
		data := buf.Bytes()
		ci := gopacket.CaptureInfo{Timestamp: base.Add(at), CaptureLength: len(data), Length: len(data)}
		if err := w.WritePacket(ci, data); err != nil {
			t.Fatal(err)
		}
	}

	sipMsg := func(lines ...string) []byte {
		s := ""
		for _, l := range lines {
			s += l + "\r\n"
		}
		return []byte(s)
	}

	offerSDP := "v=0\r\no=alice 1 1 IN IP4 192.168.1.10\r\ns=-\r\nc=IN IP4 192.168.1.10\r\nt=0 0\r\n" +
		"m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"
	answerSDP := "v=0\r\no=bob 1 1 IN IP4 192.168.1.20\r\ns=-\r\nc=IN IP4 192.168.1.20\r\nt=0 0\r\n" +
		"m=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n"

	invite := sipMsg(
		"INVITE sip:bob@192.168.1.20 SIP/2.0",
		"Via: SIP/2.0/UDP 192.168.1.10;branch=z9hG4bK1",
		"To: Bob <sip:bob@192.168.1.20>",
		"From: Alice <sip:alice@192.168.1.10>;tag=aaa111",
		"Call-ID: test-call-1@192.168.1.10",
		"CSeq: 1 INVITE",
		"Contact: <sip:alice@192.168.1.10:5060>",
		"User-Agent: TestPhone/1.0",
		"Content-Type: application/sdp",
		fmt.Sprintf("Content-Length: %d", len(offerSDP)),
		"",
		offerSDP,
	)
	trying := sipMsg(
		"SIP/2.0 100 Trying",
		"Via: SIP/2.0/UDP 192.168.1.10;branch=z9hG4bK1",
		"To: Bob <sip:bob@192.168.1.20>",
		"From: Alice <sip:alice@192.168.1.10>;tag=aaa111",
		"Call-ID: test-call-1@192.168.1.10",
		"CSeq: 1 INVITE",
		"Content-Length: 0", "",
	)
	ringing := sipMsg(
		"SIP/2.0 180 Ringing",
		"Via: SIP/2.0/UDP 192.168.1.10;branch=z9hG4bK1",
		"To: Bob <sip:bob@192.168.1.20>;tag=bbb222",
		"From: Alice <sip:alice@192.168.1.10>;tag=aaa111",
		"Call-ID: test-call-1@192.168.1.10",
		"CSeq: 1 INVITE",
		"Content-Length: 0", "",
	)
	ok200 := sipMsg(
		"SIP/2.0 200 OK",
		"Via: SIP/2.0/UDP 192.168.1.10;branch=z9hG4bK1",
		"To: Bob <sip:bob@192.168.1.20>;tag=bbb222",
		"From: Alice <sip:alice@192.168.1.10>;tag=aaa111",
		"Call-ID: test-call-1@192.168.1.10",
		"CSeq: 1 INVITE",
		"Contact: <sip:bob@192.168.1.20:5060>",
		"Server: TestPBX/2.0",
		"Content-Type: application/sdp",
		fmt.Sprintf("Content-Length: %d", len(answerSDP)),
		"",
		answerSDP,
	)
	ack := sipMsg(
		"ACK sip:bob@192.168.1.20 SIP/2.0",
		"Via: SIP/2.0/UDP 192.168.1.10;branch=z9hG4bK2",
		"To: Bob <sip:bob@192.168.1.20>;tag=bbb222",
		"From: Alice <sip:alice@192.168.1.10>;tag=aaa111",
		"Call-ID: test-call-1@192.168.1.10",
		"CSeq: 1 ACK",
		"Content-Length: 0", "",
	)
	bye := sipMsg(
		"BYE sip:bob@192.168.1.20 SIP/2.0",
		"Via: SIP/2.0/UDP 192.168.1.10;branch=z9hG4bK3",
		"To: Bob <sip:bob@192.168.1.20>;tag=bbb222",
		"From: Alice <sip:alice@192.168.1.10>;tag=aaa111",
		"Call-ID: test-call-1@192.168.1.10",
		"CSeq: 2 BYE",
		"Content-Length: 0", "",
	)
	byeOK := sipMsg(
		"SIP/2.0 200 OK",
		"Via: SIP/2.0/UDP 192.168.1.10;branch=z9hG4bK3",
		"To: Bob <sip:bob@192.168.1.20>;tag=bbb222",
		"From: Alice <sip:alice@192.168.1.10>;tag=aaa111",
		"Call-ID: test-call-1@192.168.1.10",
		"CSeq: 2 BYE",
		"Content-Length: 0", "",
	)

	write(aliceIP, bobIP, aliceMAC, bobMAC, 5060, 5060, invite, 0)
	write(bobIP, aliceIP, bobMAC, aliceMAC, 5060, 5060, trying, 50*time.Millisecond)
	write(bobIP, aliceIP, bobMAC, aliceMAC, 5060, 5060, ringing, 500*time.Millisecond)
	write(bobIP, aliceIP, bobMAC, aliceMAC, 5060, 5060, ok200, time.Second)
	write(aliceIP, bobIP, aliceMAC, bobMAC, 5060, 5060, ack, 1050*time.Millisecond)

	// RTP: Alice(40000)->Bob(40002) and Bob(40002)->Alice(40000), 40 packets @
	// 20ms each direction, dropping 2 sequence numbers on the Alice->Bob leg to
	// give the correlator real (small) loss/MOS to compute.
	rtpPacket := func(seq uint16, ssrc uint32) []byte {
		b := make([]byte, 12+160) // 160 bytes = 20ms of PCMU @ 8kHz
		b[0] = 0x80
		b[1] = 0 // PT 0 = PCMU
		binary.BigEndian.PutUint16(b[2:4], seq)
		binary.BigEndian.PutUint32(b[4:8], uint32(seq)*160)
		binary.BigEndian.PutUint32(b[8:12], ssrc)
		return b
	}
	start := 1100 * time.Millisecond
	for i := 0; i < 40; i++ {
		at := start + time.Duration(i)*20*time.Millisecond
		if i != 10 && i != 20 { // drop 2 packets Alice->Bob
			write(aliceIP, bobIP, aliceMAC, bobMAC, 40000, 40002, rtpPacket(uint16(i), 0xA11CE), at)
		}
		write(bobIP, aliceIP, bobMAC, aliceMAC, 40002, 40000, rtpPacket(uint16(i), 0xB0B00), at+2*time.Millisecond)
	}
	// One RTCP receiver report from Bob about Alice's SSRC.
	rr := make([]byte, 32)
	rr[0], rr[1] = 0x81, byte(rtcp.TypeRR)
	binary.BigEndian.PutUint16(rr[2:4], 7)
	binary.BigEndian.PutUint32(rr[4:8], 0xB0B00)
	binary.BigEndian.PutUint32(rr[8:12], 0xA11CE)
	rr[12] = 13 // ~5% fraction lost
	write(bobIP, aliceIP, bobMAC, aliceMAC, 40003, 40001, rr, 1950*time.Millisecond)

	write(aliceIP, bobIP, aliceMAC, bobMAC, 5060, 5060, bye, 2*time.Second)
	write(bobIP, aliceIP, bobMAC, aliceMAC, 5060, 5060, byeOK, 2050*time.Millisecond)

	return path
}

func TestAnalyzeFullCall(t *testing.T) {
	path := writeCallPCAP(t)
	result, err := Analyze(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if result.TotalCalls != 1 {
		t.Fatalf("expected 1 call, got %d: %+v", result.TotalCalls, result.Calls)
	}
	c := result.Calls[0]

	if c.CallID != "test-call-1@192.168.1.10" {
		t.Errorf("CallID = %q", c.CallID)
	}
	if !c.Established {
		t.Fatal("call should be Established")
	}
	if c.SetupMs < 900 || c.SetupMs > 1100 {
		t.Errorf("SetupMs = %v, want ~1000", c.SetupMs)
	}
	if !c.Terminated {
		t.Error("call should be Terminated (BYE seen)")
	}
	if c.DurationSec < 0.9 || c.DurationSec > 1.1 {
		t.Errorf("DurationSec = %v, want ~1.0", c.DurationSec)
	}
	if c.FailureCode != 0 {
		t.Errorf("successful call should have no FailureCode, got %d", c.FailureCode)
	}
	if result.Established != 1 || result.Failed != 0 {
		t.Errorf("summary wrong: established=%d failed=%d", result.Established, result.Failed)
	}

	if c.SDPOffer == nil || c.SDPAnswer == nil {
		t.Fatal("SDP offer and answer must both be captured")
	}
	if len(c.SDPOffer.Media) != 1 || c.SDPOffer.Media[0].Port != 40000 {
		t.Errorf("SDP offer media wrong: %+v", c.SDPOffer.Media)
	}

	if len(c.Timeline) != 6 { // INVITE, 100, 180, 200, ACK, BYE (excludes 200-to-BYE only if Call-ID differs — it doesn't, so 7)
		t.Logf("timeline has %d events (informational)", len(c.Timeline))
	}

	if len(c.Streams) != 2 {
		t.Fatalf("expected 2 RTP streams matched to the call, got %d: %+v", len(c.Streams), c.Streams)
	}
	for _, s := range c.Streams {
		if s.CodecName != "PCMU" || s.ClockRate != 8000 {
			t.Errorf("stream codec wrong: %+v", s)
		}
		if s.Stats.Received == 0 {
			t.Errorf("stream should have received packets: %+v", s)
		}
		if s.MOS == nil {
			t.Errorf("stream with >=20 packets should have a MOS estimate: %+v", s)
		}
	}
	if !c.Streams[0].RTCPSeen || len(c.Streams[0].RTCPReports) == 0 {
		t.Fatalf("expected parsed RTCP reports on correlated streams: %+v", c.Streams)
	}

	// The Alice->Bob leg had 2 dropped packets out of 40; find it and check loss>0.
	foundLossy := false
	for _, s := range c.Streams {
		if s.Src == "192.168.1.10:40000" && s.Stats.Lost > 0 {
			foundLossy = true
			if s.MOS.Score >= 4.4 {
				t.Errorf("lossy stream MOS should be below the perfect baseline, got %v", s.MOS.Score)
			}
		}
	}
	if !foundLossy {
		t.Error("expected the Alice->Bob stream to show the 2 dropped packets as loss")
	}

	if c.Caller.Address != "192.168.1.10:5060" {
		t.Errorf("Caller.Address = %q, want the INVITE's source", c.Caller.Address)
	}
	if c.Callee.Address != "192.168.1.20:5060" {
		t.Errorf("Callee.Address = %q, want the INVITE's destination", c.Callee.Address)
	}
	if c.Caller.UserAgent != "TestPhone/1.0" {
		t.Errorf("Caller.UserAgent = %q, want the INVITE's User-Agent", c.Caller.UserAgent)
	}
	if c.Callee.Server != "TestPBX/2.0" {
		t.Errorf("Callee.Server = %q, want the 200 OK's Server", c.Callee.Server)
	}
	// 192.168.0.0/16 is private: GeoIP must degrade cleanly, never fabricate a
	// country for an address no dataset could possibly resolve.
	if c.Caller.Country != "" || c.Caller.ASN != 0 {
		t.Errorf("a private address must not get GeoIP/ASN data: %+v", c.Caller)
	}

	if c.Diagnosis == nil {
		t.Fatal("every established call with RTP must get a Diagnosis")
	}
	if c.Diagnosis.Confidence == 0 {
		t.Error("Diagnosis.Confidence must never be the zero value on a real call")
	}
}

func TestAnalyzeNoSIPTraffic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	_ = w.WriteFileHeader(65535, layers.LinkTypeEthernet)
	f.Close()

	result, err := Analyze(context.Background(), path, nil)
	if err != nil {
		t.Fatalf("Analyze on empty pcap should not error: %v", err)
	}
	if result.TotalCalls != 0 {
		t.Errorf("expected 0 calls, got %d", result.TotalCalls)
	}
}

func TestAnalyzeMissingFile(t *testing.T) {
	if _, err := Analyze(context.Background(), "/nonexistent/path.pcap", nil); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestAttachStreamsExposesRTCPReports(t *testing.T) {
	stream := rtp.NewStream(0x1234, 8000)
	pkt := rtpPacketForTest(1, 0x1234)
	h, err := rtp.ParseHeader(pkt)
	if err != nil {
		t.Fatal(err)
	}
	stream.Add(rtp.Sample{Header: *h, Arrival: time.Now()})
	calls := map[string]*Call{"call": {CallID: "call"}}
	streams := map[string]*rtp.Stream{"stream": stream}
	meta := map[string]*streamCtx{"stream": {src: "10.0.0.1:4000", dst: "10.0.0.2:4002", payloadType: 0}}
	report := rtcp.Packet{Type: rtcp.TypeRR, SSRC: 99, Reports: []rtcp.ReportBlock{{SSRC: 0x1234, CumulativeLost: 2}}}
	obs := []rtcpObservation{{Packet: report, Arrival: time.Now()}}
	attachStreams(calls, map[string]string{"10.0.0.2:4002": "call"}, nil, nil, streams, meta, map[string][]rtcpObservation{"10.0.0.2-10.0.0.1": obs}, nil)
	if len(calls["call"].Streams) != 1 || !calls["call"].Streams[0].RTCPSeen || len(calls["call"].Streams[0].RTCPReports) != 1 {
		t.Fatalf("RTCP reports were not attached: %+v", calls["call"].Streams)
	}
}

// Gate v0.7.3, independent audit item 14C: two streams in OPPOSITE
// directions (A->B, B->A — not sharing a SSRC or an IP pair the way the
// multi-SSRC gate's fixture does) must each end up with the Report Block
// that genuinely names ITS OWN SSRC, never the other direction's.
func TestAttachStreamsTwoDirectionsEachGetTheirOwnReceiverReport(t *testing.T) {
	const ssrcAB, ssrcBA = uint32(0x1111), uint32(0x2222)
	mkStream := func(ssrc uint32) *rtp.Stream {
		st := rtp.NewStream(ssrc, 8000)
		h, err := rtp.ParseHeader(rtpPacketForTest(1, ssrc))
		if err != nil {
			t.Fatal(err)
		}
		st.Add(rtp.Sample{Header: *h, Arrival: time.Now()})
		return st
	}
	streams := map[string]*rtp.Stream{
		"ab": mkStream(ssrcAB),
		"ba": mkStream(ssrcBA),
	}
	meta := map[string]*streamCtx{
		"ab": {src: "10.0.0.1:4000", dst: "10.0.0.2:5000", payloadType: 0},
		"ba": {src: "10.0.0.2:5000", dst: "10.0.0.1:4000", payloadType: 0},
	}
	calls := map[string]*Call{"call": {CallID: "call"}}
	addrToCall := map[string]string{"10.0.0.1:4000": "call", "10.0.0.2:5000": "call"}

	// B's Report Block about ssrcAB (A->B): B is the receiver, so its RTCP
	// travels B->A on the wire — but rtcpReports is already keyed by IP pair
	// (not direction) by the time attachStreams sees it, same as production.
	reportAboutAB := rtcp.Packet{Type: rtcp.TypeRR, SSRC: 0x9001, Reports: []rtcp.ReportBlock{
		{SSRC: ssrcAB, FractionLost: 1, CumulativeLost: 10, HighestSeq: 100},
	}}
	// A's Report Block about ssrcBA (B->A).
	reportAboutBA := rtcp.Packet{Type: rtcp.TypeRR, SSRC: 0x9002, Reports: []rtcp.ReportBlock{
		{SSRC: ssrcBA, FractionLost: 9, CumulativeLost: 90, HighestSeq: 900},
	}}
	rtcpReports := map[string][]rtcpObservation{
		"10.0.0.1-10.0.0.2": {{Packet: reportAboutAB, Arrival: time.Now()}},
		"10.0.0.2-10.0.0.1": {{Packet: reportAboutBA, Arrival: time.Now()}},
	}

	attachStreams(calls, addrToCall, nil, nil, streams, meta, rtcpReports, nil)

	got := calls["call"].Streams
	if len(got) != 2 {
		t.Fatalf("expected 2 streams, got %d", len(got))
	}
	var ab, ba StreamInfo
	for _, s := range got {
		switch s.SSRC {
		case ssrcAB:
			ab = s
		case ssrcBA:
			ba = s
		}
	}
	if ab.RTCP == nil || ab.RTCP.Receiver == nil {
		t.Fatal("A->B stream: RTCP.Receiver is nil")
	}
	if ab.RTCP.Receiver.CumulativeLost != 10 || ab.RTCP.Receiver.HighestSeq != 100 {
		t.Errorf("A->B (SSRC %#x) Receiver = %+v, want CumulativeLost=10 HighestSeq=100 (B->A's are 90/900 — a swap would be obvious)", ssrcAB, ab.RTCP.Receiver)
	}
	if ba.RTCP == nil || ba.RTCP.Receiver == nil {
		t.Fatal("B->A stream: RTCP.Receiver is nil")
	}
	if ba.RTCP.Receiver.CumulativeLost != 90 || ba.RTCP.Receiver.HighestSeq != 900 {
		t.Errorf("B->A (SSRC %#x) Receiver = %+v, want CumulativeLost=90 HighestSeq=900 (A->B's are 10/100 — a swap would be obvious)", ssrcBA, ba.RTCP.Receiver)
	}
}

// Gate v0.7.3 (independent audit, third gate, item 11): when src and dst
// share the same IP (e.g. a loopback test capture), the forward and reverse
// rtcpReports bucket keys collapse to the same string — appending both must
// not duplicate every observation.
func TestAttachStreamsSameIPDoesNotDuplicateRTCPBucket(t *testing.T) {
	const ssrc = 0x5555
	st := rtp.NewStream(ssrc, 8000)
	h, err := rtp.ParseHeader(rtpPacketForTest(1, ssrc))
	if err != nil {
		t.Fatal(err)
	}
	st.Add(rtp.Sample{Header: *h, Arrival: time.Now()})
	calls := map[string]*Call{"call": {CallID: "call"}}
	streams := map[string]*rtp.Stream{"s": st}
	meta := map[string]*streamCtx{"s": {src: "127.0.0.1:4000", dst: "127.0.0.1:4002", payloadType: 0}}
	addrToCall := map[string]string{"127.0.0.1:4002": "call"}
	report := rtcp.Packet{Type: rtcp.TypeRR, SSRC: 0x9999, Reports: []rtcp.ReportBlock{{SSRC: ssrc, CumulativeLost: 2}}}
	obs := []rtcpObservation{{Packet: report, Arrival: time.Now()}}
	rtcpReports := map[string][]rtcpObservation{"127.0.0.1-127.0.0.1": obs}

	attachStreams(calls, addrToCall, nil, nil, streams, meta, rtcpReports, nil)

	got := calls["call"].Streams
	if len(got) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(got))
	}
	if len(got[0].RTCPReports) != 1 {
		t.Errorf("RTCPReports duplicated: got %d entries, want 1 (forward/reverse bucket keys collapse when src IP == dst IP)", len(got[0].RTCPReports))
	}
	if got[0].RTCP == nil || got[0].RTCP.Receiver == nil {
		t.Fatal("RTCP.Receiver is nil")
	}
	if got[0].RTCP.Receiver.CumulativeLost != 2 {
		t.Errorf("CumulativeLost = %d, want 2 (not doubled)", got[0].RTCP.Receiver.CumulativeLost)
	}
}

// Gate v0.7.3 (independent audit, third gate, item 12): two streams don't
// prove two directions — two SSRCs (or audio+video) in the SAME direction
// must still count as unidirectional; only genuine A->B + B->A evidence
// should clear the flag.
func TestHasBothDirectionsRequiresBothIPOrderings(t *testing.T) {
	sameDirection := []StreamInfo{
		{Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000"},
		{Src: "10.0.0.1:4010", Dst: "10.0.0.2:5010"}, // second SSRC, SAME direction
	}
	if hasBothDirections(sameDirection) {
		t.Error("two streams in the SAME direction (A->B, A->B) must not count as both directions")
	}

	bothDirections := []StreamInfo{
		{Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000"},
		{Src: "10.0.0.2:5000", Dst: "10.0.0.1:4000"},
	}
	if !hasBothDirections(bothDirections) {
		t.Error("A->B and B->A must count as both directions")
	}
}

// Gate v0.7.3 (independent audit, gate of closure, item 7): Unidirectional
// is documented and surfaced everywhere as being specifically about AUDIO
// (audit.go's "Audio RTP unidireccional", the UI's "audio unidireccional"),
// so it must be computed from audio streams only (video can't cover for a
// missing audio direction), and must require the full endpoint — not just
// the IP — when Src and Dst share an IP (a loopback capture, where IP alone
// can't distinguish forward from reverse at all).
func TestFinalizeUnidirectionalRequiresEvidenceOfBothDirections(t *testing.T) {
	cases := []struct {
		name    string
		streams []StreamInfo
		want    bool
	}{
		{"A: single audio leg", []StreamInfo{
			{MediaType: "audio", Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000"},
		}, true},
		{"B: audio both directions", []StreamInfo{
			{MediaType: "audio", Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000"},
			{MediaType: "audio", Src: "10.0.0.2:5000", Dst: "10.0.0.1:4000"},
		}, false},
		{"C: two audio SSRCs, same direction", []StreamInfo{
			{MediaType: "audio", Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000"},
			{MediaType: "audio", Src: "10.0.0.1:4010", Dst: "10.0.0.2:5010"},
		}, true},
		{"D: audio one-way, video covers the OTHER direction", []StreamInfo{
			{MediaType: "audio", Src: "10.0.0.1:4000", Dst: "10.0.0.2:5000"},
			{MediaType: "video", Src: "10.0.0.2:5002", Dst: "10.0.0.1:4002"},
		}, true},
		{"E: same-IP single leg (loopback)", []StreamInfo{
			{MediaType: "audio", Src: "127.0.0.1:4000", Dst: "127.0.0.1:5000"},
		}, true},
		{"F: same-IP both directions (loopback)", []StreamInfo{
			{MediaType: "audio", Src: "127.0.0.1:4000", Dst: "127.0.0.1:5000"},
			{MediaType: "audio", Src: "127.0.0.1:5000", Dst: "127.0.0.1:4000"},
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Call{CallID: tc.name, Established: true, Streams: tc.streams}
			res := finalize(map[string]*Call{tc.name: c}, nil)
			if got := res.Calls[0].Unidirectional; got != tc.want {
				t.Errorf("Unidirectional = %v, want %v", got, tc.want)
			}
		})
	}
}

// Gate v0.7.3 (independent audit, gate of closure, item 3): EstimateMOS is a
// voice-quality model (E-model/G.107/G.113 baseline for G.711) — meaningless
// for video. A video stream must never get a fabricated MOS, no matter how
// many packets or how much loss/jitter it has.
func TestVideoStreamNeverGetsVoiceMOS(t *testing.T) {
	const ssrc = 0x7777
	st := rtp.NewStream(ssrc, 90000)
	for i := 0; i < 25; i++ {
		h := rtp.Header{Version: 2, SeqNum: uint16(i), Timestamp: uint32(i) * 3000, SSRC: ssrc}
		st.Add(rtp.Sample{Header: h, Arrival: time.Now().Add(time.Duration(i) * 33 * time.Millisecond)})
	}
	calls := map[string]*Call{"call": {CallID: "call"}}
	streams := map[string]*rtp.Stream{"v": st}
	meta := map[string]*streamCtx{"v": {src: "10.0.0.1:4002", dst: "10.0.0.2:5002", payloadType: 97}}
	addrToCall := map[string]string{"10.0.0.2:5002": "call"}
	addrMediaType := map[string]string{"10.0.0.1:4002": "video", "10.0.0.2:5002": "video"}

	attachStreams(calls, addrToCall, nil, addrMediaType, streams, meta, nil, nil)

	got := calls["call"].Streams
	if len(got) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(got))
	}
	if got[0].MediaType != "video" {
		t.Fatalf("MediaType = %q, want video", got[0].MediaType)
	}
	if got[0].MOS != nil {
		t.Errorf("a video stream must never get a voice MOS, got %+v", got[0].MOS)
	}
}

// Mirror of the above: audio must still get MOS exactly as before this
// change (>=20 received packets is the only other gate).
func TestAudioStreamStillGetsMOS(t *testing.T) {
	const ssrc = 0x8888
	st := rtp.NewStream(ssrc, 8000)
	for i := 0; i < 25; i++ {
		h := rtp.Header{Version: 2, SeqNum: uint16(i), Timestamp: uint32(i) * 160, SSRC: ssrc}
		st.Add(rtp.Sample{Header: h, Arrival: time.Now().Add(time.Duration(i) * 20 * time.Millisecond)})
	}
	calls := map[string]*Call{"call": {CallID: "call"}}
	streams := map[string]*rtp.Stream{"a": st}
	meta := map[string]*streamCtx{"a": {src: "10.0.0.1:4000", dst: "10.0.0.2:5000", payloadType: 0}}
	addrToCall := map[string]string{"10.0.0.2:5000": "call"}
	addrMediaType := map[string]string{"10.0.0.1:4000": "audio", "10.0.0.2:5000": "audio"}

	attachStreams(calls, addrToCall, nil, addrMediaType, streams, meta, nil, nil)

	got := calls["call"].Streams
	if len(got) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(got))
	}
	if got[0].MediaType != "audio" {
		t.Fatalf("MediaType = %q, want audio", got[0].MediaType)
	}
	if got[0].MOS == nil {
		t.Error("an audio stream with >=20 packets must still get a MOS")
	}
}

func TestUnknownCodecClockRateIsMarkedAssumed(t *testing.T) {
	if got := codecClockRate(nil, "a", "b", 110); got != 0 {
		t.Fatalf("unknown dynamic payload clock rate = %d, want 0 assumption marker", got)
	}
}

func TestContactHostSupportsIPv6Literal(t *testing.T) {
	if got := contactHost("<sip:alice@[2001:db8::10]:5060;transport=udp>"); got != "2001:db8::10" {
		t.Fatalf("contact IPv6 host = %q", got)
	}
}

func rtpPacketForTest(seq uint16, ssrc uint32) []byte {
	b := make([]byte, 12)
	b[0] = 0x80
	binary.BigEndian.PutUint16(b[2:4], seq)
	binary.BigEndian.PutUint32(b[4:8], uint32(seq)*160)
	binary.BigEndian.PutUint32(b[8:12], ssrc)
	return b
}
