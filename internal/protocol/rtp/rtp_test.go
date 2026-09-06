package rtp

import (
	"encoding/binary"
	"testing"
	"time"
)

// buildPacket constructs a minimal RTP packet (12-byte header, no CSRC/ext).
func buildPacket(pt int, seq uint16, ts uint32, ssrc uint32, payload []byte) []byte {
	b := make([]byte, 12+len(payload))
	b[0] = 0x80 // version=2, no padding/extension/CSRC
	b[1] = byte(pt)
	binary.BigEndian.PutUint16(b[2:4], seq)
	binary.BigEndian.PutUint32(b[4:8], ts)
	binary.BigEndian.PutUint32(b[8:12], ssrc)
	copy(b[12:], payload)
	return b
}

func TestParseHeader(t *testing.T) {
	pkt := buildPacket(0, 1000, 160000, 0xdeadbeef, []byte{1, 2, 3, 4})
	h, err := ParseHeader(pkt)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.Version != 2 || h.PayloadType != 0 || h.SeqNum != 1000 || h.Timestamp != 160000 || h.SSRC != 0xdeadbeef {
		t.Errorf("header wrong: %+v", h)
	}
	if h.HeaderLen != 12 {
		t.Errorf("HeaderLen = %d, want 12", h.HeaderLen)
	}
	payload := Payload(pkt, h)
	if len(payload) != 4 || payload[0] != 1 {
		t.Errorf("payload wrong: %v", payload)
	}
}

func TestParseHeaderRejectsRTCP(t *testing.T) {
	// RTCP SR: version=2 in byte0, PT=200 (0xC8) in byte1.
	pkt := []byte{0x80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := ParseHeader(pkt); err == nil {
		t.Error("ParseHeader should reject RTCP-range PT")
	}
}

func TestParseHeaderRejectsShortOrBadVersion(t *testing.T) {
	if _, err := ParseHeader([]byte{1, 2, 3}); err == nil {
		t.Error("should reject too-short payload")
	}
	bad := buildPacket(0, 0, 0, 0, nil)
	bad[0] = 0x00 // version 0
	if _, err := ParseHeader(bad); err == nil {
		t.Error("should reject wrong version")
	}
}

func TestStreamNormalSequence(t *testing.T) {
	s := NewStream(0x1234, 8000)
	base := time.Now()
	for i := 0; i < 10; i++ {
		pkt := buildPacket(0, uint16(1000+i), uint32(160000+i*160), 0x1234, nil)
		h, _ := ParseHeader(pkt)
		s.Add(Sample{Header: *h, Arrival: base.Add(time.Duration(i) * 20 * time.Millisecond)})
	}
	snap := s.Snapshot()
	if snap.Received != 10 || snap.Expected != 10 || snap.Lost != 0 {
		t.Errorf("expected 10/10/0, got recv=%d exp=%d lost=%d", snap.Received, snap.Expected, snap.Lost)
	}
	if snap.LossPct != 0 {
		t.Errorf("lossPct = %v, want 0", snap.LossPct)
	}
}

func TestStreamLoss(t *testing.T) {
	s := NewStream(1, 8000)
	base := time.Now()
	seqs := []uint16{100, 101, 103, 104} // 102 missing
	for i, seq := range seqs {
		pkt := buildPacket(0, seq, uint32(seq)*160, 1, nil)
		h, _ := ParseHeader(pkt)
		s.Add(Sample{Header: *h, Arrival: base.Add(time.Duration(i) * 20 * time.Millisecond)})
	}
	snap := s.Snapshot()
	if snap.Received != 4 || snap.Expected != 5 || snap.Lost != 1 {
		t.Errorf("expected recv=4 exp=5 lost=1, got %+v", snap)
	}
}

func TestStreamDuplicateAndReorder(t *testing.T) {
	s := NewStream(1, 8000)
	base := time.Now()
	add := func(seq uint16, dt time.Duration) {
		pkt := buildPacket(0, seq, uint32(seq)*160, 1, nil)
		h, _ := ParseHeader(pkt)
		s.Add(Sample{Header: *h, Arrival: base.Add(dt)})
	}
	add(100, 0)
	add(101, 20*time.Millisecond)
	add(101, 25*time.Millisecond) // duplicate
	add(99, 30*time.Millisecond)  // reordered (arrived after 101 but seq is lower)

	snap := s.Snapshot()
	if snap.Duplicates != 1 {
		t.Errorf("duplicates = %d, want 1", snap.Duplicates)
	}
	if snap.Reordered != 1 {
		t.Errorf("reordered = %d, want 1", snap.Reordered)
	}
	if snap.Received != 3 { // 100, 101, 99 (dup not counted as received)
		t.Errorf("received = %d, want 3", snap.Received)
	}
}

func TestStreamSequenceWraparound(t *testing.T) {
	s := NewStream(1, 8000)
	base := time.Now()
	seqs := []uint16{65533, 65534, 65535, 0, 1, 2}
	for i, seq := range seqs {
		pkt := buildPacket(0, seq, uint32(i)*160, 1, nil)
		h, _ := ParseHeader(pkt)
		s.Add(Sample{Header: *h, Arrival: base.Add(time.Duration(i) * 20 * time.Millisecond)})
	}
	snap := s.Snapshot()
	if snap.Received != 6 {
		t.Errorf("received = %d, want 6 (wraparound should not break counting)", snap.Received)
	}
	if snap.Lost != 0 {
		t.Errorf("lost = %d, want 0 across wraparound", snap.Lost)
	}
}

func TestStreamJitterIncreasesWithVariableDelay(t *testing.T) {
	s := NewStream(1, 8000)
	base := time.Now()
	// Perfectly regular 20ms packets (160 samples @ 8kHz) → jitter should stay ~0.
	for i := 0; i < 5; i++ {
		pkt := buildPacket(0, uint16(i), uint32(i*160), 1, nil)
		h, _ := ParseHeader(pkt)
		s.Add(Sample{Header: *h, Arrival: base.Add(time.Duration(i) * 20 * time.Millisecond)})
	}
	regular := s.Snapshot().JitterMs

	s2 := NewStream(2, 8000)
	delays := []time.Duration{0, 20 * time.Millisecond, 60 * time.Millisecond, 65 * time.Millisecond, 120 * time.Millisecond}
	for i, d := range delays {
		pkt := buildPacket(0, uint16(i), uint32(i*160), 2, nil)
		h, _ := ParseHeader(pkt)
		s2.Add(Sample{Header: *h, Arrival: base.Add(d)})
	}
	jittery := s2.Snapshot().JitterMs

	if regular > 1.0 {
		t.Errorf("regular spacing jitter = %v, want ~0", regular)
	}
	if jittery <= regular {
		t.Errorf("jittery stream jitter (%v) should exceed regular stream jitter (%v)", jittery, regular)
	}
}

func TestStreamReportsClockAssumptionDurationAndSkew(t *testing.T) {
	s := NewStream(7, 0)
	base := time.Now()
	for i, arrivalMs := range []int{0, 20, 45} {
		pkt := buildPacket(0, uint16(i), uint32(i*160), 7, nil)
		h, _ := ParseHeader(pkt)
		s.Add(Sample{Header: *h, Arrival: base.Add(time.Duration(arrivalMs) * time.Millisecond)})
	}
	snap := s.Snapshot()
	if !snap.ClockAssumed {
		t.Fatal("defaulted clock rate must be marked as assumed")
	}
	if snap.ArrivalDurationMs != 45 || snap.RTPDurationMs != 40 || snap.ClockSkewMs != 5 {
		t.Fatalf("unexpected timing metrics: %+v", snap)
	}
}

func TestStreamKeepsInitialPayloadTypeZero(t *testing.T) {
	s := NewStream(8, 8000)
	base := time.Now()
	for i, pt := range []int{0, 8} {
		pkt := buildPacket(pt, uint16(i), uint32(i*160), 8, nil)
		h, _ := ParseHeader(pkt)
		s.Add(Sample{Header: *h, Arrival: base.Add(time.Duration(i) * 20 * time.Millisecond)})
	}
	if got := s.Snapshot().PayloadType; got != 0 {
		t.Fatalf("payload type = %d, want initial PT 0", got)
	}
}

func TestDecodeDTMFEvent(t *testing.T) {
	// event=5 ('5'), end bit set, volume=10, duration=800
	payload := []byte{5, 0x80 | 10, 0x03, 0x20}
	ev, ok := DecodeDTMFEvent(payload)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ev.Digit != "5" || !ev.EndOfEvent || ev.Volume != 10 || ev.Duration != 0x0320 {
		t.Errorf("DTMF decode wrong: %+v", ev)
	}
	if _, ok := DecodeDTMFEvent([]byte{1, 2}); ok {
		t.Error("short payload should fail")
	}
}
