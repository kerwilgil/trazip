package rtcp

import (
	"encoding/binary"
	"testing"
)

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func reportBlock(ssrc uint32, fractionLost8bit uint8, cumLost int32, highestSeq, jitter, lsr, dlsr uint32) []byte {
	b := make([]byte, 24)
	copy(b[0:4], u32(ssrc))
	b[4] = fractionLost8bit
	// 24-bit cumulative lost, big-endian, two's complement.
	b[5] = byte(cumLost >> 16)
	b[6] = byte(cumLost >> 8)
	b[7] = byte(cumLost)
	copy(b[8:12], u32(highestSeq))
	copy(b[12:16], u32(jitter))
	copy(b[16:20], u32(lsr))
	copy(b[20:24], u32(dlsr))
	return b
}

func buildSR(ssrc uint32, ntpHi, ntpLo, rtpTS, pktCount, octetCount uint32, blocks [][]byte) []byte {
	var body []byte
	body = append(body, u32(ssrc)...)
	body = append(body, u32(ntpHi)...)
	body = append(body, u32(ntpLo)...)
	body = append(body, u32(rtpTS)...)
	body = append(body, u32(pktCount)...)
	body = append(body, u32(octetCount)...)
	for _, blk := range blocks {
		body = append(body, blk...)
	}
	return wrapHeader(0x80|byte(len(blocks)), TypeSR, body)
}

func buildRR(ssrc uint32, blocks [][]byte) []byte {
	var body []byte
	body = append(body, u32(ssrc)...)
	for _, blk := range blocks {
		body = append(body, blk...)
	}
	return wrapHeader(0x80|byte(len(blocks)), TypeRR, body)
}

func buildBYE(ssrc uint32) []byte {
	return wrapHeader(0x81, TypeBYE, u32(ssrc))
}

func wrapHeader(byte0 byte, pt int, body []byte) []byte {
	total := 4 + len(body)
	// Pad to a multiple of 4 if needed (shouldn't happen with our fixed-size builders).
	for total%4 != 0 {
		body = append(body, 0)
		total++
	}
	lengthWords := uint16(total/4 - 1)
	pkt := make([]byte, 4, total)
	pkt[0] = byte0
	pkt[1] = byte(pt)
	binary.BigEndian.PutUint16(pkt[2:4], lengthWords)
	pkt = append(pkt, body...)
	return pkt
}

func TestParseSR(t *testing.T) {
	blk := reportBlock(0xaaaa, 26, -5, 5000, 12345, 0x11111111, 0x22222222) // 26/256*100 ≈ 10.15%
	pkt := buildSR(0xdeadbeef, 0xAABBCCDD, 0x11223344, 160000, 1000, 160000, [][]byte{blk})

	pkts, err := ParseCompound(pkt)
	if err != nil {
		t.Fatalf("ParseCompound: %v", err)
	}
	if len(pkts) != 1 || pkts[0].Type != TypeSR {
		t.Fatalf("expected 1 SR packet, got %+v", pkts)
	}
	sr := pkts[0]
	if sr.SSRC != 0xdeadbeef || sr.RTPTimestamp != 160000 || sr.PacketCount != 1000 || sr.OctetCount != 160000 {
		t.Errorf("SR fields wrong: %+v", sr)
	}
	if sr.NTPSeconds != 0xAABBCCDD || sr.NTPFraction != 0x11223344 {
		t.Errorf("NTP fields wrong: sec=%x frac=%x", sr.NTPSeconds, sr.NTPFraction)
	}
	if len(sr.Reports) != 1 {
		t.Fatalf("expected 1 report block, got %d", len(sr.Reports))
	}
	r := sr.Reports[0]
	if r.SSRC != 0xaaaa {
		t.Errorf("report SSRC = %x", r.SSRC)
	}
	if r.FractionLost < 10.0 || r.FractionLost > 10.3 {
		t.Errorf("fractionLost = %v, want ~10.15%%", r.FractionLost)
	}
	if r.CumulativeLost != -5 {
		t.Errorf("cumulativeLost = %d, want -5", r.CumulativeLost)
	}
	if r.HighestSeq != 5000 || r.JitterTicks != 12345 {
		t.Errorf("report fields wrong: %+v", r)
	}
}

func TestParseRR(t *testing.T) {
	blk := reportBlock(1, 0, 0, 100, 0, 0, 0)
	pkt := buildRR(42, [][]byte{blk})
	pkts, err := ParseCompound(pkt)
	if err != nil {
		t.Fatalf("ParseCompound: %v", err)
	}
	if len(pkts) != 1 || pkts[0].Type != TypeRR || pkts[0].SSRC != 42 {
		t.Errorf("RR wrong: %+v", pkts)
	}
}

func TestParseCompoundMultiplePackets(t *testing.T) {
	sr := buildSR(1, 0, 0, 0, 0, 0, nil)
	bye := buildBYE(1)
	compound := append(append([]byte{}, sr...), bye...)

	pkts, err := ParseCompound(compound)
	if err != nil {
		t.Fatalf("ParseCompound: %v", err)
	}
	if len(pkts) != 2 {
		t.Fatalf("expected 2 packets in compound, got %d: %+v", len(pkts), pkts)
	}
	if pkts[0].Type != TypeSR || pkts[1].Type != TypeBYE {
		t.Errorf("types wrong: %v %v", pkts[0].Type, pkts[1].Type)
	}
}

func TestParseRobustGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {}, {0x00}, {0x80, 200, 0xff, 0xff}} {
		if _, err := ParseCompound(b); err == nil {
			t.Errorf("ParseCompound(%v) should error on garbage/truncated input", b)
		}
	}
}

func TestSignExtend24(t *testing.T) {
	cases := []struct {
		b    [3]byte
		want int32
	}{
		{[3]byte{0x00, 0x00, 0x05}, 5},
		{[3]byte{0xFF, 0xFF, 0xFB}, -5},
		{[3]byte{0x00, 0x00, 0x00}, 0},
	}
	for _, c := range cases {
		got := signExtend24(c.b[:])
		if got != c.want {
			t.Errorf("signExtend24(%v) = %d, want %d", c.b, got, c.want)
		}
	}
}
