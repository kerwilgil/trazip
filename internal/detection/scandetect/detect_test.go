package scandetect

import (
	"fmt"
	"testing"

	"trazip/internal/packet"
)

func syn(src, dst string, port uint16, sec float64) packet.Summary {
	return packet.Summary{
		Src: src, Dst: dst, DstPort: port, Transport: "tcp", TCPFlags: []string{"SYN"},
		Time: fmt.Sprintf("2026-01-01T12:00:%06.3fZ", sec), TimeUnix: sec,
	}
}

func TestDetectsVerticalAndHorizontalScans(t *testing.T) {
	d := New()
	for port := uint16(20); port < 32; port++ {
		d.Add(syn("10.0.0.10", "10.0.0.20", port, float64(port)/10))
	}
	for host := 1; host <= 11; host++ {
		d.Add(syn("10.0.0.30", fmt.Sprintf("10.0.1.%d", host), 445, 10+float64(host)/10))
	}
	res := d.Result()
	if res.Vertical != 1 || res.Horizontal != 1 || len(res.Findings) != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestIgnoresEstablishedTrafficAndSmallFanout(t *testing.T) {
	d := New()
	for port := uint16(1); port <= 9; port++ {
		d.Add(syn("192.0.2.1", "192.0.2.2", port, float64(port)))
	}
	d.Add(packet.Summary{Src: "192.0.2.1", Dst: "192.0.2.2", DstPort: 443, Transport: "tcp", TCPFlags: []string{"SYN", "ACK"}})
	res := d.Result()
	if len(res.Findings) != 0 || res.InitialSYN != 9 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestEvidenceSamplesAreBounded(t *testing.T) {
	d := New()
	for port := uint16(1); port <= 100; port++ {
		d.Add(syn("198.51.100.1", "198.51.100.2", port, float64(port)/100))
	}
	res := d.Result()
	if len(res.Findings) != 1 || len(res.Findings[0].Ports) != maxEvidenceValues {
		t.Fatalf("unexpected bounded evidence: %+v", res)
	}
}
