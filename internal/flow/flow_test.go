package flow

import (
	"testing"

	"trazip/internal/packet"
)

func s(transport, src string, sp uint16, dst string, dp uint16, proto string, length int, tu float64, info string) packet.Summary {
	return packet.Summary{
		Transport: transport, Src: src, SrcPort: sp, Dst: dst, DstPort: dp,
		Proto: proto, Length: length, TimeUnix: tu, Info: info,
	}
}

func TestFlowBidirectional(t *testing.T) {
	tbl := New()
	tbl.Add(s("tcp", "192.168.1.10", 51000, "8.8.8.8", 443, "TCP", 100, 1.0, "[SYN]"))
	tbl.Add(s("tcp", "8.8.8.8", 443, "192.168.1.10", 51000, "TCP", 60, 2.0, "[SYN,ACK]"))
	tbl.Add(s("tcp", "192.168.1.10", 51000, "8.8.8.8", 443, "TCP", 40, 3.0, "[RST]"))

	if tbl.Len() != 1 {
		t.Fatalf("expected 1 flow, got %d", tbl.Len())
	}
	f := tbl.Flows()[0]
	if f.AAddr != "192.168.1.10" || f.APort != 51000 {
		t.Errorf("initiator wrong: %s:%d", f.AAddr, f.APort)
	}
	if f.Packets != 3 || f.PktsAB != 2 || f.PktsBA != 1 {
		t.Errorf("packet counts wrong: total=%d ab=%d ba=%d", f.Packets, f.PktsAB, f.PktsBA)
	}
	if f.BytesAB != 140 || f.BytesBA != 60 || f.Bytes != 200 {
		t.Errorf("byte counts wrong: ab=%d ba=%d total=%d", f.BytesAB, f.BytesBA, f.Bytes)
	}
	if f.DurationSec != 2.0 {
		t.Errorf("duration = %v, want 2.0", f.DurationSec)
	}
	if f.Resets != 1 {
		t.Errorf("resets = %d, want 1", f.Resets)
	}
}

func TestFlowSeparatesProtocols(t *testing.T) {
	tbl := New()
	tbl.Add(s("tcp", "10.0.0.1", 100, "10.0.0.2", 200, "TCP", 50, 1.0, ""))
	tbl.Add(s("udp", "10.0.0.1", 100, "10.0.0.2", 200, "UDP", 50, 1.0, ""))
	if tbl.Len() != 2 {
		t.Errorf("expected 2 flows (tcp+udp), got %d", tbl.Len())
	}
}

func TestFlowApps(t *testing.T) {
	tbl := New()
	tbl.Add(s("udp", "10.0.0.1", 53000, "8.8.8.8", 53, "DNS", 80, 1.0, "query A example.com"))
	f := tbl.Flows()[0]
	if len(f.Apps) != 1 || f.Apps[0] != "DNS" {
		t.Errorf("apps = %v, want [DNS]", f.Apps)
	}
}

func TestFlowIgnoresNoTransport(t *testing.T) {
	tbl := New()
	tbl.Add(s("", "a", 0, "b", 0, "ARP", 42, 1.0, ""))
	if tbl.Len() != 0 {
		t.Errorf("ARP (no transport) should not create a flow, got %d", tbl.Len())
	}
}
