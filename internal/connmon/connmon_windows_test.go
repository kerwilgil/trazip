//go:build windows

package connmon

import "testing"

// TestList is a light smoke test against the real OS tables (no mocking the
// IP Helper API is practical here) — it only asserts the call succeeds and
// returns internally consistent rows, not specific connections, since those
// vary with whatever is running on the machine.
func TestList(t *testing.T) {
	conns, err := List()
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	for _, c := range conns {
		if c.Proto != "tcp" && c.Proto != "udp" {
			t.Errorf("unexpected proto %q", c.Proto)
		}
		if c.LocalPort < 0 || c.LocalPort > 65535 {
			t.Errorf("local port out of range: %d", c.LocalPort)
		}
		if c.RemotePort < 0 || c.RemotePort > 65535 {
			t.Errorf("remote port out of range: %d", c.RemotePort)
		}
		if c.Proto == "tcp" && c.State == "" {
			t.Errorf("tcp row missing state: %+v", c)
		}
	}
}

func TestSwapPort(t *testing.T) {
	// 443 (0x01BB) stored big-endian in the low 16 bits, as the MIB tables do.
	raw := uint32(0xBB01)
	if got := swapPort(raw); got != 443 {
		t.Errorf("swapPort(0x%X) = %d, want 443", raw, got)
	}
}
