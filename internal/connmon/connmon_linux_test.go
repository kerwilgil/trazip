//go:build linux

package connmon

import "testing"

func TestDecodeHexAddr(t *testing.T) {
	cases := []struct {
		in       string
		wantAddr string
		wantPort int
	}{
		{"0100007F:0050", "127.0.0.1", 80}, // loopback:80
		{"00000000:1F90", "0.0.0.0", 8080}, // any:8080
		{"0100007F:1BB1", "127.0.0.1", 7089},
	}
	for _, c := range cases {
		addr, port := decodeHexAddr(c.in)
		if addr != c.wantAddr || port != c.wantPort {
			t.Errorf("decodeHexAddr(%q) = (%q, %d), want (%q, %d)", c.in, addr, port, c.wantAddr, c.wantPort)
		}
	}
}

func TestParseProcNetMissingFile(t *testing.T) {
	if _, err := parseProcNet("/proc/net/does-not-exist", "tcp"); err == nil {
		t.Error("expected error for missing file")
	}
}
