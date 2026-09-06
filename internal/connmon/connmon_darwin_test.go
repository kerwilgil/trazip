//go:build darwin

package connmon

import "testing"

func TestParseLsof(t *testing.T) {
	sample := `COMMAND   PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Spotify  1234 kerwil   45u  IPv4 0x1234567890abcdef      0t0  TCP 192.168.1.5:54321->172.217.10.14:443 (ESTABLISHED)
sshd      567 root      3u  IPv6 0x0000000000000000      0t0  TCP *:22 (LISTEN)
mDNSRes    89 root      8u  IPv4 0x00000000              0t0  UDP *:5353
`
	conns := parseLsof(sample)
	if len(conns) != 3 {
		t.Fatalf("got %d connections, want 3", len(conns))
	}

	c := conns[0]
	if c.Process != "Spotify" || c.PID != 1234 || c.Proto != "tcp" {
		t.Errorf("row0 basic fields wrong: %+v", c)
	}
	if c.LocalAddr != "192.168.1.5" || c.LocalPort != 54321 {
		t.Errorf("row0 local wrong: %+v", c)
	}
	if c.RemoteAddr != "172.217.10.14" || c.RemotePort != 443 {
		t.Errorf("row0 remote wrong: %+v", c)
	}
	if c.State != "established" {
		t.Errorf("row0 state = %q, want established", c.State)
	}

	c = conns[1]
	if c.Process != "sshd" || c.LocalAddr != "0.0.0.0" || c.LocalPort != 22 || c.State != "listen" {
		t.Errorf("row1 (listen) wrong: %+v", c)
	}

	c = conns[2]
	if c.Proto != "udp" || c.LocalPort != 5353 || c.State != "" {
		t.Errorf("row2 (udp, no state) wrong: %+v", c)
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"1.2.3.4:443", "1.2.3.4", 443},
		{"*:8080", "0.0.0.0", 8080},
		{"fe80::1:53", "fe80::1", 53},
		{"[fe80::1]:53", "fe80::1", 53},
	}
	for _, c := range cases {
		host, port := splitHostPort(c.in)
		if host != c.wantHost || port != c.wantPort {
			t.Errorf("splitHostPort(%q) = (%q, %d), want (%q, %d)", c.in, host, port, c.wantHost, c.wantPort)
		}
	}
}
