package lan

import (
	"context"
	"testing"
	"time"
)

func TestParseTargetsSingleIP(t *testing.T) {
	got, err := ParseTargets("192.168.1.5")
	if err != nil {
		t.Fatalf("ParseTargets: %v", err)
	}
	if len(got) != 1 || got[0].String() != "192.168.1.5" {
		t.Fatalf("got %v, want [192.168.1.5]", got)
	}
}

func TestParseTargetsCIDR30(t *testing.T) {
	// /30 has 4 addresses total; network+broadcast excluded, so exactly 2 hosts.
	got, err := ParseTargets("192.168.1.0/30")
	if err != nil {
		t.Fatalf("ParseTargets: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d addrs, want 2: %v", len(got), got)
	}
	if got[0].String() != "192.168.1.1" || got[1].String() != "192.168.1.2" {
		t.Fatalf("got %v, want [192.168.1.1 192.168.1.2]", got)
	}
}

func TestParseTargetsCIDR32(t *testing.T) {
	// /32 is a single host — no network/broadcast to exclude.
	got, err := ParseTargets("192.168.1.7/32")
	if err != nil {
		t.Fatalf("ParseTargets: %v", err)
	}
	if len(got) != 1 || got[0].String() != "192.168.1.7" {
		t.Fatalf("got %v, want [192.168.1.7]", got)
	}
}

func TestParseTargetsCIDRTooLarge(t *testing.T) {
	if _, err := ParseTargets("10.0.0.0/8"); err == nil {
		t.Fatal("expected an error for a /8 (16M addresses), got nil")
	}
}

func TestParseTargetsRangeFull(t *testing.T) {
	got, err := ParseTargets("192.168.1.10-192.168.1.12")
	if err != nil {
		t.Fatalf("ParseTargets: %v", err)
	}
	want := []string{"192.168.1.10", "192.168.1.11", "192.168.1.12"}
	if len(got) != len(want) {
		t.Fatalf("got %d addrs, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Errorf("index %d: got %s, want %s", i, got[i], w)
		}
	}
}

func TestParseTargetsRangeShortForm(t *testing.T) {
	got, err := ParseTargets("192.168.1.250-253")
	if err != nil {
		t.Fatalf("ParseTargets: %v", err)
	}
	want := []string{"192.168.1.250", "192.168.1.251", "192.168.1.252", "192.168.1.253"}
	if len(got) != len(want) {
		t.Fatalf("got %d addrs, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Errorf("index %d: got %s, want %s", i, got[i], w)
		}
	}
}

func TestParseTargetsRangeReversed(t *testing.T) {
	if _, err := ParseTargets("192.168.1.20-192.168.1.10"); err == nil {
		t.Fatal("expected an error when the end address is before the start, got nil")
	}
}

func TestParseTargetsInvalid(t *testing.T) {
	for _, spec := range []string{"", "not-an-ip", "192.168.1.0/abc", "192.168.1.1-abc"} {
		if _, err := ParseTargets(spec); err == nil {
			t.Errorf("ParseTargets(%q): expected an error, got nil", spec)
		}
	}
}

func TestOSGuessFromTTL(t *testing.T) {
	cases := map[int]string{
		0:   "",
		64:  "Linux/Unix/Android/macOS (estimado por TTL)",
		60:  "Linux/Unix/Android/macOS (estimado por TTL)",
		128: "Windows (estimado por TTL)",
		120: "Windows (estimado por TTL)",
		255: "Dispositivo de red (estimado por TTL)",
	}
	for ttl, want := range cases {
		if got := osGuessFromTTL(ttl); got != want {
			t.Errorf("osGuessFromTTL(%d) = %q, want %q", ttl, got, want)
		}
	}
}

// TestScanUnreachableRangeCompletes exercises the full Scan() pipeline
// against a tiny, almost-certainly-unreachable /30 in a reserved test range
// (RFC 5737 TEST-NET-1), so it should complete quickly with zero up hosts —
// this is what catches goroutine leaks/deadlocks in the worker pool, not a
// real network assertion.
func TestScanUnreachableRangeCompletes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var hostCalls, progressCalls int
	sum, err := Scan(ctx, "203.0.113.0/30", "", func(HostResult) {
		hostCalls++
	}, func(scanned, total int) {
		progressCalls++
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if sum.TotalIPs != 2 {
		t.Errorf("TotalIPs = %d, want 2", sum.TotalIPs)
	}
	if progressCalls != 2 {
		t.Errorf("progress callbacks = %d, want 2", progressCalls)
	}
	if hostCalls != 0 || sum.UpCount != 0 {
		t.Errorf("expected 0 up hosts in a reserved test range, got hostCalls=%d UpCount=%d", hostCalls, sum.UpCount)
	}
}
