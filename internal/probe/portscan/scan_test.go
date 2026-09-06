package portscan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestScanLocal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// A port that is free then closed → connection refused → closed.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()

	var mu sync.Mutex
	states := map[int]string{}
	sum, _, err := Run(context.Background(), Config{
		Target:      "127.0.0.1",
		Ports:       []int{openPort, closedPort},
		Timeout:     time.Second,
		Concurrency: 4,
		RatePerSec:  5000,
	}, func(r PortResult) {
		mu.Lock()
		states[r.Port] = r.State
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	if states[openPort] != "open" {
		t.Errorf("open port %d state = %q, want open", openPort, states[openPort])
	}
	if states[closedPort] != "closed" {
		t.Errorf("closed port %d state = %q, want closed", closedPort, states[closedPort])
	}
	if sum.Scanned != 2 || sum.OpenN != 1 {
		t.Errorf("summary wrong: %+v", sum)
	}
}

func TestClassifyDialError(t *testing.T) {
	refused := fmt.Errorf("wrapper: %w", &net.OpError{Err: fmt.Errorf("syscall: %w", syscall.ECONNREFUSED)})
	if got := classifyDialError(refused); got != Closed {
		t.Fatalf("refused state = %q, want %q", got, Closed)
	}
	if got := classifyDialError(context.DeadlineExceeded); got != Filtered {
		t.Fatalf("timeout state = %q, want %q", got, Filtered)
	}
}

func TestConfiguredRateLimitsDispatch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	ports := []int{port, port, port, port}
	start := time.Now()
	sum, _, err := Run(context.Background(), Config{
		Target: "127.0.0.1", Ports: ports, Timeout: 100 * time.Millisecond,
		Concurrency: 4, RatePerSec: 20,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 180*time.Millisecond {
		t.Fatalf("scan dispatched too quickly: %v", elapsed)
	}
	if sum.RatePerSec != 20 || sum.Concurrency != 4 || sum.TimeoutMs != 100 {
		t.Fatalf("telemetry missing: %+v", sum)
	}
}

func TestTop100AndService(t *testing.T) {
	ports := Top100()
	if len(ports) < 80 {
		t.Errorf("Top100 too small: %d", len(ports))
	}
	for i := 1; i < len(ports); i++ {
		if ports[i] <= ports[i-1] {
			t.Fatal("Top100 not sorted ascending")
		}
	}
	if ServiceName(443) != "https" || ServiceName(22) != "ssh" {
		t.Error("service names wrong")
	}
}

func TestProfiles(t *testing.T) {
	if got := Quick(); len(got) != 25 {
		t.Fatalf("quick profile has %d ports, want 25", len(got))
	}
	if got := Extended(); len(got) != 1000 || got[0] != 1 || got[999] != 1000 {
		t.Fatalf("extended profile wrong: len=%d", len(got))
	}
}

func TestParseRange(t *testing.T) {
	if r := ParseRange(80, 82); len(r) != 3 || r[0] != 80 || r[2] != 82 {
		t.Errorf("range wrong: %v", r)
	}
	if ParseRange(90, 80) != nil {
		t.Error("invalid range should be nil")
	}
}
