package session

import (
	"context"
	"testing"
)

func TestBeginActiveEnforcesAuthorizationAndLifecycle(t *testing.T) {
	m := NewManager()
	if _, err := m.BeginActive(context.Background(), "scan", "192.0.2.1", false); err == nil {
		t.Fatal("expected missing authorization to fail")
	}
	s, err := m.BeginActive(context.Background(), "scan", "192.0.2.1", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Get(s.ID); !ok {
		t.Fatal("live session was not registered")
	}
	m.Complete(s.ID)
	if _, ok := m.Get(s.ID); ok {
		t.Fatal("completed session remained live")
	}
	if s.State() != StateFinished {
		t.Fatalf("state = %s, want finished", s.State())
	}
}

// TestBeginActiveAcceptsCIDRTarget reproduces a bug reported against the LAN
// scanner: StartLanScan passes the whole range spec (e.g. "10.101.0.0/22")
// as target, so BeginActive authorizes and self-checks that exact CIDR
// string — before the fix (scope.Guard.CheckTarget not handling CIDR
// input), this always failed with "target outside authorized scope",
// making every active LAN scan with a CIDR range spec unusable.
func TestBeginActiveAcceptsCIDRTarget(t *testing.T) {
	m := NewManager()
	s, err := m.BeginActive(context.Background(), "lanscan", "10.101.0.0/22", true)
	if err != nil {
		t.Fatalf("BeginActive with a CIDR target: %v", err)
	}
	if _, ok := m.Get(s.ID); !ok {
		t.Fatal("live session was not registered")
	}
}

func TestCancelAllCancelsEverySession(t *testing.T) {
	m := NewManager()
	a := m.New(context.Background(), "a")
	b := m.New(context.Background(), "b")
	m.CancelAll()
	if a.State() != StateCanceled || b.State() != StateCanceled {
		t.Fatalf("states = %s, %s", a.State(), b.State())
	}
	if len(m.List()) != 0 {
		t.Fatal("cancelled sessions remained live")
	}
}
