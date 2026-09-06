package bgp

import (
	"context"
	"sync"
	"testing"
	"time"
)

// --- pure backoff math ---

func TestBackoffDuration_Sequence(t *testing.T) {
	want := []time.Duration{
		1: time.Second,
		2: 2 * time.Second,
		3: 4 * time.Second,
		4: 8 * time.Second,
		5: 16 * time.Second,
		6: 30 * time.Second,
		7: 30 * time.Second,
		8: 30 * time.Second,
	}
	for attempt := 1; attempt <= 8; attempt++ {
		got := backoffDuration(attempt)
		if got != want[attempt] {
			t.Errorf("backoffDuration(%d) = %v, want %v", attempt, got, want[attempt])
		}
	}
}

func TestBackoffDuration_AttemptBelowOneClampedToOne(t *testing.T) {
	if got := backoffDuration(0); got != time.Second {
		t.Errorf("backoffDuration(0) = %v, want %v (clamped to attempt 1)", got, time.Second)
	}
}

func TestApplyJitter_WithinPlusMinus20Percent(t *testing.T) {
	base := 10 * time.Second
	lo := applyJitter(base, 0)
	if lo != 8*time.Second {
		t.Errorf("applyJitter(10s, r=0) = %v, want exactly 8s (lower bound)", lo)
	}
	hi := applyJitter(base, 0.999999999)
	if hi < 11900*time.Millisecond || hi > 12*time.Second {
		t.Errorf("applyJitter(10s, r~1) = %v, want ~12s (upper bound, exclusive)", hi)
	}
	mid := applyJitter(base, 0.5)
	if mid != 10*time.Second {
		t.Errorf("applyJitter(10s, r=0.5) = %v, want exactly 10s (no jitter at the midpoint)", mid)
	}
}

// --- fakeWaiter: deterministic backoff wait for reconnect integration tests ---

// fakeWaiter never sleeps. Each Wait() call registers a pending request the
// test can inspect (exact requested duration) and release explicitly
// (simulating the backoff interval elapsing), or leave blocked so the test
// can cancel ctx instead (simulating Stop()/parent cancellation during
// backoff).
type fakeWaiter struct {
	mu       sync.Mutex
	pending  []*fakeWaitReq
	released int
}

type fakeWaitReq struct {
	d       time.Duration
	release chan struct{}
}

func newFakeWaiter() *fakeWaiter { return &fakeWaiter{} }

func (w *fakeWaiter) Wait(ctx context.Context, d time.Duration) bool {
	req := &fakeWaitReq{d: d, release: make(chan struct{})}
	w.mu.Lock()
	w.pending = append(w.pending, req)
	w.mu.Unlock()
	select {
	case <-req.release:
		return true
	case <-ctx.Done():
		return false
	}
}

// nextRequestedDuration blocks (with a bounded timeout) until at least
// n+1 Wait() calls have been made, then returns the duration requested by
// the n-th (0-based) call.
func (w *fakeWaiter) nextRequestedDuration(t *testing.T, n int) time.Duration {
	t.Helper()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		w.mu.Lock()
		if len(w.pending) > n {
			d := w.pending[n].d
			w.mu.Unlock()
			return d
		}
		w.mu.Unlock()
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatalf("timed out waiting for reconnect Wait() call #%d", n)
		}
	}
}

// releaseNext releases the oldest not-yet-released pending Wait() call,
// letting the reconnect loop proceed to its next dial attempt instantly.
func (w *fakeWaiter) releaseNext(t *testing.T) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		w.mu.Lock()
		if len(w.pending) > w.released {
			req := w.pending[w.released]
			w.released++
			w.mu.Unlock()
			close(req.release)
			return
		}
		w.mu.Unlock()
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatal("timed out waiting for a pending Wait() call to release")
		}
	}
}

func (w *fakeWaiter) pendingCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.pending)
}

// fixedJitter always returns the same r — deterministic backoff duration
// for assertions that need an exact expected value.
type fixedJitter struct{ v float64 }

func (f fixedJitter) Float64() float64 { return f.v }
