package voip

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

// assertZeroResult checks the exact contract a cancelled Analyze must honor:
// never a partially-built Result, even when pass 1 already parsed some SIP
// messages into its internal calls map before the cancellation was observed.
func assertZeroResult(t *testing.T, res Result) {
	t.Helper()
	if res.Calls != nil {
		t.Errorf("Calls = %+v, want nil (no partial result on cancellation)", res.Calls)
	}
	if res.TotalCalls != 0 || res.Established != 0 || res.Failed != 0 {
		t.Errorf("Result carries partial counters: %+v", res)
	}
	if len(res.Audit.Findings) != 0 {
		t.Errorf("Audit carries partial findings: %+v", res.Audit)
	}
}

// TestAnalyzeCancelledBeforeStart is the simplest, fully deterministic case:
// a context already cancelled before Analyze reads a single byte. Every
// packet-loop iteration in pcap.ReadPackets checks ctx.Err() before reading,
// so this must abort on the very first check.
func TestAnalyzeCancelledBeforeStart(t *testing.T) {
	path := writeCallPCAP(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	res, err := Analyze(ctx, path, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	assertZeroResult(t, res)
	if elapsed > time.Second {
		t.Errorf("Analyze took %v to return after an already-cancelled context — looks hung, not cancelled", elapsed)
	}
}

// countdownContext cancels itself deterministically after a fixed number of
// Err() checks, rather than racing a real cancel() against wall-clock read
// speed. pcap.ReadPackets calls Err() once per packet-loop iteration (top of
// the loop, before reading), so setting the countdown below the fixture's
// total packet count guarantees Analyze aborts genuinely mid-read — with a
// real Call already partially built from the SIP messages seen so far — not
// merely before it started. This is what makes the "no partial result" check
// meaningful rather than trivial.
type countdownContext struct {
	context.Context
	mu        sync.Mutex
	remaining int
	err       error
	done      chan struct{}
	closeOnce sync.Once
}

func newCountdownContext(n int) *countdownContext {
	return &countdownContext{Context: context.Background(), remaining: n, done: make(chan struct{})}
}

func (c *countdownContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.remaining--
	if c.remaining <= 0 {
		c.err = context.Canceled
		c.closeOnce.Do(func() { close(c.done) })
	}
	return c.err
}

func (c *countdownContext) Done() <-chan struct{} { return c.done }

func TestAnalyzeCancelledMidFlight(t *testing.T) {
	path := writeCallPCAP(t) // INVITE..BYE plus 80 RTP packets and an RTCP report: comfortably more than the countdown below
	ctx := newCountdownContext(3)

	res, err := Analyze(ctx, path, nil)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	assertZeroResult(t, res)
}

// TestAnalyzeCancellationLeavesNoOrphanedGoroutines runs Analyze concurrently
// against a real context.CancelFunc (not the deterministic double above, so
// the real cancellation machinery is exercised end-to-end) and checks that
// nothing measurable is left running once it returns. Analyze itself starts
// no goroutines, but this is the guarantee the GUI's own StartVoIPAnalysis
// (which does run Analyze in a goroutine) depends on: a cancelled Analyze
// must return promptly and clean, or that goroutine — and the session it
// belongs to — would leak forever.
func TestAnalyzeCancellationLeavesNoOrphanedGoroutines(t *testing.T) {
	path := writeCallPCAP(t)
	runtime.GC()
	baseline := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		_, err = Analyze(ctx, path, nil)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Analyze did not return within 5s of cancellation — looks like a leaked/hung goroutine")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}

	// Give the runtime a moment to actually tear down the goroutine above
	// (close(done) happens before the goroutine's stack is fully reclaimed).
	deadline := time.Now().Add(time.Second)
	for {
		runtime.GC()
		if runtime.NumGoroutine() <= baseline {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("goroutine count = %d after cancellation, want <= baseline %d — possible leak", runtime.NumGoroutine(), baseline)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
