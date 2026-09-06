// Reconnect/backoff contract — v1.2 Gate 3 (BGP_INTELLIGENCE_ROADMAP.md
// §23.5). Pure backoff math (backoffDuration/applyJitter) is fully
// unit-testable without any I/O; the wait mechanism itself
// (reconnectWaiter) is injectable so tests never sleep real wall-clock
// time and cancellation-during-backoff is deterministically verifiable.
package bgp

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

const (
	backoffInitial         = time.Second
	backoffMax             = 30 * time.Second
	backoffFactor          = 2
	jitterFraction         = 0.20 // ±20%
	maxConsecutiveFailures = 10   // roadmap §23.5: tras 10 reintentos consecutivos fallidos sin éxito intermedio -> SessionFailed
	stabilityThreshold     = 60 * time.Second
)

// backoffDuration returns the base (pre-jitter) backoff for the given
// 1-based attempt number: 1s, 2s, 4s, 8s, 16s, 30s, 30s, ... (roadmap
// §23.5 — exponential x2, capped at 30s).
func backoffDuration(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := backoffInitial
	for i := 2; i <= attempt; i++ {
		if d >= backoffMax {
			d = backoffMax
			break
		}
		d *= backoffFactor
	}
	if d > backoffMax {
		d = backoffMax
	}
	return d
}

// applyJitter maps a uniform r in [0,1) to a ±20% jitter factor in
// [0.8x, 1.2x) and applies it to base (roadmap §23.5 example: 1s ->
// [0.8s, 1.2s], 30s -> [24s, 36s]).
func applyJitter(base time.Duration, r float64) time.Duration {
	factor := (1 - jitterFraction) + r*(2*jitterFraction)
	return time.Duration(float64(base) * factor)
}

// JitterSource abstracts the randomness source for backoff jitter — never
// math/rand's global functions directly in production code, so tests can
// inject a fully deterministic sequence (roadmap Gate 3 §8: "no usar rand
// global difícil de testear").
type JitterSource interface {
	Float64() float64 // uniform [0,1)
}

type realJitterSource struct {
	mu sync.Mutex
	r  *rand.Rand
}

func newRealJitterSource() *realJitterSource {
	return &realJitterSource{r: rand.New(rand.NewSource(time.Now().UnixNano()))}
}

func (j *realJitterSource) Float64() float64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.r.Float64()
}

// reconnectWaiter abstracts "wait d, or return early if ctx is canceled"
// so backoff waits are cancellable via context (Stop()/parent cancellation)
// and — critically — never require go test to actually sleep for up to
// ~139s+ across a full 10-attempt backoff sequence.
type reconnectWaiter interface {
	// Wait blocks until d has elapsed or ctx is done. Returns true if it
	// waited the full duration, false if ctx was canceled first.
	Wait(ctx context.Context, d time.Duration) bool
}

type realWaiter struct{}

func (realWaiter) Wait(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
