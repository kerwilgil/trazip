// Package osint provides a context-aware, cancelable rate limiter for OSINT providers.
package osint

import (
	"context"
	"sync"
	"time"
)

// Limiter is a token-bucket rate limiter that respects context cancellation.
// It starts no background goroutines — tokens are replenished lazily, on
// each call, from elapsed time. A dynamic SetRate / SetBurst credits the
// elapsed interval at the OLD rate before switching, then wakes any waiter
// blocked in Acquire so it recomputes against the new configuration.
// Safe for concurrent use.
type Limiter struct {
	mu         sync.Mutex
	rate       float64          // tokens per second; <= 0 means unlimited
	burst      int              // max bucket size
	tokens     float64          // current tokens
	lastRefill time.Time        // last time tokens were accounted
	now        func() time.Time // clock, injectable for deterministic tests
	reconfig   chan struct{}    // closed (and replaced) on every SetRate/SetBurst/Reset
}

// NewLimiter creates a limiter with the given rate (tokens/sec) and burst.
// rate <= 0 means unlimited (no waiting). burst <= 0 defaults to 1.
func NewLimiter(rate float64, burst int) *Limiter {
	if burst <= 0 {
		burst = 1
	}
	return &Limiter{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastRefill: time.Now(),
		now:        time.Now,
		reconfig:   make(chan struct{}),
	}
}

// Acquire blocks until a token is available, the context is done, or the
// limiter is reconfigured (in which case it recomputes and keeps waiting as
// needed). Returns nil on success, or the context error if canceled/timed
// out. If rate <= 0 (unlimited), returns immediately.
func (l *Limiter) Acquire(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		l.mu.Lock()
		l.refillLocked()
		if l.rate <= 0 {
			// Unlimited — possibly just set via SetRate while we waited.
			l.mu.Unlock()
			return nil
		}
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		reconfig := l.reconfig
		l.mu.Unlock()

		if wait <= 0 {
			wait = time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			// time to retry
		case <-reconfig:
			// rate/burst changed — cancel the (possibly very long) timer and
			// recompute against the new configuration.
			if !timer.Stop() {
				<-timer.C
			}
		}
	}
}

// TryAcquire attempts to take a token without blocking. Returns true if a
// token was taken. If rate <= 0 (unlimited), always returns true.
func (l *Limiter) TryAcquire() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.refillLocked()
	if l.rate <= 0 {
		return true
	}
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// refillLocked credits tokens for the time elapsed since lastRefill at the
// CURRENT rate, then advances lastRefill. When unlimited (rate <= 0) it only
// advances lastRefill, so a later switch back to a finite rate does not
// retroactively credit the unlimited interval. Caller MUST hold l.mu.
func (l *Limiter) refillLocked() {
	now := l.now()
	if l.rate > 0 {
		elapsed := now.Sub(l.lastRefill).Seconds()
		if elapsed > 0 {
			l.tokens = min(float64(l.burst), l.tokens+elapsed*l.rate)
		}
	}
	l.lastRefill = now
}

// signalReconfigLocked wakes every current Acquire waiter and installs a
// fresh channel for future waiters. Caller MUST hold l.mu.
func (l *Limiter) signalReconfigLocked() {
	close(l.reconfig)
	l.reconfig = make(chan struct{})
}

// SetRate updates the rate (tokens/sec); <= 0 means unlimited. The interval
// elapsed since the last accounting is credited at the OLD rate first, then
// the new rate takes effect and any waiting Acquire is woken to recompute.
func (l *Limiter) SetRate(rate float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillLocked() // account elapsed time at the old rate
	l.rate = rate
	l.signalReconfigLocked()
}

// SetBurst updates the burst size (<= 0 defaults to 1). Elapsed time is
// accounted at the current rate first; tokens above the new cap are
// clamped; waiters are woken.
func (l *Limiter) SetBurst(burst int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if burst <= 0 {
		burst = 1
	}
	l.refillLocked()
	l.burst = burst
	if l.tokens > float64(l.burst) {
		l.tokens = float64(l.burst)
	}
	l.signalReconfigLocked()
}

// Tokens returns the current available tokens (after a lazy refill).
func (l *Limiter) Tokens() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillLocked()
	return l.tokens
}

// Reset restores the bucket to full and wakes any waiter.
func (l *Limiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tokens = float64(l.burst)
	l.lastRefill = l.now()
	l.signalReconfigLocked()
}

// WithClock swaps the time source for deterministic tests and returns a
// function that restores the previous clock.
func (l *Limiter) WithClock(now func() time.Time) func() {
	l.mu.Lock()
	defer l.mu.Unlock()
	old := l.now
	l.now = now
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.now = old
	}
}

// refund returns a single token to the bucket, capped at burst. Used to roll
// back a partially satisfied MultiLimiter.TryAcquire without manufacturing
// tokens the caller never held.
func (l *Limiter) refund() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tokens = min(float64(l.burst), l.tokens+1)
}

// MultiLimiter combines multiple limiters (e.g., per-provider + global).
// Acquire waits for ALL limiters to allow.
type MultiLimiter struct {
	limiters []*Limiter
}

// NewMultiLimiter creates a multi-limiter from a slice of limiters.
// Nil limiters are skipped.
func NewMultiLimiter(limiters ...*Limiter) *MultiLimiter {
	var valid []*Limiter
	for _, lim := range limiters {
		if lim != nil {
			valid = append(valid, lim)
		}
	}
	return &MultiLimiter{limiters: valid}
}

// Acquire waits for all limiters. Returns first error if any context cancels.
func (m *MultiLimiter) Acquire(ctx context.Context) error {
	for _, lim := range m.limiters {
		if err := lim.Acquire(ctx); err != nil {
			return err
		}
	}
	return nil
}

// TryAcquire attempts all limiters without blocking.
func (m *MultiLimiter) TryAcquire() bool {
	for i, lim := range m.limiters {
		if !lim.TryAcquire() {
			// Roll back the tokens already taken from earlier limiters —
			// refund one each, never more than they held.
			for _, prior := range m.limiters[:i] {
				prior.refund()
			}
			return false
		}
	}
	return true
}
