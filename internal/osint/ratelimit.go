// Package osint provides a context-aware, cancelable rate limiter for OSINT providers.
package osint

import (
	"context"
	"sync"
	"time"
)

// Limiter is a token-bucket rate limiter that respects context cancellation.
// It does NOT start any background goroutines — tokens are replenished on
// each Acquire call based on elapsed time. Safe for concurrent use.
type Limiter struct {
	mu         sync.Mutex
	rate       float64 // tokens per second
	burst      int     // max bucket size
	tokens     float64 // current tokens
	lastRefill time.Time
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
	}
}

// Acquire blocks until a token is available or ctx is done.
// Returns nil on success, or ctx error if canceled/timeout.
// If rate <= 0 (unlimited), returns immediately.
func (l *Limiter) Acquire(ctx context.Context) error {
	l.mu.Lock()
	unlimited := l.rate <= 0
	l.mu.Unlock()
	if unlimited {
		return nil // unlimited
	}

	for {
		// Refill tokens based on elapsed time
		l.refill()

		// Try to take a token
		l.mu.Lock()
		if l.rate <= 0 {
			// Rate was lowered to "unlimited" (e.g. via SetRate) while we
			// were waiting — stop blocking.
			l.mu.Unlock()
			return nil
		}
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		// Calculate wait time for next token
		wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.mu.Unlock()

		// Wait with context awareness
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
			// loop and try again
		}
	}
}

// refill adds tokens based on elapsed time. Caller must NOT hold l.mu.
func (l *Limiter) refill() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastRefill).Seconds()
	l.tokens = min(float64(l.burst), l.tokens+elapsed*l.rate)
	l.lastRefill = now
}

// TryAcquire attempts to take a token without blocking.
// Returns true if a token was taken, false otherwise.
// If rate <= 0 (unlimited), always returns true.
func (l *Limiter) TryAcquire() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.rate <= 0 {
		return true
	}

	l.refillLocked()
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// refillLocked adds tokens based on elapsed time. Caller MUST hold l.mu.
func (l *Limiter) refillLocked() {
	now := time.Now()
	elapsed := now.Sub(l.lastRefill).Seconds()
	l.tokens = min(float64(l.burst), l.tokens+elapsed*l.rate)
	l.lastRefill = now
}

// SetRate updates the rate (tokens/sec) dynamically.
// Rate <= 0 means unlimited.
func (l *Limiter) SetRate(rate float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rate = rate
}

// SetBurst updates the burst size dynamically.
// Burst <= 0 defaults to 1.
func (l *Limiter) SetBurst(burst int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if burst <= 0 {
		burst = 1
	}
	l.burst = burst
	if l.tokens > float64(l.burst) {
		l.tokens = float64(l.burst)
	}
}

// Tokens returns the current available tokens (approximate, no lock).
func (l *Limiter) Tokens() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillLocked()
	return l.tokens
}

// Reset restores the bucket to full.
func (l *Limiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tokens = float64(l.burst)
	l.lastRefill = time.Now()
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
