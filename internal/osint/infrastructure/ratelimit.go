// Package infrastructure provides a proper serializing rate limiter.
package infrastructure

import (
	"context"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter with serial execution guarantee.
// It ensures that requests are properly spaced even under high concurrency.
type RateLimiter struct {
	mu       sync.Mutex
	rate     float64       // requests per second
	interval time.Duration // minimum interval between requests
	next     time.Time     // when the next request can be made
	tokens   float64       // available tokens
	maxTokens float64      // bucket capacity
}

// NewRateLimiter creates a new rate limiter with the given rate (requests per second).
// Rate of 0 means no limit.
func NewRateLimiter(rate float64) *RateLimiter {
	if rate <= 0 {
		return &RateLimiter{rate: 0}
	}
	return &RateLimiter{
		rate:      rate,
		interval:  time.Duration(float64(time.Second) / rate),
		next:      time.Now(),
		tokens:    1.0, // start with 1 token to allow immediate first request
		maxTokens: 1.0,
	}
}

// Wait blocks until a request can be made, respecting the rate limit.
// Returns context error if context is cancelled while waiting.
func (rl *RateLimiter) Wait(ctx context.Context) error {
	if rl.rate <= 0 {
		return nil // no limit
	}

	rl.mu.Lock()
	now := time.Now()

	// Refill tokens based on time elapsed
	elapsed := now.Sub(rl.next)
	if elapsed > 0 {
		// Add tokens based on elapsed time
		rl.tokens = min(rl.maxTokens, rl.tokens+float64(elapsed)/float64(rl.interval))
	}

	if rl.tokens >= 1.0 {
		// Token available, consume it
		rl.tokens--
		rl.next = now.Add(rl.interval)
		rl.mu.Unlock()
		return nil
	}

	// No token available, need to wait
	waitTime := time.Duration((1.0 - rl.tokens) * float64(rl.interval))
	rl.tokens = 0
	rl.next = now.Add(waitTime)
	rl.mu.Unlock()

	// Wait outside the lock to avoid blocking other goroutines
	timer := time.NewTimer(waitTime)
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
		return ctx.Err()
	}
}

// min returns the minimum of two float64 values.
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// SharedRateLimiter provides a process-wide rate limiter for a given endpoint.
// This ensures all clients to the same endpoint share the same rate limit.
type SharedRateLimiter struct {
	limiters map[string]*RateLimiter
	mu       sync.Mutex
}

var defaultSharedLimiter = &SharedRateLimiter{
	limiters: make(map[string]*RateLimiter),
}

// GetLimiter returns a rate limiter for the given key (e.g., "osm", "peeringdb").
// If the limiter doesn't exist, it creates one with the given rate.
func (s *SharedRateLimiter) GetLimiter(key string, rate float64) *RateLimiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	if lim, ok := s.limiters[key]; ok {
		return lim
	}
	lim := NewRateLimiter(rate)
	s.limiters[key] = lim
	return lim
}

// GetDefaultSharedLimiter returns the process-wide shared rate limiter.
func GetDefaultSharedLimiter() *SharedRateLimiter {
	return defaultSharedLimiter
}