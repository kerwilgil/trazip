// Package infrastructure provides a proper serializing rate limiter.
package infrastructure

import (
	"context"
	"sync"
	"time"
)

// RateLimiter implements a serializing rate limiter.
// It ensures that requests are properly spaced even under high concurrency
// by assigning each caller a scheduled time slot.
type RateLimiter struct {
	mu       sync.Mutex
	rate     float64       // requests per second
	interval time.Duration // minimum interval between requests
	nextTime time.Time     // when the next request slot is available
}

// NewRateLimiter creates a new rate limiter with the given rate (requests per second).
// Rate of 0 means no limit.
func NewRateLimiter(rate float64) *RateLimiter {
	if rate <= 0 {
		return &RateLimiter{rate: 0}
	}
	return &RateLimiter{
		rate:     rate,
		interval: time.Duration(float64(time.Second) / rate),
		nextTime: time.Now(),
	}
}

// Wait blocks until a request can be made, respecting the rate limit.
// Returns context error if context is cancelled while waiting.
// Uses serial scheduling: each caller gets a reserved time slot.
func (rl *RateLimiter) Wait(ctx context.Context) error {
	if rl.rate <= 0 {
		return nil // no limit
	}

	rl.mu.Lock()
	now := time.Now()

	// Calculate when this request can run
	scheduledAt := rl.nextTime
	if now.After(scheduledAt) {
		scheduledAt = now
	}

	// Reserve the next slot
	rl.nextTime = scheduledAt.Add(rl.interval)
	rl.mu.Unlock()

	// Wait until scheduled time (outside the lock)
	if now.Before(scheduledAt) {
		waitDuration := scheduledAt.Sub(now)
		timer := time.NewTimer(waitDuration)
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

	return nil
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