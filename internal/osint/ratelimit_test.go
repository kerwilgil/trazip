// Package osint provides tests for the rate limiter.
package osint

import (
	"context"
	"testing"
	"time"
)

func TestLimiterUnlimited(t *testing.T) {
	limiter := NewLimiter(0, 0) // unlimited

	// Should not block
	if err := limiter.Acquire(context.Background()); err != nil {
		t.Errorf("Unlimited Acquire: %v", err)
	}
	if !limiter.TryAcquire() {
		t.Error("Unlimited TryAcquire should return true")
	}
}

func TestLimiterRateLimit(t *testing.T) {
	limiter := NewLimiter(10, 1) // 10/sec, burst 1

	// First should succeed immediately (burst)
	if err := limiter.Acquire(context.Background()); err != nil {
		t.Errorf("First acquire: %v", err)
	}

	// Second should wait ~100ms
	start := time.Now()
	err := limiter.Acquire(context.Background())
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Second acquire: %v", err)
	}
	if elapsed < 80*time.Millisecond {
		t.Errorf("Waited %v, expected ~100ms", elapsed)
	}
}

func TestLimiterBurst(t *testing.T) {
	limiter := NewLimiter(10, 5) // 10/sec, burst 5

	// First 5 should succeed immediately
	for i := 0; i < 5; i++ {
		if err := limiter.Acquire(context.Background()); err != nil {
			t.Errorf("Burst acquire %d: %v", i, err)
		}
	}

	// 6th should wait
	start := time.Now()
	err := limiter.Acquire(context.Background())
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("6th acquire: %v", err)
	}
	if elapsed < 80*time.Millisecond {
		t.Errorf("Waited %v, expected ~100ms", elapsed)
	}
}

func TestLimiterTryAcquire(t *testing.T) {
	limiter := NewLimiter(10, 2)

	// First two should succeed
	if !limiter.TryAcquire() {
		t.Error("First TryAcquire should succeed")
	}
	if !limiter.TryAcquire() {
		t.Error("Second TryAcquire should succeed")
	}

	// Third should fail
	if limiter.TryAcquire() {
		t.Error("Third TryAcquire should fail (no tokens)")
	}
}

func TestLimiterContextCancellation(t *testing.T) {
	limiter := NewLimiter(1, 1) // 1/sec, burst 1 - consume the burst
	limiter.Acquire(context.Background())

	// Now try to acquire with a canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := limiter.Acquire(ctx)
	if err == nil {
		t.Error("Acquire with canceled context should return error")
	}
	if !IsCanceled(err) {
		t.Errorf("Error should be canceled: %v", err)
	}
}

func TestLimiterDeadline(t *testing.T) {
	limiter := NewLimiter(1, 1)
	limiter.Acquire(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := limiter.Acquire(ctx)
	if err == nil {
		t.Error("Acquire with short deadline should timeout")
	}
	if !IsDeadlineExceeded(err) {
		t.Errorf("Error should be deadline exceeded: %v", err)
	}
}

func TestLimiterDynamicRate(t *testing.T) {
	limiter := NewLimiter(100, 1) // burst 1
	// Consume the burst so the next Acquire must wait for a refill.
	if err := limiter.Acquire(context.Background()); err != nil {
		t.Fatalf("initial acquire: %v", err)
	}

	limiter.SetRate(1) // slow the refill to 1 token/sec

	start := time.Now()
	err := limiter.Acquire(context.Background())
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Acquire after SetRate: %v", err)
	}
	if elapsed < 800*time.Millisecond {
		t.Errorf("Waited %v, expected ~1s at 1/sec", elapsed)
	}
}

func TestLimiterDynamicBurst(t *testing.T) {
	limiter := NewLimiter(10, 1)

	// Raising the cap does not manufacture tokens; Reset saturates to it.
	limiter.SetBurst(5)
	limiter.Reset()

	got := 0
	for i := 0; i < 10; i++ {
		if limiter.TryAcquire() {
			got++
		}
	}
	if got != 5 {
		t.Errorf("TryAcquire count after SetBurst(5)+Reset = %d, want 5", got)
	}

	// Shrinking the cap must clamp the current tokens down immediately.
	limiter.Reset()
	limiter.SetBurst(2)
	got = 0
	for i := 0; i < 10; i++ {
		if limiter.TryAcquire() {
			got++
		}
	}
	if got != 2 {
		t.Errorf("TryAcquire count after SetBurst(2) = %d, want 2", got)
	}
}

func TestLimiterReset(t *testing.T) {
	limiter := NewLimiter(10, 2)
	limiter.Acquire(context.Background())
	limiter.Acquire(context.Background())

	if limiter.TryAcquire() {
		t.Error("TryAcquire should fail when exhausted")
	}

	limiter.Reset()

	if !limiter.TryAcquire() {
		t.Error("TryAcquire should succeed after Reset")
	}
	if !limiter.TryAcquire() {
		t.Error("Second TryAcquire should succeed after Reset")
	}
	if limiter.TryAcquire() {
		t.Error("Third TryAcquire should fail after Reset (burst=2)")
	}
}

func TestMultiLimiter(t *testing.T) {
	perProvider := NewLimiter(10, 2)
	global := NewLimiter(5, 1)

	multi := NewMultiLimiter(perProvider, global)

	// First should pass both
	if err := multi.Acquire(context.Background()); err != nil {
		t.Errorf("First multi acquire: %v", err)
	}

	// Second should pass perProvider but wait on global
	start := time.Now()
	err := multi.Acquire(context.Background())
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Second multi acquire: %v", err)
	}
	if elapsed < 150*time.Millisecond {
		t.Errorf("Waited %v, expected ~200ms (global 5/sec)", elapsed)
	}
}

func TestMultiLimiterTryAcquire(t *testing.T) {
	lim1 := NewLimiter(10, 1)
	lim2 := NewLimiter(10, 1)

	multi := NewMultiLimiter(lim1, lim2)

	if !multi.TryAcquire() {
		t.Error("First TryAcquire should succeed")
	}
	if multi.TryAcquire() {
		t.Error("Second TryAcquire should fail (one limiter exhausted)")
	}
}

func TestMultiLimiterTryAcquireRollbackDoesNotManufactureTokens(t *testing.T) {
	// Very slow refill: token counts stay effectively static across the test.
	first := NewLimiter(0.001, 5)
	second := NewLimiter(0.001, 1)

	// Spend 3 of first's 5 tokens up front, then drain second entirely.
	for i := 0; i < 3; i++ {
		if !first.TryAcquire() {
			t.Fatalf("priming first limiter #%d", i)
		}
	}
	if !second.TryAcquire() {
		t.Fatal("priming second limiter")
	}

	multi := NewMultiLimiter(first, second)

	before := first.Tokens() // ~2
	if multi.TryAcquire() {
		t.Fatal("multi TryAcquire should fail when a downstream limiter is empty")
	}
	after := first.Tokens()

	// Correct rollback refunds exactly the one token taken (2 -> 1 -> 2).
	// The old buggy path Reset()s first back to its full burst of 5.
	if after > before+0.5 {
		t.Errorf("first limiter gained tokens on rollback: before=%.3f after=%.3f (want ~equal)", before, after)
	}
}

func TestMultiLimiterNilSkipped(t *testing.T) {
	multi := NewMultiLimiter(nil, NewLimiter(10, 1), nil)

	if err := multi.Acquire(context.Background()); err != nil {
		t.Errorf("MultiLimiter with nil should work: %v", err)
	}
}
