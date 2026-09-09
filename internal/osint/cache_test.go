// Package osint provides tests for the bounded cache.
package osint

import (
	"testing"
	"time"
)

func TestCacheBasic(t *testing.T) {
	cache := NewCache(10)

	// Miss on empty
	val, ok := cache.Get("missing")
	if ok || val != nil {
		t.Errorf("Get missing: val=%v, ok=%v, want nil/false", val, ok)
	}

	// Set and get
	cache.Set("key1", "value1", time.Minute)
	val, ok = cache.Get("key1")
	if !ok || val != "value1" {
		t.Errorf("Get key1: val=%v, ok=%v, want value1/true", val, ok)
	}

	// Update existing
	cache.Set("key1", "value2", time.Minute)
	val, ok = cache.Get("key1")
	if !ok || val != "value2" {
		t.Errorf("Get updated key1: val=%v, ok=%v, want value2/true", val, ok)
	}
}

func TestCacheTTLExpiry(t *testing.T) {
	cache := NewCache(10)

	cache.Set("key1", "value1", 10*time.Millisecond)
	val, ok := cache.Get("key1")
	if !ok || val != "value1" {
		t.Errorf("Immediate get: val=%v, ok=%v, want value1/true", val, ok)
	}

	// Wait for expiry
	time.Sleep(20 * time.Millisecond)

	val, ok = cache.Get("key1")
	if ok || val != nil {
		t.Errorf("After expiry: val=%v, ok=%v, want nil/false", val, ok)
	}
}

func TestCacheCapacityAndEviction(t *testing.T) {
	cache := NewCache(3)

	// Fill to capacity
	cache.Set("a", "1", time.Hour)
	cache.Set("b", "2", time.Hour)
	cache.Set("c", "3", time.Hour)

	if cache.Len() != 3 {
		t.Errorf("Len() = %d, want 3", cache.Len())
	}

	// Add fourth - should evict LRU (a)
	cache.Set("d", "4", time.Hour)

	if cache.Len() != 3 {
		t.Errorf("Len after eviction = %d, want 3", cache.Len())
	}

	// a should be evicted
	_, ok := cache.Get("a")
	if ok {
		t.Error("LRU key 'a' should have been evicted")
	}

	// b, c, d should still exist
	for _, k := range []string{"b", "c", "d"} {
		_, ok := cache.Get(k)
		if !ok {
			t.Errorf("Key %q should still exist after eviction", k)
		}
	}
}

func TestCacheLRUOrder(t *testing.T) {
	cache := NewCache(3)

	cache.Set("a", "1", time.Hour)
	cache.Set("b", "2", time.Hour)
	cache.Set("c", "3", time.Hour)

	// Access 'a' - makes it MRU
	_, _ = cache.Get("a")

	// Add 'd' - should evict 'b' (now LRU)
	cache.Set("d", "4", time.Hour)

	_, ok := cache.Get("b")
	if ok {
		t.Error("Key 'b' should have been evicted (was LRU)")
	}

	// a, c, d should exist
	for _, k := range []string{"a", "c", "d"} {
		_, ok := cache.Get(k)
		if !ok {
			t.Errorf("Key %q should exist", k)
		}
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	cache := NewCache(100)
	done := make(chan struct{})

	// Writer
	go func() {
		for i := 0; i < 1000; i++ {
			cache.Set(key(i), i, time.Hour)
		}
		close(done)
	}()

	// Readers
	for i := 0; i < 10; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					cache.Get(key(i % 100))
				}
			}
		}()
	}

	<-done

	// Should not panic or deadlock
	if cache.Len() > 100 {
		t.Errorf("Cache grew beyond capacity: %d", cache.Len())
	}
}

func key(i int) string { return "key" + string(rune('0'+i%10)) }

func TestCacheWithClock(t *testing.T) {
	cache := NewCache(10)
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	restore := cache.WithClock(func() time.Time { return now })
	defer restore()

	cache.Set("key1", "value1", time.Hour)

	// Time hasn't advanced - should still be valid
	val, ok := cache.Get("key1")
	if !ok || val != "value1" {
		t.Errorf("With clock: val=%v, ok=%v, want value1/true", val, ok)
	}

	// Advance time past TTL
	now = now.Add(2 * time.Hour)
	restore = cache.WithClock(func() time.Time { return now })
	defer restore()

	val, ok = cache.Get("key1")
	if ok || val != nil {
		t.Errorf("After clock advance: val=%v, ok=%v, want nil/false", val, ok)
	}
}

func TestCacheClear(t *testing.T) {
	cache := NewCache(10)
	cache.Set("a", "1", time.Hour)
	cache.Set("b", "2", time.Hour)

	cache.Clear()

	if cache.Len() != 0 {
		t.Errorf("Len after Clear = %d, want 0", cache.Len())
	}
	_, ok := cache.Get("a")
	if ok {
		t.Error("Key should be gone after Clear")
	}
}
