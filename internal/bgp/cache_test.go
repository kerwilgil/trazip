package bgp

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeClock lets tests control cache.now deterministically — no
// time.Sleep, no timing flakiness.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func TestCacheMiss(t *testing.T) {
	c := newCache(10)
	if _, ok := c.get("missing"); ok {
		t.Fatal("expected miss on empty cache")
	}
}

func TestCacheSetGetHit(t *testing.T) {
	c := newCache(10)
	c.set("k", "v", time.Minute)
	v, ok := c.get("k")
	if !ok {
		t.Fatal("expected hit after set")
	}
	if v != "v" {
		t.Fatalf("value = %v, want %q", v, "v")
	}
}

func TestCacheTTLValidWithinWindow(t *testing.T) {
	clk := newFakeClock()
	c := newCache(10)
	c.now = clk.Now

	c.set("k", "v", 5*time.Minute)
	clk.Advance(4 * time.Minute)
	if _, ok := c.get("k"); !ok {
		t.Fatal("expected hit — still within TTL window")
	}
}

func TestCacheTTLExpiration(t *testing.T) {
	clk := newFakeClock()
	c := newCache(10)
	c.now = clk.Now

	c.set("k", "v", 5*time.Minute)
	clk.Advance(5 * time.Minute) // exactly at expiry — must count as expired
	if _, ok := c.get("k"); ok {
		t.Fatal("expected miss — entry at/after its TTL boundary")
	}
	// The expired entry must also be evicted as a side effect of get(),
	// not just hidden.
	if c.len() != 0 {
		t.Fatalf("len() = %d, want 0 after expired get() evicts it", c.len())
	}
}

func TestCacheOverwriteResetsExpiry(t *testing.T) {
	clk := newFakeClock()
	c := newCache(10)
	c.now = clk.Now

	c.set("k", "v1", time.Minute)
	clk.Advance(30 * time.Second)
	c.set("k", "v2", time.Minute) // overwrite — TTL restarts from now
	clk.Advance(45 * time.Second) // 45s past the overwrite, still < 1min

	v, ok := c.get("k")
	if !ok {
		t.Fatal("expected hit — overwrite should have restarted the TTL")
	}
	if v != "v2" {
		t.Fatalf("value = %v, want %q (overwrite should replace value)", v, "v2")
	}
	if c.len() != 1 {
		t.Fatalf("len() = %d, want 1 (overwrite must not create a second entry)", c.len())
	}
}

func TestCacheLRUEvictionOrder(t *testing.T) {
	c := newCache(3)
	c.set("a", 1, time.Hour)
	c.set("b", 2, time.Hour)
	c.set("c", 3, time.Hour)

	// Touch "a" so it becomes most-recently-used; "b" is now the least
	// recently used of the three.
	if _, ok := c.get("a"); !ok {
		t.Fatal("expected hit for a")
	}

	// Inserting a 4th key at maxSize=3 must evict the LRU entry, which is
	// now "b" (a was just touched, c was inserted after b).
	c.set("d", 4, time.Hour)

	if _, ok := c.get("b"); ok {
		t.Fatal("expected b to have been evicted as least-recently-used")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := c.get(k); !ok {
			t.Errorf("expected %s to still be present", k)
		}
	}
}

func TestCacheMaxSizeRespected(t *testing.T) {
	c := newCache(5)
	for i := 0; i < 50; i++ {
		c.set("key-"+strconv.Itoa(i), i, time.Hour)
		if c.len() > 5 {
			t.Fatalf("len() = %d exceeded maxSize=5 after %d inserts", c.len(), i+1)
		}
	}
	if c.len() != 5 {
		t.Fatalf("final len() = %d, want exactly 5", c.len())
	}
}

func TestCacheDefaultMaxSize(t *testing.T) {
	c := newCache(0)
	if c.maxSize != defaultCacheMaxSize {
		t.Fatalf("maxSize = %d, want default %d", c.maxSize, defaultCacheMaxSize)
	}
}

func TestCacheClear(t *testing.T) {
	c := newCache(10)
	c.set("a", 1, time.Hour)
	c.set("b", 2, time.Hour)
	c.clear()
	if c.len() != 0 {
		t.Fatalf("len() = %d after clear, want 0", c.len())
	}
	if _, ok := c.get("a"); ok {
		t.Fatal("expected miss after clear")
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	c := newCache(50)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := string(rune('a' + n%26))
			c.set(key, n, time.Hour)
			c.get(key)
			_ = c.len()
		}(i)
	}
	wg.Wait()
	// No assertion beyond "did not deadlock/panic" — this test's real
	// value is under `go test -race` (§9 of the gate).
	if c.len() > 50 {
		t.Fatalf("len() = %d exceeded maxSize=50 under concurrent access", c.len())
	}
}
