// Package osint provides a bounded, TTL-expiring, LRU-evicting cache for OSINT results.
package osint

import (
	"container/list"
	"sync"
	"time"
)

// defaultCacheMaxSize is the default bound — memory-only, never grows
// past this regardless of how many distinct keys are requested.
const defaultCacheMaxSize = 500

// Cache is a bounded, TTL-expiring, LRU-evicting, thread-safe in-memory cache.
// No persistence, no background goroutine, no polling, no stale serving —
// an expired entry is a miss, not a degraded-but-served value.
type Cache struct {
	mu      sync.Mutex
	maxSize int
	now     func() time.Time // injectable for deterministic tests
	ll      *list.List       // front = most recently used
	items   map[string]*list.Element
}

type cacheEntry struct {
	key       string
	value     any
	expiresAt time.Time
}

// NewCache builds a cache bounded to maxSize entries. maxSize <= 0 falls
// back to defaultCacheMaxSize.
func NewCache(maxSize int) *Cache {
	if maxSize <= 0 {
		maxSize = defaultCacheMaxSize
	}
	return &Cache{
		maxSize: maxSize,
		now:     time.Now,
		ll:      list.New(),
		items:   make(map[string]*list.Element),
	}
}

// Get returns the cached value for key and true, if present and not expired.
// An expired entry is evicted immediately and reported as a miss — this cache
// never serves stale data.
func (c *Cache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	entry := el.Value.(*cacheEntry)
	if !c.now().Before(entry.expiresAt) {
		c.removeElementLocked(el)
		return nil, false
	}
	c.ll.MoveToFront(el)
	return entry.value, true
}

// Set stores value under key with the given TTL, evicting the
// least-recently-used entry if the cache is at maxSize and key is new.
func (c *Cache) Set(key string, value any, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		entry := el.Value.(*cacheEntry)
		entry.value = value
		entry.expiresAt = c.now().Add(ttl)
		c.ll.MoveToFront(el)
		return
	}

	if c.ll.Len() >= c.maxSize {
		if oldest := c.ll.Back(); oldest != nil {
			c.removeElementLocked(oldest)
		}
	}

	entry := &cacheEntry{key: key, value: value, expiresAt: c.now().Add(ttl)}
	el := c.ll.PushFront(entry)
	c.items[key] = el
}

// Len reports the current number of live entries (expiration is checked
// lazily on Get, not proactively swept — a not-yet-touched expired entry
// still counts here until its next Get() evicts it).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// Clear removes all entries. Used only by tests to reset state between
// cases without recreating the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.items = make(map[string]*list.Element)
}

// removeElementLocked removes el from both the list and the index.
// Caller must hold c.mu.
func (c *Cache) removeElementLocked(el *list.Element) {
	c.ll.Remove(el)
	entry := el.Value.(*cacheEntry)
	delete(c.items, entry.key)
}

// WithClock replaces the time source for deterministic testing.
// Returns a restore function to put the original clock back.
func (c *Cache) WithClock(now func() time.Time) func() {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.now
	c.now = now
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.now = old
	}
}
