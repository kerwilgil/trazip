package bgp

import (
	"container/list"
	"sync"
	"time"
)

// defaultCacheMaxSize is the default bound — memory-only, never grows
// past this regardless of how many distinct keys are requested.
const defaultCacheMaxSize = 200

// Per-datasource TTLs — only successful (ComponentOK) results are ever
// cached; ComponentDegraded/ComponentNotApplicable results are never
// stored, so a transient failure or a rejected input never gets served
// back as if it were a valid cached answer.
const (
	routingStatusTTL     = 2 * time.Minute
	asOverviewTTL        = 15 * time.Minute
	announcedPrefixesTTL = 10 * time.Minute
	asnNeighboursTTL     = 5 * time.Minute
	rpkiValidationTTL    = 5 * time.Minute
)

// cache is a bounded, TTL-expiring, LRU-evicting, thread-safe in-memory
// cache. No persistence, no background goroutine, no polling, no stale
// serving — an expired entry is a miss, not a degraded-but-served value.
type cache struct {
	mu      sync.Mutex
	maxSize int
	now     func() time.Time // inyectable para tests deterministas
	ll      *list.List       // front = most recently used
	items   map[string]*list.Element
}

type cacheEntry struct {
	key       string
	value     any
	expiresAt time.Time
}

// newCache builds a cache bounded to maxSize entries. maxSize <= 0 falls
// back to defaultCacheMaxSize.
func newCache(maxSize int) *cache {
	if maxSize <= 0 {
		maxSize = defaultCacheMaxSize
	}
	return &cache{
		maxSize: maxSize,
		now:     time.Now,
		ll:      list.New(),
		items:   make(map[string]*list.Element),
	}
}

// get returns the cached value for key and true, if present and not
// expired. An expired entry is evicted immediately and reported as a
// miss — this cache never serves stale data.
func (c *cache) get(key string) (any, bool) {
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

// set stores value under key with the given TTL, evicting the
// least-recently-used entry if the cache is at maxSize and key is new.
func (c *cache) set(key string, value any, ttl time.Duration) {
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

// removeElementLocked removes el from both the list and the index.
// Caller must hold c.mu.
func (c *cache) removeElementLocked(el *list.Element) {
	c.ll.Remove(el)
	entry := el.Value.(*cacheEntry)
	delete(c.items, entry.key)
}

// len reports the current number of live entries (expiration is checked
// lazily on get, not proactively swept — a not-yet-touched expired entry
// still counts here until its next get() evicts it).
func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// clear removes all entries. Used only by tests to reset state between
// cases without recreating the cache.
func (c *cache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.items = make(map[string]*list.Element)
}
