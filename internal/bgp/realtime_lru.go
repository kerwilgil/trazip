// Bounded LRU map — v1.2 Gate 3 P1-4 closure. Used by realtime_derive.go
// to keep derived-event tracking state (per-peer path/origin snapshots,
// per-ASN RPKI baselines) memory-bounded within a single long-lived
// realtime session, instead of a plain map that could in principle grow
// for as long as the session stays connected — "en la práctica serán unos
// cientos" is explicitly not an acceptable growth policy for Gate 3.
//
// Capacity is explicit, small, and deterministic; on overflow the
// least-recently-touched entry is evicted (never randomly), and every
// eviction increments a counter the caller can surface — state loss that
// could affect certainty (a peer's contribution to a MOAS union, an ASN's
// RPKI baseline) is never silent.
package bgp

import "container/list"

type lruEntry[K comparable, V any] struct {
	key K
	val V
}

// boundedLRU is a small, deterministic, fixed-capacity LRU map. Not
// internally synchronized — callers hold their own mutex around it
// (realtime_derive.go already serializes all access via derivedState.mu),
// so this stays a plain, allocation-light data structure.
type boundedLRU[K comparable, V any] struct {
	cap      int
	order    *list.List
	elements map[K]*list.Element
	evicted  int64
}

func newBoundedLRU[K comparable, V any](capacity int) *boundedLRU[K, V] {
	return &boundedLRU[K, V]{
		cap:      capacity,
		order:    list.New(),
		elements: make(map[K]*list.Element, capacity),
	}
}

// Get returns the value for key and marks it most-recently-used. Never
// mutates capacity/eviction bookkeeping.
func (l *boundedLRU[K, V]) Get(key K) (V, bool) {
	if el, ok := l.elements[key]; ok {
		l.order.MoveToFront(el)
		return el.Value.(*lruEntry[K, V]).val, true
	}
	var zero V
	return zero, false
}

// Set inserts or updates key and marks it most-recently-used. If this
// insertion grows the map beyond capacity, the least-recently-used entry
// is evicted deterministically and Evicted() increments by exactly one —
// never more than one entry evicted per Set call beyond capacity, since
// Set only ever adds at most one new entry at a time.
func (l *boundedLRU[K, V]) Set(key K, val V) {
	if el, ok := l.elements[key]; ok {
		el.Value.(*lruEntry[K, V]).val = val
		l.order.MoveToFront(el)
		return
	}
	el := l.order.PushFront(&lruEntry[K, V]{key: key, val: val})
	l.elements[key] = el
	if l.order.Len() > l.cap {
		oldest := l.order.Back()
		if oldest != nil {
			l.order.Remove(oldest)
			delete(l.elements, oldest.Value.(*lruEntry[K, V]).key)
			l.evicted++
		}
	}
}

// Delete removes key if present. Used for a real, source-driven removal
// (e.g. a genuine BGP withdrawal clearing a peer's tracked state) — never
// counted as an eviction, since this is an honest removal driven by real
// data, not a capacity-driven loss of state.
func (l *boundedLRU[K, V]) Delete(key K) {
	if el, ok := l.elements[key]; ok {
		l.order.Remove(el)
		delete(l.elements, key)
	}
}

// Len reports the current number of tracked entries — never exceeds cap.
func (l *boundedLRU[K, V]) Len() int { return l.order.Len() }

// Evicted reports how many entries have been evicted due to capacity so
// far — exposed so state loss that could affect derived-event certainty
// (MOAS/path/origin/RPKI) is never silent.
func (l *boundedLRU[K, V]) Evicted() int64 { return l.evicted }

// Range iterates over all currently tracked entries in no particular
// guaranteed order (recomputeMOASLocked, the only caller, does not care
// about order — it only needs the set of currently-tracked determinate
// origins).
func (l *boundedLRU[K, V]) Range(fn func(key K, val V)) {
	for el := l.order.Front(); el != nil; el = el.Next() {
		e := el.Value.(*lruEntry[K, V])
		fn(e.key, e.val)
	}
}
