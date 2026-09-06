// Bounded BGP realtime queue — v1.2 Gate 3 (BGP_INTELLIGENCE_ROADMAP.md
// §23.4, capa 1). Sits between the WebSocket reader and the
// normalization/derivation/publish processor. Two independent, non-blocking
// backpressure conditions share ONE counter (QueueDroppedEvents, never
// double-counted per accept attempt):
//
//   - (a) capacity: len(queue) >= MaxQueueSize -> drop-oldest, accept the
//     incoming event.
//   - (b) rate: >= MaxEventsPerWindow events already accepted within the
//     last RateWindow (sliding window) -> reject the incoming event,
//     existing queue untouched.
//
// Never an unbounded slice/channel; Push never blocks the caller (the
// WebSocket reader must never stall because the internal consumer is slow,
// roadmap §23.4).
package bgp

import (
	"sync"
	"time"
)

const (
	// MaxQueueSize is the per-session bounded capacity of the BGP realtime
	// queue (roadmap §23.4, justified by the real 7-day bgp-updates probe:
	// ~600 events/day for a single popular prefix).
	MaxQueueSize = 500
	// MaxEventsPerWindow / RateWindow is the self-imposed sustained rate
	// cap (roadmap §23.4) — protects against RIS Live disconnecting TRAZIP
	// as a "slow client" and against saturating the frontend render loop.
	MaxEventsPerWindow = 200
	RateWindow         = 10 * time.Second
)

// Clock abstracts time.Now() so the rate-limit sliding window (and the
// reconnect stability-reset check in realtime_reconnect.go) are
// deterministically testable — never a real sleep in go test.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// realtimeQueue is a bounded, single-producer/single-consumer-safe FIFO
// (guarded by its own mutex, so multiple goroutines may call Push/Pop
// concurrently without external synchronization) implementing the exact
// drop-oldest/rate-drop contract above.
type realtimeQueue struct {
	mu      sync.Mutex
	clock   Clock
	items   []BGPRealtimeEvent
	maxSize int

	rateMax     int
	rateWindow  time.Duration
	acceptTimes []time.Time // sliding window of Push-accept timestamps; inherently bounded to <= rateMax entries

	dropped int64 // capacity drops + rate drops, combined, never double-counted per Push call

	// capacityDrops/rateDrops preserve the CAUSE of each drop internally
	// (v1.2 Gate 3 P2 closure) — the public contract (RealtimeSessionInfo.
	// QueueDroppedEvents == dropped, combined) never changes; this is
	// purely for internal testability/debugging, dropped always equals
	// capacityDrops+rateDrops.
	capacityDrops int64
	rateDrops     int64

	// notify signals the processor that at least one item is available.
	// Buffered 1 so Push never blocks even if nobody is currently
	// receiving; a coalesced signal is fine because the processor always
	// drains everything available once woken (see processLoop).
	notify chan struct{}
}

func newRealtimeQueue(clock Clock, maxSize, rateMax int, rateWindow time.Duration) *realtimeQueue {
	if clock == nil {
		clock = realClock{}
	}
	return &realtimeQueue{
		clock:      clock,
		maxSize:    maxSize,
		rateMax:    rateMax,
		rateWindow: rateWindow,
		notify:     make(chan struct{}, 1),
	}
}

// Push tries to enqueue ev. Never blocks. Returns true if accepted (either
// with room to spare, or by evicting the oldest queued event to make
// room), false if rejected outright by the rate cap.
func (q *realtimeQueue) Push(ev BGPRealtimeEvent) bool {
	q.mu.Lock()
	now := q.clock.Now()
	q.pruneWindowLocked(now)

	if len(q.acceptTimes) >= q.rateMax {
		// (b) tasa excedida: el evento ENTRANTE se descarta, la cola
		// existente queda intacta — nunca "más antiguo" que evictar para
		// un problema de tasa (roadmap §23.4).
		q.dropped++
		q.rateDrops++
		q.mu.Unlock()
		return false
	}

	if len(q.items) >= q.maxSize {
		// (a) cola llena: drop-oldest — evict el evento más antiguo,
		// aceptar el entrante.
		q.items = q.items[1:]
		q.dropped++
		q.capacityDrops++
	}
	q.items = append(q.items, ev)
	q.acceptTimes = append(q.acceptTimes, now)
	q.mu.Unlock()

	select {
	case q.notify <- struct{}{}:
	default:
	}
	return true
}

// pruneWindowLocked drops accept-timestamps older than the sliding
// rateWindow. Caller must hold q.mu. acceptTimes is inherently bounded to
// at most rateMax entries (Push rejects once the window is full), so this
// is never an unbounded scan.
func (q *realtimeQueue) pruneWindowLocked(now time.Time) {
	cutoff := now.Add(-q.rateWindow)
	i := 0
	for i < len(q.acceptTimes) && !q.acceptTimes[i].After(cutoff) {
		i++
	}
	if i > 0 {
		q.acceptTimes = q.acceptTimes[i:]
	}
}

// Pop removes and returns the oldest queued event, if any. Never blocks.
func (q *realtimeQueue) Pop() (BGPRealtimeEvent, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return BGPRealtimeEvent{}, false
	}
	ev := q.items[0]
	q.items = q.items[1:]
	return ev, true
}

// Len reports the current queue depth (test/debugging use).
func (q *realtimeQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// Dropped reports the total capacity+rate drops so far — this is exactly
// RealtimeSessionInfo.QueueDroppedEvents (roadmap §23.4, capa 1). The
// public contract; never split into two public fields.
func (q *realtimeQueue) Dropped() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

// CapacityDrops/RateDrops preserve the drop CAUSE internally (v1.2 Gate 3
// P2 closure) — test/debug-only, never exposed via RealtimeSessionInfo.
// Always true: Dropped() == CapacityDrops()+RateDrops().
func (q *realtimeQueue) CapacityDrops() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.capacityDrops
}

func (q *realtimeQueue) RateDrops() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.rateDrops
}

// Notify returns the channel the processor selects on to know new items
// may be available. Never closed during the queue's lifetime (the
// processor's own ctx.Done() is what ends its loop — queue lifecycle is
// scoped to the session, not separately torn down; roadmap §23.4 "sin
// persistencia... la cola existe solo durante la sesión").
func (q *realtimeQueue) Notify() <-chan struct{} {
	return q.notify
}
