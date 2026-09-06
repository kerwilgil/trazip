package bgp

import (
	"testing"
	"time"
)

func newTestQueue(clock Clock) *realtimeQueue {
	return newRealtimeQueue(clock, MaxQueueSize, MaxEventsPerWindow, RateWindow)
}

func evWithPrefix(prefix string) BGPRealtimeEvent {
	return BGPRealtimeEvent{Type: EventAnnouncement, Prefix: prefix, Source: "ris-live"}
}

// --- §20 queue capacity/drop-oldest ---

func TestQueue_CapacityExact500(t *testing.T) {
	q := newTestQueue(newFakeClock())
	for i := 0; i < MaxQueueSize; i++ {
		// Spread pushes across enough distinct time instants that the
		// 200/10s rate cap never interferes with this capacity-only test.
		clock := q.clock.(*fakeClock)
		clock.Advance(100 * time.Millisecond)
		if !q.Push(evWithPrefix("p")) {
			t.Fatalf("push %d rejected unexpectedly (capacity test must never hit the rate cap)", i)
		}
	}
	if q.Len() != MaxQueueSize {
		t.Fatalf("Len() = %d, want exactly %d", q.Len(), MaxQueueSize)
	}
	if q.Dropped() != 0 {
		t.Fatalf("Dropped() = %d, want 0 — 500 accepted must never drop", q.Dropped())
	}
}

func TestQueue_500Accepted_NoDrop(t *testing.T) {
	clock := newFakeClock()
	q := newTestQueue(clock)
	for i := 0; i < MaxQueueSize; i++ {
		clock.Advance(time.Second) // stay well under the 200/10s rate cap by spacing pushes out
		if !q.Push(evWithPrefix("p")) {
			t.Fatalf("push %d rejected, want accepted", i)
		}
	}
	if q.Dropped() != 0 {
		t.Fatalf("Dropped() = %d, want 0", q.Dropped())
	}
}

func TestQueue_501st_EvictsOldest(t *testing.T) {
	clock := newFakeClock()
	q := newTestQueue(clock)
	for i := 0; i < MaxQueueSize; i++ {
		clock.Advance(time.Second)
		q.Push(BGPRealtimeEvent{Type: EventAnnouncement, Prefix: "p", SourceMessageID: itoaHelper(i)})
	}
	clock.Advance(time.Second)
	if !q.Push(BGPRealtimeEvent{Type: EventAnnouncement, Prefix: "p", SourceMessageID: "501st"}) {
		t.Fatal("501st push rejected, want accepted via drop-oldest")
	}
	if q.Len() != MaxQueueSize {
		t.Fatalf("Len() after 501 pushes = %d, want capped at %d", q.Len(), MaxQueueSize)
	}
	ev, ok := q.Pop()
	if !ok {
		t.Fatal("Pop() empty after overflow, want the oldest surviving element")
	}
	if ev.SourceMessageID == "0" {
		t.Error("the original oldest event (#0) survived — drop-oldest must have evicted it, not a later one")
	}
}

func TestQueue_501st_Survives(t *testing.T) {
	clock := newFakeClock()
	q := newTestQueue(clock)
	for i := 0; i < MaxQueueSize; i++ {
		clock.Advance(time.Second)
		q.Push(evWithPrefix("p"))
	}
	clock.Advance(time.Second)
	q.Push(BGPRealtimeEvent{Type: EventAnnouncement, Prefix: "p", SourceMessageID: "the-501st"})

	var last BGPRealtimeEvent
	for {
		ev, ok := q.Pop()
		if !ok {
			break
		}
		last = ev
	}
	if last.SourceMessageID != "the-501st" {
		t.Errorf("last surviving element SourceMessageID = %q, want %q (the newest push must survive an overflow)", last.SourceMessageID, "the-501st")
	}
}

func TestQueue_CapacityDrop_IncrementsExactlyOnce(t *testing.T) {
	clock := newFakeClock()
	q := newTestQueue(clock)
	for i := 0; i < MaxQueueSize; i++ {
		clock.Advance(time.Second)
		q.Push(evWithPrefix("p"))
	}
	clock.Advance(time.Second)
	q.Push(evWithPrefix("overflow"))
	if q.Dropped() != 1 {
		t.Errorf("Dropped() = %d, want exactly 1 for a single capacity overflow", q.Dropped())
	}
}

func TestQueue_MultipleOverflows_CountExactly(t *testing.T) {
	clock := newFakeClock()
	q := newTestQueue(clock)
	for i := 0; i < MaxQueueSize; i++ {
		clock.Advance(time.Second)
		q.Push(evWithPrefix("p"))
	}
	const extra = 37
	for i := 0; i < extra; i++ {
		clock.Advance(time.Second)
		q.Push(evWithPrefix("p"))
	}
	if q.Dropped() != extra {
		t.Errorf("Dropped() = %d, want exactly %d", q.Dropped(), extra)
	}
	if q.Len() != MaxQueueSize {
		t.Errorf("Len() = %d, want capped at %d", q.Len(), MaxQueueSize)
	}
}

func TestQueue_FIFO_PreservedForSurvivors(t *testing.T) {
	clock := newFakeClock()
	q := newTestQueue(clock)
	// Fill to capacity, then push 3 more (evicting the 3 oldest).
	for i := 0; i < MaxQueueSize+3; i++ {
		clock.Advance(time.Second)
		q.Push(BGPRealtimeEvent{Type: EventAnnouncement, Prefix: "p", SourceMessageID: itoaHelper(i)})
	}
	// Survivors must be messages 3..502, in that exact order.
	for want := 3; want < MaxQueueSize+3; want++ {
		ev, ok := q.Pop()
		if !ok {
			t.Fatalf("queue drained early at expected id %d", want)
		}
		if ev.SourceMessageID != itoaHelper(want) {
			t.Fatalf("FIFO order broken: got %q, want %q", ev.SourceMessageID, itoaHelper(want))
		}
	}
}

func itoaHelper(i int) string {
	// avoid importing strconv twice across test files; simple local helper
	digits := "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{digits[i%10]}, b...)
		i /= 10
	}
	return string(b)
}

func TestQueue_ProducerNeverBlocks_QueueFull(t *testing.T) {
	clock := newFakeClock()
	q := newTestQueue(clock)
	done := make(chan struct{})
	go func() {
		for i := 0; i < MaxQueueSize+50; i++ {
			clock.Advance(time.Second)
			q.Push(evWithPrefix("p"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Push() blocked with a full queue — producer must never block (roadmap §23.4)")
	}
}

// --- §21 rate limit ---

func TestQueue_RateLimit_200Within10s_Accepted(t *testing.T) {
	clock := newFakeClock()
	q := newTestQueue(clock)
	for i := 0; i < MaxEventsPerWindow; i++ {
		clock.Advance(10 * time.Millisecond) // 200 * 10ms = 2s, well within the 10s window
		if !q.Push(evWithPrefix("p")) {
			t.Fatalf("push %d rejected, want accepted (under the 200/10s cap)", i)
		}
	}
	if q.Dropped() != 0 {
		t.Errorf("Dropped() = %d, want 0", q.Dropped())
	}
}

func TestQueue_RateLimit_201stWithinWindow_Rejected(t *testing.T) {
	clock := newFakeClock()
	q := newTestQueue(clock)
	for i := 0; i < MaxEventsPerWindow; i++ {
		clock.Advance(10 * time.Millisecond)
		q.Push(evWithPrefix("p"))
	}
	clock.Advance(10 * time.Millisecond) // still well within the 10s window
	if q.Push(evWithPrefix("201st")) {
		t.Error("201st push within the rate window was accepted, want rejected")
	}
}

func TestQueue_RateDrop_ExistingQueueUntouched(t *testing.T) {
	clock := newFakeClock()
	q := newTestQueue(clock)
	for i := 0; i < MaxEventsPerWindow; i++ {
		clock.Advance(10 * time.Millisecond)
		q.Push(BGPRealtimeEvent{Type: EventAnnouncement, Prefix: "p", SourceMessageID: "kept"})
	}
	lenBefore := q.Len()
	clock.Advance(10 * time.Millisecond)
	q.Push(evWithPrefix("rejected"))
	if q.Len() != lenBefore {
		t.Errorf("Len() changed from %d to %d after a rate-drop — rate-drop must never touch the existing queue (unlike capacity drop-oldest)", lenBefore, q.Len())
	}
}

func TestQueue_RateDrop_IncrementsDropped(t *testing.T) {
	clock := newFakeClock()
	q := newTestQueue(clock)
	for i := 0; i < MaxEventsPerWindow; i++ {
		clock.Advance(10 * time.Millisecond)
		q.Push(evWithPrefix("p"))
	}
	clock.Advance(10 * time.Millisecond)
	q.Push(evWithPrefix("rejected"))
	if q.Dropped() != 1 {
		t.Errorf("Dropped() = %d, want 1", q.Dropped())
	}
}

func TestQueue_RateLimit_WindowSlides_AcceptsAgainAfter10s(t *testing.T) {
	clock := newFakeClock()
	q := newTestQueue(clock)
	for i := 0; i < MaxEventsPerWindow; i++ {
		clock.Advance(1 * time.Millisecond)
		q.Push(evWithPrefix("p"))
	}
	if q.Push(evWithPrefix("still-in-window")) {
		t.Fatal("push immediately after hitting the cap was accepted, want rejected")
	}
	clock.Advance(RateWindow + time.Millisecond) // advance past the full 10s window
	if !q.Push(evWithPrefix("after-window")) {
		t.Error("push after the rate window fully elapsed was rejected, want accepted")
	}
}

func TestQueue_RateLimit_SlidingBoundaryExact(t *testing.T) {
	clock := newFakeClock()
	q := newTestQueue(clock)
	start := clock.Now()
	_ = start
	// Push exactly 200 events, one every 50ms (200*50ms = 10s total span).
	for i := 0; i < MaxEventsPerWindow; i++ {
		if i > 0 {
			clock.Advance(50 * time.Millisecond)
		}
		if !q.Push(evWithPrefix("p")) {
			t.Fatalf("push %d rejected unexpectedly during boundary setup", i)
		}
	}
	// At this point exactly 10s (minus one tick) have elapsed since the
	// first push; the window should still contain all 200 -> next push
	// rejected.
	if q.Push(evWithPrefix("boundary-reject")) {
		t.Error("push at the sliding-window boundary was accepted, want rejected (window still full)")
	}
	// Advance past the first push's exact expiry (50ms further) — exactly
	// one slot should free up.
	clock.Advance(51 * time.Millisecond)
	if !q.Push(evWithPrefix("boundary-accept")) {
		t.Error("push just after the oldest accepted event aged out of the window was rejected, want accepted")
	}
}

// TestQueue_DropCause_TrackedSeparately_Internally verifies the internal
// capacity/rate cause tracking added in v1.2 Gate 3 P2 closure — the
// PUBLIC contract (Dropped()) never changes and always equals the sum of
// the two internal, test-only counters.
func TestQueue_DropCause_TrackedSeparately_Internally(t *testing.T) {
	clock := newFakeClock()
	q := newRealtimeQueue(clock, 5, MaxEventsPerWindow, RateWindow)
	for i := 0; i < 5; i++ {
		clock.Advance(time.Millisecond)
		q.Push(evWithPrefix("p"))
	}
	clock.Advance(time.Millisecond)
	q.Push(evWithPrefix("capacity-overflow"))
	if q.CapacityDrops() != 1 || q.RateDrops() != 0 {
		t.Fatalf("CapacityDrops()=%d RateDrops()=%d, want 1/0", q.CapacityDrops(), q.RateDrops())
	}
	if q.Dropped() != q.CapacityDrops()+q.RateDrops() {
		t.Fatalf("Dropped()=%d != CapacityDrops()+RateDrops()=%d", q.Dropped(), q.CapacityDrops()+q.RateDrops())
	}

	q2 := newRealtimeQueue(clock, MaxQueueSize, 3, RateWindow)
	for i := 0; i < 3; i++ {
		clock.Advance(time.Millisecond)
		q2.Push(evWithPrefix("p"))
	}
	clock.Advance(time.Millisecond)
	q2.Push(evWithPrefix("rate-overflow"))
	if q2.CapacityDrops() != 0 || q2.RateDrops() != 1 {
		t.Fatalf("CapacityDrops()=%d RateDrops()=%d, want 0/1", q2.CapacityDrops(), q2.RateDrops())
	}
	if q2.Dropped() != q2.CapacityDrops()+q2.RateDrops() {
		t.Fatalf("Dropped()=%d != CapacityDrops()+RateDrops()=%d", q2.Dropped(), q2.CapacityDrops()+q2.RateDrops())
	}
}

func TestQueue_CapacityAndRateDrop_ShareCounter_NoDoubleCount(t *testing.T) {
	clock := newFakeClock()
	// A queue whose capacity is smaller than the rate cap so a single
	// overflowing push can only ever hit ONE of the two conditions per
	// call — verifies Dropped() increments by exactly 1 per rejected/
	// evicted push, never 2, regardless of which condition fired.
	q := newRealtimeQueue(clock, 5, MaxEventsPerWindow, RateWindow)
	for i := 0; i < 5; i++ {
		clock.Advance(time.Millisecond)
		q.Push(evWithPrefix("p"))
	}
	clock.Advance(time.Millisecond)
	q.Push(evWithPrefix("capacity-overflow")) // hits capacity, not rate (well under 200/10s)
	if q.Dropped() != 1 {
		t.Fatalf("Dropped() after one capacity overflow = %d, want 1 (no double-count)", q.Dropped())
	}

	q2 := newRealtimeQueue(clock, MaxQueueSize, 3, RateWindow)
	for i := 0; i < 3; i++ {
		clock.Advance(time.Millisecond)
		q2.Push(evWithPrefix("p"))
	}
	clock.Advance(time.Millisecond)
	q2.Push(evWithPrefix("rate-overflow")) // hits rate, not capacity (well under 500)
	if q2.Dropped() != 1 {
		t.Fatalf("Dropped() after one rate overflow = %d, want 1 (no double-count)", q2.Dropped())
	}
}
