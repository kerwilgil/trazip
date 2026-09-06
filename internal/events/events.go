// Package events provides a typed, context-aware event bus used to stream
// engine results to the GUI and CLI without blocking producers
// (prompt maestro §6 "event bus tipado", §13 backpressure).
package events

import (
	"context"
	"sync"
	"time"
)

// Kind identifies the category of an Event so consumers can filter cheaply.
type Kind string

const (
	KindProbe    Kind = "probe"    // ping/trace/mtr sample
	KindFlow     Kind = "flow"     // flow update
	KindEndpoint Kind = "endpoint" // endpoint enrichment
	KindPacket   Kind = "packet"   // decoded packet
	KindLog      Kind = "log"      // structured log line
	KindProgress Kind = "progress" // long-task progress
	KindError    Kind = "error"    // non-fatal error surfaced to UI
	KindDone     Kind = "done"     // task completed
)

// Event is a single item flowing from an engine to consumers.
type Event struct {
	SessionID string    `json:"sessionId"`
	Kind      Kind      `json:"kind"`
	Module    string    `json:"module"`
	Topic     string    `json:"topic,omitempty"` // transport topic, e.g. "ping:reply"
	Seq       uint64    `json:"seq"`
	Time      time.Time `json:"time"`
	Payload   any       `json:"payload,omitempty"`
}

// Bus is a fan-out publisher. Subscribers get their own buffered channel; a slow
// subscriber drops events rather than stalling producers (explicit backpressure).
type Bus struct {
	mu      sync.RWMutex
	seq     uint64
	subs    map[int]*subscription
	nextID  int
	dropped uint64
}

type subscription struct {
	ch     chan Event
	filter func(Event) bool
}

// NewBus creates an empty event bus.
func NewBus() *Bus {
	return &Bus{subs: make(map[int]*subscription)}
}

// Subscribe registers a consumer with an optional filter (nil = all events) and
// a buffer size. It returns the channel and an unsubscribe func.
func (b *Bus) Subscribe(buffer int, filter func(Event) bool) (<-chan Event, func()) {
	if buffer <= 0 {
		buffer = 256
	}
	b.mu.Lock()
	id := b.nextID
	b.nextID++
	sub := &subscription{ch: make(chan Event, buffer), filter: filter}
	b.subs[id] = sub
	b.mu.Unlock()

	return sub.ch, func() {
		b.mu.Lock()
		if s, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(s.ch)
		}
		b.mu.Unlock()
	}
}

// Publish stamps and fans out an event. It never blocks: if a subscriber's buffer
// is full the event is dropped for that subscriber and counted.
func (b *Bus) Publish(e Event) {
	b.mu.Lock()
	b.seq++
	e.Seq = b.seq
	b.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = time.Now()
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, s := range b.subs {
		if s.filter != nil && !s.filter(e) {
			continue
		}
		select {
		case s.ch <- e:
		default:
			b.mu.RUnlock()
			b.mu.Lock()
			b.dropped++
			b.mu.Unlock()
			b.mu.RLock()
		}
	}
}

// Dropped reports how many events were dropped due to full subscriber buffers.
func (b *Bus) Dropped() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.dropped
}

// Emit is a convenience helper that publishes if ctx is still live.
func (b *Bus) Emit(ctx context.Context, e Event) {
	if ctx.Err() != nil {
		return
	}
	b.Publish(e)
}
