package events

import "testing"

func TestBusPreservesTopicAndCountsBackpressure(t *testing.T) {
	b := NewBus()
	ch, unsubscribe := b.Subscribe(1, nil)
	defer unsubscribe()
	b.Publish(Event{Module: "ping", Topic: "ping:reply", Kind: KindProbe})
	b.Publish(Event{Module: "ping", Topic: "ping:reply", Kind: KindProbe})
	e := <-ch
	if e.Topic != "ping:reply" || e.Seq != 1 {
		t.Fatalf("unexpected event: %+v", e)
	}
	if got := b.Dropped(); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
}
