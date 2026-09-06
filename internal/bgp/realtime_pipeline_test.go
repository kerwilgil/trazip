package bgp

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"trazip/internal/events"
	"trazip/internal/session"
)

// TestRealtimePipeline_EndToEnd_ReaderQueueProcessorBus verifies the full
// Gate 3 pipeline wired together against a real local WebSocket server
// (wire-format fidelity, like Gate 2's tests): reader decodes a real
// UPDATE message -> enqueues -> processor drains -> publishes to
// sess.Bus -> a subscriber observes it, and RealtimeSessionInfo's
// counters (ReceivedEvents, QueueDroppedEvents, DroppedEventsTotal)
// reflect reality, never fabricated.
func TestRealtimePipeline_EndToEnd_ReaderQueueProcessorBus(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	updateMsg := []byte(`{"type":"ris_message","data":{"timestamp":1787141896.080,"peer":"37.49.237.143","peer_asn":"50628","id":"37.49.237.143-01a019f537900000","host":"rrc21.ripe.net","type":"UPDATE","path":[50628,35280,6453,4637,16509],"community":[[6453,86],[6453,3000]],"origin":"IGP","announcements":[{"next_hop":"37.49.237.143","prefixes":["9.9.9.0/24"]}],"withdrawals":[]}}`)
	fake := newFakeRISServer(t, [][]byte{updateMsg}, true)

	rs := startRealtimeSession(context.Background(), mgr, client, "9.9.9.0/24", gorillaDialer{}, fake.wsURL())
	t.Cleanup(rs.Stop)

	sub, unsubscribe := rs.sess.Bus.Subscribe(16, nil)
	defer unsubscribe()

	var got events.Event
	select {
	case got = <-sub:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the decoded announcement to reach the session's event bus")
	}
	// v1.2 Gate 5 §23.8 closure: a single stable transport topic
	// ("bgp:realtime") for every event type — the actual kind lives in
	// BGPRealtimeEvent.Type below, never a per-Event.Type topic.
	if got.Topic != bgpRealtimeTopic {
		t.Errorf("Topic = %q, want %q", got.Topic, bgpRealtimeTopic)
	}
	if got.Kind != events.KindProbe {
		t.Errorf("Kind = %q, want %q", got.Kind, events.KindProbe)
	}
	if got.Module != "bgp-realtime" {
		t.Errorf("Module = %q, want %q", got.Module, "bgp-realtime")
	}
	ev, ok := got.Payload.(BGPRealtimeEvent)
	if !ok {
		t.Fatalf("Payload type = %T, want BGPRealtimeEvent", got.Payload)
	}
	if ev.Type != EventAnnouncement {
		t.Errorf("Payload.Type = %q, want %q — with a single shared Topic, this is the ONLY place the actual event kind is distinguishable", ev.Type, EventAnnouncement)
	}
	if ev.Prefix != "9.9.9.0/24" {
		t.Errorf("Prefix = %q, want 9.9.9.0/24", ev.Prefix)
	}
	if !ev.Origin.Determinate || ev.Origin.ASN != 16509 {
		t.Errorf("Origin = %+v, want Determinate=true ASN=16509 (last path element)", ev.Origin)
	}

	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		info := rs.Info()
		if info.ReceivedEvents >= 1 {
			if info.QueueDroppedEvents != 0 {
				t.Errorf("QueueDroppedEvents = %d, want 0 for a single normal event", info.QueueDroppedEvents)
			}
			if info.DroppedEventsTotal != info.QueueDroppedEvents+info.TransportDroppedEvents {
				t.Errorf("DroppedEventsTotal = %d, want QueueDroppedEvents+TransportDroppedEvents = %d", info.DroppedEventsTotal, info.QueueDroppedEvents+info.TransportDroppedEvents)
			}
			if info.LastEventAt == "" {
				t.Error("LastEventAt still empty after an event was received")
			}
			return
		}
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatalf("timed out waiting for ReceivedEvents >= 1, last Info() = %+v", info)
		}
	}
}

// --- Gate 3 P1-1: exact resolved prefix isolation ---

// TestRealtimePipeline_PrefixIsolation_OnlyResolvedPrefixEnters drives a
// real wire UPDATE message that announces TWO prefixes — only one of them
// (the session's ResolvedPrefix) — end-to-end through the reader, the
// canonical-CIDR filter (prefixMatchesResolved, realtime_event.go), the
// queue, and the Bus. TRAZIP never trusts RIS Live's `prefix` subscribe
// filter to have pruned the wire payload down to exactly what was asked
// (v1.2 Gate 3 P1-1 closure).
func TestRealtimePipeline_PrefixIsolation_OnlyResolvedPrefixEnters(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)} // no `path` in the wire message below -> indeterminate origin -> RPKI never called
	// The unrelated prefix (8.8.8.0/24) is ordinal 0, the matching one
	// (9.9.9.0/24, the session's ResolvedPrefix) is ordinal 1 — proves the
	// surviving event keeps its ORIGINAL wire ordinal, never renumbered
	// after the unrelated one is filtered out (case 4 of P1-1).
	updateMsg := []byte(`{"type":"ris_message","data":{"timestamp":1787141896.080,"peer":"37.49.237.143","peer_asn":"50628","id":"multi-prefix-1","type":"UPDATE","announcements":[{"next_hop":"37.49.237.143","prefixes":["8.8.8.0/24","9.9.9.0/24"]}],"withdrawals":[]}}`)
	fake := newFakeRISServer(t, [][]byte{updateMsg}, true)

	rs := startRealtimeSession(context.Background(), mgr, client, "9.9.9.0/24", gorillaDialer{}, fake.wsURL())
	t.Cleanup(rs.Stop)

	sub, unsubscribe := rs.sess.Bus.Subscribe(16, nil)
	defer unsubscribe()

	var got events.Event
	select {
	case got = <-sub:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the matching prefix's event to reach the bus")
	}
	ev, ok := got.Payload.(BGPRealtimeEvent)
	if !ok {
		t.Fatalf("Payload type = %T, want BGPRealtimeEvent", got.Payload)
	}
	if ev.Prefix != "9.9.9.0/24" {
		t.Fatalf("Prefix = %q, want 9.9.9.0/24 — the unrelated prefix 8.8.8.0/24 must never reach the Bus", ev.Prefix)
	}
	wantID := sourceEventID("multi-prefix-1", EventAnnouncement, "9.9.9.0/24", 1)
	if ev.ID != wantID {
		t.Errorf("ID = %q, want %q (original wire ordinal 1 preserved, never renumbered after filtering out ordinal 0)", ev.ID, wantID)
	}

	// No second event ever arrives, and Info() reflects exactly one
	// accepted event — the unrelated prefix never touched
	// ReceivedEvents/derived state/RPKI/the Bus.
	select {
	case extra := <-sub:
		t.Fatalf("a second event reached the Bus, want none: %+v", extra)
	case <-time.After(300 * time.Millisecond):
	}
	if info := rs.Info(); info.ReceivedEvents != 1 {
		t.Errorf("ReceivedEvents = %d, want exactly 1 (only the matching prefix ever counted as accepted)", info.ReceivedEvents)
	}
}

// TestRealtimePipeline_PrefixIsolation_WithdrawalUnrelatedPrefixFiltered
// is the withdrawal-side twin of the test above.
func TestRealtimePipeline_PrefixIsolation_WithdrawalUnrelatedPrefixFiltered(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: failIfCalledHTTP(t)}
	updateMsg := []byte(`{"type":"ris_message","data":{"timestamp":1787141896.080,"peer":"37.49.237.143","peer_asn":"50628","id":"multi-withdraw-1","type":"UPDATE","announcements":[],"withdrawals":["8.8.8.0/24","9.9.9.0/24"]}}`)
	fake := newFakeRISServer(t, [][]byte{updateMsg}, true)

	rs := startRealtimeSession(context.Background(), mgr, client, "9.9.9.0/24", gorillaDialer{}, fake.wsURL())
	t.Cleanup(rs.Stop)

	sub, unsubscribe := rs.sess.Bus.Subscribe(16, nil)
	defer unsubscribe()

	var got events.Event
	select {
	case got = <-sub:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the matching prefix's withdrawal event to reach the bus")
	}
	ev, ok := got.Payload.(BGPRealtimeEvent)
	if !ok || ev.Type != EventWithdrawal || ev.Prefix != "9.9.9.0/24" {
		t.Fatalf("got %+v ok=%v, want a withdrawal for 9.9.9.0/24", got.Payload, ok)
	}

	select {
	case extra := <-sub:
		t.Fatalf("a second event reached the Bus, want none: %+v", extra)
	case <-time.After(300 * time.Millisecond):
	}
	if info := rs.Info(); info.ReceivedEvents != 1 {
		t.Errorf("ReceivedEvents = %d, want exactly 1", info.ReceivedEvents)
	}
}

// slowRPKIFixtureServer answers exactly like rpkiDetailedFixtureServer but
// after an artificial delay — used to deliberately slow the Gate 3
// processor (§23.7's reader/processor split) so the reader, fed
// essentially instantly by a local fake WS server, reliably outpaces it
// and overflows the bounded queue's CAPACITY specifically — deterministic
// by construction, never a race against raw machine speed (v1.2 Gate 3 P2
// closure).
func slowRPKIFixtureServer(t *testing.T, status string, delay time.Duration) string {
	t.Helper()
	return startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		w.Write([]byte(`{"status":"ok","data":{"status":"` + status + `","validating_roas":[]}}`))
	})
}

// TestRealtimePipeline_CapacityOverflow_ReflectedInInfo drives real
// CAPACITY (drop-oldest) backpressure through the full session — not the
// rate cap, which in production (200/10s, always far below the 500
// capacity) would otherwise always trip first in any realistic burst and
// mask capacity backpressure entirely (v1.2 Gate 3 P2 closure: the
// original version of this test, using the real production rate cap,
// could only ever exercise the rate cap — its "capacity overflow" label
// was inaccurate). The rate cap is disabled here via
// startRealtimeSessionWithQueueLimits (an effectively unlimited rateMax)
// while capacity stays at the real production constant (MaxQueueSize),
// and the processor is deliberately slowed by the artificial RPKI-call
// latency. RPKI validation caches by ASN and prefix, so every announcement
// deliberately uses a distinct valid origin ASN and therefore a unique cache
// key. Each processor iteration reaches the delayed fixture, letting the
// reader reliably outrun it and exercise capacity drop-oldest behavior —
// guaranteed by construction, not by timing luck.
func TestRealtimePipeline_CapacityOverflow_ReflectedInInfo(t *testing.T) {
	mgr := session.NewManager()
	client := &Client{BaseURL: slowRPKIFixtureServer(t, "unknown", 20*time.Millisecond)}

	const n = MaxQueueSize + 100
	msgs := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		msgs = append(msgs, []byte(`{"type":"ris_message","data":{"timestamp":1787141896.080,"peer":"37.49.237.143","peer_asn":"50628","id":"burst-`+itoaHelper(i)+`","type":"UPDATE","path":[`+itoaHelper(100+i)+`],"announcements":[{"next_hop":"1.2.3.4","prefixes":["9.9.9.0/24"]}],"withdrawals":[]}}`))
	}
	fake := newFakeRISServer(t, msgs, true)

	rs := startRealtimeSessionWithQueueLimits(context.Background(), mgr, client, "9.9.9.0/24", gorillaDialer{}, fake.wsURL(), MaxQueueSize, 1_000_000, RateWindow)
	t.Cleanup(rs.Stop)

	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		info := rs.Info()
		if info.QueueDroppedEvents > 0 {
			if info.DroppedEventsTotal < info.QueueDroppedEvents {
				t.Errorf("DroppedEventsTotal = %d, want >= QueueDroppedEvents = %d", info.DroppedEventsTotal, info.QueueDroppedEvents)
			}
			return
		}
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatalf("timed out waiting for a capacity overflow (reader should far outpace a 20ms/event artificially-slowed processor); last Info() = %+v", info)
		}
	}
}

// TestRealtimeSession_Info_SurfacesDerivedStateEvictions verifies
// RealtimeSessionInfo.DerivedStateEvictions (v1.2 Gate 3 P1-4 closure) is
// actually wired through Info() end-to-end on a fully constructed
// session, not just present on the struct.
func TestRealtimeSession_Info_SurfacesDerivedStateEvictions(t *testing.T) {
	mgr := session.NewManager()
	client := unknownRPKIClient(t)
	fake := newFakeRISServer(t, nil, true)
	rs := startRealtimeSession(context.Background(), mgr, client, "9.9.9.0/24", gorillaDialer{}, fake.wsURL())
	t.Cleanup(rs.Stop)
	waitForState(t, rs, SessionConnected, 2*time.Second)

	const n = maxTrackedPeers + 50
	for i := 0; i < n; i++ {
		rs.deriveEvents(context.Background(), annEvent(fmt.Sprintf("peer-%d", i), "9.9.9.0/24", asnPath(100)))
	}
	if got := rs.Info().DerivedStateEvictions; got == 0 {
		t.Error("Info().DerivedStateEvictions = 0 after exceeding maxTrackedPeers, want > 0")
	}
}
