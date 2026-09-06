package bgp

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"trazip/internal/session"
)

// newDeriveTestSession builds a minimal RealtimeSession for calling
// deriveEvents directly, bypassing the full supervise()/goroutine
// machinery entirely (no network, no WebSocket) — deriveEvents is pure
// enough (in-memory state + one RPKIValidateDetailed call routed through
// the injected *Client) to unit test this way.
func newDeriveTestSession(client *Client, resolvedPrefix string) *RealtimeSession {
	mgr := session.NewManager()
	sess := mgr.New(context.Background(), "test")
	return &RealtimeSession{
		sess:           sess,
		client:         client,
		derived:        newDerivedState(),
		resolvedPrefix: resolvedPrefix,
		resource:       resolvedPrefix,
	}
}

func asnPath(asns ...int) BGPPath {
	p := make(BGPPath, len(asns))
	for i, a := range asns {
		p[i] = PathElement{Kind: PathElementASN, ASN: a}
	}
	return p
}

func asSetPath(prefix []int, set []int) BGPPath {
	p := asnPath(prefix...)
	return append(p, PathElement{Kind: PathElementASSet, Set: set})
}

var annEventSeq atomic.Uint64

// annEvent builds a synthetic announcement source event with a unique,
// non-empty ID per call (matching real production events, which always
// have one — v1.2 Gate 3 P1-3 closure needs distinct prev/current source
// event IDs to actually exercise derived-event provenance in tests).
func annEvent(peer, prefix string, path BGPPath) BGPRealtimeEvent {
	return BGPRealtimeEvent{
		ID:        fmt.Sprintf("test-src:%d", annEventSeq.Add(1)),
		Type:      EventAnnouncement,
		Peer:      peer,
		Prefix:    prefix,
		Resource:  prefix,
		Path:      path,
		Origin:    deriveOrigin(path, false),
		Source:    "ris-live",
		Timestamp: "2026-01-01T00:00:00Z",
	}
}

func withdrawEvent(peer, prefix string) BGPRealtimeEvent {
	return BGPRealtimeEvent{Type: EventWithdrawal, Peer: peer, Prefix: prefix, Resource: prefix, Source: "ris-live"}
}

func hasEventType(evs []BGPRealtimeEvent, t BGPRealtimeEventType) bool {
	for _, e := range evs {
		if e.Type == t {
			return true
		}
	}
	return false
}

func assertHasEventType(t *testing.T, evs []BGPRealtimeEvent, want BGPRealtimeEventType) {
	t.Helper()
	if !hasEventType(evs, want) {
		types := make([]BGPRealtimeEventType, len(evs))
		for i, e := range evs {
			types[i] = e.Type
		}
		t.Errorf("derived events = %v, want at least one %q", types, want)
	}
}

func assertNoEventType(t *testing.T, evs []BGPRealtimeEvent, unwanted BGPRealtimeEventType) {
	t.Helper()
	if hasEventType(evs, unwanted) {
		t.Errorf("derived events unexpectedly contain %q: %+v", unwanted, evs)
	}
}

// unknownRPKIClient returns a *Client backed by a local fixture server that
// always answers "unknown" — used by path_changed/origin_changed/MOAS
// tests, which incidentally trigger an RPKI check (any announcement with a
// determinate origin does) but must never fail or pollute the result with
// a first-seen "transition".
func unknownRPKIClient(t *testing.T) *Client {
	t.Helper()
	return &Client{BaseURL: rpkiDetailedFixtureServer(t, "unknown")}
}

// --- path_changed ---

func TestDerive_PathChanged_SamePath_NoEvent(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	path := asnPath(100, 200, 300)
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", path))
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", path))
	assertNoEventType(t, out, EventPathChanged)
}

func TestDerive_PathChanged_IntermediateASNChange_Fires(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100, 200, 300)))
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100, 999, 300)))
	assertHasEventType(t, out, EventPathChanged)
}

func TestDerive_PathChanged_ASSetCompositionChange_Fires(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asSetPath([]int{100}, []int{200, 300})))
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asSetPath([]int{100}, []int{200, 400})))
	assertHasEventType(t, out, EventPathChanged)
}

func TestDerive_PathChanged_FirstSeen_NoEvent(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100)))
	assertNoEventType(t, out, EventPathChanged)
}

func TestDerive_PathChanged_WithdrawalThenReannounce_NoFalseChange(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100, 200)))
	rs.deriveEvents(context.Background(), withdrawEvent("peerA", "192.0.2.0/24"))
	// Peer's state was cleared by the withdrawal — a later announcement is
	// "first seen" again, never compared against pre-withdrawal state.
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(999)))
	assertNoEventType(t, out, EventPathChanged)
	assertNoEventType(t, out, EventOriginChanged)
}

// --- origin_changed exactness (v1.2 P1-1, re-verified through the Gate 3 wiring) ---

func TestDerive_OriginChanged_DeterminateToDeterminate_Fires(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(1, 100)))
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(1, 200)))
	assertHasEventType(t, out, EventOriginChanged)
}

func TestDerive_OriginChanged_DeterminateToASSet_NoFire(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(1, 100)))
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asSetPath([]int{1}, []int{200, 300})))
	assertNoEventType(t, out, EventOriginChanged)
}

func TestDerive_OriginChanged_ASSetToDeterminate_NoFire(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asSetPath([]int{1}, []int{200, 300})))
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(1, 100)))
	assertNoEventType(t, out, EventOriginChanged)
}

func TestDerive_OriginChanged_ASSetToASSet_NoFire_ButPathChangedFires(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asSetPath([]int{1}, []int{200, 300})))
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asSetPath([]int{1}, []int{400, 500})))
	assertNoEventType(t, out, EventOriginChanged)
	assertHasEventType(t, out, EventPathChanged)
}

// --- MOAS ---

func TestDerive_MOAS_OneDeterminateOrigin_NoEvent(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100)))
	assertNoEventType(t, out, EventMOASAppeared)
	assertNoEventType(t, out, EventMOASDisappeared)
}

func TestDerive_MOAS_SecondDeterminateOriginAcrossPeer_Appears(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100)))
	out := rs.deriveEvents(context.Background(), annEvent("peerB", "192.0.2.0/24", asnPath(200)))
	assertHasEventType(t, out, EventMOASAppeared)
}

func TestDerive_MOAS_SamePeerReannouncingSameOrigin_NeverAppears(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100)))
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100)))
	assertNoEventType(t, out, EventMOASAppeared)
}

func TestDerive_MOAS_TwoPeersSameOrigin_NeverAppears(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100)))
	out := rs.deriveEvents(context.Background(), annEvent("peerB", "192.0.2.0/24", asnPath(100)))
	assertNoEventType(t, out, EventMOASAppeared)
}

func TestDerive_MOAS_OneOriginWithdraws_Disappears(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100)))
	rs.deriveEvents(context.Background(), annEvent("peerB", "192.0.2.0/24", asnPath(200)))
	out := rs.deriveEvents(context.Background(), withdrawEvent("peerB", "192.0.2.0/24"))
	assertHasEventType(t, out, EventMOASDisappeared)
}

func TestDerive_MOAS_ASSetAlone_NeverMOAS(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asSetPath([]int{1}, []int{100, 200})))
	out := rs.deriveEvents(context.Background(), annEvent("peerB", "192.0.2.0/24", asSetPath([]int{1}, []int{300, 400})))
	assertNoEventType(t, out, EventMOASAppeared)
}

func TestDerive_MOAS_DeterminatePlusASSetPeer_OnlyOneOrigin_NoMOAS(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100)))
	// peerB's origin is indeterminate (AS_SET) — must never count toward
	// the union, so the union stays at exactly 1 determinate origin.
	out := rs.deriveEvents(context.Background(), annEvent("peerB", "192.0.2.0/24", asSetPath([]int{1}, []int{200, 300})))
	assertNoEventType(t, out, EventMOASAppeared)
}

// --- provenance (v1.2 Gate 3 P1-3 closure) ---

func TestDerive_PathChanged_Evidence_ReferencesPreviousAndCurrentSourceEventIDs(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	first := annEvent("peerA", "192.0.2.0/24", asnPath(100, 200, 300))
	rs.deriveEvents(context.Background(), first)
	second := annEvent("peerA", "192.0.2.0/24", asnPath(100, 999, 300))
	out := rs.deriveEvents(context.Background(), second)
	for _, e := range out {
		if e.Type != EventPathChanged {
			continue
		}
		if len(e.Evidence) == 0 {
			t.Fatal("path_changed event has no Evidence — must reference the source events it was computed from")
		}
		ids := e.Evidence[0].SourceEventIDs
		if !containsID(ids, first.ID) {
			t.Errorf("Evidence SourceEventIDs %v never references the previous source event %q", ids, first.ID)
		}
		if !containsID(ids, second.ID) {
			t.Errorf("Evidence SourceEventIDs %v never references the current source event %q", ids, second.ID)
		}
		return
	}
	t.Fatal("no path_changed event produced")
}

func TestDerive_OriginChanged_Evidence_ReferencesPreviousAndCurrentSourceEventIDs(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	first := annEvent("peerA", "192.0.2.0/24", asnPath(1, 100))
	rs.deriveEvents(context.Background(), first)
	second := annEvent("peerA", "192.0.2.0/24", asnPath(1, 200))
	out := rs.deriveEvents(context.Background(), second)
	for _, e := range out {
		if e.Type != EventOriginChanged {
			continue
		}
		if len(e.Evidence) == 0 {
			t.Fatal("origin_changed event has no Evidence — must reference the source events it was computed from")
		}
		ids := e.Evidence[0].SourceEventIDs
		if !containsID(ids, first.ID) || !containsID(ids, second.ID) {
			t.Errorf("Evidence SourceEventIDs %v must reference both %q and %q", ids, first.ID, second.ID)
		}
		return
	}
	t.Fatal("no origin_changed event produced")
}

func TestDerive_MOAS_Evidence_NeverEmpty_NeverPresentsASSetAsOrigin(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100)))
	// peerB is an AS_SET (indeterminate) — must never be presented as
	// origin evidence, even though it's the event that triggered this
	// particular recompute call.
	rs.deriveEvents(context.Background(), annEvent("peerB", "192.0.2.0/24", asSetPath([]int{1}, []int{900, 901})))
	triggering := annEvent("peerC", "192.0.2.0/24", asnPath(200))
	out := rs.deriveEvents(context.Background(), triggering)
	for _, e := range out {
		if e.Type != EventMOASAppeared {
			continue
		}
		if len(e.Evidence) == 0 {
			t.Fatal("moas_appeared event has no Evidence — must reference the determinate source observations that established the transition")
		}
		if !containsID(e.Evidence[0].SourceEventIDs, triggering.ID) {
			t.Errorf("Evidence SourceEventIDs %v never references the triggering source event %q", e.Evidence[0].SourceEventIDs, triggering.ID)
		}
		return
	}
	t.Fatal("no moas_appeared event produced")
}

func containsID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// --- bounded derived state (v1.2 Gate 3 P1-4 closure) ---

func TestDerive_BoundedPeerState_NeverExceedsCapacity(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	const n = maxTrackedPeers + 200
	for i := 0; i < n; i++ {
		peer := fmt.Sprintf("peer-%d", i)
		rs.deriveEvents(context.Background(), annEvent(peer, "192.0.2.0/24", asnPath(100)))
		if got := rs.derived.perPeer.Len(); got > maxTrackedPeers {
			t.Fatalf("perPeer.Len() = %d after %d distinct peers, want <= %d", got, i+1, maxTrackedPeers)
		}
	}
	if rs.derived.Evictions() == 0 {
		t.Error("Evictions() = 0 after exceeding capacity by 200 peers, want > 0 — state loss must be transparent, not silent")
	}
}

func TestDerive_BoundedPeerState_ASSetSemanticsIntact_UnderEvictionPressure(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	// Push far past capacity with AS_SET-only peers — none of them is ever
	// determinate, so MOAS must never fire regardless of how much eviction
	// churn the bounded tracker goes through (bounding memory must never
	// change AS_SET semantics).
	const n = maxTrackedPeers + 200
	for i := 0; i < n; i++ {
		peer := fmt.Sprintf("peer-%d", i)
		out := rs.deriveEvents(context.Background(), annEvent(peer, "192.0.2.0/24", asSetPath([]int{1}, []int{100, 200})))
		assertNoEventType(t, out, EventMOASAppeared)
	}
}

func TestDerive_BoundedASNRPKIState_NeverExceedsCapacity(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	const n = maxTrackedASNs + 100
	for i := 0; i < n; i++ {
		rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(1000+i)))
		if got := rs.derived.perASNRPKI.Len(); got > maxTrackedASNs {
			t.Fatalf("perASNRPKI.Len() = %d after %d distinct ASNs, want <= %d", got, i+1, maxTrackedASNs)
		}
	}
	if rs.derived.Evictions() == 0 {
		t.Error("Evictions() = 0 after exceeding maxTrackedASNs, want > 0")
	}
}

// --- MOAS suppression after perPeer eviction (v1.2 Gate 3 P1 residual
// closure: LRU eviction must never fabricate a MOAS transition) ---

func TestDerive_MOAS_PeerEviction_NeverFabricatesDisappearance(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")

	// 1. Real state: peerA -> AS100, peerB -> AS200.
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100)))
	out := rs.deriveEvents(context.Background(), annEvent("peerB", "192.0.2.0/24", asnPath(200)))
	// 2. moas_appeared occurred.
	assertHasEventType(t, out, EventMOASAppeared)

	// 3. Force enough LRU pressure to evict peerA — WITHOUT ever sending a
	// withdrawal for it. peerA/peerB were touched first, so they are the
	// least-recently-used entries; enough new distinct peers push peerA out
	// first.
	for i := 0; i < maxTrackedPeers-1; i++ {
		peer := fmt.Sprintf("evict-%d", i)
		out := rs.deriveEvents(context.Background(), annEvent(peer, "192.0.2.0/24", asnPath(300+i)))
		// No individual step in this eviction pressure may fabricate a
		// disappearance either.
		assertNoEventType(t, out, EventMOASDisappeared)
		if got := rs.derived.perPeer.Len(); got > maxTrackedPeers {
			t.Fatalf("perPeer.Len() = %d, want <= %d", got, maxTrackedPeers)
		}
	}

	// 4. Eviction actually happened.
	if rs.derived.Evictions() == 0 {
		t.Fatal("Evictions() = 0, want > 0 — peerA must have been evicted by LRU pressure")
	}
	if _, stillTracked := rs.derived.perPeer.Get("peerA"); stillTracked {
		t.Fatal("peerA still tracked — test setup did not actually evict it")
	}

	// 6. A further announcement/withdrawal, insufficient to reconstruct a
	// complete view, must never emit moas_appeared/moas_disappeared while
	// the MOAS view stays degraded.
	out = rs.deriveEvents(context.Background(), annEvent("peerB", "192.0.2.0/24", asnPath(200)))
	assertNoEventType(t, out, EventMOASAppeared)
	assertNoEventType(t, out, EventMOASDisappeared)

	out = rs.deriveEvents(context.Background(), withdrawEvent("peerB", "192.0.2.0/24"))
	assertNoEventType(t, out, EventMOASAppeared)
	assertNoEventType(t, out, EventMOASDisappeared)
}

func TestDerive_MOAS_PeerEviction_PathOriginChangedStillFireForTrackedPeers(t *testing.T) {
	rs := newDeriveTestSession(unknownRPKIClient(t), "192.0.2.0/24")
	rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100)))
	rs.deriveEvents(context.Background(), annEvent("peerB", "192.0.2.0/24", asnPath(200)))
	for i := 0; i < maxTrackedPeers-1; i++ {
		peer := fmt.Sprintf("evict-%d", i)
		rs.deriveEvents(context.Background(), annEvent(peer, "192.0.2.0/24", asnPath(300+i)))
	}
	if _, stillTracked := rs.derived.perPeer.Get("peerA"); stillTracked {
		t.Fatal("peerA still tracked — test setup did not actually evict it")
	}

	// peerB is still tracked — origin_changed must still fire normally for
	// it, degraded MOAS tracking notwithstanding.
	out := rs.deriveEvents(context.Background(), annEvent("peerB", "192.0.2.0/24", asnPath(999)))
	assertHasEventType(t, out, EventOriginChanged)

	// peerA was evicted, not withdrawn — a later announcement from it must
	// be treated as first seen, never compared against its pre-eviction
	// state.
	out = rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(1)))
	assertNoEventType(t, out, EventPathChanged)
	assertNoEventType(t, out, EventOriginChanged)
}

// --- rpki_transition ---

func TestDerive_RPKITransition_FirstSeen_NoTransition(t *testing.T) {
	client := &Client{BaseURL: rpkiDetailedFixtureServer(t, "valid")}
	rs := newDeriveTestSession(client, "192.0.2.0/24")
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100)))
	assertNoEventType(t, out, EventRPKITransition)
}

func TestDerive_RPKITransition_SameStateAgain_NoTransition(t *testing.T) {
	client := &Client{BaseURL: rpkiDetailedFixtureServer(t, "valid")}
	rs := newDeriveTestSession(client, "192.0.2.0/24")
	rs.derived.perASNRPKI.Set(100, asnRPKIBaseline{State: "VALID", SourceEventID: "seed:0"})
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100)))
	assertNoEventType(t, out, EventRPKITransition)
}

func TestDerive_RPKITransition_DifferentState_Fires(t *testing.T) {
	client := &Client{BaseURL: rpkiDetailedFixtureServer(t, "invalid_asn")}
	rs := newDeriveTestSession(client, "192.0.2.0/24")
	rs.derived.perASNRPKI.Set(100, asnRPKIBaseline{State: "VALID", SourceEventID: "seed:0"})
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asnPath(100)))
	assertHasEventType(t, out, EventRPKITransition)
	for _, e := range out {
		if e.Type != EventRPKITransition {
			continue
		}
		if e.Previous == nil || e.Previous.RPKIState != "VALID" {
			t.Errorf("Previous.RPKIState = %+v, want VALID", e.Previous)
		}
		if e.Current == nil || e.Current.RPKIState != "INVALID_ASN" {
			t.Errorf("Current.RPKIState = %+v, want INVALID_ASN", e.Current)
		}
		if len(e.Evidence) == 0 {
			t.Error("rpki_transition event has no Evidence — must reference the real RPKIValidateDetailed call")
		}
		// v1.2 Gate 3 P1-3 closure: provenance must be real, not just
		// non-empty — one Evidence entry must reference the baseline's own
		// (different) source event, so "there was a real transition" can
		// be checked against a concrete previous observation.
		foundBaseline := false
		for _, ev := range e.Evidence {
			for _, id := range ev.SourceEventIDs {
				if id == "seed:0" {
					foundBaseline = true
				}
			}
		}
		if !foundBaseline {
			t.Errorf("Evidence never references the baseline's source event id %q: %+v", "seed:0", e.Evidence)
		}
	}
}

func TestDerive_RPKITransition_NeverCalledForASSetMembers(t *testing.T) {
	client := &Client{BaseURL: failIfCalledHTTP(t)} // must never be queried
	rs := newDeriveTestSession(client, "192.0.2.0/24")
	out := rs.deriveEvents(context.Background(), annEvent("peerA", "192.0.2.0/24", asSetPath([]int{1}, []int{100, 200})))
	assertNoEventType(t, out, EventRPKITransition)
}

func TestDerive_RPKITransition_NeverCalledForWithdrawal(t *testing.T) {
	client := &Client{BaseURL: failIfCalledHTTP(t)} // must never be queried
	rs := newDeriveTestSession(client, "192.0.2.0/24")
	out := rs.deriveEvents(context.Background(), withdrawEvent("peerA", "192.0.2.0/24"))
	assertNoEventType(t, out, EventRPKITransition)
}
