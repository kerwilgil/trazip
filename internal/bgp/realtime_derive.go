// Derived-event wiring — v1.2 Gate 3 (BGP_INTELLIGENCE_ROADMAP.md §23.3).
// The pure comparators (OriginChanged/PathChanged) live in
// realtime_event.go, which documents itself as I/O-free. This file is
// deliberately separate because rpki_transition requires a real network
// call (Client.RPKIValidateDetailed) — never invoked from the WebSocket
// reader goroutine (that would violate §23.7's reader/processor split);
// only the processor goroutine (realtime.go's processLoop) calls into
// this file, one event at a time, off the read path.
//
// State here is bounded EXPLICITLY (v1.2 Gate 3 P1-4 closure) via
// boundedLRU (realtime_lru.go) — never a plain map that could grow for as
// long as the session stays connected. Capacity is deliberately generous
// relative to the roadmap's own §23.1 probe data (bgplay.sources had ~370
// distinct peers for one popular prefix in 24h) while still being an
// explicit, deterministic bound, never an unbounded/user-controlled
// growth path.
package bgp

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

const (
	// maxTrackedPeers bounds derivedState.perPeer — comfortably above the
	// roadmap's own real-world probe (~370 distinct peers observed for one
	// popular prefix, §23.1 C), while still an explicit, deterministic
	// cap, never "in practice it'll be a few hundred" left unenforced.
	maxTrackedPeers = 1024
	// maxTrackedASNs bounds derivedState.perASNRPKI — MOAS origin counts
	// are realistically single/low-double-digit even in adversarial
	// cases; 256 is generous headroom while remaining bounded.
	maxTrackedASNs = 256
)

// asnRPKIBaseline is the last known RPKI validation baseline for one
// determinate origin ASN, plus which source event established it — the
// latter lets rpki_transition's Evidence honestly reference the baseline
// it transitioned FROM (v1.2 Gate 3 P1-3 closure), not just the new call.
type asnRPKIBaseline struct {
	State         string
	SourceEventID string
}

// derivedState is the per-session bounded tracker for derived-event
// comparisons. One instance per RealtimeSession, torn down with it (no
// persistence, roadmap §23.4).
type derivedState struct {
	mu sync.Mutex

	// perPeer holds the last known Path/Origin snapshot per peer IP for
	// this session's single resolved prefix (§23.2: a v1.2 realtime
	// session monitors exactly one ResolvedPrefix), bounded to
	// maxTrackedPeers via LRU eviction (v1.2 Gate 3 P1-4 closure). A
	// withdrawal clears the peer's entry via Delete (a real, source-driven
	// removal, never counted as an eviction) — a later announcement from
	// that peer is then treated as "first seen" again (no
	// path_changed/origin_changed fires against pre-withdrawal state that
	// RIS Live itself declared gone). An LRU eviction behaves identically
	// from the comparison's point of view (the next announcement from
	// that peer is "first seen" again) — the difference is purely
	// bookkeeping: an eviction increments perPeer.Evicted() (surfaced via
	// Evictions() below), a withdrawal never does, since only the former
	// represents state TRAZIP lost track of, not state BGP itself
	// retracted.
	perPeer *boundedLRU[string, BGPRealtimeChangeSnapshot]

	// moasActive is the last known aggregate MOAS state (roadmap §23.3):
	// true when the UNION of all currently-tracked peers' DETERMINATE
	// origin ASNs has more than one distinct member. AS_SET origins never
	// contribute to this union (v1.2 P1-1 closure, unchanged). An LRU
	// eviction of a peer entry never by itself triggers a MOAS
	// recompute/emit (only deriveEvents, reacting to a real source event,
	// calls recomputeMOASLocked) — so an eviction can never fabricate a
	// moas_disappeared that RIS Live never actually reported (v1.2 Gate 3
	// P1-4 requirement). It CAN silently reduce future MOAS certainty
	// (an evicted peer's contribution is simply no longer counted) —
	// that degradation is exactly what Evictions() makes observable
	// instead of leaving it silent.
	moasActive bool

	// perASNRPKI holds the last known RPKI validation baseline per
	// determinate origin ASN observed for this prefix — keyed by ASN, not
	// by peer, because RPKI validity is a property of (ASN, prefix), and
	// multiple peers reporting the SAME determinate origin must not
	// re-trigger redundant "first seen" baselines. Bounded to
	// maxTrackedASNs via LRU eviction (v1.2 Gate 3 P1-4 closure).
	perASNRPKI *boundedLRU[int, asnRPKIBaseline]

	// moasDegraded becomes true the first time perPeer evicts an entry
	// (v1.2 Gate 3 P1 residual closure — audit finding: LRU eviction must
	// never fabricate a MOAS transition). Once a peer falls out of
	// perPeer, TRAZIP can no longer prove the cross-peer origin union it
	// recomputes on the NEXT event is complete — the evicted peer might
	// have been the sole holder of a distinct origin, and its absence from
	// a later recompute would look identical to a real withdrawal it never
	// sent. There is no periodic/background reconstruction in v1.2 (never
	// added just to clear this flag), so once true it stays true for the
	// rest of the session — recomputeMOASLocked below stops emitting
	// moas_appeared/moas_disappeared entirely rather than risk asserting a
	// change from a view TRAZIP knows is incomplete.
	moasDegraded bool

	seq atomic.Uint64 // contador monotónico de derived-event Seq (roadmap §23.3 ID format)
}

func newDerivedState() *derivedState {
	return &derivedState{
		perPeer:    newBoundedLRU[string, BGPRealtimeChangeSnapshot](maxTrackedPeers),
		perASNRPKI: newBoundedLRU[int, asnRPKIBaseline](maxTrackedASNs),
	}
}

// Evictions reports the total number of LRU evictions across both bounded
// trackers so far — exposed via RealtimeSessionInfo.DerivedStateEvictions
// so that a loss of state that could affect derived-event certainty is
// transparent, never silent (v1.2 Gate 3 P1-4 closure).
func (d *derivedState) Evictions() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.perPeer.Evicted() + d.perASNRPKI.Evicted()
}

// deriveEvents processes one source event (announcement/withdrawal),
// updates the bounded per-session state, and returns zero or more derived
// BGPRealtimeEvent (path_changed/origin_changed/moas_appeared/
// moas_disappeared/rpki_transition) — never a duplicate of the source
// event's own fact (roadmap §23.3 "Nunca duplicar"). Every derived event
// that asserts a change carries Evidence referencing the exact source
// events it was computed from (v1.2 Gate 3 P1-3 closure) — never left
// empty.
func (rs *RealtimeSession) deriveEvents(ctx context.Context, ev BGPRealtimeEvent) []BGPRealtimeEvent {
	if ev.Peer == "" {
		return nil
	}
	d := rs.derived

	d.mu.Lock()
	var out []BGPRealtimeEvent
	switch ev.Type {
	case EventWithdrawal:
		d.perPeer.Delete(ev.Peer) // real BGP withdrawal — never counted as an eviction
	case EventAnnouncement:
		cur := BGPRealtimeChangeSnapshot{Path: ev.Path, Origin: ev.Origin, SourceEventID: ev.ID}
		if prev, hadPrev := d.perPeer.Get(ev.Peer); hadPrev {
			if PathChanged(prev.Path, cur.Path) {
				de := rs.newDerivedEvent(EventPathChanged, ev, snapshotPtr(prev), snapshotPtr(cur))
				de.Evidence = provenanceEvidence(prev.SourceEventID, cur.SourceEventID)
				out = append(out, de)
			}
			if OriginChanged(prev.Origin, cur.Origin) {
				de := rs.newDerivedEvent(EventOriginChanged, ev, snapshotPtr(prev), snapshotPtr(cur))
				de.Evidence = provenanceEvidence(prev.SourceEventID, cur.SourceEventID)
				out = append(out, de)
			}
		}
		evictedBefore := d.perPeer.Evicted()
		d.perPeer.Set(ev.Peer, cur)
		if d.perPeer.Evicted() > evictedBefore {
			// Capacity, not a withdrawal, just dropped some OTHER peer's
			// tracked state — the cross-peer view recomputeMOASLocked reads
			// below (and on every future call) can no longer be trusted as
			// complete. Never counted as a withdrawal, never cleared once
			// set (see moasDegraded's own doc above).
			d.moasDegraded = true
		}
	}
	out = append(out, rs.recomputeMOASLocked(ev)...)
	d.mu.Unlock()

	// RPKI transition: real network I/O (via the shared, cached
	// Client.RPKIValidateDetailed) — deliberately done AFTER releasing
	// d.mu, never while holding it, so a slow/degraded RIPEstat call can
	// never block other event processing that only needs the in-memory
	// state above.
	if ev.Type == EventAnnouncement && ev.Origin.Determinate {
		if rpkiEv, ok := rs.checkRPKITransition(ctx, ev); ok {
			out = append(out, rpkiEv)
		}
	}
	return out
}

func snapshotPtr(s BGPRealtimeChangeSnapshot) *BGPRealtimeChangeSnapshot { return &s }

// provenanceEvidence builds the minimal ComponentEvidence entry that lets
// a path_changed/origin_changed/moas_* derived event honestly reference
// the exact source events it was computed from — never left empty when
// the derived event asserts a change (v1.2 Gate 3 P1-3 closure). No
// external network call backs this evidence (it is a pure in-memory
// comparison of already-received source events), so Disclosure/FromCache
// stay at their zero value; Status is still ComponentOK because the
// referenced data WAS available and usable — never
// ComponentNotApplicable/ComponentDegraded, neither of which describes
// what happened here. Empty/blank IDs are dropped; returns nil (never an
// empty-but-non-nil slice presented as if it referenced something) if
// nothing usable was passed.
func provenanceEvidence(sourceEventIDs ...string) []ComponentEvidence {
	ids := make([]string, 0, len(sourceEventIDs))
	for _, id := range sourceEventIDs {
		if id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return []ComponentEvidence{{
		Component:      "bgp-realtime-derivation",
		Status:         ComponentOK,
		SourceEventIDs: ids,
	}}
}

// recomputeMOASLocked recomputes the union of currently-determinate origin
// ASNs across all tracked peers and emits moas_appeared/moas_disappeared
// exactly on the 1<->>1 threshold crossing (roadmap §23.3). Caller must
// hold d.mu. AS_SET (indeterminate) origins never enter this union — a
// peer with no determinate origin simply doesn't contribute a member, and
// is never presented as origin evidence either (v1.2 Gate 3 P1-3
// closure).
func (rs *RealtimeSession) recomputeMOASLocked(ev BGPRealtimeEvent) []BGPRealtimeEvent {
	d := rs.derived
	if d.moasDegraded {
		// A perPeer eviction already made the cross-peer origin view
		// unprovable-complete (moasDegraded's doc above) — emitting
		// moas_appeared/moas_disappeared from here on would risk asserting
		// a change that is really just TRAZIP having forgotten a peer, not
		// RIS Live reporting one. d.moasActive is deliberately left
		// untouched (never silently re-synced against the reduced view).
		return nil
	}
	distinct := make(map[int]struct{})
	contributing := []string{ev.ID} // el evento que disparó este recompute — siempre referenciado primero
	d.perPeer.Range(func(_ string, snap BGPRealtimeChangeSnapshot) {
		if snap.Origin.Determinate {
			distinct[snap.Origin.ASN] = struct{}{}
			if snap.SourceEventID != "" {
				contributing = append(contributing, snap.SourceEventID)
			}
		}
	})
	now := len(distinct) > 1
	if now == d.moasActive {
		return nil
	}
	d.moasActive = now
	t := EventMOASAppeared
	if !now {
		t = EventMOASDisappeared
	}
	cur := BGPRealtimeChangeSnapshot{Path: ev.Path, Origin: ev.Origin, SourceEventID: ev.ID}
	de := rs.newDerivedEvent(t, ev, nil, &cur)
	de.Evidence = provenanceEvidence(contributing...)
	return []BGPRealtimeEvent{de}
}

// checkRPKITransition validates RPKI for ev.Origin.ASN (only ever called
// when ev.Origin.Determinate — never for AS_SET members, v1.2 P1-1
// closure) via the existing v1.1 Client.RPKIValidateDetailed (own cache,
// never a second validator). Emits rpki_transition only when a PREVIOUSLY
// known baseline for that ASN differs from the fresh one — the first
// validation of a given ASN establishes a baseline, never a fabricated
// "transition from nothing". A degraded/failed validation call never
// fabricates a transition either.
func (rs *RealtimeSession) checkRPKITransition(ctx context.Context, ev BGPRealtimeEvent) (BGPRealtimeEvent, bool) {
	prefix := rs.getResolvedPrefix()
	if prefix == "" {
		return BGPRealtimeEvent{}, false
	}
	result := rs.client.RPKIValidateDetailed(ctx, ev.Origin.ASN, prefix)
	if result.Err != "" || result.Evidence.Status != ComponentOK {
		return BGPRealtimeEvent{}, false
	}
	newState := string(result.State)

	d := rs.derived
	d.mu.Lock()
	prevBaseline, had := d.perASNRPKI.Get(ev.Origin.ASN)
	d.perASNRPKI.Set(ev.Origin.ASN, asnRPKIBaseline{State: newState, SourceEventID: ev.ID})
	d.mu.Unlock()

	if !had || prevBaseline.State == newState {
		return BGPRealtimeEvent{}, false
	}
	prev := BGPRealtimeChangeSnapshot{Origin: ev.Origin, RPKIState: prevBaseline.State, SourceEventID: prevBaseline.SourceEventID}
	cur := BGPRealtimeChangeSnapshot{Origin: ev.Origin, RPKIState: newState, SourceEventID: ev.ID}
	out := rs.newDerivedEvent(EventRPKITransition, ev, &prev, &cur)

	// Evidence[0]: la evidencia REAL de la llamada RPKIValidateDetailed
	// que disparó esta transición — nunca fabricada — anotada con el
	// source event que la disparó (v1.2 Gate 3 P1-3 closure).
	realEvidence := result.Evidence
	if len(realEvidence.SourceEventIDs) == 0 {
		realEvidence.SourceEventIDs = []string{ev.ID}
	}
	evidence := []ComponentEvidence{realEvidence}
	// Evidence[1] (si distinto del disparador): referencia el source event
	// que estableció el baseline PREVIO — sin esto, "hubo una transición
	// real de estado" solo se podría afirmar contra un baseline invisible
	// para el consumidor.
	if prevBaseline.SourceEventID != "" && prevBaseline.SourceEventID != ev.ID {
		evidence = append(evidence, ComponentEvidence{
			Component:      "bgp-realtime-derivation",
			Status:         ComponentOK,
			SourceEventIDs: []string{prevBaseline.SourceEventID},
		})
	}
	out.Evidence = evidence
	return out, true
}

// newDerivedEvent builds a derived BGPRealtimeEvent with the exact ID
// format frozen in the roadmap for derived events:
// "<SessionID>:<Type>:<Prefix>:<Seq>" (Seq = per-session monotonic
// counter) — never sharing a SourceMessageID, since a derived event has no
// single originating wire message (roadmap §23.3).
func (rs *RealtimeSession) newDerivedEvent(t BGPRealtimeEventType, source BGPRealtimeEvent, prev, cur *BGPRealtimeChangeSnapshot) BGPRealtimeEvent {
	seq := rs.derived.seq.Add(1)
	return BGPRealtimeEvent{
		ID:        fmt.Sprintf("%s:%s:%s:%d", rs.sess.ID, t, source.Prefix, seq),
		Timestamp: source.Timestamp,
		Type:      t,
		Resource:  source.Resource,
		Prefix:    source.Prefix,
		PeerASN:   source.PeerASN,
		Peer:      source.Peer,
		Path:      source.Path,
		Origin:    source.Origin,
		Previous:  prev,
		Current:   cur,
		Source:    "derived",
	}
}
