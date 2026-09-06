package monitor

import (
	"strings"
	"testing"
	"time"
)

// These tests drive routeTracker.observe directly with hand-built MTR
// samples — deterministic, no live probing — pinning down every worked
// example from the master plan's own Phase D spec. mkHops builds one
// sample's hop list from TTL 1..N; an empty string at position i means "no
// response at TTL i+1" (a timeout), matching RouteHop.Addr's own
// convention.

func mkHops(addrs ...string) []Hop {
	out := make([]Hop, len(addrs))
	for i, a := range addrs {
		out[i] = Hop{TTL: i + 1, Addr: a}
	}
	return out
}

var testClock = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func nextTime() string {
	testClock = testClock.Add(5 * time.Second)
	return testClock.Format(time.RFC3339)
}

func timeOffset(base string, d time.Duration) string {
	t, err := time.Parse(time.RFC3339, base)
	if err != nil {
		panic(err)
	}
	return t.Add(d).Format(time.RFC3339)
}

func mkSample(hops []Hop) Sample {
	return Sample{Time: nextTime(), OK: len(hops) > 0, RTTms: 20, LossPct: 0, HopCount: len(hops), Hops: hops}
}

func mkSampleMetrics(hops []Hop, ok bool, rtt, loss float64) Sample {
	return Sample{Time: nextTime(), OK: ok, RTTms: rtt, LossPct: loss, HopCount: len(hops), Hops: hops}
}

// feed observes every sample in order (no degradation events) and returns
// every non-nil RouteChange produced, in order.
func feed(rt *routeTracker, targetID string, samples ...[]Hop) []*RouteChange {
	var out []*RouteChange
	for _, hops := range samples {
		if rc := rt.observe(targetID, mkSample(hops), nil); rc != nil {
			out = append(out, rc)
		}
	}
	return out
}

// 1. Stable route: no event.
func TestRouteChangeStableRoute(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1", mkHops("A", "B", "C"), mkHops("A", "B", "C"), mkHops("A", "B", "C"))
	if len(changes) != 0 {
		t.Fatalf("got %d changes, want 0 for a stable route: %+v", len(changes), changes)
	}
}

// 2. Transient change: a single divergent sample followed by a revert must
// never confirm.
func TestRouteChangeTransientNoEvent(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1", mkHops("A", "B", "C"), mkHops("A", "X", "C"), mkHops("A", "B", "C"))
	if len(changes) != 0 {
		t.Fatalf("got %d changes, want 0 for a transient blip: %+v", len(changes), changes)
	}
}

// 3. Persistent change: two consecutive divergent samples must confirm
// exactly once — the master plan's own minimal worked example.
func TestRouteChangePersistentConfirmsOnce(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1", mkHops("A", "B", "C"), mkHops("A", "X", "C"), mkHops("A", "X", "C"))
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want exactly 1: %+v", len(changes), changes)
	}
	if changes[0].FirstChangedTTL != 2 {
		t.Errorf("FirstChangedTTL = %d, want 2", changes[0].FirstChangedTTL)
	}
	if !changes[0].Persistent {
		t.Error("Persistent should always be true for a confirmed RouteChange")
	}
}

// 4. hop_changed is classified when the same-length route differs at one TTL.
func TestRouteChangeHopChanged(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1",
		mkHops("A", "B", "C", "D"),
		mkHops("A", "B", "X", "D"),
		mkHops("A", "B", "X", "D"),
	)
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want 1", len(changes))
	}
	rc := changes[0]
	if !containsStr(rc.ChangeTypes, "hop_changed") {
		t.Errorf("ChangeTypes = %v, want hop_changed", rc.ChangeTypes)
	}
	if rc.FirstChangedTTL != 3 {
		t.Errorf("FirstChangedTTL = %d, want 3 (matches the master plan's own worked example)", rc.FirstChangedTTL)
	}
}

// 5. hop_added: a TTL that didn't exist in the old (shorter) route appears.
func TestRouteChangeHopAdded(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1",
		mkHops("A", "B"),
		mkHops("A", "B", "C"),
		mkHops("A", "B", "C"),
	)
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want 1", len(changes))
	}
	if !containsStr(changes[0].ChangeTypes, "hop_added") {
		t.Errorf("ChangeTypes = %v, want hop_added", changes[0].ChangeTypes)
	}
}

// 6. hop_removed: a TTL that existed with a real reply is now gone.
func TestRouteChangeHopRemoved(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1",
		mkHops("A", "B", "C"),
		mkHops("A", "B"),
		mkHops("A", "B"),
	)
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want 1", len(changes))
	}
	if !containsStr(changes[0].ChangeTypes, "hop_removed") {
		t.Errorf("ChangeTypes = %v, want hop_removed", changes[0].ChangeTypes)
	}
}

// 7. hop_count_changed accompanies a route-length change, with
// Before/AfterHopCount set honestly.
func TestRouteChangeHopCountChanged(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1",
		mkHops("A", "B", "C"),
		mkHops("A", "B"),
		mkHops("A", "B"),
	)
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want 1", len(changes))
	}
	rc := changes[0]
	if !containsStr(rc.ChangeTypes, "hop_count_changed") {
		t.Errorf("ChangeTypes = %v, want hop_count_changed", rc.ChangeTypes)
	}
	if rc.BeforeHopCount != 3 || rc.AfterHopCount != 2 {
		t.Errorf("BeforeHopCount=%d AfterHopCount=%d, want 3/2", rc.BeforeHopCount, rc.AfterHopCount)
	}
}

// 8. A single transient timeout at one TTL must never be read as a change.
func TestRouteChangeTimeoutTransientNoEvent(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1", mkHops("A", "B", "C"), mkHops("A", "", "C"), mkHops("A", "B", "C"))
	if len(changes) != 0 {
		t.Fatalf("got %d changes, want 0 for a transient timeout: %+v", len(changes), changes)
	}
}

// 9. A persistent change survives a timeout in the middle of confirming —
// detected exactly once, never lost or duplicated by the noise.
func TestRouteChangePersistentSurvivesTimeoutNoise(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1",
		mkHops("A", "B", "C"),
		mkHops("A", "X", "C"),
		mkHops("A", "", "C"), // timeout at the diverging TTL mid-confirmation
		mkHops("A", "X", "C"),
		mkHops("A", "X", "C"),
	)
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want exactly 1 despite the timeout noise: %+v", len(changes), changes)
	}
	if changes[0].After[1].Addr != "X" {
		t.Errorf("After = %+v, want TTL2=X", changes[0].After)
	}
}

// 10. ECMP alternating forever must never produce an event storm — the
// route never repeats itself long enough to confirm either variant.
func TestRouteChangeECMPAlternatingNoStorm(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1",
		mkHops("A", "B", "C"), mkHops("A", "X", "C"),
		mkHops("A", "B", "C"), mkHops("A", "X", "C"),
		mkHops("A", "B", "C"), mkHops("A", "X", "C"),
	)
	if len(changes) != 0 {
		t.Fatalf("got %d changes, want 0 for pure ECMP alternation: %+v", len(changes), changes)
	}
}

// 11. A stable (alternating) baseline followed by a genuinely new path that
// persists must confirm exactly once.
func TestRouteChangeECMPBaselineThenGenuineChange(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1",
		mkHops("A", "B", "C"), mkHops("A", "X", "C"), mkHops("A", "B", "C"), mkHops("A", "X", "C"),
		mkHops("A", "Y", "C"), mkHops("A", "Y", "C"),
	)
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want exactly 1 for the genuinely new persistent path: %+v", len(changes), changes)
	}
	if changes[0].After[1].Addr != "Y" {
		t.Errorf("After = %+v, want TTL2=Y", changes[0].After)
	}
}

// 12. Comparison is IP-only — RouteHop carries no hostname/PTR field to
// compare on in the first place, so a hostname-only "change" cannot even be
// constructed; this documents that guarantee structurally.
func TestRouteChangeIdentityIsIPOnly(t *testing.T) {
	rt := newRouteTracker()
	h1 := []Hop{{TTL: 1, Addr: "A"}, {TTL: 2, Addr: "B", Host: "old-name.example"}}
	h2 := []Hop{{TTL: 1, Addr: "A"}, {TTL: 2, Addr: "B", Host: "new-name.example"}}
	changes := feed(rt, "t1", h1, h2, h2)
	if len(changes) != 0 {
		t.Fatalf("got %d changes, want 0 — only Host differs, never used for identity: %+v", len(changes), changes)
	}
}

// 13. A change without an associated degradation is still a valid event,
// but CoincidentDegradation must be false.
func TestRouteChangeWithoutDegradation(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSample(mkHops("A", "B", "C")), nil)
	rc := rt.observe("t1", mkSample(mkHops("A", "X", "C")), nil)
	if rc != nil {
		t.Fatal("expected no change yet after only one divergent sample")
	}
	rc = rt.observe("t1", mkSample(mkHops("A", "X", "C")), nil)
	if rc == nil {
		t.Fatal("expected a confirmed change")
	}
	if rc.CoincidentDegradation {
		t.Error("CoincidentDegradation should be false with no degradation events at all")
	}
}

// 14. A change confirmed with a loss/latency DegradationEvent inside
// routeChangeDegradationWindow must set CoincidentDegradation, reference
// that specific event in Evidence, and carry the hedged limitation.
func TestRouteChangeWithDegradation(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSample(mkHops("A", "B", "C")), nil)
	rt.observe("t1", mkSample(mkHops("A", "X", "C")), nil)
	confirmSample := mkSample(mkHops("A", "X", "C"))
	events := []DegradationEvent{{Time: timeOffset(confirmSample.Time, -90 * time.Second), Kind: "loss"}}
	rc := rt.observe("t1", confirmSample, events)
	if rc == nil {
		t.Fatal("expected a confirmed change")
	}
	if !rc.CoincidentDegradation {
		t.Error("CoincidentDegradation should be true with a loss event inside the window")
	}
	found := false
	for _, ev := range rc.Evidence {
		if ev.Type == "route_change_timing" && strings.Contains(ev.Value, "loss") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected route_change_timing evidence referencing the specific loss event, got %+v", rc.Evidence)
	}
	limFound := false
	for _, l := range rc.Limitations {
		if l == "La coincidencia temporal no demuestra causalidad." {
			limFound = true
		}
	}
	if !limFound {
		t.Errorf("expected the mandatory causality-hedge limitation, got %v", rc.Limitations)
	}
	for _, forbidden := range []string{"causó", "provocó", "responsable de"} {
		for _, ev := range rc.Evidence {
			if strings.Contains(ev.Explain, forbidden) {
				t.Errorf("Evidence must never assert causation: contains %q in %q", forbidden, ev.Explain)
			}
		}
	}
}

// 15. Degradation alone must never synthesize a route change — that's
// evaluateDegradation's own job, entirely separate from routeTracker.
func TestDegradationAloneDoesNotSynthesizeRouteChange(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1", mkHops("A", "B", "C"), mkHops("A", "B", "C"), mkHops("A", "B", "C"))
	if len(changes) != 0 {
		t.Fatalf("a stable route observed alongside degradation must not produce a route change: %+v", changes)
	}
}

// 16. Duplicate suppression: once a new route is confirmed and becomes the
// baseline, subsequent matching samples must not re-fire.
func TestRouteChangeDuplicateSuppression(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1",
		mkHops("A", "B", "C"),
		mkHops("A", "X", "C"), mkHops("A", "X", "C"), // confirms here
		mkHops("A", "X", "C"), mkHops("A", "X", "C"), mkHops("A", "X", "C"), // stable on the new route
	)
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want exactly 1 — subsequent samples on the now-confirmed route must not re-fire: %+v", len(changes), changes)
	}
}

// 17. Restart reconstruction: seed() replays the confirmed/candidate state
// machine (advance) across history — a route that was genuinely confirmed
// (two consecutive agreeing samples) before shutdown is restored as-is.
func TestRouteChangeSeedReconstructsFromHistory(t *testing.T) {
	history := []Sample{
		mkSample(mkHops("A", "B", "C")),
		mkSample(mkHops("A", "X", "C")),
		mkSample(mkHops("A", "X", "C")), // this is "current" as of before restart
		{Time: nextTime(), OK: false},   // a ping-mode-shaped sample with no hops must be skipped
	}
	rt := newRouteTracker()
	rt.seed(history)
	if rt.confirmed == nil {
		t.Fatal("seed should have found a route to reconstruct from")
	}
	if rt.confirmed[1].Addr != "X" {
		t.Errorf("seeded confirmed route = %+v, want the confirmed one (TTL2=X)", rt.confirmed)
	}
	// A sample matching the seeded route must not be treated as a change.
	if rc := rt.observe("t1", mkSample(mkHops("A", "X", "C")), nil); rc != nil {
		t.Errorf("expected no change against the correctly seeded baseline, got %+v", rc)
	}
}

// 18. IPv4 and IPv6 hop identity: comparison is purely string-based on
// Addr, so IPv6 addresses work identically to IPv4 without special-casing.
func TestRouteChangeIPv6HopIdentity(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1",
		mkHops("2001:db8::1", "2001:db8::2", "2001:db8::3"),
		mkHops("2001:db8::1", "2001:db8::99", "2001:db8::3"),
		mkHops("2001:db8::1", "2001:db8::99", "2001:db8::3"),
	)
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want 1 for an IPv6 persistent change: %+v", len(changes), changes)
	}
	if changes[0].After[1].Addr != "2001:db8::99" {
		t.Errorf("After = %+v, want the new IPv6 hop", changes[0].After)
	}
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------
// D.1-2: seed() restart baseline hardening
// ---------------------------------------------------------------------

// A single trailing divergent sample at the end of history must not
// masquerade as the restored baseline — it never got a chance to confirm
// live either, so seed() must not treat it as more authoritative in
// hindsight than it was at the time.
func TestRouteChangeSeedIgnoresTrailingTransient(t *testing.T) {
	history := []Sample{
		mkSample(mkHops("A", "B", "C")),
		mkSample(mkHops("A", "B", "C")),
		mkSample(mkHops("A", "X", "C")), // single trailing divergence, never confirmed
	}
	rt := newRouteTracker()
	rt.seed(history)
	if rt.confirmed == nil {
		t.Fatal("seed should have found a route to reconstruct from")
	}
	if rt.confirmed[1].Addr != "B" {
		t.Errorf("seeded confirmed route = %+v, want the still-stable TTL2=B, not the unconfirmed trailing X", rt.confirmed)
	}
}

// A route that genuinely confirmed (two consecutive agreeing samples) right
// before shutdown must be restored as the new baseline, not the one before.
func TestRouteChangeSeedAdoptsConfirmedNewRoute(t *testing.T) {
	history := []Sample{
		mkSample(mkHops("A", "B", "C")),
		mkSample(mkHops("A", "X", "C")),
		mkSample(mkHops("A", "X", "C")),
	}
	rt := newRouteTracker()
	rt.seed(history)
	if rt.confirmed == nil || rt.confirmed[1].Addr != "X" {
		t.Errorf("seeded confirmed route = %+v, want TTL2=X (confirmed twice before shutdown)", rt.confirmed)
	}
}

// A trailing timeout must not be adopted as if it were a new route — the
// last known-good, fully-observed route must survive it.
func TestRouteChangeSeedDoesNotAdoptTimeoutRoute(t *testing.T) {
	history := []Sample{
		mkSample(mkHops("A", "B", "C")),
		mkSample(mkHops("A", "", "C")), // timeout at TTL2 on the very last sample
	}
	rt := newRouteTracker()
	rt.seed(history)
	if rt.confirmed == nil || rt.confirmed[1].Addr != "B" {
		t.Errorf("seeded confirmed route = %+v, want TTL2=B — a trailing timeout must never become the baseline", rt.confirmed)
	}
}

// Insufficient (or absent) hop history leaves confirmed nil — live tracking
// then learns the baseline from scratch exactly as it would on first run.
func TestRouteChangeSeedInsufficientHistoryLearnsFresh(t *testing.T) {
	history := []Sample{
		{Time: nextTime(), OK: true, RTTms: 10}, // ping-mode sample, no Hops
		{Time: nextTime(), OK: false},
	}
	rt := newRouteTracker()
	rt.seed(history)
	if rt.confirmed != nil {
		t.Errorf("expected confirmed=nil with no hop-bearing history, got %+v", rt.confirmed)
	}
	// Live tracking must still work normally afterward.
	changes := feed(rt, "t1", mkHops("A", "B", "C"), mkHops("A", "B", "C"))
	if len(changes) != 0 {
		t.Errorf("fresh learning after empty seed produced unexpected changes: %+v", changes)
	}
	if rt.confirmed == nil {
		t.Error("expected confirmed to be learned from the first live hop-bearing sample")
	}
}

// seed() never emits or replays RouteChange events (it has no events output
// at all) — reconstructing through several genuine historical transitions
// must land on the correct FINAL state without needing anywhere to replay
// the intermediate changes into.
func TestRouteChangeSeedDoesNotReplayEvents(t *testing.T) {
	history := []Sample{
		mkSample(mkHops("A")),
		mkSample(mkHops("X")), mkSample(mkHops("X")), // confirms X
		mkSample(mkHops("Y")), mkSample(mkHops("Y")), // confirms Y (Y is genuinely new, not a known variant)
	}
	rt := newRouteTracker()
	rt.seed(history)
	if rt.confirmed == nil || rt.confirmed[0].Addr != "Y" {
		t.Errorf("seeded confirmed route = %+v, want the final confirmed TTL1=Y", rt.confirmed)
	}
}

// ---------------------------------------------------------------------
// D.1-3: ECMP hardening — bounded known-variant set per TTL
// ---------------------------------------------------------------------

// Simple two-way alternation: never repeats long enough to confirm either
// side, so no learning is even needed for this case (already covered by
// TestRouteChangeECMPAlternatingNoStorm above with 3-hop routes; this is
// the single-hop minimal version named after the D.1 spec's own notation).
func TestRouteChangeECMPSimpleAlternationNoEvent(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1", mkHops("A"), mkHops("B"), mkHops("A"), mkHops("B"))
	if len(changes) != 0 {
		t.Fatalf("got %d changes, want 0 for A/B/A/B alternation: %+v", len(changes), changes)
	}
}

// A/B/B/A/A: B confirms once (never seen before — a real event), then
// returning to A must be silently absorbed as a known variant, not fire a
// second event. No storm.
func TestRouteChangeECMPNoStormAfterLearning(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1", mkHops("A"), mkHops("B"), mkHops("B"), mkHops("A"), mkHops("A"))
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want exactly 1 (B's first confirmation) — A's return must be absorbed as a known variant: %+v", len(changes), changes)
	}
	if changes[0].After[0].Addr != "B" {
		t.Errorf("the one event should be the A->B confirmation, got After=%+v", changes[0].After)
	}
}

// A/B/A/B/Y/Y: A and B keep resetting each other and neither ever confirms,
// so neither is "known" — Y persisting twice must still confirm as a
// genuine, unrelated new path.
func TestRouteChangeECMPNewVariantStillConfirms(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1", mkHops("A"), mkHops("B"), mkHops("A"), mkHops("B"), mkHops("Y"), mkHops("Y"))
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want exactly 1 genuine event for Y: %+v", len(changes), changes)
	}
	if changes[0].After[0].Addr != "Y" {
		t.Errorf("After = %+v, want TTL1=Y", changes[0].After)
	}
}

// A/B/B/B: once B is already a known ECMP variant for a TTL, reconfirming
// it must not fire an event even though it's a "new" candidate streak.
func TestRouteChangeECMPKnownVariantNoEvent(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSample(mkHops("A")), nil) // confirmed=A, known={A}
	rt.variants[1] = append(rt.variants[1], knownVariant{Addr: "B", LastSeenSeq: rt.seq}) // prime B as a fresh known ECMP variant for TTL1
	changes := feed(rt, "t1", mkHops("B"), mkHops("B"), mkHops("B"))
	if len(changes) != 0 {
		t.Fatalf("got %d changes, want 0 — B was already a known ECMP variant: %+v", len(changes), changes)
	}
	if rt.confirmed == nil || rt.confirmed[0].Addr != "B" {
		t.Errorf("confirmed should have silently followed the known variant to B, got %+v", rt.confirmed)
	}
}

// Baseline case: A/A/A establishes/reinforces the baseline, then a
// genuinely unseen X confirms normally — the ECMP layer must never suppress
// a real first-time change.
func TestRouteChangeECMPBaselineThenRealChangeStillConfirms(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1", mkHops("A"), mkHops("A"), mkHops("A"), mkHops("X"), mkHops("X"))
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want exactly 1: %+v", len(changes), changes)
	}
	if changes[0].After[0].Addr != "X" {
		t.Errorf("After = %+v, want TTL1=X", changes[0].After)
	}
}

// A timeout mixed into an ECMP known-variant return must not cause a false
// event — the known-variant suppression and the timeout tolerance must
// compose correctly.
func TestRouteChangeECMPTimeoutMixedNoFalseEvent(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSample(mkHops("A")), nil) // confirmed=A, known={A}
	rt.observe("t1", mkSample(mkHops("B")), nil) // candidate=B streak=1
	firstConfirm := rt.observe("t1", mkSample(mkHops("B")), nil)
	if firstConfirm == nil {
		t.Fatal("expected B's first confirmation (not yet a known variant)")
	}
	// B is now confirmed and known={A,B}. Oscillate back toward A with a
	// timeout mixed into the confirmation.
	rc1 := rt.observe("t1", mkSample(mkHops("A")), nil)  // candidate=A streak=1
	rc2 := rt.observe("t1", mkSample(mkHops("")), nil)   // timeout: ambiguous, must not disturb the candidate
	rc3 := rt.observe("t1", mkSample(mkHops("A")), nil)  // streak=2, A is known -> suppressed
	if rc1 != nil || rc2 != nil || rc3 != nil {
		t.Fatalf("known-variant return through timeout noise must not fire: rc1=%v rc2=%v rc3=%v", rc1, rc2, rc3)
	}
}

// ---------------------------------------------------------------------
// D.1-4: RTT/Loss optional-value semantics — 0 is a real value, not absent
// ---------------------------------------------------------------------

func TestRouteChangeLossZeroToThreePreserved(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSampleMetrics(mkHops("A", "B", "C"), true, 20, 0), nil)
	rt.observe("t1", mkSampleMetrics(mkHops("A", "X", "C"), true, 40, 3), nil)
	rc := rt.observe("t1", mkSampleMetrics(mkHops("A", "X", "C"), true, 42, 3), nil)
	if rc == nil {
		t.Fatal("expected a confirmed change")
	}
	if rc.LossBefore == nil || *rc.LossBefore != 0 {
		t.Errorf("LossBefore = %v, want a pointer to 0 (a real zero-loss measurement, not absent)", rc.LossBefore)
	}
	if rc.LossAfter == nil || *rc.LossAfter != 3 {
		t.Errorf("LossAfter = %v, want a pointer to 3", rc.LossAfter)
	}
}

func TestRouteChangeLossThreeToZeroPreserved(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSampleMetrics(mkHops("A", "B", "C"), true, 20, 3), nil)
	rt.observe("t1", mkSampleMetrics(mkHops("A", "X", "C"), true, 40, 0), nil)
	rc := rt.observe("t1", mkSampleMetrics(mkHops("A", "X", "C"), true, 42, 0), nil)
	if rc == nil {
		t.Fatal("expected a confirmed change")
	}
	if rc.LossBefore == nil || *rc.LossBefore != 3 {
		t.Errorf("LossBefore = %v, want a pointer to 3", rc.LossBefore)
	}
	if rc.LossAfter == nil || *rc.LossAfter != 0 {
		t.Errorf("LossAfter = %v, want a pointer to 0 (a real zero-loss measurement, not absent)", rc.LossAfter)
	}
}

func TestRouteChangeMetricsNilWhenSampleFailed(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSampleMetrics(mkHops("A", "B", "C"), true, 20, 0), nil)
	rt.observe("t1", mkSampleMetrics(mkHops("A", "X", "C"), false, 0, 0), nil)
	rc := rt.observe("t1", mkSampleMetrics(mkHops("A", "X", "C"), false, 0, 0), nil)
	if rc == nil {
		t.Fatal("expected a confirmed change")
	}
	if rc.RTTAfter != nil || rc.LossAfter != nil {
		t.Errorf("expected nil RTT/Loss After for a failed sample, got RTTAfter=%v LossAfter=%v", rc.RTTAfter, rc.LossAfter)
	}
	if rc.RTTBefore == nil || rc.LossBefore == nil {
		t.Error("expected non-nil RTT/Loss Before — that sample succeeded")
	}
}

// ---------------------------------------------------------------------
// D.1-5: coincident degradation must reference real, nearby evidence
// ---------------------------------------------------------------------

func TestRouteChangeCoincidentOutsideWindowIsFalse(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSample(mkHops("A", "B", "C")), nil)
	rt.observe("t1", mkSample(mkHops("A", "X", "C")), nil)
	confirmSample := mkSample(mkHops("A", "X", "C"))
	events := []DegradationEvent{{Time: timeOffset(confirmSample.Time, -20 * time.Minute), Kind: "loss"}}
	rc := rt.observe("t1", confirmSample, events)
	if rc == nil {
		t.Fatal("expected a confirmed change")
	}
	if rc.CoincidentDegradation {
		t.Error("CoincidentDegradation should be false — the only event is far outside the window")
	}
}

// An old, still-unresolved degradation (the kind that would keep a naive
// "target currently degraded" flag stuck true indefinitely) must not make
// every later route change look coincident with it.
func TestRouteChangeOldStaleDegradationNoFalsePositive(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSample(mkHops("A", "B", "C")), nil)
	rt.observe("t1", mkSample(mkHops("A", "X", "C")), nil)
	confirmSample := mkSample(mkHops("A", "X", "C"))
	events := []DegradationEvent{{Time: timeOffset(confirmSample.Time, -3 * time.Hour), Kind: "loss"}}
	rc := rt.observe("t1", confirmSample, events)
	if rc == nil {
		t.Fatal("expected a confirmed change")
	}
	if rc.CoincidentDegradation {
		t.Error("a 3-hour-old degradation event must not read as coincident with a route change confirmed just now")
	}
}

// When multiple degradation events exist, Evidence must reference the
// nearest one, not an arbitrary or the farthest one.
func TestRouteChangeNearestDegradationEventSelected(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSample(mkHops("A", "B", "C")), nil)
	rt.observe("t1", mkSample(mkHops("A", "X", "C")), nil)
	confirmSample := mkSample(mkHops("A", "X", "C"))
	events := []DegradationEvent{
		{Time: timeOffset(confirmSample.Time, -4 * time.Minute), Kind: "latency"}, // far but still in window
		{Time: timeOffset(confirmSample.Time, -10 * time.Second), Kind: "loss"},   // nearest
	}
	rc := rt.observe("t1", confirmSample, events)
	if rc == nil {
		t.Fatal("expected a confirmed change")
	}
	if !rc.CoincidentDegradation {
		t.Fatal("expected CoincidentDegradation true")
	}
	found := false
	for _, ev := range rc.Evidence {
		if ev.Type != "route_change_timing" {
			continue
		}
		if strings.Contains(ev.Value, "loss") {
			found = true
		}
		if strings.Contains(ev.Value, "latency") {
			t.Errorf("Evidence referenced the farther latency event instead of the nearest loss one: %+v", ev)
		}
	}
	if !found {
		t.Errorf("expected route_change_timing evidence referencing the nearest (loss) event, got %+v", rc.Evidence)
	}
}

// ---------------------------------------------------------------------
// D.2: ECMP variant recency — known variants expire, they aren't permanent
// ---------------------------------------------------------------------

// 1. Quick A/B/B/A/A: B's first confirmation is a real event; the quick
// return to A must not storm.
func TestRouteChangeD2QuickOscillationNoStorm(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1", mkHops("A"), mkHops("B"), mkHops("B"), mkHops("A"), mkHops("A"))
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want exactly 1 (B's first confirmation): %+v", len(changes), changes)
	}
}

// 2. A/B/A/B/A/B alternating must never storm — neither side ever
// confirms long enough to matter.
func TestRouteChangeD2AlternatingNoStorm(t *testing.T) {
	rt := newRouteTracker()
	changes := feed(rt, "t1", mkHops("A"), mkHops("B"), mkHops("A"), mkHops("B"), mkHops("A"), mkHops("B"))
	if len(changes) != 0 {
		t.Fatalf("got %d changes, want 0 for pure alternation: %+v", len(changes), changes)
	}
}

// 3. A->B confirmed; B stays stable well past the recency window; A
// returns — this must now be a genuine, reportable B->A change.
func TestRouteChangeD2LateReversionIsGenuineEvent(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSample(mkHops("A")), nil)
	rt.observe("t1", mkSample(mkHops("B")), nil)
	firstConfirm := rt.observe("t1", mkSample(mkHops("B")), nil)
	if firstConfirm == nil {
		t.Fatal("expected B's first confirmation")
	}
	for i := 0; i < ecmpVariantWindowSamples+2; i++ {
		if rc := rt.observe("t1", mkSample(mkHops("B")), nil); rc != nil {
			t.Fatalf("unexpected event while B stays stable: %+v", rc)
		}
	}
	rt.observe("t1", mkSample(mkHops("A")), nil)
	rc := rt.observe("t1", mkSample(mkHops("A")), nil)
	if rc == nil {
		t.Fatal("expected a genuine B->A route change — A's only prior appearance is well outside the recency window")
	}
	if rc.After[0].Addr != "A" {
		t.Errorf("After = %+v, want TTL1=A", rc.After)
	}
}

// 4. A fresh known variant (seen recently) must still be suppressed.
func TestRouteChangeD2FreshVariantSuppressed(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSample(mkHops("A")), nil)
	rt.observe("t1", mkSample(mkHops("B")), nil)
	rc1 := rt.observe("t1", mkSample(mkHops("B")), nil)
	if rc1 == nil {
		t.Fatal("expected B's first confirmation")
	}
	rt.observe("t1", mkSample(mkHops("A")), nil)
	rc2 := rt.observe("t1", mkSample(mkHops("A")), nil)
	if rc2 != nil {
		t.Fatalf("expected A's quick return to be suppressed as a fresh known variant, got %+v", rc2)
	}
}

// 5. Symmetry: once a variant expires it becomes reportable again — and
// this keeps working back and forth, not just once.
func TestRouteChangeD2ExpiredVariantReportableAgain(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSample(mkHops("A")), nil)
	rt.observe("t1", mkSample(mkHops("B")), nil)
	rt.observe("t1", mkSample(mkHops("B")), nil) // B confirms
	for i := 0; i < ecmpVariantWindowSamples+2; i++ {
		rt.observe("t1", mkSample(mkHops("B")), nil)
	}
	rt.observe("t1", mkSample(mkHops("A")), nil)
	rcAReturn := rt.observe("t1", mkSample(mkHops("A")), nil)
	if rcAReturn == nil {
		t.Fatal("expected A's late return to confirm as a genuine event")
	}
	for i := 0; i < ecmpVariantWindowSamples+2; i++ {
		rt.observe("t1", mkSample(mkHops("A")), nil)
	}
	rt.observe("t1", mkSample(mkHops("B")), nil)
	rcBReturn := rt.observe("t1", mkSample(mkHops("B")), nil)
	if rcBReturn == nil {
		t.Fatal("expected B's now-stale return to confirm as reportable again")
	}
}

// 6. A genuinely new variant Y must confirm even while A/B are both still
// fresh known variants — freshness of unrelated addresses must never
// bleed into Y's own known-ness.
func TestRouteChangeD2NewVariantNotConfusedWithFreshOnes(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSample(mkHops("A")), nil)
	rt.observe("t1", mkSample(mkHops("B")), nil)
	rt.observe("t1", mkSample(mkHops("B")), nil) // B confirms; A,B both fresh
	rt.observe("t1", mkSample(mkHops("A")), nil)
	rt.observe("t1", mkSample(mkHops("A")), nil) // A returns, suppressed (fresh)
	rt.observe("t1", mkSample(mkHops("Y")), nil)
	rc := rt.observe("t1", mkSample(mkHops("Y")), nil)
	if rc == nil {
		t.Fatal("expected Y to confirm as a genuine new variant despite A/B being fresh known variants")
	}
	if rc.After[0].Addr != "Y" {
		t.Errorf("After = %+v, want TTL1=Y", rc.After)
	}
}

// 7. A structural hop_removed candidate must never be absorbed as ECMP
// even when every remaining address is individually known and fresh.
func TestRouteChangeD2StructuralHopRemovedNotAbsorbed(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSample(mkHops("A", "B", "C")), nil)
	rt.observe("t1", mkSample(mkHops("A", "B")), nil)
	rc := rt.observe("t1", mkSample(mkHops("A", "B")), nil)
	if rc == nil {
		t.Fatal("expected a genuine hop_removed event — A and B being individually known must not suppress a structural shape change")
	}
	if !containsStr(rc.ChangeTypes, "hop_removed") {
		t.Errorf("ChangeTypes = %v, want hop_removed", rc.ChangeTypes)
	}
}

// 8. A structural hop_added candidate must never be absorbed as ECMP.
func TestRouteChangeD2StructuralHopAddedNotAbsorbed(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSample(mkHops("A", "B")), nil)
	rt.observe("t1", mkSample(mkHops("A", "B", "C")), nil)
	rc := rt.observe("t1", mkSample(mkHops("A", "B", "C")), nil)
	if rc == nil {
		t.Fatal("expected a genuine hop_added event")
	}
	if !containsStr(rc.ChangeTypes, "hop_added") {
		t.Errorf("ChangeTypes = %v, want hop_added", rc.ChangeTypes)
	}
}

// 9. Restart: A's only appearance in history is well outside the recency
// window by the time history ends — its live return after restart must
// still confirm as a genuine event, not be silently absorbed.
func TestRouteChangeD2SeedOldVariantExpiresAcrossRestart(t *testing.T) {
	history := []Sample{mkSample(mkHops("A"))}
	for i := 0; i < 2; i++ {
		history = append(history, mkSample(mkHops("B")))
	}
	for i := 0; i < ecmpVariantWindowSamples+3; i++ {
		history = append(history, mkSample(mkHops("B")))
	}
	rt := newRouteTracker()
	rt.seed(history)
	if rt.confirmed == nil || rt.confirmed[0].Addr != "B" {
		t.Fatalf("seeded confirmed = %+v, want TTL1=B", rt.confirmed)
	}
	rt.observe("t1", mkSample(mkHops("A")), nil)
	rc := rt.observe("t1", mkSample(mkHops("A")), nil)
	if rc == nil {
		t.Fatal("expected A's post-restart return to confirm — its only prior appearance is well outside the recency window")
	}
}

// 10. Restart: recent ECMP oscillation right up to the end of history must
// still be recognized as fresh immediately after restart.
func TestRouteChangeD2SeedFreshVariantSuppressedAcrossRestart(t *testing.T) {
	history := []Sample{
		mkSample(mkHops("A")),
		mkSample(mkHops("B")), mkSample(mkHops("B")),
	}
	rt := newRouteTracker()
	rt.seed(history)
	if rt.confirmed == nil || rt.confirmed[0].Addr != "B" {
		t.Fatalf("seeded confirmed = %+v, want TTL1=B", rt.confirmed)
	}
	rt.observe("t1", mkSample(mkHops("A")), nil)
	rc := rt.observe("t1", mkSample(mkHops("A")), nil)
	if rc != nil {
		t.Fatalf("expected A's quick post-restart return to be suppressed as a still-fresh known variant, got %+v", rc)
	}
}

// 11. The ecmpMaxVariantsPerTTL count bound still applies regardless of
// recency — five distinct, all still-fresh confirmations must evict the
// oldest, not grow unbounded.
func TestRouteChangeD2BoundedVariantsStillEnforced(t *testing.T) {
	rt := newRouteTracker()
	addrs := []string{"A", "B", "C", "D", "E"}
	rt.observe("t1", mkSample(mkHops(addrs[0])), nil)
	for _, a := range addrs[1:] {
		rt.observe("t1", mkSample(mkHops(a)), nil)
		rt.observe("t1", mkSample(mkHops(a)), nil)
	}
	known := rt.variants[1]
	if len(known) > ecmpMaxVariantsPerTTL {
		t.Fatalf("known variants for TTL1 = %d, want at most %d (bounded)", len(known), ecmpMaxVariantsPerTTL)
	}
	for _, v := range known {
		if v.Addr == "A" {
			t.Errorf("expected the oldest variant A to have been evicted by the count bound, but it's still present: %+v", known)
		}
	}
}

// 12. A run of pure-timeout samples must never itself produce an event,
// and must still advance recency correctly — a known variant's only
// appearance can age out purely through the passage of samples, even ones
// that carried no information at all.
func TestRouteChangeD2TimeoutSamplesStillAdvanceRecency(t *testing.T) {
	rt := newRouteTracker()
	rt.observe("t1", mkSample(mkHops("A")), nil)
	rt.observe("t1", mkSample(mkHops("B")), nil)
	rt.observe("t1", mkSample(mkHops("B")), nil)
	for i := 0; i < ecmpVariantWindowSamples+2; i++ {
		if rc := rt.observe("t1", mkSample(mkHops("")), nil); rc != nil {
			t.Fatalf("a pure-timeout sample must never produce a route change: %+v", rc)
		}
	}
	rt.observe("t1", mkSample(mkHops("A")), nil)
	rc := rt.observe("t1", mkSample(mkHops("A")), nil)
	if rc == nil {
		t.Fatal("expected A to confirm as genuinely new — its old entry expired even through a run of timeout noise")
	}
}
