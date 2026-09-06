package monitor

import (
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"trazip/internal/model"
)

// routeChangeConfirmSamples is how many CONSECUTIVE MTR samples must agree
// on a divergent route before TRAZIP calls it a confirmed change, rather
// than a transient blip or ECMP alternation (prompt maestro TRAZIP V1 Phase
// D "PERSISTENCE / HYSTERESIS").
//
// 2 is the minimum consistent with the master plan's own worked examples:
// a single divergent sample followed by a revert (A-B-C, A-X-C, A-B-C) must
// NOT confirm, while two consecutive divergent samples (A-B-C, A-X-C,
// A-X-C) must confirm exactly once. A higher N would miss that second case.
const routeChangeConfirmSamples = 2

// routeChangeDegradationWindow bounds how close in time a degradation event
// and a route change confirmation must be for CoincidentDegradation — wide
// enough to cover the confirmation delay routeChangeConfirmSamples itself
// adds (the underlying path change happened routeChangeConfirmSamples
// ticks before it's actually confirmed) without being so wide it correlates
// genuinely unrelated incidents.
const routeChangeDegradationWindow = 5 * time.Minute

// ecmpMaxVariantsPerTTL bounds how many distinct addresses routeTracker will
// remember as "known" ECMP variants for a single TTL — enough to cover a
// small multi-path fan-out without letting the set grow unbounded (master
// plan: "Evitar aprendizaje infinito"). Chosen small and fixed rather than
// time-windowed: a TTL that genuinely has more than a handful of live
// next-hops is unusual enough that treating the (ecmpMaxVariantsPerTTL+1)th
// distinct address as a real change, not more ECMP, is the safer default.
const ecmpMaxVariantsPerTTL = 4

// ecmpVariantWindowSamples bounds how many hop-bearing samples ago a
// per-TTL address must have last actually been observed to still count as
// a "recent" ECMP variant. Recency, not permanence: a route this TTL held
// as the confirmed baseline long enough ago to fall outside this window is
// treated as fully unknown again, so its return is a genuine, reportable
// route change — not silently re-absorbed as ECMP just because the same
// address happened to appear once, much earlier, within the same retained
// history. 8 is a small, deliberately conservative default: long enough to
// cover a real multi-path fan-out oscillating within a handful of ticks,
// short enough that a route stable for a while genuinely looks new again
// if it later reverts.
const ecmpVariantWindowSamples = 8

// RouteHop is one TTL's observed address at a point in time. TTL+Addr is
// the ONLY identity ever used for comparison (master plan: "NO usar
// hostname/PTR como identidad. PTR puede cambiar sin que cambie ruta.") —
// Host is carried along for display only. Addr == "" means this TTL was
// probed but got no reply this round (a timeout); a TTL simply absent from
// a RouteChange's Before/After means the route ended before reaching it.
type RouteHop struct {
	TTL  int    `json:"ttl"`
	Addr string `json:"addr,omitempty"`
	Host string `json:"host,omitempty"`
}

// RouteChange is one confirmed, persistent change in the path to a target —
// never a single-sample blip, an ECMP alternation, or a transient timeout
// (see routeTracker.observe). Built entirely from the MTR samples this
// monitor already collects — no new probe.
type RouteChange struct {
	ID       string `json:"id"`
	TargetID string `json:"targetId"`
	// DetectedAt is RFC3339, matching Sample.Time/DegradationEvent.Time's
	// own string convention throughout this package — not time.Time, so
	// this stays consistent with everything else stored in History.
	DetectedAt string `json:"detectedAt"`

	// FirstChangedTTL is the lowest TTL where Before/After materially
	// diverge.
	FirstChangedTTL int `json:"firstChangedTtl"`

	Before []RouteHop `json:"before"`
	After  []RouteHop `json:"after"`

	BeforeHopCount int `json:"beforeHopCount"`
	AfterHopCount  int `json:"afterHopCount"`

	// ChangeTypes: "hop_changed" | "hop_added" | "hop_removed" |
	// "hop_count_changed" — a single RouteChange can carry more than one.
	ChangeTypes []string `json:"changeTypes"`

	// Persistent is always true in the current design: a RouteChange value
	// is only ever constructed once routeChangeConfirmSamples consecutive
	// samples have confirmed it — there is no "candidate" or "unconfirmed"
	// RouteChange this field could ever read false on. Kept as an explicit
	// field anyway (rather than implied) so a reader of just the JSON,
	// without the detector's own code, still sees the guarantee stated.
	Persistent bool             `json:"persistent"`
	Confidence model.Confidence `json:"confidence"`

	// CoincidentDegradation is true only when a loss/latency
	// DegradationEvent exists within routeChangeDegradationWindow of
	// DetectedAt — never more than a temporal correlation (master plan:
	// never "causó"/"provocó"/"responsable de"; always "coincide con").
	// Deliberately NOT derived from "target currently degraded": that flag
	// stays true for as long as a degradation goes unrecovered, so a route
	// change confirmed hours into an old, ongoing degradation would
	// otherwise read as coincident with it forever.
	CoincidentDegradation bool `json:"coincidentDegradation"`

	// RTTBefore/RTTAfter/LossBefore/LossAfter come from the last sample
	// that matched the old confirmed route and the sample that confirmed
	// the new one — real, observed numbers, never estimated when absent.
	// Pointers, deliberately: 0% loss is a real, common measurement, and a
	// plain float64 with `omitempty` would silently drop it from the JSON
	// indistinguishably from "not measured", which the frontend would then
	// read as absent rather than as a genuine zero.
	RTTBefore  *float64 `json:"rttBefore,omitempty"`
	RTTAfter   *float64 `json:"rttAfter,omitempty"`
	LossBefore *float64 `json:"lossBefore,omitempty"`
	LossAfter  *float64 `json:"lossAfter,omitempty"`

	Evidence    []model.Evidence `json:"evidence,omitempty"`
	Limitations []string         `json:"limitations,omitempty"`
}

// routeTracker holds one target's route-change detection state across
// ticks — the MTR-mode sibling of the *baseline the same run() loop already
// keeps for degradation. Zero value is ready to use.
type routeTracker struct {
	confirmed       []RouteHop
	confirmedSample Sample // the most recent sample that matched `confirmed`, for Before RTT/Loss

	candidate       []RouteHop
	candidateStreak int

	// seq counts hop-bearing samples this tracker has processed (advance
	// calls only — ping-mode samples never reach it). Deliberately a
	// sample count, not wall-clock time: ecmpVariantWindowSamples then
	// scales naturally with whatever interval the target is actually
	// polled at, which is what "N samples" is meant to mean.
	seq uint64

	// variants remembers, per TTL, the small set of addresses that have
	// recently been part of a confirmed route at that TTL — the ECMP
	// false-positive control (master plan: "permitir un pequeño conjunto
	// conocido de hops por TTL"). Bounded by ecmpMaxVariantsPerTTL (oldest
	// evicted first) AND by ecmpVariantWindowSamples recency, checked in
	// isKnownVariant — an entry can sit in this slice well past the point
	// it no longer counts as "known".
	variants map[int][]knownVariant
}

// knownVariant is one address routeTracker has confirmed at some TTL, and
// the sample sequence number it was last actually observed at.
type knownVariant struct {
	Addr        string
	LastSeenSeq uint64
}

func newRouteTracker() *routeTracker { return &routeTracker{variants: map[int][]knownVariant{}} }

// seed primes the tracker from history on monitor restart by replaying only
// the confirmed/candidate STATE MACHINE (advance) across the retained MTR
// samples — never emitting or re-appending any RouteChange event (those
// already happened and already are, or aren't, in h.Events; this only
// answers "what is the route right now"). Using the same hysteresis as live
// detection means a single trailing divergent sample can't masquerade as
// the restored baseline (master plan "RESTART": a route seen once at the
// very end of history is not yet a confirmed route, live or reconstructed).
// Any candidate still in progress when history ends is discarded rather
// than carried into live tracking — restart begins live confirmation
// fresh. Because advance() is the same function driving both seed and live
// detection, ECMP variant recency (rt.seq/LastSeenSeq, D.2) reconstructs
// deterministically too: a variant only stays "known" across a restart if
// it would still be within ecmpVariantWindowSamples of the end of history,
// exactly as if the process had never stopped.
func (rt *routeTracker) seed(samples []Sample) {
	for _, s := range samples {
		if len(s.Hops) == 0 {
			continue
		}
		rt.advance(toRouteHops(s.Hops), s)
	}
	rt.candidate = nil
	rt.candidateStreak = 0
}

// advance runs one sample's hops through the confirmed/candidate hysteresis
// state machine shared by observe() (live detection) and seed() (restart
// reconstruction) — the single source of truth for "is this still the same
// route". Returns true the instant rt.confirmed is promoted from
// rt.candidate (a real, structural change); seed() ignores that signal and
// only cares about the resulting rt.confirmed. confirmedSample is only ever
// updated here, and only in the branches where rt.confirmed still (or now)
// truthfully describes s — never on a sample that was merely ambiguous or
// mid-candidate, so it keeps meaning "the last sample that matched
// confirmed" for Before RTT/Loss.
func (rt *routeTracker) advance(hops []RouteHop, s Sample) bool {
	rt.seq++

	if rt.confirmed == nil {
		rt.confirmed = hops
		rt.confirmedSample = s
		rt.learnVariants(hops)
		return false
	}

	if matchesFully(rt.confirmed, hops) {
		// Positive, unambiguous match to the confirmed route — genuinely
		// stable. This is the ONLY condition that resets an in-progress
		// candidate: merely "not contradicting" confirmed (a timeout
		// masking a real divergence) must never do so, or a single
		// transient timeout mid-change could erase real progress toward
		// confirming a persistent one. Also the mechanism that keeps the
		// ACTIVE route's own recency fresh — and, just as importantly,
		// the mechanism that does NOT refresh any other previously-known
		// variant, so one that stops appearing eventually ages out (D.2
		// "ECMP RECENCY").
		rt.confirmedSample = s
		rt.candidate = nil
		rt.candidateStreak = 0
		rt.learnVariants(hops)
		return false
	}

	if !contradicts(rt.confirmed, hops) && rt.candidate == nil {
		// Inconclusive relative to confirmed (some TTL just didn't reply
		// this round) and nothing was already in progress — not enough to
		// start a candidate from pure ambiguity.
		return false
	}

	switch {
	case rt.candidate == nil || contradicts(rt.candidate, hops):
		// First divergent sample, or one that disagrees with the
		// in-progress candidate too (a second, different divergence
		// supersedes the first — neither one had confirmed yet).
		rt.candidate = hops
		rt.candidateStreak = 1
	case matchesFully(rt.candidate, hops):
		// Positively reinforces the candidate.
		rt.candidate = mergeRouteHops(rt.candidate, hops)
		rt.candidateStreak++
	default:
		// Doesn't contradict the candidate but doesn't fully confirm it
		// either — a timeout at the diverging TTL this round. Fill in any
		// new information, but this round doesn't count as positive
		// evidence (master plan: "Un timeout transitorio en un TTL: NO
		// desplaza artificialmente otros hops").
		rt.candidate = mergeRouteHops(rt.candidate, hops)
	}

	if rt.candidateStreak < routeChangeConfirmSamples {
		return false
	}

	confirmedCandidate := rt.candidate
	rt.candidate = nil
	rt.candidateStreak = 0

	if sameShape(rt.confirmed, confirmedCandidate) && rt.isKnownVariant(confirmedCandidate) {
		// Same set of TTLs as the currently confirmed route (a real
		// hop_added/hop_removed/hop_count_changed candidate never passes
		// this), and every address at those TTLs is one we've already seen
		// confirmed before — an ECMP oscillation returning to (or among)
		// known paths, not a new route. Silently adopt it as the current
		// confirmed route so RTT/Loss "before" values and future
		// comparisons stay accurate, but this is not itself reportable.
		// The shape check matters: without it, a route that simply lost
		// its last hop could read as "known" purely because every TTL it
		// still has happens to match already-learned addresses.
		rt.confirmed = confirmedCandidate
		rt.confirmedSample = s
		rt.learnVariants(confirmedCandidate)
		return false
	}

	rt.confirmed = confirmedCandidate
	rt.confirmedSample = s
	rt.learnVariants(confirmedCandidate)
	return true
}

// learnVariants records hops' addresses as known-good variants for their
// TTLs at the current sequence number — either adding a newly-seen address
// (evicting the oldest-learned one per TTL once ecmpMaxVariantsPerTTL is
// exceeded) or refreshing an already-known one's recency.
func (rt *routeTracker) learnVariants(hops []RouteHop) {
	for _, h := range hops {
		if h.Addr == "" {
			continue
		}
		known := rt.variants[h.TTL]
		found := false
		for i := range known {
			if known[i].Addr == h.Addr {
				known[i].LastSeenSeq = rt.seq
				found = true
				break
			}
		}
		if !found {
			known = append(known, knownVariant{Addr: h.Addr, LastSeenSeq: rt.seq})
			if len(known) > ecmpMaxVariantsPerTTL {
				known = known[len(known)-ecmpMaxVariantsPerTTL:]
			}
		}
		rt.variants[h.TTL] = known
	}
}

// isKnownVariant reports whether every non-empty-address TTL in hops is a
// RECENTLY recognized variant for that TTL — seen within the last
// ecmpVariantWindowSamples hop-bearing samples, not merely at some point in
// the tracker's lifetime — i.e. this candidate route introduces nothing
// structurally new anywhere, only a recombination of recently-confirmed
// per-hop addresses. A TTL never seen before (a real
// hop_added/hop_removed-shaped change, or the very first time any address
// appears at that position), or one whose only match has aged out, always
// fails this check, so structural changes and genuine late reversions are
// never absorbed as "just ECMP".
func (rt *routeTracker) isKnownVariant(hops []RouteHop) bool {
	for _, h := range hops {
		if h.Addr == "" {
			continue
		}
		known, ok := rt.variants[h.TTL]
		if !ok {
			return false
		}
		found := false
		for _, v := range known {
			if v.Addr == h.Addr && rt.seq-v.LastSeenSeq <= ecmpVariantWindowSamples {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// sameShape reports whether a and b cover exactly the same set of TTLs
// (regardless of address) — true for a pure ECMP-shaped candidate (only
// addresses at some TTLs differ), false for anything that adds, removes, or
// changes the length of the route.
func sameShape(a, b []RouteHop) bool {
	am, bm := toRouteMap(a), toRouteMap(b)
	if len(am) != len(bm) {
		return false
	}
	for ttl := range am {
		if _, ok := bm[ttl]; !ok {
			return false
		}
	}
	return true
}

// observe feeds one MTR sample into the tracker. Returns a confirmed
// *RouteChange the moment routeChangeConfirmSamples consecutive samples
// agree on a route that diverges from the current confirmed one AND that
// route isn't just a return to a known ECMP variant — nil otherwise.
// Ping-mode samples (no Hops) are a no-op.
func (rt *routeTracker) observe(targetID string, s Sample, events []DegradationEvent) *RouteChange {
	if len(s.Hops) == 0 {
		return nil
	}
	hops := toRouteHops(s.Hops)
	before := rt.confirmed
	beforeSample := rt.confirmedSample

	if !rt.advance(hops, s) {
		return nil
	}
	return buildRouteChange(targetID, before, rt.confirmed, beforeSample, s, events)
}

func toRouteHops(hops []Hop) []RouteHop {
	out := make([]RouteHop, len(hops))
	for i, h := range hops {
		out[i] = RouteHop{TTL: h.TTL, Addr: h.Addr, Host: h.Host}
	}
	return out
}

func toRouteMap(hops []RouteHop) map[int]string {
	m := make(map[int]string, len(hops))
	for _, h := range hops {
		m[h.TTL] = h.Addr
	}
	return m
}

// contradicts reports whether b actively disagrees with a at any TTL: a TTL
// with a non-empty address in both that differs, or a TTL with a non-empty
// address in one side that is structurally absent from the other (the
// route ended before/after reaching it — a real, complete observation, not
// a data gap). A TTL present with an EMPTY address in either side (a single
// round's timeout at an intermediate hop) never contradicts anything —
// exactly the master plan's "timeout transitorio... NO desplaza
// artificialmente otros hops".
func contradicts(a, b []RouteHop) bool {
	am, bm := toRouteMap(a), toRouteMap(b)
	for ttl, addrA := range am {
		if addrA == "" {
			continue
		}
		addrB, ok := bm[ttl]
		if !ok {
			return true
		}
		if addrB == "" {
			continue
		}
		if addrB != addrA {
			return true
		}
	}
	for ttl, addrB := range bm {
		if addrB == "" {
			continue
		}
		if _, ok := am[ttl]; !ok {
			return true
		}
	}
	return false
}

// matchesFully reports whether b positively confirms every non-empty TTL in
// a, with no gaps, AND introduces no new non-empty TTL of its own — used to
// decide whether a sample counts as real evidence toward confirming a
// candidate route, as opposed to merely not contradicting it (a timeout).
// The symmetric check matters: without it, a genuinely longer route (a real
// hop_added) would read as "fully matching" a shorter one, since every TTL
// the shorter route actually has would still agree.
func matchesFully(a, b []RouteHop) bool {
	am, bm := toRouteMap(a), toRouteMap(b)
	for ttl, addrA := range am {
		if addrA == "" {
			continue
		}
		addrB, ok := bm[ttl]
		if !ok || addrB == "" || addrB != addrA {
			return false
		}
	}
	for ttl, addrB := range bm {
		if addrB == "" {
			continue
		}
		if _, ok := am[ttl]; !ok {
			return false
		}
	}
	return true
}

// mergeRouteHops folds b's newer information into a, preferring a non-empty
// address over an empty (timeout) one at the same TTL from either side —
// so a candidate route that had a gap in one sample can still be completed
// by a later sample that got a real reply at that TTL.
func mergeRouteHops(a, b []RouteHop) []RouteHop {
	am := toRouteMap(a)
	hostOf := make(map[int]string, len(a)+len(b))
	for _, h := range a {
		hostOf[h.TTL] = h.Host
	}
	for _, h := range b {
		if _, ok := am[h.TTL]; !ok || h.Addr != "" {
			am[h.TTL] = h.Addr
			if h.Host != "" {
				hostOf[h.TTL] = h.Host
			}
		} else if hostOf[h.TTL] == "" && h.Host != "" {
			hostOf[h.TTL] = h.Host
		}
	}
	ttls := make([]int, 0, len(am))
	for ttl := range am {
		ttls = append(ttls, ttl)
	}
	sort.Ints(ttls)
	out := make([]RouteHop, len(ttls))
	for i, ttl := range ttls {
		out[i] = RouteHop{TTL: ttl, Addr: am[ttl], Host: hostOf[ttl]}
	}
	return out
}

// buildRouteChange turns a confirmed (before, after) pair into a full
// RouteChange, including its structured ChangeTypes/FirstChangedTTL,
// RTT/Loss deltas from the actual samples that bracketed the change, the
// degradation coincidence check, and hedged Evidence/Limitations text.
func buildRouteChange(targetID string, before, after []RouteHop, beforeSample, afterSample Sample, events []DegradationEvent) *RouteChange {
	changeTypes, firstTTL := classifyRouteChange(before, after)
	if len(changeTypes) == 0 {
		// Shouldn't happen (observe only calls this once contradicts()
		// proved a real divergence), but never emit a structurally empty
		// "change" if it somehow does.
		return nil
	}

	afterTime, err := time.Parse(time.RFC3339, afterSample.Time)
	if err != nil {
		afterTime = time.Now()
	}
	nearestDeg, coincident := nearestDegradationEvent(events, afterTime)

	rc := &RouteChange{
		ID: uuid.NewString(), TargetID: targetID, DetectedAt: afterSample.Time,
		FirstChangedTTL: firstTTL,
		Before:          before, After: after,
		BeforeHopCount: len(before), AfterHopCount: len(after),
		ChangeTypes: changeTypes, Persistent: true,
		Confidence:            routeChangeConfidence(changeTypes, beforeSample, afterSample),
		CoincidentDegradation: coincident,
	}
	if beforeSample.OK {
		rc.RTTBefore = ptrFloat(beforeSample.RTTms)
		rc.LossBefore = ptrFloat(beforeSample.LossPct)
	}
	if afterSample.OK {
		rc.RTTAfter = ptrFloat(afterSample.RTTms)
		rc.LossAfter = ptrFloat(afterSample.LossPct)
	}

	rc.Evidence = append(rc.Evidence, model.Evidence{
		Type: "route_change", Value: fmt.Sprintf("salto %d", firstTTL), Source: "monitor",
		Provenance: model.ProvObserved, Confidence: rc.Confidence, Timestamp: afterTime,
		Explain: fmt.Sprintf("La ruta hacia el objetivo cambió desde el salto %d, confirmado en %d muestras consecutivas.", firstTTL, routeChangeConfirmSamples),
	})
	if coincident {
		// nearestDeg is the specific DegradationEvent this coincidence
		// rests on — named explicitly rather than just restating the route
		// change's own timestamp, so the evidence is self-sufficient about
		// WHAT it's coincident with, not just THAT it's coincident with
		// something.
		degTime, err := time.Parse(time.RFC3339, nearestDeg.Time)
		if err != nil {
			degTime = afterTime
		}
		rc.Evidence = append(rc.Evidence, model.Evidence{
			Type: "route_change_timing", Value: fmt.Sprintf("%s @ %s", nearestDeg.Kind, nearestDeg.Time), Source: "monitor",
			Provenance: model.ProvObserved, Confidence: rc.Confidence, Timestamp: degTime,
			Explain: fmt.Sprintf("El cambio de ruta coincide temporalmente con un evento de degradación (%s) a %s de distancia.", nearestDeg.Kind, afterTime.Sub(degTime).Abs().Round(time.Second)),
		})
		rc.Limitations = append(rc.Limitations, "La coincidencia temporal no demuestra causalidad.")
	}
	return rc
}

func ptrFloat(f float64) *float64 { return &f }

// classifyRouteChange compares before/after hop-by-hop (TTL identity only)
// and returns which structural change types apply and the lowest TTL where
// they materially diverge.
func classifyRouteChange(before, after []RouteHop) (changeTypes []string, firstChangedTTL int) {
	bm, am := toRouteMap(before), toRouteMap(after)
	types := map[string]bool{}
	first := -1
	note := func(ttl int, kind string) {
		types[kind] = true
		if first == -1 || ttl < first {
			first = ttl
		}
	}

	ttlSet := map[int]bool{}
	for ttl := range bm {
		ttlSet[ttl] = true
	}
	for ttl := range am {
		ttlSet[ttl] = true
	}
	ttls := make([]int, 0, len(ttlSet))
	for ttl := range ttlSet {
		ttls = append(ttls, ttl)
	}
	sort.Ints(ttls)

	for _, ttl := range ttls {
		bAddr, bOk := bm[ttl]
		aAddr, aOk := am[ttl]
		bPresent, aPresent := bOk && bAddr != "", aOk && aAddr != ""
		switch {
		case bPresent && aPresent && bAddr != aAddr:
			note(ttl, "hop_changed")
		case !bOk && aPresent:
			// The TTL didn't exist in the old route's length at all — a
			// genuinely new hop, not a timeout resolving.
			note(ttl, "hop_added")
		case bPresent && !aOk:
			// The TTL existed with a real reply before and is now entirely
			// gone from the route's length — genuinely removed, not a
			// single round's timeout (that would leave aOk true with an
			// empty address, which this case does not match).
			note(ttl, "hop_removed")
		default:
			// Covers a timeout resolving or reappearing at a TTL that
			// stayed structurally present on both sides — never itself a
			// change (master plan: a transient timeout must not displace
			// other hops or fabricate a change).
		}
	}
	if len(before) != len(after) {
		types["hop_count_changed"] = true
		if first == -1 {
			shorter := len(before)
			if len(after) < shorter {
				shorter = len(after)
			}
			first = shorter + 1
		}
	}

	out := make([]string, 0, len(types))
	for _, k := range []string{"hop_changed", "hop_added", "hop_removed", "hop_count_changed"} {
		if types[k] {
			out = append(out, k)
		}
	}
	return out, first
}

// routeChangeConfidence is deliberately simple and bounded — this is a
// structural detection with a fixed hysteresis, not a statistical model, so
// its confidence doesn't fluctuate on much beyond "did both confirming
// samples actually respond".
func routeChangeConfidence(changeTypes []string, before, after Sample) model.Confidence {
	conf := 75
	if !before.OK || !after.OK {
		conf -= 15
	}
	if conf < 10 {
		conf = 10
	}
	if conf > 95 {
		conf = 95
	}
	return model.Confidence(conf)
}

// nearestDegradationEvent returns the loss/latency DegradationEvent closest
// in time to `at`, if one exists within routeChangeDegradationWindow — the
// only evidence CoincidentDegradation is ever allowed to rest on. There is
// deliberately no separate "is the target currently degraded" shortcut: a
// degradation that started long before this window and never recovered
// would otherwise make every later route change look coincident with it
// forever, which is exactly the false positive this function exists to
// avoid.
func nearestDegradationEvent(events []DegradationEvent, at time.Time) (*DegradationEvent, bool) {
	var best *DegradationEvent
	var bestDiff time.Duration
	for i := range events {
		e := events[i]
		if e.Kind != "loss" && e.Kind != "latency" {
			continue
		}
		ts, err := time.Parse(time.RFC3339, e.Time)
		if err != nil {
			continue
		}
		diff := at.Sub(ts).Abs()
		if diff > routeChangeDegradationWindow {
			continue
		}
		if best == nil || diff < bestDiff {
			candidate := e
			best = &candidate
			bestDiff = diff
		}
	}
	if best == nil {
		return nil, false
	}
	return best, true
}
