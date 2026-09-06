package monitor

import "time"

// RouteChangeSelfTestResult is F.0's read-only report of exercising the
// real route-change detector (routeTracker/observe) against fixed,
// synthetic MTR samples (TRAZIP V1 MASTER IMPLEMENTATION, "PHASE F.0 —
// DETERMINISTIC LOCAL SELF TEST CORE").
type RouteChangeSelfTestResult struct {
	// TransientConfirmed is true if a single divergent sample followed by a
	// revert (A→B→C, A→X→C, A→B→C) incorrectly confirmed a route change on
	// a fresh tracker — should always be false.
	TransientConfirmed bool
	// PersistentChangeCount is how many RouteChanges a second, independent
	// fresh tracker confirmed when fed two consecutive divergent samples
	// (A→B→C, A→X→C, A→X→C) — should be exactly 1.
	PersistentChangeCount int
	// PersistentChange is the single RouteChange the persistent fixture
	// confirmed, nil if PersistentChangeCount != 1.
	PersistentChange *RouteChange
}

// RunDeterministicRouteChangeSelfTest drives newRouteTracker/observe — the
// same, otherwise package-internal, detector routechange_test.go already
// exercises exhaustively — with two small, fixed-timestamp, in-memory
// fixtures. It exists solely so internal/api's F.0 self test can assert the
// real detector's hysteresis behavior without either exporting routeTracker
// wholesale or re-implementing its algorithm outside this package.
func RunDeterministicRouteChangeSelfTest() RouteChangeSelfTestResult {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seq := 0
	nextSample := func(hops []Hop) Sample {
		seq++
		return Sample{
			Time:     base.Add(time.Duration(seq) * 5 * time.Second).Format(time.RFC3339),
			OK:       len(hops) > 0,
			RTTms:    20,
			LossPct:  0,
			HopCount: len(hops),
			Hops:     hops,
		}
	}
	hops := func(addrs ...string) []Hop {
		out := make([]Hop, len(addrs))
		for i, a := range addrs {
			out[i] = Hop{TTL: i + 1, Addr: a}
		}
		return out
	}

	var res RouteChangeSelfTestResult

	transient := newRouteTracker()
	for _, h := range [][]Hop{hops("A", "B", "C"), hops("A", "X", "C"), hops("A", "B", "C")} {
		if rc := transient.observe("selftest-route-transient", nextSample(h), nil); rc != nil {
			res.TransientConfirmed = true
		}
	}

	persistent := newRouteTracker()
	for _, h := range [][]Hop{hops("A", "B", "C"), hops("A", "X", "C"), hops("A", "X", "C")} {
		if rc := persistent.observe("selftest-route-persistent", nextSample(h), nil); rc != nil {
			res.PersistentChangeCount++
			res.PersistentChange = rc
		}
	}

	return res
}
