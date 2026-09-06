package monitor

import (
	"trazip/internal/correlation"
	"trazip/internal/model"
)

// ToSnapshot adapts a route_change DegradationEvent into the shared
// correlation.Snapshot contract (TRAZIP V1 MASTER IMPLEMENTATION, "PHASE
// E.0 — SNAPSHOT ADAPTER — MONITOR"). Returns ok=false for any other Kind,
// or when RouteChange is nil, rather than fabricating a route-change
// snapshot from an event that isn't one — loss/latency/recovery events
// aren't adapted yet (Phase E.0 priority is RouteChange only).
//
// Level is deliberately capped at Low even when CoincidentDegradation is
// true: a route change is a structural fact, and the coincidence with a
// degradation is exactly that — a coincidence, never asserted as the
// cause (RouteChange.Limitations already carries the explicit hedge). It
// never reaches Medium/High on the strength of a temporal correlation
// alone.
func ToSnapshot(e DegradationEvent) (correlation.Snapshot, bool) {
	if e.Kind != "route_change" || e.RouteChange == nil {
		return correlation.Snapshot{}, false
	}
	rc := e.RouteChange

	level := model.LevelInfo
	if rc.CoincidentDegradation {
		level = model.LevelLow
	}

	return correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          correlation.SourceMonitor,
		SourceID:      rc.ID,
		Subject:       rc.TargetID,
		OccurredAt:    rc.DetectedAt,
		Assessment: model.Assessment{
			Conclusion:  e.Detail,
			Level:       level,
			Confidence:  rc.Confidence,
			Evidence:    rc.Evidence,
			Limitations: rc.Limitations,
		},
	}, true
}
