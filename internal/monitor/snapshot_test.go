package monitor

import (
	"testing"

	"trazip/internal/correlation"
	"trazip/internal/model"
)

func TestRouteChangeToSnapshotMapping(t *testing.T) {
	rc := &RouteChange{
		ID: "rc-1", TargetID: "t-1", DetectedAt: "2026-01-01T12:00:00Z",
		FirstChangedTTL: 3, Confidence: 75,
		Evidence:    []model.Evidence{{Type: "route_change", Value: "salto 3", Source: "monitor", Provenance: model.ProvObserved, Confidence: 75}},
		Limitations: []string{"una sola sesión de monitoreo"},
	}
	event := DegradationEvent{Time: rc.DetectedAt, Kind: "route_change", Detail: "Ruta cambió desde el salto 3", RouteChange: rc}

	snap, ok := ToSnapshot(event)
	if !ok {
		t.Fatal("expected ok=true for a route_change event with a RouteChange")
	}
	if snap.SchemaVersion != correlation.SnapshotSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", snap.SchemaVersion, correlation.SnapshotSchemaVersion)
	}
	if snap.Kind != correlation.SourceMonitor {
		t.Errorf("Kind = %q, want %q", snap.Kind, correlation.SourceMonitor)
	}
	if snap.SourceID != "rc-1" {
		t.Errorf("SourceID = %q, want rc.ID", snap.SourceID)
	}
	if snap.Subject != "t-1" {
		t.Errorf("Subject = %q, want rc.TargetID", snap.Subject)
	}
	if snap.OccurredAt != rc.DetectedAt {
		t.Errorf("OccurredAt = %q, want rc.DetectedAt", snap.OccurredAt)
	}
	if snap.Assessment.Conclusion != event.Detail {
		t.Errorf("Conclusion = %q, want event.Detail %q", snap.Assessment.Conclusion, event.Detail)
	}
	if snap.Assessment.Confidence != 75 {
		t.Errorf("Confidence = %d, want 75 (rc.Confidence unchanged)", snap.Assessment.Confidence)
	}
	if len(snap.Assessment.Evidence) != 1 {
		t.Errorf("Evidence not mapped: %+v", snap.Assessment.Evidence)
	}
	if len(snap.Assessment.Limitations) != 1 {
		t.Errorf("Limitations not mapped: %v", snap.Assessment.Limitations)
	}
}

func TestRouteChangeToSnapshotLevelInfoWithoutCoincidentDegradation(t *testing.T) {
	rc := &RouteChange{ID: "rc-1", TargetID: "t-1", DetectedAt: "2026-01-01T12:00:00Z", CoincidentDegradation: false}
	event := DegradationEvent{Kind: "route_change", RouteChange: rc}
	snap, ok := ToSnapshot(event)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if snap.Assessment.Level != model.LevelInfo {
		t.Errorf("Level = %q, want informativo without a coincident degradation", snap.Assessment.Level)
	}
}

func TestRouteChangeToSnapshotLevelLowWithCoincidentDegradation(t *testing.T) {
	rc := &RouteChange{ID: "rc-1", TargetID: "t-1", DetectedAt: "2026-01-01T12:00:00Z", CoincidentDegradation: true}
	event := DegradationEvent{Kind: "route_change", RouteChange: rc}
	snap, ok := ToSnapshot(event)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if snap.Assessment.Level != model.LevelLow {
		t.Errorf("Level = %q, want bajo with a coincident degradation", snap.Assessment.Level)
	}
	if snap.Assessment.Level == model.LevelMedium || snap.Assessment.Level == model.LevelHigh || snap.Assessment.Level == model.LevelCritical {
		t.Errorf("Level = %q, a temporal coincidence must never reach Medium/High/Critical on its own", snap.Assessment.Level)
	}
}

func TestRouteChangeToSnapshotRejectsNonRouteChangeEvents(t *testing.T) {
	for _, kind := range []string{"loss", "latency", "recovery"} {
		event := DegradationEvent{Kind: kind}
		if _, ok := ToSnapshot(event); ok {
			t.Errorf("expected ok=false for Kind=%q", kind)
		}
	}
}

func TestRouteChangeToSnapshotRejectsNilRouteChange(t *testing.T) {
	event := DegradationEvent{Kind: "route_change", RouteChange: nil}
	if _, ok := ToSnapshot(event); ok {
		t.Error("expected ok=false when RouteChange is nil even if Kind says route_change")
	}
}
