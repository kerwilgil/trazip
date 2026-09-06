package voip

import (
	"testing"

	"trazip/internal/correlation"
	"trazip/internal/model"
)

func TestVoipToSnapshotReusesDiagnosisExactly(t *testing.T) {
	diag := &model.Assessment{
		Conclusion: "llamada establecida sin incidencias", Level: model.LevelInfo, Confidence: 90,
		Evidence: []model.Evidence{{Type: "sip", Value: "200 OK", Source: "sip", Provenance: model.ProvObserved, Confidence: 90}},
	}
	call := &Call{
		CallID: "call-1", From: "1000", To: "2000", Diagnosis: diag,
		Timeline: []TimelineEvent{{TimeStr: "2026-01-01T09:00:00Z", Summary: "INVITE"}},
	}

	snap, ok := ToSnapshot(call)
	if !ok {
		t.Fatal("expected ok=true for a call with a Diagnosis")
	}
	if snap.SchemaVersion != correlation.SnapshotSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", snap.SchemaVersion, correlation.SnapshotSchemaVersion)
	}
	if snap.Kind != correlation.SourceVoIP {
		t.Errorf("Kind = %q, want %q", snap.Kind, correlation.SourceVoIP)
	}
	if snap.SourceID != "call-1" {
		t.Errorf("SourceID = %q, want call.CallID", snap.SourceID)
	}
	if snap.Subject != "1000 → 2000" {
		t.Errorf("Subject = %q, want %q", snap.Subject, "1000 → 2000")
	}
	if snap.OccurredAt != "2026-01-01T09:00:00Z" {
		t.Errorf("OccurredAt = %q, want the first Timeline event's TimeStr", snap.OccurredAt)
	}
	if snap.Assessment.Conclusion != diag.Conclusion || snap.Assessment.Confidence != diag.Confidence {
		t.Errorf("Assessment not reused exactly: got %+v, want %+v", snap.Assessment, *diag)
	}
	if len(snap.Assessment.Evidence) != 1 {
		t.Errorf("Evidence not preserved: %+v", snap.Assessment.Evidence)
	}
}

func TestVoipToSnapshotRejectsNilDiagnosis(t *testing.T) {
	call := &Call{CallID: "call-1", From: "1000", To: "2000", Diagnosis: nil}
	snap, ok := ToSnapshot(call)
	if ok {
		t.Fatal("expected ok=false when Diagnosis is nil")
	}
	if snap.SourceID != "" || snap.Subject != "" || snap.Kind != "" {
		t.Errorf("expected a zero-value Snapshot when ok=false, got %+v", snap)
	}
}

func TestVoipToSnapshotRejectsNilCall(t *testing.T) {
	if _, ok := ToSnapshot(nil); ok {
		t.Error("expected ok=false for a nil Call")
	}
}

func TestVoipToSnapshotSubjectWithOnlyFrom(t *testing.T) {
	call := &Call{CallID: "c", From: "1000", To: "", Diagnosis: &model.Assessment{}}
	snap, ok := ToSnapshot(call)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if snap.Subject != "1000" {
		t.Errorf("Subject = %q, want just From when To is absent — never invent the missing side", snap.Subject)
	}
}

func TestVoipToSnapshotSubjectEmptyWhenNeitherPartyKnown(t *testing.T) {
	call := &Call{CallID: "c", Diagnosis: &model.Assessment{}}
	snap, ok := ToSnapshot(call)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if snap.Subject != "" {
		t.Errorf("Subject = %q, want empty when neither From nor To is known", snap.Subject)
	}
}

func TestVoipToSnapshotOccurredAtEmptyWithoutTimeline(t *testing.T) {
	call := &Call{CallID: "c", Diagnosis: &model.Assessment{}}
	snap, ok := ToSnapshot(call)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if snap.OccurredAt != "" {
		t.Errorf("OccurredAt = %q, want empty when Timeline is empty — never fabricate a timestamp", snap.OccurredAt)
	}
}
