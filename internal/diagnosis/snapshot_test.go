package diagnosis

import (
	"testing"

	"trazip/internal/correlation"
	"trazip/internal/model"
)

func TestDiagnosisToSnapshotExactMapping(t *testing.T) {
	report := DiagnosticReport{
		Target: "example.com", Kind: "host", Mode: ModeStandard,
		Summary: "resuelve y responde", Level: model.LevelInfo, Confidence: 85,
		Evidence:    []model.Evidence{{Type: "dns", Value: "1.2.3.4", Source: "resolution", Provenance: model.ProvObserved, Confidence: 90}},
		CounterEvid: []model.Evidence{{Type: "x", Value: "y", Source: "z", Provenance: model.ProvInferred, Confidence: 40}},
		Limitations: []string{"una sola muestra ping"},
		StartedAt:   "2026-01-01T10:00:00Z",
		CompletedAt: "2026-01-01T10:00:05Z",
	}

	snap := ToSnapshot(report)

	if snap.SchemaVersion != correlation.SnapshotSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", snap.SchemaVersion, correlation.SnapshotSchemaVersion)
	}
	if snap.Kind != correlation.SourceDiagnose {
		t.Errorf("Kind = %q, want %q", snap.Kind, correlation.SourceDiagnose)
	}
	if snap.Subject != report.Target {
		t.Errorf("Subject = %q, want report.Target %q", snap.Subject, report.Target)
	}
	if snap.OccurredAt != report.CompletedAt {
		t.Errorf("OccurredAt = %q, want report.CompletedAt %q", snap.OccurredAt, report.CompletedAt)
	}
	if snap.Assessment.Conclusion != report.Summary {
		t.Errorf("Conclusion = %q, want report.Summary %q", snap.Assessment.Conclusion, report.Summary)
	}
	if snap.Assessment.Level != report.Level {
		t.Errorf("Level = %q, want %q", snap.Assessment.Level, report.Level)
	}
	if snap.Assessment.Confidence != report.Confidence {
		t.Errorf("Confidence = %d, want %d", snap.Assessment.Confidence, report.Confidence)
	}
	if len(snap.Assessment.Evidence) != 1 || snap.Assessment.Evidence[0].Value != "1.2.3.4" {
		t.Errorf("Evidence not mapped exactly: %+v", snap.Assessment.Evidence)
	}
	if len(snap.Assessment.CounterEvid) != 1 || snap.Assessment.CounterEvid[0].Value != "y" {
		t.Errorf("CounterEvidence not mapped exactly: %+v", snap.Assessment.CounterEvid)
	}
	if len(snap.Assessment.Limitations) != 1 || snap.Assessment.Limitations[0] != "una sola muestra ping" {
		t.Errorf("Limitations not mapped exactly: %v", snap.Assessment.Limitations)
	}
}

func TestDiagnosisToSnapshotUsesCompletedAtNotStartedAt(t *testing.T) {
	report := DiagnosticReport{
		Target: "x", StartedAt: "2026-01-01T10:00:00Z", CompletedAt: "2026-01-01T10:00:05Z",
	}
	snap := ToSnapshot(report)
	if snap.OccurredAt != "2026-01-01T10:00:05Z" {
		t.Errorf("OccurredAt = %q, want CompletedAt, not StartedAt", snap.OccurredAt)
	}
}
