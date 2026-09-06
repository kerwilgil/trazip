package correlation

import (
	"encoding/json"
	"testing"
	"time"

	"trazip/internal/model"
)

// 1. Snapshot v1 round-trip: every field, including zero-valued ones the
// central model treats as meaningful (0 confidence, a zero Timestamp),
// must survive encode->decode unchanged.
func TestSnapshotJSONRoundTrip(t *testing.T) {
	original := Snapshot{
		SchemaVersion: SnapshotSchemaVersion,
		Kind:          SourceDiagnose,
		SourceID:      "src-1",
		Subject:       "example.com",
		OccurredAt:    "2026-01-01T12:00:00Z",
		Assessment: model.Assessment{
			Conclusion: "todo ok",
			Level:      model.LevelInfo,
			Confidence: 0, // a real, valid zero — must not vanish
			Evidence: []model.Evidence{
				{
					Type: "dns", Value: "1.1.1.1", Source: "resolution",
					Provenance: model.ProvObserved, Confidence: 90,
					Timestamp: time.Time{}, // zero Timestamp: the original engine had none
					Explain:   "resuelto vía sistema",
				},
			},
			CounterEvid: []model.Evidence{
				{Type: "counter", Value: "x", Source: "y", Provenance: model.ProvInferred, Confidence: 50},
			},
			Limitations: []string{"una sola muestra"},
		},
	}

	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded Snapshot
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", decoded.SchemaVersion)
	}
	if decoded.Kind != SourceDiagnose {
		t.Errorf("Kind = %q, want %q", decoded.Kind, SourceDiagnose)
	}
	if decoded.Assessment.Confidence != 0 {
		t.Errorf("Confidence = %d, want 0 (a real zero, not dropped)", decoded.Assessment.Confidence)
	}
	if len(decoded.Assessment.Evidence) != 1 {
		t.Fatalf("Evidence lost in round-trip: got %d entries, want 1", len(decoded.Assessment.Evidence))
	}
	ev := decoded.Assessment.Evidence[0]
	if ev.Type != "dns" || ev.Value != "1.1.1.1" || ev.Source != "resolution" || ev.Explain != "resuelto vía sistema" {
		t.Errorf("Evidence fields not preserved: %+v", ev)
	}
	if ev.Provenance != model.ProvObserved {
		t.Errorf("Provenance = %q, want %q", ev.Provenance, model.ProvObserved)
	}
	if !ev.Timestamp.IsZero() {
		t.Errorf("Timestamp = %v, want zero — must never be artificially replaced with time.Now()", ev.Timestamp)
	}
	if len(decoded.Assessment.CounterEvid) != 1 {
		t.Fatalf("CounterEvidence lost in round-trip: got %d entries, want 1", len(decoded.Assessment.CounterEvid))
	}
	if len(decoded.Assessment.Limitations) != 1 || decoded.Assessment.Limitations[0] != "una sola muestra" {
		t.Errorf("Limitations not preserved: %v", decoded.Assessment.Limitations)
	}
}

// 2. A Snapshot with no Evidence/CounterEvidence/Limitations must encode
// them as absent (omitempty), not as empty arrays — matching every other
// model.Assessment producer in TRAZIP.
func TestSnapshotJSONOmitsEmptyEvidence(t *testing.T) {
	s := Snapshot{
		SchemaVersion: SnapshotSchemaVersion,
		Kind:          SourceMonitor,
		Assessment:    model.Assessment{Conclusion: "sin novedad", Level: model.LevelInfo, Confidence: 80},
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	assessment, ok := generic["assessment"].(map[string]any)
	if !ok {
		t.Fatal("assessment field missing or wrong shape")
	}
	for _, key := range []string{"evidence", "counterEvidence", "limitations"} {
		if _, present := assessment[key]; present {
			t.Errorf("expected %q to be omitted when empty, but it's present: %v", key, assessment[key])
		}
	}
	for _, key := range []string{"sourceId", "subject", "occurredAt"} {
		if _, present := generic[key]; present {
			t.Errorf("expected %q to be omitted when empty, but it's present", key)
		}
	}
}

// 3. PcapIncidentSummary.ToSnapshot never fabricates Subject/SourceID/
// OccurredAt — an empty-metadata call must produce an empty-metadata
// Snapshot, not invented values.
func TestPcapToSnapshotNeverInventsMetadata(t *testing.T) {
	summary := PcapIncidentSummary{
		Summary: "1 hallazgo", Level: model.LevelHigh, Confidence: 85,
		Findings: []PcapFinding{{ID: "f1", Category: "loop", Summary: "bucle", Level: model.LevelHigh, Confidence: 85, SourceArea: SourceAreaNetDiag}},
	}
	snap := summary.ToSnapshot("", "", "")
	if snap.Subject != "" || snap.SourceID != "" || snap.OccurredAt != "" {
		t.Errorf("expected empty metadata to stay empty, got Subject=%q SourceID=%q OccurredAt=%q", snap.Subject, snap.SourceID, snap.OccurredAt)
	}
	if snap.Kind != SourcePCAP {
		t.Errorf("Kind = %q, want %q", snap.Kind, SourcePCAP)
	}
	if snap.SchemaVersion != SnapshotSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", snap.SchemaVersion, SnapshotSchemaVersion)
	}
	if snap.Assessment.Conclusion != summary.Summary {
		t.Errorf("Conclusion = %q, want %q", snap.Assessment.Conclusion, summary.Summary)
	}
	if snap.Assessment.CounterEvid != nil {
		t.Errorf("expected nil CounterEvidence for a PCAP snapshot, got %v", snap.Assessment.CounterEvid)
	}
}

// 4. When metadata IS provided explicitly, ToSnapshot must use it exactly.
func TestPcapToSnapshotUsesProvidedMetadata(t *testing.T) {
	summary := PcapIncidentSummary{Summary: "ok", Level: model.LevelInfo, Confidence: 75}
	snap := summary.ToSnapshot("captura-2026-01-01", "session-abc", "2026-01-01T10:00:00Z")
	if snap.Subject != "captura-2026-01-01" || snap.SourceID != "session-abc" || snap.OccurredAt != "2026-01-01T10:00:00Z" {
		t.Errorf("metadata not passed through: %+v", snap)
	}
}

// 5. Evidence/Limitations pass through the PCAP adapter unchanged.
func TestPcapToSnapshotPreservesEvidenceAndLimitations(t *testing.T) {
	summary := PcapIncidentSummary{
		Summary: "hallazgo", Level: model.LevelMedium, Confidence: 60,
		Evidence:    []model.Evidence{{Type: "t", Value: "v", Source: "s", Provenance: model.ProvObserved, Confidence: 60}},
		Limitations: []string{"limite 1", "limite 2"},
	}
	snap := summary.ToSnapshot("", "", "")
	if len(snap.Assessment.Evidence) != 1 {
		t.Fatalf("Evidence not preserved: %+v", snap.Assessment.Evidence)
	}
	if len(snap.Assessment.Limitations) != 2 {
		t.Fatalf("Limitations not preserved: %v", snap.Assessment.Limitations)
	}
}
