package investigation

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"trazip/internal/correlation"
	"trazip/internal/model"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	return newManagerAt(t.TempDir())
}

func validSnapshot(kind correlation.SourceKind) correlation.Snapshot {
	return correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          kind,
		Subject:       "example.com",
		OccurredAt:    "2026-01-01T10:00:00Z",
		Assessment: model.Assessment{
			Conclusion: "hallazgo de prueba", Level: model.LevelHigh, Confidence: 80,
			Evidence: []model.Evidence{{
				Type: "t", Value: "v", Source: "s", Provenance: model.ProvObserved, Confidence: 80,
			}},
		},
	}
}

func mustCreate(t *testing.T, m *Manager, name string) Investigation {
	t.Helper()
	inv, err := m.Create(name, "objetivo de prueba")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return inv
}

// 1. Create.
func TestCreateInvestigation(t *testing.T) {
	m := newTestManager(t)
	inv, err := m.Create("Cliente ACME", "Validar llamadas caídas")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if inv.ID == "" {
		t.Error("expected a generated ID")
	}
	if inv.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", inv.SchemaVersion, SchemaVersion)
	}
	if inv.Name != "Cliente ACME" || inv.Objective != "Validar llamadas caídas" {
		t.Errorf("Name/Objective not stored: %+v", inv)
	}
	if inv.CreatedAt == "" || inv.UpdatedAt == "" {
		t.Error("expected CreatedAt/UpdatedAt to be set")
	}
	if inv.Entries == nil || len(inv.Entries) != 0 {
		t.Errorf("expected an empty (non-nil) Entries slice, got %+v", inv.Entries)
	}
}

// 2. Invalid empty name.
func TestCreateInvestigationEmptyNameRejected(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create("   ", "x"); !errors.Is(err, ErrNameRequired) {
		t.Errorf("err = %v, want ErrNameRequired", err)
	}
}

// 3. Name length limit.
func TestCreateInvestigationNameTooLongRejected(t *testing.T) {
	m := newTestManager(t)
	longName := strings.Repeat("a", maxNameLen+1)
	if _, err := m.Create(longName, ""); !errors.Is(err, ErrNameTooLong) {
		t.Errorf("err = %v, want ErrNameTooLong", err)
	}
	okName := strings.Repeat("a", maxNameLen)
	if _, err := m.Create(okName, ""); err != nil {
		t.Errorf("a name at exactly the limit should be accepted: %v", err)
	}
}

// 4. Objective length limit.
func TestCreateInvestigationObjectiveTooLongRejected(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Create("x", strings.Repeat("a", maxObjectiveLen+1)); !errors.Is(err, ErrObjectiveTooLong) {
		t.Errorf("err = %v, want ErrObjectiveTooLong", err)
	}
}

// 5. Persistence/reload.
func TestInvestigationSurvivesManagerRestart(t *testing.T) {
	dir := t.TempDir()
	m1 := newManagerAt(dir)
	inv := mustCreate(t, m1, "Caso 1")

	m2 := newManagerAt(dir) // simulates reopening TRAZIP
	got, err := m2.Get(inv.ID)
	if err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	if got.ID != inv.ID || got.Name != inv.Name {
		t.Errorf("investigation did not survive reload: %+v", got)
	}
}

// 6. Manager instances are fully isolated by their own dir — no shared
// global state, so portable vs installed mode never cross-contaminate.
func TestManagerInstancesAreIsolated(t *testing.T) {
	m1 := newManagerAt(t.TempDir())
	m2 := newManagerAt(t.TempDir())
	inv := mustCreate(t, m1, "solo en m1")
	if _, err := m2.Get(inv.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected m2 to know nothing about m1's investigation, got err=%v", err)
	}
}

// 7. List summary.
func TestListReturnsSummaries(t *testing.T) {
	m := newTestManager(t)
	mustCreate(t, m, "Caso A")
	mustCreate(t, m, "Caso B")
	res := m.List()
	if len(res.Investigations) != 2 {
		t.Fatalf("List = %+v, want 2 investigations", res.Investigations)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", res.Warnings)
	}
}

// 8. Get.
func TestGetReturnsFullInvestigation(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "Caso")
	m.AddSnapshot(inv.ID, validSnapshot(correlation.SourceDiagnose))
	got, err := m.Get(inv.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Entries) != 1 {
		t.Errorf("Get should return full Entries, got %d", len(got.Entries))
	}
}

// 9. Update metadata.
func TestUpdateMetadata(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "nombre viejo")
	time.Sleep(1100 * time.Millisecond) // RFC3339 second resolution — ensure UpdatedAt actually advances
	updated, err := m.UpdateMetadata(inv.ID, "nombre nuevo", "objetivo nuevo")
	if err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}
	if updated.Name != "nombre nuevo" || updated.Objective != "objetivo nuevo" {
		t.Errorf("metadata not updated: %+v", updated)
	}
	if updated.UpdatedAt == inv.UpdatedAt {
		t.Error("expected UpdatedAt to advance")
	}
	if updated.CreatedAt != inv.CreatedAt {
		t.Error("CreatedAt must never change")
	}
}

// 10. Delete.
func TestDeleteInvestigation(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "a borrar")
	if err := m.Delete(inv.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := m.Get(inv.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

// 11. Invalid UUID / traversal attempt.
func TestInvestigationIDsCannotEscapeStoreDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "investigations")
	m := newManagerAt(dir)
	sentinel := filepath.Join(root, "sentinel.json")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete("../sentinel"); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("expected ErrInvalidID for a traversal-shaped id, got %v", err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("sentinel outside the store was touched: %v", err)
	}
	if _, err := m.Get("not-a-uuid"); !errors.Is(err, ErrInvalidID) {
		t.Errorf("Get with a non-UUID id = %v, want ErrInvalidID", err)
	}
}

// 12-15. Add Snapshot for each SourceKind.
func TestAddSnapshotEachSourceKind(t *testing.T) {
	for _, kind := range []correlation.SourceKind{correlation.SourceDiagnose, correlation.SourcePCAP, correlation.SourceMonitor, correlation.SourceVoIP} {
		t.Run(string(kind), func(t *testing.T) {
			m := newTestManager(t)
			inv := mustCreate(t, m, "caso")
			entry, existing, err := m.AddSnapshot(inv.ID, validSnapshot(kind))
			if err != nil {
				t.Fatalf("AddSnapshot(%s): %v", kind, err)
			}
			if existing {
				t.Error("expected existing=false for a fresh snapshot")
			}
			if entry.Snapshot.Kind != kind {
				t.Errorf("stored Kind = %q, want %q", entry.Snapshot.Kind, kind)
			}
			got, _ := m.Get(inv.ID)
			if len(got.Entries) != 1 {
				t.Fatalf("expected 1 persisted entry, got %d", len(got.Entries))
			}
		})
	}
}

// 16. Exact duplicate suppression.
func TestAddSnapshotDuplicateSuppressed(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "caso")
	snap := validSnapshot(correlation.SourceDiagnose)

	e1, existing1, err := m.AddSnapshot(inv.ID, snap)
	if err != nil || existing1 {
		t.Fatalf("first add: entry=%+v existing=%v err=%v", e1, existing1, err)
	}
	e2, existing2, err := m.AddSnapshot(inv.ID, snap)
	if err != nil {
		t.Fatalf("second add: %v", err)
	}
	if !existing2 {
		t.Error("expected existing=true for an exact duplicate (double-click protection)")
	}
	if e2.ID != e1.ID {
		t.Errorf("expected the SAME entry back, got a different ID: %q vs %q", e2.ID, e1.ID)
	}

	got, _ := m.Get(inv.ID)
	if len(got.Entries) != 1 {
		t.Fatalf("expected exactly 1 entry after a duplicate add, got %d", len(got.Entries))
	}
}

// 17. Similar conclusion but different Evidence must NOT be treated as a
// duplicate.
func TestAddSnapshotSimilarConclusionDifferentEvidenceNotDuplicate(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "caso")

	snap1 := validSnapshot(correlation.SourceDiagnose)
	snap2 := validSnapshot(correlation.SourceDiagnose)
	snap2.Assessment.Evidence[0].Value = "un valor de evidencia distinto"

	m.AddSnapshot(inv.ID, snap1)
	_, existing, err := m.AddSnapshot(inv.ID, snap2)
	if err != nil {
		t.Fatalf("AddSnapshot: %v", err)
	}
	if existing {
		t.Error("two snapshots sharing a Conclusion but with different Evidence must not be treated as duplicates")
	}
	got, _ := m.Get(inv.ID)
	if len(got.Entries) != 2 {
		t.Fatalf("expected 2 distinct entries, got %d", len(got.Entries))
	}
}

// 18. Remove entry.
func TestRemoveEntry(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "caso")
	entry, _, _ := m.AddSnapshot(inv.ID, validSnapshot(correlation.SourceDiagnose))

	if err := m.RemoveEntry(inv.ID, entry.ID); err != nil {
		t.Fatalf("RemoveEntry: %v", err)
	}
	got, _ := m.Get(inv.ID)
	if len(got.Entries) != 0 {
		t.Errorf("expected 0 entries after removal, got %d", len(got.Entries))
	}
	if err := m.RemoveEntry(inv.ID, entry.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing an already-removed entry = %v, want ErrNotFound", err)
	}
}

// 19. Entry note.
func TestUpdateEntryNote(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "caso")
	entry, _, _ := m.AddSnapshot(inv.ID, validSnapshot(correlation.SourceDiagnose))

	updated, err := m.UpdateEntryNote(inv.ID, entry.ID, "seguimiento con el cliente el lunes")
	if err != nil {
		t.Fatalf("UpdateEntryNote: %v", err)
	}
	if updated.Note != "seguimiento con el cliente el lunes" {
		t.Errorf("Note = %q", updated.Note)
	}
	if _, err := m.UpdateEntryNote(inv.ID, entry.ID, strings.Repeat("a", maxNoteLen+1)); !errors.Is(err, ErrNoteTooLong) {
		t.Errorf("oversized note err = %v, want ErrNoteTooLong", err)
	}
}

// 20. Timeline sort by OccurredAt.
func TestTimelineSortByOccurredAt(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "caso")

	late := validSnapshot(correlation.SourceDiagnose)
	late.OccurredAt = "2026-01-01T12:00:00Z"
	early := validSnapshot(correlation.SourcePCAP)
	early.OccurredAt = "2026-01-01T09:00:00Z"

	m.AddSnapshot(inv.ID, late)
	m.AddSnapshot(inv.ID, early) // added second, but occurred first

	got, _ := m.Get(inv.ID)
	timeline := Timeline(got)
	if len(timeline) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(timeline))
	}
	if timeline[0].Snapshot.Kind != correlation.SourcePCAP {
		t.Errorf("timeline[0] = %+v, want the earlier-OccurredAt PCAP entry first", timeline[0])
	}
}

// E.1-4: two timestamps in different offsets must sort by the real
// instant they name, never by string comparison. "2026-08-14T19:00:00Z"
// (19:00 UTC) is genuinely earlier than "2026-08-14T14:30:00-05:00" (19:30
// UTC) even though the second string looks lexicographically smaller.
func TestTimelineSortsByRealInstantNotString(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "caso")

	earlierUTC := validSnapshot(correlation.SourceDiagnose) // 19:00 UTC
	earlierUTC.OccurredAt = "2026-08-14T19:00:00Z"
	laterOffset := validSnapshot(correlation.SourcePCAP) // 19:30 UTC, but a "smaller" string
	laterOffset.OccurredAt = "2026-08-14T14:30:00-05:00"

	m.AddSnapshot(inv.ID, laterOffset)
	m.AddSnapshot(inv.ID, earlierUTC)

	got, _ := m.Get(inv.ID)
	timeline := Timeline(got)
	if len(timeline) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(timeline))
	}
	if timeline[0].Snapshot.Kind != correlation.SourceDiagnose {
		t.Errorf("timeline[0] = %+v, want the genuinely-earlier (19:00 UTC) Diagnose entry first, not the lexicographically-smaller string", timeline[0])
	}
}

// 21. Fallback to AddedAt when OccurredAt is absent.
func TestTimelineFallsBackToAddedAt(t *testing.T) {
	inv := Investigation{
		Entries: []Entry{
			{ID: "a", AddedAt: "2026-01-01T10:00:00Z", Snapshot: correlation.Snapshot{}},
			{ID: "b", AddedAt: "2026-01-01T09:00:00Z", Snapshot: correlation.Snapshot{}},
		},
	}
	timeline := Timeline(inv)
	if timeline[0].ID != "b" {
		t.Errorf("expected AddedAt fallback ordering, got %+v", timeline)
	}
}

// 22. Highest severity computation.
func TestSummarizeHighestLevel(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "caso")

	low := validSnapshot(correlation.SourceDiagnose)
	low.Assessment.Level = model.LevelLow
	crit := validSnapshot(correlation.SourcePCAP)
	crit.Assessment.Level = model.LevelCritical
	crit.Assessment.Conclusion = "hallazgo crítico"

	m.AddSnapshot(inv.ID, low)
	m.AddSnapshot(inv.ID, crit)

	got, _ := m.Get(inv.ID)
	sum := Summarize(got)
	if sum.HighestLevel != model.LevelCritical {
		t.Errorf("HighestLevel = %q, want critico", sum.HighestLevel)
	}
	if sum.MainFinding != "hallazgo crítico" {
		t.Errorf("MainFinding = %q, want the critical entry's Conclusion", sum.MainFinding)
	}
}

// 23. Source counts.
func TestSummarizeSourceCounts(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "caso")
	m.AddSnapshot(inv.ID, validSnapshot(correlation.SourceDiagnose))
	pcap2 := validSnapshot(correlation.SourcePCAP)
	pcap2.Assessment.Evidence[0].Value = "otra evidencia"
	m.AddSnapshot(inv.ID, validSnapshot(correlation.SourcePCAP))
	m.AddSnapshot(inv.ID, pcap2)

	got, _ := m.Get(inv.ID)
	sum := Summarize(got)
	if sum.SourceCounts[correlation.SourceDiagnose] != 1 {
		t.Errorf("Diagnose count = %d, want 1", sum.SourceCounts[correlation.SourceDiagnose])
	}
	if sum.SourceCounts[correlation.SourcePCAP] != 2 {
		t.Errorf("PCAP count = %d, want 2", sum.SourceCounts[correlation.SourcePCAP])
	}
}

// 24. Corrupt JSON preserved, never deleted.
func TestListPreservesCorruptFile(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	id := "11111111-1111-1111-1111-111111111111"
	path := filepath.Join(dir, id+".json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}

	res := m.List()
	if len(res.Warnings) != 1 {
		t.Fatalf("expected 1 warning for the corrupt file, got %v", res.Warnings)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "{not valid json" {
		t.Errorf("corrupt file was modified or deleted: err=%v body=%q", err, body)
	}
}

// 25. One corrupt file must not hide the other valid ones.
func TestListOneCorruptDoesNotHideOthers(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	mustCreate(t, m, "caso sano")
	badID := "22222222-2222-2222-2222-222222222222"
	os.WriteFile(filepath.Join(dir, badID+".json"), []byte("{{{"), 0o600)

	res := m.List()
	if len(res.Investigations) != 1 {
		t.Fatalf("expected the healthy investigation to still be listed, got %+v", res.Investigations)
	}
	if len(res.Warnings) != 1 {
		t.Errorf("expected exactly 1 warning, got %v", res.Warnings)
	}
}

// 26. Future schema: preserved, reported, never reinterpreted or
// overwritten.
func TestListReportsFutureSchemaWarning(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	id := "33333333-3333-3333-3333-333333333333"
	path := filepath.Join(dir, id+".json")
	future := `{"schemaVersion":99,"id":"` + id + `","name":"del futuro","entries":[]}`
	os.WriteFile(path, []byte(future), 0o600)

	res := m.List()
	if len(res.Investigations) != 0 {
		t.Errorf("a future-schema investigation must not appear in the healthy list: %+v", res.Investigations)
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("expected 1 future-schema warning, got %v", res.Warnings)
	}

	if _, err := m.Get(id); !errors.Is(err, ErrUnsupportedSchema) {
		t.Errorf("Get on a future-schema file = %v, want ErrUnsupportedSchema", err)
	}
	body, _ := os.ReadFile(path)
	if string(body) != future {
		t.Error("a future-schema file must never be rewritten")
	}
}

// 27. Unsupported Snapshot schema version rejected.
func TestAddSnapshotRejectsUnsupportedSchemaVersion(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "caso")
	snap := validSnapshot(correlation.SourceDiagnose)
	snap.SchemaVersion = 99
	if _, _, err := m.AddSnapshot(inv.ID, snap); !errors.Is(err, ErrSnapshotUnsupportedSchema) {
		t.Errorf("err = %v, want ErrSnapshotUnsupportedSchema", err)
	}
}

// 28. Invalid SourceKind rejected.
func TestAddSnapshotRejectsInvalidSourceKind(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "caso")
	snap := validSnapshot(correlation.SourceKind("not-a-real-kind"))
	if _, _, err := m.AddSnapshot(inv.ID, snap); !errors.Is(err, ErrSnapshotInvalidKind) {
		t.Errorf("err = %v, want ErrSnapshotInvalidKind", err)
	}
}

// 29. Confidence > 100 rejected — both on the Assessment itself and on
// individual Evidence entries.
func TestAddSnapshotRejectsConfidenceOver100(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "caso")

	assessmentOver := validSnapshot(correlation.SourceDiagnose)
	assessmentOver.Assessment.Confidence = 150
	if _, _, err := m.AddSnapshot(inv.ID, assessmentOver); !errors.Is(err, ErrSnapshotInvalidConfidence) {
		t.Errorf("Assessment.Confidence=150: err = %v, want ErrSnapshotInvalidConfidence", err)
	}

	evidenceOver := validSnapshot(correlation.SourceDiagnose)
	evidenceOver.Assessment.Evidence[0].Confidence = 200
	if _, _, err := m.AddSnapshot(inv.ID, evidenceOver); !errors.Is(err, ErrSnapshotInvalidConfidence) {
		t.Errorf("Evidence[0].Confidence=200: err = %v, want ErrSnapshotInvalidConfidence", err)
	}
}

// 30. Oversized Snapshot rejected.
func TestAddSnapshotRejectsOversized(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "caso")
	snap := validSnapshot(correlation.SourceDiagnose)
	snap.Assessment.Conclusion = strings.Repeat("x", maxSnapshotBytes+1)
	if _, _, err := m.AddSnapshot(inv.ID, snap); !errors.Is(err, ErrSnapshotTooLarge) {
		t.Errorf("err = %v, want ErrSnapshotTooLarge", err)
	}
}

// 31. A failed write must never leave in-memory state ahead of what's
// actually on disk — forced by pre-creating a directory at the exact .tmp
// path AddSnapshot would try to write, which makes os.WriteFile fail
// portably on any OS.
func TestFailedWriteDoesNotMutateState(t *testing.T) {
	m := newTestManager(t)
	inv := mustCreate(t, m, "nombre original")

	tmpPath, err := m.investigationPath(inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	tmpPath += ".tmp"
	if err := os.Mkdir(tmpPath, 0o700); err != nil {
		t.Fatalf("failed to set up the write-failure fixture: %v", err)
	}

	if _, err := m.UpdateMetadata(inv.ID, "nombre nuevo", ""); err == nil {
		t.Fatal("expected UpdateMetadata to fail while its .tmp path is blocked by a directory")
	}

	os.Remove(tmpPath)
	got, err := m.Get(inv.ID)
	if err != nil {
		t.Fatalf("Get after failed write: %v", err)
	}
	if got.Name != "nombre original" {
		t.Errorf("Name = %q, want the pre-failure value — a failed write must never appear to have succeeded", got.Name)
	}
}

// 32. File permissions and UUID-only filenames.
func TestFilePermissionsAndFilename(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := mustCreate(t, m, "caso")

	path := filepath.Join(dir, inv.ID+".json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected the file at <dir>/<uuid>.json, got: %v", err)
	}
	if runtime.GOOS == "windows" {
		return // Windows ACLs don't map onto Unix mode bits — nothing more to assert portably.
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file perm = %v, want 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("dir perm = %v, want 0700", dirInfo.Mode().Perm())
	}
}
