package investigation

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"trazip/internal/correlation"
	"trazip/internal/model"
)

const (
	testIDA = "11111111-1111-1111-1111-111111111111"
	testIDB = "22222222-2222-2222-2222-222222222222"
)

func validEntry(id string) Entry {
	snap := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion, Kind: correlation.SourceDiagnose,
		Subject: "x", OccurredAt: "2026-01-01T10:00:00Z",
		Assessment: model.Assessment{Conclusion: "c", Level: model.LevelInfo, Confidence: 50},
	}
	fp, _ := fingerprint(snap)
	return Entry{ID: id, AddedAt: "2026-01-01T10:00:00Z", Snapshot: snap, Fingerprint: fp}
}

func validRawInvestigation(id string) Investigation {
	return Investigation{
		SchemaVersion: SchemaVersion, ID: id, Name: "caso",
		CreatedAt: "2026-01-01T08:00:00Z", UpdatedAt: "2026-01-01T08:00:00Z",
		Entries: []Entry{},
	}
}

func writeRaw(t *testing.T, dir, filenameID string, inv Investigation) {
	t.Helper()
	body, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filenameID+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readRawBytes(t *testing.T, dir, filenameID string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, filenameID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// ---------------------------------------------------------------------
// E.1-1: case file identity integrity
// ---------------------------------------------------------------------

func TestIdentityMismatchGetFails(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	// File named A but internally claims to be B.
	writeRaw(t, dir, testIDA, validRawInvestigation(testIDB))

	if _, err := m.Get(testIDA); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("Get(A) err = %v, want ErrIdentityMismatch", err)
	}
}

func TestIdentityMismatchUpdateMetadataFails(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	writeRaw(t, dir, testIDA, validRawInvestigation(testIDB))

	before := readRawBytes(t, dir, testIDA)
	if _, err := m.UpdateMetadata(testIDA, "nuevo nombre", ""); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("UpdateMetadata(A) err = %v, want ErrIdentityMismatch", err)
	}
	after := readRawBytes(t, dir, testIDA)
	if string(before) != string(after) {
		t.Error("A.json must remain byte-for-byte unchanged after a rejected UpdateMetadata")
	}
}

func TestIdentityMismatchDoesNotTouchEitherFile(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	// A.json claims to be B; a real, separate B.json also exists.
	writeRaw(t, dir, testIDA, validRawInvestigation(testIDB))
	realB := validRawInvestigation(testIDB)
	realB.Name = "el B real"
	writeRaw(t, dir, testIDB, realB)

	aBefore := readRawBytes(t, dir, testIDA)
	bBefore := readRawBytes(t, dir, testIDB)

	// Try every mutating operation against A; every one must fail and
	// touch neither file.
	m.Get(testIDA)
	m.UpdateMetadata(testIDA, "x", "")
	m.RemoveEntry(testIDA, "nonexistent")
	m.UpdateEntryNote(testIDA, "nonexistent", "note")
	m.AddSnapshot(testIDA, validEntry("").Snapshot)

	aAfter := readRawBytes(t, dir, testIDA)
	bAfter := readRawBytes(t, dir, testIDB)
	if string(aBefore) != string(aAfter) {
		t.Error("A.json (identity mismatch) must never be rewritten")
	}
	if string(bBefore) != string(bAfter) {
		t.Error("B.json (a real, unrelated case) must never be touched by operations aimed at A")
	}

	// And B, opened by its own correct ID, must still work normally.
	got, err := m.Get(testIDB)
	if err != nil {
		t.Fatalf("Get(B) should still succeed: %v", err)
	}
	if got.Name != "el B real" {
		t.Errorf("Get(B).Name = %q, want the real B content", got.Name)
	}
}

func TestIdentityMismatchExcludedFromList(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	writeRaw(t, dir, testIDA, validRawInvestigation(testIDB))

	res := m.List()
	for _, s := range res.Investigations {
		if s.ID == testIDA {
			t.Fatal("an identity-mismatched file must never appear in the healthy list")
		}
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("expected exactly 1 warning, got %v", res.Warnings)
	}
}

func TestInternalIDNotUUIDIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	raw := validRawInvestigation(testIDA)
	raw.ID = "not-a-uuid-at-all"
	writeRaw(t, dir, testIDA, raw)

	if _, err := m.Get(testIDA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Get err = %v, want ErrCorrupt for a non-UUID internal ID", err)
	}
}

// ---------------------------------------------------------------------
// E.1-2: persisted semantic validation
// ---------------------------------------------------------------------

func TestValidV1FilePassesSemanticValidation(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := validRawInvestigation(testIDA)
	inv.Entries = []Entry{validEntry("33333333-3333-3333-3333-333333333333")}
	writeRaw(t, dir, testIDA, inv)

	if _, err := m.Get(testIDA); err != nil {
		t.Fatalf("expected a well-formed schema v1 file to pass, got %v", err)
	}
}

func TestSchemaVersionZeroIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := validRawInvestigation(testIDA)
	inv.SchemaVersion = 0
	writeRaw(t, dir, testIDA, inv)

	if _, err := m.Get(testIDA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("schemaVersion=0: err = %v, want ErrCorrupt", err)
	}
}

func TestSchemaVersionNegativeIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := validRawInvestigation(testIDA)
	inv.SchemaVersion = -1
	writeRaw(t, dir, testIDA, inv)

	if _, err := m.Get(testIDA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("schemaVersion=-1: err = %v, want ErrCorrupt", err)
	}
}

func TestSchemaVersionFutureIsUnsupportedNotCorrupt(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := validRawInvestigation(testIDA)
	inv.SchemaVersion = 2
	writeRaw(t, dir, testIDA, inv)

	if _, err := m.Get(testIDA); !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("schemaVersion=2: err = %v, want ErrUnsupportedSchema (not ErrCorrupt)", err)
	}
}

func TestInvalidNameIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := validRawInvestigation(testIDA)
	inv.Name = "   " // empty after trim
	writeRaw(t, dir, testIDA, inv)

	if _, err := m.Get(testIDA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("empty Name: err = %v, want ErrCorrupt", err)
	}
}

func TestInvalidCreatedAtIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := validRawInvestigation(testIDA)
	inv.CreatedAt = "yesterday"
	writeRaw(t, dir, testIDA, inv)

	if _, err := m.Get(testIDA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid CreatedAt: err = %v, want ErrCorrupt", err)
	}
}

func TestInvalidUpdatedAtIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := validRawInvestigation(testIDA)
	inv.UpdatedAt = "123"
	writeRaw(t, dir, testIDA, inv)

	if _, err := m.Get(testIDA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid UpdatedAt: err = %v, want ErrCorrupt", err)
	}
}

func TestEntryIDNotUUIDIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := validRawInvestigation(testIDA)
	e := validEntry("not-a-uuid")
	inv.Entries = []Entry{e}
	writeRaw(t, dir, testIDA, inv)

	if _, err := m.Get(testIDA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("non-UUID Entry.ID: err = %v, want ErrCorrupt", err)
	}
}

func TestEntryAddedAtInvalidIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := validRawInvestigation(testIDA)
	e := validEntry("33333333-3333-3333-3333-333333333333")
	e.AddedAt = "not-a-time"
	inv.Entries = []Entry{e}
	writeRaw(t, dir, testIDA, inv)

	if _, err := m.Get(testIDA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid Entry.AddedAt: err = %v, want ErrCorrupt", err)
	}
}

func TestEntryNoteTooLongIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := validRawInvestigation(testIDA)
	e := validEntry("33333333-3333-3333-3333-333333333333")
	long := make([]byte, maxNoteLen+1)
	for i := range long {
		long[i] = 'a'
	}
	e.Note = string(long)
	inv.Entries = []Entry{e}
	writeRaw(t, dir, testIDA, inv)

	if _, err := m.Get(testIDA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("oversized Entry.Note: err = %v, want ErrCorrupt", err)
	}
}

func TestEntrySnapshotInvalidIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := validRawInvestigation(testIDA)
	e := validEntry("33333333-3333-3333-3333-333333333333")
	e.Snapshot.Kind = correlation.SourceKind("bogus")
	// Fingerprint would now be stale too, but Snapshot validation must
	// fail before fingerprint comparison is even reached.
	inv.Entries = []Entry{e}
	writeRaw(t, dir, testIDA, inv)

	if _, err := m.Get(testIDA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid Snapshot.Kind: err = %v, want ErrCorrupt", err)
	}
}

func TestEntryFingerprintMismatchIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := validRawInvestigation(testIDA)
	e := validEntry("33333333-3333-3333-3333-333333333333")
	e.Fingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
	inv.Entries = []Entry{e}
	writeRaw(t, dir, testIDA, inv)

	if _, err := m.Get(testIDA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("stale Fingerprint: err = %v, want ErrCorrupt", err)
	}
}

func TestDuplicateEntryIDIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := validRawInvestigation(testIDA)
	e1 := validEntry("33333333-3333-3333-3333-333333333333")
	e2 := validEntry("33333333-3333-3333-3333-333333333333")
	e2.Snapshot.Assessment.Conclusion = "algo distinto"
	fp2, _ := fingerprint(e2.Snapshot)
	e2.Fingerprint = fp2
	inv.Entries = []Entry{e1, e2}
	writeRaw(t, dir, testIDA, inv)

	if _, err := m.Get(testIDA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("duplicate Entry.ID: err = %v, want ErrCorrupt", err)
	}
}

func TestDuplicateFingerprintIsCorrupt(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	inv := validRawInvestigation(testIDA)
	e1 := validEntry("33333333-3333-3333-3333-333333333333")
	e2 := validEntry("44444444-4444-4444-4444-444444444444") // different Entry.ID, identical Snapshot -> identical fingerprint
	inv.Entries = []Entry{e1, e2}
	writeRaw(t, dir, testIDA, inv)

	if _, err := m.Get(testIDA); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("duplicate fingerprint across distinct entries: err = %v, want ErrCorrupt", err)
	}
}

// ---------------------------------------------------------------------
// E.1-8: atomic write tmp cleanup
// ---------------------------------------------------------------------

// A dedicated ordinary-file scenario, deliberately separate from
// TestFailedWriteDoesNotMutateState's directory-blocking .tmp fixture
// (E.1-8 spec: don't let cleanup auto-remove that other test's fixture and
// change what it's actually verifying). Here the .tmp WriteFile succeeds
// completely normally; only the final rename onto an already-blocked
// destination fails — exactly the scenario write()'s own best-effort
// cleanup exists for.
func TestWriteFailureCleansUpTmpFile(t *testing.T) {
	dir := t.TempDir()
	m := newManagerAt(dir)
	id := "55555555-5555-5555-5555-555555555555"
	targetPath := filepath.Join(dir, id+".json")
	if err := os.Mkdir(targetPath, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := m.write(validRawInvestigation(id)); err == nil {
		t.Fatal("expected write to fail — its destination is blocked by a directory")
	}

	tmpPath := targetPath + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Errorf("expected the .tmp file to be cleaned up after a failed rename, stat err = %v", err)
	}
	info, err := os.Stat(targetPath)
	if err != nil || !info.IsDir() {
		t.Errorf("the pre-existing blocking directory must be left untouched, err=%v", err)
	}
}

// ---------------------------------------------------------------------
// E.1-3: Snapshot.OccurredAt timestamp validation
// ---------------------------------------------------------------------

func TestValidateSnapshotOccurredAtEmpty(t *testing.T) {
	s := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion, Kind: correlation.SourceDiagnose,
		OccurredAt: "", Assessment: model.Assessment{Level: model.LevelInfo, Confidence: 50},
	}
	if err := validateSnapshot(s); err != nil {
		t.Errorf("empty OccurredAt should be allowed, got %v", err)
	}
}

func TestValidateSnapshotOccurredAtZ(t *testing.T) {
	s := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion, Kind: correlation.SourceDiagnose,
		OccurredAt: "2026-08-14T19:00:00Z", Assessment: model.Assessment{Level: model.LevelInfo, Confidence: 50},
	}
	if err := validateSnapshot(s); err != nil {
		t.Errorf("Z-suffixed RFC3339 should be valid, got %v", err)
	}
}

func TestValidateSnapshotOccurredAtOffset(t *testing.T) {
	s := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion, Kind: correlation.SourceDiagnose,
		OccurredAt: "2026-08-14T14:30:00-05:00", Assessment: model.Assessment{Level: model.LevelInfo, Confidence: 50},
	}
	if err := validateSnapshot(s); err != nil {
		t.Errorf("offset RFC3339 should be valid, got %v", err)
	}
}

func TestValidateSnapshotOccurredAtNano(t *testing.T) {
	s := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion, Kind: correlation.SourceDiagnose,
		OccurredAt: "2026-08-14T19:00:00.123456789Z", Assessment: model.Assessment{Level: model.LevelInfo, Confidence: 50},
	}
	if err := validateSnapshot(s); err != nil {
		t.Errorf("RFC3339Nano should be valid, got %v", err)
	}
}

func TestValidateSnapshotOccurredAtInvalidText(t *testing.T) {
	s := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion, Kind: correlation.SourceDiagnose,
		OccurredAt: "ayer", Assessment: model.Assessment{Level: model.LevelInfo, Confidence: 50},
	}
	if err := validateSnapshot(s); !errors.Is(err, ErrSnapshotInvalidTimestamp) {
		t.Errorf("err = %v, want ErrSnapshotInvalidTimestamp", err)
	}
}

func TestValidateSnapshotOccurredAtInvalidNumber(t *testing.T) {
	s := correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion, Kind: correlation.SourceDiagnose,
		OccurredAt: "123", Assessment: model.Assessment{Level: model.LevelInfo, Confidence: 50},
	}
	if err := validateSnapshot(s); !errors.Is(err, ErrSnapshotInvalidTimestamp) {
		t.Errorf("err = %v, want ErrSnapshotInvalidTimestamp", err)
	}
}
