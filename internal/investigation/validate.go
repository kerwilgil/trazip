package investigation

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"trazip/internal/correlation"
	"trazip/internal/model"
)

const (
	maxNameLen      = 120
	maxObjectiveLen = 2000
	maxNoteLen      = 2000

	// maxSnapshotBytes bounds one Snapshot's serialized size — investigation
	// is a small case-file store, not a blob database (Phase E: "No aceptar
	// un Snapshot gigantesco... Si se supera: error explícito. No truncar
	// evidencia silenciosamente."). 256 KiB comfortably fits any real
	// Assessment's Evidence/CounterEvidence/Limitations while still catching
	// a caller mistake (e.g. accidentally serializing a full PCAP result).
	maxSnapshotBytes = 256 * 1024
)

var (
	ErrNameRequired     = errors.New("investigation: name is required")
	ErrNameTooLong      = fmt.Errorf("investigation: name exceeds %d characters", maxNameLen)
	ErrObjectiveTooLong = fmt.Errorf("investigation: objective exceeds %d characters", maxObjectiveLen)
	ErrNoteTooLong      = fmt.Errorf("investigation: note exceeds %d characters", maxNoteLen)

	ErrSnapshotUnsupportedSchema = errors.New("investigation: snapshot schema version is not supported")
	ErrSnapshotInvalidKind       = errors.New("investigation: snapshot has an unrecognized source kind")
	ErrSnapshotInvalidLevel      = errors.New("investigation: snapshot assessment has an invalid level")
	ErrSnapshotInvalidConfidence = errors.New("investigation: snapshot confidence must be between 0 and 100")
	ErrSnapshotTooLarge          = fmt.Errorf("investigation: snapshot exceeds the %d byte limit", maxSnapshotBytes)
	// ErrSnapshotInvalidTimestamp guards OccurredAt specifically — empty is
	// allowed (Phase E: "NO inventar OccurredAt"), but a non-empty value
	// that isn't real RFC3339 would otherwise reach the timeline unparsed
	// and either crash or silently mis-sort it. Never rewritten or
	// reformatted here — only accepted or rejected as-is.
	ErrSnapshotInvalidTimestamp = errors.New("investigation: snapshot occurredAt is not a valid RFC3339 timestamp")
)

func validateName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", ErrNameRequired
	}
	if len([]rune(name)) > maxNameLen {
		return "", ErrNameTooLong
	}
	return name, nil
}

func validateObjective(objective string) (string, error) {
	objective = strings.TrimSpace(objective)
	if len([]rune(objective)) > maxObjectiveLen {
		return "", ErrObjectiveTooLong
	}
	return objective, nil
}

func validateNote(note string) (string, error) {
	note = strings.TrimSpace(note)
	if len([]rune(note)) > maxNoteLen {
		return "", ErrNoteTooLong
	}
	return note, nil
}

var validSourceKinds = map[correlation.SourceKind]bool{
	correlation.SourceDiagnose: true,
	correlation.SourcePCAP:     true,
	correlation.SourceMonitor:  true,
	correlation.SourceVoIP:     true,
}

var validLevels = map[model.Level]bool{
	model.LevelInfo:     true,
	model.LevelLow:      true,
	model.LevelMedium:   true,
	model.LevelHigh:     true,
	model.LevelCritical: true,
}

// validateSnapshot rejects a Snapshot investigation cannot safely store —
// never silently coerces or truncates it (Phase E: "No truncar evidencia
// silenciosamente"). Confidence is checked on the Assessment itself and on
// every individual Evidence/CounterEvidence entry, since each carries its
// own Confidence independently.
func validateSnapshot(s correlation.Snapshot) error {
	if s.SchemaVersion != correlation.SnapshotSchemaVersion {
		return ErrSnapshotUnsupportedSchema
	}
	if !validSourceKinds[s.Kind] {
		return ErrSnapshotInvalidKind
	}
	if !validLevels[s.Assessment.Level] {
		return ErrSnapshotInvalidLevel
	}
	if err := validateConfidence(s.Assessment.Confidence); err != nil {
		return err
	}
	for _, e := range s.Assessment.Evidence {
		if err := validateConfidence(e.Confidence); err != nil {
			return err
		}
	}
	for _, e := range s.Assessment.CounterEvid {
		if err := validateConfidence(e.Confidence); err != nil {
			return err
		}
	}
	if s.OccurredAt != "" && !isValidTimestamp(s.OccurredAt) {
		return ErrSnapshotInvalidTimestamp
	}

	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(body) > maxSnapshotBytes {
		return ErrSnapshotTooLarge
	}
	return nil
}

func validateConfidence(c model.Confidence) error {
	if c > 100 {
		return ErrSnapshotInvalidConfidence
	}
	return nil
}

// isValidTimestamp reports whether s parses as RFC3339 or RFC3339Nano —
// never reformats or rewrites it either way, only accepts or rejects the
// exact string as given (E.1-3: "Solo validar").
func isValidTimestamp(s string) bool {
	if _, err := time.Parse(time.RFC3339, s); err == nil {
		return true
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

// verifySemantics is read()'s deeper pass after JSON-unmarshal, schema
// version and filename/ID identity have already checked out (E.1-2): every
// field a corrupted-but-syntactically-valid file could still get wrong.
// Collapses every distinct problem to ErrCorrupt — List/Get callers only
// ever need to know "this file can't be trusted", not which of these
// specific checks tripped; the file itself is left completely untouched
// either way (this function only ever reads inv, an in-memory value).
func verifySemantics(inv Investigation) error {
	if _, err := validateName(inv.Name); err != nil {
		return ErrCorrupt
	}
	if _, err := validateObjective(inv.Objective); err != nil {
		return ErrCorrupt
	}
	if !isValidTimestamp(inv.CreatedAt) {
		return ErrCorrupt
	}
	if !isValidTimestamp(inv.UpdatedAt) {
		return ErrCorrupt
	}

	seenEntryID := map[string]bool{}
	seenFingerprint := map[string]bool{}
	for _, e := range inv.Entries {
		if _, err := uuid.Parse(e.ID); err != nil {
			return ErrCorrupt
		}
		if seenEntryID[e.ID] {
			return ErrCorrupt // duplicate Entry.ID
		}
		seenEntryID[e.ID] = true

		if !isValidTimestamp(e.AddedAt) {
			return ErrCorrupt
		}
		if _, err := validateNote(e.Note); err != nil {
			return ErrCorrupt
		}
		if err := validateSnapshot(e.Snapshot); err != nil {
			return ErrCorrupt
		}

		wantFP, err := fingerprint(e.Snapshot)
		if err != nil || e.Fingerprint != wantFP {
			return ErrCorrupt // stored fingerprint doesn't match its own Snapshot
		}
		if seenFingerprint[e.Fingerprint] {
			return ErrCorrupt // two entries with an identical Snapshot violates AddSnapshot's own dedup contract
		}
		seenFingerprint[e.Fingerprint] = true
	}
	return nil
}
