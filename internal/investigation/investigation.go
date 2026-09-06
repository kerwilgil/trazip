// Package investigation is TRAZIP V1's local case workspace (TRAZIP V1
// MASTER IMPLEMENTATION, "PHASE E — INVESTIGATION WORKSPACE"): an operator
// picks results a module already produced — Diagnose, PCAP, Monitor's
// route-change detection, VoIP — and collects them into one named case with
// a timeline, so they don't have to re-find them across five different
// screens later.
//
// This package never runs a diagnostic of its own. Every entry it stores is
// a correlation.Snapshot handed to it by internal/api, already built by
// that module's own Phase E.0 adapter — investigation only stores, orders,
// groups and exports what it's given. The source of truth for WHY a
// Snapshot says what it says always stays in the module that produced it;
// this package is a container, not a second opinion.
//
// Leaf-ish, not leaf: this package may import internal/correlation,
// internal/model, internal/report and internal/paths, but never
// internal/api, internal/diagnosis, internal/monitor, internal/voip or
// internal/session — see deps_test.go, which enforces this structurally.
// Those richer packages call INTO investigation (via internal/api); it
// never calls back into them.
package investigation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"trazip/internal/correlation"
	"trazip/internal/paths"
)

// SchemaVersion is this package's OWN on-disk schema version — distinct
// from correlation.SnapshotSchemaVersion, which versions the Entry.Snapshot
// shape independently. Bumped only when Investigation/Entry's own shape
// changes in a way an older persisted file would need to migrate for.
const SchemaVersion = 1

// Investigation is one operator-created case: a name, an optional
// objective, and the Snapshots they explicitly chose to add — never
// results TRAZIP collected on its own (Phase E: "NO AUTOMATIC
// COLLECTION").
type Investigation struct {
	SchemaVersion int `json:"schemaVersion"`

	ID string `json:"id"`

	Name      string `json:"name"`
	Objective string `json:"objective,omitempty"`

	CreatedAt string `json:"createdAt"` // RFC3339
	UpdatedAt string `json:"updatedAt"` // RFC3339

	Entries []Entry `json:"entries"`
}

// Entry is one Snapshot the operator added to an Investigation, plus the
// bookkeeping investigation itself owns (when it was added, the operator's
// own note, a dedup fingerprint) — never a second interpretation of the
// Snapshot's own Assessment.
type Entry struct {
	ID string `json:"id"`

	AddedAt string `json:"addedAt"` // RFC3339

	Snapshot correlation.Snapshot `json:"snapshot"`

	Note string `json:"note,omitempty"`

	// Fingerprint is sha256(canonical JSON of Snapshot), hex-encoded — the
	// exact-duplicate check AddSnapshot uses to stay idempotent against a
	// double click (Phase E: "DUPLICATE SUPPRESSION"). Never used to decide
	// whether two DIFFERENT snapshots are "similar" — only byte-for-byte
	// identity counts.
	Fingerprint string `json:"fingerprint"`
}

// Sentinel errors — callers (internal/api, and its own tests) branch on
// these with errors.Is rather than string-matching.
var (
	ErrNotFound          = errors.New("investigation: not found")
	ErrInvalidID         = errors.New("investigation: invalid id")
	ErrCorrupt           = errors.New("investigation: file is corrupt")
	ErrUnsupportedSchema = errors.New("investigation: file was created by a newer version of TRAZIP")
	// ErrIdentityMismatch is a specific, more serious case of ErrCorrupt: the
	// file at <id>.json parses as valid JSON with a supported schema, but
	// its own inv.ID doesn't match the filename it was opened by (E.1-1).
	// Never auto-corrected — a file this deceptively "healthy"-looking is
	// exactly the case fail-closed handling exists for: silently trusting
	// inv.ID here (as write() does to compute its own path) could let an
	// operation aimed at case A silently mutate case B's file instead.
	ErrIdentityMismatch = errors.New("investigation: file identity does not match its filename")
)

// Manager owns the on-disk investigation store. Safe for concurrent use —
// every mutating operation holds mu for its full read-modify-write cycle,
// and there is deliberately no in-memory cache of Investigation content to
// let drift from disk: Get/List always read the current file fresh, so a
// failed write can never leave in-memory state ahead of what's actually
// persisted (Phase E: "Si write falla: NO actualizar estado en memoria
// como si hubiera persistido correctamente").
type Manager struct {
	mu  sync.Mutex
	dir string
}

// NewManager opens (or creates) the real investigation store directory.
func NewManager() *Manager {
	return newManagerAt(investigationDir())
}

// NewManagerAt opens (or creates) an investigation store at an explicit
// directory — exported so internal/api's own tests can point a real
// Manager at a t.TempDir() instead of the user's real config directory,
// the same way this package's own tests use newManagerAt directly.
func NewManagerAt(dir string) *Manager {
	return newManagerAt(dir)
}

// newManagerAt is the shared constructor; tests point it at a temp dir so
// they never touch the real user config directory (mirrors monitor.Manager
// and quality.Manager's own newManagerAt).
func newManagerAt(dir string) *Manager {
	os.MkdirAll(dir, 0o700)
	_ = os.Chmod(dir, 0o700)
	return &Manager{dir: dir}
}

func investigationDir() string {
	return paths.Sub("investigations")
}

// investigationPath validates id as a real UUID before building a path from
// it — the same traversal guard monitor.Manager.targetPath uses. A
// caller-supplied id that isn't a valid UUID can never reach the
// filesystem as anything but this fixed, harmless sentinel path.
func (m *Manager) investigationPath(id string) (string, error) {
	if _, err := uuid.Parse(id); err != nil {
		return "", ErrInvalidID
	}
	return filepath.Join(m.dir, id+".json"), nil
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// Create starts a new, empty Investigation.
func (m *Manager) Create(name, objective string) (Investigation, error) {
	name, err := validateName(name)
	if err != nil {
		return Investigation{}, err
	}
	objective, err = validateObjective(objective)
	if err != nil {
		return Investigation{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := nowRFC3339()
	inv := Investigation{
		SchemaVersion: SchemaVersion,
		ID:            uuid.NewString(),
		Name:          name,
		Objective:     objective,
		CreatedAt:     now,
		UpdatedAt:     now,
		Entries:       []Entry{},
	}
	if err := m.write(inv); err != nil {
		return Investigation{}, err
	}
	return inv, nil
}

// Get reads one Investigation by ID, exactly as persisted.
func (m *Manager) Get(id string) (Investigation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.read(id)
}

// UpdateMetadata changes Name/Objective, bumping UpdatedAt. Entries are
// untouched — this never rewrites evidence, only the case's own label.
func (m *Manager) UpdateMetadata(id, name, objective string) (Investigation, error) {
	name, err := validateName(name)
	if err != nil {
		return Investigation{}, err
	}
	objective, err = validateObjective(objective)
	if err != nil {
		return Investigation{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	inv, err := m.read(id)
	if err != nil {
		return Investigation{}, err
	}
	inv.Name = name
	inv.Objective = objective
	inv.UpdatedAt = nowRFC3339()
	if err := m.write(inv); err != nil {
		return Investigation{}, err
	}
	return inv, nil
}

// Delete removes an Investigation entirely — an explicit, irreversible
// operator action (Phase E: "Delete Investigation: acción explícita.
// Frontend debe pedir confirmación."). Never touches the original
// Diagnose/PCAP/Monitor/VoIP result an Entry's Snapshot came from.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	path, err := m.investigationPath(id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// read loads one Investigation from disk without any caching — the file is
// always the source of truth. Distinguishes "doesn't exist" from "exists
// but is corrupt" from "exists but from a newer, unsupported schema" from
// "exists, parses, but its own ID doesn't match the filename it was opened
// by" so callers (and List, which must never let one bad file hide the
// rest) can react to each honestly. Never repairs, rewrites, moves, or
// reinterprets anything it finds wrong — every failure path here returns
// with the file on disk completely untouched (E.1-1/E.1-2).
func (m *Manager) read(id string) (Investigation, error) {
	path, err := m.investigationPath(id)
	if err != nil {
		return Investigation{}, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Investigation{}, ErrNotFound
		}
		return Investigation{}, err
	}
	var inv Investigation
	if err := json.Unmarshal(body, &inv); err != nil {
		return Investigation{}, ErrCorrupt
	}

	switch {
	case inv.SchemaVersion > SchemaVersion:
		return Investigation{}, ErrUnsupportedSchema
	case inv.SchemaVersion != SchemaVersion:
		// <= 0, or any other value that isn't today's one and only
		// supported version — there is no migration engine, so this is
		// unrecognized legacy content, not something to reinterpret
		// (E.1-2: "NO reinterpretar. NO sobrescribir.").
		return Investigation{}, ErrCorrupt
	}

	storedID, err := uuid.Parse(inv.ID)
	if err != nil {
		return Investigation{}, ErrCorrupt
	}
	requestedID, err := uuid.Parse(id)
	if err != nil {
		// id already passed through investigationPath above, so this
		// should be unreachable — kept as a defensive fallback rather
		// than a panic.
		return Investigation{}, ErrInvalidID
	}
	if storedID != requestedID {
		return Investigation{}, ErrIdentityMismatch
	}

	if err := verifySemantics(inv); err != nil {
		return Investigation{}, err
	}

	return inv, nil
}

// write persists inv atomically: marshal, write to a same-directory .tmp
// file, rename over the real path — the exact pattern monitor.Manager,
// quality.Manager and every other TRAZIP on-disk store already uses, so an
// interrupted write can never leave a half-written investigation. Returns
// the error, if any, and touches nothing else — the caller's own in-memory
// value (if any) is simply not updated on failure, since this package never
// keeps one. The pre-existing file at path (if any) is never touched by a
// failure here either: only rename() ever writes to path, and rename only
// takes effect on success.
//
// On failure, best-effort removes the .tmp file it was writing rather than
// leaving it behind (E.1-8) — a lingering .tmp can never be misread as a
// real case (List's glob only ever matches "*.json"), but it's still dead
// weight in the store directory. A cleanup failure is deliberately
// swallowed: it must never replace or mask the real error this function is
// already returning.
func (m *Manager) write(inv Investigation) error {
	path, err := m.investigationPath(inv.ID)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ListResult is List's own return shape: healthy investigations plus any
// warnings about files that exist but couldn't be included (corrupt, or
// from a newer TRAZIP version) — never a silent "zero investigations" when
// the real problem is one bad file (Phase E: "CORRUPTED / FUTURE FILES").
type ListResult struct {
	Investigations []Summary `json:"investigations"`
	Warnings       []string  `json:"warnings,omitempty"`
}

// List summarizes every investigation on disk, most recently updated
// first — never the full Entry list (Phase E: "List de investigaciones NO
// debería cargar/renderizar miles de Entry completas"). Call Get for the
// full case.
func (m *Manager) List() ListResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	files, _ := filepath.Glob(filepath.Join(m.dir, "*.json"))
	sort.Strings(files) // deterministic before-sort order; final order is by UpdatedAt below

	var out ListResult
	for _, f := range files {
		id := filepath.Base(f)
		id = id[:len(id)-len(filepath.Ext(id))]
		inv, err := m.read(id)
		switch {
		case errors.Is(err, ErrIdentityMismatch):
			out.Warnings = append(out.Warnings, "Investigación "+id+" tiene una identidad interna inconsistente con su archivo y fue preservada sin cambios — revisar manualmente.")
			continue
		case errors.Is(err, ErrCorrupt):
			out.Warnings = append(out.Warnings, "Investigación "+id+" está corrupta y fue preservada sin cambios — revisar el archivo manualmente.")
			continue
		case errors.Is(err, ErrUnsupportedSchema):
			out.Warnings = append(out.Warnings, "Investigación "+id+" fue creada por una versión más reciente de TRAZIP y no se puede abrir aquí.")
			continue
		case err != nil:
			out.Warnings = append(out.Warnings, "Investigación "+id+" no se pudo leer: "+err.Error())
			continue
		}
		out.Investigations = append(out.Investigations, Summarize(inv))
	}

	sort.SliceStable(out.Investigations, func(i, j int) bool {
		return out.Investigations[i].UpdatedAt > out.Investigations[j].UpdatedAt
	})
	return out
}

// fingerprint returns sha256(canonical JSON of s), hex-encoded. Snapshot
// (and model.Assessment beneath it) contain no maps — every field is a
// scalar, a string-slice, or a struct-slice with fixed field order — so
// plain json.Marshal is already canonical: the same Snapshot value always
// marshals to the same bytes, which is all this needs.
func fingerprint(s correlation.Snapshot) (string, error) {
	body, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}
