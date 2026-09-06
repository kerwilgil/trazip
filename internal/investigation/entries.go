package investigation

import (
	"github.com/google/uuid"

	"trazip/internal/correlation"
)

// AddSnapshot validates and appends snap as a new Entry, unless an entry
// with the exact same Snapshot (byte-for-byte, via fingerprint) already
// exists — a double click on "Añadir a investigación" must be idempotent,
// never a second identical Entry (Phase E: "DUPLICATE SUPPRESSION"). Two
// Snapshots that merely share a Conclusion string are NOT duplicates: only
// an exact fingerprint match is.
func (m *Manager) AddSnapshot(id string, snap correlation.Snapshot) (entry Entry, existing bool, err error) {
	if err := validateSnapshot(snap); err != nil {
		return Entry{}, false, err
	}
	fp, err := fingerprint(snap)
	if err != nil {
		return Entry{}, false, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	inv, err := m.read(id)
	if err != nil {
		return Entry{}, false, err
	}

	for _, e := range inv.Entries {
		if e.Fingerprint == fp {
			return e, true, nil
		}
	}

	newEntry := Entry{
		ID:          uuid.NewString(),
		AddedAt:     nowRFC3339(),
		Snapshot:    snap,
		Fingerprint: fp,
	}
	inv.Entries = append(inv.Entries, newEntry)
	inv.UpdatedAt = newEntry.AddedAt
	if err := m.write(inv); err != nil {
		return Entry{}, false, err
	}
	return newEntry, false, nil
}

// RemoveEntry deletes one Entry from an Investigation. Never touches the
// original Diagnose/PCAP/Monitor/VoIP result the Entry's Snapshot came
// from — only this case's own copy of the reference.
func (m *Manager) RemoveEntry(investigationID, entryID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	inv, err := m.read(investigationID)
	if err != nil {
		return err
	}

	kept := make([]Entry, 0, len(inv.Entries))
	found := false
	for _, e := range inv.Entries {
		if e.ID == entryID {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return ErrNotFound
	}
	inv.Entries = kept
	inv.UpdatedAt = nowRFC3339()
	return m.write(inv)
}

// UpdateEntryNote sets the operator's own note on one Entry — never the
// Snapshot's Conclusion/Level/Confidence/Evidence, which belong to the
// original result and stay read-only here (Phase E: "No permitir editar:
// Conclusion, Level, Confidence, Evidence").
func (m *Manager) UpdateEntryNote(investigationID, entryID, note string) (Entry, error) {
	note, err := validateNote(note)
	if err != nil {
		return Entry{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	inv, err := m.read(investigationID)
	if err != nil {
		return Entry{}, err
	}

	for i := range inv.Entries {
		if inv.Entries[i].ID == entryID {
			inv.Entries[i].Note = note
			inv.UpdatedAt = nowRFC3339()
			if err := m.write(inv); err != nil {
				return Entry{}, err
			}
			return inv.Entries[i], nil
		}
	}
	return Entry{}, ErrNotFound
}
