package investigation

import (
	"fmt"
	"sort"
	"time"

	"trazip/internal/correlation"
	"trazip/internal/model"
)

// Summary is the small, list-friendly view of an Investigation — computed
// fresh from its Entries every time, never a second stored opinion (Phase
// E: "Agregar una vista computada, NO una segunda diagnosis"). Everything
// here is aggregation (counts, the single highest-severity Conclusion) —
// never a new causal claim beyond what an individual Entry's own Snapshot
// already asserts.
type Summary struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Objective string `json:"objective,omitempty"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`

	EntryCount int `json:"entryCount"`
	// HighestLevel is Info when there are no entries yet — never a claim
	// that "nothing was found", just the honest floor of the vocabulary
	// (model.Level has no lower value than Info).
	HighestLevel model.Level `json:"highestLevel"`

	SourceCounts map[correlation.SourceKind]int `json:"sourceCounts,omitempty"`

	// MainFinding names the single highest-severity Entry's own Conclusion
	// — restated, never re-derived. Empty when there are no entries above
	// Info, or none at all.
	MainFinding string `json:"mainFinding,omitempty"`
}

// levelSeverity ranks model.Level the same direction every other TRAZIP
// severity ranking already does (see internal/api's pcapFindingSeverity) —
// kept as its own small copy rather than a shared helper since this is the
// only place investigation needs it and the vocabulary (Critical..Info) is
// exactly model.Level's own, no translation required.
func levelSeverity(l model.Level) int {
	switch l {
	case model.LevelCritical:
		return 4
	case model.LevelHigh:
		return 3
	case model.LevelMedium:
		return 2
	case model.LevelLow:
		return 1
	default: // model.LevelInfo, or an unrecognized value
		return 0
	}
}

// Summarize computes an Investigation's Summary from its current Entries.
func Summarize(inv Investigation) Summary {
	s := Summary{
		ID: inv.ID, Name: inv.Name, Objective: inv.Objective,
		CreatedAt: inv.CreatedAt, UpdatedAt: inv.UpdatedAt,
		EntryCount:   len(inv.Entries),
		HighestLevel: model.LevelInfo,
	}
	if len(inv.Entries) == 0 {
		return s
	}

	counts := map[correlation.SourceKind]int{}
	var top *Entry
	for i := range inv.Entries {
		e := &inv.Entries[i]
		counts[e.Snapshot.Kind]++
		if top == nil || levelSeverity(e.Snapshot.Assessment.Level) > levelSeverity(top.Snapshot.Assessment.Level) {
			top = e
		}
	}
	s.SourceCounts = counts
	s.HighestLevel = top.Snapshot.Assessment.Level
	if levelSeverity(top.Snapshot.Assessment.Level) > 0 {
		s.MainFinding = top.Snapshot.Assessment.Conclusion
	}
	return s
}

// Timeline returns inv's Entries ordered by Snapshot.OccurredAt when it's
// set, falling back to Entry.AddedAt when it isn't (Phase E: "NO inventar
// OccurredAt") — a copy, never mutating inv.Entries' own stored order.
// Ordered by actual instant, not string comparison (E.1-4): two RFC3339
// timestamps in different offsets/zones don't sort correctly as plain
// strings (e.g. "...T19:00:00Z" is later than "...T14:30:00-05:00" even
// though the second string looks "smaller" — they're both 19:00 UTC vs
// 19:30 UTC respectively). Never rewrites the stored timestamp strings
// themselves, only parses them in memory to compare.
func Timeline(inv Investigation) []Entry {
	out := make([]Entry, len(inv.Entries))
	copy(out, inv.Entries)
	sort.SliceStable(out, func(i, j int) bool {
		return entryInstant(out[i]).Before(entryInstant(out[j]))
	})
	return out
}

func entryTime(e Entry) string {
	if e.Snapshot.OccurredAt != "" {
		return e.Snapshot.OccurredAt
	}
	return e.AddedAt
}

// entryInstant parses entryTime(e) as a real instant. Falls back to the
// zero time (sorts first) on a parse failure, which should be unreachable
// for any Entry that passed read()'s own verifySemantics — kept defensive
// rather than panicking since Timeline() has no error return to surface
// one through.
func entryInstant(e Entry) time.Time {
	s := entryTime(e)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return time.Time{}
}

// mainFindingSentence renders Summary.MainFinding as the aggregation
// language Phase E requires — a restatement, never a causal claim (Phase
// E: "CASE-LEVEL LANGUAGE" — no "causa raíz", no "diagnóstico definitivo").
func mainFindingSentence(s Summary) string {
	if s.EntryCount == 0 {
		return "Esta investigación todavía no tiene evidencias añadidas."
	}
	sources := sourceCountsSentence(s.SourceCounts)
	if s.MainFinding == "" {
		return fmt.Sprintf("%d evidencia(s) añadida(s)%s. Ninguna por encima de informativo.", s.EntryCount, sources)
	}
	return fmt.Sprintf("%d evidencia(s) añadida(s)%s. El hallazgo de mayor severidad es: %s", s.EntryCount, sources, s.MainFinding)
}

func sourceCountsSentence(counts map[correlation.SourceKind]int) string {
	if len(counts) == 0 {
		return ""
	}
	kinds := make([]correlation.SourceKind, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	out := " desde "
	for i, k := range kinds {
		if i > 0 {
			if i == len(kinds)-1 {
				out += " y "
			} else {
				out += ", "
			}
		}
		out += fmt.Sprintf("%s (%d)", sourceLabel(k), counts[k])
	}
	return out
}

func sourceLabel(k correlation.SourceKind) string {
	switch k {
	case correlation.SourceDiagnose:
		return "Diagnose"
	case correlation.SourcePCAP:
		return "PCAP"
	case correlation.SourceMonitor:
		return "Monitor"
	case correlation.SourceVoIP:
		return "VoIP"
	default:
		return string(k)
	}
}
