package investigation

import (
	"strings"
	"testing"

	"trazip/internal/correlation"
	"trazip/internal/model"
)

func entryWithKind(kind correlation.SourceKind, occurredAt, conclusion string) Entry {
	return Entry{
		ID: "e-" + string(kind), AddedAt: occurredAt,
		Snapshot: correlation.Snapshot{
			SchemaVersion: correlation.SnapshotSchemaVersion, Kind: kind,
			Subject: "subject-" + string(kind), OccurredAt: occurredAt,
			Assessment: model.Assessment{Conclusion: conclusion, Level: model.LevelMedium, Confidence: 70},
		},
	}
}

func testInvestigation() Investigation {
	return Investigation{
		SchemaVersion: SchemaVersion, ID: "inv-1", Name: "Caso de prueba", Objective: "objetivo",
		CreatedAt: "2026-01-01T08:00:00Z", UpdatedAt: "2026-01-01T12:00:00Z",
		Entries: []Entry{
			entryWithKind(correlation.SourceDiagnose, "2026-01-01T11:00:00Z", "diagnose ok"),
			entryWithKind(correlation.SourcePCAP, "2026-01-01T09:00:00Z", "pcap finding"),
			entryWithKind(correlation.SourceMonitor, "2026-01-01T10:00:00Z", "ruta cambió"),
			entryWithKind(correlation.SourceVoIP, "2026-01-01T12:00:00Z", "603 decline"),
		},
	}
}

// 1. All four SourceKind must render.
func TestToReportAllSourceKinds(t *testing.T) {
	r := ToReport(testInvestigation(), "0.7.4")
	html := string(r.ToHTML())
	for _, want := range []string{"diagnose ok", "pcap finding", "ruta cambió", "603 decline"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing entry conclusion %q", want)
		}
	}
}

// 2. Timeline ordering: earliest OccurredAt first.
func TestToReportTimelineOrdering(t *testing.T) {
	r := ToReport(testInvestigation(), "0.7.4")
	for _, sec := range r.Sections {
		if sec.Title != "Timeline" {
			continue
		}
		rows := sec.Tables[0].Rows
		if len(rows) != 4 {
			t.Fatalf("expected 4 timeline rows, got %d", len(rows))
		}
		// pcap (09:00) < monitor (10:00) < diagnose (11:00) < voip (12:00)
		if rows[0][5] != "pcap finding" || rows[3][5] != "603 decline" {
			t.Errorf("timeline not ordered by OccurredAt: %+v", rows)
		}
		return
	}
	t.Fatal("Timeline section not found")
}

// 3. Evidence preserved.
func TestToReportEvidencePreserved(t *testing.T) {
	inv := Investigation{
		ID: "i", Name: "n",
		Entries: []Entry{{
			ID: "e", AddedAt: "2026-01-01T10:00:00Z",
			Snapshot: correlation.Snapshot{
				Kind: correlation.SourceDiagnose,
				Assessment: model.Assessment{
					Conclusion: "c", Level: model.LevelHigh, Confidence: 90,
					Evidence: []model.Evidence{{Type: "dns", Value: "1.2.3.4", Source: "resolution", Provenance: model.ProvObserved, Confidence: 90, Explain: "explicación"}},
				},
			},
		}},
	}
	html := string(ToReport(inv, "0.7.4").ToHTML())
	for _, want := range []string{"dns", "1.2.3.4", "resolution", "explicación"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing evidence field %q", want)
		}
	}
}

// 4. CounterEvidence preserved.
func TestToReportCounterEvidencePreserved(t *testing.T) {
	inv := Investigation{
		ID: "i", Name: "n",
		Entries: []Entry{{
			ID: "e", AddedAt: "2026-01-01T10:00:00Z",
			Snapshot: correlation.Snapshot{
				Kind: correlation.SourceDiagnose,
				Assessment: model.Assessment{
					Conclusion: "c", Level: model.LevelHigh, Confidence: 90,
					CounterEvid: []model.Evidence{{Type: "counter-type", Value: "counter-value", Source: "s", Provenance: model.ProvInferred, Confidence: 40}},
				},
			},
		}},
	}
	html := string(ToReport(inv, "0.7.4").ToHTML())
	if !strings.Contains(html, "Contraevidencia") || !strings.Contains(html, "counter-value") {
		t.Errorf("HTML missing CounterEvidence: %s", html)
	}
}

// 5. Limitations preserved.
func TestToReportLimitationsPreserved(t *testing.T) {
	inv := Investigation{
		ID: "i", Name: "n",
		Entries: []Entry{{
			ID: "e", AddedAt: "2026-01-01T10:00:00Z",
			Snapshot: correlation.Snapshot{
				Kind: correlation.SourceMonitor,
				Assessment: model.Assessment{
					Conclusion: "c", Level: model.LevelLow, Confidence: 70,
					Limitations: []string{"la coincidencia temporal no demuestra causalidad"},
				},
			},
		}},
	}
	html := string(ToReport(inv, "0.7.4").ToHTML())
	if !strings.Contains(html, "la coincidencia temporal no demuestra causalidad") {
		t.Error("HTML missing entry Limitations")
	}
}

// 6. Mandatory no-causality note must always be present, even for an
// investigation with a single entry.
func TestToReportMandatoryCausalityNote(t *testing.T) {
	r := ToReport(testInvestigation(), "0.7.4")
	found := false
	for _, sec := range r.Sections {
		if sec.Title != "Limitaciones de la investigación" {
			continue
		}
		for _, n := range sec.Notes {
			if strings.Contains(n, "no demuestra causalidad") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected the mandatory 'no demuestra causalidad' note in every investigation report")
	}
	for _, forbidden := range []string{"causa raíz", "diagnóstico definitivo", "root cause"} {
		full := r.Summary
		for _, sec := range r.Sections {
			full += sec.Summary
		}
		if strings.Contains(strings.ToLower(full), forbidden) {
			t.Errorf("report must never use %q", forbidden)
		}
	}
}

// 7. HTML escaping of an attacker-controlled field.
func TestToReportHTMLEscaping(t *testing.T) {
	inv := Investigation{
		ID: "i", Name: "<script>alert(1)</script>",
		Entries: []Entry{{
			ID: "e", AddedAt: "2026-01-01T10:00:00Z",
			Snapshot: correlation.Snapshot{
				Kind: correlation.SourceDiagnose,
				Assessment: model.Assessment{Conclusion: "<img src=x onerror=alert(2)>", Level: model.LevelInfo, Confidence: 50},
			},
		}},
	}
	html := string(ToReport(inv, "0.7.4").ToHTML())
	if strings.Contains(html, "<script>") || strings.Contains(html, "<img src=x") {
		t.Errorf("HTML output not escaped — a live tag survived: %s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") || !strings.Contains(html, "&lt;img src=x") {
		t.Error("expected the escaped form of the malicious fields to appear as inert text")
	}
}

// 8. CSV formula-injection neutralization (report package's own existing
// safety — this just confirms the investigation report actually goes
// through ToCSV, not a bespoke unsafe path).
func TestToReportCSVFormulaSafety(t *testing.T) {
	inv := Investigation{
		ID: "i", Name: "n",
		Entries: []Entry{{
			ID: "e", AddedAt: "2026-01-01T10:00:00Z",
			Snapshot: correlation.Snapshot{
				Kind:       correlation.SourceDiagnose,
				Subject:    "=cmd|'/c calc'!A1",
				Assessment: model.Assessment{Conclusion: "c", Level: model.LevelInfo, Confidence: 50},
			},
		}},
	}
	csv := string(ToReport(inv, "0.7.4").ToCSV())
	if strings.Contains(csv, "\n=cmd") || strings.Contains(csv, ",=cmd") {
		t.Errorf("a raw formula-shaped cell leaked into CSV unneutralized: %s", csv)
	}
}

// 9. Empty investigation must still export cleanly.
func TestToReportEmptyInvestigation(t *testing.T) {
	inv := Investigation{ID: "i", Name: "vacía", CreatedAt: "2026-01-01T08:00:00Z", UpdatedAt: "2026-01-01T08:00:00Z"}
	r := ToReport(inv, "0.7.4")
	if _, err := r.ToJSON(); err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if len(r.ToHTML()) == 0 || len(r.ToCSV()) == 0 || len(r.ToPDF()) == 0 {
		t.Error("expected non-empty output in every format for an empty investigation")
	}
	if !strings.Contains(r.Summary, "todavía no tiene evidencias") {
		t.Errorf("Summary = %q, want an honest empty-case message", r.Summary)
	}
}

// 10. Optional operator notes: present when set, absent (no empty section)
// when not.
func TestToReportOptionalNotes(t *testing.T) {
	withNote := testInvestigation()
	withNote.Entries[0].Note = "seguimiento pendiente"
	r := ToReport(withNote, "0.7.4")
	hasNotesSection := false
	for _, sec := range r.Sections {
		if sec.Title == "Notas del operador" {
			hasNotesSection = true
			if !strings.Contains(sec.Tables[0].Rows[0][1], "seguimiento pendiente") {
				t.Error("operator note text not present in the Notas del operador table")
			}
		}
	}
	if !hasNotesSection {
		t.Fatal("expected a Notas del operador section when an entry has a Note")
	}

	withoutNotes := testInvestigation()
	r2 := ToReport(withoutNotes, "0.7.4")
	for _, sec := range r2.Sections {
		if sec.Title == "Notas del operador" {
			t.Error("did not expect a Notas del operador section when no entry has a Note")
		}
	}
}
