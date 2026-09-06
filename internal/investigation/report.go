package investigation

import (
	"fmt"
	"sort"
	"time"

	"trazip/internal/correlation"
	"trazip/internal/model"
	"trazip/internal/report"
)

// ToReport builds a módulo-26 Report from a full Investigation — the
// module-25/investigation→26 bridge, exactly like monitor.ToReport and
// every other TRAZIP module's own report builder: report.Report itself
// stays domain-agnostic, this file is where the wording lives, and it
// never invents anything an Entry's own Snapshot didn't already say (Phase
// E: "No usar AI. No inventar executive summary. Debe ser
// determinístico.").
func ToReport(inv Investigation, trazipVersion string) report.Report {
	sum := Summarize(inv)
	timeline := Timeline(inv)

	r := report.New("TRAZIP Investigation Report — "+inv.Name, trazipVersion)
	r.Meta.Config = map[string]string{
		"investigationSchemaVersion": fmt.Sprintf("%d", inv.SchemaVersion),
		"entryCount":                 fmt.Sprintf("%d", sum.EntryCount),
	}
	r.Summary = mainFindingSentence(sum)

	r.Sections = append(r.Sections, executiveSummarySection(inv, sum))
	r.Sections = append(r.Sections, timelineSection(timeline))
	r.Sections = append(r.Sections, evidenceSections(timeline)...)
	if notes := operatorNotesSection(timeline); notes != nil {
		r.Sections = append(r.Sections, *notes)
	}
	r.Sections = append(r.Sections, report.Section{
		Title: "Limitaciones de la investigación",
		Notes: []string{
			"Esta investigación agrupa resultados seleccionados por el operador. La proximidad temporal entre hallazgos no demuestra causalidad.",
		},
	})

	return r
}

func executiveSummarySection(inv Investigation, sum Summary) report.Section {
	kvs := []report.KeyValue{{Key: "Nombre", Value: inv.Name}}
	if inv.Objective != "" {
		kvs = append(kvs, report.KeyValue{Key: "Objetivo", Value: inv.Objective})
	}
	kvs = append(kvs,
		report.KeyValue{Key: "Cantidad de evidencias", Value: fmt.Sprintf("%d", sum.EntryCount)},
		report.KeyValue{Key: "Módulos incluidos", Value: orDash(moduleListText(sum.SourceCounts))},
		report.KeyValue{Key: "Hallazgo de mayor severidad", Value: orDash(sum.MainFinding)},
		report.KeyValue{Key: "Creada", Value: inv.CreatedAt},
		report.KeyValue{Key: "Actualizada", Value: inv.UpdatedAt},
	)
	return report.Section{Title: "Resumen ejecutivo", KeyValues: kvs}
}

func timelineSection(timeline []Entry) report.Section {
	rows := make([][]string, len(timeline))
	for i, e := range timeline {
		rows[i] = []string{
			entryTime(e), sourceLabel(e.Snapshot.Kind), orDash(e.Snapshot.Subject),
			string(e.Snapshot.Assessment.Level), fmt.Sprintf("%d", e.Snapshot.Assessment.Confidence),
			e.Snapshot.Assessment.Conclusion,
		}
	}
	return report.Section{
		Title: "Timeline",
		Tables: []report.Table{{
			Title:   "Cronología",
			Columns: []string{"Fecha/Hora", "Módulo", "Subject", "Nivel", "Confianza", "Conclusión"},
			Rows:    rows,
		}},
	}
}

func evidenceSections(timeline []Entry) []report.Section {
	out := make([]report.Section, 0, len(timeline))
	for i, e := range timeline {
		sec := report.Section{
			Title:   fmt.Sprintf("%d. %s — %s", i+1, sourceLabel(e.Snapshot.Kind), orDash(e.Snapshot.Subject)),
			Summary: e.Snapshot.Assessment.Conclusion,
			KeyValues: []report.KeyValue{
				{Key: "Nivel", Value: string(e.Snapshot.Assessment.Level)},
				{Key: "Confianza", Value: fmt.Sprintf("%d", e.Snapshot.Assessment.Confidence)},
				{Key: "Momento", Value: entryTime(e)},
			},
		}
		if len(e.Snapshot.Assessment.Evidence) > 0 {
			sec.Tables = append(sec.Tables, evidenceTable("Evidencia", e.Snapshot.Assessment.Evidence))
		}
		if len(e.Snapshot.Assessment.CounterEvid) > 0 {
			sec.Tables = append(sec.Tables, evidenceTable("Contraevidencia", e.Snapshot.Assessment.CounterEvid))
		}
		sec.Notes = e.Snapshot.Assessment.Limitations
		out = append(out, sec)
	}
	return out
}

func evidenceTable(title string, evs []model.Evidence) report.Table {
	rows := make([][]string, len(evs))
	for i, e := range evs {
		ts := ""
		if !e.Timestamp.IsZero() {
			ts = e.Timestamp.UTC().Format(time.RFC3339)
		}
		rows[i] = []string{e.Type, e.Value, e.Source, string(e.Provenance), fmt.Sprintf("%d", e.Confidence), e.Explain, ts}
	}
	return report.Table{
		Title:   title,
		Columns: []string{"Type", "Value", "Source", "Provenance", "Confidence", "Explain", "Timestamp"},
		Rows:    rows,
	}
}

// operatorNotesSection returns nil when no Entry carries an operator note
// — an empty "Notas del operador" section would just be noise.
func operatorNotesSection(timeline []Entry) *report.Section {
	var rows [][]string
	for i, e := range timeline {
		if e.Note == "" {
			continue
		}
		rows = append(rows, []string{fmt.Sprintf("%d. %s — %s", i+1, sourceLabel(e.Snapshot.Kind), orDash(e.Snapshot.Subject)), e.Note})
	}
	if len(rows) == 0 {
		return nil
	}
	return &report.Section{
		Title:  "Notas del operador",
		Tables: []report.Table{{Title: "Notas", Columns: []string{"Evidencia", "Nota"}, Rows: rows}},
	}
}

func moduleListText(counts map[correlation.SourceKind]int) string {
	if len(counts) == 0 {
		return ""
	}
	kinds := make([]correlation.SourceKind, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	out := ""
	for i, k := range kinds {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s (%d)", sourceLabel(k), counts[k])
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
