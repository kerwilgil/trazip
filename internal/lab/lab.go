// Package lab implements TRAZIP's laboratory mode (prompt maestro §9 Fase 5,
// módulo 27): synthetic example captures with no personal data, reproducible
// scenarios with stated objectives, controlled replay through TRAZIP's own
// analysis engines, expected-vs-actual comparison, and evidence export for
// courses (via internal/report — the same exporter every other module
// uses, so a lab result looks like any other TRAZIP report).
//
// "Replay" here means what a passive, non-offensive tool can safely mean:
// a scenario's PCAP is generated once (deterministically — fixed
// timestamps/addresses, so the same scenario always produces byte-identical
// input) and can be re-opened and re-analyzed any number of times through
// the normal PCAP/VoIP pipelines. TRAZIP never replays packets onto a real
// wire (that would be packet injection, outside prompt maestro §3's scope).
package lab

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"trazip/internal/report"
	"trazip/internal/voip"
)

// Objective is one guided question a student should be able to answer using
// only TRAZIP's own tools against the scenario's capture.
type Objective struct {
	Question string `json:"question"`
	Hint     string `json:"hint,omitempty"`
}

// Scenario is one reproducible lab exercise.
type Scenario struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Technique   string      `json:"technique,omitempty"`
	Signal      string      `json:"signal,omitempty"`
	Objectives  []Objective `json:"objectives"`
	Expected    []Fact      `json:"expected"`

	generate func() ([]byte, error)
	analyze  func(ctx context.Context, pcapPath string) ([]Fact, error)
}

// Fact is one comparable, named finding — expected or actual. Value is
// always the string form so expected/actual can be compared without the
// registry needing per-scenario typed structs.
type Fact struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Value string `json:"value"`
}

// RunResult is the outcome of replaying one scenario and comparing findings.
type RunResult struct {
	ScenarioID string          `json:"scenarioId"`
	PcapPath   string          `json:"pcapPath"`
	RanAt      string          `json:"ranAt"` // RFC3339
	Expected   []Fact          `json:"expected"`
	Actual     []Fact          `json:"actual"`
	Matches    map[string]bool `json:"matches"` // keyed by Fact.Key
	AllMatch   bool            `json:"allMatch"`
	Passed     int             `json:"passed"`
	Total      int             `json:"total"`
	Score      int             `json:"score"`
	Status     string          `json:"status"`
	Err        string          `json:"err,omitempty"`
}

var registry = buildRegistry()

// List returns every available scenario (without regenerating any PCAP).
func List() []Scenario { return registry }

// Get looks up one scenario by ID.
func Get(id string) (Scenario, bool) {
	for _, s := range registry {
		if s.ID == id {
			return s, true
		}
	}
	return Scenario{}, false
}

// WritePCAP generates the scenario's synthetic capture and writes it to
// destDir (created if needed), returning the full path. Generation is
// deterministic, so calling this repeatedly for the same scenario always
// produces byte-identical output — the actual "reproducible" part of
// módulo 27's "escenarios reproducibles."
func (s Scenario) WritePCAP(destDir string) (string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	data, err := s.generate()
	if err != nil {
		return "", fmt.Errorf("generando captura de escenario %q: %w", s.ID, err)
	}
	path := filepath.Join(destDir, s.ID+".pcap")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// Run writes (or reuses, if pcapPath already exists and non-empty) the
// scenario's capture, analyzes it through TRAZIP's real engines, and
// compares the findings against Expected.
func (s Scenario) Run(ctx context.Context, destDir string) (RunResult, error) {
	res := RunResult{ScenarioID: s.ID, RanAt: time.Now().Format(time.RFC3339), Expected: s.Expected}

	path, err := s.WritePCAP(destDir)
	if err != nil {
		res.Err = err.Error()
		return res, err
	}
	res.PcapPath = path

	actual, err := s.analyze(ctx, path)
	if err != nil {
		res.Err = err.Error()
		return res, nil // the capture itself is still usable; report the analysis error, don't fail Run
	}
	res.Actual = actual

	res.Matches = make(map[string]bool, len(s.Expected))
	allMatch := true
	actualByKey := make(map[string]string, len(actual))
	for _, f := range actual {
		actualByKey[f.Key] = f.Value
	}
	for _, exp := range s.Expected {
		got, ok := actualByKey[exp.Key]
		match := ok && got == exp.Value
		res.Matches[exp.Key] = match
		if !match {
			allMatch = false
		} else {
			res.Passed++
		}
	}
	res.AllMatch = allMatch
	res.Total = len(s.Expected)
	if res.Total > 0 {
		res.Score = res.Passed * 100 / res.Total
	}
	res.Status = "fail"
	if res.AllMatch {
		res.Status = "pass"
	} else if res.Passed > 0 {
		res.Status = "partial"
	}
	return res, nil
}

// ToReport builds a módulo-26 Report from a lab run — "exportación de
// evidencia para cursos."
func ToReport(s Scenario, res RunResult, trazipVersion string) report.Report {
	r := report.New("Laboratorio TRAZIP — "+s.Title, trazipVersion)
	r.Meta.Config = map[string]string{"scenario": s.ID, "pcap": res.PcapPath}
	r.Summary = s.Description
	if res.Err != "" {
		r.Summary += " ADVERTENCIA: la corrida tuvo un error de análisis — ver la sección de resultados."
	} else if res.AllMatch {
		r.Summary += fmt.Sprintf(" Resultado: los %d hallazgo(s) coinciden con lo esperado.", len(res.Expected))
	} else {
		r.Summary += " Resultado: uno o más hallazgos NO coinciden con lo esperado — revisar la tabla de comparación."
	}

	objRows := make([][]string, len(s.Objectives))
	for i, o := range s.Objectives {
		objRows[i] = []string{o.Question, o.Hint}
	}
	sections := []report.Section{{
		Title:     "Objetivos",
		KeyValues: []report.KeyValue{{Key: "Técnica", Value: s.Technique}, {Key: "Señal esperada", Value: s.Signal}, {Key: "Score", Value: fmt.Sprintf("%d%% (%d/%d)", res.Score, res.Passed, res.Total)}},
		Tables:    []report.Table{{Title: "Preguntas guía", Columns: []string{"Pregunta", "Pista"}, Rows: objRows}},
	}}

	if res.Err != "" {
		sections = append(sections, report.Section{Title: "Error de análisis", Notes: []string{res.Err}})
	} else {
		actualByKey := make(map[string]Fact, len(res.Actual))
		for _, f := range res.Actual {
			actualByKey[f.Key] = f
		}
		rows := make([][]string, len(res.Expected))
		for i, exp := range res.Expected {
			got := "(no encontrado)"
			if a, ok := actualByKey[exp.Key]; ok {
				got = a.Value
			}
			status := "❌"
			if res.Matches[exp.Key] {
				status = "✅"
			}
			rows[i] = []string{exp.Label, exp.Value, got, status}
		}
		sections = append(sections, report.Section{
			Title:  "Comparación esperado vs. obtenido",
			Tables: []report.Table{{Title: "Hallazgos", Columns: []string{"Hallazgo", "Esperado", "Obtenido", "¿Coincide?"}, Rows: rows}},
			Notes:  []string{"Generado sobre una captura sintética reproducible — sin datos personales, apta para distribuir en un curso."},
		})
	}

	r.Sections = sections
	return r
}

func buildRegistry() []Scenario {
	return []Scenario{
		voipLossScenario(),
		flowBasicsScenario(),
		scanDetectionScenario(),
	}
}

// fact is a tiny constructor to keep the scenario definitions below readable.
func fact(key, label, value string) Fact { return Fact{Key: key, Label: label, Value: value} }

func factsFromVoIP(res voip.Result) []Fact {
	facts := []Fact{
		fact("total_calls", "Llamadas totales", itoa(res.TotalCalls)),
		fact("established_calls", "Llamadas establecidas", itoa(res.Established)),
		fact("failed_calls", "Llamadas fallidas", itoa(res.Failed)),
	}
	if len(res.Calls) > 0 {
		call := res.Calls[0]
		facts = append(facts, fact("call_established", "Primera llamada establecida", boolStr(call.Established)))
		lossyStreams := 0
		for _, s := range call.Streams {
			if s.Stats.Lost > 0 {
				lossyStreams++
			}
		}
		facts = append(facts, fact("streams_with_loss", "Streams RTP con pérdida", itoa(lossyStreams)))
	}
	return facts
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
