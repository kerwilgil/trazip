package api

import (
	"encoding/json"
	"fmt"
	"strings"

	"trazip/internal/correlation"
	"trazip/internal/diagnosis"
	"trazip/internal/investigation"
	"trazip/internal/monitor"
	"trazip/internal/report"
	"trazip/internal/voip"
)

// InvestigationAddResult wraps AddSnapshot's own (Entry, existing bool)
// pair into a single value: Wails' Go↔JS binding only supports a bound
// method returning at most (value, error) — a third return value (the
// existing bool) would silently fail to bind correctly.
type InvestigationAddResult struct {
	Entry    investigation.Entry `json:"entry"`
	Existing bool                `json:"existing"`
}

func addResult(entry investigation.Entry, existing bool, err error) (InvestigationAddResult, error) {
	if err != nil {
		return InvestigationAddResult{}, err
	}
	return InvestigationAddResult{Entry: entry, Existing: existing}, nil
}

// InvestigationCreate starts a new, empty case (Phase E).
func (s *Service) InvestigationCreate(name, objective string) (investigation.Investigation, error) {
	return s.investigations.Create(name, objective)
}

// InvestigationList summarizes every case on disk, most recently updated
// first, plus warnings for any file that exists but couldn't be included.
func (s *Service) InvestigationList() investigation.ListResult {
	return s.investigations.List()
}

// InvestigationGet returns one full case, including every Entry.
func (s *Service) InvestigationGet(id string) (investigation.Investigation, error) {
	return s.investigations.Get(id)
}

// InvestigationUpdateMetadata renames a case or changes its objective.
// Entries are untouched.
func (s *Service) InvestigationUpdateMetadata(id, name, objective string) (investigation.Investigation, error) {
	return s.investigations.UpdateMetadata(id, name, objective)
}

// InvestigationDelete removes a case entirely — never the original
// Diagnose/PCAP/Monitor/VoIP results any of its Entries referenced.
func (s *Service) InvestigationDelete(id string) error {
	return s.investigations.Delete(id)
}

// InvestigationRemoveEntry deletes one Entry from a case.
func (s *Service) InvestigationRemoveEntry(investigationID, entryID string) error {
	return s.investigations.RemoveEntry(investigationID, entryID)
}

// InvestigationUpdateEntryNote sets the operator's own note on one Entry —
// never the Snapshot's own Conclusion/Level/Confidence/Evidence.
func (s *Service) InvestigationUpdateEntryNote(investigationID, entryID, note string) (investigation.Entry, error) {
	return s.investigations.UpdateEntryNote(investigationID, entryID, note)
}

// InvestigationReport builds a módulo-26 Report from a full case, ready for
// the GUI to export as JSON/CSV/HTML/PDF.
func (s *Service) InvestigationReport(id string) (report.Report, error) {
	inv, err := s.investigations.Get(id)
	if err != nil {
		return report.Report{}, err
	}
	return investigation.ToReport(inv, Version), nil
}

// ---- Añadir resultados existentes (Phase E: nunca re-ejecuta nada) ----

// InvestigationAddDiagnose persists an already-completed DiagnosticReport's
// Snapshot into a case — it never runs Diagnose again. reportJSON is the
// exact JSON the frontend already holds from the diagnose:done event,
// transported as a string rather than a bound DiagnosticReport parameter:
// DiagnosticReport deliberately never appears in a bound Service method
// signature (Phase B.1 fix #6 removed Service.DiagnoseTarget to close a
// Wails authorization bypass), so it has no generated TS binding and stays
// hand-maintained in frontend/src/lib/api.ts — a second, colliding
// generated type here would break that. This method itself is not an
// authorization concern either way: it only stores a finished result, it
// never triggers a diagnosis.
func (s *Service) InvestigationAddDiagnose(investigationID, reportJSON string) (InvestigationAddResult, error) {
	var rep diagnosis.DiagnosticReport
	if err := json.Unmarshal([]byte(reportJSON), &rep); err != nil {
		return InvestigationAddResult{}, fmt.Errorf("reporte de diagnóstico inválido: %w", err)
	}
	if rep.CompletedAt == "" {
		return InvestigationAddResult{}, fmt.Errorf("el diagnóstico todavía no está completo")
	}
	// Fail-closed persistence guard (V1 hardening finding #1): the current
	// DiagnoseTarget already rejects URL userinfo before ever producing a
	// report, but this boundary must not trust that invariant blindly — a
	// legacy report persisted before that fix, or one a different/forged
	// caller constructed by hand, could still carry credentials in Target.
	// Reject it here too, before AddSnapshot ever touches disk.
	if diagnosis.HasURLUserinfo(rep.Target) {
		return InvestigationAddResult{}, fmt.Errorf("el diagnóstico no se puede guardar: el target contiene credenciales embebidas en una URL")
	}
	return addResult(s.investigations.AddSnapshot(investigationID, diagnosis.ToSnapshot(rep)))
}

// InvestigationAddPcap persists a PCAP incident summary — it never calls
// AnalyzePcap again. subject is defensively reduced to its base filename
// even if the caller passed a full path: a case file must never carry a
// local filesystem path (Phase E: "NO almacenar path completo"). sourceID
// is a different case: it's an opaque identifier (a capture session ID),
// not a display filename, so it's never silently rewritten — a value that
// looks like a filesystem path is rejected outright instead, so the same
// "no local paths persisted" guarantee holds even if a future caller
// passes one here by mistake. Rejection happens before AddSnapshot is
// called, so no investigation file is ever touched.
func (s *Service) InvestigationAddPcap(investigationID string, summary correlation.PcapIncidentSummary, subject, sourceID, occurredAt string) (InvestigationAddResult, error) {
	if subject != "" {
		subject = basenameAnySeparator(subject)
	}
	if looksLikeLocalPath(sourceID) {
		return InvestigationAddResult{}, fmt.Errorf("sourceID no debe ser una ruta de archivo local")
	}
	return addResult(s.investigations.AddSnapshot(investigationID, summary.ToSnapshot(subject, sourceID, occurredAt)))
}

// basenameAnySeparator returns subject's last path component, splitting on
// both "\" and "/" regardless of the host OS (E.1-9) — path/filepath.Base
// only recognizes the separator(s) the CURRENT runtime GOOS uses (just "/"
// on POSIX, both on Windows), so a POSIX-style path handed to a POSIX
// build of TRAZIP would strip correctly, but the same guarantee shouldn't
// depend on which OS happens to be running: the privacy contract here is
// "never persist a parent directory", not "never persist one in whatever
// separator convention this binary's OS prefers". A subject with no
// separator at all (already just a filename) passes through unchanged.
// `/\` is a two-character raw string (one slash, one real backslash) —
// LastIndexAny finds whichever separator appears last, so a mixed-
// separator or UNC path ("\\server\share\capture.pcap") strips correctly
// too.
func basenameAnySeparator(subject string) string {
	if i := strings.LastIndexAny(subject, `/\`); i >= 0 {
		return subject[i+1:]
	}
	return subject
}

// looksLikeLocalPath is InvestigationAddPcap's fail-closed guard for
// sourceID: unlike subject (which is always reduced to a basename),
// sourceID is an opaque caller-supplied identifier this package has no
// business reinterpreting — so a value that looks like a filesystem path
// is rejected outright rather than silently stripped or passed through,
// keeping the "never persist a local path" guarantee even if a future
// caller passes one here by mistake.
func looksLikeLocalPath(s string) bool {
	if strings.ContainsAny(s, `/\`) {
		return true
	}
	// A bare drive-letter prefix ("C:...") with no separator yet is still
	// path-shaped enough to reject on sight.
	if len(s) >= 2 && s[1] == ':' && isASCIILetter(s[0]) {
		return true
	}
	return false
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// InvestigationAddMonitorEvent persists a route_change DegradationEvent —
// it never restarts monitoring. Rejects any other event Kind rather than
// fabricating a route-change snapshot from one that isn't (Phase E MVP
// scope: RouteChange only, per monitor.ToSnapshot's own contract).
func (s *Service) InvestigationAddMonitorEvent(investigationID string, event monitor.DegradationEvent) (InvestigationAddResult, error) {
	snap, ok := monitor.ToSnapshot(event)
	if !ok {
		return InvestigationAddResult{}, fmt.Errorf("este evento no es un cambio de ruta con datos suficientes para agregarlo a una investigación")
	}
	return addResult(s.investigations.AddSnapshot(investigationID, snap))
}

// InvestigationAddVoIPCall persists a VoIP call's existing Diagnosis — it
// never recomputes one. Rejects a call with no Diagnosis yet rather than
// fabricating one (Phase E: "Si no tiene Diagnosis: acción deshabilitada").
func (s *Service) InvestigationAddVoIPCall(investigationID string, call voip.Call) (InvestigationAddResult, error) {
	snap, ok := voip.ToSnapshot(&call)
	if !ok {
		return InvestigationAddResult{}, fmt.Errorf("esta llamada todavía no tiene un diagnóstico para agregar")
	}
	return addResult(s.investigations.AddSnapshot(investigationID, snap))
}
