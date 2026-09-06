package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trazip/internal/correlation"
	"trazip/internal/diagnosis"
	"trazip/internal/investigation"
	"trazip/internal/lab"
	"trazip/internal/model"
	"trazip/internal/monitor"
	"trazip/internal/voip"
)

// selfTestTimeout bounds the whole local self test — every check here is
// local/offline/deterministic, so this is generous headroom against a
// hung engine, never a budget the happy path is expected to approach.
const selfTestTimeout = 30 * time.Second

// SelfTestStatus is one SelfTestCheck's own outcome (TRAZIP V1 MASTER
// IMPLEMENTATION, "PHASE F.0 — DETERMINISTIC LOCAL SELF TEST CORE").
// UNAVAILABLE is deliberately distinct from FAIL: it means an optional local
// capability isn't present (e.g. no GeoIP dataset installed), never that
// TRAZIP itself is broken.
type SelfTestStatus string

const (
	SelfTestPass        SelfTestStatus = "pass"
	SelfTestFail        SelfTestStatus = "fail"
	SelfTestSkipped     SelfTestStatus = "skipped"
	SelfTestUnavailable SelfTestStatus = "unavailable"
)

// SelfTestCheck is one orchestrated step's result. Detail is always
// sanitized before it lands here — never a raw error string that might
// carry the self test's own temp workspace path (Phase F.0 §12 privacy
// invariants).
type SelfTestCheck struct {
	ID         string         `json:"id"`
	Label      string         `json:"label"`
	Status     SelfTestStatus `json:"status"`
	Detail     string         `json:"detail,omitempty"`
	DurationMs int64          `json:"durationMs"`
}

// SelfTestResult is runSelfTestLocal's full report. Mode is always "local"
// for F.0 — a future phase may add other modes without changing this shape.
type SelfTestResult struct {
	Mode          string          `json:"mode"`
	StartedAt     string          `json:"startedAt"`
	CompletedAt   string          `json:"completedAt"`
	OverallStatus SelfTestStatus  `json:"overallStatus"`
	Checks        []SelfTestCheck `json:"checks"`
	Passed        int             `json:"passed"`
	Failed        int             `json:"failed"`
	Skipped       int             `json:"skipped"`
	Unavailable   int             `json:"unavailable"`
	// NetworkOut is always false for this runner — every check it runs is
	// local/offline by construction (Phase F.0 §1).
	NetworkOut bool `json:"networkOut"`
}

// selfTestRunner carries state between the sequential checks below — a
// plain struct, not a registry or dependency graph (Phase F.0 §16: "NO
// plugin system. NO reflection registry. NO dependency graph."). Each check
// method decides for itself whether its own prerequisites are met (usually
// "did an earlier check populate this field") and returns SKIPPED if not.
type selfTestRunner struct {
	s   *Service
	ctx context.Context

	checks []SelfTestCheck

	// tempRoot is the self test's own, dedicated temporary workspace — never
	// paths.Sub(), never the real labDir()/investigations store (Phase F.0
	// §1/§3). Empty until checkCoreWorkspace succeeds.
	tempRoot string

	flowBasicsPcap string
	voipLossPcap   string

	diagnoseSnapshot correlation.Snapshot
	diagnoseOK       bool
	pcapSnapshot     correlation.Snapshot
	pcapOK           bool
	voipSnapshot     correlation.Snapshot
	voipOK           bool
	monitorSnapshot  correlation.Snapshot
	monitorOK        bool

	invMgr *investigation.Manager
	invID  string

	reportJSON, reportCSV, reportHTML, reportPDF []byte
}

// runSelfTestLocal is F.0's orchestrator: a small, sequential runner over
// capabilities TRAZIP already has, never a second implementation of any of
// them (Phase F.0 §16). Kept as a package-level function taking an explicit
// context — Service.SelfTestLocal below is its only real entry point today
// (Phase F.1), but staying decoupled from *Service's bound method set means
// a future cancellable/CLI caller could still reach it directly, the same
// reasoning RunDiagnose/RunVoIPAnalysis already apply.
func runSelfTestLocal(parentCtx context.Context, s *Service) SelfTestResult {
	ctx, cancel := context.WithTimeout(parentCtx, selfTestTimeout)
	defer cancel()

	r := &selfTestRunner{s: s, ctx: ctx, checks: make([]SelfTestCheck, 0, 13)}
	startedAt := time.Now().UTC()

	defer func() {
		if r.tempRoot != "" {
			_ = os.RemoveAll(r.tempRoot)
		}
	}()

	r.run("core.local", "Workspace temporal local", r.checkCoreWorkspace)
	r.run("diagnose.offline", "Diagnose 2.0 — plumbing offline", r.checkDiagnoseOffline)
	r.run("lab.flow-basics", "Fixture Lab: flow-basics", r.checkLabFlowBasics)
	r.run("lab.voip-rtp-loss", "Fixture Lab: voip-rtp-loss", r.checkLabVoIPLoss)
	r.run("lab.purple-scan-detection", "Fixture Lab: purple-scan-detection", r.checkLabScanDetection)
	r.run("pcap.analysis", "Análisis PCAP + resumen correlacionado", r.checkPcapAnalysis)
	r.run("voip.diagnosis", "Diagnóstico VoIP + adapter", r.checkVoIPDiagnosis)
	r.run("monitor.routechange", "Detector de cambio de ruta (Monitor)", r.checkMonitorRouteChange)
	r.run("correlation.adapters", "Contrato de adapters de correlación", r.checkCorrelationAdapters)
	r.run("investigation.persistence", "Persistencia de Investigation (disco temporal)", r.checkInvestigationPersistence)
	r.run("report.generation", "Generación de reportes (JSON/CSV/HTML/PDF)", r.checkReportGeneration)
	r.run("privacy.invariants", "Invariantes de privacidad", r.checkPrivacyInvariants)
	r.run("capability.geoip", "Capacidad local: datasets GeoIP", r.checkGeoIPCapability)

	result := SelfTestResult{
		Mode:        "local",
		StartedAt:   startedAt.Format(time.RFC3339),
		CompletedAt: time.Now().UTC().Format(time.RFC3339),
		Checks:      r.checks,
		NetworkOut:  false,
	}
	result.OverallStatus, result.Passed, result.Failed, result.Skipped, result.Unavailable = summarizeSelfTestChecks(r.checks)
	return result
}

// SelfTestLocal is the Wails-bound entry point for TRAZIP's Product Health
// Check (TRAZIP V1 MASTER IMPLEMENTATION, "PHASE F.1 — PRODUCT HEALTH CHECK
// UI"): it takes no parameters, accepts no path/input from the caller, and
// runs entirely local/offline/deterministic checks bounded by
// runSelfTestLocal's own internal timeout — no context.Context needs to
// cross the JS boundary, and no session/active-probe authorization gate
// applies, unlike RunDiagnose's Standard/Full modes. This is deliberately
// the ONLY thing this method does: reuse F.0's already-closed core exactly
// as built, never a second runner or a reinterpretation of its result.
func (s *Service) SelfTestLocal() SelfTestResult {
	return runSelfTestLocal(context.Background(), s)
}

// summarizeSelfTestChecks reduces every check's own Status into the
// counts and the single OverallStatus a caller actually needs (Phase F.0
// §2: "si existe >=1 FAIL: overallStatus = FAIL. SKIPPED o UNAVAILABLE por
// sí solos: NO convierten la aplicación completa en FAIL.").
func summarizeSelfTestChecks(checks []SelfTestCheck) (overall SelfTestStatus, passed, failed, skipped, unavailable int) {
	for _, c := range checks {
		switch c.Status {
		case SelfTestPass:
			passed++
		case SelfTestFail:
			failed++
		case SelfTestSkipped:
			skipped++
		case SelfTestUnavailable:
			unavailable++
		}
	}
	overall = SelfTestPass
	if failed > 0 {
		overall = SelfTestFail
	}
	return overall, passed, failed, skipped, unavailable
}

// run executes one check, isolating both its panics (a single engine
// misbehaving must never take down the whole self test or panic across the
// Wails boundary — Phase F.0 §2/§14) and its Detail text (sanitized against
// tempRoot before ever being stored — §12).
func (r *selfTestRunner) run(id, label string, fn func() (SelfTestStatus, string)) {
	start := time.Now()
	status := SelfTestFail
	detail := ""
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				status = SelfTestFail
				detail = fmt.Sprintf("panic recuperado: %v", rec)
			}
		}()
		status, detail = fn()
	}()
	r.checks = append(r.checks, SelfTestCheck{
		ID:         id,
		Label:      label,
		Status:     status,
		Detail:     r.sanitize(detail),
		DurationMs: time.Since(start).Milliseconds(),
	})
}

// sanitize strips this run's own tempRoot out of a Detail string before it
// ever becomes visible — defense in depth on top of every check already
// never naming tempRoot explicitly (Phase F.0 §12).
func (r *selfTestRunner) sanitize(s string) string {
	if r.tempRoot == "" || s == "" {
		return s
	}
	return strings.ReplaceAll(s, r.tempRoot, "<selftest-tmp>")
}

// ---- 3. core / temp workspace ---------------------------------------------

func (r *selfTestRunner) checkCoreWorkspace() (SelfTestStatus, string) {
	dir, err := os.MkdirTemp("", "trazip-selftest-*")
	if err != nil {
		return SelfTestFail, "no se pudo crear el workspace temporal: " + err.Error()
	}
	r.tempRoot = dir

	probe := filepath.Join(dir, "probe.txt")
	want := "trazip-selftest-probe"
	if err := os.WriteFile(probe, []byte(want), 0o600); err != nil {
		return SelfTestFail, "no se pudo escribir en el workspace temporal: " + err.Error()
	}
	got, err := os.ReadFile(probe)
	if err != nil {
		return SelfTestFail, "no se pudo leer del workspace temporal: " + err.Error()
	}
	if string(got) != want {
		return SelfTestFail, "el contenido leído del workspace temporal no coincide con lo escrito"
	}
	return SelfTestPass, "workspace temporal creado, escrito y leído correctamente"
}

// ---- 4. diagnose plumbing offline ------------------------------------------

func (r *selfTestRunner) checkDiagnoseOffline() (SelfTestStatus, string) {
	const target = "192.0.2.1" // RFC 5737 documentation address — direct IP, no DNS involved.
	rep, err := RunDiagnose(r.ctx, target, string(diagnosis.ModeOffline), r.s)
	if err != nil {
		return SelfTestFail, "RunDiagnose devolvió un error inesperado: " + err.Error()
	}
	if rep.Target != target {
		return SelfTestFail, fmt.Sprintf("Target = %q, se esperaba %q", rep.Target, target)
	}
	if rep.PrimaryAddress != target {
		return SelfTestFail, fmt.Sprintf("PrimaryAddress = %q, se esperaba %q", rep.PrimaryAddress, target)
	}
	if len(rep.Stages) == 0 {
		return SelfTestFail, "el reporte no contiene ningún stage"
	}
	if strings.TrimSpace(rep.Summary) == "" {
		return SelfTestFail, "el resumen del diagnóstico está vacío"
	}
	if rep.NetworkOut {
		return SelfTestFail, "NetworkOut=true en ModeOffline"
	}
	if len(rep.NetworkActions) != 0 {
		return SelfTestFail, "NetworkActions no está vacío en ModeOffline"
	}

	r.diagnoseSnapshot = diagnosis.ToSnapshot(rep)
	r.diagnoseOK = true
	return SelfTestPass, fmt.Sprintf("pipeline offline verificado: %d stage(s), sin tráfico de red", len(rep.Stages))
}

// ---- 5. existing lab fixtures ----------------------------------------------

func (r *selfTestRunner) runLabScenario(id string) (lab.RunResult, SelfTestStatus, string) {
	if r.tempRoot == "" {
		return lab.RunResult{}, SelfTestSkipped, "sin workspace temporal disponible"
	}
	sc, ok := lab.Get(id)
	if !ok {
		return lab.RunResult{}, SelfTestFail, fmt.Sprintf("escenario %q no está registrado", id)
	}
	// Deliberately NOT Service.LabRunScenario: that writes under the real
	// user labDir() (paths.Sub("lab")). The self test drives the scenario
	// directly against its own temp workspace instead (Phase F.0 §1).
	res, err := sc.Run(r.ctx, filepath.Join(r.tempRoot, "lab"))
	if err != nil {
		return res, SelfTestFail, "error ejecutando el escenario: " + err.Error()
	}
	if res.Err != "" {
		return res, SelfTestFail, "error de análisis del escenario: " + res.Err
	}
	if !res.AllMatch || res.Status != "pass" || res.Passed != res.Total {
		return res, SelfTestFail, fmt.Sprintf("hallazgos no coinciden con lo esperado (%d/%d)", res.Passed, res.Total)
	}
	return res, SelfTestPass, fmt.Sprintf("%d/%d hallazgos coinciden con lo esperado", res.Passed, res.Total)
}

func (r *selfTestRunner) checkLabFlowBasics() (SelfTestStatus, string) {
	res, status, detail := r.runLabScenario("flow-basics")
	if status == SelfTestPass {
		r.flowBasicsPcap = res.PcapPath
	}
	return status, detail
}

func (r *selfTestRunner) checkLabVoIPLoss() (SelfTestStatus, string) {
	res, status, detail := r.runLabScenario("voip-rtp-loss")
	if status == SelfTestPass {
		r.voipLossPcap = res.PcapPath
	}
	return status, detail
}

func (r *selfTestRunner) checkLabScanDetection() (SelfTestStatus, string) {
	_, status, detail := r.runLabScenario("purple-scan-detection")
	return status, detail
}

// ---- 6. PCAP analysis + correlated summary --------------------------------

func (r *selfTestRunner) checkPcapAnalysis() (SelfTestStatus, string) {
	if r.flowBasicsPcap == "" {
		return SelfTestSkipped, "sin PCAP de la fixture flow-basics disponible"
	}
	res, err := r.s.AnalyzePcap(r.flowBasicsPcap)
	if err != nil {
		return SelfTestFail, "AnalyzePcap devolvió un error: " + err.Error()
	}
	if res.TotalPackets <= 0 {
		return SelfTestFail, "TotalPackets <= 0"
	}
	if res.TotalFlows <= 0 {
		return SelfTestFail, "TotalFlows <= 0"
	}
	if strings.TrimSpace(res.Summary.Summary) == "" {
		return SelfTestFail, "Summary.Summary vacío"
	}
	if res.Summary.Stats.Packets != res.TotalPackets {
		return SelfTestFail, "Summary.Stats.Packets no coincide con TotalPackets"
	}
	if res.Summary.Stats.Flows != res.TotalFlows {
		return SelfTestFail, "Summary.Stats.Flows no coincide con TotalFlows"
	}

	occurredAt := time.Now().UTC().Format(time.RFC3339)
	snap := res.Summary.ToSnapshot("capture.pcap", "selftest-pcap", occurredAt)
	if snap.Kind != correlation.SourcePCAP {
		return SelfTestFail, "Snapshot.Kind != pcap"
	}
	if snap.SchemaVersion != correlation.SnapshotSchemaVersion {
		return SelfTestFail, "Snapshot.SchemaVersion inesperado"
	}
	if snap.Subject != "capture.pcap" {
		return SelfTestFail, "Snapshot.Subject inesperado"
	}
	if snap.SourceID != "selftest-pcap" {
		return SelfTestFail, "Snapshot.SourceID inesperado"
	}

	r.pcapSnapshot = snap
	r.pcapOK = true
	return SelfTestPass, fmt.Sprintf("%d paquete(s), %d flujo(s) analizados vía AnalyzePcap real", res.TotalPackets, res.TotalFlows)
}

// ---- 7. VoIP fixture + diagnosis -------------------------------------------

func (r *selfTestRunner) checkVoIPDiagnosis() (SelfTestStatus, string) {
	if r.voipLossPcap == "" {
		return SelfTestSkipped, "sin PCAP de la fixture voip-rtp-loss disponible"
	}
	res, err := RunVoIPAnalysis(r.ctx, r.voipLossPcap, r.s)
	if err != nil {
		return SelfTestFail, "RunVoIPAnalysis devolvió un error: " + err.Error()
	}
	if len(res.Calls) == 0 {
		return SelfTestFail, "no se detectó ninguna llamada"
	}

	call := &res.Calls[0]
	for i := range res.Calls {
		if res.Calls[i].CallID == "lab-voip-loss@192.168.50.10" {
			call = &res.Calls[i]
			break
		}
	}
	if call.Diagnosis == nil {
		return SelfTestFail, "la llamada seleccionada no tiene Diagnosis"
	}
	if strings.TrimSpace(call.Diagnosis.Conclusion) == "" {
		return SelfTestFail, "Diagnosis.Conclusion vacío"
	}

	snap, ok := voip.ToSnapshot(call)
	if !ok {
		return SelfTestFail, "voip.ToSnapshot devolvió ok=false para una llamada con Diagnosis"
	}
	if snap.Kind != correlation.SourceVoIP {
		return SelfTestFail, "Snapshot.Kind != voip"
	}
	if snap.SchemaVersion != correlation.SnapshotSchemaVersion {
		return SelfTestFail, "Snapshot.SchemaVersion inesperado"
	}
	if snap.SourceID != call.CallID {
		return SelfTestFail, "Snapshot.SourceID no corresponde al CallID de la llamada"
	}

	r.voipSnapshot = snap
	r.voipOK = true
	return SelfTestPass, fmt.Sprintf("llamada %q diagnosticada y adaptada a Snapshot", call.CallID)
}

// ---- 8. monitor route-change fixture ---------------------------------------

func (r *selfTestRunner) checkMonitorRouteChange() (SelfTestStatus, string) {
	res := monitor.RunDeterministicRouteChangeSelfTest()
	if res.TransientConfirmed {
		return SelfTestFail, "una divergencia transitoria seguida de reversión confirmó un cambio de ruta"
	}
	if res.PersistentChangeCount != 1 || res.PersistentChange == nil {
		return SelfTestFail, fmt.Sprintf("se esperaba exactamente 1 cambio confirmado, se obtuvieron %d", res.PersistentChangeCount)
	}
	rc := res.PersistentChange
	if rc.FirstChangedTTL != 2 {
		return SelfTestFail, fmt.Sprintf("FirstChangedTTL = %d, se esperaba 2", rc.FirstChangedTTL)
	}
	if !rc.Persistent {
		return SelfTestFail, "Persistent == false en un cambio ya confirmado"
	}

	event := monitor.DegradationEvent{
		Time: rc.DetectedAt, Kind: "route_change",
		Detail: "cambio de ruta confirmado (self test)", RouteChange: rc,
	}
	snap, ok := monitor.ToSnapshot(event)
	if !ok {
		return SelfTestFail, "monitor.ToSnapshot devolvió ok=false para un evento route_change válido"
	}
	if snap.Kind != correlation.SourceMonitor {
		return SelfTestFail, "Snapshot.Kind != monitor"
	}
	if snap.SchemaVersion != correlation.SnapshotSchemaVersion {
		return SelfTestFail, "Snapshot.SchemaVersion inesperado"
	}
	if snap.Assessment.Level != model.LevelInfo {
		return SelfTestFail, "el nivel escaló sin degradación coincidente"
	}

	r.monitorSnapshot = snap
	r.monitorOK = true
	return SelfTestPass, "detector real verificado: transitorio no confirma, persistente confirma exactamente 1 (TTL 2)"
}

// ---- 9. all correlation adapters -------------------------------------------

// checkCorrelationAdapters depends on ALL FOUR upstream checks (Diagnose,
// PCAP, Monitor, VoIP) — a partial set is not a smaller version of this
// check, it's a dependency that didn't complete (Phase F.0 §2: "Si un check
// depende de otro que falló: SKIPPED."). Missing even one upstream Snapshot
// therefore SKIPs the whole check rather than silently validating whichever
// subset happened to be available and calling that a PASS.
func (r *selfTestRunner) checkCorrelationAdapters() (SelfTestStatus, string) {
	entries := []struct {
		ok   bool
		kind correlation.SourceKind
		snap correlation.Snapshot
	}{
		{r.diagnoseOK, correlation.SourceDiagnose, r.diagnoseSnapshot},
		{r.pcapOK, correlation.SourcePCAP, r.pcapSnapshot},
		{r.monitorOK, correlation.SourceMonitor, r.monitorSnapshot},
		{r.voipOK, correlation.SourceVoIP, r.voipSnapshot},
	}

	for _, e := range entries {
		if !e.ok {
			return SelfTestSkipped, fmt.Sprintf("adapter %s no disponible porque su check previo no produjo un Snapshot", e.kind)
		}
	}

	for _, e := range entries {
		if e.snap.SchemaVersion != correlation.SnapshotSchemaVersion {
			return SelfTestFail, fmt.Sprintf("%s: SchemaVersion inesperado", e.kind)
		}
		if e.snap.Kind != e.kind {
			return SelfTestFail, fmt.Sprintf("%s: Kind inesperado (%s)", e.kind, e.snap.Kind)
		}
		if strings.TrimSpace(e.snap.Assessment.Conclusion) == "" {
			return SelfTestFail, fmt.Sprintf("%s: Assessment.Conclusion vacío", e.kind)
		}
		if e.snap.Assessment.Confidence > 100 {
			return SelfTestFail, fmt.Sprintf("%s: Confidence fuera de contrato", e.kind)
		}
		if looksLikeLocalPath(e.snap.SourceID) {
			return SelfTestFail, fmt.Sprintf("%s: SourceID parece una ruta local", e.kind)
		}
	}
	return SelfTestPass, fmt.Sprintf("%d/%d adapter(s) de correlación verificados contra el contrato", len(entries), len(entries))
}

// ---- 10. investigation persistence (temp store) ----------------------------

func (r *selfTestRunner) firstValidSnapshot() (correlation.Snapshot, bool) {
	switch {
	case r.pcapOK:
		return r.pcapSnapshot, true
	case r.diagnoseOK:
		return r.diagnoseSnapshot, true
	case r.voipOK:
		return r.voipSnapshot, true
	case r.monitorOK:
		return r.monitorSnapshot, true
	default:
		return correlation.Snapshot{}, false
	}
}

func (r *selfTestRunner) checkInvestigationPersistence() (SelfTestStatus, string) {
	if r.tempRoot == "" {
		return SelfTestSkipped, "sin workspace temporal disponible"
	}
	snap, ok := r.firstValidSnapshot()
	if !ok {
		return SelfTestSkipped, "sin ningún snapshot válido disponible de checks anteriores"
	}

	// A dedicated temp store — never s.investigations, never
	// investigation.NewManager() (both point at the real user store; Phase
	// F.0 §10).
	invDir := filepath.Join(r.tempRoot, "investigations")
	mgr1 := investigation.NewManagerAt(invDir)

	inv, err := mgr1.Create("Self Test", "")
	if err != nil {
		return SelfTestFail, "Create falló: " + err.Error()
	}
	_, existing, err := mgr1.AddSnapshot(inv.ID, snap)
	if err != nil {
		return SelfTestFail, "AddSnapshot falló: " + err.Error()
	}
	if existing {
		return SelfTestFail, "AddSnapshot reportó existing=true en el primer agregado"
	}

	// A second Manager over the SAME directory — proves disk → reopen →
	// read, not just an in-memory round-trip.
	mgr2 := investigation.NewManagerAt(invDir)
	reopened, err := mgr2.Get(inv.ID)
	if err != nil {
		return SelfTestFail, "Get tras reabrir el store falló: " + err.Error()
	}
	if len(reopened.Entries) != 1 {
		return SelfTestFail, fmt.Sprintf("entry count = %d, se esperaba 1", len(reopened.Entries))
	}
	persisted := reopened.Entries[0].Snapshot
	if persisted.Kind != snap.Kind || persisted.SourceID != snap.SourceID || persisted.Assessment.Conclusion != snap.Assessment.Conclusion {
		return SelfTestFail, "el snapshot persistido no conserva Kind/SourceID/Assessment"
	}

	_, existing2, err := mgr2.AddSnapshot(inv.ID, snap)
	if err != nil {
		return SelfTestFail, "AddSnapshot duplicado falló: " + err.Error()
	}
	if !existing2 {
		return SelfTestFail, "la supresión de duplicados no reportó existing=true"
	}
	final, err := mgr2.Get(inv.ID)
	if err != nil {
		return SelfTestFail, "Get final falló: " + err.Error()
	}
	if len(final.Entries) != 1 {
		return SelfTestFail, "el snapshot duplicado agregó una segunda Entry"
	}

	r.invMgr = mgr2
	r.invID = inv.ID
	return SelfTestPass, "persistencia disco → reabrir → leer y supresión de duplicados verificadas"
}

// ---- 11. report generation --------------------------------------------------

func (r *selfTestRunner) checkReportGeneration() (SelfTestStatus, string) {
	if r.invMgr == nil || r.invID == "" {
		return SelfTestSkipped, "sin investigación temporal disponible"
	}
	inv, err := r.invMgr.Get(r.invID)
	if err != nil {
		return SelfTestFail, "Get de la investigación temporal falló: " + err.Error()
	}
	rep := investigation.ToReport(inv, Version)

	jsonBytes, err := rep.ToJSON()
	if err != nil {
		return SelfTestFail, "ToJSON falló: " + err.Error()
	}
	if len(jsonBytes) == 0 || !json.Valid(jsonBytes) {
		return SelfTestFail, "ToJSON produjo JSON vacío o inválido"
	}

	csvBytes := rep.ToCSV()
	if len(csvBytes) == 0 {
		return SelfTestFail, "ToCSV produjo salida vacía"
	}

	htmlBytes := rep.ToHTML()
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "<html") || !strings.Contains(htmlStr, "</html>") {
		return SelfTestFail, "ToHTML no contiene la estructura HTML esperada"
	}

	pdfBytes := rep.ToPDF()
	if len(pdfBytes) == 0 || !bytes.HasPrefix(pdfBytes, []byte("%PDF-")) {
		return SelfTestFail, "ToPDF produjo salida vacía o sin cabecera %PDF-"
	}

	r.reportJSON, r.reportCSV, r.reportHTML, r.reportPDF = jsonBytes, csvBytes, htmlBytes, pdfBytes
	return SelfTestPass, "JSON/CSV/HTML/PDF generados por los renderers reales, en memoria"
}

// ---- 12. privacy / invariants ------------------------------------------------

func (r *selfTestRunner) checkPrivacyInvariants() (SelfTestStatus, string) {
	if got := basenameAnySeparator(`C:\Users\name\capture.pcap`); got != "capture.pcap" {
		return SelfTestFail, fmt.Sprintf("basenameAnySeparator(ruta Windows) = %q, se esperaba capture.pcap", got)
	}
	if !looksLikeLocalPath(`C:\Users\name\capture.pcap`) {
		return SelfTestFail, "looksLikeLocalPath no rechazó una ruta de Windows"
	}
	if !looksLikeLocalPath(`/home/name/capture.pcap`) {
		return SelfTestFail, "looksLikeLocalPath no rechazó una ruta POSIX"
	}
	if looksLikeLocalPath("session-123") {
		return SelfTestFail, "looksLikeLocalPath rechazó un identificador opaco válido"
	}
	if looksLikeLocalPath("selftest-pcap") {
		return SelfTestFail, "looksLikeLocalPath rechazó selftest-pcap"
	}

	if r.tempRoot == "" {
		return SelfTestPass, "invariantes de rutas verificados (sin workspace temporal para comprobar fugas)"
	}

	probe := "error abriendo " + filepath.Join(r.tempRoot, "capture.pcap")
	if strings.Contains(r.sanitize(probe), r.tempRoot) {
		return SelfTestFail, "sanitize no elimina el tempRoot de un mensaje de error"
	}

	for _, c := range r.checks {
		if strings.Contains(c.Detail, r.tempRoot) {
			return SelfTestFail, "un SelfTestCheck.Detail contiene el tempRoot"
		}
	}
	for _, snap := range []correlation.Snapshot{r.diagnoseSnapshot, r.pcapSnapshot, r.monitorSnapshot, r.voipSnapshot} {
		if strings.Contains(snap.SourceID, r.tempRoot) || strings.Contains(snap.Subject, r.tempRoot) {
			return SelfTestFail, "un Snapshot usado en la Investigation contiene el tempRoot"
		}
	}
	for name, body := range map[string][]byte{"json": r.reportJSON, "csv": r.reportCSV, "html": r.reportHTML, "pdf": r.reportPDF} {
		if len(body) > 0 && bytes.Contains(body, []byte(r.tempRoot)) {
			return SelfTestFail, fmt.Sprintf("el reporte %s contiene el tempRoot", name)
		}
	}
	return SelfTestPass, "sin fugas del tempRoot en checks, snapshots ni reportes derivados"
}

// ---- 13. optional local capability -----------------------------------------

func (r *selfTestRunner) checkGeoIPCapability() (SelfTestStatus, string) {
	if r.s == nil || r.s.geo == nil || !r.s.geo.Available() {
		return SelfTestUnavailable, "datasets GeoIP no están instalados/cargados localmente"
	}
	return SelfTestPass, "datasets GeoIP disponibles localmente"
}
