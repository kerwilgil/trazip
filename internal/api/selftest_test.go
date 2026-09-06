package api

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"trazip/internal/correlation"
	"trazip/internal/diagnosis"
	"trazip/internal/model"
)

// newSelfTestRunner builds a runner over a real Service for direct,
// step-by-step exercise of the check methods — the same construction
// runSelfTestLocal itself uses, minus the deferred workspace cleanup so
// individual tests can inspect tempRoot before removing it.
func newSelfTestRunner(t *testing.T) *selfTestRunner {
	t.Helper()
	s := NewService()
	t.Cleanup(s.Close)
	r := &selfTestRunner{s: s, ctx: context.Background(), checks: make([]SelfTestCheck, 0, 13)}
	t.Cleanup(func() {
		if r.tempRoot != "" {
			_ = os.RemoveAll(r.tempRoot)
		}
	})
	return r
}

// A. Full local self test: terminates, no FAIL on the nominal fixture,
// networkOut == false, unique IDs, valid statuses.
func TestSelfTestLocalNominalRun(t *testing.T) {
	s := NewService()
	defer s.Close()
	res := runSelfTestLocal(context.Background(), s)

	if res.Mode != "local" {
		t.Errorf("Mode = %q, want local", res.Mode)
	}
	if res.NetworkOut {
		t.Error("NetworkOut = true, want false")
	}
	if len(res.Checks) == 0 {
		t.Fatal("no checks ran")
	}
	if res.OverallStatus == SelfTestFail {
		var failed []string
		for _, c := range res.Checks {
			if c.Status == SelfTestFail {
				failed = append(failed, c.ID+": "+c.Detail)
			}
		}
		t.Fatalf("OverallStatus = fail on nominal fixture: %v", failed)
	}

	seen := map[string]bool{}
	for _, c := range res.Checks {
		if c.ID == "" {
			t.Error("check with empty ID")
		}
		if seen[c.ID] {
			t.Errorf("duplicate check ID %q", c.ID)
		}
		seen[c.ID] = true
		switch c.Status {
		case SelfTestPass, SelfTestFail, SelfTestSkipped, SelfTestUnavailable:
		default:
			t.Errorf("check %q has invalid status %q", c.ID, c.Status)
		}
	}
	if res.Passed+res.Failed+res.Skipped+res.Unavailable != len(res.Checks) {
		t.Error("status counts do not add up to len(Checks)")
	}

	// correlation.adapters depends on all four upstream Snapshots; on the
	// nominal fixture every upstream succeeds, so this must be a full 4/4
	// PASS — never a partial count (Phase F.0 micro-hardening).
	var corrCheck *SelfTestCheck
	for i := range res.Checks {
		if res.Checks[i].ID == "correlation.adapters" {
			corrCheck = &res.Checks[i]
			break
		}
	}
	if corrCheck == nil {
		t.Fatal(`check "correlation.adapters" not found in nominal run`)
	}
	if corrCheck.Status != SelfTestPass {
		t.Fatalf("correlation.adapters status = %s, want pass on the nominal fixture (detail: %s)", corrCheck.Status, corrCheck.Detail)
	}
	if !strings.Contains(corrCheck.Detail, "4/4") {
		t.Errorf("correlation.adapters Detail = %q, want it to report 4/4 (never a partial count)", corrCheck.Detail)
	}
}

func TestSelfTestLocalStartedBeforeCompleted(t *testing.T) {
	s := NewService()
	defer s.Close()
	res := runSelfTestLocal(context.Background(), s)
	if res.StartedAt == "" || res.CompletedAt == "" {
		t.Fatalf("StartedAt/CompletedAt must be set: %q / %q", res.StartedAt, res.CompletedAt)
	}
	if res.CompletedAt < res.StartedAt {
		t.Errorf("CompletedAt %q is before StartedAt %q", res.CompletedAt, res.StartedAt)
	}
}

// Phase F.1: Service.SelfTestLocal is a thin Wails-bound wrapper over the
// already-closed F.0 core — this only proves the wrapper doesn't drop or
// alter the contract, not the individual checks (those stay covered above).
func TestServiceSelfTestLocalUsesClosedCore(t *testing.T) {
	s := NewService()
	defer s.Close()
	res := s.SelfTestLocal()

	if res.Mode != "local" {
		t.Errorf("Mode = %q, want local", res.Mode)
	}
	if res.NetworkOut {
		t.Error("NetworkOut = true, want false")
	}
	if len(res.Checks) == 0 {
		t.Fatal("Checks is empty")
	}
	if res.OverallStatus == SelfTestFail {
		t.Errorf("OverallStatus = fail on the nominal fixture (passed=%d failed=%d skipped=%d unavailable=%d)",
			res.Passed, res.Failed, res.Skipped, res.Unavailable)
	}
}

// B. Diagnose: direct IP + offline, zero NetworkActions.
func TestSelfTestDiagnoseOfflineDirectIPNoNetworkActions(t *testing.T) {
	s := NewService()
	defer s.Close()
	rep, err := RunDiagnose(context.Background(), "192.0.2.1", string(diagnosis.ModeOffline), s)
	if err != nil {
		t.Fatalf("RunDiagnose: %v", err)
	}
	if rep.NetworkOut {
		t.Error("NetworkOut = true in ModeOffline")
	}
	if len(rep.NetworkActions) != 0 {
		t.Errorf("NetworkActions = %v, want empty", rep.NetworkActions)
	}
}

func TestSelfTestCheckDiagnoseOfflinePasses(t *testing.T) {
	r := newSelfTestRunner(t)
	status, detail := r.checkDiagnoseOffline()
	if status != SelfTestPass {
		t.Fatalf("checkDiagnoseOffline: %s / %s", status, detail)
	}
	if !r.diagnoseOK {
		t.Error("diagnoseOK not set")
	}
	if r.diagnoseSnapshot.Kind != correlation.SourceDiagnose {
		t.Errorf("Snapshot.Kind = %s, want diagnose", r.diagnoseSnapshot.Kind)
	}
}

// C. Lab fixtures: reused (never Service.LabRunScenario / labDir()) and pass.
func TestSelfTestLabFixturesReuseAndPass(t *testing.T) {
	r := newSelfTestRunner(t)
	if status, detail := r.checkCoreWorkspace(); status != SelfTestPass {
		t.Fatalf("core workspace: %s / %s", status, detail)
	}

	for _, id := range []string{"flow-basics", "voip-rtp-loss", "purple-scan-detection"} {
		res, status, detail := r.runLabScenario(id)
		if status != SelfTestPass {
			t.Errorf("scenario %s: %s / %s", id, status, detail)
		}
		if res.PcapPath == "" {
			t.Errorf("scenario %s: PcapPath empty", id)
		}
	}
}

func TestSelfTestLabFixturesSkipWithoutWorkspace(t *testing.T) {
	r := newSelfTestRunner(t) // checkCoreWorkspace deliberately not called
	status, _ := r.checkLabFlowBasics()
	if status != SelfTestSkipped {
		t.Errorf("status = %s, want skipped when no temp workspace exists", status)
	}
}

// D. PCAP: real AnalyzePcap, coherent summary.
func TestSelfTestPcapCheckProducesCoherentSummary(t *testing.T) {
	r := newSelfTestRunner(t)
	if status, detail := r.checkCoreWorkspace(); status != SelfTestPass {
		t.Fatalf("core workspace: %s / %s", status, detail)
	}
	if status, detail := r.checkLabFlowBasics(); status != SelfTestPass {
		t.Fatalf("lab flow-basics: %s / %s", status, detail)
	}
	status, detail := r.checkPcapAnalysis()
	if status != SelfTestPass {
		t.Fatalf("pcap analysis: %s / %s", status, detail)
	}
	if !r.pcapOK {
		t.Fatal("pcapOK not set")
	}
	if r.pcapSnapshot.Kind != correlation.SourcePCAP {
		t.Errorf("Snapshot.Kind = %s, want pcap", r.pcapSnapshot.Kind)
	}
	if r.pcapSnapshot.Subject != "capture.pcap" || r.pcapSnapshot.SourceID != "selftest-pcap" {
		t.Errorf("unexpected Subject/SourceID: %q / %q", r.pcapSnapshot.Subject, r.pcapSnapshot.SourceID)
	}
}

// E. VoIP: existing diagnosis, valid adapter.
func TestSelfTestVoIPCheckProducesValidAdapter(t *testing.T) {
	r := newSelfTestRunner(t)
	if status, detail := r.checkCoreWorkspace(); status != SelfTestPass {
		t.Fatalf("core workspace: %s / %s", status, detail)
	}
	if status, detail := r.checkLabVoIPLoss(); status != SelfTestPass {
		t.Fatalf("lab voip-rtp-loss: %s / %s", status, detail)
	}
	status, detail := r.checkVoIPDiagnosis()
	if status != SelfTestPass {
		t.Fatalf("voip diagnosis: %s / %s", status, detail)
	}
	if !r.voipOK {
		t.Fatal("voipOK not set")
	}
	if r.voipSnapshot.Kind != correlation.SourceVoIP {
		t.Errorf("Snapshot.Kind = %s, want voip", r.voipSnapshot.Kind)
	}
	if r.voipSnapshot.SourceID != "lab-voip-loss@192.168.50.10" {
		t.Errorf("SourceID = %q, want the fixture's CallID", r.voipSnapshot.SourceID)
	}
}

// F. Monitor: transient never confirms, persistent confirms exactly one,
// adapter valid.
func TestSelfTestMonitorRouteChangeCheckProducesValidAdapter(t *testing.T) {
	r := newSelfTestRunner(t)
	status, detail := r.checkMonitorRouteChange()
	if status != SelfTestPass {
		t.Fatalf("monitor route change: %s / %s", status, detail)
	}
	if !r.monitorOK {
		t.Fatal("monitorOK not set")
	}
	if r.monitorSnapshot.Kind != correlation.SourceMonitor {
		t.Errorf("Snapshot.Kind = %s, want monitor", r.monitorSnapshot.Kind)
	}
	if r.monitorSnapshot.Assessment.Level != model.LevelInfo {
		t.Errorf("Assessment.Level = %s, want %s (no coincident degradation)", r.monitorSnapshot.Assessment.Level, model.LevelInfo)
	}
}

// validCorrelationSnapshot builds a structurally valid Snapshot for a given
// source — used below to prove correlation.adapters SKIPs on a MISSING
// upstream specifically, not because the snapshots it does have are
// somehow invalid.
func validCorrelationSnapshot(kind correlation.SourceKind, sourceID string) correlation.Snapshot {
	return correlation.Snapshot{
		SchemaVersion: correlation.SnapshotSchemaVersion,
		Kind:          kind,
		SourceID:      sourceID,
		Subject:       "subject de prueba",
		OccurredAt:    time.Now().UTC().Format(time.RFC3339),
		Assessment: model.Assessment{
			Conclusion: "conclusión de prueba",
			Level:      model.LevelInfo,
			Confidence: 80,
		},
	}
}

// correlation.adapters depends on ALL FOUR upstream snapshots — missing
// even one must SKIP the whole check, never PASS on a partial subset
// (Phase F.0 micro-hardening: "correlation.adapters depende de LOS CUATRO
// snapshots anteriores.").
func TestSelfTestCorrelationAdaptersSkipsWhenAnyUpstreamMissing(t *testing.T) {
	s := NewService()
	defer s.Close()
	r := &selfTestRunner{s: s, ctx: context.Background()}

	r.diagnoseOK = true
	r.diagnoseSnapshot = validCorrelationSnapshot(correlation.SourceDiagnose, "diag-1")
	r.pcapOK = true
	r.pcapSnapshot = validCorrelationSnapshot(correlation.SourcePCAP, "selftest-pcap")
	r.monitorOK = true
	r.monitorSnapshot = validCorrelationSnapshot(correlation.SourceMonitor, "route-1")
	// r.voipOK left false: the one missing upstream.

	status, detail := r.checkCorrelationAdapters()
	if status != SelfTestSkipped {
		t.Fatalf("status = %s, want skipped when 1 of 4 upstream adapters is missing (detail: %q)", status, detail)
	}
	if !strings.Contains(detail, "voip") {
		t.Errorf("detail = %q, want it to name the missing adapter (voip)", detail)
	}
}

func TestSelfTestCorrelationAdaptersFailsOnInvalidSnapshotOnlyWhenAllFourPresent(t *testing.T) {
	s := NewService()
	defer s.Close()
	r := &selfTestRunner{s: s, ctx: context.Background()}

	r.diagnoseOK = true
	r.diagnoseSnapshot = validCorrelationSnapshot(correlation.SourceDiagnose, "diag-1")
	r.pcapOK = true
	r.pcapSnapshot = validCorrelationSnapshot(correlation.SourcePCAP, "selftest-pcap")
	r.monitorOK = true
	r.monitorSnapshot = validCorrelationSnapshot(correlation.SourceMonitor, "route-1")
	r.voipOK = true
	broken := validCorrelationSnapshot(correlation.SourceVoIP, "call-1")
	broken.Assessment.Conclusion = "" // violates the contract
	r.voipSnapshot = broken

	status, detail := r.checkCorrelationAdapters()
	if status != SelfTestFail {
		t.Fatalf("status = %s, want fail when all 4 upstreams are present but one violates the contract (detail: %q)", status, detail)
	}
}

// G. Investigation: temp store, reopen, persistence, duplicate suppression.
func TestSelfTestInvestigationPersistenceTempStoreReopenDedup(t *testing.T) {
	r := newSelfTestRunner(t)
	if status, detail := r.checkCoreWorkspace(); status != SelfTestPass {
		t.Fatalf("core workspace: %s / %s", status, detail)
	}
	if status, detail := r.checkDiagnoseOffline(); status != SelfTestPass {
		t.Fatalf("diagnose offline: %s / %s", status, detail)
	}
	status, detail := r.checkInvestigationPersistence()
	if status != SelfTestPass {
		t.Fatalf("investigation persistence: %s / %s", status, detail)
	}
	if r.invMgr == nil || r.invID == "" {
		t.Fatal("investigation state not populated")
	}
	inv, err := r.invMgr.Get(r.invID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(inv.Entries) != 1 {
		t.Errorf("Entries = %d, want 1 (duplicate suppression should keep exactly one)", len(inv.Entries))
	}
	if inv.Entries[0].Snapshot.Kind != correlation.SourceDiagnose {
		t.Errorf("persisted entry Kind = %s, want diagnose", inv.Entries[0].Snapshot.Kind)
	}
}

func TestSelfTestInvestigationPersistenceSkipsWithoutSnapshot(t *testing.T) {
	r := newSelfTestRunner(t)
	if status, detail := r.checkCoreWorkspace(); status != SelfTestPass {
		t.Fatalf("core workspace: %s / %s", status, detail)
	}
	// Deliberately skip every check that would populate a snapshot.
	status, _ := r.checkInvestigationPersistence()
	if status != SelfTestSkipped {
		t.Errorf("status = %s, want skipped with no upstream snapshot", status)
	}
}

// H. Reports: JSON, CSV, HTML, PDF.
func TestSelfTestReportGenerationProducesAllFormats(t *testing.T) {
	r := newSelfTestRunner(t)
	if status, detail := r.checkCoreWorkspace(); status != SelfTestPass {
		t.Fatalf("core workspace: %s / %s", status, detail)
	}
	if status, detail := r.checkDiagnoseOffline(); status != SelfTestPass {
		t.Fatalf("diagnose offline: %s / %s", status, detail)
	}
	if status, detail := r.checkInvestigationPersistence(); status != SelfTestPass {
		t.Fatalf("investigation persistence: %s / %s", status, detail)
	}
	status, detail := r.checkReportGeneration()
	if status != SelfTestPass {
		t.Fatalf("report generation: %s / %s", status, detail)
	}
	if !json.Valid(r.reportJSON) {
		t.Error("reportJSON is not valid JSON")
	}
	if len(r.reportCSV) == 0 {
		t.Error("reportCSV is empty")
	}
	if !bytes.Contains(r.reportHTML, []byte("<html")) || !bytes.Contains(r.reportHTML, []byte("</html>")) {
		t.Error("reportHTML missing expected structure")
	}
	if !bytes.HasPrefix(r.reportPDF, []byte("%PDF-")) {
		t.Error("reportPDF missing %PDF- header")
	}
}

// I. Privacy: serialized result, Investigation/report, and sourceIDs never
// carry the self test's own temp path.
func TestSelfTestPrivacyNoTempRootLeak(t *testing.T) {
	r := newSelfTestRunner(t)

	r.run("core.local", "core", r.checkCoreWorkspace)
	r.run("diagnose.offline", "diagnose", r.checkDiagnoseOffline)
	r.run("lab.flow-basics", "lab", r.checkLabFlowBasics)
	r.run("lab.voip-rtp-loss", "lab", r.checkLabVoIPLoss)
	r.run("pcap.analysis", "pcap", r.checkPcapAnalysis)
	r.run("voip.diagnosis", "voip", r.checkVoIPDiagnosis)
	r.run("monitor.routechange", "monitor", r.checkMonitorRouteChange)
	r.run("investigation.persistence", "inv", r.checkInvestigationPersistence)
	r.run("report.generation", "report", r.checkReportGeneration)
	r.run("privacy.invariants", "privacy", r.checkPrivacyInvariants)

	if r.tempRoot == "" {
		t.Fatal("tempRoot never set — test setup broken")
	}
	for _, c := range r.checks {
		if c.Status == SelfTestFail {
			t.Fatalf("check %s unexpectedly failed: %s", c.ID, c.Detail)
		}
		if strings.Contains(c.Detail, r.tempRoot) {
			t.Errorf("check %s Detail leaks tempRoot: %s", c.ID, c.Detail)
		}
	}

	for _, snap := range []correlation.Snapshot{r.diagnoseSnapshot, r.pcapSnapshot, r.monitorSnapshot, r.voipSnapshot} {
		if strings.Contains(snap.SourceID, r.tempRoot) || strings.Contains(snap.Subject, r.tempRoot) {
			t.Error("a Snapshot leaks tempRoot in SourceID/Subject")
		}
		if snap.SourceID != "" && looksLikeLocalPath(snap.SourceID) {
			t.Errorf("Snapshot SourceID looks like a local path: %q", snap.SourceID)
		}
	}

	for name, body := range map[string][]byte{
		"json": r.reportJSON, "csv": r.reportCSV, "html": r.reportHTML, "pdf": r.reportPDF,
	} {
		if len(body) > 0 && bytes.Contains(body, []byte(r.tempRoot)) {
			t.Errorf("report %s leaks tempRoot", name)
		}
	}

	serialized, err := json.Marshal(r.checks)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(serialized, []byte(r.tempRoot)) {
		t.Error("serialized checks leak tempRoot")
	}
}

func TestSelfTestPrivacyInvariantsPureFunctions(t *testing.T) {
	s := NewService()
	defer s.Close()
	r := &selfTestRunner{s: s, ctx: context.Background()}
	status, detail := r.checkPrivacyInvariants()
	if status != SelfTestPass {
		t.Fatalf("checkPrivacyInvariants without workspace: %s / %s", status, detail)
	}
}

// J. Status semantics: FAIL dominates overall; SKIPPED != FAIL; UNAVAILABLE != FAIL.
func TestSummarizeSelfTestChecksStatusSemantics(t *testing.T) {
	allGood := []SelfTestCheck{
		{ID: "a", Status: SelfTestPass},
		{ID: "b", Status: SelfTestSkipped},
		{ID: "c", Status: SelfTestUnavailable},
	}
	overall, passed, failed, skipped, unavailable := summarizeSelfTestChecks(allGood)
	if overall != SelfTestPass {
		t.Errorf("overall = %s, want pass (SKIPPED/UNAVAILABLE alone must never fail the run)", overall)
	}
	if passed != 1 || failed != 0 || skipped != 1 || unavailable != 1 {
		t.Errorf("counts = %d/%d/%d/%d, want 1/0/1/1", passed, failed, skipped, unavailable)
	}

	withFail := []SelfTestCheck{
		{ID: "a", Status: SelfTestPass},
		{ID: "b", Status: SelfTestFail},
		{ID: "c", Status: SelfTestSkipped},
		{ID: "d", Status: SelfTestUnavailable},
	}
	overall, passed, failed, skipped, unavailable = summarizeSelfTestChecks(withFail)
	if overall != SelfTestFail {
		t.Errorf("overall = %s, want fail (>=1 FAIL must dominate)", overall)
	}
	if passed != 1 || failed != 1 || skipped != 1 || unavailable != 1 {
		t.Errorf("counts = %d/%d/%d/%d, want 1/1/1/1", passed, failed, skipped, unavailable)
	}

	overall, _, _, _, _ = summarizeSelfTestChecks(nil)
	if overall != SelfTestPass {
		t.Errorf("overall = %s, want pass for an empty check list", overall)
	}
}

func TestSelfTestGeoIPCapabilityNeverFails(t *testing.T) {
	s := NewService()
	defer s.Close()
	r := &selfTestRunner{s: s, ctx: context.Background()}
	status, _ := r.checkGeoIPCapability()
	if status != SelfTestPass && status != SelfTestUnavailable {
		t.Errorf("status = %s, want pass or unavailable, never fail/skipped for an optional capability", status)
	}
}
