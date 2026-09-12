package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trazip/internal/correlation"
	"trazip/internal/diagnosis"
	"trazip/internal/investigation"
	"trazip/internal/model"
	"trazip/internal/monitor"
	"trazip/internal/voip"
)

// newTestServiceWithInvestigations builds a real Service but redirects its
// investigation store to an isolated temp dir — NewService() itself still
// touches the real user config dir for its other managers (an existing,
// accepted pattern already used by every other internal/api test that
// calls NewService()), but no investigation data is ever written outside
// this test's own t.TempDir().
func newTestServiceWithInvestigations(t *testing.T) *Service {
	t.Helper()
	s := NewService()
	s.investigations = investigation.NewManagerAt(t.TempDir())
	return s
}

func TestInvestigationAddDiagnoseStoresAdapterOutput(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, err := s.InvestigationCreate("caso", "")
	if err != nil {
		t.Fatal(err)
	}
	rep := diagnosis.DiagnosticReport{
		Target: "example.com", Kind: "host", Mode: diagnosis.ModeStandard,
		Summary: "resuelve y responde", Level: model.LevelInfo, Confidence: 85,
		Evidence:    []model.Evidence{{Type: "dns", Value: "1.2.3.4", Source: "resolution", Provenance: model.ProvObserved, Confidence: 90}},
		StartedAt:   "2026-01-01T10:00:00Z",
		CompletedAt: "2026-01-01T10:00:05Z",
	}
	body, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.InvestigationAddDiagnose(inv.ID, string(body))
	if err != nil {
		t.Fatalf("InvestigationAddDiagnose: %v", err)
	}
	if res.Existing {
		t.Error("expected Existing=false for a fresh add")
	}

	want := diagnosis.ToSnapshot(rep)
	entry := res.Entry
	if entry.Snapshot.Kind != want.Kind || entry.Snapshot.Subject != want.Subject ||
		entry.Snapshot.OccurredAt != want.OccurredAt || entry.Snapshot.Assessment.Conclusion != want.Assessment.Conclusion ||
		entry.Snapshot.Assessment.Confidence != want.Assessment.Confidence {
		t.Errorf("stored Snapshot = %+v, want exactly diagnosis.ToSnapshot(report) = %+v", entry.Snapshot, want)
	}
}

func TestInvestigationAddDiagnoseRejectsIncompleteReport(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	rep := diagnosis.DiagnosticReport{Target: "x", StartedAt: "2026-01-01T10:00:00Z"} // CompletedAt empty
	body, _ := json.Marshal(rep)
	if _, err := s.InvestigationAddDiagnose(inv.ID, string(body)); err == nil {
		t.Error("expected an error for a report that never completed")
	}
}

// D. V1 hardening finding #1: the persistence boundary must reject a
// legacy/forged DiagnosticReport whose Target still carries URL
// credentials — DiagnoseTarget rejects these upstream today, but this
// guard must not rely on that alone (a report built by an older TRAZIP
// version, or a different caller, could reach here with one anyway).
func TestInvestigationAddDiagnoseRejectsLegacyURLCredentials(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	rep := diagnosis.DiagnosticReport{
		Target: "https://alice:s3cr3t@example.com/private", Kind: "url", Mode: diagnosis.ModeStandard,
		Summary: "resuelve y responde", Level: model.LevelInfo, Confidence: 85,
		StartedAt: "2026-01-01T10:00:00Z", CompletedAt: "2026-01-01T10:00:05Z",
	}
	body, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.InvestigationAddDiagnose(inv.ID, string(body))
	if err == nil {
		t.Fatal("expected an error for a report whose Target carries URL credentials")
	}
	if strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "alice") {
		t.Errorf("error leaks the credential: %q", err.Error())
	}

	got, listErr := s.InvestigationGet(inv.ID)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(got.Entries) != 0 {
		t.Errorf("Entries = %d, want 0 — no Entry should have been written on rejection", len(got.Entries))
	}
}

// E. The rejected case's own request body (and any error derived from it)
// must never leak the password when serialized — belt-and-suspenders on
// top of test D's error-string check.
func TestInvestigationAddDiagnoseRejectionNeverSerializesPassword(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	rep := diagnosis.DiagnosticReport{
		Target: "https://alice:s3cr3t@example.com/private", Kind: "url", Mode: diagnosis.ModeStandard,
		Summary: "x", Level: model.LevelInfo, Confidence: 50,
		StartedAt: "2026-01-01T10:00:00Z", CompletedAt: "2026-01-01T10:00:05Z",
	}
	body, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.InvestigationAddDiagnose(inv.ID, string(body))
	if err == nil {
		t.Fatal("expected an error")
	}
	resBody, marshalErr := json.Marshal(struct {
		Result InvestigationAddResult
		Err    string
	}{res, err.Error()})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(resBody), "s3cr3t") {
		t.Errorf("serialized error/result leaks the password: %s", resBody)
	}
}

// F. V1 URL-privacy micro-hardening: a legacy report whose Target is a
// credential-bearing URL that's ALSO malformed later on (an invalid
// percent-escape in the path) used to slip past the old, non-fail-closed
// HasURLUserinfo — this persistence boundary must reject it exactly like
// any other credential-bearing Target, with zero Entries written and zero
// leakage.
func TestInvestigationAddDiagnoseRejectsMalformedLegacyURLCredentials(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	rep := diagnosis.DiagnosticReport{
		Target: "https://alice:s3cr3t@example.com/%ZZ", Kind: "url", Mode: diagnosis.ModeStandard,
		Summary: "resuelve y responde", Level: model.LevelInfo, Confidence: 85,
		StartedAt: "2026-01-01T10:00:00Z", CompletedAt: "2026-01-01T10:00:05Z",
	}
	body, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.InvestigationAddDiagnose(inv.ID, string(body))
	if err == nil {
		t.Fatal("expected an error for a malformed report Target that still carries URL credentials")
	}
	resBody, marshalErr := json.Marshal(struct {
		Result InvestigationAddResult
		Err    string
	}{res, err.Error()})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, secret := range []string{"alice", "s3cr3t"} {
		if strings.Contains(string(resBody), secret) {
			t.Errorf("serialized error/result leaks %q: %s", secret, resBody)
		}
	}

	got, listErr := s.InvestigationGet(inv.ID)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(got.Entries) != 0 {
		t.Errorf("Entries = %d, want 0 — no Entry should have been written on rejection", len(got.Entries))
	}
}

// G. Surrounding whitespace around a credential-bearing Target must not
// defeat the persistence guard either.
func TestInvestigationAddDiagnoseRejectsURLCredentialsWithSurroundingWhitespace(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	rep := diagnosis.DiagnosticReport{
		Target: "  https://alice:s3cr3t@example.com/path  ", Kind: "url", Mode: diagnosis.ModeStandard,
		Summary: "x", Level: model.LevelInfo, Confidence: 50,
		StartedAt: "2026-01-01T10:00:00Z", CompletedAt: "2026-01-01T10:00:05Z",
	}
	body, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.InvestigationAddDiagnose(inv.ID, string(body)); err == nil {
		t.Fatal("expected an error for a credential-bearing Target with surrounding whitespace")
	}

	got, listErr := s.InvestigationGet(inv.ID)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(got.Entries) != 0 {
		t.Errorf("Entries = %d, want 0 — no Entry should have been written on rejection", len(got.Entries))
	}
}

func TestInvestigationAddPcapStoresAdapterOutput(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	summary := correlation.PcapIncidentSummary{
		Summary: "1 hallazgo", Level: model.LevelHigh, Confidence: 85,
		Findings: []correlation.PcapFinding{{ID: "f1", Category: "loop", Summary: "bucle", Level: model.LevelHigh, Confidence: 85, SourceArea: correlation.SourceAreaNetDiag}},
	}

	res, err := s.InvestigationAddPcap(inv.ID, summary, "capture.pcap", "session-1", "2026-01-01T09:00:00Z")
	if err != nil {
		t.Fatalf("InvestigationAddPcap: %v", err)
	}

	want := summary.ToSnapshot("capture.pcap", "session-1", "2026-01-01T09:00:00Z")
	entry := res.Entry
	if entry.Snapshot.Assessment.Conclusion != want.Assessment.Conclusion || entry.Snapshot.Kind != want.Kind || entry.Snapshot.Subject != want.Subject {
		t.Errorf("stored Snapshot = %+v, want exactly summary.ToSnapshot(...) = %+v", entry.Snapshot, want)
	}
}

func TestInvestigationAddPcapStripsFullPath(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	summary := correlation.PcapIncidentSummary{Summary: "ok", Level: model.LevelInfo, Confidence: 70}

	res, err := s.InvestigationAddPcap(inv.ID, summary, `C:\Users\kerwil\Desktop\capture.pcap`, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Entry.Snapshot.Subject != "capture.pcap" {
		t.Errorf("Subject = %q, want just the base filename — never a full local path", res.Entry.Snapshot.Subject)
	}
}

// E.1-9: the same guarantee must hold for a POSIX-style path regardless of
// which OS this binary is actually running on (path/filepath.Base alone
// only recognizes the current runtime's own separator convention).
func TestInvestigationAddPcapStripsFullPathPOSIXStyle(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	summary := correlation.PcapIncidentSummary{Summary: "ok", Level: model.LevelInfo, Confidence: 70}

	res, err := s.InvestigationAddPcap(inv.ID, summary, "/home/kerwil/captures/capture.pcap", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Entry.Snapshot.Subject != "capture.pcap" {
		t.Errorf("Subject = %q, want just the base filename for a POSIX-style path too", res.Entry.Snapshot.Subject)
	}
}

// A raw literal with one backslash and an interpreted literal with \\ are
// two different ways to SPELL the identical runtime string — Go's compiler
// proves this itself (the two can't coexist as distinct map keys in
// TestBasenameAnySeparator below). Kept as its own explicit assertion so
// that equivalence stays documented in the test suite rather than only
// implied by a compile error.
func TestWindowsPathLiteralFormsAreEquivalent(t *testing.T) {
	raw := `C:\Users\kerwil\Desktop\capture.pcap`
	interpreted := "C:\\Users\\kerwil\\Desktop\\capture.pcap"
	if raw != interpreted {
		t.Fatalf("expected these two literal forms to be byte-identical: %q vs %q", raw, interpreted)
	}
}

func TestBasenameAnySeparator(t *testing.T) {
	cases := map[string]string{
		// Raw literal, ONE real backslash per separator — what a decoded
		// Windows path actually looks like in memory (Wails/JSON never
		// double-escapes it; that only happens in a Go *source* literal —
		// see TestWindowsPathLiteralFormsAreEquivalent).
		`C:\Users\kerwil\Desktop\capture.pcap`: "capture.pcap",
		"C:/Users/kerwil/Desktop/capture.pcap": "capture.pcap",
		"/home/kerwil/captures/capture.pcap":   "capture.pcap",
		"capture.pcap":                         "capture.pcap",
		`relative\dir\capture.pcap`:            "capture.pcap",
		"relative/dir/capture.pcap":            "capture.pcap",
		`\\server\share\capture.pcap`:          "capture.pcap", // UNC
		`C:\Users/kerwil\capture.pcap`:         "capture.pcap", // mixed separators
		"":                                     "",
	}
	for input, want := range cases {
		if got := basenameAnySeparator(input); got != want {
			t.Errorf("basenameAnySeparator(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestInvestigationAddPcapAllowsEmptySourceID(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	summary := correlation.PcapIncidentSummary{Summary: "ok", Level: model.LevelInfo, Confidence: 70}

	if _, err := s.InvestigationAddPcap(inv.ID, summary, "capture.pcap", "", ""); err != nil {
		t.Errorf("empty sourceID should be allowed, got %v", err)
	}
}

func TestInvestigationAddPcapAllowsOpaqueSourceID(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	summary := correlation.PcapIncidentSummary{Summary: "ok", Level: model.LevelInfo, Confidence: 70}

	for _, id := range []string{"session-123", "capture-abc", "11111111-1111-1111-1111-111111111111"} {
		if _, err := s.InvestigationAddPcap(inv.ID, summary, "capture.pcap", id, ""); err != nil {
			t.Errorf("sourceID=%q should be allowed, got %v", id, err)
		}
	}
}

func TestInvestigationAddPcapRejectsPathLikeSourceID(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	summary := correlation.PcapIncidentSummary{Summary: "ok", Level: model.LevelInfo, Confidence: 70}

	for _, id := range []string{
		`C:\Users\kerwil\Desktop\capture.pcap`,
		"/home/kerwil/capture.pcap",
		"C:",
		`relative\path`,
	} {
		if _, err := s.InvestigationAddPcap(inv.ID, summary, "capture.pcap", id, ""); err == nil {
			t.Errorf("sourceID=%q should be rejected as path-like", id)
		}
	}
}

// A rejected sourceID must never leave a partially-modified investigation
// behind — the rejection happens before AddSnapshot is ever called.
func TestInvestigationAddPcapRejectedSourceIDTouchesNothing(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	summary := correlation.PcapIncidentSummary{Summary: "ok", Level: model.LevelInfo, Confidence: 70}

	if _, err := s.InvestigationAddPcap(inv.ID, summary, "capture.pcap", `C:\Users\name\capture.pcap`, ""); err == nil {
		t.Fatal("expected the path-like sourceID to be rejected")
	}

	got, err := s.InvestigationGet(inv.ID)
	if err != nil {
		t.Fatalf("InvestigationGet: %v", err)
	}
	if len(got.Entries) != 0 {
		t.Errorf("expected no entries after a rejected AddPcap, got %d", len(got.Entries))
	}
}

func TestInvestigationAddMonitorEventStoresAdapterOutput(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	event := monitor.DegradationEvent{
		Time: "2026-01-01T12:00:00Z", Kind: "route_change", Detail: "Ruta cambió desde el salto 3",
		RouteChange: &monitor.RouteChange{
			ID: "rc-1", TargetID: "t-1", DetectedAt: "2026-01-01T12:00:00Z",
			FirstChangedTTL: 3, Confidence: 75,
		},
	}

	res, err := s.InvestigationAddMonitorEvent(inv.ID, event)
	if err != nil {
		t.Fatalf("InvestigationAddMonitorEvent: %v", err)
	}
	want, ok := monitor.ToSnapshot(event)
	if !ok {
		t.Fatal("expected monitor.ToSnapshot to accept this event")
	}
	entry := res.Entry
	if entry.Snapshot.Kind != want.Kind || entry.Snapshot.SourceID != want.SourceID || entry.Snapshot.Assessment.Conclusion != want.Assessment.Conclusion {
		t.Errorf("stored Snapshot = %+v, want exactly monitor.ToSnapshot(event) = %+v", entry.Snapshot, want)
	}
}

func TestInvestigationAddMonitorEventRejectsNonRouteChange(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	event := monitor.DegradationEvent{Time: "2026-01-01T12:00:00Z", Kind: "loss", Detail: "pérdida detectada"}
	if _, err := s.InvestigationAddMonitorEvent(inv.ID, event); err == nil {
		t.Error("expected an error for a non-route_change event (Phase E MVP scope)")
	}
}

func TestInvestigationAddVoIPCallStoresAdapterOutput(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	call := voip.Call{
		CallID: "call-1", From: "1000", To: "2000",
		Diagnosis: &model.Assessment{Conclusion: "603 Decline", Level: model.LevelMedium, Confidence: 80},
	}

	res, err := s.InvestigationAddVoIPCall(inv.ID, call)
	if err != nil {
		t.Fatalf("InvestigationAddVoIPCall: %v", err)
	}
	want, ok := voip.ToSnapshot(&call)
	if !ok {
		t.Fatal("expected voip.ToSnapshot to accept this call")
	}
	entry := res.Entry
	if entry.Snapshot.Assessment.Conclusion != want.Assessment.Conclusion || entry.Snapshot.SourceID != want.SourceID || entry.Snapshot.Subject != want.Subject {
		t.Errorf("stored Snapshot = %+v, want exactly voip.ToSnapshot(&call) = %+v", entry.Snapshot, want)
	}
}

func TestInvestigationAddVoIPCallRejectsCallWithoutDiagnosis(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	call := voip.Call{CallID: "call-1", From: "1000", To: "2000", Diagnosis: nil}
	if _, err := s.InvestigationAddVoIPCall(inv.ID, call); err == nil {
		t.Error("expected an error for a call with no Diagnosis yet")
	}
}

// A duplicate add must round-trip Existing=true through the wrapper DTO.
func TestInvestigationAddDuplicateReflectsExistingInWrapper(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("caso", "")
	call := voip.Call{
		CallID: "call-1", From: "1000", To: "2000",
		Diagnosis: &model.Assessment{Conclusion: "603 Decline", Level: model.LevelMedium, Confidence: 80},
	}
	first, err := s.InvestigationAddVoIPCall(inv.ID, call)
	if err != nil || first.Existing {
		t.Fatalf("first add: res=%+v err=%v", first, err)
	}
	second, err := s.InvestigationAddVoIPCall(inv.ID, call)
	if err != nil {
		t.Fatalf("second add: %v", err)
	}
	if !second.Existing {
		t.Error("expected Existing=true on the duplicate add")
	}
	if second.Entry.ID != first.Entry.ID {
		t.Error("expected the same Entry back on a duplicate add")
	}
}

func TestInvestigationEnrich_EmptyInvestigation(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("empty-case", "")

	res, err := s.InvestigationEnrich(inv.ID)
	if err != nil {
		t.Fatalf("InvestigationEnrich: %v", err)
	}
	if res.InvestigationID != inv.ID {
		t.Errorf("InvestigationID = %q, want %q", res.InvestigationID, inv.ID)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 for empty investigation", len(res.Findings))
	}
	if len(res.Correlations) != 0 {
		t.Errorf("Correlations = %d, want 0 for empty investigation", len(res.Correlations))
	}
	if len(res.Evidence) != 0 {
		t.Errorf("Evidence = %d, want 0 for empty investigation", len(res.Evidence))
	}
	if res.Stats.TotalFindings != 0 {
		t.Errorf("Stats.TotalFindings = %d, want 0", res.Stats.TotalFindings)
	}
	if len(res.EntryMapping) != 0 {
		t.Errorf("EntryMapping = %d, want 0 for empty investigation", len(res.EntryMapping))
	}
}

func TestInvestigationEnrich_ValidCase(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("enrich-test", "")

	summary := correlation.PcapIncidentSummary{
		Summary:    "Scan detected",
		Level:      model.LevelHigh,
		Confidence: 85,
		Findings: []correlation.PcapFinding{
			{ID: "f1", Category: "scan_vertical", Summary: "Vertical scan from 192.0.2.100", Level: model.LevelHigh, Confidence: 85, SourceArea: correlation.SourceAreaScanDetection},
		},
		Evidence: []model.Evidence{
			{Type: "scan", Value: "vertical", Source: "pcap", Provenance: model.ProvExternal, Timestamp: time.Now().UTC(), Confidence: 85, Explain: "Vertical scan detected"},
		},
	}
	s.InvestigationAddPcap(inv.ID, summary, "capture.pcap", "session-1", "2026-01-01T10:00:00Z")

	res, err := s.InvestigationEnrich(inv.ID)
	if err != nil {
		t.Fatalf("InvestigationEnrich: %v", err)
	}

	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	finding := res.Findings[0]
	if finding.Kind != "network" {
		t.Errorf("Finding.Kind = %q, want 'network'", finding.Kind)
	}
	if finding.EvidenceClass != investigation.EvidencePossibleContext {
		t.Errorf("Finding.EvidenceClass = %v, want EvidencePossibleContext", finding.EvidenceClass)
	}
	if len(res.Evidence[finding.ID]) != 1 {
		t.Errorf("Evidence count = %d, want 1", len(res.Evidence[finding.ID]))
	}

	// Stored investigation should be unchanged
	stored, _ := s.InvestigationGet(inv.ID)
	if len(stored.Entries) != 1 {
		t.Errorf("stored investigation modified: Entries = %d, want 1", len(stored.Entries))
	}
}

func TestInvestigationEnrich_NonexistentInvestigation(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	_, err := s.InvestigationEnrich("00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Error("expected error for nonexistent investigation")
	}
}

func TestInvestigationEnrich_CorruptInvestigation(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	// Test with invalid UUID format
	_, err := s.InvestigationEnrich("not-a-valid-uuid")
	if err == nil {
		t.Error("expected error for invalid UUID")
	}
}

func TestInvestigationEnrich_EmptyArraysSerializeSafely(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("empty-enrich", "")

	res, err := s.InvestigationEnrich(inv.ID)
	if err != nil {
		t.Fatalf("InvestigationEnrich: %v", err)
	}

	// Ensure empty slices/maps serialize as empty arrays/objects, not null
	// This tests JSON serialization safety for the frontend
	if res.Findings == nil {
		t.Error("Findings should be empty slice, not nil")
	}
	if res.Correlations == nil {
		t.Error("Correlations should be empty slice, not nil")
	}
	if res.Evidence == nil {
		t.Error("Evidence should be empty map, not nil")
	}
	if res.EntryMapping == nil {
		t.Error("EntryMapping should be empty map, not nil")
	}
	if res.Stats.BySourceKind == nil {
		t.Error("Stats.BySourceKind should be empty map, not nil")
	}
}

func TestInvestigationEnrich_StoredInvestigationUnchanged(t *testing.T) {
	s := newTestServiceWithInvestigations(t)
	inv, _ := s.InvestigationCreate("enrich-no-mutate", "")

	summary := correlation.PcapIncidentSummary{
		Summary:    "Test finding",
		Level:      model.LevelMedium,
		Confidence: 70,
	}
	s.InvestigationAddPcap(inv.ID, summary, "capture.pcap", "session-1", "2026-01-01T10:00:00Z")

	// Get original investigation
	before, _ := s.InvestigationGet(inv.ID)

	// Enrich
	_, err := s.InvestigationEnrich(inv.ID)
	if err != nil {
		t.Fatalf("InvestigationEnrich: %v", err)
	}

	// Stored investigation should be unchanged
	after, _ := s.InvestigationGet(inv.ID)
	if len(after.Entries) != 1 {
		t.Errorf("Entries = %d, want 1", len(after.Entries))
	}
	if after.UpdatedAt != before.UpdatedAt {
		t.Errorf("UpdatedAt changed from %q to %q — enrichment should not mutate stored investigation", before.UpdatedAt, after.UpdatedAt)
	}
}