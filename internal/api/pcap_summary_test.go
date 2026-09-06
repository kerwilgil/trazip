package api

import (
	"strings"
	"testing"

	"trazip/internal/correlation"
	"trazip/internal/detection/netdiag"
	"trazip/internal/detection/scandetect"
	"trazip/internal/flow"
	"trazip/internal/model"
)

// These tests drive summarizePcap directly with hand-built PcapResult
// fixtures — deterministic, no real PCAP file — per Phase C's own
// requirement ("NO depender de PCAP privada real en unit tests").

func findFinding(findings []correlation.PcapFinding, id string) (correlation.PcapFinding, bool) {
	for _, f := range findings {
		if f.ID == id {
			return f, true
		}
	}
	return correlation.PcapFinding{}, false
}

// 1. Empty/minimal capture result: must not panic, must report Info with
// honest (zero) counts, never fabricate a finding.
func TestSummarizePcapEmptyResult(t *testing.T) {
	sum := summarizePcap(PcapResult{})
	if sum.Level != model.LevelInfo {
		t.Errorf("Level = %q, want informativo for an empty capture", sum.Level)
	}
	if len(sum.Findings) != 0 {
		t.Errorf("Findings = %+v, want none for an empty capture", sum.Findings)
	}
	if !strings.Contains(sum.Summary, "0 flujos") {
		t.Errorf("Summary = %q, want it to honestly report 0 flows", sum.Summary)
	}
}

// 2. Clean capture: flows/endpoints exist, no engine findings — Info, and
// the summary must name the real counts, never claim perfection.
func TestSummarizePcapCleanCapture(t *testing.T) {
	res := PcapResult{
		TotalFlows: 83, TotalEndpoints: 27,
		Flows: []flow.Flow{{Proto: "tcp", Packets: 100}},
	}
	sum := summarizePcap(res)
	if sum.Level != model.LevelInfo {
		t.Errorf("Level = %q, want informativo for a clean capture", sum.Level)
	}
	if !strings.Contains(sum.Summary, "83 flujos") || !strings.Contains(sum.Summary, "27 endpoints") {
		t.Errorf("Summary = %q, want it to cite the real flow/endpoint counts", sum.Summary)
	}
	for _, forbidden := range []string{"100%", "perfecta", "saludable al 100"} {
		if strings.Contains(sum.Summary, forbidden) {
			t.Errorf("Summary must never overclaim health: contains %q in %q", forbidden, sum.Summary)
		}
	}
}

// 3. Duplicate IP finding: netdiag's own severity/confidence carried
// through unchanged, correct SourceArea.
func TestSummarizePcapDuplicateIPFinding(t *testing.T) {
	res := PcapResult{
		NetDiag: netdiag.Result{Findings: []netdiag.Finding{{
			ID: "dupip:192.168.1.20", Kind: "duplicate_ip", Severity: "high", Confidence: 85,
			Subject: "192.168.1.20", Summary: "2 MAC distintas reclaman la IP 192.168.1.20",
			Evidence: []string{"aa:bb reclamó", "cc:dd reclamó"},
		}}},
	}
	sum := summarizePcap(res)
	f, ok := findFinding(sum.Findings, "dupip:192.168.1.20")
	if !ok {
		t.Fatal("expected the duplicate_ip finding to be present")
	}
	if f.Level != model.LevelHigh {
		t.Errorf("Level = %q, want alto", f.Level)
	}
	if f.Confidence != 85 {
		t.Errorf("Confidence = %d, want 85 (netdiag's own)", f.Confidence)
	}
	if f.SourceArea != correlation.SourceAreaNetDiag {
		t.Errorf("SourceArea = %q, want netdiag", f.SourceArea)
	}
	if sum.Level != model.LevelHigh {
		t.Errorf("global Level = %q, want alto driven by the duplicate IP finding", sum.Level)
	}
	if !strings.Contains(strings.ToLower(sum.Summary), "hallazgo principal") {
		t.Errorf("Summary = %q, want it to name this as the main finding", sum.Summary)
	}
}

// 4. Broadcast storm finding.
func TestSummarizePcapBroadcastStorm(t *testing.T) {
	res := PcapResult{
		NetDiag: netdiag.Result{Findings: []netdiag.Finding{{
			ID: "storm:aa:bb:cc", Kind: "broadcast_storm", Severity: "high", Confidence: 85,
			Summary: "aa:bb:cc emite 120 broadcasts por segundo",
		}}},
	}
	sum := summarizePcap(res)
	f, ok := findFinding(sum.Findings, "storm:aa:bb:cc")
	if !ok {
		t.Fatal("expected the broadcast_storm finding to be present")
	}
	if f.Category != "broadcast_storm" || f.SourceArea != correlation.SourceAreaNetDiag {
		t.Errorf("finding = %+v, unexpected category/source area", f)
	}
}

// 5. Scan detection finding: correct SourceArea, category prefixed for the
// unified taxonomy.
func TestSummarizePcapScanDetectionFinding(t *testing.T) {
	res := PcapResult{
		ScanDetection: scandetect.Result{Findings: []scandetect.Finding{{
			ID: "scan:10.0.0.5", Kind: "horizontal", Severity: "medium", Confidence: 82,
			Summary: "10.0.0.5 escaneó 40 hosts distintos en el puerto 22",
		}}},
	}
	sum := summarizePcap(res)
	f, ok := findFinding(sum.Findings, "scan:10.0.0.5")
	if !ok {
		t.Fatal("expected the scan finding to be present")
	}
	if f.Category != "scan_horizontal" {
		t.Errorf("Category = %q, want scan_horizontal", f.Category)
	}
	if f.SourceArea != correlation.SourceAreaScanDetection {
		t.Errorf("SourceArea = %q, want scan_detection", f.SourceArea)
	}
	if f.Level != model.LevelMedium {
		t.Errorf("Level = %q, want medio (scandetect's own severity)", f.Level)
	}
}

// 6. Multiple simultaneous findings: all survive into Findings, none lost,
// and the global summary picks the single most severe one.
func TestSummarizePcapMultipleSimultaneousFindings(t *testing.T) {
	res := PcapResult{
		TotalFlows: 10, TotalEndpoints: 5,
		NetDiag: netdiag.Result{Findings: []netdiag.Finding{
			{ID: "dupip:1", Kind: "duplicate_ip", Severity: "high", Confidence: 85, Summary: "conflicto de IP"},
		}},
		ScanDetection: scandetect.Result{Findings: []scandetect.Finding{
			{ID: "scan:1", Kind: "vertical", Severity: "medium", Confidence: 80, Summary: "escaneo vertical"},
		}},
		TopHosts: []TalkerRow{{Key: "10.0.0.5", Label: "10.0.0.5", Packets: 500}},
	}
	sum := summarizePcap(res)
	if len(sum.Findings) < 3 {
		t.Fatalf("Findings = %+v, want at least 3 (duplicate IP + scan + top traffic)", sum.Findings)
	}
	if _, ok := findFinding(sum.Findings, "dupip:1"); !ok {
		t.Error("expected the duplicate_ip finding to survive")
	}
	if _, ok := findFinding(sum.Findings, "scan:1"); !ok {
		t.Error("expected the scan finding to survive")
	}
	if _, ok := findFinding(sum.Findings, "top_traffic"); !ok {
		t.Error("expected the top_traffic context finding to survive")
	}
	if sum.Level != model.LevelHigh {
		t.Errorf("global Level = %q, want alto (the most severe of the three)", sum.Level)
	}
}

// 7. Severity ordering: findings appended out of order must come back
// sorted by severity descending.
func TestSummarizePcapSeverityOrdering(t *testing.T) {
	res := PcapResult{
		NetDiag: netdiag.Result{Findings: []netdiag.Finding{
			{ID: "low1", Kind: "loop", Severity: "medium", Confidence: 55, Summary: "loop débil"},
			{ID: "high1", Kind: "duplicate_ip", Severity: "high", Confidence: 85, Summary: "conflicto de IP"},
		}},
		TopHosts: []TalkerRow{{Key: "x", Label: "x", Packets: 1}}, // Info-level top_traffic
	}
	sum := summarizePcap(res)
	if len(sum.Findings) < 3 {
		t.Fatalf("expected at least 3 findings, got %+v", sum.Findings)
	}
	for i := 1; i < len(sum.Findings); i++ {
		if pcapFindingSeverity(sum.Findings[i-1].Level) < pcapFindingSeverity(sum.Findings[i].Level) {
			t.Fatalf("Findings not sorted by severity descending: %+v", sum.Findings)
		}
	}
	if sum.Findings[0].ID != "high1" {
		t.Errorf("Findings[0].ID = %q, want the high-severity finding first", sum.Findings[0].ID)
	}
}

// 8. High traffic but no anomaly: volume alone must never elevate severity
// (false-positive policy).
func TestSummarizePcapHighTrafficNoAnomaly(t *testing.T) {
	res := PcapResult{
		TotalFlows: 500, TotalEndpoints: 200,
		TopHosts: []TalkerRow{{Key: "1.2.3.4", Label: "1.2.3.4", Packets: 1_000_000, Bytes: 5_000_000_000}},
	}
	sum := summarizePcap(res)
	if sum.Level != model.LevelInfo {
		t.Errorf("Level = %q, want informativo — high traffic volume alone must never be an anomaly", sum.Level)
	}
	f, ok := findFinding(sum.Findings, "top_traffic")
	if !ok || f.Level != model.LevelInfo {
		t.Errorf("top_traffic finding = %+v, want Level informativo regardless of volume", f)
	}
}

// 9. SIP present must always be Info-only context, regardless of how much
// SIP traffic there is.
func TestSummarizePcapSIPPresentIsInfoOnly(t *testing.T) {
	flows := make([]flow.Flow, 0, 50)
	for i := 0; i < 50; i++ {
		flows = append(flows, flow.Flow{Proto: "udp", Apps: []string{"SIP"}})
	}
	res := PcapResult{Flows: flows}
	sum := summarizePcap(res)
	f, ok := findFinding(sum.Findings, "protocol_sip")
	if !ok {
		t.Fatal("expected a protocol_sip context finding")
	}
	if f.Level != model.LevelInfo {
		t.Errorf("Level = %q, want informativo regardless of SIP flow volume", f.Level)
	}
	if sum.Level != model.LevelInfo {
		t.Errorf("global Level = %q, want informativo — SIP volume alone must never drive severity", sum.Level)
	}
	if !sum.Stats.SIPDetected {
		t.Error("Stats.SIPDetected should be true")
	}
}

// 10. Missing Geo/ASN: must not crash or fabricate ASN/geo info when
// GeoAvailable is false and endpoints/top ASN carry no enrichment.
func TestSummarizePcapMissingGeoASN(t *testing.T) {
	res := PcapResult{
		GeoAvailable: false,
		Endpoints:    []EndpointInfo{{Addr: "10.0.0.5", Classes: []string{"private"}}},
		TopASN:       nil,
	}
	sum := summarizePcap(res)
	if sum.Stats.GeoAvailable {
		t.Error("Stats.GeoAvailable should reflect the real false value")
	}
	if sum.Stats.TopASN != "" {
		t.Errorf("Stats.TopASN = %q, want empty when no ASN data exists", sum.Stats.TopASN)
	}
	if sum.Stats.PrivateEndpoints != 1 || sum.Stats.PublicEndpoints != 0 {
		t.Errorf("Stats = %+v, want 1 private/0 public endpoint", sum.Stats)
	}
}

// 11. Limitations preserved: a netdiag Caveat must survive into the
// PcapFinding's own Limitations.
func TestSummarizePcapLimitationsPreserved(t *testing.T) {
	res := PcapResult{
		NetDiag: netdiag.Result{Findings: []netdiag.Finding{{
			ID: "dupip:1", Kind: "duplicate_ip", Severity: "high", Confidence: 85,
			Summary: "conflicto de IP",
			Caveat:  "Una captura no distingue un conflicto de direcciones por configuración de un envenenamiento ARP deliberado.",
		}}},
	}
	sum := summarizePcap(res)
	f, ok := findFinding(sum.Findings, "dupip:1")
	if !ok {
		t.Fatal("expected the finding to be present")
	}
	if len(f.Limitations) != 1 || !strings.Contains(f.Limitations[0], "envenenamiento ARP") {
		t.Errorf("Limitations = %v, want the netdiag Caveat preserved", f.Limitations)
	}
}

// 12. Confidence preserved: netdiag/scandetect's own Confidence must carry
// through unchanged, never recomputed.
func TestSummarizePcapConfidencePreserved(t *testing.T) {
	res := PcapResult{
		NetDiag: netdiag.Result{Findings: []netdiag.Finding{
			{ID: "loop:1", Kind: "loop", Severity: "medium", Confidence: 55, Summary: "loop débil"},
		}},
		ScanDetection: scandetect.Result{Findings: []scandetect.Finding{
			{ID: "scan:1", Kind: "vertical", Severity: "high", Confidence: 95, Summary: "escaneo agresivo"},
		}},
	}
	sum := summarizePcap(res)
	loop, ok := findFinding(sum.Findings, "loop:1")
	if !ok || loop.Confidence != 55 {
		t.Errorf("loop finding Confidence = %v, want 55 unchanged", loop)
	}
	scan, ok := findFinding(sum.Findings, "scan:1")
	if !ok || scan.Confidence != 95 {
		t.Errorf("scan finding Confidence = %v, want 95 unchanged", scan)
	}
}

// --- Phase C.1 fix #1: global Evidence/Limitations self-sufficiency ---

// A high finding must leave the global Evidence non-empty.
func TestSummarizePcapGlobalEvidenceNonEmptyForHighFinding(t *testing.T) {
	res := PcapResult{
		NetDiag: netdiag.Result{Findings: []netdiag.Finding{{
			ID: "dupip:1", Kind: "duplicate_ip", Severity: "high", Confidence: 85,
			Summary: "conflicto de IP", Evidence: []string{"aa:bb reclamó 192.168.1.20"},
		}}},
	}
	sum := summarizePcap(res)
	if len(sum.Evidence) == 0 {
		t.Fatal("global Evidence should not be empty when a high finding exists")
	}
	if sum.Evidence[0].Value != "aa:bb reclamó 192.168.1.20" {
		t.Errorf("global Evidence = %+v, want the high finding's own evidence", sum.Evidence)
	}
}

// A finding's Caveat must survive into the global Limitations.
func TestSummarizePcapGlobalLimitationsPreserveCaveat(t *testing.T) {
	res := PcapResult{
		NetDiag: netdiag.Result{Findings: []netdiag.Finding{{
			ID: "dupip:1", Kind: "duplicate_ip", Severity: "high", Confidence: 85,
			Summary: "conflicto de IP",
			Caveat:  "Una captura no distingue un conflicto de direcciones por configuración de un envenenamiento ARP deliberado.",
		}}},
	}
	sum := summarizePcap(res)
	found := false
	for _, l := range sum.Limitations {
		if strings.Contains(l, "envenenamiento ARP") {
			found = true
		}
	}
	if !found {
		t.Errorf("global Limitations = %v, want the finding's caveat preserved", sum.Limitations)
	}
}

// Multiple above-Info findings must both contribute their own evidence to
// the global Evidence — none silently dropped.
func TestSummarizePcapGlobalEvidenceFromMultipleFindings(t *testing.T) {
	res := PcapResult{
		NetDiag: netdiag.Result{Findings: []netdiag.Finding{
			{ID: "dupip:1", Kind: "duplicate_ip", Severity: "high", Confidence: 85, Summary: "conflicto de IP", Evidence: []string{"evidencia dupip"}},
		}},
		ScanDetection: scandetect.Result{Findings: []scandetect.Finding{
			{ID: "scan:1", Kind: "vertical", Severity: "medium", Confidence: 80, Summary: "escaneo vertical", Explain: "evidencia scan"},
		}},
	}
	sum := summarizePcap(res)
	hasDupip, hasScan := false, false
	for _, e := range sum.Evidence {
		if e.Value == "evidencia dupip" {
			hasDupip = true
		}
		if strings.Contains(e.Explain, "evidencia scan") {
			hasScan = true
		}
	}
	if !hasDupip || !hasScan {
		t.Errorf("global Evidence = %+v, want evidence from BOTH findings", sum.Evidence)
	}
}

// An Info-only capture must never fabricate "health" evidence.
func TestSummarizePcapGlobalEvidenceEmptyWhenInfoOnly(t *testing.T) {
	res := PcapResult{
		TotalFlows: 10, TotalEndpoints: 5,
		TopHosts: []TalkerRow{{Key: "1.2.3.4", Label: "1.2.3.4", Packets: 100}},
	}
	sum := summarizePcap(res)
	if len(sum.Evidence) != 0 {
		t.Errorf("global Evidence = %+v, want empty for an Info-only capture — never fabricate health evidence", sum.Evidence)
	}
	if len(sum.Limitations) != 0 {
		t.Errorf("global Limitations = %v, want empty for an Info-only capture", sum.Limitations)
	}
}

// --- Phase C.1 fix #2: endpoint counts (public/private/other) ---

func endpointWithClass(class string) EndpointInfo {
	return EndpointInfo{Addr: "x", Classes: []string{class}}
}

func TestPcapSummaryStatsEndpointCountsPublic(t *testing.T) {
	stats := pcapSummaryStats(PcapResult{Endpoints: []EndpointInfo{endpointWithClass("public")}})
	if stats.PublicEndpoints != 1 || stats.PrivateEndpoints != 0 || stats.OtherEndpoints != 0 {
		t.Errorf("stats = %+v, want 1 public/0 private/0 other", stats)
	}
}

func TestPcapSummaryStatsEndpointCountsPrivate(t *testing.T) {
	stats := pcapSummaryStats(PcapResult{Endpoints: []EndpointInfo{endpointWithClass("private")}})
	if stats.PrivateEndpoints != 1 || stats.PublicEndpoints != 0 || stats.OtherEndpoints != 0 {
		t.Errorf("stats = %+v, want 1 private/0 public/0 other", stats)
	}
}

func TestPcapSummaryStatsEndpointCountsLoopback(t *testing.T) {
	stats := pcapSummaryStats(PcapResult{Endpoints: []EndpointInfo{endpointWithClass("loopback")}})
	if stats.OtherEndpoints != 1 {
		t.Errorf("stats = %+v, want loopback counted as other, never private", stats)
	}
	if stats.PrivateEndpoints != 0 {
		t.Errorf("stats.PrivateEndpoints = %d, loopback must never be miscounted as private", stats.PrivateEndpoints)
	}
}

func TestPcapSummaryStatsEndpointCountsLinkLocal(t *testing.T) {
	stats := pcapSummaryStats(PcapResult{Endpoints: []EndpointInfo{endpointWithClass("link_local")}})
	if stats.OtherEndpoints != 1 || stats.PrivateEndpoints != 0 {
		t.Errorf("stats = %+v, want link-local counted as other, never private", stats)
	}
}

func TestPcapSummaryStatsEndpointCountsReserved(t *testing.T) {
	stats := pcapSummaryStats(PcapResult{Endpoints: []EndpointInfo{endpointWithClass("reserved")}})
	if stats.OtherEndpoints != 1 || stats.PrivateEndpoints != 0 {
		t.Errorf("stats = %+v, want reserved counted as other, never private", stats)
	}
}

func TestPcapSummaryStatsEndpointCountsMixed(t *testing.T) {
	res := PcapResult{Endpoints: []EndpointInfo{
		endpointWithClass("public"), endpointWithClass("public"),
		endpointWithClass("private"),
		endpointWithClass("loopback"), endpointWithClass("bogon"), endpointWithClass("multicast"),
	}}
	stats := pcapSummaryStats(res)
	if stats.PublicEndpoints != 2 {
		t.Errorf("PublicEndpoints = %d, want 2", stats.PublicEndpoints)
	}
	if stats.PrivateEndpoints != 1 {
		t.Errorf("PrivateEndpoints = %d, want 1", stats.PrivateEndpoints)
	}
	if stats.OtherEndpoints != 3 {
		t.Errorf("OtherEndpoints = %d, want 3 (loopback+bogon+multicast)", stats.OtherEndpoints)
	}
	total := stats.PublicEndpoints + stats.PrivateEndpoints + stats.OtherEndpoints
	if total != len(res.Endpoints) {
		t.Errorf("counted %d endpoints total, want %d (every endpoint must land in exactly one bucket)", total, len(res.Endpoints))
	}
}

// V1 hardening finding #3: PcapIncidentSummary must be built from the FULL
// analysis, never from whatever survives the Wails UI payload caps.
// AnalyzePcap's real order is: build the full-data PcapResult, call
// summarizePcap(res), THEN applyPcapUILimits(&res) — these tests drive
// that exact sequence directly on a hand-built PcapResult, per Phase C's
// own "no depender de PCAP real" convention, rather than generating a
// multi-thousand-packet capture file.

// A "late" flow/endpoint sits past the UI cap by construction, so the
// summary can only see it if it was computed before truncation.

func TestApplyPcapUILimitsCapsFlowsButSummarySeesAllOfThem(t *testing.T) {
	flows := make([]flow.Flow, 0, flowUILimit+5)
	for i := 0; i < flowUILimit+5; i++ {
		flows = append(flows, flow.Flow{Proto: "tcp", Packets: 1})
	}
	// A flow past the UI cap carries evidence that must still reach the
	// summary: SIP traffic and a TCP reset.
	flows = append(flows, flow.Flow{Proto: "tcp", Packets: 1, Apps: []string{"SIP"}, Resets: 3})

	res := PcapResult{Flows: flows, TotalFlows: len(flows)}
	res.Summary = summarizePcap(res) // must run on the FULL slice
	applyPcapUILimits(&res)

	if len(res.Flows) != flowUILimit {
		t.Fatalf("len(res.Flows) = %d, want capped at flowUILimit=%d", len(res.Flows), flowUILimit)
	}
	if res.TotalFlows != len(flows) {
		t.Errorf("TotalFlows = %d, want the true uncapped count %d", res.TotalFlows, len(flows))
	}
	if res.Summary.Stats.Flows != res.TotalFlows {
		t.Errorf("Summary.Stats.Flows = %d, want %d (== TotalFlows)", res.Summary.Stats.Flows, res.TotalFlows)
	}
	if !res.Summary.Stats.SIPDetected {
		t.Error("Summary.Stats.SIPDetected = false, want true — the late SIP flow must still be visible to the summary")
	}
	if res.Summary.Stats.TCPResets != 3 {
		t.Errorf("Summary.Stats.TCPResets = %d, want 3 from the late flow", res.Summary.Stats.TCPResets)
	}
}

func TestApplyPcapUILimitsCapsEndpointsButSummaryReconciles(t *testing.T) {
	endpoints := make([]EndpointInfo, 0, endpointUILimit+7)
	for i := 0; i < endpointUILimit; i++ {
		endpoints = append(endpoints, endpointWithClass("public"))
	}
	for i := 0; i < 5; i++ {
		endpoints = append(endpoints, endpointWithClass("private"))
	}
	for i := 0; i < 2; i++ {
		endpoints = append(endpoints, endpointWithClass("bogon"))
	}

	res := PcapResult{Endpoints: endpoints, TotalEndpoints: len(endpoints)}
	res.Summary = summarizePcap(res) // must run on the FULL slice
	applyPcapUILimits(&res)

	if len(res.Endpoints) != endpointUILimit {
		t.Fatalf("len(res.Endpoints) = %d, want capped at endpointUILimit=%d", len(res.Endpoints), endpointUILimit)
	}
	if res.TotalEndpoints != len(endpoints) {
		t.Errorf("TotalEndpoints = %d, want the true uncapped count %d", res.TotalEndpoints, len(endpoints))
	}
	if res.Summary.Stats.Endpoints != res.TotalEndpoints {
		t.Errorf("Summary.Stats.Endpoints = %d, want %d (== TotalEndpoints)", res.Summary.Stats.Endpoints, res.TotalEndpoints)
	}
	reconciled := res.Summary.Stats.PublicEndpoints + res.Summary.Stats.PrivateEndpoints + res.Summary.Stats.OtherEndpoints
	if reconciled != res.TotalEndpoints {
		t.Errorf("Public(%d)+Private(%d)+Other(%d) = %d, want %d (== TotalEndpoints, every endpoint classified)",
			res.Summary.Stats.PublicEndpoints, res.Summary.Stats.PrivateEndpoints, res.Summary.Stats.OtherEndpoints, reconciled, res.TotalEndpoints)
	}
}
