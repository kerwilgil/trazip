package api

import (
	"fmt"
	"sort"

	"trazip/internal/correlation"
	"trazip/internal/detection/netdiag"
	"trazip/internal/detection/scandetect"
	"trazip/internal/model"
)

// Package placement note: TRAZIP V1's architecture puts correlation layers
// in internal/diagnosis so Diagnose/PCAP/Monitor/Investigation share one
// vocabulary — and this file does share that vocabulary (model.Assessment's
// shape, via correlation.PcapIncidentSummary/PcapFinding). It cannot
// physically LIVE in internal/diagnosis, though: internal/api already
// imports internal/diagnosis (RunDiagnose, Dependencies — see diagnose2.go),
// and the data this correlator needs — EndpointInfo/TalkerRow with their
// GeoIP/ASN enrichment — only exists as api's own DTOs, built by
// api.Service's enrichment methods (endpointsFromFlows/topTalkers) from
// engines internal/diagnosis has no reason to depend on. This file reuses
// the same model.Assessment/Evidence/Level/Confidence vocabulary regardless
// of which package it's compiled into.
//
// Phase E.0: PcapFinding, PcapSummaryStats and PcapIncidentSummary
// themselves moved to internal/correlation (a leaf package internal/
// investigation can import without depending on internal/api) — see that
// package's own doc comment. summarizePcap's correlation LOGIC stays here:
// it still needs api's own EndpointInfo/TalkerRow DTOs above, and moving
// the logic itself would require moving those too, which would be the kind
// of engine rewrite Phase C already ruled out. Only the persistable RESULT
// TYPE needed to move for Investigation to hold one.

// pcapFindingSeverity ranks PcapFinding.Level the same way correlate()'s own
// severity() does — kept as a separate, smaller copy here rather than a
// shared helper: this only ever compares model.Level values that netdiag/
// scandetect severities map onto (low/medium/high), never Critical or the
// diagnosis package's Warning/Problem/Unknown/Skipped vocabulary, so
// reusing that function would need translating through a vocabulary this
// package doesn't have.
func pcapFindingSeverity(l model.Level) int {
	switch l {
	case model.LevelCritical:
		return 4
	case model.LevelHigh:
		return 3
	case model.LevelMedium:
		return 2
	case model.LevelLow:
		return 1
	default: // model.LevelInfo
		return 0
	}
}

// severityStringToLevel maps netdiag/scandetect's own plain "low"/"medium"/
// "high" Severity strings onto the central model.Level vocabulary — never
// upgraded or downgraded, just translated, so this correlator never
// second-guesses a severity the originating detector already assigned
// (Phase C: "respetar confidence/severity existentes").
func severityStringToLevel(s string) model.Level {
	switch s {
	case "critical":
		return model.LevelCritical
	case "high":
		return model.LevelHigh
	case "medium":
		return model.LevelMedium
	case "low":
		return model.LevelLow
	default:
		return model.LevelInfo
	}
}

// summarizePcap correlates AnalyzePcap's already-computed results into one
// PcapIncidentSummary — the single entry point this file exists to provide.
func summarizePcap(res PcapResult) correlation.PcapIncidentSummary {
	var findings []correlation.PcapFinding

	for _, f := range res.NetDiag.Findings {
		findings = append(findings, netDiagFinding(f))
	}
	for _, f := range res.ScanDetection.Findings {
		findings = append(findings, scanFinding(f))
	}
	if f, ok := topTrafficFinding(res); ok {
		findings = append(findings, f)
	}
	findings = append(findings, protocolContextFindings(res)...)
	if f, ok := tcpResetsFinding(res); ok {
		findings = append(findings, f)
	}

	// Priority order: severity descending; ties keep the order findings
	// were appended above (L2 faults and scans — the actionable ones —
	// before context findings), which sort.SliceStable preserves (Phase C:
	// "Dentro de mismo nivel: hallazgos accionables primero.").
	sort.SliceStable(findings, func(i, j int) bool {
		return pcapFindingSeverity(findings[i].Level) > pcapFindingSeverity(findings[j].Level)
	})

	stats := pcapSummaryStats(res)
	summary, level, confidence := globalPcapAssessment(findings, stats)
	evidence, limitations := globalEvidenceAndLimitations(findings)

	return correlation.PcapIncidentSummary{
		Summary:     summary,
		Level:       level,
		Confidence:  confidence,
		Findings:    findings,
		Evidence:    evidence,
		Limitations: limitations,
		Stats:       stats,
	}
}

// globalEvidenceAndLimitations pools every ABOVE-Info finding's own
// Evidence/Limitations into the summary-level view (Phase C.1 fix #1),
// preserving findings' severity order (the caller has already sorted
// findings that way) and deduplicating both — the same netdiag finding can
// legitimately share an Evidence entry's wording with another, but the
// summary should only say it once.
func globalEvidenceAndLimitations(findings []correlation.PcapFinding) (evidence []model.Evidence, limitations []string) {
	seenEvidence := map[string]bool{}
	seenLimitation := map[string]bool{}
	for _, f := range findings {
		if pcapFindingSeverity(f.Level) == 0 { // Info: context, never backs a negative headline
			continue
		}
		for _, e := range f.Evidence {
			key := e.Type + "|" + e.Value + "|" + e.Explain
			if seenEvidence[key] {
				continue
			}
			seenEvidence[key] = true
			evidence = append(evidence, e)
		}
		for _, l := range f.Limitations {
			if seenLimitation[l] {
				continue
			}
			seenLimitation[l] = true
			limitations = append(limitations, l)
		}
	}
	return evidence, limitations
}

// netDiagFinding adapts one netdiag.Finding — reusing its own Severity/
// Confidence/Evidence rather than recomputing anything.
func netDiagFinding(f netdiag.Finding) correlation.PcapFinding {
	var evidence []model.Evidence
	for _, e := range f.Evidence {
		evidence = append(evidence, model.Evidence{
			Type: "netdiag_" + f.Kind, Value: e, Source: "netdiag",
			Provenance: model.ProvObserved, Confidence: model.Confidence(f.Confidence), Explain: f.Explain,
		})
	}
	var limitations []string
	if f.Caveat != "" {
		limitations = append(limitations, f.Caveat)
	}
	return correlation.PcapFinding{
		ID: f.ID, Category: f.Kind, Summary: f.Summary,
		Level: severityStringToLevel(f.Severity), Confidence: model.Confidence(f.Confidence),
		Evidence: evidence, Limitations: limitations, SourceArea: correlation.SourceAreaNetDiag,
	}
}

// scanFinding adapts one scandetect.Finding the same way.
func scanFinding(f scandetect.Finding) correlation.PcapFinding {
	evidence := []model.Evidence{{
		Type: "scan_" + f.Kind, Value: f.Summary, Source: "scandetect",
		Provenance: model.ProvObserved, Confidence: model.Confidence(f.Confidence), Explain: f.Explain,
	}}
	return correlation.PcapFinding{
		ID: f.ID, Category: "scan_" + f.Kind, Summary: f.Summary,
		Level: severityStringToLevel(f.Severity), Confidence: model.Confidence(f.Confidence),
		Evidence: evidence, SourceArea: correlation.SourceAreaScanDetection,
	}
}

// topTrafficFinding is context, never an anomaly: high transfer volume by
// itself proves nothing (Phase C false-positive policy). Always Info.
func topTrafficFinding(res PcapResult) (correlation.PcapFinding, bool) {
	if len(res.TopHosts) == 0 {
		return correlation.PcapFinding{}, false
	}
	top := res.TopHosts[0]
	label := top.Label
	if label == "" {
		label = top.Key
	}
	summary := fmt.Sprintf("Host de mayor tráfico: %s (%d paquetes)", label, top.Packets)
	return correlation.PcapFinding{
		ID: "top_traffic", Category: "top_traffic", Summary: summary,
		Level: model.LevelInfo, Confidence: 70,
		Evidence: []model.Evidence{{
			Type: "top_talker", Value: label, Source: "flow",
			Provenance: model.ProvObserved, Confidence: 70,
			Explain: "Mayor volumen de paquetes observado en la captura — no implica, por sí solo, un problema.",
		}},
		SourceArea: correlation.SourceAreaFlows,
	}, true
}

// protocolContextFindings surfaces detected application protocols as
// context, never as a finding with severity (Phase C: "Esto es contexto, no
// problema."). SIP gets its own entry since it's the one protocol V1
// already has a dedicated deeper analysis for (VoIP Calls).
func protocolContextFindings(res PcapResult) []correlation.PcapFinding {
	apps := map[string]int{}
	for _, fl := range res.Flows {
		for _, a := range fl.Apps {
			apps[a]++
		}
	}
	if len(apps) == 0 {
		return nil
	}
	var names []string
	for a := range apps {
		names = append(names, a)
	}
	sort.Strings(names)

	var out []correlation.PcapFinding
	if apps["SIP"] > 0 {
		out = append(out, correlation.PcapFinding{
			ID: "protocol_sip", Category: "protocol_context",
			Summary: fmt.Sprintf("Tráfico SIP detectado en %d flujo(s) — ver VoIP Calls para el detalle de las llamadas.", apps["SIP"]),
			Level:   model.LevelInfo, Confidence: 80,
			Evidence: []model.Evidence{{
				Type: "protocol_sip", Value: fmt.Sprintf("%d flujo(s)", apps["SIP"]), Source: "flow",
				Provenance: model.ProvObserved, Confidence: 80,
				Explain: "Señalización SIP identificada por puerto/patrón en los flujos agregados — el número exacto de llamadas requiere el análisis VoIP dedicado.",
			}},
			SourceArea: correlation.SourceAreaPackets,
		})
	}
	other := make([]string, 0, len(names))
	for _, a := range names {
		if a != "SIP" {
			other = append(other, a)
		}
	}
	if len(other) > 0 {
		out = append(out, correlation.PcapFinding{
			ID: "protocol_context", Category: "protocol_context",
			Summary: "Protocolos observados: " + joinComma(other),
			Level:   model.LevelInfo, Confidence: 70,
			SourceArea: correlation.SourceAreaFlows,
		})
	}
	return out
}

// tcpResetsFinding is context only: TRAZIP has no established, tested
// threshold for "too many resets" (Phase C: "NO inventar umbrales nuevos
// arbitrarios. Si no existe una semántica madura... mostrar como
// INFO/contexto."), so this only ever reports the count, never a severity.
func tcpResetsFinding(res PcapResult) (correlation.PcapFinding, bool) {
	total := 0
	for _, fl := range res.Flows {
		total += fl.Resets
	}
	if total == 0 {
		return correlation.PcapFinding{}, false
	}
	return correlation.PcapFinding{
		ID: "tcp_resets", Category: "tcp_resets",
		Summary: fmt.Sprintf("%d reset(s) TCP observados en la captura", total),
		Level:   model.LevelInfo, Confidence: 80,
		Evidence: []model.Evidence{{
			Type: "tcp_resets", Value: fmt.Sprintf("%d", total), Source: "flow",
			Provenance: model.ProvObserved, Confidence: 80,
			Explain: "Conteo de flujos terminados con RST — TRAZIP no declara un umbral de \"demasiados\" resets; revisar los flujos específicos para contexto.",
		}},
		SourceArea: correlation.SourceAreaFlows,
	}, true
}

func hasClass(classes []string, want string) bool {
	for _, c := range classes {
		if c == want {
			return true
		}
	}
	return false
}

func pcapSummaryStats(res PcapResult) correlation.PcapSummaryStats {
	stats := correlation.PcapSummaryStats{
		Packets: res.TotalPackets, Flows: res.TotalFlows, Endpoints: res.TotalEndpoints,
		GeoAvailable: res.GeoAvailable,
	}
	for _, ep := range res.Endpoints {
		switch {
		case hasClass(ep.Classes, "public"):
			stats.PublicEndpoints++
		case hasClass(ep.Classes, "private"):
			stats.PrivateEndpoints++
		default:
			// loopback, link_local, multicast, reserved, documentation,
			// bogon, or no classification at all — a real, distinct
			// category classify.Classify already assigned, never smeared
			// into "private" by default (Phase C.1 fix #2).
			stats.OtherEndpoints++
		}
	}
	for _, fl := range res.Flows {
		for _, a := range fl.Apps {
			if a == "SIP" {
				stats.SIPDetected = true
			}
		}
		stats.TCPResets += fl.Resets
	}
	if len(res.TopHosts) > 0 {
		if res.TopHosts[0].Label != "" {
			stats.TopTalker = res.TopHosts[0].Label
		} else {
			stats.TopTalker = res.TopHosts[0].Key
		}
	}
	if len(res.TopASN) > 0 {
		top := res.TopASN[0]
		if top.Org != "" {
			stats.TopASN = fmt.Sprintf("AS%d %s", top.ASN, top.Org)
		} else if top.Label != "" {
			stats.TopASN = top.Label
		}
	}
	return stats
}

// globalPcapAssessment reduces every finding into one headline — honestly:
// no findings means "nothing found with the available engines", never "the
// network is perfect" (Phase C: 'no "Red saludable al 100%."').
func globalPcapAssessment(findings []correlation.PcapFinding, stats correlation.PcapSummaryStats) (summary string, level model.Level, confidence model.Confidence) {
	var top *correlation.PcapFinding
	for i := range findings {
		if pcapFindingSeverity(findings[i].Level) > 0 { // above Info
			top = &findings[i]
			break // findings is already sorted by severity descending
		}
	}
	if top == nil {
		return fmt.Sprintf(
			"No se detectaron anomalías de alta confianza en los motores disponibles. La captura contiene %d flujos y %d endpoints.",
			stats.Flows, stats.Endpoints,
		), model.LevelInfo, 75
	}

	switch top.Level {
	case model.LevelCritical, model.LevelHigh:
		summary = fmt.Sprintf("Se detectó %s; es el hallazgo principal de esta captura.", lowerFirst(top.Summary))
	default:
		summary = fmt.Sprintf("Hallazgo a revisar: %s.", lowerFirst(top.Summary))
	}
	return summary, top.Level, top.Confidence
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'A' && r[0] <= 'Z' {
		r[0] = r[0] + ('a' - 'A')
	}
	return string(r)
}

func joinComma(items []string) string {
	out := items[0]
	for _, s := range items[1:] {
		out += ", " + s
	}
	return out
}
