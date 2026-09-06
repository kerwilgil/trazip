package diagnosis

import (
	"strings"
	"testing"

	"trazip/internal/model"
)

// These tests drive correlate() directly with hand-built stage fixtures —
// deterministic by construction, unlike the stage runners that touch the
// network — so they can safely run under `go test -count=20` per the
// master plan's own validation gate, and each one pins down one of the
// specific correlation rules the master plan calls out by name.

func skippedStage(id string) DiagnosticStage {
	return DiagnosticStage{ID: id, Status: StageSkipped, Summary: "skipped"}
}

// A. DNS falla → problema de resolución observado, not silently ignored.
func TestCorrelateDNSFailureIsTheHeadline(t *testing.T) {
	stages := []DiagnosticStage{
		{ID: StageIDResolution, Status: StageProblem, Summary: `No se pudo resolver "no-existe.invalid": no such host`},
		skippedStage(StageIDReachability), skippedStage(StageIDRoute),
		skippedStage(StageIDOwnership), skippedStage(StageIDRoutingSecurity),
		skippedStage(StageIDTLS), skippedStage(StageIDHTTP), skippedStage(StageIDReputation),
	}
	summary, level, _, _, _, _ := correlate(stages, resolvedTarget{kind: "host"}, false)
	if level != model.LevelMedium {
		t.Errorf("Level = %q, want medio for an explicit DNS resolution failure", level)
	}
	if !strings.Contains(summary, "resolver") {
		t.Errorf("Summary should describe the resolution failure: %q", summary)
	}
}

// B. DNS OK + ping sin respuesta must NOT read as a confirmed outage — the
// master plan is explicit that ICMP filtering is not proof of unavailability.
func TestCorrelatePingTimeoutIsHedgedNotDown(t *testing.T) {
	pingLimitation := "ICMP sin respuesta; no demuestra indisponibilidad del servicio — puede estar filtrado por firewall/NAT sin afectar el tráfico real."
	stages := []DiagnosticStage{
		{ID: StageIDResolution, Status: StageOK, Summary: "resolved"},
		{ID: StageIDReachability, Status: StageWarning, Summary: "Sin respuesta ICMP.", Limitations: []string{pingLimitation}},
		skippedStage(StageIDRoute), skippedStage(StageIDOwnership), skippedStage(StageIDRoutingSecurity),
		skippedStage(StageIDTLS), skippedStage(StageIDHTTP), skippedStage(StageIDReputation),
	}
	summary, level, _, _, _, limitations := correlate(stages, resolvedTarget{kind: "host"}, true)
	if level == model.LevelHigh || level == model.LevelMedium {
		t.Errorf("Level = %q, an unanswered ping alone must never read as a confirmed/serious outage", level)
	}
	if strings.Contains(strings.ToLower(summary), "caíd") || strings.Contains(strings.ToLower(summary), "indisponible") {
		t.Errorf("Summary must never assert the host is down/unavailable from ICMP alone: %q", summary)
	}
	found := false
	for _, l := range limitations {
		if l == pingLimitation {
			found = true
		}
	}
	if !found {
		t.Error("expected the ICMP-filtering limitation to survive into the global report")
	}
}

// C. TLS válido + HTTP 200 → conclusión de servicio web accesible, Level Info.
func TestCorrelateTLSAndHTTPOKMeansAccessible(t *testing.T) {
	stages := []DiagnosticStage{
		{ID: StageIDResolution, Status: StageOK, Summary: "resolved"},
		{ID: StageIDReachability, Status: StageOK, Summary: "Responde a ICMP, RTT promedio 12.0ms."},
		{ID: StageIDRoute, Status: StageOK, Summary: "Ruta alcanza el destino en 8 saltos."},
		{ID: StageIDOwnership, Status: StageOK, Summary: "Propietario/ASN identificado."},
		{ID: StageIDRoutingSecurity, Status: StageOK, Summary: "RPKI válido para AS15169."},
		{ID: StageIDTLS, Status: StageOK, Summary: "TLS válido."},
		{ID: StageIDHTTP, Status: StageOK, Summary: "HTTP 200 — servicio web accesible."},
		{ID: StageIDReputation, Status: StageOK, Summary: "Sin señales de reputación negativas en las listas offline."},
	}
	summary, level, confidence, _, counter, _ := correlate(stages, resolvedTarget{kind: "host"}, true)
	if level != model.LevelInfo {
		t.Errorf("Level = %q, want informativo when every stage came back OK", level)
	}
	if confidence < 70 {
		t.Errorf("Confidence = %d, want high when every stage succeeded cleanly", confidence)
	}
	if !strings.Contains(summary, "HTTP 200") {
		t.Errorf("Summary should surface the HTTP 200 result: %q", summary)
	}
	_ = counter
}

// D. RPKI invalid → hallazgo de seguridad de ruta, nunca "hijack"/"secuestro
// confirmado".
func TestCorrelateRPKIInvalidIsAFindingNotAHijack(t *testing.T) {
	stages := []DiagnosticStage{
		{ID: StageIDResolution, Status: StageOK, Summary: "resolved"},
		{ID: StageIDReachability, Status: StageOK, Summary: "ok"},
		{ID: StageIDRoute, Status: StageOK, Summary: "ok"},
		{ID: StageIDOwnership, Status: StageOK, Summary: "ok"},
		{ID: StageIDRoutingSecurity, Status: StageWarning, Summary: "RPKI inválido para AS64500 — hallazgo de seguridad de ruta, no confirma un secuestro de ruta (hijack)."},
		{ID: StageIDTLS, Status: StageOK, Summary: "ok"},
		{ID: StageIDHTTP, Status: StageOK, Summary: "ok"},
		{ID: StageIDReputation, Status: StageOK, Summary: "ok"},
	}
	summary, level, _, _, _, _ := correlate(stages, resolvedTarget{kind: "host"}, true)
	if level != model.LevelMedium {
		t.Errorf("Level = %q, want medio for an RPKI invalid finding", level)
	}
	for _, forbidden := range []string{"secuestro confirmado", "hijack confirmado", "ataque confirmado"} {
		if strings.Contains(strings.ToLower(summary), forbidden) {
			t.Errorf("Summary must never declare a confirmed hijack from RPKI invalid alone: %q", summary)
		}
	}
}

// E. Route: pérdida en un salto intermedio que NO impide llegar al destino
// no debe leerse como pérdida end-to-end — the Route stage itself already
// hedges this in its own Limitation; correlate() must not discard it nor
// escalate Route's own OK status into something worse.
func TestCorrelateIntermediateHopLossIsNotEndToEnd(t *testing.T) {
	hopLimitation := "1 salto(s) intermedio(s) no respondieron al TTL-exceeded, pero la ruta sí llegó al destino — no se interpreta como pérdida end-to-end; el hop intermedio pudo simplemente no responder ICMP."
	stages := []DiagnosticStage{
		{ID: StageIDResolution, Status: StageOK, Summary: "resolved"},
		{ID: StageIDReachability, Status: StageOK, Summary: "ok"},
		{ID: StageIDRoute, Status: StageOK, Summary: "Ruta alcanza el destino en 10 saltos.", Limitations: []string{hopLimitation}},
		skippedStage(StageIDOwnership), skippedStage(StageIDRoutingSecurity),
		skippedStage(StageIDTLS), skippedStage(StageIDHTTP), skippedStage(StageIDReputation),
	}
	summary, level, _, _, _, limitations := correlate(stages, resolvedTarget{kind: "host"}, true)
	if level == model.LevelHigh || level == model.LevelMedium {
		t.Errorf("Level = %q, a route that reached its destination must not read as a routing problem", level)
	}
	if strings.Contains(strings.ToLower(summary), "pérdida end-to-end") || strings.Contains(strings.ToLower(summary), "ruta rota") {
		t.Errorf("Summary must not claim end-to-end loss from one unresponsive intermediate hop: %q", summary)
	}
	found := false
	for _, l := range limitations {
		if l == hopLimitation {
			found = true
		}
	}
	if !found {
		t.Error("expected the intermediate-hop limitation to survive into the global report")
	}
}

// F. Nothing ran at all (offline mode, no IP) — must not fabricate evidence
// or a counter-evidence list out of stages that never executed.
func TestCorrelateNothingRanIsInfoNotFabricated(t *testing.T) {
	stages := []DiagnosticStage{
		{ID: StageIDResolution, Status: StageSkipped, Summary: "Modo offline: no se intentó resolución DNS."},
		skippedStage(StageIDReachability), skippedStage(StageIDRoute),
		skippedStage(StageIDOwnership), skippedStage(StageIDRoutingSecurity),
		skippedStage(StageIDTLS), skippedStage(StageIDHTTP),
		{ID: StageIDReputation, Status: StageSkipped, Summary: "Sin dirección IP resuelta; no hay reputación que evaluar."},
	}
	_, level, _, evidence, counter, _ := correlate(stages, resolvedTarget{kind: "host"}, false)
	if level != model.LevelInfo {
		t.Errorf("Level = %q, want informativo when nothing ran", level)
	}
	if len(evidence) != 0 || len(counter) != 0 {
		t.Errorf("expected no Evidence/CounterEvid when every stage was skipped, got %d/%d", len(evidence), len(counter))
	}
}

// --- Phase B.1 fix #1: Evidence vs CounterEvidence semantics ---
//
// The bug: OK stages were unconditionally dumped into CounterEvid and
// Warning/Problem stages into Evidence, regardless of what the global
// verdict actually was. A fully healthy run (every stage OK) produced
// Evidence=[] and CounterEvid=all the positive findings — backwards: with no
// negative conclusion, there is nothing for that "counter"-evidence to
// counter.

func ev(typ string) model.Evidence { return model.Evidence{Type: typ, Value: "x", Explain: typ} }

func hasType(list []model.Evidence, typ string) bool {
	for _, e := range list {
		if e.Type == typ {
			return true
		}
	}
	return false
}

// 1. All healthy: OK stages ARE the positive finding (Evidence), and there
// is no negative claim for CounterEvid to contradict.
func TestCorrelateAllHealthyEvidenceNotCounterEvidence(t *testing.T) {
	stages := []DiagnosticStage{
		{ID: StageIDResolution, Status: StageOK, Summary: "resolved", Evidence: []model.Evidence{ev("dns_resolved")}},
		{ID: StageIDReachability, Status: StageOK, Summary: "ok", Evidence: []model.Evidence{ev("icmp_ping")}},
		{ID: StageIDRoute, Status: StageOK, Summary: "ok", Evidence: []model.Evidence{ev("traceroute_hops")}},
		{ID: StageIDOwnership, Status: StageOK, Summary: "ok", Evidence: []model.Evidence{ev("asn_org")}},
		{ID: StageIDRoutingSecurity, Status: StageOK, Summary: "RPKI válido para AS1234."},
		{ID: StageIDTLS, Status: StageOK, Summary: "ok", Evidence: []model.Evidence{ev("tls_handshake")}},
		{ID: StageIDHTTP, Status: StageOK, Summary: "HTTP 200 — servicio web accesible.", Evidence: []model.Evidence{ev("http_status")}},
		{ID: StageIDReputation, Status: StageOK, Summary: "ok"},
	}
	_, level, _, evidence, counter, _ := correlate(stages, resolvedTarget{kind: "host"}, true)
	if level != model.LevelInfo {
		t.Errorf("Level = %q, want informativo", level)
	}
	if len(counter) != 0 {
		t.Errorf("CounterEvid should be empty for a healthy verdict (nothing to contradict), got %d entries", len(counter))
	}
	if !hasType(evidence, "http_status") || !hasType(evidence, "dns_resolved") {
		t.Errorf("healthy stages' own findings should land in Evidence, got %+v", evidence)
	}
}

// 2. ICMP warning + HTTP OK: the ping finding is Evidence; HTTP's OK result
// is the one fact that keeps it from reading as "the host is down" —
// exactly the master plan's own example.
func TestCorrelateICMPWarningHTTPOKIsCounterEvidence(t *testing.T) {
	stages := []DiagnosticStage{
		{ID: StageIDResolution, Status: StageOK, Summary: "resolved"},
		{ID: StageIDReachability, Status: StageWarning, Summary: "Sin respuesta ICMP.", Evidence: []model.Evidence{ev("icmp_ping")}},
		skippedStage(StageIDRoute), skippedStage(StageIDOwnership), skippedStage(StageIDRoutingSecurity),
		skippedStage(StageIDTLS),
		{ID: StageIDHTTP, Status: StageOK, Summary: "HTTP 200 — servicio web accesible.", Evidence: []model.Evidence{ev("http_status")}},
		{ID: StageIDReputation, Status: StageOK, Summary: "ok", Evidence: []model.Evidence{ev("reputation_score")}},
	}
	_, _, _, evidence, counter, _ := correlate(stages, resolvedTarget{kind: "host"}, true)
	if !hasType(evidence, "icmp_ping") {
		t.Errorf("the ping finding itself should be in Evidence, got %+v", evidence)
	}
	if !hasType(counter, "http_status") {
		t.Errorf("HTTP's OK result should be CounterEvid for an ICMP warning, got %+v", counter)
	}
	if hasType(counter, "reputation_score") {
		t.Errorf("reputation is not an availability signal and must not be auto-added as CounterEvid, got %+v", counter)
	}
}

// 3. HTTP 500 + DNS/route OK: DNS and route being fine is the relevant
// counter-context ("the network path works, this is an application-layer
// problem"), not every unrelated OK stage.
func TestCorrelateHTTP500WithDNSRouteOKAsCounterEvidence(t *testing.T) {
	stages := []DiagnosticStage{
		{ID: StageIDResolution, Status: StageOK, Summary: "resolved", Evidence: []model.Evidence{ev("dns_resolved")}},
		{ID: StageIDReachability, Status: StageOK, Summary: "ok"},
		{ID: StageIDRoute, Status: StageOK, Summary: "Ruta alcanza el destino en 5 saltos.", Evidence: []model.Evidence{ev("traceroute_hops")}},
		{ID: StageIDOwnership, Status: StageOK, Summary: "ok"},
		{ID: StageIDRoutingSecurity, Status: StageOK, Summary: "ok"},
		{ID: StageIDTLS, Status: StageOK, Summary: "TLS válido."},
		{ID: StageIDHTTP, Status: StageProblem, Summary: "HTTP 500 — error de servidor.", Evidence: []model.Evidence{ev("http_status")}},
		{ID: StageIDReputation, Status: StageOK, Summary: "ok", Evidence: []model.Evidence{ev("reputation_score")}},
	}
	_, level, _, evidence, counter, _ := correlate(stages, resolvedTarget{kind: "host"}, true)
	if level != model.LevelMedium {
		t.Errorf("Level = %q, want medio for an HTTP 500", level)
	}
	if !hasType(evidence, "http_status") {
		t.Errorf("the HTTP 500 finding itself should be in Evidence, got %+v", evidence)
	}
	if !hasType(counter, "dns_resolved") || !hasType(counter, "traceroute_hops") {
		t.Errorf("DNS/route being OK should be CounterEvid for an HTTP 500 (network path isn't the problem), got %+v", counter)
	}
	if hasType(counter, "reputation_score") {
		t.Errorf("reputation is not an availability signal and must not be auto-added as CounterEvid, got %+v", counter)
	}
}

// 4. Unknown/error driving: an inconclusive result must never be dressed up
// with unrelated OK evidence as if it were proof of health.
func TestCorrelateUnknownDrivingHasNoFabricatedCounterEvidence(t *testing.T) {
	stages := []DiagnosticStage{
		{ID: StageIDResolution, Status: StageOK, Summary: "resolved", Evidence: []model.Evidence{ev("dns_resolved")}},
		{ID: StageIDReachability, Status: StageOK, Summary: "ok", Evidence: []model.Evidence{ev("icmp_ping")}},
		{ID: StageIDRoute, Status: StageUnknown, Summary: "El traceroute no devolvió saltos."},
		skippedStage(StageIDOwnership), skippedStage(StageIDRoutingSecurity), skippedStage(StageIDTLS), skippedStage(StageIDHTTP),
		{ID: StageIDReputation, Status: StageOK, Summary: "ok"},
	}
	summary, level, _, _, counter, limitations := correlate(stages, resolvedTarget{kind: "host"}, true)
	if level != model.LevelLow {
		t.Errorf("Level = %q, want bajo for an inconclusive result", level)
	}
	if !strings.Contains(summary, "inconcluso") {
		t.Errorf("Summary should say the result is inconclusive: %q", summary)
	}
	if len(counter) != 0 {
		t.Errorf("an inconclusive result must not be backed by fabricated CounterEvid, got %+v", counter)
	}
	found := false
	for _, l := range limitations {
		if strings.Contains(l, "inconcluso") {
			found = true
		}
	}
	if !found {
		t.Error("expected a limitation explaining the result is inconclusive")
	}
}

// 5. Clean offline diagnosis: identical intent to
// TestCorrelateNothingRanIsInfoNotFabricated, named explicitly for the
// Phase B.1 gate — every stage skipped (ModeOffline, no IP) must never
// fabricate either Evidence or CounterEvid.
func TestCorrelateCleanOfflineDiagnosisHasNoFabricatedEvidence(t *testing.T) {
	stages := []DiagnosticStage{
		{ID: StageIDResolution, Status: StageSkipped, Summary: "Modo offline: no se intentó resolución DNS."},
		skippedStage(StageIDReachability), skippedStage(StageIDRoute), skippedStage(StageIDOwnership),
		skippedStage(StageIDRoutingSecurity), skippedStage(StageIDTLS), skippedStage(StageIDHTTP),
		{ID: StageIDReputation, Status: StageSkipped, Summary: "Sin dirección IP resuelta; no hay reputación que evaluar."},
	}
	summary, level, confidence, evidence, counter, _ := correlate(stages, resolvedTarget{kind: "host"}, false)
	if level != model.LevelInfo {
		t.Errorf("Level = %q, want informativo", level)
	}
	if len(evidence) != 0 || len(counter) != 0 {
		t.Errorf("a fully offline/skipped run must not fabricate Evidence or CounterEvid, got %d/%d", len(evidence), len(counter))
	}
	if confidence == 0 {
		t.Error("Confidence must never be the zero value")
	}
	if summary == "" {
		t.Error("expected a non-empty summary explaining nothing ran")
	}
}
