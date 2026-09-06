package diagnosis

import (
	"context"
	"fmt"
	"time"

	"trazip/internal/httpintel"
	"trazip/internal/model"
	"trazip/internal/tlsintel"
	"trazip/internal/webintel"
)

// ttfbSlowMs is where runHTTP starts calling out a slow first byte. It is
// reported as observed latency, never as a saturation/overload claim the
// data doesn't demonstrate (master plan: "TTFB alto: reportar latencia
// observada del servidor, no afirmar saturación.").
const ttfbSlowMs = 1000

// httpTargetURL is the URL TLS/HTTP (and, in ModeFull, WebIntel) actually
// operate on — the raw URL when the target was one, otherwise a scheme
// guessed from Kind: https for a hostname (TLS has something to inspect
// there), http for a bare IP (no SNI to offer, so https would only be
// misleading).
func httpTargetURL(rt resolvedTarget) string {
	if rt.rawURL != "" {
		return rt.rawURL
	}
	if rt.kind == "ip" {
		return "http://" + rt.host + "/"
	}
	return "https://" + rt.host + "/"
}

// runWebPair produces the TLS and HTTP stages together — Phase B.1 fix #4.
// ModeStandard runs each as its own lightweight, independent call (as
// before). ModeFull calls internal/webintel's full pipeline EXACTLY ONCE and
// derives both stages from that single Result — TLS/HTTP evidence comes
// from the SAME tlsintel.Result/httpintel.Result WebIntel already produced
// internally, never a second Inspect() call against the same target (master
// plan: "NO duplicar las llamadas TLS/HTTP de Standard cuando Full ya
// ejecuta WebIntel."). Stage IDs stay "tls"/"http" either way — stable for
// the UI regardless of which mode actually produced them.
func runWebPair(ctx context.Context, deps Dependencies, rt resolvedTarget, mode Mode) (tlsStage, httpStage DiagnosticStage) {
	tlsStage = DiagnosticStage{ID: StageIDTLS, Label: "TLS"}
	httpStage = DiagnosticStage{ID: StageIDHTTP, Label: "HTTP"}

	if mode == ModeOffline {
		tlsStage.Status, tlsStage.Summary = StageSkipped, "Modo offline: sin pruebas activas."
		httpStage.Status, httpStage.Summary = StageSkipped, "Modo offline: sin pruebas activas."
		return tlsStage, httpStage
	}

	if mode == ModeFull {
		return runWebIntelligencePair(ctx, deps, rt)
	}
	return runTLS(ctx, rt), runHTTP(ctx, rt)
}

// runWebIntelligencePair is ModeFull's half of runWebPair — one
// webintel.Analyze call feeding both stages, plus the extra context module
// 18 already collects (DNS/CNAME chain, redirect chain, contacted
// endpoints, CDN/WAF signals) folded into HTTP's evidence. CDN/WAF signals
// are deliberately never treated as a Warning/Problem — they describe
// infrastructure, not a fault (master plan: "NO convertir señales CDN/WAF
// en problemas. Son contexto.").
func runWebIntelligencePair(ctx context.Context, deps Dependencies, rt resolvedTarget) (tlsStage, httpStage DiagnosticStage) {
	start := time.Now()
	tlsStage = DiagnosticStage{ID: StageIDTLS, Label: "TLS"}
	httpStage = DiagnosticStage{ID: StageIDHTTP, Label: "HTTP"}

	target := httpTargetURL(rt)
	httpStage.Subjects = []string{target}
	httpStage.NetworkOut = true
	tlsStage.NetworkOut = true // WebIntel's own TLS step, when it runs — see below if it didn't
	// These two entries disclose the CLASSES of operation this Full-mode
	// pipeline runs, not an exhaustive request ledger (Phase B.1.1 fix #2 —
	// see NetworkAction's own doc comment): internal/webintel does its own
	// DNS query via a public resolver before the HTTP request (distinct
	// from Resolution's earlier system-resolver lookup, so disclosed here
	// under StageIDHTTP, not StageIDResolution), then makes the HTTP
	// request itself. What this does NOT claim: that this is every DNS
	// lookup the pipeline performs — following a redirect to a different
	// hostname triggers another one internally, and net/http's own dialer
	// does its own system-level resolution during the HTTP/TLS connection,
	// neither of which internal/webintel exposes as a separately countable
	// event this package could honestly itemize.
	httpStage.NetworkActions = append(httpStage.NetworkActions,
		netAction(StageIDHTTP, "dns", rt.host, DestPublicResolver, "hostname"),
		netAction(StageIDHTTP, "http", target, DestTarget, "URL/hostname"))

	wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	res := webintel.Analyze(wctx, deps.Geo, target, "")
	dur := time.Since(start).Milliseconds()

	tlsStage, httpStage = deriveWebIntelStages(res, rt, tlsStage, httpStage)
	httpStage.Limitations = append(httpStage.Limitations,
		"Esta etapa usó el pipeline de WebIntel: puede haber realizado operaciones de red internas adicionales (p. ej. resolución de nombres de hosts de redirects, o la resolución del sistema que hace el propio cliente HTTP) que el motor no expone como eventos individualmente contables — NetworkActions describe clases de operación, no un listado exhaustivo.")
	tlsStage.DurationMs, httpStage.DurationMs = dur, dur
	return tlsStage, httpStage
}

// deriveWebIntelStages turns one completed webintel.Result into the TLS/HTTP
// stage pair — pulled out of runWebIntelligencePair as a pure function (no
// network) so the HTTP-error-without-top-level-Err case is unit-testable
// without a live call. tlsStage/httpStage arrive already carrying what the
// caller recorded BEFORE making the request (Subjects/NetworkOut/
// NetworkActions reflecting intent); this only fills in what the RESULT
// says actually happened.
//
// Two different failure points both mean "no usable HTTP response", and
// both must be caught: res.Err is WebIntel's own top-level failure
// (normalization/DNS never even got as far as attempting HTTP), but DNS can
// succeed while the HTTP request itself still fails — and THAT failure
// surfaces only on res.HTTP.Err, not res.Err, since webintel.Analyze never
// propagates httpintel's own error up to its own Err field (see
// webintel.go: it stores httpRes in res.HTTP and moves on to
// registerHost/TLS/extraction regardless). Missing this check let a real
// HTTP failure fall through to httpFindings(res.HTTP), which reads
// FinalStatus/Redirects assuming a completed request — on a failed one
// those are zero-valued, not absent, so it fabricated http_status="0" and
// http_ttfb="0ms" as if they were observed facts (Phase B.1.1 fix #1).
func deriveWebIntelStages(res webintel.Result, rt resolvedTarget, tlsStage, httpStage DiagnosticStage) (DiagnosticStage, DiagnosticStage) {
	if res.Err != "" || res.HTTP.Err != "" {
		httpErr := res.Err
		if httpErr == "" {
			httpErr = res.HTTP.Err
		}
		httpStage.Status = StageUnknown
		httpStage.Summary = "No se completó la solicitud HTTP: " + httpErr
		httpStage.Limitations = []string{"Una solicitud HTTP fallida no distingue por sí sola entre servicio caído, bloqueo de red o TLS/puerto incorrecto."}
		// DNS/CNAME chain is still real, independently-observed evidence
		// (WebIntel resolves the host before attempting HTTP) — kept, but
		// never anything implying the HTTP request itself succeeded.
		if len(res.DNSChain) > 0 {
			httpStage.Evidence = webIntelDNSEvidence(res)
		}

		if res.TLS != nil {
			// WebIntel got far enough to actually inspect TLS (e.g. the
			// connection came up but the HTTP layer above it failed) — a
			// real, independent result, described exactly like the
			// success path would.
			tlsStage.Subjects = []string{rt.host}
			tlsStage.NetworkActions = append(tlsStage.NetworkActions, netAction(StageIDTLS, "tls", rt.host, DestTarget, "hostname/SNI"))
			tlsStage.Status, tlsStage.Summary, tlsStage.Evidence, tlsStage.Limitations = tlsFindings(*res.TLS)
		} else {
			tlsStage.Status = StageUnknown
			tlsStage.Summary = "No se completó: la solicitud HTTP falló antes de confirmar TLS."
			tlsStage.NetworkOut = false
		}
		return tlsStage, httpStage
	}

	httpStage.Status, httpStage.Summary, httpStage.Evidence, httpStage.Limitations = httpFindings(res.HTTP)
	httpStage.Evidence = append(httpStage.Evidence, webIntelEvidence(res)...)

	if res.TLS == nil {
		tlsStage.Status = StageSkipped
		tlsStage.Summary = "La respuesta final no fue HTTPS; WebIntel no inspeccionó TLS."
		tlsStage.NetworkOut = false
	} else {
		tlsStage.Subjects = []string{rt.host}
		tlsStage.NetworkActions = append(tlsStage.NetworkActions, netAction(StageIDTLS, "tls", rt.host, DestTarget, "hostname/SNI"))
		tlsStage.Status, tlsStage.Summary, tlsStage.Evidence, tlsStage.Limitations = tlsFindings(*res.TLS)
	}
	return tlsStage, httpStage
}

// webIntelDNSEvidence is the one piece of webIntelEvidence that stays valid
// even when the HTTP request itself failed: WebIntel resolves the host
// BEFORE attempting HTTP, so a DNS/CNAME chain it already observed is real,
// independently-obtained evidence regardless of what happened next (Phase
// B.1.1 fix #1) — split out from webIntelEvidence so the error path can
// reuse just this part without also claiming the redirect chain, contacted
// endpoints, or CDN/WAF signals a failed request never actually produced.
func webIntelDNSEvidence(res webintel.Result) []model.Evidence {
	if len(res.DNSChain) == 0 {
		return nil
	}
	return []model.Evidence{{
		Type: "dns_chain", Value: fmt.Sprintf("%d salto(s)", len(res.DNSChain)), Source: "diagnosis",
		Provenance: model.ProvResolved, Confidence: 85, Timestamp: time.Now(),
		Explain: "Cadena CNAME/A/AAAA resuelta por WebIntel para este objetivo.",
	}}
}

// webIntelEvidence surfaces the extra context module 18's pipeline
// collected beyond the bare HTTP status — DNS/CNAME chain, the redirect
// chain, other endpoints contacted, and CDN/WAF signals. Never the response
// body/HTML itself (master plan: "No hace falta exponer cada detalle del
// HTML.").
func webIntelEvidence(res webintel.Result) []model.Evidence {
	out := webIntelDNSEvidence(res)
	if len(res.HTTP.Redirects) > 1 {
		out = append(out, model.Evidence{
			Type: "http_redirect_chain", Value: fmt.Sprintf("%d salto(s)", len(res.HTTP.Redirects)), Source: "diagnosis",
			Provenance: model.ProvObserved, Confidence: 90, Timestamp: time.Now(),
			Explain: fmt.Sprintf("La solicitud siguió %d redirecciones hasta %s.", len(res.HTTP.Redirects)-1, res.HTTP.FinalURL),
		})
	}
	if len(res.ContactedEndpoints) > 0 {
		out = append(out, model.Evidence{
			Type: "contacted_endpoints", Value: fmt.Sprintf("%d endpoint(s)", len(res.ContactedEndpoints)), Source: "diagnosis",
			Provenance: model.ProvObserved, Confidence: 80, Timestamp: time.Now(),
			Explain: "Hosts+IP distintos tocados durante la resolución/redirects (incluye GeoIP/ASN offline cuando aplica).",
		})
	}
	for _, sig := range res.HTTP.Signals {
		// Context, not a finding — never phrased as a problem, per this
		// function's own doc comment.
		out = append(out, model.Evidence{
			Type: "cdn_waf_signal", Value: sig.Label, Source: "diagnosis",
			Provenance: model.ProvInferred, Confidence: 60, Timestamp: time.Now(),
			Explain: fmt.Sprintf("Señal de infraestructura detectada (contexto, no un hallazgo): %s.", sig.Evidence),
		})
	}
	return out
}

// runTLS completes a TLS handshake at :443 for host-shaped targets. Skipped
// entirely for a bare IP target: without a hostname there is no meaningful
// SNI/certificate-name comparison to make, and guessing one would be
// exactly the kind of invented probe this package's own doc comment rules
// out. ModeStandard's own lightweight path — ModeFull never calls this (see
// runWebIntelligencePair).
func runTLS(ctx context.Context, rt resolvedTarget) DiagnosticStage {
	start := time.Now()
	s := DiagnosticStage{ID: StageIDTLS, Label: "TLS"}

	if rt.kind == "ip" {
		s.Status = StageSkipped
		s.Summary = "Objetivo es una IP directa; sin nombre de host no hay SNI que inspeccionar."
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}

	s.Subjects = []string{rt.host}
	s.NetworkOut = true
	s.NetworkActions = append(s.NetworkActions, netAction(StageIDTLS, "tls", rt.host, DestTarget, "hostname/SNI"))
	tctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	res := tlsintel.Inspect(tctx, rt.host, 443, rt.host)
	s.Status, s.Summary, s.Evidence, s.Limitations = tlsFindings(res)
	s.DurationMs = time.Since(start).Milliseconds()
	return s
}

// tlsFindings turns one tlsintel.Result into a stage's status/summary/
// evidence/limitations — shared by runTLS (ModeStandard) and
// runWebIntelligencePair (ModeFull), so both modes describe a successful or
// failed handshake identically regardless of which engine call produced it.
func tlsFindings(res tlsintel.Result) (status StageStatus, summary string, evidence []model.Evidence, limitations []string) {
	if res.Err != "" {
		return StageUnknown, "No se completó el handshake TLS: " + res.Err, nil,
			[]string{"No se pudo abrir TLS en el puerto 443 — puede ser que el servicio no ofrezca HTTPS ahí, o un bloqueo de red; no se afirma cuál."}
	}

	evidence = append(evidence, model.Evidence{
		Type: "tls_handshake", Value: res.Protocol, Source: "diagnosis",
		Provenance: model.ProvObserved, Confidence: 90, Timestamp: time.Now(),
		Explain: fmt.Sprintf("Handshake TLS completado: %s, cifrado %s.", res.Protocol, res.CipherSuite),
	})
	if len(res.Chain) > 0 {
		leaf := res.Chain[0]
		evidence = append(evidence, model.Evidence{
			Type: "tls_cert_expiry", Value: fmt.Sprintf("%d días", leaf.DaysUntilExpiry), Source: "diagnosis",
			Provenance: model.ProvObserved, Confidence: 90, Timestamp: time.Now(),
			Explain: fmt.Sprintf("Certificado emitido por %s, vence %s.", leaf.Issuer, leaf.NotAfter),
		})
	}

	if !res.ValidationOK {
		status = StageWarning
		summary = "TLS conecta pero la validación del certificado falló: " + res.ValidationError
	} else {
		status = StageOK
		summary = "TLS válido."
	}
	return status, summary, evidence, limitations
}

// runHTTP performs one bounded GET — never the URL Analyzer's full pipeline,
// and the response body is never retained here, matching HTTPInspect's own
// existing contract. ModeStandard's own lightweight path — ModeFull never
// calls this (see runWebIntelligencePair).
func runHTTP(ctx context.Context, rt resolvedTarget) DiagnosticStage {
	start := time.Now()
	s := DiagnosticStage{ID: StageIDHTTP, Label: "HTTP"}

	target := httpTargetURL(rt)
	// Subject is the URL actually requested — never an inferred IP:
	// httpintel.Result carries no field for the address it actually
	// connected to, and this package never guesses one it wasn't handed
	// (Phase B.1 fix #3: "No inferir una IP si el motor no la entrega.").
	s.Subjects = []string{target}
	s.NetworkOut = true
	s.NetworkActions = append(s.NetworkActions, netAction(StageIDHTTP, "http", target, DestTarget, "URL/hostname"))
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res := httpintel.Inspect(hctx, target, "GET", 5, 0, false)
	if res.Err != "" {
		s.Status = StageUnknown
		s.Summary = "No se completó la solicitud HTTP: " + res.Err
		s.Limitations = []string{"Una solicitud HTTP fallida no distingue por sí sola entre servicio caído, bloqueo de red o TLS/puerto incorrecto."}
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}

	s.Status, s.Summary, s.Evidence, s.Limitations = httpFindings(res)
	s.DurationMs = time.Since(start).Milliseconds()
	return s
}

// httpFindings turns one successful httpintel.Result into a stage's
// status/summary/evidence/limitations — pulled out as a pure function so
// the TTFB-vs-total-duration distinction (Phase B.1 fix #2) is unit-testable
// without a live HTTP request, and so ModeFull's WebIntel-derived
// httpintel.Result (Phase B.1 fix #4) is described identically to
// ModeStandard's own direct httpintel.Inspect call.
//
// http_total_duration and http_ttfb are deliberately two separate evidence
// entries, never one number wearing the other's name: DurationMs is the
// whole operation — every redirect hop plus the final response — while
// TTFBMs is the FINAL hop's own time-to-first-byte, from httpintel's
// per-hop trace (see finalHopTTFB). Conflating them let a multi-hop
// redirect chain's cumulative time read as if the origin server itself
// were slow to respond, even when the final hop's actual TTFB was fast —
// and the ttfbSlowMs limitation below applies to TTFB alone for the same
// reason: a high total duration with a fast TTFB says "many redirects", not
// "slow server".
func httpFindings(res httpintel.Result) (status StageStatus, summary string, evidence []model.Evidence, limitations []string) {
	evidence = append(evidence, model.Evidence{
		Type: "http_status", Value: fmt.Sprintf("%d", res.FinalStatus), Source: "diagnosis",
		Provenance: model.ProvObserved, Confidence: 90, Timestamp: time.Now(),
		Explain: fmt.Sprintf("Respuesta HTTP %d en %s.", res.FinalStatus, res.FinalURL),
	})
	if res.DurationMs > 0 {
		evidence = append(evidence, model.Evidence{
			Type: "http_total_duration", Value: fmt.Sprintf("%dms", res.DurationMs), Source: "diagnosis",
			Provenance: model.ProvObserved, Confidence: 85, Timestamp: time.Now(),
			Explain: "Tiempo total observado para toda la operación (incluye redirects, si los hubo) — latencia observada, no una conclusión sobre la carga del servidor.",
		})
	}
	ttfbMs, haveTTFB := finalHopTTFB(res)
	if haveTTFB {
		evidence = append(evidence, model.Evidence{
			Type: "http_ttfb", Value: fmt.Sprintf("%dms", ttfbMs), Source: "diagnosis",
			Provenance: model.ProvObserved, Confidence: 85, Timestamp: time.Now(),
			Explain: "Tiempo hasta el primer byte de la respuesta final — latencia del servidor observada, no una conclusión sobre su carga.",
		})
	}

	switch {
	case res.FinalStatus >= 200 && res.FinalStatus < 400:
		status = StageOK
		summary = fmt.Sprintf("HTTP %d — servicio web accesible.", res.FinalStatus)
	case res.FinalStatus >= 400 && res.FinalStatus < 500:
		status = StageWarning
		summary = fmt.Sprintf("HTTP %d — el servidor respondió pero rechazó la solicitud.", res.FinalStatus)
	case res.FinalStatus >= 500:
		status = StageProblem
		summary = fmt.Sprintf("HTTP %d — error de servidor.", res.FinalStatus)
	default:
		status = StageUnknown
		summary = "Respuesta HTTP sin código de estado reconocible."
	}
	if haveTTFB && ttfbMs >= ttfbSlowMs {
		limitations = append(limitations, fmt.Sprintf("Tiempo hasta el primer byte observado de %dms — se reporta como latencia observada, no como evidencia de saturación del servidor.", ttfbMs))
	}
	return status, summary, evidence, limitations
}

// finalHopTTFB returns the actual final response's time-to-first-byte —
// res.Redirects' last entry, never res.DurationMs (the whole multi-hop
// operation) and never an earlier redirect hop's own TTFB. False when no hop
// was recorded at all, which never happens on the success path this is
// called from but is handled rather than risking an index panic on a future
// caller.
func finalHopTTFB(res httpintel.Result) (int64, bool) {
	if len(res.Redirects) == 0 {
		return 0, false
	}
	return res.Redirects[len(res.Redirects)-1].Timing.TTFBMs, true
}
