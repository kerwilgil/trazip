package voip

import (
	"fmt"
	"math"

	"trazip/internal/model"
)

// Diagnose builds a single evidence-based Assessment for a call, reusing the
// central model (prompt maestro §8/§10) rather than a bespoke shape — every
// other judgement TRAZIP makes already looks like this, and the frontend
// already knows how to render it.
//
// It never claims a cause the data doesn't demonstrate: Conclusion is hedged
// ("compatible con", "sugiere", "posible"), and Confidence is reduced — not
// just footnoted — whenever a signal this diagnosis leans on is itself
// uncertain: an assumed clock rate, no RTCP corroboration, only one captured
// direction, or no SDP to compare against (§10 "reglas").
//
// Deliberately NOT attempted: guessing which party is "the carrier" and which
// is "the client" from ASN/organization data alone. The observable fact is an
// address and, when GeoIP/ASN resolved it, an organization name — asserting a
// network *role* from that would be exactly the kind of unsupported claim §10
// forbids, so the conclusion names the address (and organization, when known)
// instead of a role.
func Diagnose(c Call) model.Assessment {
	if !c.Established {
		return diagnoseUnestablished(c)
	}
	if len(c.Streams) == 0 {
		return model.Assessment{
			Conclusion:  "Llamada establecida pero sin flujo RTP capturado — no hay datos de calidad que evaluar",
			Level:       model.LevelInfo,
			Confidence:  70,
			Limitations: []string{"Ningún stream RTP quedó correlacionado a esta llamada en la captura"},
		}
	}

	// This conclusion is presented as call/voice quality — EstimateMOS's own
	// model only means anything for audio, and a video stream's independent
	// loss/jitter must never dominate a conclusion the UI shows as MOS. So
	// worstStream is chosen only among audio streams, not the full mixed
	// set; a non-audio stream still gets its own RTP stats and SDP findings
	// elsewhere, just never feeds this voice-quality Assessment.
	audioStreams := audioOnlyStreams(c.Streams)
	if len(audioStreams) == 0 {
		return model.Assessment{
			Conclusion:  "No se observó un stream de audio; el diagnóstico de calidad de voz no está disponible",
			Level:       model.LevelInfo,
			Confidence:  70,
			Limitations: []string{"Ningún stream de audio quedó correlacionado a esta llamada en la captura (puede haber streams de otro tipo de media)"},
		}
	}

	worst := worstStream(audioStreams)
	confidence := 90
	var limitations []string
	if worst.Stats.ClockAssumed {
		confidence -= 20
		limitations = append(limitations, "El clock rate de al menos un stream no se confirmó mediante SDP (se asumió 8kHz); jitter y clock skew tienen menor confianza")
	}
	// The question isn't "was RTCP seen anywhere in this call" — it's "does
	// the STREAM THIS DIAGNOSIS IS ABOUT (worst) have a genuine Receiver
	// Report corroborating it". A clean stream's RR elsewhere in the call
	// says nothing about worst; and worst.RTCPSeen can be true from a
	// Sender-Report-only observation (see RTCPSummary's doc comment) — an
	// SR is self-reported by the same party Stats already measures locally,
	// not corroboration from the far end at all.
	if worst.RTCP == nil || worst.RTCP.Receiver == nil {
		confidence -= 15
		if worst.RTCP != nil && worst.RTCP.Sender != nil {
			limitations = append(limitations, "No se observó un Receiver Report para el stream evaluado; no existe corroboración RTCP del receptor sobre su pérdida/jitter (sí se observó el Sender Report de su propio origen)")
		} else {
			limitations = append(limitations, "No se observó un Receiver Report para el stream evaluado; no existe corroboración RTCP del receptor sobre su pérdida/jitter")
		}
	}
	if c.Unidirectional {
		confidence -= 10
		limitations = append(limitations, "Solo se capturó un sentido del audio (posible NAT/firewall, o la captura no vio el otro tramo)")
	}
	if c.SDPOffer == nil && c.SDPAnswer == nil {
		confidence -= 10
		limitations = append(limitations, "No se capturó SDP: no hay negociación contra la que comparar el tráfico RTP observado")
	}
	confidence = clampConfidence(confidence)

	level, headline := classifyQuality(worst)
	// worst.Dst is the receiver of the more-affected leg — the natural side
	// to name ("the leg toward X"). An earlier version of this also tried to
	// pick worst.Src when it matched Callee's SIP address, but RTP and SIP
	// almost never share a port, so that branch could never actually fire;
	// removed rather than kept as dead-looking-live code.
	tramo := fmt.Sprintf("hacia %s", ipOf(worst.Dst))
	if org := partyOrganization(c, worst.Dst); org != "" {
		tramo += fmt.Sprintf(" (%s)", org)
	}

	conclusion := headline
	if level != model.LevelInfo {
		conclusion = fmt.Sprintf("%s — tramo %s más afectado", headline, tramo)
	}

	evidence, counter := diagnosisEvidence(c, worst)

	return model.Assessment{
		Conclusion:  conclusion,
		Level:       level,
		Confidence:  model.Confidence(confidence),
		Evidence:    evidence,
		CounterEvid: counter,
		Limitations: limitations,
	}
}

func diagnoseUnestablished(c Call) model.Assessment {
	conclusion := "Llamada no establecida"
	level := model.LevelLow
	limitations := []string{"La llamada no llegó a establecerse: no hay tráfico RTP que evaluar"}
	var evidence []model.Evidence

	switch {
	case c.FailureCode > 0:
		conclusion = fmt.Sprintf("Llamada no establecida — SIP %d %s", c.FailureCode, c.FailureReason)
		if origin := failureOriginLabel(c); origin != "" {
			conclusion += fmt.Sprintf(" originado en %s", origin)
		}
		if c.ProbableCause != "" {
			conclusion += " (" + c.ProbableCause + ")"
		}
		level = model.LevelMedium
		evidence = append(evidence, model.Evidence{
			Type: "sip_failure", Value: fmt.Sprintf("%d", c.FailureCode), Source: "voip",
			Provenance: model.ProvObserved, Confidence: 95,
			Explain: fmt.Sprintf("Respuesta SIP %d %s observada en la señalización", c.FailureCode, c.FailureReason),
		})
		// FailureOrigin is the address that actually sent the final SIP
		// response — recorded separately from sip_failure above because a
		// proxy/SBC/carrier can relay that response onward, so "who sent the
		// response we captured last" (sip_failure, always Callee's leg) and
		// "who actually originated it" (this) are different claims backed by
		// different evidence (see buildSignalingPath's doc comment).
		if c.FailureOrigin != "" {
			evidence = append(evidence, model.Evidence{
				Type: "sip_failure_origin", Value: c.FailureOrigin, Source: "voip",
				Provenance: model.ProvObserved, Confidence: 90,
				Explain: fmt.Sprintf("%s originó la respuesta SIP %d final antes de que un intermediario, si lo hubo, la reenviara hacia el origen de la llamada", ipOf(c.FailureOrigin), c.FailureCode),
			})
		}
	case c.ProbableCause != "":
		conclusion = "Llamada no establecida — " + c.ProbableCause
	default:
		conclusion = "Llamada no establecida y sin respuesta de error explícita — compatible con timeout o captura incompleta"
		limitations = append(limitations, "Sin una respuesta de error explícita, no se puede atribuir el fallo a un extremo concreto desde esta captura")
	}

	if c.Retransmissions >= sipRetransWarn {
		evidence = append(evidence, model.Evidence{
			Type: "sip_retransmissions", Value: fmt.Sprintf("%d", c.Retransmissions), Source: "voip",
			Provenance: model.ProvObserved, Confidence: 90,
			Explain: fmt.Sprintf("%d retransmisiones SIP — sugiere señalización lenta o con pérdida", c.Retransmissions),
		})
	}

	return model.Assessment{Conclusion: conclusion, Level: level, Confidence: 75, Evidence: evidence, Limitations: limitations}
}

// audioOnlyStreams filters to streams Diagnose's voice-quality conclusion
// may draw from. MediaType == "" (SDP never captured, or neither end of the
// stream matched a negotiated media address) is treated as audio for
// backward compatibility — the exact same leniency EstimateMOS's own gate in
// attachStreams uses, so a stream either gets a MOS and counts here, or gets
// neither.
func audioOnlyStreams(streams []StreamInfo) []StreamInfo {
	var out []StreamInfo
	for _, s := range streams {
		if s.MediaType == "" || s.MediaType == "audio" {
			out = append(out, s)
		}
	}
	return out
}

// worstStream picks the single direction most worth pointing at first.
//
// Ranked by classifyQuality's own Level FIRST, not by MOS/loss score alone —
// classifyQuality also escalates on Reordered/Duplicates/JitterMs/ClockSkewMs,
// signals streamScore below knows nothing about. Scoring streams purely by
// MOS/loss let a stream with a slightly better MOS but, say, 100 reordered
// packets hide a stream that classifyQuality would call more severe — the
// headline and evidence would describe the milder direction while the
// worse one went unmentioned. Only within the same Level does streamScore
// break the tie, as a deterministic "worse of the two equally-bad-looking
// streams" preference. Ties after that keep the first stream in the
// (already Src-sorted) slice.
func worstStream(streams []StreamInfo) StreamInfo {
	worst := streams[0]
	worstLevel, _ := classifyQuality(worst)
	worstScore := streamScore(worst)
	for _, s := range streams[1:] {
		level, _ := classifyQuality(s)
		score := streamScore(s)
		if levelSeverity(level) > levelSeverity(worstLevel) ||
			(levelSeverity(level) == levelSeverity(worstLevel) && score < worstScore) {
			worst, worstLevel, worstScore = s, level, score
		}
	}
	return worst
}

// levelSeverity orders model.Level for worstStream's ranking — higher means
// worse. model.Level is a plain string with no inherent order of its own.
func levelSeverity(l model.Level) int {
	switch l {
	case model.LevelHigh:
		return 3
	case model.LevelMedium:
		return 2
	case model.LevelLow:
		return 1
	default:
		return 0
	}
}

// streamScore is lower = worse, used only to break ties between streams
// classifyQuality already considers equally severe. MOS (1-4.5) already
// encodes loss+jitter together; loss alone is the fallback when there
// weren't enough packets for MOS.
func streamScore(s StreamInfo) float64 {
	if s.MOS != nil {
		return s.MOS.Score
	}
	return 4.5 - s.Stats.LossPct/20 // rough proxy, only used pre-MOS-eligibility
}

func classifyQuality(s StreamInfo) (model.Level, string) {
	loss := s.Stats.LossPct
	var mos float64 = -1
	if s.MOS != nil {
		mos = s.MOS.Score
	}
	switch {
	case loss >= lossHighPct || (mos >= 0 && mos < mosPoorScore):
		return model.LevelHigh, "Calidad mala"
	case loss >= lossWarnPct || (mos >= 0 && mos < mosLowScore) || s.Stats.Reordered > 0 || s.Stats.Duplicates > 0:
		return model.LevelMedium, "Calidad degradada"
	case s.Stats.JitterMs >= jitterElevatedMs || math.Abs(s.Stats.ClockSkewMs) >= clockSkewWarnMs:
		return model.LevelLow, "Calidad aceptable con señales menores"
	default:
		return model.LevelInfo, "Buena calidad"
	}
}

// partyOrganization returns the ASN organization for whichever call party
// (Caller/Callee) or signaling hop matches addr exactly, when GeoIP/ASN
// resolved one — empty otherwise (private address, no dataset, or no match).
//
// Takes one specific address, not "either end of the stream": matching
// against both Src and Dst let this return the WRONG party's organization
// next to a different IP than the one actually being displayed — caught by
// running Diagnose against a real two-sided capture (1.1.1.1↔8.8.8.8) rather
// than trusting the unit tests, which never had two distinct real
// organizations to tell apart.
func partyOrganization(c Call, addr string) string {
	_, org := partyASNOrg(c, addr)
	return org
}

// partyASNOrg is partyOrganization's ASN-carrying equivalent, used wherever
// the caller needs to name the AS number alongside the organization (e.g.
// "AS20473 The Constant Company") rather than just the org name. Searches
// Caller/Callee first, then SignalingPath — an intermediary or the true
// destination of a failed call is frequently neither Caller nor Callee (a
// proxy/SBC/carrier relaying the final response), so a lookup that only
// checked Caller/Callee would silently come back empty for exactly the
// addresses FailureOrigin most needs to describe.
func partyASNOrg(c Call, addr string) (uint32, string) {
	target := ipOf(addr)
	if target == "" {
		return 0, ""
	}
	for _, p := range []CallParty{c.Caller, c.Callee} {
		if p.Address != "" && ipOf(p.Address) == target && p.Organization != "" {
			return p.ASN, p.Organization
		}
	}
	for _, h := range c.SignalingPath {
		if h.Address != "" && ipOf(h.Address) == target && h.Organization != "" {
			return h.ASN, h.Organization
		}
	}
	return 0, ""
}

// failureOriginLabel renders Call.FailureOrigin for the diagnosis conclusion:
// just the address when no enrichment exists, or "address (AS# Org)" when
// GeoIP/ASN resolved one via Caller/Callee/SignalingPath (see partyASNOrg).
// Never invents a carrier/provider/client role — only what was actually
// resolved. Empty when FailureOrigin itself is empty or doesn't parse.
func failureOriginLabel(c Call) string {
	if c.FailureOrigin == "" {
		return ""
	}
	ip := ipOf(c.FailureOrigin)
	if ip == "" {
		return ""
	}
	if asn, org := partyASNOrg(c, c.FailureOrigin); org != "" {
		if asn != 0 {
			return fmt.Sprintf("%s (AS%d %s)", ip, asn, org)
		}
		return fmt.Sprintf("%s (%s)", ip, org)
	}
	return ip
}

// diagnosisEvidence turns the worst stream's numbers, plus whatever the far
// end reported via RTCP, into Evidence/CounterEvid entries. Confidence on each
// entry reflects how directly TRAZIP observed it — a locally counted RTP
// statistic is more certain than an estimate derived from it.
func diagnosisEvidence(c Call, worst StreamInfo) (evidence, counter []model.Evidence) {
	if worst.Stats.LossPct > 0 {
		evidence = append(evidence, model.Evidence{
			Type: "rtp_loss_local", Value: fmt.Sprintf("%.2f%%", worst.Stats.LossPct), Source: "voip",
			Provenance: model.ProvObserved, Confidence: 95,
			Explain: fmt.Sprintf("Pérdida RTP observada localmente en %s→%s: %.2f%%", ipOf(worst.Src), ipOf(worst.Dst), worst.Stats.LossPct),
		})
	}
	if worst.Stats.JitterMs >= jitterElevatedMs {
		evidence = append(evidence, model.Evidence{
			Type: "rtp_jitter", Value: fmt.Sprintf("%.1fms", worst.Stats.JitterMs), Source: "voip",
			Provenance: model.ProvObserved, Confidence: 90,
			Explain: fmt.Sprintf("Jitter observado %.1fms, por encima del umbral donde el modelo de calidad empieza a penalizar", worst.Stats.JitterMs),
		})
	}
	if worst.MOS != nil {
		evidence = append(evidence, model.Evidence{
			Type: "mos_estimate", Value: fmt.Sprintf("%.2f", worst.MOS.Score), Source: "voip",
			Provenance: model.ProvInferred, Confidence: 70,
			Explain: fmt.Sprintf("MOS estimado %.2f (%s)", worst.MOS.Score, worst.MOS.Formula),
		})
	}
	if worst.Stats.Reordered > 0 {
		evidence = append(evidence, model.Evidence{
			Type: "rtp_reordered", Value: fmt.Sprintf("%d", worst.Stats.Reordered), Source: "voip",
			Provenance: model.ProvObserved, Confidence: 95,
			Explain: fmt.Sprintf("%d paquetes fuera de orden — compatible con audio picado sin que suba la pérdida", worst.Stats.Reordered),
		})
	}
	if worst.Stats.Duplicates > 0 {
		evidence = append(evidence, model.Evidence{
			Type: "rtp_duplicates", Value: fmt.Sprintf("%d", worst.Stats.Duplicates), Source: "voip",
			Provenance: model.ProvObserved, Confidence: 95,
			Explain: fmt.Sprintf("%d paquetes duplicados — compatible con un bucle de red o un SBC reenviando", worst.Stats.Duplicates),
		})
	}
	if math.Abs(worst.Stats.ClockSkewMs) >= clockSkewWarnMs {
		evidence = append(evidence, model.Evidence{
			Type: "clock_skew", Value: fmt.Sprintf("%.1fms", worst.Stats.ClockSkewMs), Source: "voip",
			Provenance: model.ProvObserved, Confidence: 80,
			Explain: fmt.Sprintf("Deriva de reloj de %.1fms entre la llegada y la marca de tiempo RTP — posible reloj del gateway corriendo mal", worst.Stats.ClockSkewMs),
		})
	}

	if worst.RTCP != nil {
		// worst.RTCP.Receiver — when present — is the party RECEIVING this
		// exact SAME Src→Dst stream reporting how IT saw the traffic TRAZIP
		// also measured locally as worst.Stats. Same stream, same direction,
		// two vantage points — never framed as "the opposite direction" or
		// compared as if the two numbers measured the same window: Stats is
		// a running total across the whole capture, FractionLostPct is only
		// the interval since the receiver's PREVIOUS report (RFC 3550
		// §6.4.2), typically a few seconds. A gap between the two is not, by
		// itself, evidence of anything — it's two different windows of the
		// same signal — so it is never treated as counter-evidence of an
		// asymmetric or opposite-direction problem here.
		if r := worst.RTCP.Receiver; r != nil {
			evidence = append(evidence, model.Evidence{
				Type: "rtcp_receiver_loss", Value: fmt.Sprintf("%.2f%%", r.FractionLostPct), Source: "voip",
				Provenance: model.ProvObserved, Confidence: 85,
				Explain: fmt.Sprintf(
					"El extremo receptor de %s→%s reporta %.2f%% de pérdida en el último intervalo RTCP (ventana propia, no comparable directamente con el %.2f%% acumulado observado localmente)",
					ipOf(worst.Src), ipOf(worst.Dst), r.FractionLostPct, worst.Stats.LossPct),
			})
		}
		if worst.RTCP.EstimatedRTTMs != nil {
			// Deliberately the lowest confidence and the only ProvInferred
			// entry in this function (everything else here is either a direct
			// local count or literally what the receiver reported). RFC
			// 3550's formula needs the RR's arrival time AT THE ORIGINAL SR's
			// SENDER; a passive capture only has its own capture-point
			// timestamp to substitute, so the result carries unknown,
			// unbounded bias from however far the capture sits from that
			// endpoint. Never let this read as a measurement — the Value, the
			// Explain text and the Confidence all say "estimado", not "RTT".
			evidence = append(evidence, model.Evidence{
				Type: "rtcp_rtt_estimated", Value: fmt.Sprintf("~%.0fms", *worst.RTCP.EstimatedRTTMs), Source: "voip",
				Provenance: model.ProvInferred, Confidence: 50,
				Explain: fmt.Sprintf(
					"RTT RTCP estimado: ~%.0fms. Estimado desde el punto de captura; la precisión depende de la ubicación de la captura respecto al endpoint",
					*worst.RTCP.EstimatedRTTMs),
			})
		}
	}

	for _, f := range c.MediaFindings {
		if f.Level != "warn" {
			continue
		}
		evidence = append(evidence, model.Evidence{
			Type: "sdp_vs_rtp", Value: f.Summary, Source: "voip",
			Provenance: model.ProvInferred, Confidence: 60,
			Explain: f.Summary,
		})
	}

	return evidence, counter
}

func clampConfidence(v int) int {
	if v < 10 {
		return 10
	}
	if v > 95 { // a passive, single-vantage-point capture is never fully certain
		return 95
	}
	return v
}
