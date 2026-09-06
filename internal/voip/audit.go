package voip

import (
	"fmt"
	"strings"

	"trazip/internal/protocol/sdp"
)

// AuditCalls derives defensive findings only from evidence present in the
// capture. It does not probe SIP endpoints or infer credentials.
func AuditCalls(calls []Call) AuditResult {
	r := AuditResult{Findings: []AuditFinding{}}
	add := func(f AuditFinding) {
		r.Findings = append(r.Findings, f)
		switch f.Level {
		case "high":
			r.High++
		case "medium":
			r.Medium++
		default:
			r.Low++
		}
	}
	for _, c := range calls {
		// The current correlator accepts SIP over UDP only, so every parsed
		// timeline is direct evidence of plaintext signaling.
		if len(c.Timeline) > 0 {
			add(AuditFinding{Level: "medium", Category: "plaintext_sip", CallID: c.CallID, Summary: "Señalización SIP observada sin TLS", Evidence: "SIP/UDP visible en la captura", Confidence: 100})
		}
		if !mediaSecured(c.SDPOffer) || !mediaSecured(c.SDPAnswer) {
			if c.SDPOffer != nil || c.SDPAnswer != nil {
				add(AuditFinding{Level: "medium", Category: "unencrypted_rtp", CallID: c.CallID, Summary: "SDP negocia RTP sin perfil seguro", Evidence: mediaProtocols(c), Confidence: 95})
			}
		}
		if c.NATIssue {
			add(AuditFinding{Level: "high", Category: "nat_mismatch", CallID: c.CallID, Summary: "Dirección SDP no coincide con el origen observado", Confidence: 90})
		}
		if c.Unidirectional {
			add(AuditFinding{Level: "high", Category: "one_way_audio", CallID: c.CallID, Summary: "Audio RTP unidireccional", Confidence: 95})
		}
		if c.Retransmissions >= sipRetransWarn {
			add(AuditFinding{Level: "medium", Category: "sip_retransmissions", CallID: c.CallID, Summary: "Retransmisiones SIP elevadas", Evidence: fmt.Sprintf("%d retransmisiones", c.Retransmissions), Confidence: 90})
		}
		if !c.Authenticated {
			add(AuditFinding{Level: "low", Category: "no_auth_challenge_seen", CallID: c.CallID, Summary: "No se observó desafío de autenticación", Evidence: "No demuestra que el servicio acepte llamadas sin autenticación.", Confidence: 55})
		}
		for _, s := range c.Streams {
			if s.Stats.LossPct >= lossWarnPct {
				add(AuditFinding{Level: "medium", Category: "rtp_loss", CallID: c.CallID, Summary: "Pérdida RTP elevada", Evidence: fmt.Sprintf("%s → %s: %.2f%%", s.Src, s.Dst, s.Stats.LossPct), Confidence: 95})
			}
			if s.MOS != nil && s.MOS.Score < mosLowScore {
				add(AuditFinding{Level: "medium", Category: "low_mos", CallID: c.CallID, Summary: "MOS estimado bajo", Evidence: fmt.Sprintf("%s → %s: %.2f", s.Src, s.Dst, s.MOS.Score), Confidence: 80})
			}
			if s.DTMFDigits != "" {
				add(AuditFinding{Level: "low", Category: "dtmf_visible", CallID: c.CallID, Summary: "Dígitos DTMF visibles en RTP", Evidence: "RFC2833/telephone-event observado; el informe no reproduce los dígitos.", Confidence: 100})
			}
		}
	}
	return r
}

func mediaSecured(desc *sdp.SDP) bool {
	if desc == nil {
		return true
	}
	for _, m := range desc.Media {
		if strings.EqualFold(m.Type, "audio") {
			p := strings.ToUpper(m.Proto)
			if !strings.Contains(p, "SAVP") {
				return false
			}
		}
	}
	return true
}

func mediaProtocols(c Call) string {
	set := map[string]bool{}
	for _, desc := range []*sdp.SDP{c.SDPOffer, c.SDPAnswer} {
		if desc == nil {
			continue
		}
		for _, m := range desc.Media {
			if strings.EqualFold(m.Type, "audio") {
				set[m.Proto] = true
			}
		}
	}
	vals := make([]string, 0, len(set))
	for p := range set {
		vals = append(vals, p)
	}
	return strings.Join(vals, ", ")
}
