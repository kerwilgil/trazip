package diagnosis

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"trazip/internal/intel/classify"
	"trazip/internal/model"
)

// runRoutingSecurity checks whether the address's announcing ASN is a valid
// RPKI origin for the covering prefix, via RIPEstat. Never a live query in
// ModeOffline. An "invalid" result is reported as exactly that — a routing
// security finding worth investigating — never escalated into a declared
// BGP hijack, which RPKI invalid alone does not prove (master plan: "RPKI
// invalid: hallazgo de routing security, no declarar hijack.").
func runRoutingSecurity(ctx context.Context, deps Dependencies, haveIP bool, ip netip.Addr, mode Mode) DiagnosticStage {
	start := time.Now()
	s := DiagnosticStage{ID: StageIDRoutingSecurity, Label: "Seguridad de ruta (RPKI)"}

	if !haveIP {
		s.Status = StageSkipped
		s.Summary = "Sin dirección IP pública; no aplica RPKI."
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}
	s.Subjects = []string{ip.String()}
	if !classify.IsPublic(ip) {
		s.Status = StageSkipped
		s.Summary = "Sin dirección IP pública; no aplica RPKI."
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}
	if mode == ModeOffline {
		s.Status = StageSkipped
		s.Summary = "Modo offline: no se consultó RPKI (requiere RIPEstat)."
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}
	if deps.BGP == nil {
		s.Status = StageUnknown
		s.Summary = "Cliente BGP no disponible."
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}

	s.NetworkOut = true
	s.NetworkActions = append(s.NetworkActions, netAction(StageIDRoutingSecurity, "bgp", ip.String(), DestRIPEstat, "IP pública"))
	bctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	route := deps.BGP.RoutingStatus(bctx, ip.String())
	if route.Err != "" || !route.Announced || len(route.Origins) == 0 {
		s.Status = StageUnknown
		s.Summary = "No se pudo establecer qué ASN anuncia esta dirección."
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}

	// A MOAS (Multiple Origin AS) announcement lists more than one origin
	// ASN for the same prefix — TRAZIP must evaluate every one of them,
	// never just route.Origins[0]: RIPEstat's own ordering carries no
	// semantic meaning about which origin is "the real one" (V1 hardening
	// finding #5). Deduplicated: RIPEstat can repeat an origin.
	origins := uniqueOrigins(route.Origins)
	for _, asn := range origins {
		s.Subjects = append(s.Subjects, fmt.Sprintf("AS%d", asn))
		s.Evidence = append(s.Evidence, model.Evidence{
			Type: "bgp_origin_asn", Value: fmt.Sprintf("AS%d", asn), Source: "diagnosis",
			Provenance: model.ProvExternal, Confidence: 75, Timestamp: time.Now(),
			Explain: "ASN que actualmente anuncia esta dirección, según RIPEstat.",
		})
	}

	// RPKIValidate must be asked about the REAL announced prefix
	// (route.Prefix, e.g. "1.1.1.0/24"), never a synthesized /32 or /128: a
	// ROA's maxLength routinely excludes a full-length prefix even when the
	// real, less-specific announcement it actually covers is valid, so
	// validating the wrong prefix reports a false "invalid" for nearly every
	// address (caught live: 1.1.1.1 queried as a /32 came back "invalid"
	// against Cloudflare's real, valid /24 ROA — a bug that would have made
	// this stage cry wolf on almost every target). Skip validation entirely,
	// honestly, rather than guess a prefix RIPEstat itself didn't resolve —
	// for every origin, not just the first (V1 hardening finding #5).
	if route.Prefix == "" {
		// StageUnknown, not StageOK: zero origins were actually proven RPKI
		// valid here — RIPEstat simply never resolved a prefix to validate
		// against, so this is inconclusive, never a clean bill of health
		// (V1 hardening finding #5, no-prefix status semantics fix).
		s.Status = StageUnknown
		s.Summary = fmt.Sprintf("Anunciado por %s; RIPEstat no resolvió el prefijo anunciado, por lo que no fue posible validar RPKI.", asnList(origins))
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}
	s.Subjects = append(s.Subjects, route.Prefix)

	// Each origin is validated against the SAME real route.Prefix — never a
	// per-origin synthetic prefix — and each actual RPKIValidate call gets
	// its own NetworkAction, so the disclosure reflects exactly what was
	// queried (V1 hardening finding #5: "registrar NetworkAction
	// correspondiente a la validación realmente realizada").
	var validCount, invalidCount, unknownCount int
	var invalidASNs []int
	for _, asn := range origins {
		s.NetworkActions = append(s.NetworkActions, netAction(StageIDRoutingSecurity, "bgp", fmt.Sprintf("%s AS%d", route.Prefix, asn), DestRIPEstat, "prefijo/ASN"))
		rpki := deps.BGP.RPKIValidate(bctx, asn, route.Prefix)
		if rpki.Err != "" || rpki.Status == "" {
			unknownCount++
			continue
		}
		s.Evidence = append(s.Evidence, model.Evidence{
			Type: "rpki_status", Value: rpki.Status, Source: "diagnosis",
			Provenance: model.ProvExternal, Confidence: 80, Timestamp: time.Now(),
			Explain: fmt.Sprintf("Validación RPKI ROV para AS%d / %s: %s.", asn, route.Prefix, rpki.Status),
		})
		switch rpki.Status {
		case "invalid":
			invalidCount++
			invalidASNs = append(invalidASNs, asn)
		case "valid":
			validCount++
		default:
			unknownCount++
		}
	}

	// Aggregate severity across every origin (V1 hardening finding #5):
	// ANY invalid origin is a warning worth investigating — never phrased
	// as a confirmed hijack, the same hedge the single-origin case already
	// carried. Only ALL-valid reaches StageOK; a mix of valid/unknown (no
	// invalid at all) never gets upgraded to a blanket "valid" when only
	// part of the MOAS set was actually validated.
	switch {
	case invalidCount > 0:
		s.Status = StageWarning
		s.Summary = fmt.Sprintf("RPKI inválido para %s — hallazgo de seguridad de ruta, no confirma un secuestro de ruta (hijack).", asnList(invalidASNs))
		s.Limitations = append(s.Limitations, "Un estado RPKI 'invalid' señala un ROA que no autoriza ese origen; por sí solo no distingue una mala configuración de un ataque.")
	case unknownCount == 0 && validCount > 0:
		s.Status = StageOK
		s.Summary = fmt.Sprintf("RPKI válido para %s.", asnList(origins))
	default:
		s.Status = StageUnknown
		s.Summary = fmt.Sprintf("Validación RPKI incompleta para %s: %d de %d origen(es) no se pudieron validar.", asnList(origins), unknownCount, len(origins))
	}

	s.DurationMs = time.Since(start).Milliseconds()
	return s
}

// uniqueOrigins deduplicates route.Origins while keeping RIPEstat's own
// first-seen order — RIPEstat can legitimately repeat an origin, and this
// package never treats that repetition as a second, distinct MOAS
// participant.
func uniqueOrigins(origins []int) []int {
	seen := make(map[int]bool, len(origins))
	out := make([]int, 0, len(origins))
	for _, asn := range origins {
		if seen[asn] {
			continue
		}
		seen[asn] = true
		out = append(out, asn)
	}
	return out
}

// asnList renders a set of origin ASNs for a Summary string — plain
// "AS64500, AS64501", never implying which one (if any) is legitimate.
func asnList(origins []int) string {
	parts := make([]string, len(origins))
	for i, asn := range origins {
		parts[i] = fmt.Sprintf("AS%d", asn)
	}
	return strings.Join(parts, ", ")
}
