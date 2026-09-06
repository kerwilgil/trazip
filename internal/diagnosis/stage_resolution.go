package diagnosis

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"trazip/internal/dnsintel"
	"trazip/internal/model"
)

// runResolution is always the first stage: every later stage that needs an
// IP depends on what this one establishes. A direct-IP target never touches
// DNS at all — resolving an address that's already an address would be a
// probe this package invented, not one an existing engine performs (package
// doc comment).
func runResolution(ctx context.Context, rt resolvedTarget, mode Mode) (DiagnosticStage, []netip.Addr) {
	start := time.Now()
	s := DiagnosticStage{ID: StageIDResolution, Label: "Resolución DNS", Subjects: []string{rt.host}}

	if rt.isDirect {
		s.Status = StageOK
		s.Summary = fmt.Sprintf("%s es una dirección IP directa; no requiere resolución DNS.", rt.host)
		s.DurationMs = time.Since(start).Milliseconds()
		return s, nil
	}

	if mode == ModeOffline {
		s.Status = StageSkipped
		s.Summary = "Modo offline: no se intentó resolución DNS."
		s.Limitations = []string{"Sin IP resuelto, las etapas que dependen de una dirección (alcance, ruta, propiedad, TLS/HTTP por IP) no pudieron ejecutarse."}
		s.DurationMs = time.Since(start).Milliseconds()
		return s, nil
	}

	s.NetworkOut = true
	s.NetworkActions = append(s.NetworkActions, netAction(StageIDResolution, "dns", rt.host, DestSystemResolver, "hostname"))
	addrs, err := resolveHost(ctx, rt.host)
	if err != nil {
		s.Status = StageProblem
		s.Summary = fmt.Sprintf("No se pudo resolver %q: %s", rt.host, err.Error())
		s.Evidence = append(s.Evidence, model.Evidence{
			Type: "dns_resolution_failed", Value: rt.host, Source: "diagnosis",
			Provenance: model.ProvObserved, Confidence: 90, Timestamp: time.Now(),
			Explain: "El resolver del sistema no devolvió direcciones para este nombre.",
		})
		s.DurationMs = time.Since(start).Milliseconds()
		return s, nil
	}
	if len(addrs) == 0 {
		s.Status = StageProblem
		s.Summary = fmt.Sprintf("%q resolvió sin direcciones.", rt.host)
		s.DurationMs = time.Since(start).Milliseconds()
		return s, nil
	}

	s.Status = StageOK
	vals := make([]string, len(addrs))
	for i, a := range addrs {
		vals[i] = a.String()
	}
	s.Summary = fmt.Sprintf("%q resolvió a %d dirección(es).", rt.host, len(addrs))
	s.Evidence = append(s.Evidence, model.Evidence{
		Type: "dns_resolved", Value: joinAddrs(vals), Source: "diagnosis",
		Provenance: model.ProvResolved, Confidence: 90, Timestamp: time.Now(),
		Explain: "Direcciones devueltas por el resolver DNS del sistema.",
	})

	if mode == ModeFull {
		s.NetworkActions = append(s.NetworkActions, netAction(StageIDResolution, "dns", rt.host, DestPublicResolver, "hostname"))
		cmp := dnsintel.Compare(ctx, rt.host, "A", dnsintel.WellKnownResolvers, false)
		if !cmp.Consistent {
			s.Evidence = append(s.Evidence, model.Evidence{
				Type: "dns_divergence", Value: fmt.Sprintf("%d divergencia(s)", len(cmp.Divergences)), Source: "diagnosis",
				Provenance: model.ProvObserved, Confidence: 80, Timestamp: time.Now(),
				Explain: "Los resolvers públicos comparados no devuelven el mismo conjunto de direcciones — puede ser DNS split-horizon, CDN por geolocalización, o una respuesta desactualizada en caché; no se afirma cuál resolver es el correcto.",
			})
			s.Limitations = append(s.Limitations, "Se detectó divergencia entre resolvers DNS; el resto de este diagnóstico usa únicamente la respuesta del resolver del sistema.")
		}
	}

	s.DurationMs = time.Since(start).Milliseconds()
	return s, addrs
}

func joinAddrs(vals []string) string {
	out := vals[0]
	for _, v := range vals[1:] {
		out += ", " + v
	}
	return out
}
