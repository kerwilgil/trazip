package diagnosis

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"trazip/internal/model"
	"trazip/internal/probe/trace"
)

// runRoute performs a short, bounded traceroute — ModeFull gets more hops
// and more probes per hop than ModeStandard, but both stay a single quick
// pass, never MTR's sustained per-hop monitoring (that belongs to Monitor).
//
// A timed-out intermediate hop that the trace nonetheless continues past —
// reaching the destination on a later TTL — is recorded as a limitation on
// THAT hop only, never escalated into "end-to-end packet loss": routers very
// commonly deprioritize or drop the ICMP TTL-exceeded replies traceroute
// depends on while still forwarding the actual traffic behind them (master
// plan: "pérdida en hop intermedio que NO continúa a destino NO debe
// diagnosticarse como pérdida end-to-end").
func runRoute(ctx context.Context, haveIP bool, ip netip.Addr, mode Mode) DiagnosticStage {
	start := time.Now()
	s := DiagnosticStage{ID: StageIDRoute, Label: "Ruta"}

	if !haveIP {
		s.Status = StageSkipped
		s.Summary = "Sin dirección IP resuelta; no se intentó traceroute."
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}
	if mode == ModeOffline {
		s.Status = StageSkipped
		s.Summary = "Modo offline: sin pruebas activas."
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}

	cfg := trace.Config{Target: ip.String(), MaxHops: 20, Probes: 1, Timeout: 1500 * time.Millisecond}
	if mode == ModeFull {
		cfg.MaxHops, cfg.Probes = 30, 2
	}

	s.Subjects = []string{ip.String()}
	s.NetworkOut = true
	s.NetworkActions = append(s.NetworkActions, netAction(StageIDRoute, "traceroute", ip.String(), DestTargetPath, "IP objetivo + sondas"))
	tctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	hops, _, err := trace.Run(tctx, cfg, nil)
	if err != nil {
		s.Status = StageError
		s.Summary = "No se pudo ejecutar el traceroute: " + err.Error()
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}

	reachedAt := -1
	timedOutIntermediate := 0
	for i, h := range hops {
		if h.Reached {
			reachedAt = i
		} else if h.Timeout {
			timedOutIntermediate++
		}
	}

	s.Evidence = append(s.Evidence, model.Evidence{
		Type: "traceroute_hops", Value: fmt.Sprintf("%d saltos", len(hops)), Source: "diagnosis",
		Provenance: model.ProvObserved, Confidence: 85, Timestamp: time.Now(),
		Explain: fmt.Sprintf("Traceroute corto hacia %s, %d saltos observados.", ip.String(), len(hops)),
	})

	switch {
	case reachedAt >= 0:
		s.Status = StageOK
		s.Summary = fmt.Sprintf("Ruta alcanza el destino en %d saltos.", reachedAt+1)
		if timedOutIntermediate > 0 {
			s.Limitations = append(s.Limitations, fmt.Sprintf(
				"%d salto(s) intermedio(s) no respondieron al TTL-exceeded, pero la ruta sí llegó al destino — no se interpreta como pérdida end-to-end; el hop intermedio pudo simplemente no responder ICMP.", timedOutIntermediate))
		}
	case len(hops) == 0:
		s.Status = StageUnknown
		s.Summary = "El traceroute no devolvió saltos."
	default:
		s.Status = StageWarning
		s.Summary = fmt.Sprintf("La ruta no confirmó llegar al destino dentro de %d saltos.", cfg.MaxHops)
		s.Limitations = append(s.Limitations, "Un traceroute corto sin confirmar el destino no demuestra que la ruta esté rota — puede requerir más saltos, o el destino puede no responder ICMP aunque el servicio esté disponible.")
	}

	s.DurationMs = time.Since(start).Milliseconds()
	return s
}
