package diagnosis

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"trazip/internal/model"
	"trazip/internal/probe/ping"
)

// runReachability sends a short bounded ICMP echo run — never a sustained
// monitor (that's Monitor's job, not Diagnose 2.0's). Deliberately does NOT
// escalate an unanswered ping to "host down": ICMP is commonly filtered by
// firewalls/NAT while the actual service stays fully reachable, so a 100%
// loss result is reported as StageWarning with an explicit limitation, never
// StageProblem (master plan: "DNS OK + ping timeout NO implica
// automáticamente host caído. Ping puede estar filtrado.").
func runReachability(ctx context.Context, haveIP bool, ip netip.Addr, mode Mode) DiagnosticStage {
	start := time.Now()
	s := DiagnosticStage{ID: StageIDReachability, Label: "Alcance (ICMP)"}

	if !haveIP {
		s.Status = StageSkipped
		s.Summary = "Sin dirección IP resuelta; no se intentó ping."
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}
	if mode == ModeOffline {
		s.Status = StageSkipped
		s.Summary = "Modo offline: sin pruebas activas."
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}

	s.Subjects = []string{ip.String()}
	s.NetworkOut = true
	s.NetworkActions = append(s.NetworkActions, netAction(StageIDReachability, "icmp", ip.String(), DestTarget, "IP objetivo + eco ICMP"))
	pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	stats, _, err := ping.Run(pctx, ping.Config{Target: ip.String(), Count: 4, Timeout: 1500 * time.Millisecond}, nil)
	if err != nil {
		s.Status = StageError
		s.Summary = "No se pudo ejecutar el ping: " + err.Error()
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}

	s.Evidence = append(s.Evidence, model.Evidence{
		Type: "icmp_ping", Value: fmt.Sprintf("%d/%d recibidos, %.0f%% pérdida", stats.Recv, stats.Sent, stats.LossPct), Source: "diagnosis",
		Provenance: model.ProvObserved, Confidence: 90, Timestamp: time.Now(),
		Explain: fmt.Sprintf("%d paquetes ICMP echo enviados a %s, %d respondidos.", stats.Sent, ip.String(), stats.Recv),
	})

	switch {
	case stats.Recv == 0:
		s.Status = StageWarning
		s.Summary = "Sin respuesta ICMP."
		s.Limitations = []string{"ICMP sin respuesta; no demuestra indisponibilidad del servicio — puede estar filtrado por firewall/NAT sin afectar el tráfico real."}
	case stats.LossPct > 0:
		s.Status = StageWarning
		s.Summary = fmt.Sprintf("Respuesta ICMP con %.0f%% de pérdida.", stats.LossPct)
	default:
		s.Status = StageOK
		s.Summary = fmt.Sprintf("Responde a ICMP, RTT promedio %.1fms.", stats.AvgMs)
		s.Evidence = append(s.Evidence, model.Evidence{
			Type: "icmp_rtt_avg", Value: fmt.Sprintf("%.1fms", stats.AvgMs), Source: "diagnosis",
			Provenance: model.ProvObserved, Confidence: 90, Timestamp: time.Now(),
			Explain: "RTT promedio observado en esta ronda corta de ping.",
		})
	}

	s.DurationMs = time.Since(start).Milliseconds()
	return s
}
