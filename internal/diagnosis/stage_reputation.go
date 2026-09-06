package diagnosis

import (
	"fmt"
	"net/netip"
	"time"

	"trazip/internal/intel/classify"
	"trazip/internal/intel/threatfeed"
	"trazip/internal/model"
	"trazip/internal/reputation"
)

// runReputation scores the address from offline data only — the downloaded
// threat lists are consulted locally, so this stage runs identically in
// every Mode including ModeOffline (master plan's Offline stage list names
// "reputation offline" explicitly), never sending the address anywhere.
func runReputation(deps Dependencies, haveIP bool, ip netip.Addr) DiagnosticStage {
	start := time.Now()
	s := DiagnosticStage{ID: StageIDReputation, Label: "Reputación"}

	if !haveIP {
		s.Status = StageSkipped
		s.Summary = "Sin dirección IP resuelta; no hay reputación que evaluar."
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}
	s.Subjects = []string{ip.String()}
	if !classify.IsPublic(ip) {
		s.Status = StageUnknown
		s.Summary = "Dirección no pública; no aplica reputación."
		s.DurationMs = time.Since(start).Milliseconds()
		return s
	}

	score := reputation.AssessOffline(ip)
	if deps.ThreatFeed != nil {
		for _, hit := range deps.ThreatFeed.Lookup(ip) {
			detail := hit.Detail
			if hit.Prefix != "" {
				detail += " (rango " + hit.Prefix + ")"
			}
			score = reputation.WithAdapterSignal(score, reputation.Signal{
				Source: "feed:" + hit.Feed, Label: string(hit.Category), Detail: detail, Confidence: "alta",
			}, feedWeight[hit.Category])
		}
	}

	s.Evidence = append(s.Evidence, model.Evidence{
		Type: "reputation_score", Value: fmt.Sprintf("%d/100 (%s)", score.Value, score.Level), Source: "diagnosis",
		Provenance: model.ProvResolved, Confidence: 75, Timestamp: time.Now(),
		Explain: score.Freshness,
	})
	for _, sig := range score.Signals {
		s.Evidence = append(s.Evidence, model.Evidence{
			Type: "reputation_signal", Value: sig.Label, Source: "diagnosis",
			Provenance: model.ProvResolved, Confidence: 70, Timestamp: time.Now(),
			Explain: sig.Detail,
		})
	}

	switch score.Level {
	case "alto riesgo":
		s.Status = StageWarning
		s.Summary = "Señales de reputación de alto riesgo (listas offline)."
	case "sospechoso":
		s.Status = StageWarning
		s.Summary = "Señales de reputación sospechosas (listas offline)."
	default:
		s.Status = StageOK
		s.Summary = "Sin señales de reputación negativas en las listas offline."
	}
	if deps.ThreatFeed == nil || !deps.ThreatFeed.Loaded() {
		s.Limitations = append(s.Limitations, "Sin listas de amenazas descargadas: este resultado no incluye comprobación contra Spamhaus DROP ni nodos Tor.")
	}

	s.DurationMs = time.Since(start).Milliseconds()
	return s
}

// feedWeight mirrors api.feedWeight (kept as its own copy rather than an
// import — api depends on diagnosis, not the other way, so sharing it would
// need moving both into a third package for one lookup table; see this
// file's sibling in internal/api/service.go for the reasoning behind each
// weight).
var feedWeight = map[threatfeed.Category]int{
	threatfeed.CatMalicious: 70,
	threatfeed.CatTor:       30,
}
