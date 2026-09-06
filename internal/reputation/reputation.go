// Package reputation implements the offline reputation scorer (prompt
// maestro §9 Fase 4, módulo 23): "listas offline y adaptadores web
// opcionales... ningún proveedor será fuente única." The always-available
// path scores an address from the same versioned offline classification
// engine used by Raw Traffic GeoIP (internal/intel/classify) — never a
// single external verdict.
//
// classify.Classify currently only ever returns bogon/reserved/documentation
// (plus the neutral public/private) — its own doc comment notes VPN/Tor/
// hosting labels are "dataset-backed... layered on top elsewhere," and that
// layer doesn't exist in this codebase yet. classWeight below already
// accounts for vpn/proxy/tor/hosting so this scorer needs zero changes once
// that dataset layer lands; until then those signals are simply inert, not
// broken — don't read AssessOffline's current output as "checked for VPN."
//
// §5.7 names ipquery.io as an explicitly-opt-in corroboration adapter
// ("nunca fuente primaria"), but its exact current API contract isn't
// something this package can verify offline, and guessing an endpoint to
// wire real user IP data into would be exactly the kind of unverified
// external call the security rules ask not to fabricate. AdapterResult and
// the Adapter function type below are the extension point for that (or any
// other opt-in web adapter) — deliberately left unimplemented rather than
// wired to a guessed URL. See CONTEXT-trazip.md for the exact next step.
package reputation

import (
	"net/netip"

	"trazip/internal/intel/classify"
	"trazip/internal/intel/external"
)

// Signal is one piece of evidence behind a score — never a bare verdict.
type Signal struct {
	Source     string `json:"source"` // e.g. "classify:vpn", "classify:tor"
	Label      string `json:"label"`
	Detail     string `json:"detail"`
	Confidence string `json:"confidence"` // "alta" (listas offline curadas) | "media" (adaptador web opcional)
	Delta      int    `json:"delta"`      // how many points this signal cost, for transparency
}

// Score is the offline reputation assessment for one address.
type Score struct {
	Addr              string   `json:"addr"`
	Value             int      `json:"value"` // 0-100; 100 = sin señales negativas
	Level             string   `json:"level"` // "limpio" | "sospechoso" | "alto riesgo"
	Signals           []Signal `json:"signals,omitempty"`
	Freshness         string   `json:"freshness"` // dataset provenance note, never invented
	FalsePositiveNote string   `json:"falsePositiveNote"`
}

// classWeight is how many points each offline classification costs — bogons
// are weighted heaviest since a bogon address should never appear as a live
// traffic endpoint at all, unlike VPN/proxy/hosting which are legitimate,
// common traffic sources that merely warrant a note.
var classWeight = map[string]int{
	"tor":           30,
	"vpn":           20,
	"proxy":         20,
	"hosting":       10,
	"bogon":         70, // a bogon alone must land in "alto riesgo" — it should never route at all
	"reserved":      15,
	"documentation": 15,
}

const (
	levelClean      = "limpio"
	levelSuspicious = "sospechoso"
	levelHighRisk   = "alto riesgo"
)

// AssessOffline scores addr using only local, versioned datasets — no
// network call, always available, safe to run on every endpoint without
// asking (unlike the web adapter extension point).
func AssessOffline(addr netip.Addr) Score {
	score := Score{
		Addr:      addr.String(),
		Value:     100,
		Signals:   nil,
		Freshness: "listas offline versionadas (VPN/Tor/bogons/reservados) — ver Settings/Datasets para fecha de build",
		FalsePositiveNote: "las listas VPN/proxy/hosting identifican rangos de proveedores, no comportamiento individual: " +
			"una IP dentro de un rango de hosting puede ser tráfico legítimo de servidor, no evidencia de abuso por sí sola.",
	}

	classes := classify.Classify(addr)
	for _, c := range classes {
		cls := string(c)
		if cls == "public" || cls == "private" {
			continue // neutral classifications, not reputation signals
		}
		weight, known := classWeight[cls]
		if !known {
			continue
		}
		score.Signals = append(score.Signals, Signal{
			Source:     "classify:" + cls,
			Label:      cls,
			Detail:     "dirección clasificada como " + cls + " por las listas offline de TRAZIP",
			Confidence: "alta",
			Delta:      -weight,
		})
		score.Value -= weight
	}

	if score.Value < 0 {
		score.Value = 0
	}
	score.Level = levelFromValue(score.Value)
	return score
}

func levelFromValue(v int) string {
	switch {
	case v >= 80:
		return levelClean
	case v >= 40:
		return levelSuspicious
	default:
		return levelHighRisk
	}
}

// AdapterResult is what an opt-in web reputation adapter would return.
type AdapterResult struct {
	Signal     Signal
	Disclosure external.Disclosure
	Err        string
}

// Adapter is the extension point for an opt-in, explicitly-triggered web
// reputation source (e.g. ipquery.io per §5.7). None is wired by default —
// see the package doc comment for why.
type Adapter func(addr netip.Addr) (AdapterResult, error)

// WithAdapterSignal merges one opt-in adapter's signal into an existing
// offline Score, re-deriving Value/Level — used by the GUI after the user
// explicitly triggers a web corroboration check, never automatically.
func WithAdapterSignal(base Score, adapterSignal Signal, delta int) Score {
	adapterSignal.Delta = -delta
	base.Signals = append(base.Signals, adapterSignal)
	base.Value -= delta
	if base.Value < 0 {
		base.Value = 0
	}
	if base.Value > 100 {
		base.Value = 100
	}
	base.Level = levelFromValue(base.Value)
	return base
}
