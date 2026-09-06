package bgp

import "fmt"

// HealthState is one of the four public health states — deterministic,
// rule-based, never an ML/AI score.
type HealthState string

const (
	HealthNormal    HealthState = "normal"
	HealthAttention HealthState = "atencion"
	HealthDegraded  HealthState = "degradado"
	HealthRisk      HealthState = "riesgo"
)

var severityOrder = map[HealthState]int{
	HealthNormal:    0,
	HealthAttention: 1,
	HealthDegraded:  2,
	HealthRisk:      3,
}

func maxSeverity(a, b HealthState) HealthState {
	if severityOrder[b] > severityOrder[a] {
		return b
	}
	return a
}

// HealthRule is one evaluated rule — always reported, whether it fired
// or not, and whether it was even evaluable.
type HealthRule struct {
	ID     string `json:"id"`
	Fired  bool   `json:"fired"`
	Detail string `json:"detail"`
	// Applicable is false when the rule could not be evaluated at all
	// (insufficient data) — distinct from Fired=false, which means "was
	// evaluated and did not apply".
	Applicable bool `json:"applicable"`
}

// HealthResult is EvaluateHealth's output — every rule considered, plus
// whether the underlying data was sufficient to trust State at all.
type HealthResult struct {
	State          HealthState  `json:"state"`
	Rules          []HealthRule `json:"rules"`
	DataSufficient bool         `json:"dataSufficient"`
}

// EvaluateHealth is a pure function — no HTTP, no cache, no side
// effects — that derives a deterministic, explainable health state from
// an already-fetched Overview.
//
// Two-step algorithm:
//
// Step 1 decides whether the available data is sufficient to trust any
// security-signal conclusion at all. This is a decision, not an entry in
// the same max-severity calculation as Step 2 — DEGRADADO from Step 1
// wins outright over anything Step 2 might have concluded from partial
// data, because it represents an incomplete evaluation, not a route
// signal. Critical components are routing-status and, when relevant,
// every rpki-validation call the origins required — as-overview,
// announced-prefixes and asn-neighbours are never critical: their
// failure/inapplicability never forces DEGRADADO on its own.
//
// An ASN Overview (routing-status succeeded, but RPKI is deliberately
// not evaluated — no single representative prefix exists for it in this
// gate, see overview.go) is treated as insufficient rather than allowed
// to silently present as NORMAL: the security evaluation genuinely was
// not performed, and this must never be hidden behind a default state.
//
// Step 2, only entered when Step 1 confirms sufficiency, applies
// explicit, deterministic severity rules — never ML, never a numeric
// score, never an automatic "HIJACK" label.
func EvaluateHealth(ov Overview) HealthResult {
	sufficient := isDataSufficient(ov)

	rules := []HealthRule{
		ruleRPKIInvalid(ov, sufficient),
		ruleMOASDetected(ov, sufficient),
		ruleRPKIUnknownAll(ov, sufficient),
		ruleRPKIPartialUnknown(ov, sufficient),
		ruleNoRulesFired(ov, sufficient),
	}

	if !sufficient {
		return HealthResult{State: HealthDegraded, Rules: rules, DataSufficient: false}
	}

	state := HealthNormal
	for _, r := range rules {
		if !r.Applicable || !r.Fired {
			continue
		}
		switch r.ID {
		case "rpki-invalid":
			state = maxSeverity(state, HealthRisk)
		case "moas-detected", "rpki-unknown-all", "rpki-partial-unknown":
			state = maxSeverity(state, HealthAttention)
		}
	}
	return HealthResult{State: state, Rules: rules, DataSufficient: true}
}

// isDataSufficient implements Step 1. routing-status and every required
// rpki-validation are the only critical components; anything else being
// degraded/unavailable/not-applicable never forces insufficiency on its
// own.
func isDataSufficient(ov Overview) bool {
	rs := findEvidence(ov.Evidence, "routing-status")
	if rs == nil || rs.Status != ComponentOK {
		return false
	}

	// RPKI is deliberately never evaluated for an ASN Overview in this
	// gate (no single representative prefix) — presenting that as
	// "sufficient, all clear" would be exactly the false NORMAL this
	// algorithm must avoid.
	if ov.Kind == KindASN {
		return false
	}

	// A resource with no announced origins has no route security to
	// evaluate at all — same reasoning as the ASN case.
	if len(ov.Origins) == 0 {
		return false
	}

	// The defensive fan-out bound was hit — RPKI was intentionally
	// skipped, not degraded, but the evaluation is still incomplete.
	if len(ov.Origins) > maxOriginsForRPKIFanout {
		return false
	}

	// Every origin must have a completed, successful RPKI result — a
	// short fan-out (e.g. cut by context cancellation) or any degraded
	// individual lookup makes the evaluation incomplete.
	if len(ov.RPKI.Results) != len(ov.Origins) {
		return false
	}
	for _, r := range ov.RPKI.Results {
		if r.Evidence.Status != ComponentOK {
			return false
		}
	}
	return true
}

func findEvidence(evidence []ComponentEvidence, component string) *ComponentEvidence {
	for i := range evidence {
		if evidence[i].Component == component {
			return &evidence[i]
		}
	}
	return nil
}

func notApplicableRule(id string) HealthRule {
	return HealthRule{ID: id, Applicable: false, Detail: "no evaluable: datos insuficientes para una conclusión de seguridad confiable"}
}

func ruleRPKIInvalid(ov Overview, sufficient bool) HealthRule {
	if !sufficient {
		return notApplicableRule("rpki-invalid")
	}
	var invalidOrigins []int
	for _, res := range ov.RPKI.Results {
		if res.State == RPKIInvalidASN || res.State == RPKIInvalidLength {
			invalidOrigins = append(invalidOrigins, res.ASN)
		}
	}
	r := HealthRule{ID: "rpki-invalid", Applicable: true, Fired: len(invalidOrigins) > 0}
	if r.Fired {
		r.Detail = fmt.Sprintf("origen(es) con RPKI inválido (INVALID_ASN o INVALID_LENGTH): %v", invalidOrigins)
	} else {
		r.Detail = "ningún origen evaluado tiene RPKI inválido"
	}
	return r
}

func ruleMOASDetected(ov Overview, sufficient bool) HealthRule {
	if !sufficient {
		return notApplicableRule("moas-detected")
	}
	r := HealthRule{ID: "moas-detected", Applicable: true, Fired: ov.MOAS}
	if r.Fired {
		r.Detail = fmt.Sprintf("múltiples orígenes observados para el mismo recurso: %v", ov.Origins)
	} else {
		r.Detail = "un único origen observado"
	}
	return r
}

func ruleRPKIUnknownAll(ov Overview, sufficient bool) HealthRule {
	if !sufficient {
		return notApplicableRule("rpki-unknown-all")
	}
	r := HealthRule{ID: "rpki-unknown-all", Applicable: true}
	if len(ov.RPKI.Results) == 0 {
		r.Detail = "sin resultados RPKI que evaluar"
		return r
	}
	allUnknown := true
	for _, res := range ov.RPKI.Results {
		if res.State != RPKIUnknown {
			allUnknown = false
			break
		}
	}
	r.Fired = allUnknown
	if r.Fired {
		r.Detail = "todos los orígenes evaluados están en UNKNOWN (sin ROA que los cubra)"
	} else {
		r.Detail = "al menos un origen tiene un estado RPKI distinto de UNKNOWN"
	}
	return r
}

// ruleRPKIPartialUnknown is the conservative rule for the mixed
// VALID+UNKNOWN case: never automatically NORMAL, because at least one
// origin's claim could not be confirmed by a ROA, even though none was
// proven wrong.
func ruleRPKIPartialUnknown(ov Overview, sufficient bool) HealthRule {
	if !sufficient {
		return notApplicableRule("rpki-partial-unknown")
	}
	r := HealthRule{ID: "rpki-partial-unknown", Applicable: true}
	if len(ov.RPKI.Results) < 2 {
		r.Detail = "no aplica: menos de dos resultados RPKI"
		return r
	}
	hasValid, hasUnknown, hasInvalid := false, false, false
	for _, res := range ov.RPKI.Results {
		switch res.State {
		case RPKIValid:
			hasValid = true
		case RPKIUnknown:
			hasUnknown = true
		case RPKIInvalidASN, RPKIInvalidLength:
			hasInvalid = true
		}
	}
	r.Fired = hasValid && hasUnknown && !hasInvalid
	if r.Fired {
		r.Detail = "mezcla de orígenes VALID y UNKNOWN — al menos una afirmación de origen no pudo confirmarse mediante ROA"
	} else {
		r.Detail = "no se presenta esta combinación específica de estados"
	}
	return r
}

// ruleNoRulesFired is the positive confirmation of normality — it must
// be mutually exclusive with every other signal rule. It requires the
// narrowest possible condition (exactly one origin, exactly one
// successful RPKI result, that result VALID, no MOAS) rather than merely
// "a VALID exists and nothing invalid" — the latter would also fire
// alongside rpki-partial-unknown whenever a VALID+UNKNOWN mix is
// present, contradicting that rule's own ATENCIÓN conclusion.
func ruleNoRulesFired(ov Overview, sufficient bool) HealthRule {
	if !sufficient {
		return notApplicableRule("no-rules-fired")
	}
	r := HealthRule{
		ID:         "no-rules-fired",
		Applicable: true,
		Fired: len(ov.Origins) == 1 &&
			len(ov.RPKI.Results) == 1 &&
			ov.RPKI.Results[0].State == RPKIValid &&
			!ov.MOAS,
	}
	if r.Fired {
		r.Detail = "un único origen, con un único resultado RPKI VALID, sin MOAS — estado normal"
	} else {
		r.Detail = "las condiciones de normalidad no se cumplen"
	}
	return r
}
