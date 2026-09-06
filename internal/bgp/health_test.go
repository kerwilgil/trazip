package bgp

import "testing"

func findRule(rules []HealthRule, id string) *HealthRule {
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i]
		}
	}
	return nil
}

// newSufficientOverview builds a minimal Overview with routing-status OK
// and one ComponentOK rpki-validation result per origin/state pair — the
// Step-1-sufficient baseline most Health tests start from.
func newSufficientOverview(kind ResourceKind, origins []int, states []RPKIState) Overview {
	ov := Overview{Kind: kind, Origins: origins, MOAS: len(origins) > 1}
	ov.Evidence = []ComponentEvidence{{Component: "routing-status", Status: ComponentOK}}
	summary := RPKISummary{States: map[RPKIState]int{}}
	for i, st := range states {
		summary.Results = append(summary.Results, RPKIValidationDetailed{
			ASN: origins[i], State: st,
			Evidence: ComponentEvidence{Component: "rpki-validation", Status: ComponentOK},
		})
		summary.States[st]++
	}
	ov.RPKI = summary
	return ov
}

func TestEvaluateHealthNormal(t *testing.T) {
	ov := newSufficientOverview(KindIPv4, []int{13335}, []RPKIState{RPKIValid})
	res := EvaluateHealth(ov)
	if !res.DataSufficient {
		t.Fatalf("DataSufficient = false, want true")
	}
	if res.State != HealthNormal {
		t.Fatalf("State = %q, want %q", res.State, HealthNormal)
	}
	if r := findRule(res.Rules, "no-rules-fired"); r == nil || !r.Fired || !r.Applicable {
		t.Fatalf("no-rules-fired rule = %+v, want Fired=true Applicable=true", r)
	}
}

func TestEvaluateHealthAttentionMOAS(t *testing.T) {
	ov := newSufficientOverview(KindPrefix4, []int{1, 2}, []RPKIState{RPKIValid, RPKIValid})
	res := EvaluateHealth(ov)
	if res.State != HealthAttention {
		t.Fatalf("State = %q, want %q", res.State, HealthAttention)
	}
	if r := findRule(res.Rules, "moas-detected"); r == nil || !r.Fired {
		t.Fatalf("moas-detected rule = %+v, want Fired=true", r)
	}
}

func TestEvaluateHealthAttentionAllUnknown(t *testing.T) {
	ov := newSufficientOverview(KindIPv4, []int{1}, []RPKIState{RPKIUnknown})
	res := EvaluateHealth(ov)
	if res.State != HealthAttention {
		t.Fatalf("State = %q, want %q", res.State, HealthAttention)
	}
	if r := findRule(res.Rules, "rpki-unknown-all"); r == nil || !r.Fired {
		t.Fatalf("rpki-unknown-all rule = %+v, want Fired=true", r)
	}
}

func TestEvaluateHealthAttentionPartialUnknown(t *testing.T) {
	ov := newSufficientOverview(KindPrefix4, []int{1, 2}, []RPKIState{RPKIValid, RPKIUnknown})
	res := EvaluateHealth(ov)
	if res.State != HealthAttention {
		t.Fatalf("State = %q, want %q", res.State, HealthAttention)
	}
	if r := findRule(res.Rules, "rpki-partial-unknown"); r == nil || !r.Fired {
		t.Fatalf("rpki-partial-unknown rule = %+v, want Fired=true", r)
	}
}

func TestEvaluateHealthRiskInvalidASN(t *testing.T) {
	ov := newSufficientOverview(KindIPv4, []int{1}, []RPKIState{RPKIInvalidASN})
	res := EvaluateHealth(ov)
	if res.State != HealthRisk {
		t.Fatalf("State = %q, want %q", res.State, HealthRisk)
	}
	if r := findRule(res.Rules, "rpki-invalid"); r == nil || !r.Fired {
		t.Fatalf("rpki-invalid rule = %+v, want Fired=true", r)
	}
}

func TestEvaluateHealthRiskInvalidLength(t *testing.T) {
	ov := newSufficientOverview(KindIPv4, []int{1}, []RPKIState{RPKIInvalidLength})
	res := EvaluateHealth(ov)
	if res.State != HealthRisk {
		t.Fatalf("State = %q, want %q", res.State, HealthRisk)
	}
	if r := findRule(res.Rules, "rpki-invalid"); r == nil || !r.Fired {
		t.Fatalf("rpki-invalid rule = %+v, want Fired=true", r)
	}
}

func TestEvaluateHealthRiskWinsOverMOASSeverity(t *testing.T) {
	// MOAS alone is ATENCIÓN, but an invalid origin present in the same
	// MOAS must escalate to RIESGO — max-severity across Step 2's rules.
	ov := newSufficientOverview(KindPrefix4, []int{1, 2}, []RPKIState{RPKIValid, RPKIInvalidASN})
	res := EvaluateHealth(ov)
	if res.State != HealthRisk {
		t.Fatalf("State = %q, want %q", res.State, HealthRisk)
	}
	if r := findRule(res.Rules, "moas-detected"); r == nil || !r.Fired {
		t.Fatalf("moas-detected rule = %+v, want Fired=true (both rules fire, RIESGO wins by severity)", r)
	}
}

func TestEvaluateHealthDegradedOnRoutingStatusFailure(t *testing.T) {
	ov := Overview{
		Kind:     KindIPv4,
		Origins:  []int{1},
		Evidence: []ComponentEvidence{{Component: "routing-status", Status: ComponentDegraded}},
	}
	res := EvaluateHealth(ov)
	if res.DataSufficient {
		t.Fatalf("DataSufficient = true, want false")
	}
	if res.State != HealthDegraded {
		t.Fatalf("State = %q, want %q", res.State, HealthDegraded)
	}
	for _, r := range res.Rules {
		if r.Applicable {
			t.Errorf("rule %s: Applicable = true, want false — no rule is evaluable without sufficient data", r.ID)
		}
	}
}

func TestEvaluateHealthDegradedOnRequiredRPKIFailure(t *testing.T) {
	ov := Overview{
		Kind:     KindIPv4,
		Origins:  []int{1},
		Evidence: []ComponentEvidence{{Component: "routing-status", Status: ComponentOK}},
		RPKI: RPKISummary{
			Results: []RPKIValidationDetailed{
				{ASN: 1, Evidence: ComponentEvidence{Component: "rpki-validation", Status: ComponentDegraded}},
			},
		},
	}
	res := EvaluateHealth(ov)
	if res.DataSufficient {
		t.Fatalf("DataSufficient = true, want false")
	}
	if res.State != HealthDegraded {
		t.Fatalf("State = %q, want %q", res.State, HealthDegraded)
	}
}

func TestEvaluateHealthDegradedOnShortFanout(t *testing.T) {
	// Simulates a context-cancellation-cut fan-out: 2 origins but only 1
	// RPKI result — must never be evaluated as if complete.
	ov := Overview{
		Kind:     KindPrefix4,
		Origins:  []int{1, 2},
		MOAS:     true,
		Evidence: []ComponentEvidence{{Component: "routing-status", Status: ComponentOK}},
		RPKI: RPKISummary{
			Results: []RPKIValidationDetailed{
				{ASN: 1, State: RPKIValid, Evidence: ComponentEvidence{Component: "rpki-validation", Status: ComponentOK}},
			},
		},
	}
	res := EvaluateHealth(ov)
	if res.DataSufficient {
		t.Fatalf("DataSufficient = true, want false")
	}
	if res.State != HealthDegraded {
		t.Fatalf("State = %q, want %q", res.State, HealthDegraded)
	}
}

func TestEvaluateHealthASNOverviewNeverFalseNormal(t *testing.T) {
	// An ASN Overview never runs RPKI (see overview.go) — Health must
	// never present this as a confirmed NORMAL.
	ov := Overview{
		Kind: KindASN,
		Evidence: []ComponentEvidence{
			{Component: "routing-status", Status: ComponentOK},
			{Component: "rpki-validation", Status: ComponentNotApplicable},
		},
	}
	res := EvaluateHealth(ov)
	if res.State == HealthNormal {
		t.Fatalf("State = NORMAL for an ASN Overview where RPKI was never evaluated — must never silently present as confirmed-safe")
	}
	if res.DataSufficient {
		t.Fatalf("DataSufficient = true, want false — RPKI was deliberately not evaluated for this ASN Overview")
	}
}

func TestEvaluateHealthNotApplicableComponentDoesNotForceDegraded(t *testing.T) {
	// asn-neighbours (non-critical) being NotApplicable — e.g. a MOAS,
	// where no single ASN is attributable — must never by itself force
	// DEGRADADO when routing-status and every required RPKI call succeeded.
	ov := newSufficientOverview(KindPrefix4, []int{1, 2}, []RPKIState{RPKIValid, RPKIValid})
	ov.Evidence = append(ov.Evidence, ComponentEvidence{Component: "asn-neighbours", Status: ComponentNotApplicable})
	res := EvaluateHealth(ov)
	if !res.DataSufficient {
		t.Fatalf("DataSufficient = false, want true — asn-neighbours is not a critical component")
	}
	if res.State != HealthAttention {
		t.Fatalf("State = %q, want %q (MOAS still applies)", res.State, HealthAttention)
	}
}

func TestEvaluateHealthAlwaysReturnsAllRuleIDs(t *testing.T) {
	wantIDs := []string{"rpki-invalid", "moas-detected", "rpki-unknown-all", "rpki-partial-unknown", "no-rules-fired"}
	scenarios := []Overview{
		newSufficientOverview(KindIPv4, []int{1}, []RPKIState{RPKIValid}),
		{Kind: KindASN, Evidence: []ComponentEvidence{{Component: "routing-status", Status: ComponentOK}}},
		{Kind: KindIPv4, Evidence: []ComponentEvidence{{Component: "routing-status", Status: ComponentDegraded}}},
	}
	for i, ov := range scenarios {
		res := EvaluateHealth(ov)
		if len(res.Rules) != len(wantIDs) {
			t.Fatalf("scenario %d: len(Rules) = %d, want %d — every relevant rule must always be present, not just fired ones", i, len(res.Rules), len(wantIDs))
		}
		for _, id := range wantIDs {
			if findRule(res.Rules, id) == nil {
				t.Errorf("scenario %d: missing rule %q", i, id)
			}
		}
	}
}

// assertNoRulesFiredInvariant enforces mutual exclusivity: whenever any
// signal rule (rpki-invalid, moas-detected, rpki-unknown-all,
// rpki-partial-unknown) fires, no-rules-fired must not — it is the
// positive confirmation of normality, so it can never coexist with a
// signal it directly contradicts.
func assertNoRulesFiredInvariant(t *testing.T, rules []HealthRule) {
	t.Helper()
	signalIDs := []string{"rpki-invalid", "moas-detected", "rpki-unknown-all", "rpki-partial-unknown"}
	anySignalFired := false
	for _, id := range signalIDs {
		if r := findRule(rules, id); r != nil && r.Fired {
			anySignalFired = true
		}
	}
	noRulesFired := findRule(rules, "no-rules-fired")
	if noRulesFired == nil {
		t.Fatalf("no-rules-fired rule missing")
	}
	if anySignalFired && noRulesFired.Fired {
		t.Errorf("invariant violated: a signal rule fired but no-rules-fired.Fired = true")
	}
}

func TestEvaluateHealthRuleInvariants(t *testing.T) {
	cases := []struct {
		name      string
		ov        Overview
		wantState HealthState
		wantFired map[string]bool // rule ID -> want Fired; only asserted IDs are checked
	}{
		{
			name:      "unique VALID",
			ov:        newSufficientOverview(KindIPv4, []int{1}, []RPKIState{RPKIValid}),
			wantState: HealthNormal,
			wantFired: map[string]bool{
				"no-rules-fired":       true,
				"rpki-invalid":         false,
				"moas-detected":        false,
				"rpki-unknown-all":     false,
				"rpki-partial-unknown": false,
			},
		},
		{
			name:      "VALID + UNKNOWN",
			ov:        newSufficientOverview(KindPrefix4, []int{1, 2}, []RPKIState{RPKIValid, RPKIUnknown}),
			wantState: HealthAttention,
			wantFired: map[string]bool{
				"no-rules-fired":       false,
				"rpki-partial-unknown": true,
			},
		},
		{
			name:      "UNKNOWN único",
			ov:        newSufficientOverview(KindIPv4, []int{1}, []RPKIState{RPKIUnknown}),
			wantState: HealthAttention,
			wantFired: map[string]bool{
				"no-rules-fired":   false,
				"rpki-unknown-all": true,
			},
		},
		{
			name:      "MOAS VALID + VALID",
			ov:        newSufficientOverview(KindPrefix4, []int{1, 2}, []RPKIState{RPKIValid, RPKIValid}),
			wantState: HealthAttention,
			wantFired: map[string]bool{
				"no-rules-fired": false,
				"moas-detected":  true,
			},
		},
		{
			name:      "INVALID_ASN",
			ov:        newSufficientOverview(KindIPv4, []int{1}, []RPKIState{RPKIInvalidASN}),
			wantState: HealthRisk,
			wantFired: map[string]bool{
				"no-rules-fired": false,
				"rpki-invalid":   true,
			},
		},
		{
			name:      "INVALID_LENGTH",
			ov:        newSufficientOverview(KindIPv4, []int{1}, []RPKIState{RPKIInvalidLength}),
			wantState: HealthRisk,
			wantFired: map[string]bool{
				"no-rules-fired": false,
				"rpki-invalid":   true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := EvaluateHealth(tc.ov)
			if res.State != tc.wantState {
				t.Errorf("State = %q, want %q", res.State, tc.wantState)
			}
			for id, wantFired := range tc.wantFired {
				r := findRule(res.Rules, id)
				if r == nil {
					t.Fatalf("rule %q not found", id)
				}
				if r.Fired != wantFired {
					t.Errorf("rule %q: Fired = %v, want %v", id, r.Fired, wantFired)
				}
			}
			assertNoRulesFiredInvariant(t, res.Rules)
		})
	}
}
