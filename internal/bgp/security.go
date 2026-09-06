package bgp

import "context"

// SecurityResult is a single-resource point-in-time security analysis.
// It never labels anything "HIJACK" and never carries a numeric/ML
// score — see Health.
type SecurityResult struct {
	Resource string       `json:"resource"`
	Kind     ResourceKind `json:"kind"`

	// ASN is set for a KindASN resource. For IP/prefix resources it is
	// always 0 — Origins carries the relevant ASN(s) instead.
	ASN int `json:"asn,omitempty"`

	// Prefix is RIPEstat's own resolved covering prefix for an IP/prefix
	// resource — never fabricated, empty for a KindASN resource.
	Prefix  string `json:"prefix,omitempty"`
	Origins []int  `json:"origins,omitempty"`
	MOAS    bool   `json:"moas"`

	// RPKI covers every relevant origin for an IP/prefix resource (see
	// Overview.overviewForIPOrPrefix) — never just the first, never
	// collapsed into one ambiguous result. For a KindASN resource this is
	// always empty: RPKI validation is prefix-scoped, not something this
	// package fabricates as a "global ASN RPKI state". A caller wanting
	// RPKI coverage for an ASN must pivot to one of its specific
	// prefixes (see PrefixList) — never inferred here.
	RPKI RPKISummary `json:"rpki"`

	// Health reuses EvaluateHealth verbatim — no rule is duplicated or
	// reimplemented here.
	Health HealthResult `json:"health"`

	Evidence []ComponentEvidence `json:"evidence"`

	// Complete is false whenever RPKI coverage could not be evaluated in
	// full — a KindASN resource (RPKI is deliberately never evaluated
	// globally), an origin count beyond maxOriginsForRPKIFanout, a
	// short/cancelled fan-out, or a routing-status/RPKI failure. It
	// mirrors Health.DataSufficient exactly (see EvaluateHealth's Step 1)
	// rather than reimplementing an equivalent check. Complete is about
	// evaluation coverage, not verdict — RIESGO/ATENCIÓN from a fully
	// covered evaluation is still Complete=true.
	Complete bool   `json:"complete"`
	Err      string `json:"err,omitempty"`
}

// Security produces a point-in-time security analysis for one resource
// (ASN, IP, or prefix), reusing Overview for resolution/RPKI fan-out and
// EvaluateHealth for the health verdict — no datasource call or Health
// rule is reimplemented here.
func (c *Client) Security(ctx context.Context, resource string) SecurityResult {
	ov := c.Overview(ctx, resource)

	res := SecurityResult{
		Resource: ov.Resource,
		Kind:     ov.Kind,
		ASN:      ov.ASN,
		Origins:  ov.Origins,
		MOAS:     ov.MOAS,
		RPKI:     ov.RPKI,
		Evidence: ov.Evidence,
		Err:      ov.Err,
	}
	if len(ov.Prefixes) > 0 {
		res.Prefix = ov.Prefixes[0]
	}

	res.Health = EvaluateHealth(ov)
	res.Complete = res.Health.DataSufficient
	return res
}
