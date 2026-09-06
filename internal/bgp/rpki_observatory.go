// RPKI Observatory / History — v1.3 Gate 3. A one-shot VRP-count
// timeseries for one resource, backed entirely by RIPEstat's rpki-history
// endpoint — never a subscription, never polling.
//
// CONTRACT CORRECTION (verified live before implementing, per Gate 3's own
// mandatory wire preflight): rpki-history has no starttime/endtime
// parameters at all — its only parameters are resource (required),
// family (4|6), resolution (d|w|m|y), and delegated (unused here). This
// file therefore has no StartTime/EndTime request or result fields, does
// not reuse history.go/bgplay.go's validateTimeRange (that helper is
// contractually bound to bgp-updates/bgplay's own <=24h window, a
// different API), and never presents a locally-sliced subset of a larger
// download as if it were a requested range — whatever data.timeseries
// rpki-history actually returns for (resource, family, resolution) is
// the whole result, verbatim, in source order.
//
// WIRE POLYMORPHISM (verified live): rpki.vrp_count's JSON shape depends
// entirely on resolution — a bare number for resolution=d (e.g.
// "vrp_count": 7), but an object for resolution=w|m|y (e.g. "vrp_count":
// {"min":2,"max","avg","first","last","samples"}). This is why
// RPKIObservatoryPoint carries both a daily field (VRPCount) and six
// aggregated fields (Min/Max/Avg/First/Last/Samples) — never one shape
// pretending to be the other, and aggregated points never get a
// synthesized VRPCount.
//
// RESOURCE SCOPE (verified live before finalizing): rpki-history's wire
// shape for a PREFIX resource (IPv4/IPv6) is fundamentally different from
// its ASN/country shape verified above — no "rpki" wrapper at all, a flat
// scalar "vrp_count" regardless of resolution, plus "count" and
// "max_length" fields never seen on ASN/country responses. Confirmed
// live with two different prefixes (2001:4860::/32, 1.1.1.0/24) and two
// different resolution values (m, y) returning byte-identical datasets —
// "resolution" has no observable effect on a prefix query at all,
// contradicting the very premise this file's daily/aggregated point
// contract is built on. Rather than force this incompatible shape through
// the ASN/country decode path (which would either fail to decode or
// silently misreport a complete prefix history as ComponentDegraded),
// prefix resources are out of Gate 3's scope entirely — approved by the
// user rather than invent a third contract under time pressure. Only ASN
// and country resources are supported; a prefix or single IP is rejected
// locally with zero HTTP calls, same as a hostname or any other
// unsupported shape.
//
// SEMANTICS: rpki-history reports how many VRPs (Validated ROA Payloads)
// existed for this resource at each point in time — nothing about
// whether any particular BGP route is currently RPKI-valid. This file
// never produces VALID/INVALID_ASN/INVALID_LENGTH/UNKNOWN (those are
// rpki-validation's per-(prefix,origin) states, RPKIValidate in bgp.go —
// untouched by this Gate) and never computes a validity percentage,
// adoption metric, health/risk/security score, or hijack/attack
// inference from a VRP count trend. VRP count != route validity, and a
// VRP count going up or down carries no causal story this file will
// tell.
package bgp

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// rpkiHistoryResolutions is the only resolution values RIPEstat's
// rpki-history accepts.
var rpkiHistoryResolutions = map[string]bool{"d": true, "w": true, "m": true, "y": true}

// RPKIObservatoryRequest queries rpki-history for one resource — an ASN
// or an officially assigned ISO 3166-1 alpha-2 country code (prefixes are
// out of this Gate's scope, see package doc comment). There is
// deliberately no StartTime/EndTime (see package doc) and no Delegated
// (kept out of Gate 3's scope).
type RPKIObservatoryRequest struct {
	Resource   string
	Family     int    // 4 or 6
	Resolution string // "d" | "w" | "m" | "y"
}

// RPKIObservatoryPoint is one data.timeseries entry, decoded losslessly.
// For a daily-resolution request only VRPCount is populated (Min through
// Samples are all nil); for an aggregated (w|m|y) request only Min
// through Samples are populated (VRPCount is nil) — the two shapes are
// never mixed or converted into each other. Every pointer is nil when its
// wire field was genuinely absent, never a fabricated 0 — a present
// field whose real value is 0 is a distinct, valid pointer-to-zero.
type RPKIObservatoryPoint struct {
	Time string `json:"time"`

	// VRPCount is set only when Resolution=="d" — RIPEstat's raw
	// rpki.vrp_count integer for that day.
	VRPCount *int `json:"vrpCount,omitempty"`

	// Min/Max/Avg/First/Last/Samples are set only when
	// Resolution=="w"|"m"|"y" — RIPEstat's raw rpki.vrp_count.{min,max,
	// avg,first,last,samples} for that bin. Never reconstructed into a
	// single daily-style VRPCount, and never used to reconstruct any
	// daily value this Gate didn't actually receive.
	Min     *float64 `json:"min,omitempty"`
	Max     *float64 `json:"max,omitempty"`
	Avg     *float64 `json:"avg,omitempty"`
	First   *float64 `json:"first,omitempty"`
	Last    *float64 `json:"last,omitempty"`
	Samples *int     `json:"samples,omitempty"`
}

// RPKIObservatoryResult is the bounded, honest result of one
// RPKIObservatoryRequest.
type RPKIObservatoryResult struct {
	Resource string `json:"resource"`
	// ResourceKind is "asn" or "country" in this Gate — decided entirely
	// by this package's own ClassifyResource/isoAlpha2Countries
	// classification of the input, never read off any wire field (the
	// wire's own per-point asn/cc identifier is not decoded here and is
	// not authoritative for this field). "prefix" is intentionally
	// unreachable: prefix resources are rejected during validation (see
	// validateRPKIObservatoryRequest and this file's package doc comment)
	// because rpki-history's prefix wire shape is incompatible with this
	// Gate's contract — the value is typed as a plain string rather than
	// a closed enum so a future gate can add "prefix" without breaking
	// this field's type.
	ResourceKind string `json:"resourceKind"`
	Family       int    `json:"family"`
	Resolution   string `json:"resolution"`

	Points []RPKIObservatoryPoint `json:"points"`

	// DataSufficient is true only when the HTTP call and decode
	// succeeded, data.timeseries was non-empty, AND every point decoded
	// with its resolution-appropriate fields all present (§ Shape
	// Completeness). A single structurally incomplete point makes the
	// whole result insufficient — the already-decoded Points are still
	// returned (for transparency), but DataSufficient=false and Evidence
	// Degraded make clear the result must not be treated as complete.
	DataSufficient bool `json:"dataSufficient"`

	Evidence []ComponentEvidence `json:"evidence"`
	Err      string              `json:"err,omitempty"`
}

// rpkiHistoryDailyData/rpkiHistoryDailyPointWire mirror RIPEstat's real
// rpki-history response for resolution=d (verified live): rpki.vrp_count
// is a bare JSON number, absent (nil) rather than present-as-zero when
// the source has nothing for that day.
type rpkiHistoryDailyData struct {
	Timeseries []rpkiHistoryDailyPointWire `json:"timeseries"`
}

type rpkiHistoryDailyPointWire struct {
	Time string `json:"time"`
	RPKI struct {
		VRPCount *int `json:"vrp_count"`
	} `json:"rpki"`
}

// rpkiHistoryAggData/rpkiHistoryAggPointWire mirror RIPEstat's real
// rpki-history response for resolution=w|m|y (verified live):
// rpki.vrp_count is an object, not a bare number — a structurally
// different shape from the daily case at the exact same JSON path.
type rpkiHistoryAggData struct {
	Timeseries []rpkiHistoryAggPointWire `json:"timeseries"`
}

type rpkiHistoryAggPointWire struct {
	Time string `json:"time"`
	RPKI struct {
		VRPCount rpkiVRPCountAggWire `json:"vrp_count"`
	} `json:"rpki"`
}

type rpkiVRPCountAggWire struct {
	Min     *float64 `json:"min"`
	Max     *float64 `json:"max"`
	Avg     *float64 `json:"avg"`
	First   *float64 `json:"first"`
	Last    *float64 `json:"last"`
	Samples *int     `json:"samples"`
}

// validateRPKIObservatoryRequest enforces the full Gate 3 local contract
// before any network access: Family exactly 4 or 6, Resolution exactly
// one of d|w|m|y, Resource classified as either an ASN or an officially
// assigned ISO 3166-1 alpha-2 country code (reusing Gate 1's
// isoAlpha2Countries) — anything else (a prefix, a single IP, a hostname,
// an arbitrary string, a reserved/unassigned country code, an
// out-of-range or AS0 ASN) is rejected here, zero HTTP calls. Prefixes
// are rejected unconditionally regardless of Family — see this file's
// package doc comment for why (rpki-history's prefix wire shape was
// verified live to be fundamentally incompatible with this Gate's
// contract, an explicit scope decision, not an oversight).
func validateRPKIObservatoryRequest(req RPKIObservatoryRequest) (resource, kind string, err error) {
	if req.Family != 4 && req.Family != 6 {
		return "", "", fmt.Errorf("family inválida (se espera 4 o 6): %d", req.Family)
	}
	if !rpkiHistoryResolutions[req.Resolution] {
		return "", "", fmt.Errorf("resolution inválida (se espera exactamente d|w|m|y): %q", req.Resolution)
	}

	trimmed := strings.TrimSpace(req.Resource)
	if trimmed == "" {
		return "", "", fmt.Errorf("Resource vacío — obligatorio")
	}

	switch classified, normalized := ClassifyResource(trimmed); classified {
	case KindASN:
		return normalized, "asn", nil
	case KindPrefix4, KindPrefix6, KindIPv4, KindIPv6:
		return "", "", fmt.Errorf("prefijos e IPs individuales no soportados en RPKI Observatory v1.3 Gate 3 (rpki-history usa un wire incompatible para recursos de tipo prefix, verificado en vivo — fuera de alcance de este Gate); se espera ASN o código de país ISO alpha-2: %q", req.Resource)
	}

	// Not a resource ClassifyResource recognizes — the only remaining
	// accepted shape is an officially assigned ISO 3166-1 alpha-2 country
	// code (Gate 1's whitelist, reused verbatim).
	country := strings.ToUpper(trimmed)
	if isoAlpha2Countries[country] {
		return country, "country", nil
	}
	return "", "", fmt.Errorf("recurso inválido (se espera ASN o código de país ISO alpha-2 oficialmente asignado): %q", req.Resource)
}

// firstIncompleteDailyPoint returns the index and missing-field name of
// the first structurally incomplete daily point, or ok=false if every
// point has both Time and VRPCount present.
func firstIncompleteDailyPoint(points []rpkiHistoryDailyPointWire) (index int, field string, incomplete bool) {
	for i, p := range points {
		if p.Time == "" {
			return i, "time", true
		}
		if p.RPKI.VRPCount == nil {
			return i, "vrp_count", true
		}
	}
	return 0, "", false
}

// firstIncompleteAggPoint returns the index and missing-field name of the
// first structurally incomplete aggregated point, or ok=false if every
// point has Time and all six vrp_count fields present.
func firstIncompleteAggPoint(points []rpkiHistoryAggPointWire) (index int, field string, incomplete bool) {
	for i, p := range points {
		if p.Time == "" {
			return i, "time", true
		}
		v := p.RPKI.VRPCount
		switch {
		case v.Min == nil:
			return i, "min", true
		case v.Max == nil:
			return i, "max", true
		case v.Avg == nil:
			return i, "avg", true
		case v.First == nil:
			return i, "first", true
		case v.Last == nil:
			return i, "last", true
		case v.Samples == nil:
			return i, "samples", true
		}
	}
	return 0, "", false
}

// RPKIObservatory queries rpki-history for req.Resource at req.Resolution
// — one HTTP call, user-initiated, never polling, never a background
// timer or goroutine. Any local validation failure short-circuits before
// any network access, Evidence.Status = ComponentNotApplicable, Err
// honest and specific.
func (c *Client) RPKIObservatory(ctx context.Context, req RPKIObservatoryRequest) RPKIObservatoryResult {
	res := RPKIObservatoryResult{
		Family:     req.Family,
		Resolution: req.Resolution,
		Points:     []RPKIObservatoryPoint{},
	}

	resource, kind, err := validateRPKIObservatoryRequest(req)
	if err != nil {
		res.Resource = strings.TrimSpace(req.Resource)
		res.Err = err.Error()
		res.Evidence = []ComponentEvidence{{Component: "rpki-history", Status: ComponentNotApplicable}}
		return res
	}
	res.Resource = resource
	res.ResourceKind = kind

	// Disclosure reflects exactly resource/family/resolution — never a
	// requested time range, since rpki-history has none.
	dataSent := fmt.Sprintf("resource %s, family %d, resolution %s", resource, req.Family, req.Resolution)
	params := url.Values{
		"resource":   {resource},
		"family":     {strconv.Itoa(req.Family)},
		"resolution": {req.Resolution},
	}

	if req.Resolution == "d" {
		return c.fetchRPKIHistoryDaily(ctx, res, params, dataSent)
	}
	return c.fetchRPKIHistoryAggregated(ctx, res, params, dataSent)
}

func (c *Client) fetchRPKIHistoryDaily(ctx context.Context, res RPKIObservatoryResult, params url.Values, dataSent string) RPKIObservatoryResult {
	var data rpkiHistoryDailyData
	if err := c.get(ctx, "rpki-history", params, &data); err != nil {
		res.Err = err.Error()
		res.Evidence = []ComponentEvidence{{
			Component:  "rpki-history",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        res.Err,
		}}
		return res
	}
	if len(data.Timeseries) == 0 {
		res.Evidence = []ComponentEvidence{{Component: "rpki-history", Status: ComponentOK, Disclosure: disclosure(dataSent)}}
		return res
	}

	points := make([]RPKIObservatoryPoint, len(data.Timeseries))
	for i, p := range data.Timeseries {
		points[i] = RPKIObservatoryPoint{Time: p.Time, VRPCount: p.RPKI.VRPCount}
	}
	res.Points = points

	if idx, field, incomplete := firstIncompleteDailyPoint(data.Timeseries); incomplete {
		res.Err = fmt.Sprintf("rpki-history punto %d incompleto: %s ausente", idx, field)
		res.Evidence = []ComponentEvidence{{
			Component:  "rpki-history",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        res.Err,
		}}
		return res
	}

	res.DataSufficient = true
	res.Evidence = []ComponentEvidence{{Component: "rpki-history", Status: ComponentOK, Disclosure: disclosure(dataSent)}}
	return res
}

func (c *Client) fetchRPKIHistoryAggregated(ctx context.Context, res RPKIObservatoryResult, params url.Values, dataSent string) RPKIObservatoryResult {
	var data rpkiHistoryAggData
	if err := c.get(ctx, "rpki-history", params, &data); err != nil {
		res.Err = err.Error()
		res.Evidence = []ComponentEvidence{{
			Component:  "rpki-history",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        res.Err,
		}}
		return res
	}
	if len(data.Timeseries) == 0 {
		res.Evidence = []ComponentEvidence{{Component: "rpki-history", Status: ComponentOK, Disclosure: disclosure(dataSent)}}
		return res
	}

	points := make([]RPKIObservatoryPoint, len(data.Timeseries))
	for i, p := range data.Timeseries {
		points[i] = RPKIObservatoryPoint{
			Time:    p.Time,
			Min:     p.RPKI.VRPCount.Min,
			Max:     p.RPKI.VRPCount.Max,
			Avg:     p.RPKI.VRPCount.Avg,
			First:   p.RPKI.VRPCount.First,
			Last:    p.RPKI.VRPCount.Last,
			Samples: p.RPKI.VRPCount.Samples,
		}
	}
	res.Points = points

	if idx, field, incomplete := firstIncompleteAggPoint(data.Timeseries); incomplete {
		res.Err = fmt.Sprintf("rpki-history punto %d incompleto: %s ausente", idx, field)
		res.Evidence = []ComponentEvidence{{
			Component:  "rpki-history",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        res.Err,
		}}
		return res
	}

	res.DataSufficient = true
	res.Evidence = []ComponentEvidence{{Component: "rpki-history", Status: ComponentOK, Disclosure: disclosure(dataSent)}}
	return res
}
