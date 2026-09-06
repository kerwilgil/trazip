package bgp

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// maxASN is the largest valid 4-byte ASN (RFC 6793).
const maxASN = 4294967295

// RPKIState is the exact ROV outcome, mapped directly and losslessly
// from RIPEstat's raw top-level rpki-validation "status" field — never
// inferred or reconstructed from validating_roas, and never parsed out
// of RPKIStatus.Reason's free text.
type RPKIState string

const (
	RPKIValid         RPKIState = "VALID"
	RPKIInvalidASN    RPKIState = "INVALID_ASN"
	RPKIInvalidLength RPKIState = "INVALID_LENGTH"
	RPKIUnknown       RPKIState = "UNKNOWN"
)

// mapRPKIState is a pure, total mapping from RIPEstat's raw top-level
// status string to RPKIState. Anything it doesn't recognize — including
// a future status value RIPEstat might introduce — maps to RPKIUnknown,
// never to RPKIValid: an unrecognized status must never be silently
// treated as "safe".
func mapRPKIState(raw string) RPKIState {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "valid":
		return RPKIValid
	case "invalid_asn":
		return RPKIInvalidASN
	case "invalid_length":
		return RPKIInvalidLength
	default:
		return RPKIUnknown
	}
}

// RPKIValidationROA is one validating ROA, preserved as complementary
// evidence only — RPKIValidationDetailed.State never derives from this,
// only from the top-level status.
type RPKIValidationROA struct {
	Origin    string `json:"origin"`
	Prefix    string `json:"prefix"`
	MaxLength int    `json:"maxLength"`
	Validity  string `json:"validity"`
}

// RPKIValidationDetailed is the exact ROV outcome for one (ASN, prefix)
// pair. State always comes from RIPEstat's top-level data.status, never
// from ROAs — see mapRPKIState.
type RPKIValidationDetailed struct {
	ASN      int                 `json:"asn"`
	Prefix   string              `json:"prefix"`
	State    RPKIState           `json:"state"`
	ROAs     []RPKIValidationROA `json:"roas,omitempty"`
	Evidence ComponentEvidence   `json:"evidence"`
	Err      string              `json:"err,omitempty"`
}

// RPKIValidateDetailed calls the same rpki-validation endpoint as
// RPKIValidate but returns the exact top-level State (never collapsed to
// the "valid"/"invalid"/"unknown" summary normalizeRPKIStatus produces)
// plus the per-ROA evidence. RPKIValidate, RPKIStatus and
// normalizeRPKIStatus are untouched — existing callers
// (stage_routing_security.go, BGPRPKIValidate) keep their current
// behavior unchanged.
func (c *Client) RPKIValidateDetailed(ctx context.Context, asn int, prefix string) RPKIValidationDetailed {
	prefix = strings.TrimSpace(prefix)
	res := RPKIValidationDetailed{ASN: asn, Prefix: prefix}

	// Input validation happens entirely before any network access. A
	// rejected input is never a "datasource degraded" outcome — RIPEstat
	// was never asked anything — so Evidence.Status is
	// ComponentNotApplicable, never ComponentDegraded, and
	// Evidence.Err/Disclosure stay unpopulated (no external.Disclosure
	// exists for a call that never happened). The real error lives only
	// in RPKIValidationDetailed.Err.
	if asn <= 0 || asn > maxASN {
		res.Err = fmt.Sprintf("ASN inválido: %d (debe estar entre 1 y %d)", asn, maxASN)
		res.Evidence = ComponentEvidence{Component: "rpki-validation", Status: ComponentNotApplicable}
		return res
	}

	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		res.Err = "prefijo inválido: " + err.Error()
		res.Evidence = ComponentEvidence{Component: "rpki-validation", Status: ComponentNotApplicable}
		return res
	}
	prefix = p.Masked().String()

	cacheKey := fmt.Sprintf("rpki-validation|%d|%s", asn, prefix)
	if cached, ok := c.getCache().get(cacheKey); ok {
		result := cached.(RPKIValidationDetailed)
		result.Evidence.FromCache = true
		return result
	}

	result := c.fetchRPKIValidateDetailed(ctx, asn, prefix)
	if result.Evidence.Status == ComponentOK {
		c.getCache().set(cacheKey, result, rpkiValidationTTL)
	}
	return result
}

func (c *Client) fetchRPKIValidateDetailed(ctx context.Context, asn int, prefix string) RPKIValidationDetailed {
	res := RPKIValidationDetailed{ASN: asn, Prefix: prefix}
	dataSent := fmt.Sprintf("ASN %d + prefijo %s", asn, prefix)
	var data rpkiValidationData
	params := url.Values{"resource": {strconv.Itoa(asn)}, "prefix": {prefix}}
	if err := c.get(ctx, "rpki-validation", params, &data); err != nil {
		res.Err = err.Error()
		res.Evidence = ComponentEvidence{
			Component:  "rpki-validation",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        res.Err,
		}
		return res
	}

	res.State = mapRPKIState(data.Status)
	for _, roa := range data.ValidatingROAs {
		res.ROAs = append(res.ROAs, RPKIValidationROA{
			Origin:    roa.Origin,
			Prefix:    roa.Prefix,
			MaxLength: roa.MaxLength,
			Validity:  roa.Validity,
		})
	}
	res.Evidence = ComponentEvidence{
		Component:  "rpki-validation",
		Status:     ComponentOK,
		Disclosure: disclosure(dataSent),
	}
	return res
}
