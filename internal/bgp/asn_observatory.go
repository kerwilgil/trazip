// ASN Observatory — v1.3 Gate 2 Part B. A one-shot count of one ASN's
// currently RIS-observed announced IPv4/IPv6 prefixes — never a
// subscription, never polling. Reuses AnnouncedPrefixesRaw
// (announced_prefixes.go, v1.1) instead of querying announced-prefixes a
// second time through a new code path: this file adds zero new HTTP
// calls beyond what that function already makes.
package bgp

import (
	"context"
	"fmt"
)

// ASNObservatoryRequest accepts the same ASN shapes ClassifyResource
// already normalizes: "AS13335" or "13335".
type ASNObservatoryRequest struct {
	ASN string
}

// ASNObservatoryResult is the bounded, honest result of one
// ASNObservatoryRequest. AnnouncedIPv4Prefixes/AnnouncedIPv6Prefixes are
// RIS-observed counts, never a claim of ownership, size, or importance.
type ASNObservatoryResult struct {
	ASN int `json:"asn"`

	AnnouncedIPv4Prefixes int `json:"announcedIPv4Prefixes"`
	AnnouncedIPv6Prefixes int `json:"announcedIPv6Prefixes"`

	// DataSufficient is true iff the underlying announced-prefixes call
	// succeeded — including when it explicitly reports zero prefixes
	// (Prefixes == []): a real, source-confirmed zero is DataSufficient,
	// a datasource failure never is.
	DataSufficient bool `json:"dataSufficient"`

	Evidence []ComponentEvidence `json:"evidence"`
	Err      string              `json:"err,omitempty"`
}

// ASNObservatory validates and normalizes req.ASN locally via the same
// ClassifyResource/parseCanonicalASN path Overview already uses (0 HTTP
// calls on any local rejection — empty, "AS0"/"0" per RFC 7607, negative,
// non-numeric, IPs, prefixes, country codes, or out-of-range all resolve
// to KindInvalid/non-KindASN before any network access), then reuses
// AnnouncedPrefixesRaw for the one HTTP call this result needs — this
// file never re-queries announced-prefixes through a second code path.
func (c *Client) ASNObservatory(ctx context.Context, req ASNObservatoryRequest) ASNObservatoryResult {
	var res ASNObservatoryResult

	kind, normalized := ClassifyResource(req.ASN)
	if kind != KindASN {
		res.Err = fmt.Sprintf("ASN inválido: %q", req.ASN)
		res.Evidence = []ComponentEvidence{{Component: "announced-prefixes", Status: ComponentNotApplicable}}
		return res
	}
	asn, err := parseCanonicalASN(normalized)
	if err != nil {
		res.Err = err.Error()
		res.Evidence = []ComponentEvidence{{Component: "announced-prefixes", Status: ComponentNotApplicable}}
		return res
	}
	res.ASN = asn

	ap := c.AnnouncedPrefixesRaw(ctx, asn)
	res.Evidence = []ComponentEvidence{ap.Evidence}
	if ap.Evidence.Status != ComponentOK {
		res.Err = ap.Err
		return res
	}

	v4, v6 := 0, 0
	for _, entry := range ap.Prefixes {
		switch kind, _ := ClassifyResource(entry.Prefix); kind {
		case KindPrefix4:
			v4++
		case KindPrefix6:
			v6++
		}
	}
	res.AnnouncedIPv4Prefixes = v4
	res.AnnouncedIPv6Prefixes = v6
	res.DataSufficient = true
	return res
}
