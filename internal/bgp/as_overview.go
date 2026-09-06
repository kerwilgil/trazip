package bgp

import (
	"context"
	"fmt"
)

// ASBlock is IANA registry evidence for the ASN block an ASN falls
// within — complementary metadata, not a claim about the ASN itself.
type ASBlock struct {
	Resource string `json:"resource,omitempty"`
	Desc     string `json:"desc,omitempty"`
	Name     string `json:"name,omitempty"`
}

// ASOverviewResult is RIPEstat's as-overview for one ASN.
//
// Announced==false means exactly one thing: this ASN did not originate
// any prefix visible to at least 10 full-feed RIS peers at query time —
// per RIPEstat's own definition. It is NOT evidence of the ASN being
// down, non-existent, unreachable, non-routable, or risky. A
// transit-only ASN legitimately never originates anything and will
// always show Announced=false.
type ASOverviewResult struct {
	Resource  string   `json:"resource"`
	Announced bool     `json:"announced"`
	Holder    string   `json:"holder,omitempty"` // empty if RIPEstat returned null/absent — never fabricated
	Type      string   `json:"type,omitempty"`
	Block     *ASBlock `json:"block,omitempty"`

	Evidence ComponentEvidence `json:"evidence"`
	Err      string            `json:"err,omitempty"`
}

type asOverviewData struct {
	Resource  string  `json:"resource"`
	Announced bool    `json:"announced"`
	Holder    *string `json:"holder"`
	Type      string  `json:"type"`
	Block     *struct {
		Resource string `json:"resource"`
		Desc     string `json:"desc"`
		Name     string `json:"name"`
	} `json:"block"`
}

// ASOverview calls RIPEstat's as-overview endpoint for one ASN. A null or
// absent holder is left as an empty string — never fabricated — and does
// not by itself make the call anything other than ComponentOK, since the
// rest of the response (announced, resource) is still valid and usable.
// ComponentUnavailable is reserved for a response that produces no
// usable data at all, not for each individually-optional field being
// empty.
func (c *Client) ASOverview(ctx context.Context, asn int) ASOverviewResult {
	res := ASOverviewResult{Resource: fmt.Sprintf("AS%d", asn)}

	if asn <= 0 || asn > maxASN {
		res.Err = fmt.Sprintf("ASN inválido: %d (debe estar entre 1 y %d)", asn, maxASN)
		res.Evidence = ComponentEvidence{Component: "as-overview", Status: ComponentNotApplicable}
		return res
	}

	cacheKey := fmt.Sprintf("as-overview|%d", asn)
	if cached, ok := c.getCache().get(cacheKey); ok {
		result := cached.(ASOverviewResult)
		result.Evidence.FromCache = true
		return result
	}

	result := c.fetchASOverview(ctx, asn)
	if result.Evidence.Status == ComponentOK {
		c.getCache().set(cacheKey, result, asOverviewTTL)
	}
	return result
}

func (c *Client) fetchASOverview(ctx context.Context, asn int) ASOverviewResult {
	res := ASOverviewResult{Resource: fmt.Sprintf("AS%d", asn)}
	dataSent := fmt.Sprintf("ASN %d", asn)
	var data asOverviewData
	if err := c.get(ctx, "as-overview", urlValuesResource(fmt.Sprintf("AS%d", asn)), &data); err != nil {
		res.Err = err.Error()
		res.Evidence = ComponentEvidence{
			Component:  "as-overview",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        res.Err,
		}
		return res
	}

	res.Resource = data.Resource
	res.Announced = data.Announced
	res.Type = data.Type
	if data.Holder != nil {
		res.Holder = *data.Holder
	}
	if data.Block != nil {
		res.Block = &ASBlock{Resource: data.Block.Resource, Desc: data.Block.Desc, Name: data.Block.Name}
	}
	res.Evidence = ComponentEvidence{
		Component:  "as-overview",
		Status:     ComponentOK,
		Disclosure: disclosure(dataSent),
	}
	return res
}
