package bgp

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// bgpStateTTL follows the roadmap's "topología derivada" bucket (§15):
// 10 minutes. No stale/background refresh — on expiry the next call is
// simply live again, same as every other datasource in this package.
const bgpStateTTL = 10 * time.Minute

// BGPStateRoute is one raw route entry from RIPEstat's bgp-state — one
// AS path a RIS collector holds towards the queried resource, exactly as
// RIPEstat returned it (Path is never re-sorted, deduplicated, or
// reconstructed here — that belongs to topology.go's sanitization).
type BGPStateRoute struct {
	TargetPrefix string   `json:"targetPrefix"`
	SourceID     string   `json:"sourceId"`
	Path         []int    `json:"path"` // AS path in order, origin last
	Community    []string `json:"community,omitempty"`
}

// BGPStateResult is a RAW decode of RIPEstat's bgp-state for one
// resource — the sole source of real AS paths in this package. Never
// combined with or substituted by routing-status/asn-neighbours, and
// never crawled recursively (only the paths this one call returns).
type BGPStateResult struct {
	Resource  string          `json:"resource"`
	QueryTime string          `json:"queryTime,omitempty"`
	NrRoutes  int             `json:"nrRoutes"`
	Routes    []BGPStateRoute `json:"routes"`

	Evidence ComponentEvidence `json:"evidence"`
	Err      string            `json:"err,omitempty"`
}

type bgpStateData struct {
	Resource  string `json:"resource"`
	Timestamp string `json:"timestamp"`
	NrRoutes  int    `json:"nr_routes"`
	BGPState  []struct {
		TargetPrefix string   `json:"target_prefix"`
		SourceID     string   `json:"source_id"`
		Path         []int    `json:"path"`
		Community    []string `json:"community"`
	} `json:"bgp_state"`
}

// BGPState calls RIPEstat's bgp-state endpoint for one resource (ASN,
// IP, or prefix — validated locally via ClassifyResource before any
// network access, same as every other method in this package).
func (c *Client) BGPState(ctx context.Context, resource string) BGPStateResult {
	res := BGPStateResult{Resource: strings.TrimSpace(resource)}

	kind, normalized := ClassifyResource(resource)
	if kind == KindInvalid {
		res.Err = fmt.Sprintf("recurso inválido: %q", resource)
		res.Evidence = ComponentEvidence{Component: "bgp-state", Status: ComponentNotApplicable}
		return res
	}

	cacheKey := "bgp-state|" + normalized
	if cached, ok := c.getCache().get(cacheKey); ok {
		result := cached.(BGPStateResult)
		result.Evidence.FromCache = true
		return result
	}

	result := c.fetchBGPState(ctx, normalized)
	if result.Evidence.Status == ComponentOK {
		c.getCache().set(cacheKey, result, bgpStateTTL)
	}
	return result
}

func (c *Client) fetchBGPState(ctx context.Context, normalized string) BGPStateResult {
	res := BGPStateResult{Resource: normalized}
	dataSent := fmt.Sprintf("recurso %s", normalized)
	var data bgpStateData
	if err := c.get(ctx, "bgp-state", urlValuesResource(normalized), &data); err != nil {
		res.Err = err.Error()
		res.Evidence = ComponentEvidence{
			Component:  "bgp-state",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        res.Err,
		}
		return res
	}

	res.Resource = data.Resource
	res.QueryTime = data.Timestamp
	res.NrRoutes = data.NrRoutes
	for _, r := range data.BGPState {
		res.Routes = append(res.Routes, BGPStateRoute{
			TargetPrefix: r.TargetPrefix,
			SourceID:     r.SourceID,
			Path:         r.Path,
			Community:    r.Community,
		})
	}
	res.Evidence = ComponentEvidence{
		Component:  "bgp-state",
		Status:     ComponentOK,
		Disclosure: disclosure(dataSent),
	}
	return res
}
