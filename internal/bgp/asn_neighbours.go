package bgp

import (
	"context"
	"fmt"
)

// NeighbourPosition is the observed adjacency direction from RIS's point
// of view — never a commercial relationship. "left"/"right" mirror
// RIPEstat's own AS-path terminology (the neighbour appears immediately
// before/after the queried ASN in observed paths); "uncertain" is
// RIPEstat's own value for a neighbour seen only as a RIS collector's
// direct peer, with no clear path position. This package must never
// produce "provider"/"customer"/"upstream"/"downstream"/"Tier-1"/
// "transit provider"/"commercial peer" from this data — none of that is
// something RIS observations can prove.
type NeighbourPosition string

const (
	PositionLeft      NeighbourPosition = "left"
	PositionRight     NeighbourPosition = "right"
	PositionUncertain NeighbourPosition = "uncertain"
	// PositionUnknown is distinct from PositionUncertain: "uncertain" is
	// RIPEstat's own documented value with its own meaning (a neighbour
	// seen only as a RIS collector's direct peer). PositionUnknown is
	// what this decoder falls back to for anything else it doesn't
	// recognize — e.g. a future value RIPEstat introduces — so the two
	// are never conflated. RawPosition below preserves the original
	// string either way.
	PositionUnknown NeighbourPosition = "unknown"
)

// NeighbourObservation is one observed adjacency — "vecino observado",
// never a business relationship.
type NeighbourObservation struct {
	ASN         int               `json:"asn"`
	Position    NeighbourPosition `json:"position"`
	RawPosition string            `json:"rawPosition"` // the exact value RIPEstat sent, before normalization — lossless even for PositionUnknown
	PathCount   int               `json:"pathCount"`
	PeerCountV4 int               `json:"peerCountV4"`
	PeerCountV6 int               `json:"peerCountV6"`
}

// NeighbourCounts are the aggregate counts RIPEstat reports alongside the
// per-neighbour list.
type NeighbourCounts struct {
	Left      int `json:"left"`
	Right     int `json:"right"`
	Unique    int `json:"unique"`
	Uncertain int `json:"uncertain"`
}

// ASNNeighboursResult is a RAW decode of RIPEstat's asn-neighbours for
// one ASN — direct RIS-observed adjacencies only.
type ASNNeighboursResult struct {
	Resource        string                 `json:"resource"`
	QueryTime       string                 `json:"queryTime,omitempty"`
	NeighbourCounts NeighbourCounts        `json:"neighbourCounts"`
	Neighbours      []NeighbourObservation `json:"neighbours"`

	Evidence ComponentEvidence `json:"evidence"`
	Err      string            `json:"err,omitempty"`
}

// asnNeighbourRaw accepts both known wire shapes RIPEstat's
// asn-neighbours has used across versions (type vs. position naming;
// power vs. path_count; v4_peers/v6_peers vs. nested peer_count) and
// normalizes them into one stable internal contract — never inferring a
// value that isn't present in either form.
type asnNeighbourRaw struct {
	ASN       int    `json:"asn"`
	Type      string `json:"type"`
	Position  string `json:"position"`
	Power     int    `json:"power"`
	PathCount int    `json:"path_count"`
	V4Peers   int    `json:"v4_peers"`
	V6Peers   int    `json:"v6_peers"`
	PeerCount struct {
		V4 int `json:"v4"`
		V6 int `json:"v6"`
	} `json:"peer_count"`
}

type asnNeighboursData struct {
	Resource        string `json:"resource"`
	QueryTime       string `json:"query_time"`
	NeighbourCounts struct {
		Left      int `json:"left"`
		Right     int `json:"right"`
		Unique    int `json:"unique"`
		Uncertain int `json:"uncertain"`
	} `json:"neighbour_counts"`
	Neighbours []asnNeighbourRaw `json:"neighbours"`
}

func normalizePosition(raw string) NeighbourPosition {
	switch raw {
	case "left":
		return PositionLeft
	case "right":
		return PositionRight
	case "uncertain":
		return PositionUncertain
	default:
		// Anything else — including a future value RIPEstat might
		// introduce — is PositionUnknown, never silently folded into
		// "uncertain" (which has its own documented meaning) or guessed
		// as left/right. RawPosition preserves the original string.
		return PositionUnknown
	}
}

// AsnNeighboursRaw calls RIPEstat's asn-neighbours endpoint for one ASN.
// Zero neighbours is a valid, ComponentOK result — not
// ComponentUnavailable.
func (c *Client) AsnNeighboursRaw(ctx context.Context, asn int) ASNNeighboursResult {
	res := ASNNeighboursResult{Resource: fmt.Sprintf("AS%d", asn)}

	if asn <= 0 || asn > maxASN {
		res.Err = fmt.Sprintf("ASN inválido: %d (debe estar entre 1 y %d)", asn, maxASN)
		res.Evidence = ComponentEvidence{Component: "asn-neighbours", Status: ComponentNotApplicable}
		return res
	}

	cacheKey := fmt.Sprintf("asn-neighbours|%d", asn)
	if cached, ok := c.getCache().get(cacheKey); ok {
		result := cached.(ASNNeighboursResult)
		result.Evidence.FromCache = true
		return result
	}

	result := c.fetchAsnNeighbours(ctx, asn)
	if result.Evidence.Status == ComponentOK {
		c.getCache().set(cacheKey, result, asnNeighboursTTL)
	}
	return result
}

func (c *Client) fetchAsnNeighbours(ctx context.Context, asn int) ASNNeighboursResult {
	res := ASNNeighboursResult{Resource: fmt.Sprintf("AS%d", asn)}
	dataSent := fmt.Sprintf("ASN %d", asn)
	var data asnNeighboursData
	if err := c.get(ctx, "asn-neighbours", urlValuesResource(fmt.Sprintf("AS%d", asn)), &data); err != nil {
		res.Err = err.Error()
		res.Evidence = ComponentEvidence{
			Component:  "asn-neighbours",
			Status:     ComponentDegraded,
			Disclosure: disclosure(dataSent),
			Err:        res.Err,
		}
		return res
	}

	res.Resource = data.Resource
	res.QueryTime = data.QueryTime
	res.NeighbourCounts = NeighbourCounts{
		Left: data.NeighbourCounts.Left, Right: data.NeighbourCounts.Right,
		Unique: data.NeighbourCounts.Unique, Uncertain: data.NeighbourCounts.Uncertain,
	}

	for _, n := range data.Neighbours {
		position := n.Type
		if position == "" {
			position = n.Position
		}

		pathCount := n.PathCount
		if pathCount == 0 {
			pathCount = n.Power
		}

		peerV4 := n.V4Peers
		if peerV4 == 0 {
			peerV4 = n.PeerCount.V4
		}
		peerV6 := n.V6Peers
		if peerV6 == 0 {
			peerV6 = n.PeerCount.V6
		}

		res.Neighbours = append(res.Neighbours, NeighbourObservation{
			ASN:         n.ASN,
			Position:    normalizePosition(position),
			RawPosition: position,
			PathCount:   pathCount,
			PeerCountV4: peerV4,
			PeerCountV6: peerV6,
		})
	}

	res.Evidence = ComponentEvidence{
		Component:  "asn-neighbours",
		Status:     ComponentOK,
		Disclosure: disclosure(dataSent),
	}
	return res
}
