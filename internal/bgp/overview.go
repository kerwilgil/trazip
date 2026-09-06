package bgp

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// maxOriginsForRPKIFanout bounds how many origins a single Overview call
// will run RPKIValidateDetailed against — a defensive limit against a
// pathological MOAS with an implausible number of origins. If the real
// origin count exceeds this, RPKI validation for this Overview is
// skipped entirely and reported via Evidence — never silently partial,
// never silently truncated to "the first N".
const maxOriginsForRPKIFanout = 32

// RPKISummary aggregates RPKIValidateDetailed results across every
// relevant origin — one full result per origin, states never collapsed
// (INVALID_ASN and INVALID_LENGTH are always counted separately).
type RPKISummary struct {
	States  map[RPKIState]int        `json:"states,omitempty"`
	Results []RPKIValidationDetailed `json:"results,omitempty"`
}

// NeighborsSummary is an observational summary of AsnNeighboursRaw —
// counts by position only, never a commercial-relationship inference.
type NeighborsSummary struct {
	Count        int                    `json:"count"`
	Left         int                    `json:"left"`
	Right        int                    `json:"right"`
	Uncertain    int                    `json:"uncertain"`
	Unknown      int                    `json:"unknown"`
	Observations []NeighbourObservation `json:"observations,omitempty"`
}

// Overview aggregates every relevant RIPEstat datasource for one
// resource (ASN, IP, or prefix) into a single structured result. No UI
// string ever substitutes for structured data — every field here is
// either a real decoded value or explicitly absent (nil/zero/empty
// slice), never a human-readable summary standing in for missing
// structure.
type Overview struct {
	Resource string       `json:"resource"`
	Kind     ResourceKind `json:"kind"`

	ASN    int    `json:"asn,omitempty"`
	Holder string `json:"holder,omitempty"`

	Prefixes []string `json:"prefixes,omitempty"`

	AnnouncedSpaceV4 *AnnouncedSpaceV4 `json:"announcedSpaceV4,omitempty"`
	AnnouncedSpaceV6 *AnnouncedSpaceV6 `json:"announcedSpaceV6,omitempty"`

	VisibilityV4 *Visibility `json:"visibilityV4,omitempty"`
	VisibilityV6 *Visibility `json:"visibilityV6,omitempty"`

	FirstSeen *SeenEvent `json:"firstSeen,omitempty"`
	LastSeen  *SeenEvent `json:"lastSeen,omitempty"`

	Origins []int `json:"origins,omitempty"`
	MOAS    bool  `json:"moas"`

	RPKI RPKISummary `json:"rpki"`

	Neighbors NeighborsSummary `json:"neighbors"`

	// Evidence has one entry per underlying datasource call made for
	// this Overview — including one entry per individual RPKI
	// validation, never collapsed into a single ambiguous entry.
	Evidence []ComponentEvidence `json:"evidence"`

	// Err is set only when the Overview could not produce any useful
	// information at all — a single failed component never sets this on
	// its own; see Evidence for per-component outcomes.
	Err string `json:"err,omitempty"`
}

// Overview resolves resource (ASN, IP, or prefix) and aggregates
// as-overview, routing-status, announced-prefixes, asn-neighbours and
// (for IP/prefix) per-origin rpki-validation into one Overview. It never
// fabricates a CIDR for RPKI — only prefixes RIPEstat itself resolved —
// and never discards an otherwise-useful partial result because one
// component failed.
func (c *Client) Overview(ctx context.Context, resource string) Overview {
	kind, normalized := ClassifyResource(resource)
	if kind == KindInvalid {
		return Overview{Resource: strings.TrimSpace(resource), Kind: KindInvalid, Err: fmt.Sprintf("recurso inválido: %q", resource)}
	}
	if kind == KindASN {
		return c.overviewForASN(ctx, normalized)
	}
	return c.overviewForIPOrPrefix(ctx, kind, normalized)
}

func (c *Client) overviewForASN(ctx context.Context, normalized string) Overview {
	ov := Overview{Resource: normalized, Kind: KindASN}
	asn, err := parseCanonicalASN(normalized)
	if err != nil {
		ov.Err = err.Error()
		return ov
	}
	ov.ASN = asn

	asOverview := c.ASOverview(ctx, asn)
	ov.Evidence = append(ov.Evidence, asOverview.Evidence)
	ov.Holder = asOverview.Holder

	routing := c.RoutingStatusDetailedQuery(ctx, normalized)
	ov.Evidence = append(ov.Evidence, routing.Evidence)
	ov.VisibilityV4 = routing.VisibilityV4
	ov.VisibilityV6 = routing.VisibilityV6
	ov.FirstSeen = routing.FirstSeen
	ov.LastSeen = routing.LastSeen
	ov.AnnouncedSpaceV4 = routing.AnnouncedSpaceV4
	ov.AnnouncedSpaceV6 = routing.AnnouncedSpaceV6

	prefixesRaw := c.AnnouncedPrefixesRaw(ctx, asn)
	ov.Evidence = append(ov.Evidence, prefixesRaw.Evidence)
	for _, p := range prefixesRaw.Prefixes {
		ov.Prefixes = append(ov.Prefixes, p.Prefix)
	}

	// RPKI: an ASN has no single representative prefix to run ROV
	// against — bulk RPKI across every announced prefix belongs to the
	// future Prefixes gate, never synthesized or guessed here.
	ov.Evidence = append(ov.Evidence, ComponentEvidence{Component: "rpki-validation", Status: ComponentNotApplicable})

	neighbours := c.AsnNeighboursRaw(ctx, asn)
	ov.Evidence = append(ov.Evidence, neighbours.Evidence)
	ov.Neighbors = summarizeNeighbours(neighbours)

	if ov.Holder == "" && len(ov.Prefixes) == 0 && ov.VisibilityV4 == nil && ov.VisibilityV6 == nil && len(ov.Neighbors.Observations) == 0 {
		ov.Err = "no fue posible obtener información para este ASN"
	}
	return ov
}

func (c *Client) overviewForIPOrPrefix(ctx context.Context, kind ResourceKind, normalized string) Overview {
	ov := Overview{Resource: normalized, Kind: kind}

	routing := c.RoutingStatusDetailedQuery(ctx, normalized)
	ov.Evidence = append(ov.Evidence, routing.Evidence)
	if routing.Err != "" {
		// Without a resolved prefix/origins there is nothing else this
		// Overview can usefully produce (RPKI needs the prefix, Neighbors
		// needs an origin) — this is the one case where a single failed
		// component legitimately becomes the Overview-level error.
		ov.Err = routing.Err
		return ov
	}

	if routing.Prefix != "" {
		ov.Prefixes = []string{routing.Prefix}
	}
	ov.VisibilityV4 = routing.VisibilityV4
	ov.VisibilityV6 = routing.VisibilityV6
	ov.FirstSeen = routing.FirstSeen
	ov.LastSeen = routing.LastSeen
	ov.AnnouncedSpaceV4 = routing.AnnouncedSpaceV4
	ov.AnnouncedSpaceV6 = routing.AnnouncedSpaceV6

	for _, o := range routing.Origins {
		ov.Origins = append(ov.Origins, o.Origin)
	}
	ov.MOAS = len(ov.Origins) > 1

	resolvedPrefix := routing.Prefix
	switch {
	case len(ov.Origins) == 0:
		// Not announced — nothing to validate against.
	case len(ov.Origins) > maxOriginsForRPKIFanout:
		ov.Evidence = append(ov.Evidence, ComponentEvidence{
			Component: "rpki-validation",
			Status:    ComponentDegraded,
			Err:       fmt.Sprintf("%d orígenes exceden el límite defensivo de %d — validación RPKI omitida para este Overview", len(ov.Origins), maxOriginsForRPKIFanout),
		})
	case resolvedPrefix == "":
		ov.Evidence = append(ov.Evidence, ComponentEvidence{Component: "rpki-validation", Status: ComponentNotApplicable})
	default:
		summary := RPKISummary{States: map[RPKIState]int{}}
		for _, origin := range ov.Origins {
			if ctx.Err() != nil {
				break // cancellation cuts the remaining fan-out short
			}
			detail := c.RPKIValidateDetailed(ctx, origin, resolvedPrefix)
			ov.Evidence = append(ov.Evidence, detail.Evidence)
			summary.Results = append(summary.Results, detail)
			if detail.Evidence.Status == ComponentOK {
				summary.States[detail.State]++
			}
		}
		ov.RPKI = summary
	}

	switch len(ov.Origins) {
	case 1:
		neighbours := c.AsnNeighboursRaw(ctx, ov.Origins[0])
		ov.Evidence = append(ov.Evidence, neighbours.Evidence)
		ov.Neighbors = summarizeNeighbours(neighbours)
	default:
		// Zero origins (nothing to look up) or MOAS (no single ASN to
		// attribute neighbours to without guessing a "primary origin") —
		// both explicitly not applicable, never guessed.
		ov.Evidence = append(ov.Evidence, ComponentEvidence{Component: "asn-neighbours", Status: ComponentNotApplicable})
	}

	return ov
}

func summarizeNeighbours(res ASNNeighboursResult) NeighborsSummary {
	s := NeighborsSummary{Observations: res.Neighbours}
	for _, n := range res.Neighbours {
		s.Count++
		switch n.Position {
		case PositionLeft:
			s.Left++
		case PositionRight:
			s.Right++
		case PositionUncertain:
			s.Uncertain++
		default:
			s.Unknown++
		}
	}
	return s
}

// parseCanonicalASN parses the "ASxxxx" form ClassifyResource produces
// for KindASN back into its integer value.
func parseCanonicalASN(canonical string) (int, error) {
	digits := strings.TrimPrefix(strings.TrimPrefix(canonical, "AS"), "as")
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0, fmt.Errorf("ASN canónico inválido: %q", canonical)
	}
	return n, nil
}
