package bgp

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// maxTopologyNodes/maxTopologyEdges are the v1.1 view bounds (gate-fixed,
// within the roadmap's target range of 60–100 nodes / 150–250 edges).
const (
	maxTopologyNodes                     = 100
	maxTopologyEdges                     = 250
	maxTopologyNameEnrichment            = 15
	maxTopologyNameEnrichmentConcurrency = 3
)

// RPKIEvidence is the exact ROV outcome for one (prefix, origin) pair,
// attached to a topology Node only when that node is the origin of the
// specific resource queried — never a global per-ASN RPKI claim (RPKI is
// prefix+origin-scoped, not ASN-scoped).
type RPKIEvidence struct {
	Prefix string `json:"prefix"`
	State  string `json:"state"`
}

// Node is one ASN observed in bgp-state's AS paths for the queried
// resource. DisplayName is intentionally left empty in v1.1 — no
// as-overview enrichment is performed for topology nodes (that would be
// an unbounded per-node fan-out up to maxTopologyNodes calls, out of
// scope for this gate) — an empty DisplayName here means "no evidence
// gathered", never a fabricated placeholder.
type Node struct {
	ASN         int    `json:"asn"`
	DisplayName string `json:"displayName,omitempty"` // exact ASOverview Holder when bounded enrichment succeeds; otherwise empty
	// ObservedRole is "origin" | "intermediate" | "ris-peer" — derived
	// strictly from this ASN's position(s) across bgp-state's own paths,
	// never a commercial relationship (no provider/customer/upstream/
	// downstream/Tier-1 vocabulary anywhere in this package).
	ObservedRole string        `json:"observedRole"`
	OriginRPKI   *RPKIEvidence `json:"originRpki,omitempty"`
	PathCount    int           `json:"pathCount"`
}

// Edge is one observed AS-path hop, aggregated across every bgp-state
// path that contains it consecutively.
type Edge struct {
	From             int `json:"from"`
	To               int `json:"to"`
	ObservationCount int `json:"observationCount"`
}

// Graph is a bounded topology view derived exclusively from bgp-state —
// never reconstructed or inferred from routing-status/asn-neighbours,
// never crawled recursively beyond the paths bgp-state returns for the
// single queried resource.
type Graph struct {
	Resource  string `json:"resource"`
	Timestamp string `json:"timestamp,omitempty"`

	Nodes []Node `json:"nodes"` // already bounded to maxTopologyNodes
	Edges []Edge `json:"edges"` // already bounded to maxTopologyEdges

	// Routes preserves bgp-state's own raw path text (e.g. "328840
	// 327727 174 1273 3333") — one entry per route that had a non-empty
	// path, exactly as RIPEstat reported it, before any sanitization.
	Routes []string `json:"routes,omitempty"`

	// ObservedRoutes/ObservedNodes/ObservedEdges are exactly what this
	// bgp-state response contained (ObservedRoutes == nr_routes) — never
	// "global topology", only the evidence this one call returned.
	ObservedRoutes int `json:"observedRoutes"`
	ObservedNodes  int `json:"observedNodes"`
	ObservedEdges  int `json:"observedEdges"`

	// ViewTruncated is true when ObservedNodes/ObservedEdges exceeded the
	// v1.1 view bounds and len(Nodes)/len(Edges) is therefore smaller —
	// the only truncation flag in this contract (bgp-state exposes no
	// source-level pagination/truncation indicator to mirror).
	ViewTruncated bool `json:"viewTruncated"`

	Evidence []ComponentEvidence `json:"evidence"`
	Err      string              `json:"err,omitempty"`
}

// Topology builds a bounded AS-path graph for one resource (ASN, IP, or
// prefix) from bgp-state alone. For an IP/prefix resource it reuses
// Security's already-computed RPKI fan-out (no second fan-out) to attach
// OriginRPKI to origin nodes; for a bare ASN it never mass-validates
// RPKI across bgp-state's many distinct target prefixes — OriginRPKI
// stays nil for every node, matching Security's own ASN-scoped rule
// (RPKI validation is prefix-scoped, never fabricated as a global ASN
// claim).
func (c *Client) Topology(ctx context.Context, resource string) Graph {
	kind, normalized := ClassifyResource(resource)
	// Nodes/Edges start as non-nil empty slices — every return path
	// (including the early-return error paths below) must serialize as
	// JSON "[]", never "null": the contract declares Edge[]/Node[], and
	// consumers call .length/.map unconditionally whenever Err is empty.
	g := Graph{Resource: strings.TrimSpace(resource), Nodes: []Node{}, Edges: []Edge{}}
	if kind == KindInvalid {
		g.Err = fmt.Sprintf("recurso inválido: %q", resource)
		return g
	}
	g.Resource = normalized

	state := c.BGPState(ctx, normalized)
	g.Evidence = append(g.Evidence, state.Evidence)
	if state.Err != "" {
		g.Err = state.Err
		return g
	}

	g.Timestamp = state.QueryTime
	g.ObservedRoutes = state.NrRoutes

	nodeAgg, edgeAgg, routeTexts := buildGraphAggregates(state.Routes)
	g.Routes = routeTexts
	g.ObservedNodes = len(nodeAgg)
	g.ObservedEdges = len(edgeAgg)

	var originRPKI map[int]RPKIEvidence
	if kind != KindASN {
		sec := c.Security(ctx, normalized)
		g.Evidence = append(g.Evidence, sec.Evidence...)
		originRPKI = make(map[int]RPKIEvidence, len(sec.RPKI.Results))
		for _, r := range sec.RPKI.Results {
			if r.Evidence.Status == ComponentOK {
				originRPKI[r.ASN] = RPKIEvidence{Prefix: r.Prefix, State: string(r.State)}
			}
		}
	}

	nodes := finalizeNodes(nodeAgg, originRPKI)
	edges := finalizeEdges(edgeAgg)
	nodes, edges, truncated := boundGraph(nodes, edges)
	// Holder enrichment is deliberately applied only after the view is bounded:
	// Nodes and Edges still come exclusively from bgp-state, while these are
	// bounded, best-effort presentation details.
	c.enrichTopologyNodeNames(ctx, nodes)
	g.Nodes = nodes
	g.Edges = edges
	g.ViewTruncated = truncated

	return g
}

// enrichTopologyNodeNames fills DisplayName from ASOverview for at most the
// leading maxTopologyNameEnrichment nodes. boundGraph has already sorted these
// by PathCount (then ASN), so the request budget is deterministic. Individual
// lookup failures leave DisplayName empty and never fail a usable topology.
func (c *Client) enrichTopologyNodeNames(ctx context.Context, nodes []Node) {
	limit := len(nodes)
	if limit > maxTopologyNameEnrichment {
		limit = maxTopologyNameEnrichment
	}
	if limit == 0 {
		return
	}

	holders := make([]string, limit)
	jobs := make(chan int)
	workers := maxTopologyNameEnrichmentConcurrency
	if workers > limit {
		workers = limit
	}
	done := make(chan struct{}, workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for index := range jobs {
				overview := c.ASOverview(ctx, nodes[index].ASN)
				if overview.Err == "" {
					holders[index] = overview.Holder
				}
			}
		}()
	}
	for index := 0; index < limit; index++ {
		jobs <- index
	}
	close(jobs)
	for worker := 0; worker < workers; worker++ {
		<-done
	}
	for index, holder := range holders {
		if holder != "" {
			nodes[index].DisplayName = holder
		}
	}
}

type nodeAgg struct {
	pathCount   int
	sawAsOrigin bool // ever the last element of a sanitized path
	sawAsFirst  bool // ever the first element of a sanitized path
}

type edgeKey struct{ from, to int }

// sanitizePath removes consecutive duplicate ASNs (prepending — never a
// real hop) and splits the path into separate segments at every
// invalid/zero ASN. An invalid entry breaks the chain rather than
// silently bridging the two real ASNs on either side of it: dropping it
// outright (instead of segmenting) would fabricate an edge between two
// ASNs that bgp-state never actually reported as adjacent — a real gap
// in the evidence must never become a fake hop. Edges are only ever
// built within one segment (see buildGraphAggregates); role
// classification (first/last overall) still spans every segment, since
// that is a position label, not a claim of adjacency. Non-consecutive
// repeats within one segment (a genuine path loop, unusual but real
// evidence) are left alone — collapsing those would invent structure
// bgp-state never reported. Invalid entries are dropped, never replaced
// with a fabricated ASN.
func sanitizePath(path []int) [][]int {
	var segments [][]int
	var current []int
	flush := func() {
		if len(current) > 0 {
			segments = append(segments, current)
			current = nil
		}
	}
	for _, asn := range path {
		if asn <= 0 || asn > maxASN {
			flush()
			continue
		}
		if len(current) > 0 && current[len(current)-1] == asn {
			continue
		}
		current = append(current, asn)
	}
	flush()
	return segments
}

func formatPathText(path []int) string {
	parts := make([]string, len(path))
	for i, asn := range path {
		parts[i] = strconv.Itoa(asn)
	}
	return strings.Join(parts, " ")
}

// buildGraphAggregates derives node/edge statistics and raw route text
// from bgp-state's routes — the only source topology.go reads from.
// Edges are only ever built between two consecutive ASNs within the
// same sanitized segment — an invalid ASN between two real ones (e.g.
// [100, 0, 200]) breaks the chain, so 100 and 200 are never joined into
// a fabricated edge just because the invalid entry between them was
// dropped.
func buildGraphAggregates(routes []BGPStateRoute) (map[int]*nodeAgg, map[edgeKey]int, []string) {
	nodes := map[int]*nodeAgg{}
	edges := map[edgeKey]int{}
	var routeTexts []string

	for _, route := range routes {
		if len(route.Path) > 0 {
			routeTexts = append(routeTexts, formatPathText(route.Path))
		}
		segments := sanitizePath(route.Path)
		if len(segments) == 0 {
			continue
		}
		seen := map[int]bool{}
		lastSegment := len(segments) - 1
		for segIdx, seg := range segments {
			lastInSeg := len(seg) - 1
			for i, asn := range seg {
				n, ok := nodes[asn]
				if !ok {
					n = &nodeAgg{}
					nodes[asn] = n
				}
				if !seen[asn] {
					seen[asn] = true
					n.pathCount++
				}
				if segIdx == 0 && i == 0 {
					n.sawAsFirst = true
				}
				if segIdx == lastSegment && i == lastInSeg {
					n.sawAsOrigin = true
				}
				if i > 0 {
					edges[edgeKey{from: seg[i-1], to: asn}]++
				}
			}
		}
	}
	return nodes, edges, routeTexts
}

func finalizeNodes(agg map[int]*nodeAgg, originRPKI map[int]RPKIEvidence) []Node {
	nodes := make([]Node, 0, len(agg))
	for asn, a := range agg {
		role := "intermediate"
		switch {
		case a.sawAsOrigin:
			role = "origin"
		case a.sawAsFirst:
			role = "ris-peer"
		}
		n := Node{ASN: asn, ObservedRole: role, PathCount: a.pathCount}
		if role == "origin" {
			if rpki, ok := originRPKI[asn]; ok {
				rpkiCopy := rpki
				n.OriginRPKI = &rpkiCopy
			}
		}
		nodes = append(nodes, n)
	}
	return nodes
}

func finalizeEdges(agg map[edgeKey]int) []Edge {
	edges := make([]Edge, 0, len(agg))
	for k, count := range agg {
		edges = append(edges, Edge{From: k.from, To: k.to, ObservationCount: count})
	}
	return edges
}

// boundGraph ranks nodes by PathCount and edges by ObservationCount,
// both descending with a stable ASN-based tie-break, truncates nodes to
// the v1.1 view bound, then drops any edge whose From or To is not among
// the surviving nodes before ranking/truncating edges to their own view
// bound — an edge referencing an ASN outside the returned Nodes slice
// would be dangling, misleading evidence, so referential closure between
// Nodes and Edges is guaranteed. ViewTruncated is true whenever either
// slice ends up smaller than what was actually observed, whether from
// hitting a view bound directly or from this node-driven edge filtering.
func boundGraph(nodes []Node, edges []Edge) ([]Node, []Edge, bool) {
	originalNodeCount := len(nodes)
	originalEdgeCount := len(edges)

	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].PathCount != nodes[j].PathCount {
			return nodes[i].PathCount > nodes[j].PathCount
		}
		return nodes[i].ASN < nodes[j].ASN
	})
	if len(nodes) > maxTopologyNodes {
		nodes = nodes[:maxTopologyNodes]
	}

	survivors := make(map[int]bool, len(nodes))
	for _, n := range nodes {
		survivors[n.ASN] = true
	}
	// Non-nil even when nothing survives filtering — json.Marshal on a
	// nil slice produces "null", but the contract declares Edge[] and
	// consumers call .length/.map unconditionally.
	filteredEdges := make([]Edge, 0, len(edges))
	for _, e := range edges {
		if survivors[e.From] && survivors[e.To] {
			filteredEdges = append(filteredEdges, e)
		}
	}

	sort.SliceStable(filteredEdges, func(i, j int) bool {
		if filteredEdges[i].ObservationCount != filteredEdges[j].ObservationCount {
			return filteredEdges[i].ObservationCount > filteredEdges[j].ObservationCount
		}
		if filteredEdges[i].From != filteredEdges[j].From {
			return filteredEdges[i].From < filteredEdges[j].From
		}
		return filteredEdges[i].To < filteredEdges[j].To
	})
	if len(filteredEdges) > maxTopologyEdges {
		filteredEdges = filteredEdges[:maxTopologyEdges]
	}

	truncated := len(nodes) < originalNodeCount || len(filteredEdges) < originalEdgeCount
	return nodes, filteredEdges, truncated
}
