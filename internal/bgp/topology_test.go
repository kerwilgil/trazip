package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func findNode(nodes []Node, asn int) *Node {
	for i := range nodes {
		if nodes[i].ASN == asn {
			return &nodes[i]
		}
	}
	return nil
}

func findEdge(edges []Edge, from, to int) *Edge {
	for i := range edges {
		if edges[i].From == from && edges[i].To == to {
			return &edges[i]
		}
	}
	return nil
}

func TestTopologyNameEnrichmentIsBoundedBestEffortAndKeepsEdges(t *testing.T) {
	var routes []string
	for asn := 1000; asn < 1016; asn++ {
		routes = append(routes, fmt.Sprintf(`{"target_prefix":"1.1.1.0/24","source_id":"00-1.1.1.1","path":[%d,2000],"community":[]}`, asn))
	}

	var mu sync.Mutex
	calls, active, maxActive := 0, 0, 0
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(fmt.Sprintf(`{"status":"ok","data":{"resource":"AS2000","timestamp":"2026-08-18T23:59:52","nr_routes":16,"bgp_state":[%s]}}`, strings.Join(routes, ","))))
		},
		"/as-overview/data.json": func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			calls++
			active++
			if active > maxActive {
				maxActive = active
			}
			mu.Unlock()
			defer func() {
				mu.Lock()
				active--
				mu.Unlock()
			}()
			time.Sleep(5 * time.Millisecond)
			if r.URL.Query().Get("resource") == "AS1000" {
				http.Error(w, "temporary as-overview failure", http.StatusBadGateway)
				return
			}
			asn := r.URL.Query().Get("resource")
			w.Write([]byte(fmt.Sprintf(`{"status":"ok","data":{"resource":"%s","announced":true,"holder":"Holder %s","type":"asn"}}`, asn, asn)))
		},
	})

	g := (&Client{BaseURL: addr}).Topology(context.Background(), "AS2000")
	if g.Err != "" {
		t.Fatalf("Err = %q, want empty despite one holder failure", g.Err)
	}
	mu.Lock()
	gotCalls, gotMaxActive := calls, maxActive
	mu.Unlock()
	if gotCalls != maxTopologyNameEnrichment {
		t.Fatalf("ASOverview calls = %d, want %d", gotCalls, maxTopologyNameEnrichment)
	}
	if gotMaxActive > maxTopologyNameEnrichmentConcurrency {
		t.Fatalf("ASOverview maximum concurrency = %d, want <= %d", gotMaxActive, maxTopologyNameEnrichmentConcurrency)
	}
	if n := findNode(g.Nodes, 2000); n == nil || n.DisplayName != "Holder AS2000" {
		t.Fatalf("node 2000 = %+v, want exact Holder AS2000", n)
	}
	if n := findNode(g.Nodes, 1000); n == nil || n.DisplayName != "" {
		t.Fatalf("failed holder node 1000 = %+v, want empty DisplayName", n)
	}
	if n := findNode(g.Nodes, 1014); n == nil || n.DisplayName != "" {
		t.Fatalf("unselected node 1014 = %+v, want empty DisplayName", n)
	}
	if n := findNode(g.Nodes, 1001); n == nil || n.DisplayName != "Holder AS1001" {
		t.Fatalf("node 1001 = %+v, want exact Holder AS1001", n)
	}
	if len(g.Edges) != 16 {
		t.Fatalf("len(Edges) = %d, want 16; name enrichment must not alter edges", len(g.Edges))
	}
	for asn := 1000; asn < 1016; asn++ {
		if e := findEdge(g.Edges, asn, 2000); e == nil || e.ObservationCount != 1 {
			t.Fatalf("edge %d->2000 = %+v, want original observation", asn, e)
		}
	}
}

func TestTopologySimplePath(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","timestamp":"2026-08-18T23:59:52","nr_routes":1,"bgp_state":[
				{"target_prefix":"1.1.1.0/24","source_id":"00-1.1.1.1","path":[100,200,300],"community":[]}
			]}}`))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":300}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
		"/asn-neighbours/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS300","neighbours":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "1.1.1.1")

	if g.Err != "" {
		t.Fatalf("Err = %q, want empty", g.Err)
	}
	if g.ObservedRoutes != 1 || g.ObservedNodes != 3 || g.ObservedEdges != 2 {
		t.Fatalf("Observed = routes:%d nodes:%d edges:%d, want 1/3/2", g.ObservedRoutes, g.ObservedNodes, g.ObservedEdges)
	}
	if g.ViewTruncated {
		t.Fatalf("ViewTruncated = true, want false")
	}

	n100, n200, n300 := findNode(g.Nodes, 100), findNode(g.Nodes, 200), findNode(g.Nodes, 300)
	if n100 == nil || n100.ObservedRole != "ris-peer" {
		t.Fatalf("node 100 = %+v, want ObservedRole=ris-peer", n100)
	}
	if n200 == nil || n200.ObservedRole != "intermediate" {
		t.Fatalf("node 200 = %+v, want ObservedRole=intermediate", n200)
	}
	if n300 == nil || n300.ObservedRole != "origin" {
		t.Fatalf("node 300 = %+v, want ObservedRole=origin", n300)
	}
	if n300.OriginRPKI == nil || n300.OriginRPKI.State != "VALID" || n300.OriginRPKI.Prefix != "1.1.1.0/24" {
		t.Fatalf("node 300 OriginRPKI = %+v, want VALID for 1.1.1.0/24", n300.OriginRPKI)
	}
	if n100.OriginRPKI != nil || n200.OriginRPKI != nil {
		t.Fatalf("intermediate/ris-peer nodes must never carry OriginRPKI: n100=%+v n200=%+v", n100.OriginRPKI, n200.OriginRPKI)
	}

	if e := findEdge(g.Edges, 100, 200); e == nil || e.ObservationCount != 1 {
		t.Fatalf("edge 100->200 = %+v, want ObservationCount=1", e)
	}
	if e := findEdge(g.Edges, 200, 300); e == nil || e.ObservationCount != 1 {
		t.Fatalf("edge 200->300 = %+v, want ObservationCount=1", e)
	}
}

func TestTopologyMultiplePathsEdgeCounting(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS300","timestamp":"2026-08-18T23:59:52","nr_routes":2,"bgp_state":[
				{"target_prefix":"1.1.1.0/24","source_id":"00-1.1.1.1","path":[100,200,300],"community":[]},
				{"target_prefix":"1.1.2.0/24","source_id":"00-2.2.2.2","path":[400,200,300],"community":[]}
			]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "AS300")

	if g.Err != "" {
		t.Fatalf("Err = %q, want empty", g.Err)
	}
	// Nodes: 100, 200, 300, 400 — edges: 100->200, 200->300 (x2), 400->200.
	if g.ObservedNodes != 4 {
		t.Fatalf("ObservedNodes = %d, want 4", g.ObservedNodes)
	}
	if g.ObservedEdges != 3 {
		t.Fatalf("ObservedEdges = %d, want 3", g.ObservedEdges)
	}
	n200 := findNode(g.Nodes, 200)
	if n200 == nil || n200.PathCount != 2 {
		t.Fatalf("node 200 = %+v, want PathCount=2 (appears in both routes)", n200)
	}
	if e := findEdge(g.Edges, 200, 300); e == nil || e.ObservationCount != 2 {
		t.Fatalf("edge 200->300 = %+v, want ObservationCount=2", e)
	}
	if e := findEdge(g.Edges, 100, 200); e == nil || e.ObservationCount != 1 {
		t.Fatalf("edge 100->200 = %+v, want ObservationCount=1", e)
	}
	if e := findEdge(g.Edges, 400, 200); e == nil || e.ObservationCount != 1 {
		t.Fatalf("edge 400->200 = %+v, want ObservationCount=1", e)
	}
}

func TestTopologyPrependingNoSelfEdge(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS300","timestamp":"2026-08-18T23:59:52","nr_routes":1,"bgp_state":[
				{"target_prefix":"1.1.1.0/24","source_id":"00-1.1.1.1","path":[100,100,100,200,300],"community":[]}
			]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "AS300")

	if findEdge(g.Edges, 100, 100) != nil {
		t.Fatalf("edges = %+v, must never contain a 100->100 self-edge from consecutive prepending", g.Edges)
	}
	if g.ObservedNodes != 3 {
		t.Fatalf("ObservedNodes = %d, want 3 (100, 200, 300 — prepending must not inflate node count)", g.ObservedNodes)
	}
	if e := findEdge(g.Edges, 100, 200); e == nil || e.ObservationCount != 1 {
		t.Fatalf("edge 100->200 = %+v, want ObservationCount=1", e)
	}
}

func TestTopologyNonConsecutiveRepeatPreservesLoopEdges(t *testing.T) {
	// A B A C — non-consecutive repeat of A is a genuine (if unusual) path
	// loop, not prepending — must not be silently collapsed.
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS300","timestamp":"2026-08-18T23:59:52","nr_routes":1,"bgp_state":[
				{"target_prefix":"1.1.1.0/24","source_id":"00-1.1.1.1","path":[100,200,100,300],"community":[]}
			]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "AS300")

	if e := findEdge(g.Edges, 100, 200); e == nil {
		t.Fatalf("edge 100->200 missing: %+v", g.Edges)
	}
	if e := findEdge(g.Edges, 200, 100); e == nil {
		t.Fatalf("edge 200->100 missing: %+v", g.Edges)
	}
	if e := findEdge(g.Edges, 100, 300); e == nil {
		t.Fatalf("edge 100->300 missing: %+v", g.Edges)
	}
}

func TestTopologyEmptyAndInvalidPathElementsHandledSafely(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS300","timestamp":"2026-08-18T23:59:52","nr_routes":2,"bgp_state":[
				{"target_prefix":"1.1.1.0/24","source_id":"00-1.1.1.1","path":[],"community":[]},
				{"target_prefix":"1.1.2.0/24","source_id":"00-2.2.2.2","path":[100,0,200],"community":[]}
			]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "AS300")

	if g.Err != "" {
		t.Fatalf("Err = %q, want empty (no panic/crash on empty or invalid-ASN path elements)", g.Err)
	}
	// The empty path contributes nothing. The second path's invalid "0"
	// entry breaks the chain — 100 and 200 are both real nodes (each its
	// own segment), but they were never actually adjacent in the
	// evidence, so no edge is fabricated between them.
	if g.ObservedNodes != 2 {
		t.Fatalf("ObservedNodes = %d, want 2 (100, 200)", g.ObservedNodes)
	}
	if e := findEdge(g.Edges, 100, 200); e != nil {
		t.Fatalf("edge 100->200 = %+v, must not exist — the invalid ASN between them must never be silently bridged into a fabricated edge", e)
	}
	if g.ObservedEdges != 0 {
		t.Fatalf("ObservedEdges = %d, want 0", g.ObservedEdges)
	}
	if len(g.Routes) != 1 {
		t.Fatalf("len(Routes) = %d, want 1 (the empty path contributes no raw route text)", len(g.Routes))
	}
}

func TestTopologyInvalidASNMiddleDoesNotBridgeNeighbours(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS300","timestamp":"2026-08-18T23:59:52","nr_routes":1,"bgp_state":[
				{"target_prefix":"1.1.1.0/24","source_id":"00-1.1.1.1","path":[100,0,200],"community":[]}
			]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "AS300")

	if e := findEdge(g.Edges, 100, 200); e != nil {
		t.Fatalf("edge 100->200 = %+v, must not exist (invalid ASN in the middle)", e)
	}
	if g.ObservedNodes != 2 || g.ObservedEdges != 0 {
		t.Fatalf("Observed = nodes:%d edges:%d, want 2/0", g.ObservedNodes, g.ObservedEdges)
	}
	n100, n200 := findNode(g.Nodes, 100), findNode(g.Nodes, 200)
	if n100 == nil || n100.ObservedRole != "ris-peer" {
		t.Fatalf("node 100 = %+v, want ObservedRole=ris-peer (first overall)", n100)
	}
	if n200 == nil || n200.ObservedRole != "origin" {
		t.Fatalf("node 200 = %+v, want ObservedRole=origin (last overall)", n200)
	}
}

func TestTopologyInvalidASNAtStartDoesNotAffectPath(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS300","timestamp":"2026-08-18T23:59:52","nr_routes":1,"bgp_state":[
				{"target_prefix":"1.1.1.0/24","source_id":"00-1.1.1.1","path":[0,100,200],"community":[]}
			]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "AS300")

	if e := findEdge(g.Edges, 100, 200); e == nil || e.ObservationCount != 1 {
		t.Fatalf("edge 100->200 = %+v, want ObservationCount=1 (leading invalid entry must not break the real hop that follows it)", e)
	}
	if g.ObservedNodes != 2 || g.ObservedEdges != 1 {
		t.Fatalf("Observed = nodes:%d edges:%d, want 2/1", g.ObservedNodes, g.ObservedEdges)
	}
}

func TestTopologyInvalidASNAtEndDoesNotAffectPath(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS300","timestamp":"2026-08-18T23:59:52","nr_routes":1,"bgp_state":[
				{"target_prefix":"1.1.1.0/24","source_id":"00-1.1.1.1","path":[100,200,0],"community":[]}
			]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "AS300")

	if e := findEdge(g.Edges, 100, 200); e == nil || e.ObservationCount != 1 {
		t.Fatalf("edge 100->200 = %+v, want ObservationCount=1 (trailing invalid entry must not break the real hop before it)", e)
	}
	if g.ObservedNodes != 2 || g.ObservedEdges != 1 {
		t.Fatalf("Observed = nodes:%d edges:%d, want 2/1", g.ObservedNodes, g.ObservedEdges)
	}
}

func TestTopologyDeterministicNodeTruncation(t *testing.T) {
	const n = 105
	var routes []string
	for i := 0; i < n; i++ {
		asn := 3000 + i
		routes = append(routes, fmt.Sprintf(`{"target_prefix":"1.1.%d.0/24","source_id":"00-1.1.1.1","path":[%d],"community":[]}`, i, asn))
	}
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(fmt.Sprintf(`{"status":"ok","data":{"resource":"AS300","timestamp":"2026-08-18T23:59:52","nr_routes":%d,"bgp_state":[%s]}}`, n, strings.Join(routes, ","))))
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "AS300")

	if g.ObservedNodes != n {
		t.Fatalf("ObservedNodes = %d, want %d", g.ObservedNodes, n)
	}
	if !g.ViewTruncated {
		t.Fatalf("ViewTruncated = false, want true (%d nodes > maxTopologyNodes=%d)", n, maxTopologyNodes)
	}
	if len(g.Nodes) != maxTopologyNodes {
		t.Fatalf("len(Nodes) = %d, want %d", len(g.Nodes), maxTopologyNodes)
	}
	// Every node here has PathCount=1 (tie), so the tie-break (ASN
	// ascending) must deterministically keep the 100 smallest ASNs:
	// 3000..3099.
	if findNode(g.Nodes, 3000) == nil {
		t.Fatalf("expected ASN 3000 to be kept (smallest ASN, tie-break)")
	}
	if findNode(g.Nodes, 3099) == nil {
		t.Fatalf("expected ASN 3099 to be kept (100th smallest)")
	}
	if findNode(g.Nodes, 3100) != nil {
		t.Fatalf("ASN 3100 must have been truncated (101st smallest)")
	}
	if findNode(g.Nodes, 3104) != nil {
		t.Fatalf("ASN 3104 must have been truncated (105th smallest)")
	}
}

func TestTopologyDeterministicEdgeTruncation(t *testing.T) {
	// A small fully-connected pool (17 ASNs, well under maxTopologyNodes)
	// so edge truncation is exercised in isolation, with no node-driven
	// (P2) filtering in play: one 2-hop route per ordered pair i!=j gives
	// 17*16=272 directed edges, each ObservationCount=1.
	const poolSize = 17
	const base = 9000
	var routes []string
	for i := 0; i < poolSize; i++ {
		for j := 0; j < poolSize; j++ {
			if i == j {
				continue
			}
			routes = append(routes, fmt.Sprintf(`{"target_prefix":"1.1.1.0/24","source_id":"00-1.1.1.1","path":[%d,%d],"community":[]}`, base+i, base+j))
		}
	}
	wantEdges := poolSize * (poolSize - 1)
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(fmt.Sprintf(`{"status":"ok","data":{"resource":"AS300","timestamp":"2026-08-18T23:59:52","nr_routes":%d,"bgp_state":[%s]}}`, wantEdges, strings.Join(routes, ","))))
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "AS300")

	if g.ObservedNodes != poolSize {
		t.Fatalf("ObservedNodes = %d, want %d (no node truncation in this scenario)", g.ObservedNodes, poolSize)
	}
	if len(g.Nodes) != poolSize {
		t.Fatalf("len(Nodes) = %d, want %d — this test must not exercise node truncation", len(g.Nodes), poolSize)
	}
	if g.ObservedEdges != wantEdges {
		t.Fatalf("ObservedEdges = %d, want %d", g.ObservedEdges, wantEdges)
	}
	if !g.ViewTruncated {
		t.Fatalf("ViewTruncated = false, want true")
	}
	if len(g.Edges) != maxTopologyEdges {
		t.Fatalf("len(Edges) = %d, want %d", len(g.Edges), maxTopologyEdges)
	}
	// All ObservationCount=1 (tie) — tie-break (From asc, then To asc):
	// the very first edge (smallest From, smallest To) must survive, and
	// the highest-From group (9016's, 16 edges, positions 257-272) must
	// be entirely cut since 250 < 15*16=240+16=256.
	if findEdge(g.Edges, base, base+1) == nil {
		t.Fatalf("edge %d->%d must be kept (smallest From/To)", base, base+1)
	}
	for _, e := range g.Edges {
		if e.From == base+poolSize-1 {
			t.Fatalf("edge %+v: From=%d must have been entirely truncated (highest From value)", e, base+poolSize-1)
		}
	}
}

func TestTopologyEdgesNeverReferenceATruncatedNode(t *testing.T) {
	// 100 single-ASN routes (4000..4099, PathCount=1 each) exactly fill
	// the node budget. One extra route adds a real edge 4050->4100:
	// 4050 (already present) gains PathCount=2 and is guaranteed to
	// survive; 4100 is brand new with PathCount=1, tied with 99 other
	// PathCount=1 nodes for 99 remaining slots — as the single largest
	// ASN in that tied pool, 4100 is deterministically the one pruned.
	// The edge into it must therefore never appear in the final Edges.
	var routes []string
	for i := 0; i < 100; i++ {
		routes = append(routes, fmt.Sprintf(`{"target_prefix":"1.1.%d.0/24","source_id":"00-1.1.1.1","path":[%d],"community":[]}`, i, 4000+i))
	}
	routes = append(routes, `{"target_prefix":"1.1.200.0/24","source_id":"00-2.2.2.2","path":[4050,4100],"community":[]}`)
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(fmt.Sprintf(`{"status":"ok","data":{"resource":"AS300","timestamp":"2026-08-18T23:59:52","nr_routes":101,"bgp_state":[%s]}}`, strings.Join(routes, ","))))
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "AS300")

	if g.ObservedNodes != 101 {
		t.Fatalf("ObservedNodes = %d, want 101", g.ObservedNodes)
	}
	if findNode(g.Nodes, 4100) != nil {
		t.Fatalf("ASN 4100 must have been truncated (largest ASN among the PathCount=1 tie pool)")
	}
	if findNode(g.Nodes, 4050) == nil {
		t.Fatalf("ASN 4050 must survive (PathCount=2)")
	}
	if e := findEdge(g.Edges, 4050, 4100); e != nil {
		t.Fatalf("edge 4050->4100 = %+v, must not appear — its endpoint 4100 was truncated from Nodes", e)
	}
	survivors := make(map[int]bool, len(g.Nodes))
	for _, n := range g.Nodes {
		survivors[n.ASN] = true
	}
	for _, e := range g.Edges {
		if !survivors[e.From] || !survivors[e.To] {
			t.Fatalf("edge %+v references a node outside g.Nodes — referential closure violated", e)
		}
	}
}

func TestTopologyASNResourceNeverMassValidatesRPKI(t *testing.T) {
	var rpkiCalls int
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS300","timestamp":"2026-08-18T23:59:52","nr_routes":2,"bgp_state":[
				{"target_prefix":"1.1.1.0/24","source_id":"00-1.1.1.1","path":[100,300],"community":[]},
				{"target_prefix":"1.1.2.0/24","source_id":"00-2.2.2.2","path":[200,300],"community":[]}
			]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			rpkiCalls++
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "AS300")

	if rpkiCalls != 0 {
		t.Fatalf("rpkiCalls = %d, want 0 — an ASN topology query must never mass-validate RPKI across bgp-state's distinct target prefixes", rpkiCalls)
	}
	for _, n := range g.Nodes {
		if n.OriginRPKI != nil {
			t.Fatalf("node %d: OriginRPKI = %+v, want nil for an ASN-resource topology", n.ASN, n.OriginRPKI)
		}
	}
}

func TestTopologyInvalidResource(t *testing.T) {
	c := &Client{BaseURL: "http://unused.invalid"}
	g := c.Topology(context.Background(), "not-a-valid-resource!!")
	if g.Err == "" {
		t.Fatalf("Err = empty, want a message for an invalid resource")
	}
	if len(g.Nodes) != 0 || len(g.Edges) != 0 {
		t.Fatalf("Nodes/Edges = %v/%v, want empty", g.Nodes, g.Edges)
	}
	if g.Nodes == nil || g.Edges == nil {
		t.Fatalf("Nodes/Edges = %v/%v, want non-nil empty slices even on the invalid-resource error path — the contract declares Node[]/Edge[], never null", g.Nodes, g.Edges)
	}
	encoded, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(encoded), `"nodes":[]`) || !strings.Contains(string(encoded), `"edges":[]`) {
		t.Fatalf("JSON must contain both \"nodes\":[] and \"edges\":[], never null — got: %s", encoded)
	}
}

func TestTopologyZeroEdgesSerializeAsEmptyArrayNeverNull(t *testing.T) {
	// Three separate single-ASN routes: each path has no consecutive
	// ASNs at all, so zero edges are ever built, even though nodes are
	// non-empty — the exact case where a nil slice previously leaked
	// into the JSON as "edges":null.
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS300","timestamp":"2026-08-18T23:59:52","nr_routes":3,"bgp_state":[
				{"target_prefix":"1.1.1.0/24","source_id":"00-1.1.1.1","path":[100],"community":[]},
				{"target_prefix":"1.1.2.0/24","source_id":"00-2.2.2.2","path":[200],"community":[]},
				{"target_prefix":"1.1.3.0/24","source_id":"00-3.3.3.3","path":[300],"community":[]}
			]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "AS300")

	if g.Err != "" {
		t.Fatalf("Err = %q, want empty", g.Err)
	}
	if len(g.Nodes) != 3 {
		t.Fatalf("len(Nodes) = %d, want 3", len(g.Nodes))
	}
	if len(g.Edges) != 0 {
		t.Fatalf("Edges = %+v, want empty (no consecutive ASNs in any single-element path)", g.Edges)
	}
	if g.Edges == nil {
		t.Fatalf("Edges is nil, want a non-nil empty slice")
	}
	if g.Nodes == nil {
		t.Fatalf("Nodes is nil, want a non-nil slice")
	}

	encoded, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	s := string(encoded)
	if !strings.Contains(s, `"edges":[]`) {
		t.Fatalf("JSON does not contain \"edges\":[] (must never be \"edges\":null) — got: %s", s)
	}
	if !strings.Contains(s, `"nodes":[`) {
		t.Fatalf("JSON \"nodes\" is not a serialized array — got: %s", s)
	}
}

func TestTopologyBGPStateFailurePropagatesErr(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "AS300")

	if g.Err == "" {
		t.Fatalf("Err = empty, want a message when bgp-state itself fails")
	}
	ev := findEvidence(g.Evidence, "bgp-state")
	if ev == nil || ev.Status != ComponentDegraded {
		t.Fatalf("bgp-state evidence = %+v, want ComponentDegraded", ev)
	}
}

func TestTopologyNeverUsesCommercialVocabulary(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","timestamp":"2026-08-18T23:59:52","nr_routes":1,"bgp_state":[
				{"target_prefix":"1.1.1.0/24","source_id":"00-1.1.1.1","path":[100,200,300],"community":[]}
			]}}`))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":300}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"invalid_asn","validating_roas":[]}}`))
		},
		"/asn-neighbours/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS300","neighbours":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	g := c.Topology(context.Background(), "1.1.1.1")

	encoded, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	upper := strings.ToUpper(string(encoded))
	for _, banned := range []string{"PROVIDER", "CUSTOMER", "UPSTREAM", "DOWNSTREAM", "TIER-1", "TIER1", "HIJACK"} {
		if strings.Contains(upper, banned) {
			t.Fatalf("Graph JSON contains banned term %q: %s", banned, encoded)
		}
	}
}
