package bgp

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestNormalizePosition(t *testing.T) {
	tests := []struct {
		raw  string
		want NeighbourPosition
	}{
		{"left", PositionLeft},
		{"right", PositionRight},
		{"uncertain", PositionUncertain},
		{"future-new-value", PositionUnknown},
		{"", PositionUnknown},
	}
	for _, tc := range tests {
		if got := normalizePosition(tc.raw); got != tc.want {
			t.Errorf("normalizePosition(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestAsnNeighboursRawLeftRightUncertain(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{
			"resource":"12386",
			"query_time":"2026-01-01T00:00:00Z",
			"neighbour_counts":{"left":1,"right":1,"unique":3,"uncertain":1},
			"neighbours":[
				{"asn":1205,"type":"left","path_count":156,"v4_peers":42,"v6_peers":38},
				{"asn":6667,"type":"right","path_count":90,"v4_peers":10,"v6_peers":5},
				{"asn":9999,"type":"uncertain","path_count":2,"v4_peers":1,"v6_peers":0}
			]
		}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.AsnNeighboursRaw(context.Background(), 12386)

	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if len(res.Neighbours) != 3 {
		t.Fatalf("Neighbours = %+v, want 3", res.Neighbours)
	}
	byASN := map[int]NeighbourObservation{}
	for _, n := range res.Neighbours {
		byASN[n.ASN] = n
	}
	if byASN[1205].Position != PositionLeft || byASN[1205].PathCount != 156 || byASN[1205].PeerCountV4 != 42 || byASN[1205].PeerCountV6 != 38 {
		t.Errorf("AS1205 = %+v", byASN[1205])
	}
	if byASN[6667].Position != PositionRight {
		t.Errorf("AS6667.Position = %s, want right", byASN[6667].Position)
	}
	if byASN[9999].Position != PositionUncertain {
		t.Errorf("AS9999.Position = %s, want uncertain", byASN[9999].Position)
	}
	if res.NeighbourCounts != (NeighbourCounts{Left: 1, Right: 1, Unique: 3, Uncertain: 1}) {
		t.Errorf("NeighbourCounts = %+v", res.NeighbourCounts)
	}
}

func TestAsnNeighboursRawCompatibleFieldNaming(t *testing.T) {
	// Older/alternate wire shape: "position" instead of "type", "power"
	// instead of "path_count", nested "peer_count" instead of flat
	// v4_peers/v6_peers. Must normalize to the same internal contract.
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{
			"resource":"12386",
			"neighbours":[
				{"asn":1205,"position":"left","power":156,"peer_count":{"v4":42,"v6":38}}
			]
		}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.AsnNeighboursRaw(context.Background(), 12386)

	if len(res.Neighbours) != 1 {
		t.Fatalf("Neighbours = %+v, want 1", res.Neighbours)
	}
	n := res.Neighbours[0]
	if n.Position != PositionLeft {
		t.Errorf("Position = %s, want left (from \"position\" field)", n.Position)
	}
	if n.PathCount != 156 {
		t.Errorf("PathCount = %d, want 156 (from \"power\" field)", n.PathCount)
	}
	if n.PeerCountV4 != 42 || n.PeerCountV6 != 38 {
		t.Errorf("PeerCountV4/V6 = %d/%d, want 42/38 (from nested peer_count)", n.PeerCountV4, n.PeerCountV6)
	}
}

func TestAsnNeighboursRawZeroNeighboursIsValid(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"64500","neighbours":[]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.AsnNeighboursRaw(context.Background(), 64500)

	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if len(res.Neighbours) != 0 {
		t.Errorf("Neighbours = %+v, want empty", res.Neighbours)
	}
	if res.Evidence.Status != ComponentOK {
		t.Errorf("Evidence.Status = %s, want %s — zero neighbours is a valid result", res.Evidence.Status, ComponentOK)
	}
}

func TestAsnNeighboursRawNeverProducesCommercialVocabulary(t *testing.T) {
	forbidden := []string{"provider", "customer", "upstream", "downstream", "tier-1", "tier1", "transit provider", "commercial peer"}

	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{
			"resource":"12386",
			"neighbours":[
				{"asn":1205,"type":"left","path_count":1},
				{"asn":6667,"type":"right","path_count":1},
				{"asn":7777,"type":"weird-unrecognized-value","path_count":1}
			]
		}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.AsnNeighboursRaw(context.Background(), 12386)

	for _, n := range res.Neighbours {
		lower := strings.ToLower(string(n.Position))
		for _, word := range forbidden {
			if strings.Contains(lower, word) {
				t.Fatalf("neighbour %d.Position = %q contains forbidden commercial vocabulary %q", n.ASN, n.Position, word)
			}
		}
	}
	// An unrecognized type value must fall back to "unknown" — never
	// guessed as left/right, and never folded into "uncertain" (which
	// has its own distinct, documented meaning) — with the original
	// string preserved losslessly in RawPosition.
	for _, n := range res.Neighbours {
		if n.ASN == 7777 {
			if n.Position != PositionUnknown {
				t.Errorf("unrecognized type value should map to PositionUnknown, got %s", n.Position)
			}
			if n.RawPosition != "weird-unrecognized-value" {
				t.Errorf("RawPosition = %q, want the original unrecognized value preserved losslessly", n.RawPosition)
			}
		}
	}
}

func TestAsnNeighboursRawInvalidASNNoHTTPCall(t *testing.T) {
	var requests int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(`{"status":"ok","data":{"resource":"1","neighbours":[]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.AsnNeighboursRaw(context.Background(), -5)

	if res.Err == "" {
		t.Error("expected Err for invalid ASN")
	}
	if res.Evidence.Status != ComponentNotApplicable {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentNotApplicable)
	}
	if requests != 0 {
		t.Errorf("requests = %d, want 0", requests)
	}
}

func TestAsnNeighboursRawDatasourceError(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := &Client{BaseURL: addr}
	res := c.AsnNeighboursRaw(context.Background(), 12386)
	if res.Err == "" {
		t.Fatal("expected Err on HTTP failure")
	}
	if res.Evidence.Status != ComponentDegraded {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentDegraded)
	}
}
