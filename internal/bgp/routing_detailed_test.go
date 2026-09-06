package bgp

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"trazip/internal/intel/external"
)

func TestClassifyVisibility(t *testing.T) {
	tests := []struct {
		ratio float64
		want  string
	}{
		{0.66, "alta"},
		{1.0, "alta"},
		{0.65, "media"},
		{0.33, "media"},
		{0.32, "baja"},
		{0.01, "baja"},
		{0, "no_observado"},
	}
	for _, tc := range tests {
		if got := classifyVisibility(tc.ratio); got != tc.want {
			t.Errorf("classifyVisibility(%v) = %q, want %q", tc.ratio, got, tc.want)
		}
	}
}

func TestRoutingStatusDetailedASNWithBothFamilies(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{
			"resource":"AS3333",
			"origins":[{"origin":3333,"route_objects":["RIPE"]}],
			"visibility":{
				"v4":{"ris_peers_seeing":300,"total_ris_peers":400},
				"v6":{"ris_peers_seeing":150,"total_ris_peers":400}
			},
			"first_seen":{"time":"2010-01-01T00:00:00Z","origin":3333,"prefix":"193.0.0.0/21"},
			"last_seen":{"time":"2026-01-01T00:00:00Z","origin":"AS3333","prefix":"193.0.0.0/21"},
			"announced_space":{
				"v4":{"prefixes":10,"ips":5120},
				"v6":{"prefixes":3,"48s":768}
			},
			"observed_neighbours":42,
			"query_time":"2026-01-01T00:00:00Z"
		}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.RoutingStatusDetailedQuery(context.Background(), "AS3333")

	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if !res.Announced {
		t.Error("expected Announced=true")
	}
	if res.VisibilityV4 == nil || res.VisibilityV4.RISPeersSeeing != 300 || res.VisibilityV4.TotalRISPeers != 400 {
		t.Errorf("VisibilityV4 = %+v", res.VisibilityV4)
	}
	if res.VisibilityV6 == nil || res.VisibilityV6.RISPeersSeeing != 150 || res.VisibilityV6.TotalRISPeers != 400 {
		t.Errorf("VisibilityV6 = %+v", res.VisibilityV6)
	}
	if res.VisibilityV4.Ratio == res.VisibilityV6.Ratio {
		t.Error("v4 and v6 ratios should differ here — they must never be combined into one")
	}
	if res.FirstSeen == nil || res.FirstSeen.Origin != 3333 || res.FirstSeen.Prefix != "193.0.0.0/21" {
		t.Errorf("FirstSeen = %+v", res.FirstSeen)
	}
	if res.LastSeen == nil || res.LastSeen.Origin != 3333 {
		t.Errorf("LastSeen.Origin (from \"AS3333\" string form) = %+v, want 3333", res.LastSeen)
	}
	if res.AnnouncedSpaceV4 == nil || res.AnnouncedSpaceV4.Prefixes != 10 || res.AnnouncedSpaceV4.IPs != 5120 {
		t.Errorf("AnnouncedSpaceV4 = %+v", res.AnnouncedSpaceV4)
	}
	if res.AnnouncedSpaceV6 == nil || res.AnnouncedSpaceV6.Prefixes != 3 || res.AnnouncedSpaceV6.Slash48s != 768 {
		t.Errorf("AnnouncedSpaceV6 = %+v", res.AnnouncedSpaceV6)
	}
	if res.ObservedNeighbours != 42 {
		t.Errorf("ObservedNeighbours = %d, want 42", res.ObservedNeighbours)
	}
	if res.Evidence.Status != ComponentOK || res.Evidence.Component != "routing-status" {
		t.Errorf("Evidence = %+v", res.Evidence)
	}
}

func TestRoutingStatusDetailedPrefixSingleFamily(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{
			"resource":"1.1.1.0/24",
			"origins":[{"origin":13335,"route_objects":["APNIC"]}],
			"visibility":{"v4":{"ris_peers_seeing":400,"total_ris_peers":400}}
		}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.RoutingStatusDetailedQuery(context.Background(), "1.1.1.0/24")

	if res.VisibilityV4 == nil {
		t.Fatal("expected VisibilityV4 to be populated")
	}
	if res.VisibilityV6 != nil {
		t.Errorf("VisibilityV6 should be nil for a v4-only response, got %+v", res.VisibilityV6)
	}
}

func TestRoutingStatusDetailedIPv6AnnouncedSpaceWireKey(t *testing.T) {
	// RIPEstat's real wire key for the IPv6 /48-equivalent count is "48s",
	// not "/48s" — a fixture pinned exactly to the real key, to catch a
	// silent-zero regression if the json tag ever drifts again.
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{
			"resource":"AS3333",
			"origins":[],
			"announced_space":{"v6":{"prefixes":1,"48s":123}}
		}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.RoutingStatusDetailedQuery(context.Background(), "AS3333")

	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if res.AnnouncedSpaceV6 == nil {
		t.Fatal("AnnouncedSpaceV6 is nil")
	}
	if res.AnnouncedSpaceV6.Prefixes != 1 {
		t.Errorf("Prefixes = %d, want 1", res.AnnouncedSpaceV6.Prefixes)
	}
	if res.AnnouncedSpaceV6.Slash48s != 123 {
		t.Fatalf("Slash48s = %d, want 123 — a wrong json tag would silently leave this at 0", res.AnnouncedSpaceV6.Slash48s)
	}
}

func TestRoutingStatusDetailedTotalRISPeersZero(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{
			"resource":"192.0.2.0/24",
			"origins":[],
			"visibility":{"v4":{"ris_peers_seeing":0,"total_ris_peers":0}}
		}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.RoutingStatusDetailedQuery(context.Background(), "192.0.2.0/24")

	if res.VisibilityV4.Ratio != 0 {
		t.Errorf("Ratio = %v, want 0 when TotalRISPeers == 0", res.VisibilityV4.Ratio)
	}
	if res.VisibilityV4.Classification != "no_observado" {
		t.Errorf("Classification = %q, want no_observado", res.VisibilityV4.Classification)
	}
}

func TestRoutingStatusDetailedMOASMultipleOrigins(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{
			"resource":"203.0.113.0/24",
			"origins":[
				{"origin":100,"route_objects":["A"]},
				{"origin":200,"route_objects":["B"]}
			]
		}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.RoutingStatusDetailedQuery(context.Background(), "203.0.113.0/24")

	if len(res.Origins) != 2 {
		t.Fatalf("Origins = %+v, want 2 (MOAS preserved as multiple origins)", res.Origins)
	}
	if !res.Announced {
		t.Error("expected Announced=true with multiple origins")
	}
}

func TestRoutingStatusDetailedMalformedJSON(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	})
	c := &Client{BaseURL: addr}
	res := c.RoutingStatusDetailedQuery(context.Background(), "1.1.1.1")
	if res.Err == "" {
		t.Fatal("expected Err on malformed JSON")
	}
	if res.Evidence.Status != ComponentDegraded {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentDegraded)
	}
}

func TestRoutingStatusDetailedHTTPError(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := &Client{BaseURL: addr}
	res := c.RoutingStatusDetailedQuery(context.Background(), "1.1.1.1")
	if res.Err == "" {
		t.Fatal("expected Err on HTTP failure")
	}
	if res.Evidence.Status != ComponentDegraded {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentDegraded)
	}
}

func TestRoutingStatusDetailedContextCancellation(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.1","origins":[]}}`))
	})
	c := &Client{BaseURL: addr}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := c.RoutingStatusDetailedQuery(ctx, "1.1.1.1")
	if res.Err == "" {
		t.Fatal("expected Err when context is already cancelled")
	}
	if res.Evidence.Status != ComponentDegraded {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentDegraded)
	}
}

func TestRoutingStatusDetailedEmptyResourceNoHTTPCall(t *testing.T) {
	var requests int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(`{"status":"ok","data":{"resource":"","origins":[]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.RoutingStatusDetailedQuery(context.Background(), "   ")
	if res.Err == "" {
		t.Fatal("expected Err for empty resource")
	}
	if res.Evidence.Status != ComponentNotApplicable {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentNotApplicable)
	}
	if requests != 0 {
		t.Errorf("requests = %d, want 0", requests)
	}
}

func TestRoutingStatusDetailedMalformedResourceNoHTTPCall(t *testing.T) {
	// Not just empty — genuinely malformed input (fails ClassifyResource)
	// must also be rejected locally, reusing the same resource parser as
	// everything else in this package rather than duplicating validation.
	var requests int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(`{"status":"ok","data":{"resource":"","origins":[]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.RoutingStatusDetailedQuery(context.Background(), "not-a-valid-resource")

	if res.Err == "" {
		t.Fatal("expected Err for malformed resource")
	}
	if res.Evidence.Status != ComponentNotApplicable {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentNotApplicable)
	}
	if res.Evidence.Err != "" {
		t.Errorf("Evidence.Err = %q, want empty — the error belongs only on RoutingStatusDetailed.Err", res.Evidence.Err)
	}
	if res.Evidence.Disclosure != (external.Disclosure{}) {
		t.Errorf("Evidence.Disclosure should stay zero-valued: %+v", res.Evidence.Disclosure)
	}
	if requests != 0 {
		t.Errorf("requests = %d, want 0", requests)
	}
}

func TestRoutingStatusDetailedUsesClassifyResourceNormalization(t *testing.T) {
	cases := []struct {
		name              string
		input             string
		wantResourceParam string
	}{
		{"lowercase asn gets canonicalized", "as3333", "AS3333"},
		{"prefix with host bits gets masked", "192.0.2.7/24", "192.0.2.0/24"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotParam string
			addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
				gotParam = r.URL.Query().Get("resource")
				w.Write([]byte(`{"status":"ok","data":{"resource":"` + gotParam + `","origins":[]}}`))
			})
			c := &Client{BaseURL: addr}
			res := c.RoutingStatusDetailedQuery(context.Background(), tc.input)

			if res.Err != "" {
				t.Fatalf("unexpected error: %s", res.Err)
			}
			if gotParam != tc.wantResourceParam {
				t.Errorf("resource param sent to RIPEstat = %q, want normalized form %q", gotParam, tc.wantResourceParam)
			}
			if res.Resource != tc.wantResourceParam {
				t.Errorf("RoutingStatusDetailed.Resource = %q, want %q", res.Resource, tc.wantResourceParam)
			}
		})
	}
}

func TestRoutingStatusDetailedDataSentReflectsExactResource(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"AS3333","origins":[]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.RoutingStatusDetailedQuery(context.Background(), " as3333 ")

	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if !strings.Contains(res.Evidence.Disclosure.DataSent, "AS3333") {
		t.Errorf("Disclosure.DataSent = %q, want it to contain the actual resource queried (AS3333), not generic text", res.Evidence.Disclosure.DataSent)
	}
}

func TestRoutingStatusExistingBehaviorUnchanged(t *testing.T) {
	// Regression guard: the pre-existing RoutingStatus/RouteStatus
	// contract (bgp.go) must behave identically after this file's
	// additions.
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":13335,"route_objects":["APNIC","RADB"]}]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.RoutingStatus(context.Background(), "1.1.1.0/24")
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if !res.Announced || res.Prefix != "1.1.1.0/24" || len(res.Origins) != 1 || res.Origins[0] != 13335 {
		t.Fatalf("RouteStatus = %+v, existing contract broken", res)
	}
}
