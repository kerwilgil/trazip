package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"trazip/internal/bgp"
)

func startBGPFakeServer(t *testing.T, routes map[string]http.HandlerFunc) string {
	t.Helper()
	mux := http.NewServeMux()
	for path, h := range routes {
		mux.HandleFunc(path, h)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func newTestServiceWithBGP(addr string) *Service {
	return &Service{bgpClient: &bgp.Client{BaseURL: addr}}
}

func TestBGPOverviewDelegates(t *testing.T) {
	addr := startBGPFakeServer(t, map[string]http.HandlerFunc{
		"/as-overview/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS100","announced":true,"holder":"EXAMPLE-NET"}}`))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS100","origins":[]}}`))
		},
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS100","prefixes":[]}}`))
		},
		"/asn-neighbours/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS100","neighbours":[]}}`))
		},
	})
	s := newTestServiceWithBGP(addr)
	ov := s.BGPOverview("AS100")

	if ov.Holder != "EXAMPLE-NET" {
		t.Fatalf("Holder = %q, want EXAMPLE-NET — method must delegate to bgp.Client.Overview, not reimplement it", ov.Holder)
	}
}

func TestBGPPrefixesDelegates(t *testing.T) {
	addr := startBGPFakeServer(t, map[string]http.HandlerFunc{
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS100","prefixes":[{"prefix":"10.0.0.0/24","timelines":[]}]}}`))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"10.0.0.0/24","origins":[{"origin":100}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	s := newTestServiceWithBGP(addr)
	page := s.BGPPrefixes(bgp.PrefixPageRequest{ASN: 100, Page: 1})

	if page.TotalItems != 1 || len(page.Items) != 1 {
		t.Fatalf("page = %+v, want 1 item — method must delegate to bgp.Client.PrefixList", page)
	}
	if page.Items[0].State != bgp.PrefixLoaded {
		t.Fatalf("Items[0].State = %q, want %q", page.Items[0].State, bgp.PrefixLoaded)
	}
}

func TestBGPSecurityDelegates(t *testing.T) {
	addr := startBGPFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":100}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"invalid_asn","validating_roas":[]}}`))
		},
	})
	s := newTestServiceWithBGP(addr)
	res := s.BGPSecurity("1.1.1.1")

	if res.Health.State != bgp.HealthRisk {
		t.Fatalf("Health.State = %q, want %q — method must delegate to bgp.Client.Security", res.Health.State, bgp.HealthRisk)
	}
}

func TestBGPNeighboursDelegates(t *testing.T) {
	addr := startBGPFakeServer(t, map[string]http.HandlerFunc{
		"/asn-neighbours/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS100","neighbours":[{"asn":200,"type":"left"}]}}`))
		},
	})
	s := newTestServiceWithBGP(addr)
	res := s.BGPNeighbours(100)

	if len(res.Neighbours) != 1 || res.Neighbours[0].ASN != 200 {
		t.Fatalf("Neighbours = %+v, want one entry with ASN=200 — method must delegate to bgp.Client.AsnNeighboursRaw", res.Neighbours)
	}
}

func TestBGPTopologyDelegates(t *testing.T) {
	addr := startBGPFakeServer(t, map[string]http.HandlerFunc{
		"/bgp-state/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS100","timestamp":"2026-08-18T23:59:52","nr_routes":1,"bgp_state":[
				{"target_prefix":"10.0.0.0/24","source_id":"00-1.1.1.1","path":[300,100],"community":[]}
			]}}`))
		},
	})
	s := newTestServiceWithBGP(addr)
	g := s.BGPTopology("AS100")

	if g.ObservedNodes != 2 || g.ObservedEdges != 1 {
		t.Fatalf("Graph = %+v, want ObservedNodes=2 ObservedEdges=1 — method must delegate to bgp.Client.Topology", g)
	}
}

func TestBGPMethodsInvalidInputNeverPanics(t *testing.T) {
	addr := startBGPFakeServer(t, map[string]http.HandlerFunc{})
	s := newTestServiceWithBGP(addr)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a BGP method panicked on invalid input: %v", r)
		}
	}()

	ov := s.BGPOverview("not-a-valid-resource!!")
	if ov.Err == "" {
		t.Errorf("BGPOverview: Err = empty, want a message for invalid input")
	}

	page := s.BGPPrefixes(bgp.PrefixPageRequest{ASN: -1, Page: 1})
	if page.Err == "" {
		t.Errorf("BGPPrefixes: Err = empty, want a message for invalid ASN")
	}

	sec := s.BGPSecurity("not-a-valid-resource!!")
	if sec.Err == "" {
		t.Errorf("BGPSecurity: Err = empty, want a message for invalid input")
	}

	neighbours := s.BGPNeighbours(-1)
	if neighbours.Err == "" {
		t.Errorf("BGPNeighbours: Err = empty, want a message for invalid ASN")
	}

	topo := s.BGPTopology("not-a-valid-resource!!")
	if topo.Err == "" {
		t.Errorf("BGPTopology: Err = empty, want a message for invalid input")
	}
}

// TestBGPLegacyContractsStillWork is a regression check: the new v1.1
// methods must never break BGPRoutingStatus/BGPRPKIValidate.
func TestBGPLegacyContractsStillWork(t *testing.T) {
	addr := startBGPFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS100","origins":[{"origin":100,"route_objects":[]}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	s := newTestServiceWithBGP(addr)

	rs := s.BGPRoutingStatus("AS100")
	if !rs.Announced {
		t.Fatalf("BGPRoutingStatus.Announced = false, want true")
	}

	rpki := s.BGPRPKIValidate(100, "10.0.0.0/24")
	if rpki.Prefix != "10.0.0.0/24" {
		t.Fatalf("BGPRPKIValidate.Prefix = %q, want 10.0.0.0/24", rpki.Prefix)
	}
}
