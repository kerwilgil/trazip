package bgp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// startOverviewFakeServer multiplexes fixture handlers by RIPEstat
// endpoint path (e.g. "/as-overview/data.json") so a single hermetic
// server can stand in for every datasource Overview aggregates.
func startOverviewFakeServer(t *testing.T, routes map[string]http.HandlerFunc) string {
	t.Helper()
	mux := http.NewServeMux()
	for path, h := range routes {
		mux.HandleFunc(path, h)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestOverviewASNAggregatesWithoutRPKIFanout(t *testing.T) {
	var rpkiCalls int
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/as-overview/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","announced":true,"holder":"CLOUDFLARENET"}}`))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","origins":[],"visibility":{"v4":{"ris_peers_seeing":8,"total_ris_peers":10}}}}`))
		},
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","prefixes":[{"prefix":"1.1.1.0/24","timelines":[]}]}}`))
		},
		"/asn-neighbours/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","neighbours":[{"asn":3356,"type":"left"}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			rpkiCalls++
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}

	ov := c.Overview(context.Background(), "AS13335")

	if ov.Kind != KindASN {
		t.Fatalf("Kind = %q, want KindASN", ov.Kind)
	}
	if ov.ASN != 13335 {
		t.Fatalf("ASN = %d, want 13335", ov.ASN)
	}
	if ov.Holder != "CLOUDFLARENET" {
		t.Fatalf("Holder = %q, want CLOUDFLARENET", ov.Holder)
	}
	if len(ov.Prefixes) != 1 || ov.Prefixes[0] != "1.1.1.0/24" {
		t.Fatalf("Prefixes = %v, want [1.1.1.0/24]", ov.Prefixes)
	}
	if ov.Neighbors.Count != 1 || ov.Neighbors.Left != 1 {
		t.Fatalf("Neighbors = %+v, want Count=1 Left=1", ov.Neighbors)
	}
	if rpkiCalls != 0 {
		t.Fatalf("rpkiCalls = %d, want 0 — an ASN Overview must never fan out RPKI (no single representative prefix)", rpkiCalls)
	}
	rpkiEvidence := findEvidence(ov.Evidence, "rpki-validation")
	if rpkiEvidence == nil || rpkiEvidence.Status != ComponentNotApplicable {
		t.Fatalf("rpki-validation evidence = %+v, want ComponentNotApplicable", rpkiEvidence)
	}
	if ov.Err != "" {
		t.Fatalf("Err = %q, want empty", ov.Err)
	}
}

func TestOverviewASNCachesUnderlyingCalls(t *testing.T) {
	var asOverviewCalls, routingCalls int
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/as-overview/data.json": func(w http.ResponseWriter, r *http.Request) {
			asOverviewCalls++
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","announced":true,"holder":"CLOUDFLARENET"}}`))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			routingCalls++
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","origins":[]}}`))
		},
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","prefixes":[]}}`))
		},
		"/asn-neighbours/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","neighbours":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}

	c.Overview(context.Background(), "AS13335")
	c.Overview(context.Background(), "AS13335")

	if asOverviewCalls != 1 {
		t.Errorf("asOverviewCalls = %d, want 1 (second Overview call must hit cache)", asOverviewCalls)
	}
	if routingCalls != 1 {
		t.Errorf("routingCalls = %d, want 1 (second Overview call must hit cache)", routingCalls)
	}
}

func TestOverviewIPSingleOriginValidatesExactlyThatOrigin(t *testing.T) {
	var rpkiRequests int
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":13335,"route_objects":[]}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			rpkiRequests++
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
		"/asn-neighbours/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","neighbours":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}

	ov := c.Overview(context.Background(), "1.1.1.1")

	if ov.Kind != KindIPv4 {
		t.Fatalf("Kind = %q, want KindIPv4", ov.Kind)
	}
	if ov.MOAS {
		t.Fatalf("MOAS = true, want false (single origin)")
	}
	if len(ov.Origins) != 1 || ov.Origins[0] != 13335 {
		t.Fatalf("Origins = %v, want [13335]", ov.Origins)
	}
	if rpkiRequests != 1 {
		t.Fatalf("rpkiRequests = %d, want exactly 1", rpkiRequests)
	}
	if len(ov.RPKI.Results) != 1 || ov.RPKI.Results[0].State != RPKIValid {
		t.Fatalf("RPKI.Results = %+v, want one VALID result", ov.RPKI.Results)
	}
	if ov.RPKI.States[RPKIValid] != 1 {
		t.Fatalf("RPKI.States = %v, want {VALID:1}", ov.RPKI.States)
	}
}

func TestOverviewPrefixMOASValidatesEveryOrigin(t *testing.T) {
	var rpkiCallCount int
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":13335},{"origin":20940}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			rpkiCallCount++
			asn := r.URL.Query().Get("resource")
			if asn == "13335" {
				w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
			} else {
				w.Write([]byte(`{"status":"ok","data":{"status":"invalid_asn","validating_roas":[]}}`))
			}
		},
	})
	c := &Client{BaseURL: addr}

	ov := c.Overview(context.Background(), "1.1.1.0/24")

	if !ov.MOAS {
		t.Fatalf("MOAS = false, want true (2 origins)")
	}
	if rpkiCallCount != 2 {
		t.Fatalf("rpkiCallCount = %d, want 2 — every origin in a MOAS must be validated individually, never collapsed", rpkiCallCount)
	}
	if len(ov.RPKI.Results) != 2 {
		t.Fatalf("RPKI.Results = %d entries, want 2", len(ov.RPKI.Results))
	}
	if ov.RPKI.States[RPKIValid] != 1 || ov.RPKI.States[RPKIInvalidASN] != 1 {
		t.Fatalf("RPKI.States = %v, want {VALID:1, INVALID_ASN:1}", ov.RPKI.States)
	}
	neighboursEvidence := findEvidence(ov.Evidence, "asn-neighbours")
	if neighboursEvidence == nil || neighboursEvidence.Status != ComponentNotApplicable {
		t.Fatalf("asn-neighbours evidence = %+v, want ComponentNotApplicable (MOAS has no single attributable ASN)", neighboursEvidence)
	}
}

func TestOverviewRPKIStatesAllFourPlusMixedAndMOAS(t *testing.T) {
	cases := []struct {
		name       string
		rpkiStatus []string
		wantStates map[RPKIState]int
	}{
		{"valid", []string{"valid"}, map[RPKIState]int{RPKIValid: 1}},
		{"invalid_asn", []string{"invalid_asn"}, map[RPKIState]int{RPKIInvalidASN: 1}},
		{"invalid_length", []string{"invalid_length"}, map[RPKIState]int{RPKIInvalidLength: 1}},
		{"unknown", []string{"unknown"}, map[RPKIState]int{RPKIUnknown: 1}},
		{"MOAS valid+unknown", []string{"valid", "unknown"}, map[RPKIState]int{RPKIValid: 1, RPKIUnknown: 1}},
		{"MOAS both valid", []string{"valid", "valid"}, map[RPKIState]int{RPKIValid: 2}},
		{"MOAS valid+invalid", []string{"valid", "invalid_asn"}, map[RPKIState]int{RPKIValid: 1, RPKIInvalidASN: 1}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var origins []string
			statusByASN := map[string]string{}
			for i, s := range tc.rpkiStatus {
				asn := 10000 + i
				origins = append(origins, fmt.Sprintf(`{"origin":%d}`, asn))
				statusByASN[fmt.Sprintf("%d", asn)] = s
			}
			addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
				"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte(`{"status":"ok","data":{"resource":"9.9.9.0/24","origins":[` + strings.Join(origins, ",") + `]}}`))
				},
				"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
					status := statusByASN[r.URL.Query().Get("resource")]
					w.Write([]byte(`{"status":"ok","data":{"status":"` + status + `","validating_roas":[]}}`))
				},
				"/asn-neighbours/data.json": func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte(`{"status":"ok","data":{"resource":"AS10000","neighbours":[]}}`))
				},
			})
			c := &Client{BaseURL: addr}
			ov := c.Overview(context.Background(), "9.9.9.0/24")

			if len(ov.RPKI.Results) != len(tc.rpkiStatus) {
				t.Fatalf("RPKI.Results = %d entries, want %d", len(ov.RPKI.Results), len(tc.rpkiStatus))
			}
			for state, want := range tc.wantStates {
				if ov.RPKI.States[state] != want {
					t.Errorf("RPKI.States[%s] = %d, want %d (full: %v)", state, ov.RPKI.States[state], want, ov.RPKI.States)
				}
			}
		})
	}
}

func TestOverviewExceedsFanoutBoundSkipsRPKIEntirely(t *testing.T) {
	var origins []string
	for i := 0; i < maxOriginsForRPKIFanout+1; i++ {
		origins = append(origins, fmt.Sprintf(`{"origin":%d}`, 100+i))
	}
	var rpkiCalls int
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"9.9.9.0/24","origins":[` + strings.Join(origins, ",") + `]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			rpkiCalls++
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	ov := c.Overview(context.Background(), "9.9.9.0/24")

	if rpkiCalls != 0 {
		t.Fatalf("rpkiCalls = %d, want 0 — exceeding the defensive fan-out bound must skip RPKI entirely, never silently truncate to the first N", rpkiCalls)
	}
	ev := findEvidence(ov.Evidence, "rpki-validation")
	if ev == nil || ev.Status != ComponentDegraded {
		t.Fatalf("rpki-validation evidence = %+v, want ComponentDegraded", ev)
	}
}

func TestOverviewASNPartialFailurePreserved(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/as-overview/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","origins":[],"visibility":{"v4":{"ris_peers_seeing":8,"total_ris_peers":10}}}}`))
		},
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","prefixes":[]}}`))
		},
		"/asn-neighbours/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","neighbours":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	ov := c.Overview(context.Background(), "AS13335")

	if ov.Err != "" {
		t.Fatalf("Err = %q, want empty — routing-status succeeded, Overview must stay useful despite as-overview failing", ov.Err)
	}
	if ov.Holder != "" {
		t.Fatalf("Holder = %q, want empty (as-overview failed)", ov.Holder)
	}
	if ov.VisibilityV4 == nil {
		t.Fatalf("VisibilityV4 = nil, want populated from the succeeding routing-status call")
	}
	asOverviewEvidence := findEvidence(ov.Evidence, "as-overview")
	if asOverviewEvidence == nil || asOverviewEvidence.Status != ComponentDegraded {
		t.Fatalf("as-overview evidence = %+v, want ComponentDegraded", asOverviewEvidence)
	}
}

func TestOverviewIPNeighboursFailureDoesNotBlockRPKI(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":13335}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
		"/asn-neighbours/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		},
	})
	c := &Client{BaseURL: addr}
	ov := c.Overview(context.Background(), "1.1.1.1")

	if ov.Err != "" {
		t.Fatalf("Err = %q, want empty", ov.Err)
	}
	if len(ov.RPKI.Results) != 1 || ov.RPKI.Results[0].State != RPKIValid {
		t.Fatalf("RPKI.Results = %+v, want one VALID result despite neighbours failing", ov.RPKI.Results)
	}
	neighboursEvidence := findEvidence(ov.Evidence, "asn-neighbours")
	if neighboursEvidence == nil || neighboursEvidence.Status != ComponentDegraded {
		t.Fatalf("asn-neighbours evidence = %+v, want ComponentDegraded", neighboursEvidence)
	}
}

func TestOverviewZeroOriginsDoesNoRPKIOrNeighboursAndHealthNeverNormal(t *testing.T) {
	var rpkiCalls, neighbourCalls int
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"9.9.9.0/24","origins":[]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			rpkiCalls++
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
		"/asn-neighbours/data.json": func(w http.ResponseWriter, r *http.Request) {
			neighbourCalls++
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS1","neighbours":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	ov := c.Overview(context.Background(), "9.9.9.0/24")

	if rpkiCalls != 0 {
		t.Fatalf("rpkiCalls = %d, want 0 — a resource with zero announced origins has nothing to validate", rpkiCalls)
	}
	if neighbourCalls != 0 {
		t.Fatalf("neighbourCalls = %d, want 0 — no origin ASN to attribute neighbours to", neighbourCalls)
	}

	health := EvaluateHealth(ov)
	if health.State == HealthNormal {
		t.Fatalf("Health.State = NORMAL for a resource with zero announced origins — nothing was confirmed safe, must never present as NORMAL")
	}
	if health.DataSufficient {
		t.Fatalf("Health.DataSufficient = true, want false — there is no route security to evaluate for an unannounced resource")
	}
}

func TestOverviewContextCancellationCutsRPKIFanoutShort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var rpkiCallCount int
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"9.9.9.0/24","origins":[{"origin":1},{"origin":2},{"origin":3}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			rpkiCallCount++
			first := rpkiCallCount == 1
			mu.Unlock()
			if first {
				cancel()
			}
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}

	ov := c.Overview(ctx, "9.9.9.0/24")

	mu.Lock()
	finalCount := rpkiCallCount
	mu.Unlock()

	if finalCount >= 3 {
		t.Fatalf("rpkiCallCount = %d, want < 3 — cancellation after the first call must cut the remaining fan-out short", finalCount)
	}
	if len(ov.RPKI.Results) != finalCount {
		t.Fatalf("RPKI.Results = %d, want to match the number of RPKI calls actually attempted (%d)", len(ov.RPKI.Results), finalCount)
	}
}

func TestOverviewInvalidResource(t *testing.T) {
	c := &Client{BaseURL: "http://unused.invalid"}
	ov := c.Overview(context.Background(), "not-a-valid-resource!!")
	if ov.Kind != KindInvalid {
		t.Fatalf("Kind = %q, want KindInvalid", ov.Kind)
	}
	if ov.Err == "" {
		t.Fatalf("Err = empty, want a message for an invalid resource")
	}
}
