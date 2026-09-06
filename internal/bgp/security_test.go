package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestSecurityOneOriginValid(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":13335}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
		"/asn-neighbours/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","neighbours":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	res := c.Security(context.Background(), "1.1.1.1")

	if res.MOAS {
		t.Fatalf("MOAS = true, want false")
	}
	if len(res.RPKI.Results) != 1 || res.RPKI.Results[0].State != RPKIValid {
		t.Fatalf("RPKI.Results = %+v, want one VALID result", res.RPKI.Results)
	}
	if res.Health.State != HealthNormal {
		t.Fatalf("Health.State = %q, want %q", res.Health.State, HealthNormal)
	}
	if !res.Complete {
		t.Fatalf("Complete = false, want true")
	}
}

func TestSecurityMOASAllOrigins(t *testing.T) {
	var rpkiASNs []string
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":1},{"origin":2},{"origin":3}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			rpkiASNs = append(rpkiASNs, r.URL.Query().Get("resource"))
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	res := c.Security(context.Background(), "1.1.1.0/24")

	if !res.MOAS {
		t.Fatalf("MOAS = false, want true")
	}
	if len(rpkiASNs) != 3 {
		t.Fatalf("rpkiASNs = %v, want 3 calls — every origin in a MOAS must be validated, no exception", rpkiASNs)
	}
	if len(res.RPKI.Results) != 3 {
		t.Fatalf("RPKI.Results = %d entries, want 3", len(res.RPKI.Results))
	}
	if res.Health.State != HealthAttention {
		t.Fatalf("Health.State = %q, want %q (MOAS, all VALID)", res.Health.State, HealthAttention)
	}
	if !res.Complete {
		t.Fatalf("Complete = false, want true — full RPKI coverage across all 3 origins")
	}
}

func TestSecurityInvalidASN(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":1}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"invalid_asn","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	res := c.Security(context.Background(), "1.1.1.1")

	if res.Health.State != HealthRisk {
		t.Fatalf("Health.State = %q, want %q", res.Health.State, HealthRisk)
	}
}

func TestSecurityInvalidLength(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":1}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"invalid_length","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	res := c.Security(context.Background(), "1.1.1.1")

	if res.Health.State != HealthRisk {
		t.Fatalf("Health.State = %q, want %q", res.Health.State, HealthRisk)
	}
}

func TestSecurityUnknown(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":1}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"unknown","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	res := c.Security(context.Background(), "1.1.1.1")

	if res.Health.State != HealthAttention {
		t.Fatalf("Health.State = %q, want %q", res.Health.State, HealthAttention)
	}
}

func TestSecurityValidPlusUnknown(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":1},{"origin":2}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			asn := r.URL.Query().Get("resource")
			status := "valid"
			if asn == "2" {
				status = "unknown"
			}
			w.Write([]byte(`{"status":"ok","data":{"status":"` + status + `","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	res := c.Security(context.Background(), "1.1.1.0/24")

	if res.Health.State != HealthAttention {
		t.Fatalf("Health.State = %q, want %q", res.Health.State, HealthAttention)
	}
	if !res.Complete {
		t.Fatalf("Complete = false, want true")
	}
}

func TestSecurityExceeds32OriginsIncomplete(t *testing.T) {
	var origins []string
	for i := 0; i < maxOriginsForRPKIFanout+1; i++ {
		origins = append(origins, fmt.Sprintf(`{"origin":%d}`, 1000+i))
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
	res := c.Security(context.Background(), "9.9.9.0/24")

	if rpkiCalls != 0 {
		t.Fatalf("rpkiCalls = %d, want 0 — exceeding the fan-out bound must skip RPKI entirely, never validate the first 32", rpkiCalls)
	}
	if res.Complete {
		t.Fatalf("Complete = true, want false — coverage exceeded the defensive bound")
	}
	if res.Health.State != HealthDegraded {
		t.Fatalf("Health.State = %q, want %q (incomplete evaluation)", res.Health.State, HealthDegraded)
	}
}

func TestSecurityASNOnlyNoMassRPKI(t *testing.T) {
	var rpkiCalls int
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/as-overview/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","announced":true,"holder":"CLOUDFLARENET"}}`))
		},
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","origins":[]}}`))
		},
		"/announced-prefixes/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","prefixes":[{"prefix":"1.1.1.0/24","timelines":[]}]}}`))
		},
		"/asn-neighbours/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"AS13335","neighbours":[]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			rpkiCalls++
			w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	res := c.Security(context.Background(), "AS13335")

	if rpkiCalls != 0 {
		t.Fatalf("rpkiCalls = %d, want 0 — Security for a pure ASN must never mass-validate its prefixes", rpkiCalls)
	}
	if len(res.RPKI.Results) != 0 {
		t.Fatalf("RPKI.Results = %+v, want empty — no global ASN RPKI state is fabricated", res.RPKI.Results)
	}
	rpkiEvidence := findEvidence(res.Evidence, "rpki-validation")
	if rpkiEvidence == nil || rpkiEvidence.Status != ComponentNotApplicable {
		t.Fatalf("rpki-validation evidence = %+v, want ComponentNotApplicable", rpkiEvidence)
	}
	if res.Complete {
		t.Fatalf("Complete = true, want false — RPKI validation for an ASN is prefix-scoped, not evaluated here")
	}
}

func TestSecurityNeverLabelsHIJACK(t *testing.T) {
	addr := startOverviewFakeServer(t, map[string]http.HandlerFunc{
		"/routing-status/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":1},{"origin":2}]}}`))
		},
		"/rpki-validation/data.json": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"status":"ok","data":{"status":"invalid_asn","validating_roas":[]}}`))
		},
	})
	c := &Client{BaseURL: addr}
	res := c.Security(context.Background(), "1.1.1.0/24")

	if res.Health.State != HealthRisk {
		t.Fatalf("Health.State = %q, want %q (sanity check for this fixture)", res.Health.State, HealthRisk)
	}

	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(strings.ToUpper(string(encoded)), "HIJACK") {
		t.Fatalf("SecurityResult JSON contains \"HIJACK\": %s", encoded)
	}
}
