package bgp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trazip/internal/intel/external"
)

func TestMapRPKIState(t *testing.T) {
	tests := []struct {
		raw  string
		want RPKIState
	}{
		{"valid", RPKIValid},
		{"invalid_asn", RPKIInvalidASN},
		{"invalid_length", RPKIInvalidLength},
		{"unknown", RPKIUnknown},
		{"unexpected-future-value", RPKIUnknown},
		{"", RPKIUnknown},
		{"VALID", RPKIValid}, // case-insensitive
	}
	for _, tc := range tests {
		if got := mapRPKIState(tc.raw); got != tc.want {
			t.Errorf("mapRPKIState(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func rpkiDetailedFixtureServer(t *testing.T, status string) string {
	t.Helper()
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"status":"` + status + `","validating_roas":[{"origin":"13335","prefix":"1.1.1.0/24","validity":"valid","max_length":24}]}}`))
	})
	return addr
}

// startFakeServerHTTP is a minimal local httptest wrapper matching the
// hermetic-server style already used by bgp_test.go's other tests.
func startFakeServerHTTP(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestRPKIValidateDetailedTopLevelStatus(t *testing.T) {
	cases := []struct {
		name   string
		status string
		want   RPKIState
	}{
		{"valid", "valid", RPKIValid},
		{"invalid_asn", "invalid_asn", RPKIInvalidASN},
		{"invalid_length", "invalid_length", RPKIInvalidLength},
		{"unknown", "unknown", RPKIUnknown},
		{"unexpected future value", "unexpected-future-value", RPKIUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := rpkiDetailedFixtureServer(t, tc.status)
			c := &Client{BaseURL: addr}
			res := c.RPKIValidateDetailed(context.Background(), 13335, "1.1.1.0/24")
			if res.Err != "" {
				t.Fatalf("unexpected error: %s", res.Err)
			}
			if res.State != tc.want {
				t.Errorf("State = %s, want %s", res.State, tc.want)
			}
			if res.Evidence.Status != ComponentOK {
				t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentOK)
			}
			if len(res.ROAs) != 1 || res.ROAs[0].Origin != "13335" || res.ROAs[0].Validity != "valid" {
				t.Errorf("ROAs not preserved correctly: %+v", res.ROAs)
			}
		})
	}
}

func TestRPKIValidateDetailedStateIgnoresROAValidity(t *testing.T) {
	// Top-level status says invalid_asn, but the (only) ROA's own
	// "validity" field says "valid" — State must follow the top-level
	// status, never the per-ROA evidence.
	addr := rpkiDetailedFixtureServer(t, "invalid_asn")
	c := &Client{BaseURL: addr}
	res := c.RPKIValidateDetailed(context.Background(), 13335, "1.1.1.0/24")
	if res.State != RPKIInvalidASN {
		t.Fatalf("State = %s, want %s (top-level status must win over ROA validity)", res.State, RPKIInvalidASN)
	}
	if len(res.ROAs) != 1 || res.ROAs[0].Validity != "valid" {
		t.Fatalf("expected the ROA's own (differing) validity to be preserved as evidence: %+v", res.ROAs)
	}
}

func TestRPKIValidateDetailedInvalidInputRejectedLocally(t *testing.T) {
	cases := []struct {
		name   string
		asn    int
		prefix string
	}{
		{"asn zero", 0, "1.1.1.0/24"},
		{"asn negative", -13335, "1.1.1.0/24"},
		{"asn above max uint32", maxASN + 1, "1.1.1.0/24"},
		{"prefix empty", 13335, ""},
		{"prefix malformed text", 13335, "not-a-prefix"},
		{"ip without cidr", 13335, "1.1.1.1"},
		{"prefix invalid bits", 13335, "1.1.1.0/33"},
		{"prefix invalid syntax", 13335, "1.1.1.0/24/extra"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var requests int
			addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
			})
			c := &Client{BaseURL: addr}

			res := c.RPKIValidateDetailed(context.Background(), tc.asn, tc.prefix)

			if res.Err == "" {
				t.Error("RPKIValidationDetailed.Err should be non-empty for rejected input")
			}
			if res.Evidence.Status != ComponentNotApplicable {
				t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentNotApplicable)
			}
			if res.Evidence.Err != "" {
				t.Errorf("Evidence.Err = %q, want empty — the error belongs only on RPKIValidationDetailed.Err", res.Evidence.Err)
			}
			if res.Evidence.Disclosure != (external.Disclosure{}) {
				t.Errorf("Evidence.Disclosure should stay zero-valued — no external call happened: %+v", res.Evidence.Disclosure)
			}
			if requests != 0 {
				t.Errorf("requests = %d, want 0 (rejected input must never reach the network)", requests)
			}
		})
	}
}

func TestRPKIValidateDetailedNormalizesPrefixWithHostBits(t *testing.T) {
	var gotPrefixParam string
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		gotPrefixParam = r.URL.Query().Get("prefix")
		w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
	})
	c := &Client{BaseURL: addr}

	res := c.RPKIValidateDetailed(context.Background(), 13335, "192.0.2.7/24")
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if res.Prefix != "192.0.2.0/24" {
		t.Errorf("Prefix = %q, want %q (host bits must be masked off)", res.Prefix, "192.0.2.0/24")
	}
	if gotPrefixParam != "192.0.2.0/24" {
		t.Errorf("prefix sent to RIPEstat = %q, want the normalized form", gotPrefixParam)
	}
}

func TestRPKIValidateDetailedHTTPError(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := &Client{BaseURL: addr}
	res := c.RPKIValidateDetailed(context.Background(), 13335, "1.1.1.0/24")
	if res.Err == "" {
		t.Fatal("expected Err on HTTP failure")
	}
	if res.Evidence.Status != ComponentDegraded {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentDegraded)
	}
}

func TestRPKIValidateDetailedMalformedJSON(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	})
	c := &Client{BaseURL: addr}
	res := c.RPKIValidateDetailed(context.Background(), 13335, "1.1.1.0/24")
	if res.Err == "" {
		t.Fatal("expected Err on malformed JSON")
	}
	if res.Evidence.Status != ComponentDegraded {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentDegraded)
	}
	if !strings.Contains(res.Err, "no interpretable") && res.Err == "" {
		// message text isn't pinned exactly (comes from bgp.go's shared
		// get()), just confirm it's non-empty and reached this branch.
		t.Errorf("Err = %q", res.Err)
	}
}

func TestRPKIValidateDetailedContextCancellation(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
	})
	c := &Client{BaseURL: addr}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res := c.RPKIValidateDetailed(ctx, 13335, "1.1.1.0/24")
	if res.Err == "" {
		t.Fatal("expected Err when context is already cancelled")
	}
	if res.Evidence.Status != ComponentDegraded {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentDegraded)
	}
}
