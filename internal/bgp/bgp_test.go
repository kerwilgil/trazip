package bgp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoutingStatusHermetic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "routing-status") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("resource") != "1.1.1.0/24" {
			t.Errorf("resource param = %q, want 1.1.1.0/24", r.URL.Query().Get("resource"))
		}
		w.Write([]byte(`{"status":"ok","data":{"origins":[{"origin":13335,"route_objects":["APNIC","RADB"]}]}}`))
	}))
	defer srv.Close()

	c := &Client{HTTPClient: srv.Client(), BaseURL: srv.URL}
	res := c.RoutingStatus(context.Background(), "1.1.1.0/24")
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if !res.Announced {
		t.Error("expected Announced=true")
	}
	if len(res.Origins) != 1 || res.Origins[0] != 13335 {
		t.Errorf("Origins = %v, want [13335]", res.Origins)
	}
	if res.Disclosure.Source == "" {
		t.Error("Disclosure should be populated")
	}
}

// TestRoutingStatusPopulatesPrefixField pins down Phase B.1's RPKI
// regression guard: RouteStatus.Prefix must carry RIPEstat's own resolved
// covering prefix (the top-level "resource" field, e.g. "1.1.1.0/24" for a
// query of "1.1.1.1") — the value diagnosis.runRoutingSecurity now uses for
// RPKIValidate instead of ever synthesizing a /32.
func TestRoutingStatusPopulatesPrefixField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":13335,"route_objects":["APNIC","RADB"]}]}}`))
	}))
	defer srv.Close()

	c := &Client{HTTPClient: srv.Client(), BaseURL: srv.URL}
	res := c.RoutingStatus(context.Background(), "1.1.1.1")
	if res.Prefix != "1.1.1.0/24" {
		t.Errorf("Prefix = %q, want the real covering prefix 1.1.1.0/24 (queried resource was a bare /32 IP)", res.Prefix)
	}
}

func TestRoutingStatusNotAnnounced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"origins":[]}}`))
	}))
	defer srv.Close()

	c := &Client{HTTPClient: srv.Client(), BaseURL: srv.URL}
	res := c.RoutingStatus(context.Background(), "192.0.2.0/24")
	if res.Announced {
		t.Error("expected Announced=false")
	}
	if len(res.Origins) != 0 {
		t.Errorf("Origins = %v, want none", res.Origins)
	}
}

func TestRPKIValidateHermetic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resource") != "13335" || r.URL.Query().Get("prefix") != "1.1.1.0/24" {
			t.Errorf("params = %v", r.URL.Query())
		}
		w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[{"origin":"13335","prefix":"1.1.1.0/24","validity":"valid","max_length":24}]}}`))
	}))
	defer srv.Close()

	c := &Client{HTTPClient: srv.Client(), BaseURL: srv.URL}
	res := c.RPKIValidate(context.Background(), 13335, "1.1.1.0/24")
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if res.Status != "valid" {
		t.Errorf("Status = %q, want valid", res.Status)
	}
	if !strings.Contains(res.Reason, "origin=13335") || !strings.Contains(res.Reason, "validity=valid") {
		t.Errorf("Reason = %q, want it to summarize the matched ROA", res.Reason)
	}
}

func TestRPKIValidateInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"status":"invalid","validating_roas":[{"origin":"13335","prefix":"1.1.1.0/24","validity":"invalid_asn","max_length":24}]}}`))
	}))
	defer srv.Close()

	c := &Client{HTTPClient: srv.Client(), BaseURL: srv.URL}
	res := c.RPKIValidate(context.Background(), 64500, "203.0.113.0/24")
	if res.Status != "invalid" {
		t.Errorf("Status = %q, want invalid", res.Status)
	}
}

func TestRPKIValidateBadInput(t *testing.T) {
	c := NewClient()
	res := c.RPKIValidate(context.Background(), 0, "")
	if res.Err == "" {
		t.Error("expected an error for empty prefix/ASN")
	}
}

func TestRoutingStatusRIPEstatError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"error","data":{}}`))
	}))
	defer srv.Close()

	c := &Client{HTTPClient: srv.Client(), BaseURL: srv.URL}
	res := c.RoutingStatus(context.Background(), "1.1.1.0/24")
	if res.Err == "" {
		t.Error("expected an error when RIPEstat status != ok")
	}
}

func TestRoutingStatusEmptyResource(t *testing.T) {
	c := NewClient()
	res := c.RoutingStatus(context.Background(), "")
	if res.Err == "" {
		t.Error("expected an error for an empty resource")
	}
}

func TestNormalizeRPKIStatusBucketsInvalidVariants(t *testing.T) {
	// RIPEstat distinguishes invalid_asn (wrong origin) from
	// invalid_length (prefix more specific than the ROA's max_length) —
	// both must still bucket to the spec's plain "invalid" (§22).
	cases := map[string]string{
		"valid":          "valid",
		"invalid_asn":    "invalid",
		"invalid_length": "invalid",
		"unknown":        "unknown",
		"":               "unknown",
	}
	for in, want := range cases {
		if got := normalizeRPKIStatus(in); got != want {
			t.Errorf("normalizeRPKIStatus(%q) = %q, want %q", in, got, want)
		}
	}
}
