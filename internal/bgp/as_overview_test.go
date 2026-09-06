package bgp

import (
	"context"
	"net/http"
	"testing"
)

func TestASOverviewAnnouncedTrue(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"3333","announced":true,"holder":"RIPE NCC","type":"as"}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.ASOverview(context.Background(), 3333)

	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if !res.Announced {
		t.Error("expected Announced=true")
	}
	if res.Holder != "RIPE NCC" {
		t.Errorf("Holder = %q, want %q", res.Holder, "RIPE NCC")
	}
	if res.Evidence.Status != ComponentOK {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentOK)
	}
}

func TestASOverviewAnnouncedFalseIsNotAnError(t *testing.T) {
	// A transit-only ASN legitimately never originates a prefix.
	// Announced=false must never be treated as a failure/degraded state.
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"64500","announced":false,"holder":"Example Transit ASN","type":"as"}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.ASOverview(context.Background(), 64500)

	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if res.Announced {
		t.Error("expected Announced=false")
	}
	if res.Evidence.Status != ComponentOK {
		t.Errorf("Evidence.Status = %s, want %s — announced=false is a valid result, not a failure", res.Evidence.Status, ComponentOK)
	}
}

func TestASOverviewHolderNull(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"64501","announced":false,"holder":null,"type":"as"}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.ASOverview(context.Background(), 64501)

	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if res.Holder != "" {
		t.Errorf("Holder = %q, want empty (never fabricated)", res.Holder)
	}
	if res.Evidence.Status != ComponentOK {
		t.Errorf("Evidence.Status = %s, want %s — a null optional field must not make the whole call unavailable", res.Evidence.Status, ComponentOK)
	}
}

func TestASOverviewInvalidASNNoHTTPCall(t *testing.T) {
	cases := []int{0, -1, maxASN + 1}
	for _, asn := range cases {
		var requests int
		addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
			requests++
			w.Write([]byte(`{"status":"ok","data":{"resource":"1","announced":true}}`))
		})
		c := &Client{BaseURL: addr}
		res := c.ASOverview(context.Background(), asn)

		if res.Err == "" {
			t.Errorf("asn=%d: expected Err", asn)
		}
		if res.Evidence.Status != ComponentNotApplicable {
			t.Errorf("asn=%d: Evidence.Status = %s, want %s", asn, res.Evidence.Status, ComponentNotApplicable)
		}
		if requests != 0 {
			t.Errorf("asn=%d: requests = %d, want 0", asn, requests)
		}
	}
}

func TestASOverviewDatasourceError(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := &Client{BaseURL: addr}
	res := c.ASOverview(context.Background(), 3333)
	if res.Err == "" {
		t.Fatal("expected Err on HTTP failure")
	}
	if res.Evidence.Status != ComponentDegraded {
		t.Errorf("Evidence.Status = %s, want %s", res.Evidence.Status, ComponentDegraded)
	}
}
