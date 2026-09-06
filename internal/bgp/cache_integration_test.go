package bgp

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestRoutingStatusDetailedQueryCacheLifecycle(t *testing.T) {
	var requests int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(`{"status":"ok","data":{"resource":"AS3333","origins":[{"origin":3333,"route_objects":["A"]}]}}`))
	})
	c := &Client{BaseURL: addr}

	// Force cache init and inject a deterministic clock BEFORE any fetch,
	// so the first entry's expiresAt is computed against the fake clock,
	// not real time.
	clk := newFakeClock()
	c.getCache().now = clk.Now

	// First call: live.
	res1 := c.RoutingStatusDetailedQuery(context.Background(), "AS3333")
	if res1.Err != "" {
		t.Fatalf("unexpected error: %s", res1.Err)
	}
	if res1.Evidence.FromCache {
		t.Error("first call: FromCache = true, want false (live)")
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
	firstQueriedAt := res1.Evidence.Disclosure.QueriedAt

	// Second call, within TTL (routingStatusTTL = 2min): must be a cache
	// hit — no new request, FromCache=true, QueriedAt preserved from the
	// original live call (never "now").
	clk.Advance(90 * time.Second)
	res2 := c.RoutingStatusDetailedQuery(context.Background(), "AS3333")
	if requests != 1 {
		t.Fatalf("requests = %d after second call within TTL, want still 1 (cache hit)", requests)
	}
	if !res2.Evidence.FromCache {
		t.Error("second call within TTL: FromCache = false, want true")
	}
	if res2.Evidence.Disclosure.QueriedAt != firstQueriedAt {
		t.Errorf("QueriedAt changed on cache hit: got %q, want preserved %q", res2.Evidence.Disclosure.QueriedAt, firstQueriedAt)
	}

	// Advance past the TTL: must go live again.
	clk.Advance(2 * time.Minute)
	res3 := c.RoutingStatusDetailedQuery(context.Background(), "AS3333")
	if requests != 2 {
		t.Fatalf("requests = %d after TTL expiry, want 2 (live again)", requests)
	}
	if res3.Evidence.FromCache {
		t.Error("call after TTL expiry: FromCache = true, want false")
	}
}

func TestCacheKeysDoNotCollideAcrossDifferentResources(t *testing.T) {
	var requests []string
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Query().Get("resource"))
		w.Write([]byte(`{"status":"ok","data":{"resource":"` + r.URL.Query().Get("resource") + `","origins":[]}}`))
	})
	c := &Client{BaseURL: addr}

	c.RoutingStatusDetailedQuery(context.Background(), "AS3333")
	c.RoutingStatusDetailedQuery(context.Background(), "AS6667")
	c.RoutingStatusDetailedQuery(context.Background(), "AS3333") // repeat — should hit cache, not add a 3rd request

	if len(requests) != 2 {
		t.Fatalf("requests = %+v, want exactly 2 distinct live requests (AS3333, AS6667), no collision and no unnecessary repeat", requests)
	}
}

func TestCacheKeysDoNotCollideAcrossDifferentRPKIPairs(t *testing.T) {
	var requests int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`))
	})
	c := &Client{BaseURL: addr}

	c.RPKIValidateDetailed(context.Background(), 13335, "1.1.1.0/24")
	c.RPKIValidateDetailed(context.Background(), 20940, "1.1.1.0/24") // same prefix, different ASN
	c.RPKIValidateDetailed(context.Background(), 13335, "2.2.2.0/24") // same ASN, different prefix
	c.RPKIValidateDetailed(context.Background(), 13335, "1.1.1.0/24") // repeat of the first — cache hit

	if requests != 3 {
		t.Fatalf("requests = %d, want exactly 3 (three distinct ASN+prefix pairs, fourth call is a cache hit)", requests)
	}
}

func TestCacheDoesNotStoreDegradedResponses(t *testing.T) {
	var requests int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := &Client{BaseURL: addr}

	c.RoutingStatusDetailedQuery(context.Background(), "AS3333")
	c.RoutingStatusDetailedQuery(context.Background(), "AS3333")

	if requests != 2 {
		t.Fatalf("requests = %d, want 2 — a degraded (failed) response must never be cached, so both calls must go live", requests)
	}
}

func TestCacheDoesNotStoreRejectedInput(t *testing.T) {
	var requests int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(`{"status":"ok","data":{"resource":"1","announced":true}}`))
	})
	c := &Client{BaseURL: addr}

	c.ASOverview(context.Background(), 0)
	c.ASOverview(context.Background(), 0)

	if requests != 0 {
		t.Fatalf("requests = %d, want 0 — rejected input is never cached and never reaches the network regardless of repetition", requests)
	}
}

func TestAsnNeighboursCacheLifecycle(t *testing.T) {
	var requests int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(`{"status":"ok","data":{"resource":"3333","neighbours":[]}}`))
	})
	c := &Client{BaseURL: addr}
	c.AsnNeighboursRaw(context.Background(), 3333)
	c.AsnNeighboursRaw(context.Background(), 3333)
	if requests != 1 {
		t.Fatalf("requests = %d, want 1 (second call should hit cache)", requests)
	}
}

func TestAnnouncedPrefixesCacheLifecycle(t *testing.T) {
	var requests int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(`{"status":"ok","data":{"resource":"3333","prefixes":[]}}`))
	})
	c := &Client{BaseURL: addr}
	c.AnnouncedPrefixesRaw(context.Background(), 3333)
	c.AnnouncedPrefixesRaw(context.Background(), 3333)
	if requests != 1 {
		t.Fatalf("requests = %d, want 1 (second call should hit cache)", requests)
	}
}

func TestASOverviewCacheLifecycle(t *testing.T) {
	var requests int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Write([]byte(`{"status":"ok","data":{"resource":"3333","announced":true}}`))
	})
	c := &Client{BaseURL: addr}
	c.ASOverview(context.Background(), 3333)
	c.ASOverview(context.Background(), 3333)
	if requests != 1 {
		t.Fatalf("requests = %d, want 1 (second call should hit cache)", requests)
	}
}

func TestNilClientCacheIsSafe(t *testing.T) {
	// A bare &Client{BaseURL: addr}, exactly as existing tests/consumers
	// build it, must work correctly with no explicit cache setup.
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"AS3333","origins":[]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.RoutingStatusDetailedQuery(context.Background(), "AS3333")
	if res.Err != "" {
		t.Fatalf("unexpected error on zero-value-cache Client: %s", res.Err)
	}
}
