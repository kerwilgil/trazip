package bgp

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestBGPStateIPv4(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"1.1.1.0/24","timestamp":"2026-08-18T23:59:52","nr_routes":2,"bgp_state":[
			{"target_prefix":"1.1.1.0/24","source_id":"00-1.2.3.4","path":[100,200,13335],"community":["100:1"]},
			{"target_prefix":"1.1.1.0/24","source_id":"00-5.6.7.8","path":[300,13335],"community":[]}
		]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.BGPState(context.Background(), "1.1.1.1")

	if res.Err != "" {
		t.Fatalf("Err = %q, want empty", res.Err)
	}
	if res.Evidence.Status != ComponentOK {
		t.Fatalf("Evidence.Status = %q, want ComponentOK", res.Evidence.Status)
	}
	if res.NrRoutes != 2 || len(res.Routes) != 2 {
		t.Fatalf("NrRoutes=%d len(Routes)=%d, want 2/2", res.NrRoutes, len(res.Routes))
	}
	if res.Routes[0].TargetPrefix != "1.1.1.0/24" {
		t.Errorf("Routes[0].TargetPrefix = %q, want 1.1.1.0/24", res.Routes[0].TargetPrefix)
	}
	want := []int{100, 200, 13335}
	if len(res.Routes[0].Path) != len(want) {
		t.Fatalf("Routes[0].Path = %v, want %v", res.Routes[0].Path, want)
	}
	for i, asn := range want {
		if res.Routes[0].Path[i] != asn {
			t.Errorf("Routes[0].Path[%d] = %d, want %d", i, res.Routes[0].Path[i], asn)
		}
	}
}

func TestBGPStateIPv6(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"2001:db8::/32","timestamp":"2026-08-18T23:59:52","nr_routes":1,"bgp_state":[
			{"target_prefix":"2001:db8::/32","source_id":"00-9.9.9.9","path":[400,500],"community":[]}
		]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.BGPState(context.Background(), "2001:db8::1")

	if res.Err != "" {
		t.Fatalf("Err = %q, want empty", res.Err)
	}
	if res.NrRoutes != 1 || len(res.Routes) != 1 {
		t.Fatalf("NrRoutes=%d len(Routes)=%d, want 1/1", res.NrRoutes, len(res.Routes))
	}
}

func TestBGPStatePrefix(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"10.0.0.0/24","timestamp":"2026-08-18T23:59:52","nr_routes":1,"bgp_state":[
			{"target_prefix":"10.0.0.0/24","source_id":"00-1.1.1.1","path":[600],"community":[]}
		]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.BGPState(context.Background(), "10.0.0.0/24")

	if res.Err != "" {
		t.Fatalf("Err = %q, want empty", res.Err)
	}
	if len(res.Routes) != 1 || len(res.Routes[0].Path) != 1 || res.Routes[0].Path[0] != 600 {
		t.Fatalf("Routes = %+v, want one route with path [600]", res.Routes)
	}
}

func TestBGPStateMultipleRoutes(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"AS100","timestamp":"2026-08-18T23:59:52","nr_routes":3,"bgp_state":[
			{"target_prefix":"10.0.0.0/24","source_id":"00-1.1.1.1","path":[700,100],"community":[]},
			{"target_prefix":"10.0.1.0/24","source_id":"00-2.2.2.2","path":[800,100],"community":[]},
			{"target_prefix":"10.0.2.0/24","source_id":"00-3.3.3.3","path":[900,100],"community":[]}
		]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.BGPState(context.Background(), "AS100")

	if res.NrRoutes != 3 || len(res.Routes) != 3 {
		t.Fatalf("NrRoutes=%d len(Routes)=%d, want 3/3", res.NrRoutes, len(res.Routes))
	}
}

func TestBGPStateInvalidResourceNoHTTP(t *testing.T) {
	var calls int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"status":"ok","data":{"resource":"x","nr_routes":0,"bgp_state":[]}}`))
	})
	c := &Client{BaseURL: addr}
	res := c.BGPState(context.Background(), "not-a-valid-resource!!")

	if calls != 0 {
		t.Fatalf("calls = %d, want 0 — invalid input must never reach the network", calls)
	}
	if res.Evidence.Status != ComponentNotApplicable {
		t.Fatalf("Evidence.Status = %q, want ComponentNotApplicable", res.Evidence.Status)
	}
	if res.Err == "" {
		t.Fatalf("Err = empty, want a message")
	}
}

func TestBGPStateMalformedJSON(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not valid json`))
	})
	c := &Client{BaseURL: addr}
	res := c.BGPState(context.Background(), "AS100")

	if res.Evidence.Status != ComponentDegraded {
		t.Fatalf("Evidence.Status = %q, want ComponentDegraded", res.Evidence.Status)
	}
	if res.Err == "" {
		t.Fatalf("Err = empty, want a message")
	}
}

func TestBGPStateHTTPError(t *testing.T) {
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	c := &Client{BaseURL: addr}
	res := c.BGPState(context.Background(), "AS100")

	if res.Evidence.Status != ComponentDegraded {
		t.Fatalf("Evidence.Status = %q, want ComponentDegraded", res.Evidence.Status)
	}
}

func TestBGPStateCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","data":{"resource":"AS100","nr_routes":0,"bgp_state":[]}}`))
	})
	c := &Client{BaseURL: addr}

	done := make(chan BGPStateResult, 1)
	go func() { done <- c.BGPState(ctx, "AS100") }()

	select {
	case res := <-done:
		if res.Evidence.Status != ComponentDegraded {
			t.Fatalf("Evidence.Status = %q, want ComponentDegraded (context already cancelled)", res.Evidence.Status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("BGPState did not return after context cancellation")
	}
}

func TestBGPStateCacheLifecycle(t *testing.T) {
	var calls int
	addr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"status":"ok","data":{"resource":"AS100","nr_routes":0,"bgp_state":[]}}`))
	})
	c := &Client{BaseURL: addr}
	c.BGPState(context.Background(), "AS100")
	res2 := c.BGPState(context.Background(), "AS100")

	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (second call must hit cache)", calls)
	}
	if !res2.Evidence.FromCache {
		t.Fatalf("second call: FromCache = false, want true")
	}
}
