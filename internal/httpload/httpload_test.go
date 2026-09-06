package httpload

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunAgainstLocalServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Params{URL: srv.URL, Concurrency: 4, DurationMs: 400}, nil)
	if err != nil {
		t.Fatalf("Run: %v (%s)", err, res.Err)
	}
	if res.TotalRequests == 0 {
		t.Fatal("expected at least one request to complete")
	}
	if res.ErrorRatePct != 0 {
		t.Errorf("ErrorRatePct = %f, want 0 (server always returns 200)", res.ErrorRatePct)
	}
	if res.StatusCounts[200] != int(res.TotalRequests) {
		t.Errorf("StatusCounts[200] = %d, want %d (all requests)", res.StatusCounts[200], res.TotalRequests)
	}
	if res.AvgRPS <= 0 {
		t.Errorf("AvgRPS = %f, want positive", res.AvgRPS)
	}
}

func TestRunReportsErrorStatuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Params{URL: srv.URL, Concurrency: 2, DurationMs: 300}, nil)
	if err != nil {
		t.Fatalf("Run: %v (%s)", err, res.Err)
	}
	if res.ErrorRatePct != 100 {
		t.Errorf("ErrorRatePct = %f, want 100 (server always 500s)", res.ErrorRatePct)
	}
	if res.StatusCounts[500] != int(res.TotalRequests) {
		t.Errorf("StatusCounts[500] = %d, want %d", res.StatusCounts[500], res.TotalRequests)
	}
}

func TestRunReportsTransportErrors(t *testing.T) {
	// Nothing listening — every request should fail at the transport level,
	// counted as an error with no status code.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	res, err := Run(context.Background(), Params{URL: "http://" + addr + "/", Concurrency: 2, DurationMs: 300}, nil)
	if err != nil {
		t.Fatalf("Run: %v (%s)", err, res.Err)
	}
	if res.TotalRequests == 0 {
		t.Fatal("expected failed attempts to still be counted")
	}
	if res.ErrorRatePct != 100 {
		t.Errorf("ErrorRatePct = %f, want 100 (connection refused)", res.ErrorRatePct)
	}
	if len(res.StatusCounts) != 0 {
		t.Errorf("StatusCounts = %+v, want empty (no responses received)", res.StatusCounts)
	}
}

func TestRunHonorsConcurrency(t *testing.T) {
	var inFlight, maxInFlight int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			old := atomic.LoadInt32(&maxInFlight)
			if n <= old || atomic.CompareAndSwapInt32(&maxInFlight, old, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := Run(context.Background(), Params{URL: srv.URL, Concurrency: 8, DurationMs: 300}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if atomic.LoadInt32(&maxInFlight) < 2 {
		t.Errorf("maxInFlight = %d, want concurrent requests to overlap (>=2)", maxInFlight)
	}
}

func TestRunStreamsProgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var ticks int32
	_, err := Run(context.Background(), Params{URL: srv.URL, Concurrency: 4, DurationMs: 1200}, func(ProgressTick) {
		atomic.AddInt32(&ticks, 1)
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if atomic.LoadInt32(&ticks) < 2 {
		t.Errorf("ticks = %d, want at least 2 progress callbacks over 1.2s (tickInterval=500ms) plus the final one", ticks)
	}
}

func TestRunHonorsCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	started := time.Now()
	_, err := Run(ctx, Params{URL: srv.URL, Concurrency: 4, DurationMs: 5000}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("cancelación tardó demasiado: %v", elapsed)
	}
}

func TestValidateRejectsBadParams(t *testing.T) {
	// Concurrency is not checked here: withDefaults() always clamps it into
	// range first (same precedent as throughput.Params.Streams), so it can
	// never reach validate() out of bounds.
	cases := []Params{
		{URL: ""},
		{URL: "not-a-url"},
		{URL: "ftp://example.com"},
		{URL: "http://example.com", DurationMs: maxDurationMs + 1},
		{URL: "http://example.com", TargetRPS: -1},
	}
	for _, p := range cases {
		p.withDefaults()
		if err := p.validate(); err == nil {
			t.Errorf("validate(%+v) = nil, want an error", p)
		}
	}
}

func TestWithDefaultsCapsConcurrency(t *testing.T) {
	p := Params{URL: "http://example.com", Concurrency: maxConcurrency + 50}
	p.withDefaults()
	if p.Concurrency != maxConcurrency {
		t.Errorf("Concurrency = %d, want capped at %d", p.Concurrency, maxConcurrency)
	}
}

func TestPercentileMonotonic(t *testing.T) {
	sorted := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	p50 := percentile(sorted, 50)
	p95 := percentile(sorted, 95)
	if p95 < p50 {
		t.Errorf("p95 (%f) should be >= p50 (%f)", p95, p50)
	}
	if percentile(nil, 50) != 0 {
		t.Error("percentile of an empty slice should be 0, not panic")
	}
}

func TestAggregatorLatencyMemoryIsBounded(t *testing.T) {
	a := newAggregator()
	for i := 0; i < 1_000_000; i++ {
		a.record(outcome{latencyMs: float64(i % 1000), status: 200})
	}
	if a.total != 1_000_000 {
		t.Fatalf("total = %d, want 1000000", a.total)
	}
	if len(a.latencies) != maxLatencySamples {
		t.Fatalf("latency samples = %d, want bounded at %d", len(a.latencies), maxLatencySamples)
	}
	if got := a.tick(time.Second); got.Requests != 1_000_000 || got.P95LatencyMs <= 0 {
		t.Fatalf("bounded snapshot lost aggregate data: %+v", got)
	}
}
