// Package httpload implements TRAZIP's own concurrent HTTP load test — "Prueba
// de carga HTTP". It is deliberately its own small tool, not a port or
// reimplementation of Apache JMeter (a registered trademark): no .jmx test
// plans, no Thread Groups, no samplers — just N goroutines hammering one URL
// for a bounded duration, with live progress (RPS, latency percentiles,
// error rate) streamed back while it runs, closing the same "watch it
// saturate in real time" gap Throughput has for raw TCP/UDP but this covers
// at the HTTP/application layer instead.
//
// Like Throughput, this is diagnostic tooling for a system the operator is
// authorized to test — not a stress/DoS tool: concurrency and duration are
// hard-capped (maxConcurrency, maxDurationMs) regardless of what the caller
// requests.
package httpload

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxConcurrency    = 100
	minDurationMs     = 100
	maxDurationMs     = 5 * 60 * 1000
	tickInterval      = 500 * time.Millisecond
	maxLatencySamples = 65536
)

// Params are the negotiated load-test parameters.
type Params struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Concurrency int               `json:"concurrency"`
	DurationMs  int               `json:"durationMs"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	TargetRPS   float64           `json:"targetRps,omitempty"` // 0 = unthrottled
}

func (p *Params) withDefaults() {
	if p.Method == "" {
		p.Method = "GET"
	}
	p.Method = strings.ToUpper(p.Method)
	if p.Concurrency <= 0 {
		p.Concurrency = 1
	}
	if p.Concurrency > maxConcurrency {
		p.Concurrency = maxConcurrency
	}
	if p.DurationMs <= 0 {
		p.DurationMs = 10000
	}
}

func (p Params) validate() error {
	if strings.TrimSpace(p.URL) == "" {
		return fmt.Errorf("URL requerida")
	}
	u, err := url.Parse(p.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("URL inválida: %q", p.URL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("esquema no soportado: %q (usa http o https)", u.Scheme)
	}
	if p.DurationMs < minDurationMs || p.DurationMs > maxDurationMs {
		return fmt.Errorf("duración fuera de rango (%d..%d ms)", minDurationMs, maxDurationMs)
	}
	if p.TargetRPS < 0 {
		return fmt.Errorf("RPS objetivo no puede ser negativo")
	}
	return nil
}

// ProgressTick is a periodic snapshot streamed while a load test runs.
type ProgressTick struct {
	ElapsedMs      int64       `json:"elapsedMs"`
	Requests       int64       `json:"requests"`
	RPS            float64     `json:"rps"`
	AvgLatencyMs   float64     `json:"avgLatencyMs"`
	P95LatencyMs   float64     `json:"p95LatencyMs"`
	ErrorRatePct   float64     `json:"errorRatePct"`
	ThroughputMbps float64     `json:"throughputMbps"` // rendimiento de descarga de los cuerpos de respuesta
	StatusCounts   map[int]int `json:"statusCounts,omitempty"`
}

// Result is the full, reproducible outcome of a load test.
type Result struct {
	Params         Params      `json:"params"`
	TotalRequests  int64       `json:"totalRequests"`
	DurationSec    float64     `json:"durationSec"`
	AvgRPS         float64     `json:"avgRps"`
	P50LatencyMs   float64     `json:"p50LatencyMs"`
	P90LatencyMs   float64     `json:"p90LatencyMs"`
	P95LatencyMs   float64     `json:"p95LatencyMs"`
	P99LatencyMs   float64     `json:"p99LatencyMs"`
	ErrorRatePct   float64     `json:"errorRatePct"`
	TotalBytes     int64       `json:"totalBytes"`     // suma de cuerpos de respuesta leídos
	AvgBytesPerReq float64     `json:"avgBytesPerReq"` // tamaño medio de respuesta
	ThroughputMbps float64     `json:"throughputMbps"` // Mbit/s de descarga agregada
	StatusCounts   map[int]int `json:"statusCounts,omitempty"`
	Err            string      `json:"err,omitempty"`
}

// outcome is one completed request, recorded by a worker.
type outcome struct {
	latencyMs float64
	status    int   // 0 = transport error (no response received)
	bytes     int64 // response body bytes actually read (0 on transport error)
}

// aggregator collects outcomes from every worker under a single mutex — the
// request rate here (at most a few hundred/sec) never makes lock contention
// a bottleneck, so a plain mutex is simpler and just as correct as a
// lock-free structure would be.
type aggregator struct {
	mu           sync.Mutex
	latencies    []float64
	statusCounts map[int]int
	errors       int64
	total        int64
	bytes        int64
}

func newAggregator() *aggregator {
	return &aggregator{statusCounts: map[int]int{}}
}

func (a *aggregator) record(o outcome) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.total++
	a.bytes += o.bytes
	if len(a.latencies) < maxLatencySamples {
		a.latencies = append(a.latencies, o.latencyMs)
	} else {
		// Deterministic reservoir sampling keeps percentile memory and snapshot
		// sorting bounded while still sampling the full duration of a fast run.
		j := splitmix64(uint64(a.total)) % uint64(a.total)
		if j < maxLatencySamples {
			a.latencies[j] = o.latencyMs
		}
	}
	if o.status == 0 || o.status >= 400 {
		a.errors++
	}
	if o.status != 0 {
		a.statusCounts[o.status]++
	}
}

func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

func (a *aggregator) snapshot() (sortedLatencies []float64, statusCounts map[int]int, total, errs, bytes int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sortedLatencies = append([]float64(nil), a.latencies...)
	sort.Float64s(sortedLatencies)
	statusCounts = make(map[int]int, len(a.statusCounts))
	for k, v := range a.statusCounts {
		statusCounts[k] = v
	}
	return sortedLatencies, statusCounts, a.total, a.errors, a.bytes
}

func (a *aggregator) tick(elapsed time.Duration) ProgressTick {
	sorted, statusCounts, total, errs, bytes := a.snapshot()
	t := ProgressTick{ElapsedMs: elapsed.Milliseconds(), Requests: total, StatusCounts: statusCounts}
	if elapsed > 0 {
		t.RPS = round2(float64(total) / elapsed.Seconds())
		t.ThroughputMbps = round2(float64(bytes) * 8 / 1e6 / elapsed.Seconds())
	}
	if total > 0 {
		t.ErrorRatePct = round2(float64(errs) / float64(total) * 100)
	}
	t.AvgLatencyMs = round2(avg(sorted))
	t.P95LatencyMs = round2(percentile(sorted, 95))
	return t
}

func (a *aggregator) result(p Params, elapsed time.Duration) Result {
	sorted, statusCounts, total, errs, bytes := a.snapshot()
	res := Result{Params: p, TotalRequests: total, DurationSec: round2(elapsed.Seconds()), StatusCounts: statusCounts, TotalBytes: bytes}
	if elapsed > 0 {
		res.AvgRPS = round2(float64(total) / elapsed.Seconds())
		res.ThroughputMbps = round2(float64(bytes) * 8 / 1e6 / elapsed.Seconds())
	}
	if total > 0 {
		res.ErrorRatePct = round2(float64(errs) / float64(total) * 100)
		res.AvgBytesPerReq = round2(float64(bytes) / float64(total))
	}
	res.P50LatencyMs = round2(percentile(sorted, 50))
	res.P90LatencyMs = round2(percentile(sorted, 90))
	res.P95LatencyMs = round2(percentile(sorted, 95))
	res.P99LatencyMs = round2(percentile(sorted, 99))
	return res
}

// Run fires Concurrency workers at Params.URL for DurationMs, invoking
// onProgress roughly every tickInterval with a running snapshot. It returns
// the final Result once every worker has stopped (duration elapsed or ctx
// cancelled — cancellation is not reported as an error, mirroring
// throughput.Run and ping.Run).
func Run(ctx context.Context, p Params, onProgress func(ProgressTick)) (Result, error) {
	p.withDefaults()
	if err := p.validate(); err != nil {
		return Result{Params: p, Err: err.Error()}, err
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        p.Concurrency * 2,
			MaxIdleConnsPerHost: p.Concurrency,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	agg := newAggregator()
	start := time.Now()
	stopAt := start.Add(time.Duration(p.DurationMs) * time.Millisecond)

	var interval time.Duration
	if p.TargetRPS > 0 {
		perWorker := p.TargetRPS / float64(p.Concurrency)
		if perWorker > 0 {
			interval = time.Duration(float64(time.Second) / perWorker)
		}
	}

	tickerDone := make(chan struct{})
	if onProgress != nil {
		go func() {
			ticker := time.NewTicker(tickInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					onProgress(agg.tick(time.Since(start)))
				case <-tickerDone:
					return
				}
			}
		}()
	}

	var wg sync.WaitGroup
	for i := 0; i < p.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(ctx, client, p, agg, stopAt, interval)
		}()
	}
	wg.Wait()
	close(tickerDone)

	elapsed := time.Since(start)
	res := agg.result(p, elapsed)
	if onProgress != nil {
		onProgress(agg.tick(elapsed))
	}
	return res, nil
}

func worker(ctx context.Context, client *http.Client, p Params, agg *aggregator, stopAt time.Time, interval time.Duration) {
	next := time.Now()
	for {
		if ctx.Err() != nil || time.Now().After(stopAt) {
			return
		}
		var bodyReader io.Reader
		if p.Body != "" {
			bodyReader = strings.NewReader(p.Body)
		}
		req, err := http.NewRequestWithContext(ctx, p.Method, p.URL, bodyReader)
		if err != nil {
			return // malformed request/URL won't succeed on retry either
		}
		for k, v := range p.Headers {
			req.Header.Set(k, v)
		}

		reqStart := time.Now()
		resp, doErr := client.Do(req)
		latencyMs := float64(time.Since(reqStart)) / float64(time.Millisecond)
		if doErr != nil {
			agg.record(outcome{latencyMs: latencyMs, status: 0})
		} else {
			// Read the whole body so the measured latency reflects the full
			// response transfer (not just time-to-first-byte) and so bytes
			// downloaded can be reported — this is a real download of each
			// response, just not persisted anywhere.
			n, _ := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			agg.record(outcome{latencyMs: latencyMs, status: resp.StatusCode, bytes: n})
		}

		if interval > 0 {
			next = next.Add(interval)
			if d := time.Until(next); d > 0 {
				select {
				case <-time.After(d):
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p / 100)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func avg(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var sum float64
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}

func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}
