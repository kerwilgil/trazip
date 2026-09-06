// Package portscan implements TRAZIP's own TCP connect scanner (prompt maestro
// §9 Fase 2 #12). It is unprivileged (full TCP connect), rate/concurrency limited
// and cancellable. SYN/UDP scans that need privileges are layered later. It never
// shells out to nmap/naabu.
package portscan

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"trazip/internal/probe/ping"
)

// State is the observed state of a port.
type State string

const (
	Open     State = "open"
	Closed   State = "closed"
	Filtered State = "filtered" // no response before timeout
)

// Config parameterizes a scan.
type Config struct {
	Target      string
	Ports       []int
	Concurrency int
	Timeout     time.Duration
	Family      string
	RatePerSec  int
}

func (c *Config) withDefaults() {
	if c.Concurrency <= 0 || c.Concurrency > 512 {
		c.Concurrency = 128
	}
	if c.Timeout <= 0 {
		c.Timeout = 1500 * time.Millisecond
	}
	if c.RatePerSec <= 0 || c.RatePerSec > 10000 {
		c.RatePerSec = 250
	}
	if len(c.Ports) == 0 {
		c.Ports = Top100()
	}
}

// PortResult is the outcome for a single port.
type PortResult struct {
	Port    int     `json:"port"`
	State   string  `json:"state"`
	Service string  `json:"service,omitempty"`
	RTTms   float64 `json:"rttMs,omitempty"`
}

// Summary is returned at the end of a scan.
type Summary struct {
	Target      string  `json:"target"`
	Scanned     int     `json:"scanned"`
	OpenN       int     `json:"open"`
	ClosedN     int     `json:"closed"`
	FilterN     int     `json:"filtered"`
	Duration    float64 `json:"durationSec"`
	RatePerSec  int     `json:"ratePerSec"`
	ActualRate  float64 `json:"actualRate"`
	Concurrency int     `json:"concurrency"`
	TimeoutMs   int64   `json:"timeoutMs"`
	Cancelled   bool    `json:"cancelled"`
}

// Run performs a TCP connect scan, invoking onResult per port (in completion
// order). It returns a summary and the resolved address.
func Run(ctx context.Context, cfg Config, onResult func(PortResult)) (Summary, netip.Addr, error) {
	cfg.withDefaults()
	addr, err := ping.Resolve(ctx, cfg.Target, cfg.Family)
	if err != nil {
		return Summary{}, netip.Addr{}, err
	}
	host := addr.String()
	start := time.Now()

	ports := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	sum := Summary{
		Target: host, RatePerSec: cfg.RatePerSec, Concurrency: cfg.Concurrency,
		TimeoutMs: cfg.Timeout.Milliseconds(),
	}

	dialer := net.Dialer{Timeout: cfg.Timeout}

	worker := func() {
		defer wg.Done()
		for port := range ports {
			if ctx.Err() != nil {
				return
			}
			t0 := time.Now()
			addrPort := net.JoinHostPort(host, strconv.Itoa(port))
			conn, derr := dialer.DialContext(ctx, "tcp", addrPort)
			res := PortResult{Port: port, Service: ServiceName(port)}
			if derr == nil {
				res.State = string(Open)
				res.RTTms = float64(time.Since(t0)) / float64(time.Millisecond)
				res.RTTms = float64(int64(res.RTTms*100)) / 100
				conn.Close()
			} else {
				res.State = string(classifyDialError(derr))
			}

			mu.Lock()
			sum.Scanned++
			switch State(res.State) {
			case Open:
				sum.OpenN++
			case Closed:
				sum.ClosedN++
			default:
				sum.FilterN++
			}
			mu.Unlock()

			if onResult != nil {
				onResult(res)
			}
		}
	}

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go worker()
	}
	interval := time.Second / time.Duration(cfg.RatePerSec)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
dispatch:
	for _, p := range cfg.Ports {
		select {
		case <-ctx.Done():
			break dispatch
		case <-ticker.C:
		}
		select {
		case <-ctx.Done():
			break dispatch
		case ports <- p:
		}
	}
	close(ports)
	wg.Wait()

	sum.Duration = time.Since(start).Seconds()
	if sum.Duration > 0 {
		sum.ActualRate = float64(sum.Scanned) / sum.Duration
		sum.ActualRate = float64(int64(sum.ActualRate*100)) / 100
	}
	sum.Cancelled = ctx.Err() != nil
	return sum, addr, nil
}

func classifyDialError(err error) State {
	if isConnectionRefused(err) {
		return Closed
	}
	return Filtered
}
