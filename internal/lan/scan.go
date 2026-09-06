// Active LAN discovery (prompt maestro §9 Fase 2 #11, extended per user
// request beyond the original passive ARP/NDP read in lan.go). Unlike
// Discover(), Scan() actively probes a CIDR or IP range: ICMP echo per
// address to find what's alive, then per responsive host a Top100 TCP
// connect scan, reverse DNS, MAC/vendor (from the same ARP table Discover()
// already reads — ICMP replies populate it, so no extra privilege is
// needed), and a TTL-based OS guess. It builds entirely on ping/portscan
// engines that already exist elsewhere in TRAZIP — no new probing primitive,
// no raw sockets, no elevation requirement beyond what those already have.
package lan

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"trazip/internal/probe/ping"
	"trazip/internal/probe/portscan"
)

// maxScanHosts caps a single Scan() call so a typo like "10.0.0.0/8"
// doesn't silently try to probe 16 million addresses — the caller gets a
// clear error asking for a smaller range instead.
const maxScanHosts = 4096

const (
	pingWorkers    = 48
	enrichWorkers  = 12
	pingTimeout    = 700 * time.Millisecond
	arpSettleDelay = 300 * time.Millisecond
)

// HostResult is one actively-probed host.
type HostResult struct {
	IP        string                `json:"ip"`
	Up        bool                  `json:"up"`
	Hostname  string                `json:"hostname,omitempty"`
	MAC       string                `json:"mac,omitempty"`
	Vendor    string                `json:"vendor,omitempty"`
	RTTms     float64               `json:"rttMs,omitempty"`
	OpenPorts []portscan.PortResult `json:"openPorts,omitempty"`
	OSGuess   string                `json:"osGuess,omitempty"`
	Iface     string                `json:"iface,omitempty"`
}

// ScanSummary is returned once a Scan() run finishes (or is cancelled).
type ScanSummary struct {
	Range       string  `json:"range"`
	TotalIPs    int     `json:"totalIPs"`
	Scanned     int     `json:"scanned"`
	UpCount     int     `json:"upCount"`
	DurationSec float64 `json:"durationSec"`
}

// ParseTargets expands a CIDR ("192.168.1.0/24"), a dash range
// ("192.168.1.1-192.168.1.254" or the short form "192.168.1.1-254"), or a
// single address into the concrete IPv4 addresses to probe.
func ParseTargets(spec string) ([]netip.Addr, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("rango vacío")
	}
	if strings.Contains(spec, "/") {
		return expandCIDR(spec)
	}
	if strings.Contains(spec, "-") {
		return expandRange(spec)
	}
	a, err := netip.ParseAddr(spec)
	if err != nil {
		return nil, fmt.Errorf("no se pudo interpretar %q como CIDR, rango o IP: %w", spec, err)
	}
	return []netip.Addr{a}, nil
}

func expandCIDR(spec string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(spec)
	if err != nil {
		return nil, fmt.Errorf("CIDR inválido %q: %w", spec, err)
	}
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("por ahora Scan() solo soporta IPv4")
	}
	base := prefix.Masked().Addr()
	bits := prefix.Bits()
	count := 1 << uint(32-bits)
	if count > maxScanHosts {
		return nil, fmt.Errorf("el rango tiene %d direcciones — el máximo por corrida es %d, usá un prefijo más chico (ej. /20 o menor)", count, maxScanHosts)
	}
	out := make([]netip.Addr, 0, count)
	addr := base
	for i := 0; i < count; i++ {
		// Skip network/broadcast addresses when the mask actually has them.
		if count > 2 && (i == 0 || i == count-1) {
			addr = nextAddr(addr)
			continue
		}
		out = append(out, addr)
		addr = nextAddr(addr)
	}
	return out, nil
}

func expandRange(spec string) ([]netip.Addr, error) {
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("rango inválido %q — formato esperado a.b.c.d-a.b.c.d", spec)
	}
	startStr, endStr := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	start, err := netip.ParseAddr(startStr)
	if err != nil || !start.Is4() {
		return nil, fmt.Errorf("IP inicial inválida %q", startStr)
	}

	var end netip.Addr
	if strings.Contains(endStr, ".") {
		end, err = netip.ParseAddr(endStr)
		if err != nil || !end.Is4() {
			return nil, fmt.Errorf("IP final inválida %q", endStr)
		}
	} else {
		// Short form: "192.168.1.1-254" — reuse the first three octets.
		lastOctet, perr := strconv.Atoi(endStr)
		if perr != nil || lastOctet < 0 || lastOctet > 255 {
			return nil, fmt.Errorf("IP final inválida %q", endStr)
		}
		b := start.As4()
		b[3] = byte(lastOctet)
		end = netip.AddrFrom4(b)
	}

	startB, endB := start.As4(), end.As4()
	startN := binary.BigEndian.Uint32(startB[:])
	endN := binary.BigEndian.Uint32(endB[:])
	if endN < startN {
		return nil, fmt.Errorf("la IP final es menor que la inicial")
	}
	count := int(endN-startN) + 1
	if count > maxScanHosts {
		return nil, fmt.Errorf("el rango tiene %d direcciones — el máximo por corrida es %d", count, maxScanHosts)
	}
	out := make([]netip.Addr, 0, count)
	for n := startN; n <= endN; n++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], n)
		out = append(out, netip.AddrFrom4(b))
	}
	return out, nil
}

func nextAddr(a netip.Addr) netip.Addr {
	b := a.As4()
	n := binary.BigEndian.Uint32(b[:]) + 1
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], n)
	return netip.AddrFrom4(out)
}

// Scan actively probes every address in spec. onProgress is called after
// every ICMP probe (up or down) with (scanned, total); onHost is called once
// per address that actually replied, already enriched with hostname/MAC/
// vendor/open ports/OS guess. iface is not used to steer routing (TRAZIP has
// no raw-socket per-NIC binding) — it is only recorded on each result so the
// UI can show which interface's network the operator picked.
func Scan(ctx context.Context, spec, iface string, onHost func(HostResult), onProgress func(scanned, total int)) (ScanSummary, error) {
	targets, err := ParseTargets(spec)
	if err != nil {
		return ScanSummary{}, err
	}
	start := time.Now()
	total := len(targets)

	type pingHit struct {
		addr  netip.Addr
		rttMs float64
		ttl   int
	}

	// Phase 1: bounded-concurrency ICMP sweep — cheap, finds who's alive.
	jobs := make(chan netip.Addr)
	hits := make(chan pingHit, total)
	var scanned int32

	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	workers := pingWorkers
	if workers > total {
		workers = total
	}
	if workers < 1 {
		workers = 1
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range jobs {
				if ctx.Err() != nil {
					return
				}
				var replied bool
				var rttMs float64
				var ttl int
				pctx, cancel := context.WithTimeout(ctx, pingTimeout+200*time.Millisecond)
				_, _, _ = ping.Run(pctx, ping.Config{Target: addr.String(), Count: 1, Timeout: pingTimeout}, func(r ping.Reply, _ ping.Snapshot) {
					if r.OK {
						replied, rttMs, ttl = true, r.RTTms, r.TTL
					}
				})
				cancel()
				n := atomic.AddInt32(&scanned, 1)
				if onProgress != nil {
					onProgress(int(n), total)
				}
				if replied {
					hits <- pingHit{addr: addr, rttMs: rttMs, ttl: ttl}
				}
			}
		}()
	}
	wg.Wait()
	close(hits)

	var upHosts []pingHit
	for h := range hits {
		upHosts = append(upHosts, h)
	}

	summary := ScanSummary{Range: spec, TotalIPs: total, Scanned: int(scanned), UpCount: len(upHosts)}
	if ctx.Err() != nil {
		summary.DurationSec = time.Since(start).Seconds()
		return summary, nil
	}

	// The ICMP replies above trigger ARP resolution on the same L2 segment;
	// give the OS a brief moment to finish populating its table, then read
	// it ONCE (not once per host) — populate() is the same read Discover()
	// already uses for the passive view.
	time.Sleep(arpSettleDelay)
	nbs, _ := neighbors()
	byIP := make(map[string]Neighbor, len(nbs))
	for _, n := range nbs {
		byIP[n.IP] = n
	}

	// Phase 2: enrich each responsive host (hostname/vendor/ports/OS guess).
	hostJobs := make(chan pingHit)
	go func() {
		defer close(hostJobs)
		for _, h := range upHosts {
			select {
			case hostJobs <- h:
			case <-ctx.Done():
				return
			}
		}
	}()

	ew := enrichWorkers
	if ew > len(upHosts) {
		ew = len(upHosts)
	}
	if ew < 1 {
		ew = 1
	}

	var ewg sync.WaitGroup
	for i := 0; i < ew; i++ {
		ewg.Add(1)
		go func() {
			defer ewg.Done()
			for h := range hostJobs {
				if ctx.Err() != nil {
					return
				}
				hr := HostResult{IP: h.addr.String(), Up: true, RTTms: h.rttMs, Iface: iface, OSGuess: osGuessFromTTL(h.ttl)}
				if nb, ok := byIP[hr.IP]; ok {
					hr.MAC = nb.MAC
					hr.Vendor = nb.Vendor
				}
				hr.Hostname = reverseLookup(ctx, h.addr)
				hr.OpenPorts = openPortsFor(ctx, h.addr)
				if onHost != nil {
					onHost(hr)
				}
			}
		}()
	}
	ewg.Wait()

	summary.DurationSec = time.Since(start).Seconds()
	return summary, nil
}

func openPortsFor(ctx context.Context, addr netip.Addr) []portscan.PortResult {
	sctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var mu sync.Mutex
	var open []portscan.PortResult
	_, _, _ = portscan.Run(sctx, portscan.Config{Target: addr.String(), Ports: portscan.Top100(), Concurrency: 32, Timeout: 600 * time.Millisecond}, func(pr portscan.PortResult) {
		if pr.State == string(portscan.Open) {
			mu.Lock()
			open = append(open, pr)
			mu.Unlock()
		}
	})
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
}

// osGuessFromTTL is the well-known coarse heuristic (initial TTL 64/128/255
// decremented per hop) — always labeled "estimado", never asserted as fact,
// since it's trivially spoofable and varies by OS/kernel version.
func osGuessFromTTL(ttl int) string {
	switch {
	case ttl <= 0:
		return ""
	case ttl <= 64:
		return "Linux/Unix/Android/macOS (estimado por TTL)"
	case ttl <= 128:
		return "Windows (estimado por TTL)"
	default:
		return "Dispositivo de red (estimado por TTL)"
	}
}

func reverseLookup(ctx context.Context, addr netip.Addr) string {
	rctx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(rctx, addr.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
