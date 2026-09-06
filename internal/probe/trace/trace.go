// Package trace implements TRAZIP's own traceroute engine (prompt maestro §5.2,
// §9 Fase 1 #2). It reuses the same unprivileged ICMP approach as the ping
// engine: on Windows it drives IcmpSendEcho with an incremental TTL (the reply
// carries the intermediate router that expired the packet); on macOS/Linux it
// sets the socket TTL/hop-limit via x/net/icmp. Reverse DNS and offline IP
// classification are attached per hop.
package trace

import (
	"context"
	"net"
	"net/netip"
	"time"

	"trazip/internal/intel/classify"
	"trazip/internal/probe/ping"
)

// Config parameterizes a traceroute run.
type Config struct {
	Target      string
	MaxHops     int
	Probes      int // probes per hop
	Timeout     time.Duration
	PayloadSize int
	Family      string // "", "ip4", "ip6"
	ResolveDNS  bool   // reverse DNS per hop
}

func (c *Config) withDefaults() {
	if c.MaxHops <= 0 || c.MaxHops > 64 {
		c.MaxHops = 30
	}
	if c.Probes <= 0 {
		c.Probes = 3
	}
	if c.Timeout <= 0 {
		c.Timeout = 2 * time.Second
	}
	if c.PayloadSize <= 0 {
		c.PayloadSize = 32
	}
}

// Probe is a single measurement within a hop.
type Probe struct {
	RTTms float64 `json:"rttMs"`
	OK    bool    `json:"ok"`
}

// Hop is one TTL step of the route. Country/ASN/Org are filled by the caller
// (api.Service) via offline GeoIP enrichment — this package only knows about
// RFC classification, not geography (prompt maestro §10 layering).
type Hop struct {
	TTL         int      `json:"ttl"`
	Addr        string   `json:"addr"`
	Hostname    string   `json:"hostname,omitempty"`
	Probes      []Probe  `json:"probes"`
	BestMs      float64  `json:"bestMs"`
	AvgMs       float64  `json:"avgMs"`
	Timeout     bool     `json:"timeout"` // every probe timed out
	Reached     bool     `json:"reached"` // this hop is the destination
	Classes     []string `json:"classes,omitempty"`
	Country     string   `json:"country,omitempty"`
	CountryCode string   `json:"countryCode,omitempty"`
	City        string   `json:"city,omitempty"`
	Region      string   `json:"region,omitempty"`
	ASN         uint32   `json:"asn,omitempty"`
	Org         string   `json:"org,omitempty"`
	Lat         float64  `json:"lat,omitempty"`
	Lon         float64  `json:"lon,omitempty"`
}

// ProbeResult is the low-level outcome of a single TTL probe. Exported so the MTR
// engine can reuse the same platform transport.
type ProbeResult struct {
	Addr     netip.Addr
	RTT      time.Duration
	Reached  bool
	TimedOut bool
}

// Session is the platform ICMP transport with TTL control (trace_windows.go /
// trace_other.go). It is the shared primitive for Traceroute and MTR.
type Session interface {
	Probe(ttl, seq int, payload []byte, timeout time.Duration) ProbeResult
	Close() error
}

// Run walks the route hop by hop, invoking onHop for each TTL. It stops when the
// destination is reached or MaxHops is exceeded. A cancelled context stops cleanly.
func Run(ctx context.Context, cfg Config, onHop func(Hop)) ([]Hop, netip.Addr, error) {
	cfg.withDefaults()
	addr, err := ping.Resolve(ctx, cfg.Target, cfg.Family)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	sess, err := NewSession(addr)
	if err != nil {
		return nil, addr, err
	}
	defer sess.Close()

	payload := make([]byte, cfg.PayloadSize)
	for i := range payload {
		payload[i] = byte('0' + (i % 10))
	}

	var hops []Hop
	seq := 0
	for ttl := 1; ttl <= cfg.MaxHops; ttl++ {
		if ctx.Err() != nil {
			break
		}
		hop := Hop{TTL: ttl}
		var hopAddr netip.Addr
		var best, sum float64
		okCount := 0

		for p := 0; p < cfg.Probes; p++ {
			if ctx.Err() != nil {
				break
			}
			seq++
			res := sess.Probe(ttl, seq, payload, cfg.Timeout)
			if res.TimedOut {
				hop.Probes = append(hop.Probes, Probe{OK: false})
				continue
			}
			ms := float64(res.RTT) / float64(time.Millisecond)
			ms = round2(ms)
			hop.Probes = append(hop.Probes, Probe{RTTms: ms, OK: true})
			okCount++
			sum += ms
			if okCount == 1 || ms < best {
				best = ms
			}
			if res.Addr.IsValid() {
				hopAddr = res.Addr
			}
			if res.Reached {
				hop.Reached = true
			}
		}

		if okCount == 0 {
			hop.Timeout = true
		} else {
			hop.BestMs = round2(best)
			hop.AvgMs = round2(sum / float64(okCount))
		}
		if hopAddr.IsValid() {
			hop.Addr = hopAddr.String()
			for _, c := range classify.Classify(hopAddr) {
				hop.Classes = append(hop.Classes, string(c))
			}
			if cfg.ResolveDNS {
				hop.Hostname = reverseDNS(ctx, hopAddr)
			}
		}

		if onHop != nil {
			onHop(hop)
		}
		hops = append(hops, hop)
		if hop.Reached {
			break
		}
	}
	return hops, addr, nil
}

func reverseDNS(ctx context.Context, addr netip.Addr) string {
	rctx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(rctx, addr.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	name := names[0]
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}

func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}
