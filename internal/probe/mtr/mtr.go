// Package mtr implements TRAZIP's MTR engine (prompt maestro §5.2, §9 Fase 1 #3):
// continuous per-hop probing that combines the traceroute path discovery with
// live ping statistics. It reuses the trace.Session transport (unprivileged ICMP
// with TTL) and the ping.Stats accumulator, rather than re-implementing either.
package mtr

import (
	"context"
	"net"
	"net/netip"
	"time"

	"trazip/internal/intel/classify"
	"trazip/internal/probe/ping"
	"trazip/internal/probe/trace"
)

// Config parameterizes an MTR run.
type Config struct {
	Target        string
	MaxHops       int
	Timeout       time.Duration
	RoundInterval time.Duration // pause between full-path rounds
	PayloadSize   int
	Family        string
	ResolveDNS    bool
}

func (c *Config) withDefaults() {
	if c.MaxHops <= 0 || c.MaxHops > 64 {
		c.MaxHops = 30
	}
	if c.Timeout <= 0 {
		c.Timeout = 1500 * time.Millisecond
	}
	if c.RoundInterval <= 0 {
		c.RoundInterval = time.Second
	}
	if c.PayloadSize <= 0 {
		c.PayloadSize = 32
	}
}

// HopStat is the accumulated per-hop state emitted each round.
type HopStat struct {
	TTL         int      `json:"ttl"`
	Addr        string   `json:"addr"`
	Hostname    string   `json:"hostname,omitempty"`
	Sent        int      `json:"sent"`
	Recv        int      `json:"recv"`
	LossPct     float64  `json:"lossPct"`
	LastMs      float64  `json:"lastMs"`
	BestMs      float64  `json:"bestMs"`
	AvgMs       float64  `json:"avgMs"`
	WorstMs     float64  `json:"worstMs"`
	StdDevMs    float64  `json:"stdDevMs"`
	JitterMs    float64  `json:"jitterMs"`
	Classes     []string `json:"classes,omitempty"`
	Reached     bool     `json:"reached"`
	Country     string   `json:"country,omitempty"`
	CountryCode string   `json:"countryCode,omitempty"`
	City        string   `json:"city,omitempty"`
	Region      string   `json:"region,omitempty"`
	ASN         uint32   `json:"asn,omitempty"`
	Org         string   `json:"org,omitempty"`
	Lat         float64  `json:"lat,omitempty"`
	Lon         float64  `json:"lon,omitempty"`
}

type hopState struct {
	stats    ping.Stats
	addr     netip.Addr
	hostname string
	classes  []string
	reached  bool
}

// Run performs continuous per-hop probing, invoking onUpdate with the full hop
// table after every round. A cancelled context stops the loop cleanly.
func Run(ctx context.Context, cfg Config, onUpdate func([]HopStat)) (netip.Addr, error) {
	cfg.withDefaults()
	addr, err := ping.Resolve(ctx, cfg.Target, cfg.Family)
	if err != nil {
		return netip.Addr{}, err
	}
	sess, err := trace.NewSession(addr)
	if err != nil {
		return addr, err
	}
	defer sess.Close()

	payload := make([]byte, cfg.PayloadSize)
	for i := range payload {
		payload[i] = byte('0' + (i % 10))
	}

	hops := make([]*hopState, cfg.MaxHops)
	for i := range hops {
		hops[i] = &hopState{}
	}

	destTTL := 0 // 0 until the destination is located
	seq := 0

	for {
		if ctx.Err() != nil {
			return addr, nil
		}

		limit := cfg.MaxHops
		if destTTL > 0 {
			limit = destTTL
		}

		for ttl := 1; ttl <= limit; ttl++ {
			if ctx.Err() != nil {
				return addr, nil
			}
			seq++
			res := sess.Probe(ttl, seq, payload, cfg.Timeout)
			st := hops[ttl-1]
			st.stats.MarkSent()
			if !res.TimedOut {
				st.stats.AddReply(res.RTT)
				if res.Addr.IsValid() && !st.addr.IsValid() {
					st.addr = res.Addr
					for _, c := range classify.Classify(res.Addr) {
						st.classes = append(st.classes, string(c))
					}
					if cfg.ResolveDNS {
						st.hostname = reverseDNS(ctx, res.Addr)
					}
				}
				if res.Reached {
					st.reached = true
					if destTTL == 0 || ttl < destTTL {
						destTTL = ttl
					}
				}
			}
			if destTTL > 0 && ttl >= destTTL {
				break
			}
		}

		// destTTL may have just been discovered during this very round (the
		// inner loop breaks as soon as it is), in which case `limit` above is
		// still the round's stale pre-discovery value (cfg.MaxHops) — without
		// this, the very first round that reaches the destination reports
		// cfg.MaxHops hops with all the entries past the destination empty,
		// self-correcting only from the second round onward. A continuous
		// caller barely notices (round 2 fixes it), but a caller that only
		// takes one round per invocation (internal/monitor) hits this on
		// every single sample.
		snapLimit := limit
		if destTTL > 0 && destTTL < snapLimit {
			snapLimit = destTTL
		}
		onUpdate(snapshot(hops, snapLimit))

		select {
		case <-ctx.Done():
			return addr, nil
		case <-time.After(cfg.RoundInterval):
		}
	}
}

func snapshot(hops []*hopState, limit int) []HopStat {
	out := make([]HopStat, 0, limit)
	for i := 0; i < limit; i++ {
		st := hops[i]
		snap := st.stats.Snapshot()
		out = append(out, HopStat{
			TTL:      i + 1,
			Addr:     addrStr(st.addr),
			Hostname: st.hostname,
			Sent:     snap.Sent,
			Recv:     snap.Recv,
			LossPct:  snap.LossPct,
			LastMs:   snap.LastMs,
			BestMs:   snap.MinMs,
			AvgMs:    snap.AvgMs,
			WorstMs:  snap.MaxMs,
			StdDevMs: snap.StdDevMs,
			JitterMs: snap.JitterMs,
			Classes:  st.classes,
			Reached:  st.reached,
		})
	}
	return out
}

func addrStr(a netip.Addr) string {
	if a.IsValid() {
		return a.String()
	}
	return ""
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
