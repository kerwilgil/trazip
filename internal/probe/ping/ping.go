// Package ping implements TRAZIP's own ICMP echo engine (prompt maestro §5.2,
// §9 Fase 1 #1). It is unprivileged where the OS allows: on Windows it uses the
// IP Helper API (IcmpSendEcho); on macOS/Linux it uses datagram ICMP sockets via
// x/net/icmp, falling back to raw sockets when permitted. The engine is the
// shared foundation the Trace and MTR engines build on.
package ping

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Config parameterizes a ping run.
type Config struct {
	Target      string        // IP, hostname
	Count       int           // 0 = continuous until context is cancelled
	Interval    time.Duration // between probes
	Timeout     time.Duration // per probe
	PayloadSize int           // ICMP data bytes
	Family      string        // "", "ip4", "ip6"
}

func (c *Config) withDefaults() {
	if c.Interval <= 0 {
		c.Interval = time.Second
	}
	if c.Timeout <= 0 {
		c.Timeout = 2 * time.Second
	}
	if c.PayloadSize <= 0 {
		c.PayloadSize = 32
	}
}

// Reply is the outcome of a single probe (success or failure).
type Reply struct {
	Seq     int           `json:"seq"`
	From    netip.Addr    `json:"-"`
	FromStr string        `json:"from"`
	RTT     time.Duration `json:"-"`
	RTTms   float64       `json:"rttMs"`
	TTL     int           `json:"ttl"`
	Size    int           `json:"size"`
	Time    time.Time     `json:"-"`
	OK      bool          `json:"ok"`
	Err     string        `json:"err,omitempty"`
}

// icmpSession is the platform-specific ICMP transport. Implementations live in
// icmp_windows.go and icmp_other.go.
type icmpSession interface {
	send(seq int, payload []byte, timeout time.Duration) (rtt time.Duration, ttl int, from netip.Addr, err error)
	close() error
}

// Resolve turns a target (IP or hostname) into an address, honoring family.
func Resolve(ctx context.Context, target, family string) (netip.Addr, error) {
	target = trimSpace(target)
	if a, err := netip.ParseAddr(target); err == nil {
		return a.Unmap(), nil
	}
	network := "ip"
	switch family {
	case "ip4":
		network = "ip4"
	case "ip6":
		network = "ip6"
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(rctx, network, target)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("sin registros para %q", target)
	}
	return ips[0].Unmap(), nil
}

// Run executes the ping loop, invoking onReply for every probe (success or
// timeout) with the probe result and the running statistics. It returns the
// final statistics and the resolved address. A cancelled context stops the loop
// cleanly and is not reported as an error.
func Run(ctx context.Context, cfg Config, onReply func(Reply, Snapshot)) (Snapshot, netip.Addr, error) {
	cfg.withDefaults()
	addr, err := Resolve(ctx, cfg.Target, cfg.Family)
	if err != nil {
		return Snapshot{}, netip.Addr{}, fmt.Errorf("no se pudo resolver %q: %w", cfg.Target, err)
	}
	sess, err := newICMPSession(addr)
	if err != nil {
		return Snapshot{}, addr, err
	}
	defer sess.close()

	payload := make([]byte, cfg.PayloadSize)
	for i := range payload {
		payload[i] = byte('0' + (i % 10))
	}

	var stats Stats
	seq := 0
	for {
		if cfg.Count > 0 && seq >= cfg.Count {
			break
		}
		seq++
		stats.MarkSent()
		rtt, ttl, from, perr := sess.send(seq, payload, cfg.Timeout)
		r := Reply{Seq: seq, Time: time.Now()}
		if perr != nil {
			r.OK = false
			r.Err = perr.Error()
		} else {
			stats.AddReply(rtt)
			r.OK = true
			r.From = from
			r.FromStr = from.String()
			r.RTT = rtt
			r.RTTms = round2(float64(rtt) / float64(time.Millisecond))
			r.TTL = ttl
			r.Size = len(payload)
		}
		if onReply != nil {
			onReply(r, stats.Snapshot())
		}
		if cfg.Count > 0 && seq >= cfg.Count {
			break
		}
		select {
		case <-ctx.Done():
			return stats.Snapshot(), addr, nil
		case <-time.After(cfg.Interval):
		}
	}
	return stats.Snapshot(), addr, nil
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
