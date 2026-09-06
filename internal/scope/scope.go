// Package scope implements the Scope Guard: every active operation (scan, probe,
// capture) must be authorized against a declared scope before running
// (prompt maestro §3 "Alcance de uso y seguridad").
package scope

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// ErrOutOfScope is returned when a target is not covered by the authorized scope.
var ErrOutOfScope = errors.New("target outside authorized scope")

// Guard holds the authorized targets for a session and rate/concurrency limits.
type Guard struct {
	mu sync.RWMutex

	// Authorized indicates the operator explicitly declared a scope. Active
	// operations are refused until this is true.
	authorized bool
	label      string
	prefixes   []netip.Prefix
	hosts      map[string]struct{}

	// Limits applied to active operations.
	MaxConcurrency int
	MaxRate        int // operations per second, 0 = unlimited

	declaredAt time.Time
}

// NewGuard returns an unauthorized guard. Nothing active may run until Authorize.
func NewGuard() *Guard {
	return &Guard{
		hosts:          make(map[string]struct{}),
		MaxConcurrency: 64,
		MaxRate:        0,
	}
}

// Authorize records the operator's declared scope. Entries may be CIDRs,
// single IPs, or hostnames. An empty scope stays unauthorized.
func (g *Guard) Authorize(label string, entries []string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	var prefixes []netip.Prefix
	hosts := make(map[string]struct{})
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			prefixes = append(prefixes, p)
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		hosts[strings.ToLower(e)] = struct{}{}
	}
	if len(prefixes) == 0 && len(hosts) == 0 {
		return fmt.Errorf("empty scope: declare at least one IP, CIDR or host")
	}
	g.authorized = true
	g.label = label
	g.prefixes = prefixes
	g.hosts = hosts
	g.declaredAt = time.Now()
	return nil
}

// Authorized reports whether an active scope is declared.
func (g *Guard) Authorized() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.authorized
}

// Label returns the human description of the current scope.
func (g *Guard) Label() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.label
}

// CheckAddr verifies an IP target is within scope.
func (g *Guard) CheckAddr(addr netip.Addr) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.authorized {
		return fmt.Errorf("%w: no scope authorized", ErrOutOfScope)
	}
	for _, p := range g.prefixes {
		if p.Contains(addr) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrOutOfScope, addr)
}

// CheckHost verifies a hostname target is within scope.
func (g *Guard) CheckHost(host string) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.authorized {
		return fmt.Errorf("%w: no scope authorized", ErrOutOfScope)
	}
	if _, ok := g.hosts[strings.ToLower(strings.TrimSpace(host))]; ok {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrOutOfScope, host)
}

// CheckTarget verifies an IP address, a hostname, or a CIDR range against the
// declared scope. Keeping this normalization in the guard prevents every
// active engine adapter from implementing subtly different checks.
//
// CIDR is checked first: some callers' "target" is itself a whole range
// (e.g. the LAN scanner authorizes and immediately self-checks the CIDR it
// was given, not a single host within it) — netip.ParseAddr rejects any
// string with a "/", so without this a freshly authorized CIDR would always
// fail its own self-check, misreported as "outside authorized scope" for a
// scope that in fact exactly matches it.
func (g *Guard) CheckTarget(target string) error {
	target = strings.TrimSpace(target)
	if prefix, err := netip.ParsePrefix(target); err == nil {
		return g.CheckPrefix(prefix)
	}
	if addr, err := netip.ParseAddr(target); err == nil {
		return g.CheckAddr(addr.Unmap())
	}
	return g.CheckHost(target)
}

// CheckPrefix verifies a CIDR range is covered by the declared scope — either
// it was authorized verbatim, or it falls entirely within a broader
// authorized prefix.
func (g *Guard) CheckPrefix(target netip.Prefix) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.authorized {
		return fmt.Errorf("%w: no scope authorized", ErrOutOfScope)
	}
	for _, p := range g.prefixes {
		if p == target || (p.Bits() <= target.Bits() && p.Contains(target.Addr())) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrOutOfScope, target)
}
