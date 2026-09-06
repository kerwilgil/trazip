// Package classify implements the offline IP Classification Engine. It labels an
// address by its RFC-defined nature (private, loopback, bogon, ...) using only
// netip primitives — no external datasets and no network calls
// (prompt maestro §5.2, §5.4, §6). Dataset-backed labels (hosting/VPN/Tor) are
// layered on top elsewhere; this package is the deterministic base.
package classify

import (
	"net/netip"

	"trazip/internal/model"
)

// bogonV4 lists IPv4 ranges that should never appear as routable public source
// or destination addresses on the open Internet (RFC 1918/5735/6598/etc.).
var bogonV4 = mustPrefixes(
	"0.0.0.0/8",       // "this network"
	"100.64.0.0/10",   // CGNAT (RFC 6598)
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1 documentation
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2 documentation
	"203.0.113.0/24",  // TEST-NET-3 documentation
	"240.0.0.0/4",     // reserved (future use)
)

var docV6 = mustPrefixes(
	"2001:db8::/32", // documentation
	"3fff::/20",     // documentation (RFC 9637)
)

// Classify returns the set of network classes that apply to addr. The result is
// deterministic and offline; it always yields at least one class.
func Classify(addr netip.Addr) []model.NetClass {
	if !addr.IsValid() {
		return []model.NetClass{model.ClassUnknown}
	}
	addr = addr.Unmap()
	var out []model.NetClass

	switch {
	case addr.IsLoopback():
		out = append(out, model.ClassLoopback)
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		out = append(out, model.ClassLinkLocal)
	}
	if addr.IsMulticast() {
		out = append(out, model.ClassMulticast)
	}
	if addr.IsPrivate() {
		out = append(out, model.ClassPrivate)
	}
	if isDocumentation(addr) {
		out = append(out, model.ClassDocumentation)
	}
	if isBogon(addr) {
		out = append(out, model.ClassBogon)
	}

	// If none of the special classes matched and it's globally unicast, it's public.
	if len(out) == 0 && addr.IsGlobalUnicast() {
		out = append(out, model.ClassPublic)
	}
	if len(out) == 0 {
		out = append(out, model.ClassReserved)
	}
	return out
}

// IsPublic reports whether addr is a routable public address (no special class
// and globally unicast).
func IsPublic(addr netip.Addr) bool {
	for _, c := range Classify(addr) {
		if c == model.ClassPublic {
			return true
		}
	}
	return false
}

func isDocumentation(addr netip.Addr) bool {
	if addr.Is4() {
		for _, p := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"} {
			if netip.MustParsePrefix(p).Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, p := range docV6 {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func isBogon(addr netip.Addr) bool {
	if addr.IsUnspecified() {
		return true
	}
	if addr.Is4() {
		for _, p := range bogonV4 {
			if p.Contains(addr) {
				return true
			}
		}
	}
	return false
}

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}
