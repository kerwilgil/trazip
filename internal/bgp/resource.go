package bgp

import (
	"net/netip"
	"strconv"
	"strings"
)

// ResourceKind classifies one user-provided BGP resource string.
type ResourceKind string

const (
	KindASN     ResourceKind = "asn"
	KindIPv4    ResourceKind = "ipv4"
	KindIPv6    ResourceKind = "ipv6"
	KindPrefix4 ResourceKind = "prefix4"
	KindPrefix6 ResourceKind = "prefix6"
	KindInvalid ResourceKind = "invalid"
)

// ClassifyResource parses and normalizes a user-typed BGP resource — an
// ASN (with or without an "AS"/"as" prefix), an IPv4/IPv6 address, or an
// IPv4/IPv6 prefix — into a stable canonical form. It never touches the
// network and never guesses: anything that doesn't cleanly match one of
// the four accepted shapes is KindInvalid with an empty normalized value.
func ClassifyResource(raw string) (ResourceKind, string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return KindInvalid, ""
	}

	digits := stripASPrefix(trimmed)
	if isAllDigits(digits) {
		n, err := strconv.ParseUint(digits, 10, 32)
		if err != nil || n == 0 {
			// Looked like an ASN attempt (all-digit, optional AS
			// prefix) but failed range validation or is the reserved
			// AS0 (RFC 7607) — never silently retried as an IP/prefix.
			return KindInvalid, ""
		}
		return KindASN, "AS" + strconv.FormatUint(n, 10)
	}

	if strings.Contains(trimmed, "/") {
		p, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return KindInvalid, ""
		}
		masked := p.Masked()
		if masked.Addr().Is4() {
			return KindPrefix4, masked.String()
		}
		return KindPrefix6, masked.String()
	}

	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return KindInvalid, ""
	}
	if addr.Is4() {
		return KindIPv4, addr.String()
	}
	return KindIPv6, addr.String()
}

func stripASPrefix(s string) string {
	if len(s) >= 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		return s[2:]
	}
	return s
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
