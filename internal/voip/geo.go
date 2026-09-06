package voip

import (
	"net/netip"

	"trazip/internal/intel/classify"
	"trazip/internal/intel/geoip"
)

// enrichParty fills a CallParty's Country/ASN/Organization from the offline
// GeoIP engine already owned by Service and shared across TRAZIP (no new
// engine instance — prompt maestro §5.4). Degrades to a no-op, cleanly and
// silently, when geo is nil (no dataset loaded), the address doesn't parse,
// or it isn't public: a private/loopback/bogon address has no meaningful
// country, and showing one would be fabricated, not enriched.
func enrichParty(p *CallParty, geo *geoip.Engine) {
	if p == nil {
		return
	}
	r, ok := lookupAddressGeo(p.Address, geo)
	if !ok {
		return
	}
	p.Country, p.CountryCode = r.Country, r.CountryCode
	p.ASN, p.Organization = r.ASN, r.Organization
}

// enrichHop is enrichParty's SignalingHop equivalent — same offline-only
// GeoIP/ASN engine, same silent no-op degrade for private/unparseable
// addresses or a missing dataset (see enrichParty's doc comment).
func enrichHop(h *SignalingHop, geo *geoip.Engine) {
	if h == nil {
		return
	}
	r, ok := lookupAddressGeo(h.Address, geo)
	if !ok {
		return
	}
	h.Country, h.CountryCode = r.Country, r.CountryCode
	h.ASN, h.Organization = r.ASN, r.Organization
}

// addressGeoResult is enrichParty/enrichHop's shared lookup result — kept
// separate from CallParty/SignalingHop themselves so lookupAddressGeo has no
// dependency on which one it's enriching.
type addressGeoResult struct {
	Country      string
	CountryCode  string
	ASN          uint32
	Organization string
}

// lookupAddressGeo resolves one "ip:port" address against the offline
// GeoIP/ASN engine. ok is false whenever there is nothing safe to enrich
// with — no engine loaded, an unparseable address, or a private/loopback/
// bogon address (which has no meaningful country and would be fabricated,
// not enriched) — the same three degrade conditions enrichParty always had,
// just centralized so enrichHop shares them exactly rather than
// re-implementing the address parsing a second time.
func lookupAddressGeo(address string, geo *geoip.Engine) (addressGeoResult, bool) {
	if address == "" || geo == nil {
		return addressGeoResult{}, false
	}
	// address is built elsewhere as plain "ip:port" (fmt.Sprintf("%s:%d",
	// ip, port)) — never bracketed, even for IPv6, so net.SplitHostPort
	// (which requires "[ipv6]:port" brackets) fails on every IPv6 address
	// here with "too many colons" and silently degrades GeoIP/ASN to empty.
	// ipOf already handles this exact internal format correctly (it splits
	// on the LAST colon, which — since only the port we ourselves appended
	// is ever separated by a colon at the very end of the string — is
	// always the right one, IPv4 or IPv6) and is already the single source
	// of truth every other address-splitting call site in this package
	// uses, so reusing it here keeps this consistent with ipOf/portOf/SDP
	// comparison/stream keys instead of adding a second, divergent parser.
	host := ipOf(address)
	if host == "" {
		return addressGeoResult{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return addressGeoResult{}, false
	}
	addr = addr.Unmap()
	if !classify.IsPublic(addr) {
		return addressGeoResult{}, false
	}
	r := geo.Lookup(addr)
	out := addressGeoResult{}
	if r.HasGeo {
		out.Country, out.CountryCode = r.Country, r.CountryCode
	}
	if r.HasASN {
		out.ASN, out.Organization = r.ASN, r.Org
	}
	return out, true
}
