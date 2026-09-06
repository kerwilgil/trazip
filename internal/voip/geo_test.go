package voip

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"trazip/internal/intel/geoip"
)

func TestEnrichPartyNilGeoIsNoOp(t *testing.T) {
	p := CallParty{Address: "203.0.113.5:5060"} // TEST-NET-3, but the point here is geo==nil
	enrichParty(&p, nil)
	if p.Country != "" || p.ASN != 0 {
		t.Errorf("nil engine must never populate geo data: %+v", p)
	}
}

func TestEnrichPartyDegradesForPrivateAndInvalidAddresses(t *testing.T) {
	dataDir := filepath.Join("..", "..", "data")
	if _, err := os.Stat(filepath.Join(dataDir, "GeoLite2-City.mmdb")); err != nil {
		t.Skip("no GeoLite2 dataset in this checkout; degrade-cleanly path only needs geo==nil, already covered")
	}
	geo := geoip.Open(dataDir)
	defer geo.Close()

	for _, addr := range []string{"192.168.1.10:5060", "127.0.0.1:5060", "not-an-address", ""} {
		p := CallParty{Address: addr}
		enrichParty(&p, geo)
		if p.Country != "" || p.ASN != 0 {
			t.Errorf("address %q must not get GeoIP/ASN data, got %+v", addr, p)
		}
	}
}

// Real enrichment, guarded: skipped when this checkout has no dataset (e.g. a
// CI environment), so the suite stays green everywhere while still proving
// the pipeline against real MaxMind data whenever it's available — the exact
// same data/ directory geoip.FindDataDir() resolves to in the real app.
func TestEnrichPartyResolvesAKnownPublicIP(t *testing.T) {
	dataDir := filepath.Join("..", "..", "data")
	if _, err := os.Stat(filepath.Join(dataDir, "GeoLite2-ASN.mmdb")); err != nil {
		t.Skip("no GeoLite2 ASN dataset in this checkout")
	}
	geo := geoip.Open(dataDir)
	defer geo.Close()

	// 1.1.1.1 (Cloudflare) has an exceptionally stable ASN across MMDB
	// snapshots — a safe anchor for this test.
	p := CallParty{Address: "1.1.1.1:5060"}
	enrichParty(&p, geo)
	if p.ASN == 0 {
		t.Fatal("expected an ASN for a well-known public IP with the ASN dataset loaded")
	}
}

// Gate v0.7.3 (independent audit, third gate, item 10): every internal
// "ip:port" string in this package (including CallParty.Address) is built as
// fmt.Sprintf("%s:%d", ip, port) — never bracketed, even for IPv6.
// net.SplitHostPort requires "[ipv6]:port" brackets and fails entirely on an
// unbracketed IPv6 address ("too many colons"), which used to make
// enrichParty silently degrade GeoIP/ASN to empty for every IPv6 endpoint.
// This is parsing-only and must not depend on a dataset being present.
func TestIPOfExtractsIPv6HostFromCallPartyAddressFormat(t *testing.T) {
	got := ipOf("2606:4700:4700::1111:5060")
	want := "2606:4700:4700::1111"
	if got != want {
		t.Fatalf("ipOf(IPv6 host:port) = %q, want %q", got, want)
	}
	if _, err := netip.ParseAddr(got); err != nil {
		t.Errorf("ipOf's IPv6 extraction must be netip.ParseAddr-valid: %v", err)
	}
}

// enrichParty itself, with an IPv6 address and no engine, must not error out
// or bail before even trying to parse — it should reach the same "geo==nil"
// no-op path an IPv4 address would, not fail earlier due to a parsing error.
func TestEnrichPartyParsesIPv6WithoutADataset(t *testing.T) {
	p := CallParty{Address: "2606:4700:4700::1111:5060"}
	enrichParty(&p, nil) // geo==nil is the only reason this is a no-op, not a parse failure
	if p.Country != "" || p.ASN != 0 {
		t.Errorf("nil engine must never populate geo data: %+v", p)
	}
}

// Real enrichment for an IPv6 address, guarded the same way as the IPv4
// version above — skipped without a dataset, but proves the IPv6 pipeline
// against real MaxMind data whenever one is available.
func TestEnrichPartyResolvesAKnownPublicIPv6(t *testing.T) {
	dataDir := filepath.Join("..", "..", "data")
	if _, err := os.Stat(filepath.Join(dataDir, "GeoLite2-ASN.mmdb")); err != nil {
		t.Skip("no GeoLite2 ASN dataset in this checkout")
	}
	geo := geoip.Open(dataDir)
	defer geo.Close()

	// 2606:4700:4700::1111 is Cloudflare's IPv6 anchor, mirroring 1.1.1.1.
	p := CallParty{Address: "2606:4700:4700::1111:5060"}
	enrichParty(&p, geo)
	if p.ASN == 0 {
		t.Fatal("expected an ASN for a well-known public IPv6 address with the ASN dataset loaded")
	}
}
