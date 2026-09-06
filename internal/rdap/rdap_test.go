package rdap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func bootstrapJSON(t *testing.T, resources []string, rdapURL string) http.HandlerFunc {
	t.Helper()
	body, err := json.Marshal(bootstrapFile{Services: [][2][]string{{resources, {rdapURL}}}})
	if err != nil {
		t.Fatal(err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}
}

func emptyBootstrap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"services":[]}`))
}

// newIPClient wires a Client whose IPv4 bootstrap maps resources to a local
// RDAP server driven by rdapHandler; IPv6/ASN bootstraps are empty. Fully
// hermetic — never touches real IANA/RIR infrastructure.
func newIPClient(t *testing.T, resources []string, rdapHandler http.HandlerFunc) *Client {
	t.Helper()
	rdapSrv := httptest.NewServer(rdapHandler)
	t.Cleanup(rdapSrv.Close)

	ipv4Srv := httptest.NewServer(bootstrapJSON(t, resources, rdapSrv.URL))
	t.Cleanup(ipv4Srv.Close)
	ipv6Srv := httptest.NewServer(http.HandlerFunc(emptyBootstrap))
	t.Cleanup(ipv6Srv.Close)
	asnSrv := httptest.NewServer(http.HandlerFunc(emptyBootstrap))
	t.Cleanup(asnSrv.Close)

	return &Client{
		HTTPClient:       http.DefaultClient,
		BootstrapIPv4URL: ipv4Srv.URL,
		BootstrapIPv6URL: ipv6Srv.URL,
		BootstrapASNURL:  asnSrv.URL,
	}
}

func newASNClient(t *testing.T, resources []string, rdapHandler http.HandlerFunc) *Client {
	t.Helper()
	rdapSrv := httptest.NewServer(rdapHandler)
	t.Cleanup(rdapSrv.Close)

	ipv4Srv := httptest.NewServer(http.HandlerFunc(emptyBootstrap))
	t.Cleanup(ipv4Srv.Close)
	ipv6Srv := httptest.NewServer(http.HandlerFunc(emptyBootstrap))
	t.Cleanup(ipv6Srv.Close)
	asnSrv := httptest.NewServer(bootstrapJSON(t, resources, rdapSrv.URL))
	t.Cleanup(asnSrv.Close)

	return &Client{
		HTTPClient:       http.DefaultClient,
		BootstrapIPv4URL: ipv4Srv.URL,
		BootstrapIPv6URL: ipv6Srv.URL,
		BootstrapASNURL:  asnSrv.URL,
	}
}

func TestLookupIPHermetic(t *testing.T) {
	rdapBody := []byte(`{
		"handle": "203.0.113.0 - 203.0.113.255",
		"name": "EXAMPLE-NET",
		"country": "US",
		"startAddress": "203.0.113.0",
		"endAddress": "203.0.113.255",
		"status": ["active"],
		"events": [
			{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"},
			{"eventAction":"last changed","eventDate":"2024-06-01T00:00:00Z"}
		],
		"entities": [
			{"roles": ["registrant"], "vcardArray": ["vcard", [["version",{},"text","4.0"],["fn",{},"text","Example Org"]]]},
			{"roles": ["abuse"], "vcardArray": ["vcard", [["fn",{},"text","Abuse Team"],["email",{},"text","abuse@example.test"]]]}
		],
		"remarks": [{"title":"Note","description":["informational only"]}]
	}`)

	c := newIPClient(t, []string{"203.0.113.0/24"}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write(rdapBody)
	})

	res, err := c.LookupIP(context.Background(), "203.0.113.10")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	if res.Err != "" {
		t.Fatalf("unexpected Result.Err: %s", res.Err)
	}
	if res.Name != "EXAMPLE-NET" {
		t.Errorf("Name = %q, want EXAMPLE-NET", res.Name)
	}
	if res.Country != "US" {
		t.Errorf("Country = %q, want US", res.Country)
	}
	if res.AbuseEmail != "abuse@example.test" {
		t.Errorf("AbuseEmail = %q, want abuse@example.test", res.AbuseEmail)
	}
	if len(res.Contacts) != 2 {
		t.Fatalf("Contacts = %+v, want 2 entries", res.Contacts)
	}
	if res.Registered == "" || res.LastChanged == "" {
		t.Error("Registered/LastChanged should be parsed from the events section")
	}
	if len(res.Remarks) != 1 || res.Remarks[0] != "Note: informational only" {
		t.Errorf("Remarks = %v, want [\"Note: informational only\"]", res.Remarks)
	}
	if res.Disclosure.Source == "" || res.Disclosure.QueriedAt == "" {
		t.Error("Disclosure should be fully populated")
	}
}

func TestLookupIPCidr0AndNameservers(t *testing.T) {
	// LACNIC-style response: cidr0_cidrs gives the exact allocated CIDR (more
	// precise than reconstructing one from start/endAddress), and
	// nameservers carries the reverse-DNS delegation — both absent from the
	// original parser.
	rdapBody := []byte(`{
		"handle": "179.63.192.0/21",
		"name": "Metro MPLS",
		"country": "PA",
		"startAddress": "179.63.192.0",
		"endAddress": "179.63.199.255",
		"status": ["allocated"],
		"cidr0_cidrs": [{"v4prefix": "179.63.192.0", "length": 21}],
		"nameservers": [{"ldhName": "NS1.METROMPLS.COM"}, {"ldhName": "NS2.METROMPLS.COM"}],
		"entities": [
			{"roles": ["technical"], "vcardArray": ["vcard", [["fn",{},"text","Guillermo Peterkin"],["adr",{},"text",["","","Sortis Business Tower, 10C","","","0832","Panama"]]]]}
		]
	}`)

	c := newIPClient(t, []string{"179.63.192.0/21"}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write(rdapBody)
	})

	res, err := c.LookupIP(context.Background(), "179.63.192.10")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	if res.CIDR != "179.63.192.0/21" {
		t.Errorf("CIDR = %q, want 179.63.192.0/21", res.CIDR)
	}
	if len(res.Nameservers) != 2 || res.Nameservers[0] != "NS1.METROMPLS.COM" {
		t.Errorf("Nameservers = %v, want [NS1.METROMPLS.COM NS2.METROMPLS.COM]", res.Nameservers)
	}
	if len(res.Contacts) != 1 || res.Contacts[0].Address == "" {
		t.Fatalf("expected the technical contact's Address to be parsed, got %+v", res.Contacts)
	}
}

func TestLookupIPNotFound(t *testing.T) {
	c := newIPClient(t, []string{"198.51.100.0/24"}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	res, err := c.LookupIP(context.Background(), "198.51.100.5")
	if err != nil {
		t.Fatalf("LookupIP should not itself error on a 404, got %v", err)
	}
	if res.Err == "" {
		t.Error("expected Result.Err to explain the 404")
	}
}

func TestLookupIPNoBootstrapMatch(t *testing.T) {
	c := newIPClient(t, nil, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("RDAP server should never be queried when no bootstrap entry matches")
	})

	_, err := c.LookupIP(context.Background(), "203.0.113.10")
	if err == nil {
		t.Error("expected an error when no bootstrap entry covers the address")
	}
}

func TestLookupIPInvalidAddress(t *testing.T) {
	c := NewClient()
	_, err := c.LookupIP(context.Background(), "not-an-ip")
	if err == nil {
		t.Error("expected an error for an invalid IP")
	}
}

func TestLookupASNHermetic(t *testing.T) {
	rdapBody := []byte(`{
		"handle": "AS64500",
		"name": "EXAMPLE-AS",
		"country": "US",
		"startAutnum": 64500,
		"endAutnum": 64500,
		"status": ["active"]
	}`)
	c := newASNClient(t, []string{"64500-64510"}, func(w http.ResponseWriter, r *http.Request) {
		w.Write(rdapBody)
	})

	res, err := c.LookupASN(context.Background(), 64500)
	if err != nil {
		t.Fatalf("LookupASN: %v", err)
	}
	if res.Name != "EXAMPLE-AS" {
		t.Errorf("Name = %q, want EXAMPLE-AS", res.Name)
	}
	if res.StartASN != 64500 {
		t.Errorf("StartASN = %d, want 64500", res.StartASN)
	}
}

func TestParseASNRange(t *testing.T) {
	cases := []struct {
		in         string
		start, end uint32
		ok         bool
	}{
		{"1-1876", 1, 1876, true},
		{"64512", 64512, 64512, true},
		{"bogus", 0, 0, false},
	}
	for _, c := range cases {
		start, end, ok := parseASNRange(c.in)
		if ok != c.ok || start != c.start || end != c.end {
			t.Errorf("parseASNRange(%q) = %d,%d,%v want %d,%d,%v", c.in, start, end, ok, c.start, c.end, c.ok)
		}
	}
}

func TestParseVCard(t *testing.T) {
	raw := []byte(`["vcard", [["version",{},"text","4.0"],["fn",{},"text","Jane Doe"],["org",{},"text","Example Corp"],["email",{},"text","jane@example.test"],["tel",{},"text","+1-555-0100"]]]`)
	name, org, email, phone, address := parseVCard(raw)
	if name != "Jane Doe" || org != "Example Corp" || email != "jane@example.test" || phone != "+1-555-0100" || address != "" {
		t.Errorf("parseVCard = %q %q %q %q %q", name, org, email, phone, address)
	}
}

func TestParseVCardAddress(t *testing.T) {
	// "adr" per RFC 6350 is a 7-element structured value
	// [POBox, ExtendedAddress, Street, Locality, Region, PostalCode, Country],
	// not a plain string like the other fields — this is the case that broke
	// naive string unmarshaling before the fix.
	raw := []byte(`["vcard", [["fn",{},"text","Jorge Iribarren"],["adr",{},"text",["","","Sortis Business Tower, 10C, Calle 57 Obarrio","","","0832","Panama"]]]]`)
	_, _, _, _, address := parseVCard(raw)
	want := "Sortis Business Tower, 10C, Calle 57 Obarrio, 0832, Panama"
	if address != want {
		t.Errorf("parseVCard address = %q, want %q", address, want)
	}
}
