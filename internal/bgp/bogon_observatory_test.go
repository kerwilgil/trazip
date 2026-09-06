package bgp

import (
	"bytes"
	"context"
	"encoding/csv"
	"net/http"
	"strings"
	"testing"
)

// ---- fixture helpers ----

var ianaCSVHeader = []string{"Address Block", "Name", "RFC", "Allocation Date", "Termination Date", "Source", "Destination", "Forwardable", "Globally Reachable", "Reserved-by-Protocol"}

func ianaCSVBody(header []string, rows [][]string) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write(header)
	for _, r := range rows {
		w.Write(r)
	}
	w.Flush()
	return buf.String()
}

// realIANAIPv4Rows mirrors real entries confirmed live in Gate 4's wire
// preflight (10.0.0.0/8, 192.0.2.0/24, the 192.0.0.0/24 + 192.0.0.9/32
// most-specific pair, and the 192.0.0.170/32, 192.0.0.171/32 multi-prefix
// NAT64/DNS64 row) plus a broader containing block to exercise
// most-specific selection.
func realIANAIPv4Rows() [][]string {
	return [][]string{
		{"10.0.0.0/8", "Private-Use", "[RFC1918]", "1996-02", "N/A", "True", "True", "True", "False", "False"},
		{"192.0.2.0/24", "Documentation (TEST-NET-1)", "[RFC5737]", "2010-01", "N/A", "False", "False", "False", "False", "False"},
		{"192.0.0.0/24", "IETF Protocol Assignments", "[RFC6890]", "2010-01", "N/A", "", "", "", "False", ""},
		{"192.0.0.9/32", "IPv4 Service Continuity Prefix", "[RFC7335]", "2014-06", "N/A", "True", "True", "True", "False", "False"},
		{"192.0.0.170/32, 192.0.0.171/32", "NAT64/DNS64 Discovery", "[RFC8880][RFC7050]", "2016-02", "N/A", "True", "False", "False", "False", "False"},
	}
}

func realIANAIPv6Rows() [][]string {
	return [][]string{
		{"::1/128", "Loopback Address", "[RFC4291]", "2006-02", "N/A", "False", "False", "False", "False", "True"},
		{"::/128", "Unspecified Address", "[RFC4291]", "2006-02", "N/A", "True", "False", "False", "False", "True"},
	}
}

func cymruFeedBody(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

// withBogonFixtures redirects the package-level IANA/Cymru URL vars for
// the given family to two local fixture servers, restoring the originals
// via t.Cleanup — no change to Client's own fields.
func withBogonFixtures(t *testing.T, family int, ianaBody string, ianaStatus int, cymruBody string, cymruStatus int) {
	t.Helper()
	ianaAddr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		if ianaStatus != http.StatusOK {
			w.WriteHeader(ianaStatus)
			return
		}
		w.Write([]byte(ianaBody))
	})
	cymruAddr := startFakeServerHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		if cymruStatus != http.StatusOK {
			w.WriteHeader(cymruStatus)
			return
		}
		w.Write([]byte(cymruBody))
	})
	var ianaVar, cymruVar *string
	if family == 6 {
		ianaVar, cymruVar = &ianaIPv6CSVURL, &cymruIPv6URL
	} else {
		ianaVar, cymruVar = &ianaIPv4CSVURL, &cymruIPv4URL
	}
	origIana, origCymru := *ianaVar, *cymruVar
	*ianaVar, *cymruVar = ianaAddr, cymruAddr
	t.Cleanup(func() { *ianaVar, *cymruVar = origIana, origCymru })
}

// withBogonFixturesFailIfCalled asserts NEITHER feed is ever fetched —
// used for local-rejection zero-HTTP proofs.
func withBogonFixturesFailIfCalled(t *testing.T) {
	t.Helper()
	origV4Iana, origV6Iana := ianaIPv4CSVURL, ianaIPv6CSVURL
	origV4Cymru, origV6Cymru := cymruIPv4URL, cymruIPv6URL
	addr := failIfCalledHTTP(t)
	ianaIPv4CSVURL, ianaIPv6CSVURL, cymruIPv4URL, cymruIPv6URL = addr, addr, addr, addr
	t.Cleanup(func() {
		ianaIPv4CSVURL, ianaIPv6CSVURL = origV4Iana, origV6Iana
		cymruIPv4URL, cymruIPv6URL = origV4Cymru, origV6Cymru
	})
}

func defaultIANAv4Body() string { return ianaCSVBody(ianaCSVHeader, realIANAIPv4Rows()) }
func defaultIANAv6Body() string { return ianaCSVBody(ianaCSVHeader, realIANAIPv6Rows()) }
func defaultCymruV4Body() string {
	return cymruFeedBody("# last updated", "# comment", "10.0.0.0/8", "", "203.0.113.0/24")
}
func defaultCymruV6Body() string { return cymruFeedBody("# last updated", "::/10", "2001:db8::/32") }

// ================= VALIDATION (1-12) =================

func TestBogonLookup_ValidIPv4IP(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "8.8.8.8"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.ResourceKind != "ip" || res.Family != 4 {
		t.Errorf("Kind/Family = %q/%d, want ip/4", res.ResourceKind, res.Family)
	}
}

func TestBogonLookup_ValidIPv6IP(t *testing.T) {
	withBogonFixtures(t, 6, defaultIANAv6Body(), http.StatusOK, defaultCymruV6Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "2001:4860:4860::8888"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.ResourceKind != "ip" || res.Family != 6 {
		t.Errorf("Kind/Family = %q/%d, want ip/6", res.ResourceKind, res.Family)
	}
}

func TestBogonLookup_ValidIPv4Prefix(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.0.0.0/8"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.ResourceKind != "prefix" || res.Family != 4 {
		t.Errorf("Kind/Family = %q/%d, want prefix/4", res.ResourceKind, res.Family)
	}
}

func TestBogonLookup_ValidIPv6Prefix(t *testing.T) {
	withBogonFixtures(t, 6, defaultIANAv6Body(), http.StatusOK, defaultCymruV6Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "2001:db8::/32"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.ResourceKind != "prefix" || res.Family != 6 {
		t.Errorf("Kind/Family = %q/%d, want prefix/6", res.ResourceKind, res.Family)
	}
}

func TestBogonLookup_NormalizesInput(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.0.0.5/8"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.Resource != "10.0.0.0/8" {
		t.Errorf("Resource = %q, want normalized/masked %q (host bits cleared)", res.Resource, "10.0.0.0/8")
	}
}

func TestBogonLookup_LocalRejections_ZeroHTTP(t *testing.T) {
	withBogonFixturesFailIfCalled(t)
	c := &Client{}
	cases := map[string]string{
		"empty":            "",
		"ASN":              "AS13335",
		"hostname":         "example.com",
		"country":          "PA",
		"malformed IP":     "999.999.999.999",
		"malformed prefix": "10.0.0.0/99",
	}
	for name, resource := range cases {
		t.Run(name, func(t *testing.T) {
			res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: resource})
			if res.Err == "" {
				t.Fatalf("Err empty for %q, want a rejection", resource)
			}
			if len(res.Evidence) != 2 {
				t.Fatalf("Evidence = %+v, want exactly 2 entries", res.Evidence)
			}
			for _, e := range res.Evidence {
				if e.Status != ComponentNotApplicable {
					t.Errorf("Evidence[%s].Status = %s, want %s", e.Component, e.Status, ComponentNotApplicable)
				}
			}
			if res.DataSufficient {
				t.Error("DataSufficient = true, want false")
			}
		})
	}
}

func TestBogonLookup_EveryLocalRejection_ZeroNetworkCalls(t *testing.T) {
	withBogonFixturesFailIfCalled(t)
	c := &Client{}
	for _, resource := range []string{"", "AS13335", "example.com", "PA", "999.999.999.999", "10.0.0.0/99"} {
		c.BogonLookup(context.Background(), BogonLookupRequest{Resource: resource})
	}
}

// ================= IANA (13-30) =================

func TestBogonLookup_IANA_IPv4FullDecode(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "192.0.2.1"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.IANASpecialPurpose == nil || !*res.IANASpecialPurpose {
		t.Fatalf("IANASpecialPurpose = %v, want true", res.IANASpecialPurpose)
	}
	if res.IANAMatch == nil || res.IANAMatch.Name != "Documentation (TEST-NET-1)" {
		t.Errorf("IANAMatch = %+v, want Documentation (TEST-NET-1)", res.IANAMatch)
	}
}

func TestBogonLookup_IANA_IPv6FullDecode(t *testing.T) {
	withBogonFixtures(t, 6, defaultIANAv6Body(), http.StatusOK, defaultCymruV6Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "::1"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.IANASpecialPurpose == nil || !*res.IANASpecialPurpose {
		t.Fatalf("IANASpecialPurpose = %v, want true", res.IANASpecialPurpose)
	}
	if res.IANAMatch == nil || res.IANAMatch.Name != "Loopback Address" {
		t.Errorf("IANAMatch = %+v, want Loopback Address", res.IANAMatch)
	}
}

func TestBogonLookup_IANA_HeaderMappedByName_NotIndex(t *testing.T) {
	// Reordered header + rows — still must decode correctly since columns
	// are matched by name.
	reordered := []string{"Name", "Address Block", "RFC", "Source", "Destination", "Forwardable", "Globally Reachable", "Reserved-by-Protocol", "Allocation Date", "Termination Date"}
	rows := [][]string{{"Private-Use", "10.0.0.0/8", "[RFC1918]", "True", "True", "True", "False", "False", "1996-02", "N/A"}}
	withBogonFixtures(t, 4, ianaCSVBody(reordered, rows), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.1.2.3"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.IANAMatch == nil || res.IANAMatch.Name != "Private-Use" {
		t.Errorf("IANAMatch = %+v, want Private-Use (proves name-based mapping)", res.IANAMatch)
	}
}

func TestBogonLookup_IANA_MissingRequiredHeader_Degraded(t *testing.T) {
	badHeader := []string{"Address Block", "Name", "RFC", "Allocation Date", "Termination Date", "Source", "Destination", "Forwardable", "Globally Reachable"} // missing Reserved-by-Protocol
	withBogonFixtures(t, 4, ianaCSVBody(badHeader, [][]string{{"10.0.0.0/8", "Private-Use", "[RFC1918]", "1996-02", "N/A", "True", "True", "True", "False"}}), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.1.2.3"})
	if res.IANASpecialPurpose != nil {
		t.Errorf("IANASpecialPurpose = %v, want nil", res.IANASpecialPurpose)
	}
	if res.DataSufficient {
		t.Error("DataSufficient = true, want false")
	}
	var iana *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "iana-special-purpose" {
			iana = &res.Evidence[i]
		}
	}
	if iana == nil || iana.Status != ComponentDegraded {
		t.Errorf("iana-special-purpose Evidence = %+v, want ComponentDegraded", iana)
	}
}

func TestBogonLookup_IANA_MalformedCSV_Degraded(t *testing.T) {
	withBogonFixtures(t, 4, `not,"a valid csv`, http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.1.2.3"})
	if res.IANASpecialPurpose != nil {
		t.Errorf("IANASpecialPurpose = %v, want nil", res.IANASpecialPurpose)
	}
	var iana *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "iana-special-purpose" {
			iana = &res.Evidence[i]
		}
	}
	if iana == nil || iana.Status != ComponentDegraded {
		t.Errorf("iana-special-purpose Evidence = %+v, want ComponentDegraded", iana)
	}
}

func TestBogonLookup_IANA_MalformedAddressBlock_Degraded(t *testing.T) {
	rows := [][]string{{"not-a-prefix", "Bogus", "[RFC0000]", "2020-01", "N/A", "True", "True", "True", "False", "False"}}
	withBogonFixtures(t, 4, ianaCSVBody(ianaCSVHeader, rows), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.1.2.3"})
	if res.IANASpecialPurpose != nil {
		t.Errorf("IANASpecialPurpose = %v, want nil", res.IANASpecialPurpose)
	}
	var iana *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "iana-special-purpose" {
			iana = &res.Evidence[i]
		}
	}
	if iana == nil || iana.Status != ComponentDegraded {
		t.Errorf("iana-special-purpose Evidence = %+v, want ComponentDegraded", iana)
	}
}

func TestBogonLookup_IANA_MultiPrefixAddressBlock_BothMatch(t *testing.T) {
	rows := [][]string{{"192.0.0.170/32, 192.0.0.171/32", "NAT64/DNS64 Discovery", "[RFC8880]", "2016-02", "N/A", "True", "False", "False", "False", "False"}}
	withBogonFixtures(t, 4, ianaCSVBody(ianaCSVHeader, rows), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	for _, ip := range []string{"192.0.0.170", "192.0.0.171"} {
		t.Run(ip, func(t *testing.T) {
			res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: ip})
			if res.Err != "" {
				t.Fatalf("unexpected Err: %s", res.Err)
			}
			if res.IANASpecialPurpose == nil || !*res.IANASpecialPurpose {
				t.Fatalf("IANASpecialPurpose = %v, want true for %s", res.IANASpecialPurpose, ip)
			}
			if res.IANAMatch == nil || res.IANAMatch.Name != "NAT64/DNS64 Discovery" {
				t.Errorf("IANAMatch = %+v, want NAT64/DNS64 Discovery for %s", res.IANAMatch, ip)
			}
		})
	}
}

func TestBogonLookup_IANA_PrivateUse_10001(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.0.0.1"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.IANAMatch == nil || res.IANAMatch.Name != "Private-Use" {
		t.Errorf("IANAMatch = %+v, want Private-Use", res.IANAMatch)
	}
}

func TestBogonLookup_IANA_Documentation_192_0_2_1(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "192.0.2.1"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.IANAMatch == nil || res.IANAMatch.Name != "Documentation (TEST-NET-1)" {
		t.Errorf("IANAMatch = %+v, want Documentation (TEST-NET-1)", res.IANAMatch)
	}
}

func TestBogonLookup_IANA_Loopback_IPv6(t *testing.T) {
	withBogonFixtures(t, 6, defaultIANAv6Body(), http.StatusOK, defaultCymruV6Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "::1"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.IANAMatch == nil || res.IANAMatch.Name != "Loopback Address" {
		t.Errorf("IANAMatch = %+v, want Loopback Address", res.IANAMatch)
	}
}

func TestBogonLookup_IANA_RegularPublicIP_NoMatch(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "8.8.8.8"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.IANASpecialPurpose == nil || *res.IANASpecialPurpose {
		t.Fatalf("IANASpecialPurpose = %v, want false", res.IANASpecialPurpose)
	}
	if res.IANAMatch != nil {
		t.Errorf("IANAMatch = %+v, want nil", res.IANAMatch)
	}
}

func TestBogonLookup_IANA_MostSpecificMatch(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "192.0.0.9"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.IANAMatch == nil || res.IANAMatch.Prefix != "192.0.0.9/32" {
		t.Errorf("IANAMatch = %+v, want the /32 entry, not the broader /24", res.IANAMatch)
	}
	if res.IANAMatch.Name != "IPv4 Service Continuity Prefix" {
		t.Errorf("IANAMatch.Name = %q, want the specific entry's name, not the /24 parent's", res.IANAMatch.Name)
	}
}

func TestBogonLookup_IANA_BoolTruePreserved(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.0.0.1"})
	if res.IANAMatch == nil || res.IANAMatch.Source == nil || !*res.IANAMatch.Source {
		t.Fatalf("Source = %v, want pointer to true", res.IANAMatch.Source)
	}
}

func TestBogonLookup_IANA_BoolFalsePreserved(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "192.0.2.1"})
	if res.IANAMatch == nil || res.IANAMatch.Source == nil || *res.IANAMatch.Source {
		t.Fatalf("Source = %v, want pointer to false", res.IANAMatch.Source)
	}
}

// Gate 4 live-smoke finding: IANA's real CSV embeds footnote markers like
// "[2]" directly inside cell values — both in Address Block ("192.0.0.0/24
// [2]") and in boolean columns ("False [1]") — confirmed against the real
// registry. A footnote's mere presence must never make a valid prefix look
// malformed or a real true/false value look absent.
func TestBogonLookup_IANA_FootnoteMarker_AddressBlock_StillParses(t *testing.T) {
	rows := [][]string{{"192.0.0.0/24 [2]", "IETF Protocol Assignments", "[RFC6890]", "2010-01", "N/A", "True", "False", "False", "False", "False"}}
	withBogonFixtures(t, 4, ianaCSVBody(ianaCSVHeader, rows), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "192.0.0.5"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.IANASpecialPurpose == nil || !*res.IANASpecialPurpose {
		t.Fatalf("IANASpecialPurpose = %v, want true — a footnote marker must not make the Address Block unparseable", res.IANASpecialPurpose)
	}
	if res.IANAMatch == nil || res.IANAMatch.Prefix != "192.0.0.0/24" {
		t.Errorf("IANAMatch.Prefix = %v, want 192.0.0.0/24 with the footnote stripped", res.IANAMatch)
	}
}

func TestBogonLookup_IANA_FootnoteMarker_BooleanColumn_StillParsesRealValue(t *testing.T) {
	rows := [][]string{{"::1/128", "Loopback Address", "[RFC4291]", "2006-02", "N/A", "False [1]", "False", "False", "False", "True"}}
	withBogonFixtures(t, 6, ianaCSVBody(ianaCSVHeader, rows), http.StatusOK, defaultCymruV6Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "::1"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.IANAMatch == nil || res.IANAMatch.Source == nil {
		t.Fatalf("Source = %v, want a real non-nil pointer despite the footnote — a footnote must never turn a real False into an absent/nil value", res.IANAMatch)
	}
	if *res.IANAMatch.Source {
		t.Errorf("Source = %v, want pointer to false (\"False [1]\" is a real false, not true)", *res.IANAMatch.Source)
	}
}

func TestBogonLookup_IANA_EmptyBoolBecomesNil(t *testing.T) {
	// 192.0.0.0/24 row has empty Source/Destination/Forwardable/Reserved-by-Protocol cells.
	rows := [][]string{{"192.0.0.5/32", "IETF Protocol Assignments", "[RFC6890]", "2010-01", "N/A", "", "", "", "False", ""}}
	withBogonFixtures(t, 4, ianaCSVBody(ianaCSVHeader, rows), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "192.0.0.5"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	m := res.IANAMatch
	if m == nil {
		t.Fatal("IANAMatch = nil")
	}
	if m.Source != nil || m.Destination != nil || m.Forwardable != nil || m.ReservedByProtocol != nil {
		t.Errorf("Source/Destination/Forwardable/ReservedByProtocol = %v/%v/%v/%v, want all nil (empty cells)", m.Source, m.Destination, m.Forwardable, m.ReservedByProtocol)
	}
	if m.GloballyReachable == nil || *m.GloballyReachable {
		t.Errorf("GloballyReachable = %v, want pointer to false (explicitly \"False\" in fixture)", m.GloballyReachable)
	}
}

func TestBogonLookup_IANA_RFCMetadataPreserved(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.0.0.1"})
	if res.IANAMatch == nil || res.IANAMatch.RFC != "[RFC1918]" {
		t.Errorf("RFC = %q, want [RFC1918]", res.IANAMatch.RFC)
	}
}

func TestBogonLookup_IANA_AllocationDatePreserved(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.0.0.1"})
	if res.IANAMatch == nil || res.IANAMatch.AllocationDate != "1996-02" {
		t.Errorf("AllocationDate = %q, want 1996-02", res.IANAMatch.AllocationDate)
	}
}

func TestBogonLookup_IANA_TerminationDatePreserved(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.0.0.1"})
	if res.IANAMatch == nil || res.IANAMatch.TerminationDate != "N/A" {
		t.Errorf("TerminationDate = %q, want N/A", res.IANAMatch.TerminationDate)
	}
}

// ================= PREFIX CONTAINMENT (31-33) =================

func TestBogonLookup_PrefixContainment_FullyInside(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.0.0.0/9"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.IANASpecialPurpose == nil || !*res.IANASpecialPurpose {
		t.Fatalf("IANASpecialPurpose = %v, want true — 10.0.0.0/9 is fully inside 10.0.0.0/8", res.IANASpecialPurpose)
	}
}

func TestBogonLookup_PrefixContainment_ExactMatch(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.0.0.0/8"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.IANASpecialPurpose == nil || !*res.IANASpecialPurpose {
		t.Fatalf("IANASpecialPurpose = %v, want true — exact match", res.IANASpecialPurpose)
	}
}

func TestBogonLookup_PrefixContainment_PartialOverlap_NotContained(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "8.0.0.0/7"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.IANASpecialPurpose == nil || *res.IANASpecialPurpose {
		t.Fatalf("IANASpecialPurpose = %v, want false — 8.0.0.0/7 only partially overlaps 10.0.0.0/8, never fully contained", res.IANASpecialPurpose)
	}
}

// ================= CYMRU (34-45) =================

func TestBogonLookup_Cymru_ParseIPv4Fixture(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "203.0.113.5"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.CymruFullBogon == nil || !*res.CymruFullBogon {
		t.Fatalf("CymruFullBogon = %v, want true", res.CymruFullBogon)
	}
}

func TestBogonLookup_Cymru_ParseIPv6Fixture(t *testing.T) {
	withBogonFixtures(t, 6, defaultIANAv6Body(), http.StatusOK, defaultCymruV6Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "2001:db8::1"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.CymruFullBogon == nil || !*res.CymruFullBogon {
		t.Fatalf("CymruFullBogon = %v, want true", res.CymruFullBogon)
	}
}

func TestBogonLookup_Cymru_CommentsIgnored(t *testing.T) {
	body := cymruFeedBody("# last updated 123", "# Know your network!", "203.0.113.0/24")
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, body, http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "203.0.113.1"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.CymruFullBogon == nil || !*res.CymruFullBogon {
		t.Fatalf("CymruFullBogon = %v, want true", res.CymruFullBogon)
	}
}

func TestBogonLookup_Cymru_BlankLinesIgnored(t *testing.T) {
	body := "203.0.113.0/24\n\n\n"
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, body, http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "203.0.113.1"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.CymruFullBogon == nil || !*res.CymruFullBogon {
		t.Fatalf("CymruFullBogon = %v, want true", res.CymruFullBogon)
	}
}

func TestBogonLookup_Cymru_MalformedDataLine_Degraded(t *testing.T) {
	body := cymruFeedBody("# comment", "not-a-cidr", "203.0.113.0/24")
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, body, http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "203.0.113.1"})
	if res.CymruFullBogon != nil {
		t.Errorf("CymruFullBogon = %v, want nil", res.CymruFullBogon)
	}
	var cymru *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "team-cymru-fullbogons" {
			cymru = &res.Evidence[i]
		}
	}
	if cymru == nil || cymru.Status != ComponentDegraded {
		t.Errorf("team-cymru-fullbogons Evidence = %+v, want ComponentDegraded", cymru)
	}
}

func TestBogonLookup_Cymru_WrongFamilyPrefix_Degraded(t *testing.T) {
	// An IPv6 CIDR inside the IPv4 feed.
	body := cymruFeedBody("203.0.113.0/24", "2001:db8::/32")
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, body, http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "203.0.113.1"})
	if res.CymruFullBogon != nil {
		t.Errorf("CymruFullBogon = %v, want nil", res.CymruFullBogon)
	}
	var cymru *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "team-cymru-fullbogons" {
			cymru = &res.Evidence[i]
		}
	}
	if cymru == nil || cymru.Status != ComponentDegraded {
		t.Errorf("team-cymru-fullbogons Evidence = %+v, want ComponentDegraded", cymru)
	}
}

func TestBogonLookup_Cymru_IPContained_True(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.5.5.5"})
	if res.CymruFullBogon == nil || !*res.CymruFullBogon {
		t.Fatalf("CymruFullBogon = %v, want true", res.CymruFullBogon)
	}
}

func TestBogonLookup_Cymru_IPNoMatch_False(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "8.8.8.8"})
	if res.CymruFullBogon == nil || *res.CymruFullBogon {
		t.Fatalf("CymruFullBogon = %v, want false", res.CymruFullBogon)
	}
	if res.CymruMatchPrefix != "" {
		t.Errorf("CymruMatchPrefix = %q, want empty", res.CymruMatchPrefix)
	}
}

func TestBogonLookup_Cymru_PrefixFullyContained_True(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.0.0.0/16"})
	if res.CymruFullBogon == nil || !*res.CymruFullBogon {
		t.Fatalf("CymruFullBogon = %v, want true", res.CymruFullBogon)
	}
}

func TestBogonLookup_Cymru_BroadPrefixPartialOverlap_False(t *testing.T) {
	body := cymruFeedBody("10.0.0.0/8")
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, body, http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "8.0.0.0/7"})
	if res.CymruFullBogon == nil || *res.CymruFullBogon {
		t.Fatalf("CymruFullBogon = %v, want false — only partial overlap with 10.0.0.0/8", res.CymruFullBogon)
	}
}

func TestBogonLookup_Cymru_MostSpecificPreserved(t *testing.T) {
	body := cymruFeedBody("10.0.0.0/8", "10.0.0.0/24")
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, body, http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.0.0.5"})
	if res.CymruMatchPrefix != "10.0.0.0/24" {
		t.Errorf("CymruMatchPrefix = %q, want the more specific 10.0.0.0/24, not the broader /8", res.CymruMatchPrefix)
	}
}

func TestBogonLookup_Cymru_EmptyFeed_ValidFalse(t *testing.T) {
	// An empty-but-successfully-parsed feed is a valid "no entries"
	// state (Gate 4 decision, documented alongside the parser): the call
	// and decode succeeded, there is simply nothing in the feed, so
	// ComponentOK + CymruFullBogon=pointer(false), never Degraded.
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, "", http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "8.8.8.8"})
	if res.CymruFullBogon == nil {
		t.Fatal("CymruFullBogon = nil, want pointer to false")
	}
	if *res.CymruFullBogon {
		t.Error("CymruFullBogon = true, want false")
	}
	var cymru *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "team-cymru-fullbogons" {
			cymru = &res.Evidence[i]
		}
	}
	if cymru == nil || cymru.Status != ComponentOK {
		t.Errorf("team-cymru-fullbogons Evidence = %+v, want ComponentOK", cymru)
	}
}

// ================= ZERO VS ABSENT / PARTIAL (46-54) =================

func TestBogonLookup_IANAFailure_CymruPreserved(t *testing.T) {
	withBogonFixtures(t, 4, "", http.StatusInternalServerError, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.5.5.5"})
	if res.IANASpecialPurpose != nil {
		t.Errorf("IANASpecialPurpose = %v, want nil", res.IANASpecialPurpose)
	}
	if res.DataSufficient {
		t.Error("DataSufficient = true, want false")
	}
	if res.CymruFullBogon == nil || !*res.CymruFullBogon {
		t.Errorf("CymruFullBogon = %v, want true (preserved despite IANA failure)", res.CymruFullBogon)
	}
}

func TestBogonLookup_CymruFailure_IANAPreserved(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, "", http.StatusInternalServerError)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.5.5.5"})
	if res.CymruFullBogon != nil {
		t.Errorf("CymruFullBogon = %v, want nil", res.CymruFullBogon)
	}
	if res.DataSufficient {
		t.Error("DataSufficient = true, want false")
	}
	if res.IANASpecialPurpose == nil || !*res.IANASpecialPurpose {
		t.Errorf("IANASpecialPurpose = %v, want true (preserved despite Cymru failure)", res.IANASpecialPurpose)
	}
}

func TestBogonLookup_BothSuccess_BothFalse_DataSufficient(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "8.8.8.8"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	if res.IANASpecialPurpose == nil || *res.IANASpecialPurpose {
		t.Errorf("IANASpecialPurpose = %v, want pointer to false", res.IANASpecialPurpose)
	}
	if res.CymruFullBogon == nil || *res.CymruFullBogon {
		t.Errorf("CymruFullBogon = %v, want pointer to false", res.CymruFullBogon)
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true")
	}
}

func TestBogonLookup_IANATrue_CymruFalse(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "192.0.2.1"})
	if res.IANASpecialPurpose == nil || !*res.IANASpecialPurpose {
		t.Errorf("IANASpecialPurpose = %v, want true", res.IANASpecialPurpose)
	}
	if res.CymruFullBogon == nil || *res.CymruFullBogon {
		t.Errorf("CymruFullBogon = %v, want false", res.CymruFullBogon)
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true")
	}
}

func TestBogonLookup_IANAFalse_CymruTrue(t *testing.T) {
	body := cymruFeedBody("8.8.8.0/24")
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, body, http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "8.8.8.8"})
	if res.IANASpecialPurpose == nil || *res.IANASpecialPurpose {
		t.Errorf("IANASpecialPurpose = %v, want false", res.IANASpecialPurpose)
	}
	if res.CymruFullBogon == nil || !*res.CymruFullBogon {
		t.Errorf("CymruFullBogon = %v, want true", res.CymruFullBogon)
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true")
	}
}

func TestBogonLookup_BothTrue(t *testing.T) {
	body := cymruFeedBody("10.0.0.0/8")
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, body, http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.0.0.1"})
	if res.IANASpecialPurpose == nil || !*res.IANASpecialPurpose {
		t.Errorf("IANASpecialPurpose = %v, want true", res.IANASpecialPurpose)
	}
	if res.CymruFullBogon == nil || !*res.CymruFullBogon {
		t.Errorf("CymruFullBogon = %v, want true", res.CymruFullBogon)
	}
	if !res.DataSufficient {
		t.Error("DataSufficient = false, want true")
	}
}

func TestBogonLookup_Evidence_ExactlyOnePerDatasource(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "8.8.8.8"})
	if len(res.Evidence) != 2 {
		t.Fatalf("Evidence = %+v, want exactly 2 entries", res.Evidence)
	}
	seen := map[string]bool{}
	for _, e := range res.Evidence {
		seen[e.Component] = true
	}
	if !seen["iana-special-purpose"] || !seen["team-cymru-fullbogons"] {
		t.Errorf("Evidence components = %+v, want iana-special-purpose and team-cymru-fullbogons", res.Evidence)
	}
}

func TestBogonLookup_Disclosure_CorrectSource(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "8.8.8.8"})
	for _, e := range res.Evidence {
		switch e.Component {
		case "iana-special-purpose":
			if e.Disclosure.Source != "IANA (Internet Assigned Numbers Authority)" {
				t.Errorf("iana Disclosure.Source = %q", e.Disclosure.Source)
			}
		case "team-cymru-fullbogons":
			if e.Disclosure.Source != "Team Cymru (Fullbogons)" {
				t.Errorf("cymru Disclosure.Source = %q", e.Disclosure.Source)
			}
		}
	}
}

func TestBogonLookup_Disclosure_NeverRIPEstat(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "8.8.8.8"})
	for _, e := range res.Evidence {
		if strings.Contains(e.Disclosure.Source, "RIPEstat") || strings.Contains(e.Disclosure.Source, "RIPE NCC") {
			t.Errorf("Evidence[%s].Disclosure.Source = %q, must never claim RIPEstat", e.Component, e.Disclosure.Source)
		}
	}
}

// ================= P1 FIX: IANA DISCLOSURE MUST NOT LEAK RESOURCE =================
//
// classifyIANA's HTTP call downloads the same static CSV regardless of
// what's being looked up — the queried IP/prefix never travels in the
// request, so Disclosure.DataSent must never imply otherwise (Gate 4 P1
// fix: an earlier revision wrongly interpolated the resource into
// DataSent).

func iANAEvidence(res BogonLookupResult) *ComponentEvidence {
	for i := range res.Evidence {
		if res.Evidence[i].Component == "iana-special-purpose" {
			return &res.Evidence[i]
		}
	}
	return nil
}

func cymruEvidence(res BogonLookupResult) *ComponentEvidence {
	for i := range res.Evidence {
		if res.Evidence[i].Component == "team-cymru-fullbogons" {
			return &res.Evidence[i]
		}
	}
	return nil
}

func TestBogonLookup_IANADisclosure_IPv4_NoResourceLeak(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.0.0.1"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}

	iana := iANAEvidence(res)
	if iana == nil || iana.Status != ComponentOK {
		t.Fatalf("iana-special-purpose Evidence = %+v, want ComponentOK", iana)
	}
	if iana.Disclosure.Source != "IANA (Internet Assigned Numbers Authority)" {
		t.Errorf("Disclosure.Source = %q, want %q", iana.Disclosure.Source, "IANA (Internet Assigned Numbers Authority)")
	}
	if strings.Contains(iana.Disclosure.DataSent, "10.0.0.1") {
		t.Errorf("Disclosure.DataSent = %q, must not contain the queried resource %q", iana.Disclosure.DataSent, "10.0.0.1")
	}
	if !strings.Contains(iana.Disclosure.DataSent, "IPv4") || !strings.Contains(strings.ToLower(iana.Disclosure.DataSent), "csv") {
		t.Errorf("Disclosure.DataSent = %q, want it to describe the full IPv4 CSV registry download", iana.Disclosure.DataSent)
	}
	if !strings.Contains(iana.Disclosure.DataSent, "no viaja en la petición") {
		t.Errorf("Disclosure.DataSent = %q, want it to state the resource never travels in the request", iana.Disclosure.DataSent)
	}
}

func TestBogonLookup_IANADisclosure_IPv6_NoResourceLeak(t *testing.T) {
	withBogonFixtures(t, 6, defaultIANAv6Body(), http.StatusOK, defaultCymruV6Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "2001:db8::1"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}

	iana := iANAEvidence(res)
	if iana == nil || iana.Status != ComponentOK {
		t.Fatalf("iana-special-purpose Evidence = %+v, want ComponentOK", iana)
	}
	if strings.Contains(iana.Disclosure.DataSent, "2001:db8::1") {
		t.Errorf("Disclosure.DataSent = %q, must not contain the queried resource %q", iana.Disclosure.DataSent, "2001:db8::1")
	}
	if !strings.Contains(iana.Disclosure.DataSent, "IPv6") {
		t.Errorf("Disclosure.DataSent = %q, want it to describe the full IPv6 CSV registry download", iana.Disclosure.DataSent)
	}
}

func TestBogonLookup_CymruDisclosure_StillNoResourceLeak(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "10.0.0.1"})
	if res.Err != "" {
		t.Fatalf("unexpected Err: %s", res.Err)
	}
	cymru := cymruEvidence(res)
	if cymru == nil || cymru.Status != ComponentOK {
		t.Fatalf("team-cymru-fullbogons Evidence = %+v, want ComponentOK", cymru)
	}
	if strings.Contains(cymru.Disclosure.DataSent, "10.0.0.1") {
		t.Errorf("Disclosure.DataSent = %q, must not contain the queried resource %q", cymru.Disclosure.DataSent, "10.0.0.1")
	}
	if cymru.Disclosure.Source != "Team Cymru (Fullbogons)" {
		t.Errorf("Disclosure.Source = %q, want %q", cymru.Disclosure.Source, "Team Cymru (Fullbogons)")
	}
}

// ================= NETWORK SAFETY (55-59) =================

func TestBogonLookup_IANA_HTTPNon200_Degraded(t *testing.T) {
	withBogonFixtures(t, 4, "", http.StatusServiceUnavailable, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "8.8.8.8"})
	if res.IANASpecialPurpose != nil {
		t.Errorf("IANASpecialPurpose = %v, want nil", res.IANASpecialPurpose)
	}
	var iana *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "iana-special-purpose" {
			iana = &res.Evidence[i]
		}
	}
	if iana == nil || iana.Status != ComponentDegraded {
		t.Errorf("iana-special-purpose Evidence = %+v, want ComponentDegraded", iana)
	}
}

func TestBogonLookup_Cymru_HTTPNon200_Degraded(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, "", http.StatusServiceUnavailable)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "8.8.8.8"})
	if res.CymruFullBogon != nil {
		t.Errorf("CymruFullBogon = %v, want nil", res.CymruFullBogon)
	}
	var cymru *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "team-cymru-fullbogons" {
			cymru = &res.Evidence[i]
		}
	}
	if cymru == nil || cymru.Status != ComponentDegraded {
		t.Errorf("team-cymru-fullbogons Evidence = %+v, want ComponentDegraded", cymru)
	}
}

func TestBogonLookup_ContextCanceled_BothDegraded(t *testing.T) {
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, defaultCymruV4Body(), http.StatusOK)
	c := &Client{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := c.BogonLookup(ctx, BogonLookupRequest{Resource: "8.8.8.8"})
	if res.Err == "" {
		t.Fatal("Err empty, want a context-canceled error")
	}
	for _, e := range res.Evidence {
		if e.Status != ComponentDegraded {
			t.Errorf("Evidence[%s].Status = %s, want %s", e.Component, e.Status, ComponentDegraded)
		}
	}
}

func TestBogonLookup_BodyExactlyAtLimit_Accepted(t *testing.T) {
	// Pad a valid Cymru feed with a long trailing comment so the body is
	// exactly bogonFeedMaxBytes bytes, and confirm it still decodes.
	base := "203.0.113.0/24\n"
	padding := bogonFeedMaxBytes - len(base) - 2 // leave room for the '#' prefix and trailing newline
	body := base + "#" + strings.Repeat("x", padding) + "\n"
	if len(body) != bogonFeedMaxBytes {
		t.Fatalf("test setup: body = %d bytes, want exactly %d", len(body), bogonFeedMaxBytes)
	}
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, body, http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "203.0.113.1"})
	if res.Err != "" {
		t.Fatalf("unexpected Err at exactly the byte limit: %s", res.Err)
	}
	if res.CymruFullBogon == nil || !*res.CymruFullBogon {
		t.Errorf("CymruFullBogon = %v, want true", res.CymruFullBogon)
	}
}

func TestBogonLookup_BodyOverLimit_Degraded_NeverPartial(t *testing.T) {
	body := "203.0.113.0/24\n#" + strings.Repeat("x", bogonFeedMaxBytes) + "\n"
	withBogonFixtures(t, 4, defaultIANAv4Body(), http.StatusOK, body, http.StatusOK)
	c := &Client{}
	res := c.BogonLookup(context.Background(), BogonLookupRequest{Resource: "203.0.113.1"})
	if res.CymruFullBogon != nil {
		t.Errorf("CymruFullBogon = %v, want nil — over-limit body must never be partially parsed", res.CymruFullBogon)
	}
	var cymru *ComponentEvidence
	for i := range res.Evidence {
		if res.Evidence[i].Component == "team-cymru-fullbogons" {
			cymru = &res.Evidence[i]
		}
	}
	if cymru == nil || cymru.Status != ComponentDegraded {
		t.Errorf("team-cymru-fullbogons Evidence = %+v, want ComponentDegraded", cymru)
	}
}

// ================= SEMANTIC AUDIT (test-verified absence) =================

func TestBogonLookup_NoForbiddenSemanticFields(t *testing.T) {
	forbidden := []string{"malicious", "attacker", "attack", "hijack", "compromised", "unsafe", "threat", "isbad", "isdangerous"}
	fields := []string{}
	for _, name := range []string{"Resource", "ResourceKind", "Family", "IANASpecialPurpose", "IANAMatch", "CymruFullBogon", "CymruMatchPrefix", "DataSufficient", "Evidence", "Err"} {
		fields = append(fields, name)
	}
	for _, f := range fields {
		lower := strings.ToLower(f)
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				t.Errorf("field %q contains forbidden substring %q", f, bad)
			}
		}
	}
}
