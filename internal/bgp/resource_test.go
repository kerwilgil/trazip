package bgp

import "testing"

func TestClassifyResource(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantKind   ResourceKind
		wantNormal string
	}{
		{"asn with AS uppercase", "AS262248", KindASN, "AS262248"},
		{"asn with as lowercase", "as262248", KindASN, "AS262248"},
		{"asn numeric only", "262248", KindASN, "AS262248"},
		{"asn lower bound (1)", "AS1", KindASN, "AS1"},
		{"asn upper bound (max uint32)", "AS4294967295", KindASN, "AS4294967295"},
		{"asn overflow beyond max uint32", "AS4294967296", KindInvalid, ""},
		{"asn zero reserved (AS0)", "AS0", KindInvalid, ""},
		{"asn zero reserved bare", "0", KindInvalid, ""},
		{"asn negative", "-5", KindInvalid, ""},
		{"asn empty after AS prefix", "AS", KindInvalid, ""},
		{"asn AS prefix with non-digits", "ASabc", KindInvalid, ""},
		{"asn AS prefix with internal space", "AS 262248", KindInvalid, ""},
		{"asn mixed garbage", "AS123abc456", KindInvalid, ""},

		{"ipv4 plain", "1.1.1.1", KindIPv4, "1.1.1.1"},
		{"ipv4 another", "192.0.2.7", KindIPv4, "192.0.2.7"},
		{"ipv6 plain", "2001:db8::1", KindIPv6, "2001:db8::1"},
		{"ipv6 loopback", "::1", KindIPv6, "::1"},

		{"prefix4 already masked", "192.0.2.0/24", KindPrefix4, "192.0.2.0/24"},
		{"prefix4 with host bits normalized", "192.0.2.7/24", KindPrefix4, "192.0.2.0/24"},
		{"prefix6 already masked", "2001:db8::/32", KindPrefix6, "2001:db8::/32"},
		{"prefix6 with host bits normalized", "2001:db8::1/32", KindPrefix6, "2001:db8::/32"},

		{"whitespace around valid asn", "  262248  ", KindASN, "AS262248"},
		{"whitespace only", "   ", KindInvalid, ""},
		{"empty input", "", KindInvalid, ""},

		{"malformed text", "not-a-resource", KindInvalid, ""},
		{"malformed partial ip", "1.2.3", KindInvalid, ""},
		{"malformed ip octet overflow", "300.300.300.300", KindInvalid, ""},
		{"malformed prefix bits overflow", "192.0.2.0/33", KindInvalid, ""},
		{"malformed prefix no address", "/24", KindInvalid, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotKind, gotNormal := ClassifyResource(tc.raw)
			if gotKind != tc.wantKind {
				t.Errorf("ClassifyResource(%q) kind = %q, want %q", tc.raw, gotKind, tc.wantKind)
			}
			if gotNormal != tc.wantNormal {
				t.Errorf("ClassifyResource(%q) normalized = %q, want %q", tc.raw, gotNormal, tc.wantNormal)
			}
		})
	}
}

func TestClassifyResourceNeverTouchesNetwork(t *testing.T) {
	// A resource that could plausibly be a valid ASN/IP/prefix but is
	// deliberately unusual should classify purely from its shape, with
	// no attempt to resolve/validate it against anything external. This
	// test exists as a structural guard: ClassifyResource takes no
	// context.Context and no *Client, so it cannot make a network call —
	// pinning that signature is itself the regression guard.
	kind, norm := ClassifyResource("AS4200000000") // private 32-bit ASN range
	if kind != KindASN || norm != "AS4200000000" {
		t.Fatalf("private-range ASN should classify as a plain valid ASN: kind=%s norm=%s", kind, norm)
	}
}
