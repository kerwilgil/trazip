package diagnosis

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"trazip/internal/bgp"
)

// These tests pin down the Phase B.1 RPKI regression: RPKIValidate must be
// asked about the REAL announced prefix RIPEstat resolves (e.g.
// "1.1.1.0/24"), never a synthesized /32 or /128 — querying the wrong one
// reports a false "invalid" for nearly any address whose ROA has a
// maxLength shorter than the query (caught live against 1.1.1.1: see
// stage_routing_security.go's own doc comment). A hermetic httptest server
// stands in for RIPEstat, so this is deterministic and network-free.

func hermeticRIPEstat(t *testing.T, routingStatusJSON, rpkiValidateJSON string, onRPKIRequest func(*http.Request)) *bgp.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "routing-status"):
			w.Write([]byte(routingStatusJSON))
		case strings.Contains(r.URL.Path, "rpki-validation"):
			if onRPKIRequest != nil {
				onRPKIRequest(r)
			}
			w.Write([]byte(rpkiValidateJSON))
		default:
			t.Errorf("unexpected RIPEstat path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return &bgp.Client{HTTPClient: srv.Client(), BaseURL: srv.URL}
}

// 1. Announced /24 + ROA maxLength /24 → VALID, and RPKIValidate is asked
// about the real /24, never a synthesized /32.
func TestRoutingSecurityUsesRealPrefixNotSynthetic32(t *testing.T) {
	var gotPrefix, gotResource string
	client := hermeticRIPEstat(t,
		`{"status":"ok","data":{"resource":"1.1.1.0/24","origins":[{"origin":13335}]}}`,
		`{"status":"ok","data":{"status":"valid","validating_roas":[{"origin":"13335","prefix":"1.1.1.0/24","validity":"valid","max_length":24}]}}`,
		func(r *http.Request) {
			gotResource = r.URL.Query().Get("resource")
			gotPrefix = r.URL.Query().Get("prefix")
		},
	)

	ip := netip.MustParseAddr("1.1.1.1") // host IP inside the announced /24
	s := runRoutingSecurity(context.Background(), Dependencies{BGP: client}, true, ip, ModeStandard)

	if gotPrefix != "1.1.1.0/24" {
		t.Errorf("RPKIValidate was asked about prefix=%q, want the real announced 1.1.1.0/24", gotPrefix)
	}
	if gotPrefix == "1.1.1.1/32" {
		t.Fatal("regression: RPKIValidate was asked about a synthesized /32 instead of the real announced prefix")
	}
	if gotResource != "13335" {
		t.Errorf("RPKIValidate was asked about ASN resource=%q, want 13335", gotResource)
	}
	if s.Status != StageOK {
		t.Errorf("Status = %q, want ok for a valid ROA covering the real announced prefix", s.Status)
	}
	if !strings.Contains(s.Summary, "válido") {
		t.Errorf("Summary = %q, want it to say RPKI is valid", s.Summary)
	}
}

// 2. IPv6 equivalent: a host address inside an announced IPv6 prefix must
// use that real prefix too, never a synthesized /128.
func TestRoutingSecurityUsesRealPrefixIPv6(t *testing.T) {
	var gotPrefix string
	client := hermeticRIPEstat(t,
		`{"status":"ok","data":{"resource":"2606:4700:4700::/48","origins":[{"origin":13335}]}}`,
		`{"status":"ok","data":{"status":"valid","validating_roas":[{"origin":"13335","prefix":"2606:4700:4700::/48","validity":"valid","max_length":48}]}}`,
		func(r *http.Request) { gotPrefix = r.URL.Query().Get("prefix") },
	)

	ip := netip.MustParseAddr("2606:4700:4700::1111")
	s := runRoutingSecurity(context.Background(), Dependencies{BGP: client}, true, ip, ModeStandard)

	if gotPrefix != "2606:4700:4700::/48" {
		t.Errorf("RPKIValidate was asked about prefix=%q, want the real announced 2606:4700:4700::/48", gotPrefix)
	}
	if gotPrefix == "2606:4700:4700::1111/128" {
		t.Fatal("regression: RPKIValidate was asked about a synthesized /128 instead of the real announced prefix")
	}
	if s.Status != StageOK {
		t.Errorf("Status = %q, want ok", s.Status)
	}
}

// 3. When RIPEstat doesn't resolve a covering prefix at all, this package
// must not guess one — RPKI validation is skipped, honestly, rather than
// querying a fabricated prefix.
func TestRoutingSecuritySkipsRPKIWithoutRealPrefix(t *testing.T) {
	rpkiCalled := false
	client := hermeticRIPEstat(t,
		`{"status":"ok","data":{"resource":"","origins":[{"origin":64500}]}}`,
		`{"status":"ok","data":{"status":"valid","validating_roas":[]}}`,
		func(r *http.Request) { rpkiCalled = true },
	)

	ip := netip.MustParseAddr("93.184.216.34") // a real, publicly-routed address (classify.IsPublic must accept it)
	s := runRoutingSecurity(context.Background(), Dependencies{BGP: client}, true, ip, ModeStandard)

	if rpkiCalled {
		t.Error("RPKIValidate must not be called when RIPEstat didn't resolve a real prefix")
	}
	// Unknown, not OK: zero origins were actually proven RPKI valid here —
	// this is inconclusive, never a clean bill of health (V1 hardening
	// finding #5, no-prefix status semantics fix).
	if s.Status != StageUnknown {
		t.Errorf("Status = %q, want unknown (announced, but nothing was actually validated)", s.Status)
	}
	if !strings.Contains(s.Summary, "no fue posible validar RPKI") {
		t.Errorf("Summary = %q, want it to say RPKI could not be validated", s.Summary)
	}
	if strings.Contains(s.Summary, "válido") {
		t.Errorf("Summary = %q, must never claim RPKI is valid when it was never checked", s.Summary)
	}
}

// --- V1 hardening finding #5: MOAS (Multiple Origin AS) — every unique
// origin ASN RIPEstat returns must be validated, never just Origins[0]. ---

// hermeticRIPEstatMOAS is hermeticRIPEstat's MOAS-capable sibling: it
// answers rpki-validation differently per queried ASN (resource=), and
// optionally records every ASN actually queried, so a test can assert both
// "every origin was validated" and "no origin was skipped/duplicated".
func hermeticRIPEstatMOAS(t *testing.T, routingStatusJSON string, rpkiByASN map[string]string, queriedASNs *[]string) *bgp.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "routing-status"):
			w.Write([]byte(routingStatusJSON))
		case strings.Contains(r.URL.Path, "rpki-validation"):
			asn := r.URL.Query().Get("resource")
			if queriedASNs != nil {
				*queriedASNs = append(*queriedASNs, asn)
			}
			body, ok := rpkiByASN[asn]
			if !ok {
				t.Errorf("unexpected RPKI validation request for ASN resource=%q", asn)
				return
			}
			w.Write([]byte(body))
		default:
			t.Errorf("unexpected RIPEstat path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return &bgp.Client{HTTPClient: srv.Client(), BaseURL: srv.URL}
}

const moasRoutingStatusJSON = `{"status":"ok","data":{"resource":"93.184.216.0/24","origins":[{"origin":64500},{"origin":64501}]}}`

func validROAJSON(asn string) string {
	return `{"status":"ok","data":{"status":"valid","validating_roas":[{"origin":"` + asn + `","prefix":"93.184.216.0/24","validity":"valid","max_length":24}]}}`
}

func invalidROAJSON(asn string) string {
	return `{"status":"ok","data":{"status":"invalid","validating_roas":[{"origin":"` + asn + `","prefix":"93.184.216.0/24","validity":"invalid_asn","max_length":24}]}}`
}

// A. MOAS with one valid and one invalid origin: both must be queried, the
// stage must escalate to StageWarning, and the summary must name the
// invalid origin without ever declaring a confirmed hijack/attack.
func TestRoutingSecurityMOASMixedValidInvalid(t *testing.T) {
	var queried []string
	client := hermeticRIPEstatMOAS(t, moasRoutingStatusJSON, map[string]string{
		"64500": validROAJSON("64500"),
		"64501": invalidROAJSON("64501"),
	}, &queried)

	ip := netip.MustParseAddr("93.184.216.5")
	s := runRoutingSecurity(context.Background(), Dependencies{BGP: client}, true, ip, ModeStandard)

	if len(queried) != 2 {
		t.Fatalf("RPKIValidate was called for %v, want exactly 2 origins queried", queried)
	}
	if s.Status != StageWarning {
		t.Errorf("Status = %q, want warning when at least one origin is RPKI invalid", s.Status)
	}
	if !strings.Contains(s.Summary, "AS64501") {
		t.Errorf("Summary = %q, want it to name the invalid origin AS64501", s.Summary)
	}
	for _, forbidden := range []string{"secuestro confirmado", "ataque confirmado", "hijack confirmado"} {
		if strings.Contains(s.Summary, forbidden) {
			t.Errorf("Summary must never declare a confirmed hijack/attack: contains %q in %q", forbidden, s.Summary)
		}
	}
	var originEvidence int
	for _, e := range s.Evidence {
		if e.Type == "bgp_origin_asn" {
			originEvidence++
		}
	}
	if originEvidence != 2 {
		t.Errorf("bgp_origin_asn evidence entries = %d, want 2 (one per origin)", originEvidence)
	}
}

// B. MOAS where every origin validates: StageOK.
func TestRoutingSecurityMOASAllValid(t *testing.T) {
	client := hermeticRIPEstatMOAS(t, moasRoutingStatusJSON, map[string]string{
		"64500": validROAJSON("64500"),
		"64501": validROAJSON("64501"),
	}, nil)

	ip := netip.MustParseAddr("93.184.216.5")
	s := runRoutingSecurity(context.Background(), Dependencies{BGP: client}, true, ip, ModeStandard)

	if s.Status != StageOK {
		t.Errorf("Status = %q, want ok when every MOAS origin validates", s.Status)
	}
}

// C. MOAS where one origin is valid and the other can't be validated at
// all (no invalid origin): the set must never be declared fully "valid" —
// StageUnknown.
func TestRoutingSecurityMOASPartialUnknown(t *testing.T) {
	client := hermeticRIPEstatMOAS(t, moasRoutingStatusJSON, map[string]string{
		"64500": validROAJSON("64500"),
		"64501": `{"status":"ok","data":{"status":"unknown","validating_roas":[]}}`,
	}, nil)

	ip := netip.MustParseAddr("93.184.216.5")
	s := runRoutingSecurity(context.Background(), Dependencies{BGP: client}, true, ip, ModeStandard)

	if s.Status != StageUnknown {
		t.Errorf("Status = %q, want unknown: one origin unvalidated, none invalid — never a blanket ok", s.Status)
	}
}

// D. A single origin (the common case) keeps behaving exactly as before —
// covered already by TestRoutingSecurityUsesRealPrefixNotSynthetic32/IPv6
// above, which both exercise a one-origin RouteStatus end to end.

// E. MOAS with no resolved route.Prefix: RPKI must not be called for any
// origin, and no prefix may be synthesized.
func TestRoutingSecurityMOASNoPrefixSkipsRPKIForAllOrigins(t *testing.T) {
	var queried []string
	client := hermeticRIPEstatMOAS(t,
		`{"status":"ok","data":{"resource":"","origins":[{"origin":64500},{"origin":64501}]}}`,
		nil, &queried,
	)

	ip := netip.MustParseAddr("93.184.216.5")
	s := runRoutingSecurity(context.Background(), Dependencies{BGP: client}, true, ip, ModeStandard)

	if len(queried) != 0 {
		t.Errorf("RPKIValidate was called for %v, want none — no resolved prefix means no validation at all", queried)
	}
	// Unknown, not OK: neither origin was actually proven RPKI valid —
	// inconclusive, never a clean bill of health (V1 hardening finding #5,
	// no-prefix status semantics fix).
	if s.Status != StageUnknown {
		t.Errorf("Status = %q, want unknown (both origins announced, but nothing was actually validated)", s.Status)
	}
	if !strings.Contains(s.Summary, "AS64500") || !strings.Contains(s.Summary, "AS64501") {
		t.Errorf("Summary = %q, want it to name both observed origins", s.Summary)
	}
	if !strings.Contains(s.Summary, "no fue posible validar RPKI") {
		t.Errorf("Summary = %q, want it to say RPKI could not be validated", s.Summary)
	}
	if strings.Contains(s.Summary, "válido") {
		t.Errorf("Summary = %q, must never claim RPKI is valid when it was never checked", s.Summary)
	}
	for _, e := range s.Evidence {
		if e.Type == "rpki_status" {
			t.Errorf("no rpki_status evidence should exist when RPKIValidate was never called: %+v", e)
		}
	}
}

// RIPEstat repeating the same origin must not be treated as a second MOAS
// participant.
func TestRoutingSecurityDeduplicatesRepeatedOrigin(t *testing.T) {
	var queried []string
	client := hermeticRIPEstatMOAS(t,
		`{"status":"ok","data":{"resource":"93.184.216.0/24","origins":[{"origin":64500},{"origin":64500}]}}`,
		map[string]string{"64500": validROAJSON("64500")},
		&queried,
	)

	ip := netip.MustParseAddr("93.184.216.5")
	s := runRoutingSecurity(context.Background(), Dependencies{BGP: client}, true, ip, ModeStandard)

	if len(queried) != 1 {
		t.Errorf("RPKIValidate was called for %v, want exactly 1 (the repeated origin deduplicated)", queried)
	}
	if s.Status != StageOK {
		t.Errorf("Status = %q, want ok", s.Status)
	}
}
