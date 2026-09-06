package diagnosis

import (
	"strings"
	"testing"

	"trazip/internal/httpintel"
	"trazip/internal/model"
	"trazip/internal/tlsintel"
	"trazip/internal/webintel"
)

// These tests drive httpFindings/finalHopTTFB directly with hand-built
// httpintel.Result fixtures — no live request — pinning down Phase B.1 fix
// #2: http_ttfb must be the final hop's real TTFBMs, never
// Result.DurationMs (the whole multi-hop operation) wearing the wrong name.

func hopWithTiming(status int, ttfbMs, totalMs int64) httpintel.Hop {
	return httpintel.Hop{StatusCode: status, Timing: httpintel.Timing{TTFBMs: ttfbMs, TotalMs: totalMs}}
}

func findEv(evidence []model.Evidence, typ string) (model.Evidence, bool) {
	for _, e := range evidence {
		if e.Type == typ {
			return e, true
		}
	}
	return model.Evidence{}, false
}

// 1. TTFB alto: the limitation must fire, quoting the real TTFB, not the
// total duration.
func TestHTTPFindingsSlowTTFB(t *testing.T) {
	res := httpintel.Result{
		FinalStatus: 200, FinalURL: "https://slow.example/", DurationMs: 1500,
		Redirects: []httpintel.Hop{hopWithTiming(200, 1400, 1500)},
	}
	status, _, evidence, limitations := httpFindings(res)
	if status != StageOK {
		t.Fatalf("Status = %q, want ok for HTTP 200", status)
	}
	ttfb, ok := findEv(evidence, "http_ttfb")
	if !ok || ttfb.Value != "1400ms" {
		t.Errorf("http_ttfb = %+v, want 1400ms", ttfb)
	}
	found := false
	for _, l := range limitations {
		if strings.Contains(l, "1400ms") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a slow-TTFB limitation citing 1400ms, got %v", limitations)
	}
}

// 2. Total alto / TTFB normal: a multi-redirect chain with a fast final
// TTFB must NOT trigger the slow-response limitation — that would blame the
// server for the redirect chain's cumulative time.
func TestHTTPFindingsHighTotalDurationNormalTTFB(t *testing.T) {
	res := httpintel.Result{
		FinalStatus: 200, FinalURL: "https://example.com/final", DurationMs: 3000,
		Redirects: []httpintel.Hop{
			hopWithTiming(301, 200, 250),
			hopWithTiming(301, 180, 230),
			hopWithTiming(200, 90, 120), // fast final hop
		},
	}
	_, _, evidence, limitations := httpFindings(res)
	ttfb, ok := findEv(evidence, "http_ttfb")
	if !ok || ttfb.Value != "90ms" {
		t.Fatalf("http_ttfb = %+v, want the FINAL hop's 90ms, not an earlier redirect's or the total", ttfb)
	}
	total, ok := findEv(evidence, "http_total_duration")
	if !ok || total.Value != "3000ms" {
		t.Errorf("http_total_duration = %+v, want 3000ms", total)
	}
	for _, l := range limitations {
		if strings.Contains(l, "saturación") || strings.Contains(l, "3000ms") {
			t.Errorf("a fast final TTFB must not produce a slow-response limitation, even with a high total duration: %v", limitations)
		}
	}
}

// 3. Redirects: http_ttfb must come from the LAST hop, never the first.
func TestHTTPFindingsRedirectsUseFinalHopTTFB(t *testing.T) {
	res := httpintel.Result{
		FinalStatus: 200, FinalURL: "https://example.com/b",
		Redirects: []httpintel.Hop{
			hopWithTiming(301, 999, 999), // first hop's TTFB must be ignored
			hopWithTiming(200, 42, 60),
		},
	}
	ms, ok := finalHopTTFB(res)
	if !ok || ms != 42 {
		t.Errorf("finalHopTTFB = (%d, %v), want (42, true) — the final hop's own TTFB", ms, ok)
	}
}

// 4. No timing disponible: an empty Redirects slice must not fabricate a
// TTFB evidence entry.
func TestHTTPFindingsNoTimingAvailable(t *testing.T) {
	res := httpintel.Result{FinalStatus: 200, FinalURL: "https://example.com/"}
	_, ok := finalHopTTFB(res)
	if ok {
		t.Error("finalHopTTFB should report unavailable when there are no recorded hops")
	}
	_, _, evidence, _ := httpFindings(res)
	if _, found := findEv(evidence, "http_ttfb"); found {
		t.Error("httpFindings must not fabricate an http_ttfb entry when no hop timing exists")
	}
}

// 5. Request error: the error path in runHTTP returns before httpFindings
// is ever called, so no TTFB/duration evidence is fabricated for a failed
// request — verified structurally here since httpFindings has no Err
// parameter to mishandle in the first place.
func TestHTTPFindingsNeverCalledOnRequestError(t *testing.T) {
	// httpFindings' signature takes no error — a caller literally cannot
	// pass res.Err through to it, which is what keeps runHTTP's early
	// return (on res.Err != "") the only path for a failed request.
	res := httpintel.Result{Err: "context deadline exceeded"}
	// Even if someone did call it on an errored, hop-less Result, no
	// evidence should be fabricated from zero values.
	_, _, evidence, _ := httpFindings(res)
	if _, found := findEv(evidence, "http_ttfb"); found {
		t.Error("must not fabricate http_ttfb from an errored, hop-less Result")
	}
}

// --- Phase B.1.1 fix #1: WebIntel HTTP error propagation ---
//
// webintel.Analyze can return res.Err == "" (DNS/normalization worked) while
// res.HTTP.Err != "" (the HTTP request itself failed) — httpintel.Inspect's
// own error never gets copied up to Result.Err (see webintel.go: it stores
// httpRes in res.HTTP and moves on regardless). deriveWebIntelStages is the
// pure function pulled out of runWebIntelligencePair specifically so this is
// testable without a live network call.

func emptyStagePair() (tls, http DiagnosticStage) {
	return DiagnosticStage{ID: StageIDTLS, Label: "TLS"}, DiagnosticStage{ID: StageIDHTTP, Label: "HTTP", NetworkOut: true}
}

// 1. DNS/normalization succeeded (res.Err == "") but the HTTP request
// itself failed (res.HTTP.Err != "", FinalStatus == 0) — must not fabricate
// http_status="0" or http_ttfb, must preserve the real error, and Status
// must be Unknown (inconclusive), never a fabricated OK/Warning/Problem
// derived from the zero-valued FinalStatus.
func TestDeriveWebIntelStagesHTTPErrorWithoutTopLevelErr(t *testing.T) {
	res := webintel.Result{
		Err: "", // WebIntel itself reports success...
		HTTP: httpintel.Result{
			Err:         "dial tcp: connection refused", // ...but the HTTP leg failed
			FinalStatus: 0,
			Redirects:   []httpintel.Hop{{Err: "dial tcp: connection refused"}},
			DurationMs:  1200,
		},
		DNSChain: []webintel.DNSChainEntry{{Type: "A", Name: "example.invalid", Value: "203.0.113.9", TTL: 300}},
	}
	tlsIn, httpIn := emptyStagePair()
	tlsOut, httpOut := deriveWebIntelStages(res, resolvedTarget{kind: "host", host: "example.invalid"}, tlsIn, httpIn)

	if httpOut.Status != StageUnknown {
		t.Errorf("HTTP Status = %q, want unknown for a failed request", httpOut.Status)
	}
	if !strings.Contains(httpOut.Summary, "connection refused") {
		t.Errorf("Summary = %q, want the real error preserved", httpOut.Summary)
	}
	if _, found := findEv(httpOut.Evidence, "http_status"); found {
		t.Error("must not fabricate http_status when the HTTP request itself failed (FinalStatus is zero-valued, not a real 0 response)")
	}
	if _, found := findEv(httpOut.Evidence, "http_ttfb"); found {
		t.Error("must not fabricate http_ttfb when the HTTP request itself failed")
	}
	if _, found := findEv(httpOut.Evidence, "http_total_duration"); found {
		t.Error("must not present the failed attempt's duration as evidence of a completed response")
	}
	if len(httpOut.Limitations) == 0 {
		t.Error("expected a limitation explaining the failure couldn't be attributed to a specific cause")
	}
	// The DNS chain WebIntel resolved before attempting HTTP is still real,
	// independently-obtained evidence — kept, unlike everything above.
	if _, found := findEv(httpOut.Evidence, "dns_chain"); !found {
		t.Error("expected the real, independently-observed DNS chain evidence to survive the HTTP failure")
	}
	// TLS never ran (res.TLS is nil) — must say so honestly, not Skipped
	// (which would imply a deliberate decision not to check), and must not
	// claim network output it didn't confirm.
	if tlsOut.Status != StageUnknown {
		t.Errorf("TLS Status = %q, want unknown (never confirmed, request failed first)", tlsOut.Status)
	}
	if tlsOut.NetworkOut {
		t.Error("TLS NetworkOut must be false when it never actually ran")
	}
}

// 2. The original res.Err (WebIntel never got past DNS/normalization) path
// must still work identically to before this fix.
func TestDeriveWebIntelStagesTopLevelErr(t *testing.T) {
	res := webintel.Result{Err: "resolución DNS falló: no such host"}
	tlsIn, httpIn := emptyStagePair()
	tlsOut, httpOut := deriveWebIntelStages(res, resolvedTarget{kind: "host", host: "no-existe.invalid"}, tlsIn, httpIn)

	if httpOut.Status != StageUnknown {
		t.Errorf("HTTP Status = %q, want unknown", httpOut.Status)
	}
	if !strings.Contains(httpOut.Summary, "no such host") {
		t.Errorf("Summary = %q, want the real DNS error preserved", httpOut.Summary)
	}
	if tlsOut.Status != StageUnknown {
		t.Errorf("TLS Status = %q, want unknown", tlsOut.Status)
	}
}

// 3. A real HTTP failure that nonetheless got far enough to complete a TLS
// handshake (res.TLS != nil) must describe that TLS result honestly rather
// than discarding it just because HTTP itself failed afterward.
func TestDeriveWebIntelStagesHTTPErrorWithRealTLSResult(t *testing.T) {
	res := webintel.Result{
		HTTP: httpintel.Result{Err: "unexpected EOF", FinalStatus: 0},
		TLS:  &tlsintel.Result{Protocol: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", ValidationOK: true},
	}
	tlsIn, httpIn := emptyStagePair()
	tlsOut, _ := deriveWebIntelStages(res, resolvedTarget{kind: "host", host: "example.invalid"}, tlsIn, httpIn)

	if tlsOut.Status != StageOK {
		t.Errorf("TLS Status = %q, want ok — the handshake itself genuinely succeeded even though HTTP failed after it", tlsOut.Status)
	}
	if _, found := findEv(tlsOut.Evidence, "tls_handshake"); !found {
		t.Error("expected real TLS handshake evidence to be preserved")
	}
}

// 4. The success path (no error anywhere) must be unaffected by this fix.
func TestDeriveWebIntelStagesSuccess(t *testing.T) {
	res := webintel.Result{
		HTTP: httpintel.Result{FinalStatus: 200, FinalURL: "https://example.com/", Redirects: []httpintel.Hop{{StatusCode: 200}}},
		TLS:  &tlsintel.Result{Protocol: "TLS 1.3", ValidationOK: true},
	}
	tlsIn, httpIn := emptyStagePair()
	tlsOut, httpOut := deriveWebIntelStages(res, resolvedTarget{kind: "host", host: "example.com"}, tlsIn, httpIn)

	if httpOut.Status != StageOK {
		t.Errorf("HTTP Status = %q, want ok for a clean 200", httpOut.Status)
	}
	if tlsOut.Status != StageOK {
		t.Errorf("TLS Status = %q, want ok", tlsOut.Status)
	}
}
