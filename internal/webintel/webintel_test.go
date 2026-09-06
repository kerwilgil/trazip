package webintel

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
)

// IP-literal targets keep these tests hermetic: net/http's own DNS
// resolution never has to touch real DNS, and Analyze's fast path skips its
// own DNS query for literal IPs too (see the netip.ParseAddr(host) branch).

func TestAnalyzeSimplePage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write([]byte(`<html><body><a href="https://cdn.example.test/lib.js">lib</a> contact 198.51.100.7</body></html>`))
	}))
	defer srv.Close()

	res := Analyze(context.Background(), nil, srv.URL, "")
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if res.HTTP.FinalStatus != http.StatusOK {
		t.Errorf("FinalStatus = %d, want 200", res.HTTP.FinalStatus)
	}
	if len(res.ContactedEndpoints) != 1 {
		t.Fatalf("ContactedEndpoints = %+v, want exactly the server's own IP", res.ContactedEndpoints)
	}
	if len(res.DNSChain) != 0 {
		t.Errorf("DNSChain should be empty for an IP-literal target, got %+v", res.DNSChain)
	}

	foundHost, foundIP := false, false
	for _, h := range res.ExtractedHostnames {
		if h == "cdn.example.test" {
			foundHost = true
		}
	}
	for _, ip := range res.ExtractedIPs {
		if ip == "198.51.100.7" {
			foundIP = true
		}
	}
	if !foundHost {
		t.Errorf("expected cdn.example.test among ExtractedHostnames, got %v", res.ExtractedHostnames)
	}
	if !foundIP {
		t.Errorf("expected 198.51.100.7 among ExtractedIPs, got %v", res.ExtractedIPs)
	}
}

func TestAnalyzeGraphHasDomainAndIPNodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res := Analyze(context.Background(), nil, srv.URL, "")
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	var hasDomain, hasIP bool
	for _, n := range res.Graph.Nodes {
		if n.Kind == "domain" {
			hasDomain = true
		}
		if n.Kind == "ip" {
			hasIP = true
		}
	}
	if !hasDomain {
		t.Error("expected a domain node in the graph")
	}
	if !hasIP {
		t.Error("expected an ip node in the graph")
	}
}

func TestAnalyzeRedirectChainAcrossPorts(t *testing.T) {
	// Two servers, both bound to 127.0.0.1: the first redirects to the
	// second, exercising the redirect-hop registration path without needing
	// real DNS for a "different domain."
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("final"))
	}))
	defer second.Close()

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL+"/", http.StatusFound)
	}))
	defer first.Close()

	res := Analyze(context.Background(), nil, first.URL, "")
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if len(res.HTTP.Redirects) != 2 {
		t.Fatalf("Redirects = %d hops, want 2", len(res.HTTP.Redirects))
	}
	if res.HTTP.FinalStatus != http.StatusOK {
		t.Errorf("FinalStatus = %d, want 200", res.HTTP.FinalStatus)
	}
}

func TestAnalyzeInvalidInput(t *testing.T) {
	res := Analyze(context.Background(), nil, "", "")
	if res.Err == "" {
		t.Error("expected an error for empty input")
	}
	if res.Error == nil || res.Error.Code != "invalid_input" || res.Error.Stage != "Analysis" {
		t.Fatalf("structured error = %+v, want invalid_input at Analysis", res.Error)
	}
	if res.Error.TechnicalDetail == "" || res.Error.FriendlyMessageES == "" || res.Error.FriendlyMessageEN == "" {
		t.Fatalf("error must preserve technical and bilingual friendly messages: %+v", res.Error)
	}
	assertResultCollections(t, res)
}

func TestAnalyzeUnreachableHost(t *testing.T) {
	res := Analyze(context.Background(), nil, "http://127.0.0.1:1", "")
	if res.Err != "" {
		t.Fatalf("Analyze() itself should not fail just because the HTTP hop errors: %s", res.Err)
	}
	if res.HTTP.Err == "" {
		t.Error("expected the embedded HTTP result to report the connection error")
	}
	if res.Error == nil || res.Error.Code != "connection_refused" || res.Error.Stage != "HTTP" {
		t.Fatalf("structured error = %+v, want connection_refused at HTTP", res.Error)
	}
	assertResultCollections(t, res)
}

func TestAnalyzeOperationDeadlineUsesSinglePipelineBudget(t *testing.T) {
	old := operationTimeout
	operationTimeout = 15 * time.Millisecond
	t.Cleanup(func() { operationTimeout = old })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := Analyze(context.Background(), nil, srv.URL, "")
	if res.Error == nil || res.Error.Code != "operation_timeout" {
		t.Fatalf("structured error = %+v, want operation_timeout", res.Error)
	}
	assertResultCollections(t, res)
}

func TestAnalyzeRedirectLimitIsStructured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer srv.Close()

	res := Analyze(context.Background(), nil, srv.URL, "")
	if res.Error == nil || res.Error.Code != "redirect_limit" || res.Error.Stage != "Redirect" {
		t.Fatalf("structured error = %+v, want redirect_limit at Redirect", res.Error)
	}
	assertResultCollections(t, res)
}

func TestAnalyzeNXDOMAINUsesDNSResultBeforeHTTP(t *testing.T) {
	resolver := newNXDOMAINResolver(t)
	res := Analyze(context.Background(), nil, "missing.example.test", resolver)
	if res.Error == nil || res.Error.Code != "dns_nxdomain" || res.Error.Stage != "DNS" || res.Error.Retryable {
		t.Fatalf("structured error = %+v, want non-retryable dns_nxdomain", res.Error)
	}
	assertResultCollections(t, res)
}

func TestAnalyzeUntrustedCertificateIsTLSValidation(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	res := Analyze(context.Background(), nil, srv.URL, "")
	if res.Error == nil || res.Error.Code != "tls_validation" || res.Error.Stage != "TLS" || res.Error.Retryable {
		t.Fatalf("structured error = %+v, want non-retryable tls_validation", res.Error)
	}
	if res.Error.TechnicalDetail == "" {
		t.Fatal("TLS technical detail was lost")
	}
}

func TestClassifyFailurePrefersWrappedTypedCauses(t *testing.T) {
	deadline := fmt.Errorf("wrapper: %w", context.DeadlineExceeded)
	dnsCause := fmt.Errorf("wrapper: %w", &net.DNSError{IsNotFound: true})
	refused := fmt.Errorf("wrapper: %w", &net.OpError{Err: fmt.Errorf("wrapped: %w", syscall.ECONNREFUSED)})
	tlsCause := fmt.Errorf("wrapper: %w", x509.UnknownAuthorityError{})
	tests := []struct {
		stage               string
		cause               error
		wantCode, wantStage string
		wantRetry           bool
	}{
		{"HTTP", deadline, "operation_timeout", "HTTP", true},
		{"DNS", dnsCause, "dns_nxdomain", "DNS", false},
		{"HTTP", refused, "connection_refused", "HTTP", true},
		{"HTTP", tlsCause, "tls_validation", "TLS", false},
		{"HTTP", nil, "redirect_limit", "Redirect", false},
	}
	for _, tt := range tests {
		technical := "ordinary failure"
		if tt.wantCode == "redirect_limit" {
			technical = "se alcanzó el límite de redirects"
		}
		code, stage := classifyFailure(tt.stage, tt.cause, technical, "")
		if code != tt.wantCode || stage != tt.wantStage || retryable(code) != tt.wantRetry {
			t.Errorf("classifyFailure(%q, %v) = (%q, %q, retry=%v), want (%q, %q, retry=%v)", tt.stage, tt.cause, code, stage, retryable(code), tt.wantCode, tt.wantStage, tt.wantRetry)
		}
	}
}

func newNXDOMAINResolver(t *testing.T) string {
	t.Helper()
	cancel, addr, err := dnstest.UDPServer("127.0.0.1:0", func(s *dns.Server) {
		s.Handler = dns.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			dnsutil.SetReply(m, r)
			m.Rcode = dns.RcodeNameError
			m.WriteTo(w)
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	return addr
}

func assertResultCollections(t *testing.T, res Result) {
	t.Helper()
	encoded, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"dnsChain", "contactedEndpoints", "extractedHostnames", "extractedIPs", "nodes", "edges", "redirects", "securityHeaders", "signals"} {
		if strings.Contains(string(encoded), `"`+key+`":null`) {
			t.Fatalf("%s serialized as null: %s", key, encoded)
		}
	}
}

func TestExtractHostsAndIPsDedupesAndSorts(t *testing.T) {
	body := "visit example.test and example.test again, or 10.0.0.5 and 10.0.0.5"
	hosts, ips := extractHostsAndIPs(body, nil)
	if len(hosts) != 1 || hosts[0] != "example.test" {
		t.Errorf("hosts = %v, want [example.test] deduped", hosts)
	}
	if len(ips) != 1 || ips[0] != "10.0.0.5" {
		t.Errorf("ips = %v, want [10.0.0.5] deduped", ips)
	}
}
