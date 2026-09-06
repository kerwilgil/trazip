// Package httpintel implements the HTTP Inspector (prompt maestro §9 Fase 4,
// módulo 21): a bounded GET/HEAD with a manually-followed redirect chain
// (each hop timed for DNS/connect/TLS/TTFB via httptrace), header capture,
// basic security-header analysis and documented CDN/WAF signal detection.
// Never executes JavaScript, never crawls recursively, and never retains a
// response body beyond an explicit opt-in with an enforced size limit
// (prompt maestro §18 reglas / §12 privacidad).
package httpintel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
)

// DefaultMaxBodyBytes bounds how much of a response body Inspect will ever
// read, regardless of Content-Length.
const DefaultMaxBodyBytes = 512 * 1024

// DefaultMaxRedirects bounds how many redirects Inspect will follow before
// giving up and reporting the chain so far.
const DefaultMaxRedirects = 10

// Timing captures the per-hop breakdown requested by the spec.
type Timing struct {
	DNSMs     int64 `json:"dnsMs"`
	ConnectMs int64 `json:"connectMs"`
	TLSMs     int64 `json:"tlsMs"`
	TTFBMs    int64 `json:"ttfbMs"`
	TotalMs   int64 `json:"totalMs"`
}

// Hop is one request in the redirect chain.
type Hop struct {
	URL        string      `json:"url"`
	Method     string      `json:"method"`
	StatusCode int         `json:"statusCode"`
	Location   string      `json:"location,omitempty"` // Location header, if this hop redirected
	Headers    http.Header `json:"headers"`
	Timing     Timing      `json:"timing"`
	Err        string      `json:"err,omitempty"`
}

// SecurityHeader reports the presence/value of one well-known hardening
// header, never asserting a verdict — just what was observed.
type SecurityHeader struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
}

var securityHeaderNames = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

// Signal is one piece of documented evidence toward a CDN/WAF inference —
// never a bare verdict, always the header that triggered it (Evidence model,
// prompt maestro §8/§10).
type Signal struct {
	Label    string `json:"label"`    // e.g. "Cloudflare"
	Evidence string `json:"evidence"` // e.g. `header "cf-ray" presente`
}

// Result is the outcome of inspecting one URL.
type Result struct {
	RequestedURL    string           `json:"requestedURL"`
	FinalURL        string           `json:"finalURL"`
	Method          string           `json:"method"`
	Redirects       []Hop            `json:"redirects"`
	FinalStatus     int              `json:"finalStatus"`
	Headers         http.Header      `json:"headers"`
	SecurityHeaders []SecurityHeader `json:"securityHeaders"`
	Signals         []Signal         `json:"signals"`
	BodyBytesRead   int64            `json:"bodyBytesRead"`
	BodyTruncated   bool             `json:"bodyTruncated"`
	Body            []byte           `json:"-"` // only populated when keepBody is true; never sent to the GUI (raw page bytes stay server-side)
	DurationMs      int64            `json:"durationMs"`
	Err             string           `json:"err,omitempty"`
	Cause           error            `json:"-"`
}

// Inspect performs a bounded GET/HEAD against rawURL, following redirects up
// to maxRedirects (0 uses DefaultMaxRedirects). keepBody retains up to
// maxBodyBytes (0 uses DefaultMaxBodyBytes) of the response body for callers
// that need it (e.g. the URL analyzer's hostname/IP extraction, módulo 18
// paso 8) — the standalone HTTP Inspector tool should pass keepBody=false.
func Inspect(ctx context.Context, rawURL, method string, maxRedirects int, maxBodyBytes int64, keepBody bool) Result {
	start := time.Now()
	if method == "" {
		method = http.MethodGet
	}
	if maxRedirects <= 0 {
		maxRedirects = DefaultMaxRedirects
	}
	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultMaxBodyBytes
	}

	res := Result{RequestedURL: rawURL, Method: method}
	current := rawURL
	if _, err := url.Parse(current); err != nil {
		res.Err = "URL inválida: " + err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // we follow redirects manually to time and cap each hop
		},
	}

	for i := 0; i <= maxRedirects; i++ {
		hop, body, err := doHop(ctx, client, current, method, maxBodyBytes, keepBody)
		if err != nil {
			hop.Err = err.Error()
			res.Redirects = append(res.Redirects, hop)
			res.Err = err.Error()
			res.Cause = err
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}
		res.Redirects = append(res.Redirects, hop)

		if !isRedirectStatus(hop.StatusCode) || hop.Location == "" {
			res.FinalURL = current
			res.FinalStatus = hop.StatusCode
			res.Headers = hop.Headers
			res.BodyBytesRead = int64(len(body))
			res.BodyTruncated = int64(len(body)) >= maxBodyBytes
			if keepBody {
				res.Body = body
			}
			res.SecurityHeaders = analyzeSecurityHeaders(hop.Headers)
			res.Signals = detectSignals(hop.Headers)
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}

		next, err := resolveLocation(current, hop.Location)
		if err != nil {
			res.Err = fmt.Sprintf("Location inválida en %s: %s", current, err.Error())
			res.Cause = err
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}
		current = next
	}

	res.Err = fmt.Sprintf("se alcanzó el límite de %d redirects sin resolver", maxRedirects)
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

func isRedirectStatus(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

func resolveLocation(base, location string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	loc, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	return baseURL.ResolveReference(loc).String(), nil
}

func doHop(ctx context.Context, client *http.Client, rawURL, method string, maxBodyBytes int64, keepBody bool) (Hop, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return Hop{URL: rawURL, Method: method}, nil, err
	}
	req.Header.Set("User-Agent", "TRAZIP/1.0 (+web intelligence inspector; passive, single request)")

	var t Timing
	var dnsStart, connectStart, tlsStart, reqStart time.Time
	trace := &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:              func(httptrace.DNSDoneInfo) { t.DNSMs = time.Since(dnsStart).Milliseconds() },
		ConnectStart:         func(string, string) { connectStart = time.Now() },
		ConnectDone:          func(string, string, error) { t.ConnectMs = time.Since(connectStart).Milliseconds() },
		TLSHandshakeStart:    func() { tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { t.TLSMs = time.Since(tlsStart).Milliseconds() },
		GotFirstResponseByte: func() { t.TTFBMs = time.Since(reqStart).Milliseconds() },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	reqStart = time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Hop{URL: rawURL, Method: method, Timing: t}, nil, err
	}
	defer resp.Body.Close()

	var body []byte
	if keepBody || method == http.MethodGet {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	}
	t.TotalMs = time.Since(reqStart).Milliseconds()

	return Hop{
		URL:        rawURL,
		Method:     method,
		StatusCode: resp.StatusCode,
		Location:   resp.Header.Get("Location"),
		Headers:    resp.Header,
		Timing:     t,
	}, body, nil
}

func analyzeSecurityHeaders(h http.Header) []SecurityHeader {
	out := make([]SecurityHeader, 0, len(securityHeaderNames))
	for _, name := range securityHeaderNames {
		v := h.Get(name)
		out = append(out, SecurityHeader{Name: name, Present: v != "", Value: v})
	}
	return out
}

// detectSignals infers CDN/WAF presence purely from documented, publicly
// known header conventions — always paired with the exact evidence, never a
// bare label (prompt maestro §21 "Server/CDN/WAF como inferencia con
// evidencia").
func detectSignals(h http.Header) []Signal {
	var sig []Signal
	add := func(label, evidence string) { sig = append(sig, Signal{Label: label, Evidence: evidence}) }

	server := strings.ToLower(h.Get("Server"))
	switch {
	case strings.Contains(server, "cloudflare"):
		add("Cloudflare", `header "Server: `+h.Get("Server")+`"`)
	case strings.Contains(server, "cloudfront"):
		add("Amazon CloudFront", `header "Server: `+h.Get("Server")+`"`)
	case strings.Contains(server, "awselb"):
		add("AWS Elastic Load Balancer", `header "Server: `+h.Get("Server")+`"`)
	case strings.Contains(server, "akamaighost"):
		add("Akamai", `header "Server: `+h.Get("Server")+`"`)
	case strings.Contains(server, "varnish"):
		add("Varnish (caché/CDN)", `header "Server: `+h.Get("Server")+`"`)
	case strings.Contains(server, "sucuri"):
		add("Sucuri (WAF)", `header "Server: `+h.Get("Server")+`"`)
	}

	if h.Get("Cf-Ray") != "" {
		add("Cloudflare", `header "cf-ray" presente`)
	}
	if h.Get("X-Amz-Cf-Id") != "" {
		add("Amazon CloudFront", `header "x-amz-cf-id" presente`)
	}
	if h.Get("X-Akamai-Transformed") != "" || h.Get("X-Akamai-Request-Id") != "" {
		add("Akamai", `header "x-akamai-*" presente`)
	}
	if h.Get("X-Sucuri-Id") != "" || h.Get("X-Sucuri-Cache") != "" {
		add("Sucuri (WAF)", `header "x-sucuri-*" presente`)
	}
	if h.Get("X-Vercel-Id") != "" {
		add("Vercel", `header "x-vercel-id" presente`)
	}
	if h.Get("X-Fastly-Request-Id") != "" || h.Get("Fastly-Debug-Path") != "" {
		add("Fastly", `header "x-fastly-*"/"fastly-*" presente`)
	}
	if strings.Contains(strings.ToLower(h.Get("X-Powered-By")), "asp.net") {
		add("ASP.NET", `header "X-Powered-By: `+h.Get("X-Powered-By")+`"`)
	}

	return sig
}
