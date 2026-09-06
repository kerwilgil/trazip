// Package webintel implements the URL/domain analyzer pipeline (prompt
// maestro §9 Fase 4, módulo 18): normalize → resolve DNS/CNAME chain →
// follow redirects → inspect TLS → collect headers → detect CDN/WAF →
// extract hostnames/IPs from the response → correlate with GeoIP/ASN →
// build a domain→DNS→IP→ASN→país→certificado graph.
//
// RDAP/BGP/RPKI enrichment (módulo 22) is deliberately NOT part of this
// pipeline — the spec lists it as on-demand enrichment (módulo 4 "RDAP bajo
// demanda"), so it stays a separate, explicit action the GUI triggers per
// endpoint rather than something every analysis silently fires off.
package webintel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"trazip/internal/dnsintel"
	"trazip/internal/httpintel"
	"trazip/internal/intel/classify"
	"trazip/internal/intel/geoip"
	"trazip/internal/tlsintel"
)

// DefaultResolver is used to walk the DNS/CNAME chain when the caller does
// not specify one — a fixed, well-documented public resolver (§5.7:
// enrichment is explicit, never a hidden default masquerading as local).
const DefaultResolver = "1.1.1.1:53"

const DefaultOperationTimeout = 25 * time.Second

// operationTimeout is mutable only for package tests of the global deadline.
var operationTimeout = DefaultOperationTimeout

// DNSChainEntry is one hop in the resolution chain for the analyzed host.
type DNSChainEntry struct {
	Type  string `json:"type"` // "CNAME", "A" or "AAAA"
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// ContactedEndpoint is one hostname+IP pair the analysis actually touched —
// either via DNS resolution or an HTTP redirect hop — enriched with offline
// GeoIP/ASN/classification (never RDAP; that stays on-demand, see above).
type ContactedEndpoint struct {
	Hostname string   `json:"hostname,omitempty"`
	IP       string   `json:"ip"`
	Country  string   `json:"country,omitempty"`
	ASN      uint32   `json:"asn,omitempty"`
	Org      string   `json:"org,omitempty"`
	IsPublic bool     `json:"isPublic"`
	Classes  []string `json:"classes"`
}

// GraphNode and GraphEdge model the domain→DNS→IP→ASN→país→certificado
// graph requested by módulo 18 paso 10.
type GraphNode struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"` // domain | dns | ip | asn | country | cert
	Label string `json:"label"`
}

type GraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"` // resolves_to | redirects_to | in_asn | in_country | serves_cert
}

type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// Error is the stable failure contract. The technical cause stays available
// for diagnostics but is never intended as the primary UI message.
type Error struct {
	Code              string `json:"code"`
	Stage             string `json:"stage"`
	FriendlyMessageES string `json:"friendlyMessageES"`
	FriendlyMessageEN string `json:"friendlyMessageEN"`
	TechnicalDetail   string `json:"technicalDetail"`
	Retryable         bool   `json:"retryable"`
}

// Result is the full pipeline output for one input URL/domain.
type Result struct {
	InputURL           string              `json:"inputURL"`
	NormalizedURL      string              `json:"normalizedURL"`
	Resolver           string              `json:"resolver"`
	DNSChain           []DNSChainEntry     `json:"dnsChain"`
	HTTP               httpintel.Result    `json:"http"`
	TLS                *tlsintel.Result    `json:"tls,omitempty"`
	ContactedEndpoints []ContactedEndpoint `json:"contactedEndpoints"`
	ExtractedHostnames []string            `json:"extractedHostnames"`
	ExtractedIPs       []string            `json:"extractedIPs"`
	Graph              Graph               `json:"graph"`
	DurationMs         int64               `json:"durationMs"`
	Err                string              `json:"err,omitempty"`
	Error              *Error              `json:"error,omitempty"`
}

// Analyze runs the full pipeline. geo may be nil (or unavailable) — GeoIP/ASN
// fields are simply left empty in that case, never invented.
func Analyze(ctx context.Context, geo *geoip.Engine, rawInput, resolverAddr string) (res Result) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if resolverAddr == "" {
		resolverAddr = DefaultResolver
	}
	res = newResult(rawInput, resolverAddr)
	defer func() {
		res.DurationMs = time.Since(start).Milliseconds()
		normalizeResult(&res)
	}()

	normalized, host, err := normalizeURL(rawInput)
	if err != nil {
		res.setError("invalid_input", "Analysis", err.Error(), false)
		return res
	}
	res.NormalizedURL = normalized

	// Step 2: DNS + CNAME chain — skipped when the host is already a literal
	// IP (querying DNS for an address makes no sense and would just fail).
	// Querying type A against a full recursive resolver returns the whole
	// chain (CNAME hops then the terminal A/AAAA records) in one Answer
	// section — no extra round trips needed.
	var finalIPs []string
	if _, err := netip.ParseAddr(host); err == nil {
		finalIPs = append(finalIPs, host)
	} else {
		dnsRes := dnsintel.Query(ctx, host, "A", resolverAddr, false)
		for _, rec := range dnsRes.Records {
			switch rec.Type {
			case "CNAME":
				res.DNSChain = append(res.DNSChain, DNSChainEntry{Type: "CNAME", Name: rec.Name, Value: rec.Value, TTL: rec.TTL})
			case "A", "AAAA":
				res.DNSChain = append(res.DNSChain, DNSChainEntry{Type: rec.Type, Name: rec.Name, Value: rec.Value, TTL: rec.TTL})
				finalIPs = append(finalIPs, rec.Value)
			}
		}
		if strings.EqualFold(dnsRes.RCode, "NXDOMAIN") {
			technical := dnsRes.Err
			if technical == "" {
				technical = "DNS RCODE NXDOMAIN"
			}
			res.setFailure("DNS", dnsRes.Cause, technical, dnsRes.RCode)
			return res
		}
		if dnsRes.Err != "" && len(finalIPs) == 0 {
			res.setFailure("DNS", dnsRes.Cause, dnsRes.Err, dnsRes.RCode)
			return res
		}
	}

	// Steps 3, 4, 6, 7: follow redirects, recording every hop; collect
	// headers; CDN/WAF signals. keepBody=true feeds step 8 below.
	httpRes := httpintel.Inspect(ctx, normalized, "GET", 0, 0, true)
	res.HTTP = httpRes
	if httpRes.Err != "" {
		res.setFailure("HTTP", httpRes.Cause, httpRes.Err, "")
		return res
	}

	// Step 4/9: register every hostname+IP contacted, enriched offline.
	endpoints := map[string]ContactedEndpoint{}
	registerHost := func(hostname string) {
		if hostname == "" {
			return
		}
		if addr, err := netip.ParseAddr(hostname); err == nil {
			registerIP(endpoints, "", addr, geo)
			return
		}
		// Resolve this hostname too if it differs from the original (a
		// redirect can hop to a different domain entirely).
		r := dnsintel.Query(ctx, hostname, "A", resolverAddr, false)
		for _, rec := range r.Records {
			if rec.Type != "A" && rec.Type != "AAAA" {
				continue
			}
			if addr, err := netip.ParseAddr(rec.Value); err == nil {
				registerIP(endpoints, hostname, addr, geo)
			}
		}
	}
	registerHost(host)
	for _, hop := range httpRes.Redirects {
		if u, err := url.Parse(hop.URL); err == nil {
			registerHost(u.Hostname())
		}
	}
	for k := range endpoints {
		res.ContactedEndpoints = append(res.ContactedEndpoints, endpoints[k])
	}
	sort.Slice(res.ContactedEndpoints, func(i, j int) bool { return res.ContactedEndpoints[i].IP < res.ContactedEndpoints[j].IP })

	// Step 5: TLS inspection of the final host.
	if finalURL, err := url.Parse(httpRes.FinalURL); err == nil && finalURL.Scheme == "https" {
		port := 443
		if p := finalURL.Port(); p != "" {
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		}
		tlsRes := tlsintel.Inspect(ctx, finalURL.Hostname(), port, finalURL.Hostname())
		res.TLS = &tlsRes
		if tlsRes.Err != "" {
			res.setFailure("TLS", nil, tlsRes.Err, "")
			return res
		}
		if tlsRes.ValidationError != "" {
			res.setFailure("TLS", nil, tlsRes.ValidationError, "")
		}
	}

	// Step 8: extract hostnames/IPs visible in the HTML body and headers.
	res.ExtractedHostnames, res.ExtractedIPs = extractHostsAndIPs(string(httpRes.Body), httpRes.Headers)

	// Step 10: build the domain → DNS → IP → ASN → país → certificado graph.
	res.Graph = buildGraph(host, res)

	return res
}

func newResult(inputURL, resolver string) Result {
	return Result{
		InputURL: inputURL, Resolver: resolver,
		DNSChain: make([]DNSChainEntry, 0),
		HTTP: httpintel.Result{
			Redirects: make([]httpintel.Hop, 0), Headers: http.Header{},
			SecurityHeaders: make([]httpintel.SecurityHeader, 0), Signals: make([]httpintel.Signal, 0),
		},
		ContactedEndpoints: make([]ContactedEndpoint, 0),
		ExtractedHostnames: make([]string, 0), ExtractedIPs: make([]string, 0),
		Graph: Graph{Nodes: make([]GraphNode, 0), Edges: make([]GraphEdge, 0)},
	}
}

func normalizeResult(res *Result) {
	if res.DNSChain == nil {
		res.DNSChain = make([]DNSChainEntry, 0)
	}
	if res.ContactedEndpoints == nil {
		res.ContactedEndpoints = make([]ContactedEndpoint, 0)
	}
	if res.ExtractedHostnames == nil {
		res.ExtractedHostnames = make([]string, 0)
	}
	if res.ExtractedIPs == nil {
		res.ExtractedIPs = make([]string, 0)
	}
	if res.Graph.Nodes == nil {
		res.Graph.Nodes = make([]GraphNode, 0)
	}
	if res.Graph.Edges == nil {
		res.Graph.Edges = make([]GraphEdge, 0)
	}
	if res.HTTP.Redirects == nil {
		res.HTTP.Redirects = make([]httpintel.Hop, 0)
	}
	if res.HTTP.Headers == nil {
		res.HTTP.Headers = http.Header{}
	}
	if res.HTTP.SecurityHeaders == nil {
		res.HTTP.SecurityHeaders = make([]httpintel.SecurityHeader, 0)
	}
	if res.HTTP.Signals == nil {
		res.HTTP.Signals = make([]httpintel.Signal, 0)
	}
	for i := range res.ContactedEndpoints {
		if res.ContactedEndpoints[i].Classes == nil {
			res.ContactedEndpoints[i].Classes = make([]string, 0)
		}
	}
	if res.TLS != nil && res.TLS.Chain == nil {
		res.TLS.Chain = make([]tlsintel.CertInfo, 0)
	}
}

func (res *Result) setError(code, stage, technical string, retryable bool) {
	res.Err = technical
	res.setIssue(code, stage, technical, retryable)
}

func (res *Result) setIssue(code, stage, technical string, retryable bool) {
	if res.Error != nil {
		return
	}
	res.Error = &Error{Code: code, Stage: stage, TechnicalDetail: technical, Retryable: retryable,
		FriendlyMessageES: friendlyMessage(code, false), FriendlyMessageEN: friendlyMessage(code, true)}
}

func (res *Result) setFailure(stage string, cause error, technical, rcode string) {
	code, classifiedStage := classifyFailure(stage, cause, technical, rcode)
	res.setIssue(code, classifiedStage, technical, retryable(code))
}

func retryable(code string) bool {
	switch code {
	case "dns_timeout", "dns_unreachable", "http_timeout", "connection_refused", "tls_timeout", "operation_timeout":
		return true
	default:
		return false
	}
}

func friendlyMessage(code string, english bool) string {
	messages := map[string][2]string{
		"invalid_input":      {"La URL o el dominio no son válidos.", "The URL or domain is invalid."},
		"dns_nxdomain":       {"No se pudo resolver el dominio.", "The domain could not be resolved."},
		"dns_timeout":        {"La consulta DNS tardó demasiado.", "The DNS query took too long."},
		"dns_unreachable":    {"No se pudo contactar el resolver DNS.", "The DNS resolver could not be reached."},
		"http_timeout":       {"El servidor tardó demasiado en responder.", "The server took too long to respond."},
		"connection_refused": {"El servidor rechazó la conexión.", "The server refused the connection."},
		"http_failure":       {"No se pudo completar la solicitud HTTP.", "The HTTP request could not be completed."},
		"tls_handshake":      {"No se pudo completar la conexión TLS.", "The TLS handshake could not be completed."},
		"tls_validation":     {"No fue posible validar el certificado TLS.", "The TLS certificate could not be validated."},
		"tls_timeout":        {"La conexión TLS tardó demasiado.", "The TLS connection took too long."},
		"redirect_limit":     {"Se alcanzó el límite de redirecciones.", "The redirect limit was reached."},
		"operation_timeout":  {"El análisis tardó demasiado en completarse.", "The analysis took too long to complete."},
		"cancelled":          {"El análisis fue cancelado.", "The analysis was cancelled."},
		"unknown":            {"No se pudo completar el análisis.", "The analysis could not be completed."},
	}
	m, ok := messages[code]
	if !ok {
		m = messages["unknown"]
	}
	if english {
		return m[1]
	}
	return m[0]
}

func classifyFailure(stage string, cause error, technical, rcode string) (string, string) {
	if strings.EqualFold(rcode, "NXDOMAIN") {
		return "dns_nxdomain", "DNS"
	}
	if errors.Is(cause, context.Canceled) {
		return "cancelled", stage
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return "operation_timeout", stage
	}

	var dnsErr *net.DNSError
	if errors.As(cause, &dnsErr) {
		if dnsErr.IsNotFound {
			return "dns_nxdomain", "DNS"
		}
		if dnsErr.IsTimeout {
			return "dns_timeout", "DNS"
		}
		return "dns_unreachable", "DNS"
	}
	var netErr net.Error
	if errors.As(cause, &netErr) && netErr.Timeout() {
		if stage == "TLS" {
			return "tls_timeout", "TLS"
		}
		if stage == "DNS" {
			return "dns_timeout", "DNS"
		}
		return "http_timeout", "HTTP"
	}
	if isConnectionRefused(cause) {
		return "connection_refused", "HTTP"
	}

	var unknownAuthority x509.UnknownAuthorityError
	var invalidCert x509.CertificateInvalidError
	var hostnameErr x509.HostnameError
	if errors.As(cause, &unknownAuthority) || errors.As(cause, &invalidCert) || errors.As(cause, &hostnameErr) {
		return "tls_validation", "TLS"
	}
	var recordHeader tls.RecordHeaderError
	if errors.As(cause, &recordHeader) {
		return "tls_handshake", "TLS"
	}

	lower := strings.ToLower(technical)
	if stage == "HTTP" && strings.Contains(lower, "redirect") && strings.Contains(lower, "límite") {
		return "redirect_limit", "Redirect"
	}
	// Windows may surface WSAECONNREFUSED as localized connectex text rather
	// than syscall.ECONNREFUSED. This is a compatibility fallback after the
	// typed checks above.
	if stage == "HTTP" && (strings.Contains(lower, "connection refused") || strings.Contains(lower, "actively refused")) {
		return "connection_refused", "HTTP"
	}
	if stage == "TLS" && strings.Contains(lower, "validation") {
		return "tls_validation", "TLS"
	}
	if stage == "TLS" && (strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline exceeded")) {
		return "tls_timeout", "TLS"
	}
	if stage == "DNS" && strings.Contains(lower, "timeout") {
		return "dns_timeout", "DNS"
	}
	if stage == "DNS" {
		return "dns_unreachable", "DNS"
	}
	if stage == "TLS" {
		return "tls_handshake", "TLS"
	}
	if strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline exceeded") {
		return "http_timeout", "HTTP"
	}
	return "http_failure", "HTTP"
}

func normalizeURL(raw string) (normalized, host string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("entrada vacía")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("URL inválida: %w", err)
	}
	if u.Hostname() == "" {
		return "", "", fmt.Errorf("no se pudo determinar el host de %q", raw)
	}
	return u.String(), u.Hostname(), nil
}

func registerIP(endpoints map[string]ContactedEndpoint, hostname string, addr netip.Addr, geo *geoip.Engine) {
	key := hostname + "|" + addr.String()
	if _, ok := endpoints[key]; ok {
		return
	}
	ep := ContactedEndpoint{Hostname: hostname, IP: addr.String(), IsPublic: classify.IsPublic(addr)}
	for _, c := range classify.Classify(addr) {
		ep.Classes = append(ep.Classes, string(c))
	}
	if geo != nil && geo.Available() && ep.IsPublic {
		g := geo.Lookup(addr)
		ep.Country = g.Country
		ep.ASN = g.ASN
		ep.Org = g.Org
	}
	endpoints[key] = ep
}

// hostnameCandidate matches domain-like tokens (letters/digits/hyphens with
// at least one dot and a plausible TLD) — a heuristic, not an RFC-1035
// validator: módulo 18 only asks to surface what's visible, not to prove it.
var hostnameCandidate = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b`)
var ipCandidate = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

const maxExtracted = 200

func extractHostsAndIPs(body string, headers map[string][]string) (hosts, ips []string) {
	seenHost := map[string]bool{}
	seenIP := map[string]bool{}

	scan := func(text string) {
		for _, m := range hostnameCandidate.FindAllString(text, maxExtracted) {
			m = strings.ToLower(strings.Trim(m, "."))
			if seenHost[m] || len(hosts) >= maxExtracted {
				continue
			}
			seenHost[m] = true
			hosts = append(hosts, m)
		}
		for _, m := range ipCandidate.FindAllString(text, maxExtracted) {
			if _, err := netip.ParseAddr(m); err != nil {
				continue
			}
			if seenIP[m] || len(ips) >= maxExtracted {
				continue
			}
			seenIP[m] = true
			ips = append(ips, m)
		}
	}

	scan(body)
	for _, vals := range headers {
		for _, v := range vals {
			scan(v)
		}
	}
	sort.Strings(hosts)
	sort.Strings(ips)
	return hosts, ips
}

func buildGraph(originalHost string, res Result) Graph {
	var g Graph
	seen := map[string]bool{}
	addNode := func(id, kind, label string) {
		if seen[id] {
			return
		}
		seen[id] = true
		g.Nodes = append(g.Nodes, GraphNode{ID: id, Kind: kind, Label: label})
	}
	addEdge := func(from, to, kind string) {
		if from == "" || to == "" {
			return
		}
		g.Edges = append(g.Edges, GraphEdge{From: from, To: to, Kind: kind})
	}

	domainID := "domain:" + originalHost
	addNode(domainID, "domain", originalHost)

	prevID := domainID
	for _, hop := range res.DNSChain {
		if hop.Type == "CNAME" {
			id := "dns:" + hop.Value
			addNode(id, "dns", hop.Value)
			addEdge(prevID, id, "resolves_to")
			prevID = id
		} else {
			ipID := "ip:" + hop.Value
			addNode(ipID, "ip", hop.Value)
			addEdge(prevID, ipID, "resolves_to")
		}
	}

	for _, ep := range res.ContactedEndpoints {
		ipID := "ip:" + ep.IP
		addNode(ipID, "ip", ep.IP)
		if ep.ASN != 0 {
			asnID := fmt.Sprintf("asn:%d", ep.ASN)
			label := fmt.Sprintf("AS%d", ep.ASN)
			if ep.Org != "" {
				label += " " + ep.Org
			}
			addNode(asnID, "asn", label)
			addEdge(ipID, asnID, "in_asn")
			if ep.Country != "" {
				countryID := "country:" + ep.Country
				addNode(countryID, "country", ep.Country)
				addEdge(asnID, countryID, "in_country")
			}
		} else if ep.Country != "" {
			countryID := "country:" + ep.Country
			addNode(countryID, "country", ep.Country)
			addEdge(ipID, countryID, "in_country")
		}
	}

	// Redirect chain: host(hop) -> host(next hop), when they differ.
	var lastHost string
	for _, hop := range res.HTTP.Redirects {
		if u, err := url.Parse(hop.URL); err == nil {
			h := u.Hostname()
			if lastHost != "" && lastHost != h {
				addNode("domain:"+lastHost, "domain", lastHost)
				addNode("domain:"+h, "domain", h)
				addEdge("domain:"+lastHost, "domain:"+h, "redirects_to")
			}
			lastHost = h
		}
	}

	if res.TLS != nil && len(res.TLS.Chain) > 0 {
		leaf := res.TLS.Chain[0]
		certID := "cert:" + leaf.SHA256Fingerprint
		addNode(certID, "cert", leaf.Subject)
		finalHost := res.TLS.Host
		addEdge("domain:"+finalHost, certID, "serves_cert")
	}

	return g
}
