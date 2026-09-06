// Package dnsintel implements the DNS Toolkit (prompt maestro §9 Fase 4,
// módulo 19): raw queries for the record types the Go stdlib resolver does
// not expose (SOA, CAA, and EDNS0/DNSSEC metadata), comparison across
// resolvers, and PTR reverse lookups. Named resolvers (Cloudflare, Google,
// Quad9, or a custom server) are queried directly over UDP/TCP with
// codeberg.org/miekg/dns so RCODE, TTL and DNSSEC flags are exact — the OS
// resolver ("Sistema") is used only for the record types net.Resolver
// actually supports, since discovering the OS's configured DNS servers
// portably (Windows/macOS/Linux) without cgo is out of scope; querying an
// unverified guessed address instead would be dishonest, not a shortcut.
package dnsintel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Resolver names a DNS server to query, or the special "system" address that
// routes through the OS resolver instead of a raw UDP/TCP query.
type Resolver struct {
	Addr  string `json:"addr"` // "system" or "host:port" (port defaults to 53 if omitted)
	Label string `json:"label"`
}

const SystemResolverAddr = "system"

// WellKnownResolvers are offered as one-click comparison targets in the GUI.
var WellKnownResolvers = []Resolver{
	{Addr: SystemResolverAddr, Label: "Sistema"},
	{Addr: "1.1.1.1:53", Label: "Cloudflare"},
	{Addr: "8.8.8.8:53", Label: "Google"},
	{Addr: "9.9.9.9:53", Label: "Quad9"},
}

// Record is one answer entry in human-readable form.
type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
	// SRV holds the structured fields for SRV records only (nil for every
	// other type), so the GUI can render Priority/Weight/Port/Target as
	// columns instead of re-parsing Value.
	SRV *SRVData `json:"srv,omitempty"`
}

// SRVData is the structured form of one SRV record.
type SRVData struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

// DNSSECInfo reports what was asked for and what the response actually
// signaled — never inferred beyond the wire bits present.
type DNSSECInfo struct {
	Requested     bool `json:"requested"`     // DO bit set in the query (EDNS0)
	Authenticated bool `json:"authenticated"` // AD bit set in the response
	HasRRSIG      bool `json:"hasRRSIG"`      // at least one RRSIG present in the answer section
}

// QueryResult is one DNS query against one resolver for one record type.
type QueryResult struct {
	Domain     string     `json:"domain"`
	Type       string     `json:"type"`
	Resolver   string     `json:"resolver"` // resolved label, e.g. "Cloudflare (1.1.1.1:53)" or "Sistema"
	Records    []Record   `json:"records"`
	RCode      string     `json:"rcode"`
	Truncated  bool       `json:"truncated"`
	DurationMs int64      `json:"durationMs"`
	DNSSEC     DNSSECInfo `json:"dnssec"`
	Err        string     `json:"err,omitempty"`
	Cause      error      `json:"-"`
}

var supportedTypes = map[string]uint16{
	"A": dns.TypeA, "AAAA": dns.TypeAAAA, "CNAME": dns.TypeCNAME,
	"MX": dns.TypeMX, "TXT": dns.TypeTXT, "NS": dns.TypeNS,
	"SOA": dns.TypeSOA, "SRV": dns.TypeSRV, "CAA": dns.TypeCAA,
	"PTR": dns.TypePTR,
}

// SupportedTypes lists the record types this toolkit understands, in a
// stable order for GUI dropdowns.
func SupportedTypes() []string {
	return []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "PTR"}
}

// stdlibOnlyTypes are the record types the OS resolver ("Sistema") can
// actually answer through net.Resolver — SOA and CAA have no stdlib lookup.
var stdlibOnlyTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true,
	"TXT": true, "NS": true, "SRV": true, "PTR": true,
}

func normalizeAddr(addr string) string {
	if addr == "" || addr == SystemResolverAddr {
		return SystemResolverAddr
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "53")
}

func resolverLabel(addr string) string {
	if addr == SystemResolverAddr {
		return "Sistema"
	}
	for _, r := range WellKnownResolvers {
		if r.Addr == addr {
			return fmt.Sprintf("%s (%s)", r.Label, addr)
		}
	}
	return addr
}

// Query resolves one record type for one domain against one resolver. dnssec
// requests the DO bit (EDNS0) on raw queries; it is a no-op against "system"
// since the stdlib resolver does not expose EDNS controls.
func Query(ctx context.Context, domain, recordType, resolverAddr string, dnssec bool) QueryResult {
	start := time.Now()
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	domain = strings.TrimSpace(domain)
	addr := normalizeAddr(resolverAddr)

	res := QueryResult{Domain: domain, Type: recordType, Resolver: resolverLabel(addr)}
	qtype, ok := supportedTypes[recordType]
	if !ok {
		res.Err = fmt.Sprintf("tipo de registro no soportado: %q", recordType)
		return res
	}

	if addr == SystemResolverAddr {
		res = querySystem(ctx, domain, recordType, res)
	} else {
		res = queryRaw(ctx, domain, qtype, addr, dnssec, res)
	}
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

// ReversePTR performs a PTR lookup for an IP address. The stdlib resolver
// ("Sistema") wants the IP itself — net.Resolver.LookupAddr does the
// IP→ARPA conversion internally — while an explicit raw DNS resolver needs
// the ARPA name built by hand, since queryRaw sends whatever name it is
// given as a literal DNS query. Handing the ARPA name to LookupAddr instead
// of the IP is exactly what "unrecognized address" used to mean here.
func ReversePTR(ctx context.Context, ip, resolverAddr string, dnssec bool) QueryResult {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return QueryResult{Domain: ip, Type: "PTR", Err: "dirección IP inválida: " + err.Error()}
	}

	if normalizeAddr(resolverAddr) == SystemResolverAddr {
		return querySystemPTR(ctx, addr)
	}

	arpa := strings.TrimSuffix(dnsutil.ReverseAddr(addr), ".")
	return Query(ctx, arpa, "PTR", resolverAddr, dnssec)
}

// lookupAddr is net.DefaultResolver.LookupAddr, kept as a package var so
// tests can verify querySystemPTR hands it the raw IP (never an ARPA name)
// without needing a real network/DNS server.
var lookupAddr = net.DefaultResolver.LookupAddr

func querySystemPTR(ctx context.Context, addr netip.Addr) QueryResult {
	start := time.Now()
	ip := addr.String()
	res := QueryResult{Domain: ip, Type: "PTR", Resolver: resolverLabel(SystemResolverAddr)}
	names, err := lookupAddr(ctx, ip)
	if err != nil {
		res.Err = err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	for _, n := range names {
		res.Records = append(res.Records, Record{Name: ip, Type: "PTR", Value: strings.TrimSuffix(n, ".")})
	}
	res.RCode = "NOERROR"
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

// srvSIPLabels are the standard SIP SRV service/proto labels tried during
// discovery, in the order services normally publish them: UDP first, then
// TCP, then TLS-secured SIP.
var srvSIPLabels = []string{"_sip._udp", "_sip._tcp", "_sips._tcp"}

// SRVDiscoveryCandidate is one SIP SRV name tried during discovery and what
// querying it for SRV actually returned.
type SRVDiscoveryCandidate struct {
	Name   string      `json:"name"`
	Result QueryResult `json:"result"`
}

// DiscoverSRVSIP queries the standard SIP SRV names under name — never a
// parent domain, never a resolver other than the one requested — and
// reports every candidate tried alongside its full result, so the caller
// can show exactly what was checked instead of only the first hit. It never
// substitutes a different name into a query the user actually typed; it is
// an explicit, separate lookup the caller opts into.
func DiscoverSRVSIP(ctx context.Context, name, resolverAddr string, dnssec bool) []SRVDiscoveryCandidate {
	base := strings.TrimSuffix(strings.TrimSpace(name), ".")
	out := make([]SRVDiscoveryCandidate, 0, len(srvSIPLabels))
	for _, label := range srvSIPLabels {
		candidate := label + "." + base
		out = append(out, SRVDiscoveryCandidate{
			Name:   candidate,
			Result: Query(ctx, candidate, "SRV", resolverAddr, dnssec),
		})
	}
	return out
}

// TargetResolution is the A/AAAA lookup result for one SRV target.
type TargetResolution struct {
	Target string   `json:"target"`
	IPs    []string `json:"ips"`
	Err    string   `json:"err,omitempty"`
}

// srvTargetBatchTimeout bounds the whole ResolveSRVTargets call, including
// every target it looks up — a slow/unreachable target must not make the
// batch (or the "Sistema" branch, which otherwise has no caller-imposed
// deadline of its own) run indefinitely.
const srvTargetBatchTimeout = 10 * time.Second

// srvTargetBatchConcurrency bounds how many targets are looked up at once,
// so a long SRV target list can't fan out into unbounded goroutines/sockets.
const srvTargetBatchConcurrency = 4

// ResolveSRVTargets resolves A and AAAA for each unique target using
// resolverAddr — the same resolver the caller used for the SRV query itself,
// never a different one, so results stay attributable to one source. A
// target with no A/AAAA record (or a transient lookup failure) does not
// invalidate the SRV record it came from; it is reported on its own entry,
// with an empty IPs slice and, if a lookup genuinely errored, Err set. The
// whole batch runs under a bounded deadline and bounded concurrency: one
// target timing out only affects that target's own entry.
func ResolveSRVTargets(ctx context.Context, targets []string, resolverAddr string) []TargetResolution {
	ctx, cancel := context.WithTimeout(ctx, srvTargetBatchTimeout)
	defer cancel()

	// Dedupe up front so the output order reflects first appearance and
	// every unique target is looked up exactly once.
	order := make([]string, 0, len(targets))
	seen := make(map[string]bool, len(targets))
	for _, raw := range targets {
		target := strings.TrimSuffix(strings.TrimSpace(raw), ".")
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		order = append(order, target)
	}

	out := make([]TargetResolution, len(order))
	sem := make(chan struct{}, srvTargetBatchConcurrency)
	var wg sync.WaitGroup
	for i, target := range order {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, target string) {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = resolveTargetAddrs(ctx, target, resolverAddr)
		}(i, target)
	}
	wg.Wait()
	return out
}

func resolveTargetAddrs(ctx context.Context, target, resolverAddr string) TargetResolution {
	res := TargetResolution{Target: target}
	var lastErr string

	a := Query(ctx, target, "A", resolverAddr, false)
	if a.Err != "" {
		lastErr = a.Err
	}
	for _, rec := range a.Records {
		if ip, ok := validTargetIP(rec, "A"); ok {
			res.IPs = append(res.IPs, ip)
		}
	}

	aaaa := Query(ctx, target, "AAAA", resolverAddr, false)
	if aaaa.Err != "" && lastErr == "" {
		lastErr = aaaa.Err
	}
	for _, rec := range aaaa.Records {
		if ip, ok := validTargetIP(rec, "AAAA"); ok {
			res.IPs = append(res.IPs, ip)
		}
	}

	if len(res.IPs) == 0 && lastErr != "" {
		res.Err = lastErr
	}
	return res
}

// validTargetIP accepts a Record only if it is genuinely the record type
// asked for (A/AAAA) with a value that parses as an IP address. A raw
// resolver's Answer section for an A/AAAA query can legitimately include
// CNAME records for the alias chain — those must never leak into
// TargetResolution.IPs as if they were addresses.
func validTargetIP(rec Record, wantType string) (string, bool) {
	if rec.Type != wantType {
		return "", false
	}
	if _, err := netip.ParseAddr(rec.Value); err != nil {
		return "", false
	}
	return rec.Value, true
}

func querySystem(ctx context.Context, domain, recordType string, res QueryResult) QueryResult {
	if !stdlibOnlyTypes[recordType] {
		res.Err = fmt.Sprintf("%s no está disponible vía el resolver del sistema; use un resolver DNS explícito (Cloudflare/Google/Quad9/personalizado)", recordType)
		return res
	}
	r := net.DefaultResolver
	switch recordType {
	case "A", "AAAA":
		ips, err := r.LookupIP(ctx, map[string]string{"A": "ip4", "AAAA": "ip6"}[recordType], domain)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		for _, ip := range ips {
			res.Records = append(res.Records, Record{Name: domain, Type: recordType, Value: ip.String()})
		}
	case "CNAME":
		cname, err := r.LookupCNAME(ctx, domain)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		res.Records = append(res.Records, Record{Name: domain, Type: "CNAME", Value: strings.TrimSuffix(cname, ".")})
	case "MX":
		mxs, err := r.LookupMX(ctx, domain)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		for _, mx := range mxs {
			res.Records = append(res.Records, Record{Name: domain, Type: "MX", Value: fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, "."))})
		}
	case "TXT":
		txts, err := r.LookupTXT(ctx, domain)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		for _, t := range txts {
			res.Records = append(res.Records, Record{Name: domain, Type: "TXT", Value: t})
		}
	case "NS":
		nss, err := r.LookupNS(ctx, domain)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		for _, ns := range nss {
			res.Records = append(res.Records, Record{Name: domain, Type: "NS", Value: strings.TrimSuffix(ns.Host, ".")})
		}
	case "SRV":
		_, srvs, err := r.LookupSRV(ctx, "", "", domain)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		for _, s := range srvs {
			target := strings.TrimSuffix(s.Target, ".")
			res.Records = append(res.Records, Record{
				Name:  domain,
				Type:  "SRV",
				Value: fmt.Sprintf("prio=%d peso=%d %s:%d", s.Priority, s.Weight, target, s.Port),
				SRV:   &SRVData{Priority: s.Priority, Weight: s.Weight, Port: s.Port, Target: target},
			})
		}
	case "PTR":
		names, err := r.LookupAddr(ctx, domain)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		for _, n := range names {
			res.Records = append(res.Records, Record{Name: domain, Type: "PTR", Value: strings.TrimSuffix(n, ".")})
		}
	}
	res.RCode = "NOERROR"
	return res
}

func queryRaw(ctx context.Context, domain string, qtype uint16, addr string, dnssec bool, res QueryResult) QueryResult {
	m := dns.NewMsg(domain, qtype)
	if m == nil {
		res.Err = fmt.Sprintf("tipo de registro no soportado por el cliente DNS: %d", qtype)
		return res
	}
	if dnssec {
		m.Security = true
		m.UDPSize = 4096
		res.DNSSEC.Requested = true
	}

	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	c := dns.NewClient()
	in, _, err := c.Exchange(qctx, m, "udp", addr)
	if err != nil {
		res.Err = err.Error()
		res.Cause = err
		return res
	}
	if in.Truncated {
		// Retry over TCP per RFC 1035 §4.2.2 when UDP truncates the answer.
		if tin, _, terr := c.Exchange(qctx, m, "tcp", addr); terr == nil {
			in = tin
		} else {
			res.Truncated = true
		}
	}

	res.RCode = dnsutil.RcodeToString(in.Rcode)
	if res.RCode == "" {
		res.RCode = fmt.Sprintf("RCODE%d", in.Rcode)
	}
	res.DNSSEC.Authenticated = in.AuthenticatedData

	for _, rr := range in.Answer {
		if _, isRRSIG := rr.(*dns.RRSIG); isRRSIG {
			res.DNSSEC.HasRRSIG = true
		}
		if rec, ok := toRecord(rr); ok {
			res.Records = append(res.Records, rec)
		}
	}
	sort.SliceStable(res.Records, func(i, j int) bool { return res.Records[i].Type < res.Records[j].Type })
	return res
}

func toRecord(rr dns.RR) (Record, bool) {
	hdr := rr.Header()
	base := Record{Name: strings.TrimSuffix(hdr.Name, "."), Type: dnsutil.TypeToString(dns.RRToType(rr)), TTL: hdr.TTL}
	switch v := rr.(type) {
	case *dns.A:
		base.Value = v.A.Addr.String()
	case *dns.AAAA:
		base.Value = v.AAAA.Addr.String()
	case *dns.CNAME:
		base.Value = strings.TrimSuffix(v.CNAME.Target, ".")
	case *dns.MX:
		base.Value = fmt.Sprintf("%d %s", v.MX.Preference, strings.TrimSuffix(v.MX.Mx, "."))
	case *dns.TXT:
		base.Value = strings.Join(v.TXT.Txt, " ")
	case *dns.NS:
		base.Value = strings.TrimSuffix(v.NS.Ns, ".")
	case *dns.SOA:
		base.Value = fmt.Sprintf("%s %s serial=%d refresh=%d retry=%d expire=%d minttl=%d",
			strings.TrimSuffix(v.SOA.Ns, "."), strings.TrimSuffix(v.SOA.Mbox, "."), v.SOA.Serial, v.SOA.Refresh, v.SOA.Retry, v.SOA.Expire, v.SOA.Minttl)
	case *dns.SRV:
		target := strings.TrimSuffix(v.SRV.Target, ".")
		base.Value = fmt.Sprintf("prio=%d peso=%d %s:%d", v.SRV.Priority, v.SRV.Weight, target, v.SRV.Port)
		base.SRV = &SRVData{Priority: v.SRV.Priority, Weight: v.SRV.Weight, Port: v.SRV.Port, Target: target}
	case *dns.CAA:
		base.Value = fmt.Sprintf("flag=%d %s %q", v.CAA.Flag, v.CAA.Tag, v.CAA.Value)
	case *dns.PTR:
		base.Value = strings.TrimSuffix(v.PTR.Ptr, ".")
	default:
		return Record{}, false
	}
	return base, true
}

// Comparison runs the same query across several resolvers and flags whether
// the answer sets diverge (different addresses, different record counts, or
// different RCODEs) — surfacing split-horizon DNS, hijacking, or stale
// caches without asserting which resolver is "correct."
type Comparison struct {
	Domain      string        `json:"domain"`
	Type        string        `json:"type"`
	Results     []QueryResult `json:"results"`
	Consistent  bool          `json:"consistent"`
	Divergences []string      `json:"divergences,omitempty"`
}

// Compare queries every resolver in parallel and reports divergences.
func Compare(ctx context.Context, domain, recordType string, resolvers []Resolver, dnssec bool) Comparison {
	results := make([]QueryResult, len(resolvers))
	done := make(chan int, len(resolvers))
	for i, r := range resolvers {
		go func(i int, addr string) {
			results[i] = Query(ctx, domain, recordType, addr, dnssec)
			done <- i
		}(i, r.Addr)
	}
	for range resolvers {
		<-done
	}

	cmp := Comparison{Domain: domain, Type: strings.ToUpper(recordType), Results: results, Consistent: true}
	var baseline answerSignature
	haveBaseline := false
	for _, r := range results {
		if r.Err != "" {
			// A transport/query error stays outside the answer-set
			// comparison, exactly as before (V1 hardening finding #4
			// scope: only real, comparable answers are compared).
			continue
		}
		sig := answerSignature{rcode: r.RCode, values: valueSet(r.Records)}
		if !haveBaseline {
			baseline, haveBaseline = sig, true
			continue
		}
		if !sig.equal(baseline) {
			cmp.Consistent = false
		}
	}
	if !cmp.Consistent {
		for _, r := range results {
			if r.Err == "" {
				cmp.Divergences = append(cmp.Divergences, fmt.Sprintf("%s [%s] → %s", r.Resolver, orDash(r.RCode), joinOrDash(valueSet(r.Records))))
			}
		}
	}
	return cmp
}

// answerSignature is what Compare actually treats as "the same answer":
// RCODE plus the sorted set of record values. TTL is deliberately excluded
// — a shorter TTL from a colder cache doesn't mean a resolver returned a
// different answer (V1 hardening finding #4: "TTL distinto por caché no
// debe convertir por sí solo la respuesta en distinta").
type answerSignature struct {
	rcode  string
	values []string
}

func (a answerSignature) equal(b answerSignature) bool {
	return a.rcode == b.rcode && sameSet(a.values, b.values)
}

// orDash returns s, or "?" when the RCODE is unexpectedly empty for an
// answer that otherwise reached the comparable-results branch — never left
// as a bare blank next to the resolver's label in Divergences.
func orDash(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// joinOrDash renders a record value set for Divergences — an explicit
// "(sin records)" instead of a bare, confusing empty string, which matters
// specifically for the NXDOMAIN/empty-answer case this finding is about.
func joinOrDash(vals []string) string {
	if len(vals) == 0 {
		return "(sin records)"
	}
	return strings.Join(vals, ", ")
}

func valueSet(records []Record) []string {
	vals := make([]string, len(records))
	for i, r := range records {
		vals[i] = r.Value
	}
	sort.Strings(vals)
	return vals
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
