package diagnosis

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"trazip/internal/bgp"
	"trazip/internal/intel/geoip"
	"trazip/internal/intel/netclass"
	"trazip/internal/intel/threatfeed"
	"trazip/internal/model"
	"trazip/internal/rdap"
)

// Dependencies bundles the already-instantiated engine clients DiagnoseTarget
// orchestrates — the same instances api.Service already owns and shares
// everywhere else, never a second engine instance (prompt maestro §5.4).
// Every field is individually nilable: a nil dependency degrades its stage to
// StageUnknown/StageSkipped, exactly like enrichParty/enrichHop already
// degrade cleanly when geo is nil.
type Dependencies struct {
	Geo        *geoip.Engine
	NetClass   *netclass.Engine
	RDAP       *rdap.Client
	BGP        *bgp.Client
	ThreatFeed *threatfeed.Engine
}

// resolvedTarget is what parseTarget establishes before any stage runs.
type resolvedTarget struct {
	kind     string // "ip" | "host" | "url"
	host     string // hostname to resolve, or the IP itself for kind=="ip"
	rawURL   string // only set for kind=="url" — the original input, for HTTPInspect
	directIP netip.Addr
	isDirect bool
}

func parseTarget(input string) resolvedTarget {
	target := strings.TrimSpace(input)
	host := target
	rt := resolvedTarget{kind: "host", host: target}
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			host = u.Hostname()
			rt.kind = "url"
			rt.rawURL = target
			rt.host = host
		}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		rt.directIP = addr.Unmap()
		rt.isDirect = true
		if rt.kind != "url" {
			rt.kind = "ip"
		}
		rt.host = host
	}
	return rt
}

// DiagnoseTarget runs the correlated diagnosis pipeline for one target
// (TRAZIP V1 MASTER IMPLEMENTATION, "PHASE B"). ctx governs the whole run —
// cancelling it stops every in-flight stage (master plan "CONCURRENCIA":
// "Cancelación completa desde UI").
//
// Architecture: every stage reads only results already produced by earlier
// engines/stages, computes its own model.Evidence, and reports structured
// facts into a shared, mutex-guarded accumulator — never raw strings —
// which correlate() alone turns into the report's global conclusion. React
// (or any other UI) only ever renders what this function already decided;
// it is never asked to interpret ten engines itself (master plan
// "ARQUITECTURA").
func DiagnoseTarget(ctx context.Context, deps Dependencies, input string, mode Mode) (DiagnosticReport, error) {
	start := time.Now()
	rt := parseTarget(input)
	report := DiagnosticReport{
		Target:    strings.TrimSpace(input),
		Kind:      rt.kind,
		Mode:      mode,
		StartedAt: start.UTC().Format(time.RFC3339),
	}
	if report.Target == "" {
		report.Summary = "Entrada vacía"
		report.Level = model.LevelInfo
		report.Confidence = 10
		report.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		return report, errEmptyInput
	}
	// Fail-closed on URL userinfo BEFORE any stage runs — resolvedTarget.
	// rawURL would otherwise carry the raw credential-bearing string all
	// the way into runWebPair's HTTP/TLS calls, and report.Target into
	// diagnosis.ToSnapshot / Investigation. Rejected here, before DNS,
	// before any network output, and with report.Target itself cleared so
	// a caller that inspects the report despite the non-nil error still
	// never sees the credential (Snapshot's own contract: never secrets/
	// credentials).
	if HasURLUserinfo(report.Target) {
		report.Target = ""
		report.Summary = "Entrada rechazada: las URLs con credenciales embebidas no están admitidas en Diagnose"
		report.Level = model.LevelInfo
		report.Confidence = 10
		report.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		return report, errURLCredentials
	}

	// --- Stage 1: Resolution (sequential — every later stage needs an IP) ---
	resStage, addrs := runResolution(ctx, rt, mode)
	report.Stages = append(report.Stages, resStage)
	ip, haveIP := applyResolvedAddresses(&report, rt, addrs)

	// --- Stages 2..N: fan out once the IP (if any) is known. Each stage is
	// independent of every other stage in this set — none reads another's
	// output — so they run concurrently under one shared timeout budget per
	// stage, all bounded by ctx (master plan "CONCURRENCIA"). ---
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		stages []DiagnosticStage
	)
	add := func(s DiagnosticStage) {
		mu.Lock()
		stages = append(stages, s)
		mu.Unlock()
	}
	run := func(fn func() DiagnosticStage) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			add(fn())
		}()
	}

	run(func() DiagnosticStage { return runReachability(ctx, haveIP, ip, mode) })
	run(func() DiagnosticStage { return runRoute(ctx, haveIP, ip, mode) })
	run(func() DiagnosticStage { return runOwnership(ctx, deps, haveIP, ip, mode) })
	run(func() DiagnosticStage { return runRoutingSecurity(ctx, deps, haveIP, ip, mode) })
	run(func() DiagnosticStage { return runReputation(deps, haveIP, ip) })

	// TLS and HTTP are produced together, not as two independent run()
	// calls: ModeFull derives both from ONE webintel.Analyze call rather
	// than two separate engine calls (Phase B.1 fix #4) — see runWebPair.
	wg.Add(1)
	go func() {
		defer wg.Done()
		tlsStage, httpStage := runWebPair(ctx, deps, rt, mode)
		add(tlsStage)
		add(httpStage)
	}()
	wg.Wait()

	// Stable, deterministic order for the UI regardless of goroutine
	// scheduling — the fixed sequence from the master plan's own list.
	order := []string{
		StageIDReachability, StageIDRoute, StageIDOwnership,
		StageIDRoutingSecurity, StageIDTLS, StageIDHTTP, StageIDReputation,
	}
	byID := make(map[string]DiagnosticStage, len(stages))
	for _, s := range stages {
		byID[s.ID] = s
	}
	for _, id := range order {
		if s, ok := byID[id]; ok {
			report.Stages = append(report.Stages, s)
		}
	}

	report.NetworkOut, report.NetworkActions = aggregateNetworkDisclosure(report.Stages)

	summary, level, confidence, evidence, counter, limitations := correlate(report.Stages, rt, haveIP)
	report.Summary, report.Level, report.Confidence = summary, level, confidence
	report.Evidence, report.CounterEvid, report.Limitations = evidence, counter, limitations

	if l, ok := multiAddressLimitation(report); ok {
		report.Limitations = append(report.Limitations, l)
	}

	report.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	report.DurationMs = time.Since(start).Milliseconds()
	return report, nil
}

// applyResolvedAddresses records EVERY address Resolution actually returned
// on the report (ResolvedAddresses) and picks the single one every later
// IP-bound stage probes (PrimaryAddress) — pulled out of DiagnoseTarget as
// its own pure function so the "one probed out of N resolved" bookkeeping
// (Phase B.1 fix #3) is unit-testable without a live DNS lookup. Always the
// first address for a resolved host — same "first" DiagnoseResult (Quick
// Diagnose 1.0) already implied by using it for classification — never all
// of them: Reachability/Route/Ownership/Routing Security/Reputation each
// probe exactly one address per run, not the full set.
func applyResolvedAddresses(report *DiagnosticReport, rt resolvedTarget, addrs []netip.Addr) (ip netip.Addr, haveIP bool) {
	switch {
	case rt.isDirect:
		ip, haveIP = rt.directIP, true
		report.ResolvedAddresses = []string{rt.directIP.String()}
	case len(addrs) > 0:
		ip, haveIP = addrs[0], true
		for _, a := range addrs {
			report.ResolvedAddresses = append(report.ResolvedAddresses, a.String())
		}
	}
	if haveIP {
		report.PrimaryAddress = ip.String()
	}
	return ip, haveIP
}

// multiAddressLimitation reports the "only one of several resolved
// addresses was actually probed" caveat — extracted as its own pure
// function purely for unit-testability (Phase B.1 fix #3). Never claims
// every A/AAAA record was tested.
func multiAddressLimitation(report DiagnosticReport) (string, bool) {
	if len(report.ResolvedAddresses) <= 1 {
		return "", false
	}
	return fmt.Sprintf(
		"Los stages de red activos evaluaron %s de %d direcciones resueltas; otros endpoints pueden comportarse de forma diferente.",
		report.PrimaryAddress, len(report.ResolvedAddresses)), true
}

var errEmptyInput = &diagnosisError{"entrada vacía"}

// errURLCredentials is DiagnoseTarget's fail-closed rejection for a URL
// carrying embedded userinfo (https://user:pass@host/...) — deliberately a
// fixed, generic message that never echoes the offending URL or any part
// of it, so the credential can never reach a log line, an error string, or
// a caller that only inspects err.Error().
var errURLCredentials = &diagnosisError{"las URLs con credenciales embebidas no están admitidas en Diagnose"}

type diagnosisError struct{ msg string }

func (e *diagnosisError) Error() string { return e.msg }

// HasURLUserinfo reports whether input parses as an absolute URL
// (scheme://...) carrying userinfo (user, or user:password) — the same
// "://" detection parseTarget itself uses, kept independent of it so this
// check runs standalone, before parseTarget's own result is otherwise
// needed. Deliberately narrow and structural: this recognizes url.URL.User
// being set, never scans arbitrary strings for words like "password"
// (Phase V1 hardening finding #1 — "El caso confirmado es URL userinfo
// estructurado"). Exported so internal/api's Investigation persistence
// boundary (InvestigationAddDiagnose) can apply the exact same check to a
// legacy/forged DiagnosticReport.Target, without a second, drifting
// implementation.
func HasURLUserinfo(input string) bool {
	trimmed := strings.TrimSpace(input)
	schemeEnd := strings.Index(trimmed, "://")
	if schemeEnd < 0 {
		return false
	}
	// The authority is everything between "://" and the first path/query/
	// fragment delimiter — checked structurally, on the raw string, rather
	// than via url.Parse: a malformed URL (e.g. an invalid percent-escape
	// later in the path, such as ".../%ZZ") still has a perfectly
	// well-formed, credential-bearing authority, and url.Parse failing on
	// the REST of the string must never be read as "no credentials here"
	// (V1 hardening: HasURLUserinfo must fail closed, not merely when
	// net/url happens to accept the whole input). An "@" anywhere in the
	// authority — even a bare "@" with no username — is userinfo-shaped
	// and rejected; an "@" appearing only after the authority (in a path
	// segment or a query value) is not.
	authority := trimmed[schemeEnd+len("://"):]
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	return strings.Contains(authority, "@")
}

// resolveHost is the shared bounded DNS lookup Resolution and (indirectly)
// every later stage depends on — same net.DefaultResolver.LookupNetIP
// DiagnoseResult (Quick Diagnose 1.0) already used, kept identical rather
// than swapped for dnsintel.Query so ModeStandard's behavior doesn't
// silently change shape; dnsintel is reserved for ModeFull's explicit
// cross-resolver comparison (see stage_resolution.go).
func resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(rctx, "ip", host)
	if err != nil {
		return nil, err
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range ips {
		a = a.Unmap()
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out, nil
}
