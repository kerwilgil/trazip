package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"trazip/internal/bgp"
	"trazip/internal/capture"
	"trazip/internal/connmon"
	"trazip/internal/detection/netdiag"
	"trazip/internal/detection/scandetect"
	"trazip/internal/dnsintel"
	"trazip/internal/flow"
	"trazip/internal/httpintel"
	"trazip/internal/intel/classify"
	"trazip/internal/intel/geoip"
	"trazip/internal/intel/geoupdate"
	"trazip/internal/intel/netclass"
	"trazip/internal/intel/oui"
	"trazip/internal/intel/threatfeed"
	"trazip/internal/investigation"
	"trazip/internal/ipcalc"
	"trazip/internal/lab"
	"trazip/internal/lan"
	"trazip/internal/model"
	"trazip/internal/monitor"
	"trazip/internal/osint"
	"trazip/internal/packet"
	"trazip/internal/paths"
	"trazip/internal/pcap"
	"trazip/internal/phoneintel"
	"trazip/internal/rdap"
	"trazip/internal/report"
	"trazip/internal/reputation"
	"trazip/internal/serviceaudit"
	"trazip/internal/session"
	"trazip/internal/tlsintel"
	"trazip/internal/update"
	"trazip/internal/voip"
	"trazip/internal/voip/quality"
	"trazip/internal/webintel"
	"trazip/internal/wifi"
)

// pcapUILimit bounds how many packet summaries are returned to the UI. Flows are
// still aggregated over the entire file.
const pcapUILimit = 8000

// endpointUILimit prevents a high-cardinality capture from producing an
// unbounded Wails payload. TotalEndpoints still reports the complete count.
const endpointUILimit = 5000

// flowUILimit bounds how many flows are returned to the UI. TotalFlows
// still reports the complete count, and PcapIncidentSummary is always
// built from every flow before this cap is applied (see
// applyPcapUILimits).
const flowUILimit = 2000

// bgpFinalSnapshotLimit bounds Service.bgpFinalSnapshots (v1.2 Gate 5.1) —
// a post-mortem cache, never a lifecycle registry, so it must never grow
// without bound across a long-running app session. Deterministic FIFO
// eviction (bgpFinalOrder) is sufficient: nothing depends on which
// terminated session survives once more than 64 have terminated.
const bgpFinalSnapshotLimit = 64

// Version is the TRAZIP build version, overridden at link time.
//
// Al subir de versión hay que tocar TRES lugares o la app muestra un número y
// el ejecutable declara otro: este valor (lo que se ve dentro de la app y en
// los reportes de sesión), `productVersion` en wails.json (propiedades del
// .exe) y `version` en frontend/package.json. El ZIP portable no cuenta:
// package_portable.ps1 lo deriva del tag de git.
var Version = "1.4.0"

// Service is the backend facade shared by the GUI (via Wails bindings) and the
// CLI, so both drive the exact same domain logic (prompt maestro §6, §15).
type Service struct {
	sessions       *session.Manager
	elevated       bool
	geo            *geoip.Engine
	geoUpdater     *geoupdate.Manager
	rdapClient     *rdap.Client
	bgpClient      *bgp.Client
	monitorMgr     *monitor.Manager
	voipQualMgr    *quality.Manager
	lanTrust       *lan.TrustStore
	wifiPosture    *wifi.PostureStore
	netClass       *netclass.Engine
	threatFeed     *threatfeed.Engine
	oui            *oui.Engine
	updateMgr      *update.Manager
	investigations *investigation.Manager

	// osintRegistry is the OSINT Intelligence foundation's provider registry
	// (V1.5-2). V1.5-3 wires only its read-only metadata to the UI via
	// ListOSINTProviders — no provider is registered yet, and the registry
	// never hands out a runnable provider. Execution (Executor + ScopeGuard)
	// is a later phase.
	osintRegistry *osint.Registry

	// bgpRealtimeStart constructs (but never starts — see
	// bgp.PrepareRealtimeSession's own doc comment) a v1.2 BGP realtime
	// session — a field, not a direct bgp.PrepareRealtimeSession call,
	// purely so Gate 5's own tests can substitute
	// bgp.PrepareRealtimeSessionWithDialer (a local fake WebSocket server)
	// instead of the real RIS Live endpoint, without touching production
	// wiring (default set in NewServiceWithSessions). Returns an error,
	// never a failed *bgp.RealtimeSession, for anything realtime v1.2
	// doesn't support (invalid resource, ASN) — v1.2 Gate 5 P1-1 closure:
	// nothing is ever constructed for those, so there is nothing for
	// registerBGPSession to register or clean up. onTerminate is threaded
	// straight through to whichever bgp.PrepareRealtimeSession* the field
	// calls.
	bgpRealtimeStart func(ctx context.Context, mgr *session.Manager, client *bgp.Client, resource string, onTerminate func(sessionID string)) (*bgp.RealtimeSession, error)

	// bgpSessions is a caller-side SessionID -> *bgp.RealtimeSession
	// index — NOT a second lifecycle registry (v1.2 Gate 5 "REALTIME
	// OWNERSHIP"). session.Manager (the `sessions` field above, shared
	// with App) remains the only source of truth for whether a session is
	// actually alive; this map only exists because Stop() needs the
	// concrete *bgp.RealtimeSession object (for its deterministic
	// supervisor/watcher/processor join — session.Manager only knows
	// about the generic *session.Session, which has no such join). Every
	// entry is added by registerBGPSession strictly BEFORE the session's
	// supervisor goroutine is ever launched (rs.Run() runs later, in
	// BGPRealtimeStart, only after registration — v1.2 Gate 5 P1-3
	// closure: self-termination can therefore never race the insert,
	// because it cannot happen before Run() exists to trigger it) and
	// removed either by BGPRealtimeStop's own atomic check-and-delete or
	// by the RealtimeSession's onTerminate hook firing on self-termination
	// (see registerBGPSession in bgp_realtime.go) — both paths are driven
	// by the SAME underlying terminateOnce-guarded event, so this index
	// can never diverge from what session.Manager already decided.
	bgpSessionsMu sync.Mutex
	bgpSessions   map[string]*bgp.RealtimeSession

	// bgpFinalSnapshots is a bounded, read-only post-mortem cache (v1.2
	// Gate 5.1 "REALTIME SESSION OBSERVABILITY") — NOT a second lifecycle
	// registry, and never consulted to restart/stop/decide-alive/authorize
	// anything. session.Manager (and, for live BGP sessions, bgpSessions
	// above) remain the only lifecycle authority. It exists purely so
	// BGPRealtimeInfo can still answer with a terminated session's FINAL
	// State/LastError/counters/DerivedStateEvictions after the live
	// bgpSessions entry is gone (autonomous termination or explicit Stop)
	// — Gate 6's UI needs to show why a session ended, not just that it's
	// no longer live. Stores immutable RealtimeSessionInfo VALUES only,
	// never a *bgp.RealtimeSession handle. Bounded at bgpFinalSnapshotLimit
	// entries via bgpFinalOrder's deterministic FIFO eviction — no TTL, no
	// disk, no background goroutine. Guarded by bgpSessionsMu (the same
	// mutex as bgpSessions above, not a second one) so the move from live
	// to final is a single atomic critical section: an ID is never absent
	// from BOTH maps at once from an external observer's perspective (see
	// registerBGPSession's onTerminate closure and BGPRealtimeStop, both
	// in bgp_realtime.go).
	bgpFinalSnapshots map[string]bgp.RealtimeSessionInfo
	bgpFinalOrder     []string
}

// NewService constructs the backend facade with its own private session,
// monitor and VoIP-quality managers (standalone use, e.g. a future CLI).
func NewService() *Service {
	return NewServiceWithSessions(session.NewManager(), monitor.NewManager(), quality.NewManager())
}

// NewServiceWithSessions constructs the facade around a shared session
// manager, monitor manager and VoIP-quality manager. All are owned by the
// caller (Wails' App, so its own Start/Stop methods that need
// event-emission access can share the exact same running-state) rather than
// by Service itself — the same dependency-injection pattern already used
// for session.Manager. Service deliberately has no accessor that returns
// the raw managers: Wails binds every exported Service method to JS, and
// these types aren't meaningfully serializable, so such an accessor would
// leak a broken binding (caught before shipping — see
// CONTEXT-trazip.md §8sexies).
func NewServiceWithSessions(sessions *session.Manager, monitorMgr *monitor.Manager, voipQualMgr *quality.Manager) *Service {
	dataDir := geoip.FindDataDir()
	geo := geoip.Open(dataDir)
	s := &Service{
		sessions:          sessions,
		elevated:          detectElevated(),
		geo:               geo,
		rdapClient:        rdap.NewClient(),
		bgpClient:         bgp.NewClient(),
		monitorMgr:        monitorMgr,
		voipQualMgr:       voipQualMgr,
		lanTrust:          lan.NewTrustStore(paths.Sub("lan", "trust.json")),
		wifiPosture:       wifi.NewPostureStore(paths.Sub("wifi", "posture.json")),
		netClass:          netclass.New(dataDir),
		oui:               oui.New(dataDir),
		threatFeed:        threatfeed.New(dataDir),
		investigations:    investigation.NewManager(),
		bgpRealtimeStart:  bgp.PrepareRealtimeSession,
		bgpSessions:       make(map[string]*bgp.RealtimeSession),
		bgpFinalSnapshots: make(map[string]bgp.RealtimeSessionInfo),
		osintRegistry:     osint.NewRegistry(),
	}
	s.geoUpdater = geoupdate.New(dataDir, geo)
	s.updateMgr = update.NewManager(Version, paths.Sub("updates"), paths.Sub("update-settings.json"))
	return s
}

// GeoStatus reports which offline datasets are loaded (§5.4).
func (s *Service) GeoStatus() []geoip.DatasetInfo {
	return s.geo.Datasets()
}

// GeoUpdateStatus returns updater configuration and dataset provenance without
// ever exposing the stored MaxMind license key.
func (s *Service) GeoUpdateStatus() geoupdate.Status {
	return s.geoUpdater.Status()
}

// SaveGeoUpdateSettings encrypts the license key with Windows DPAPI. Passing
// an empty key preserves the currently stored credential.
func (s *Service) SaveGeoUpdateSettings(accountID, licenseKey string, autoUpdate bool) (geoupdate.Status, error) {
	return s.geoUpdater.SaveSettings(accountID, licenseKey, autoUpdate)
}

// CheckGeoUpdates checks MaxMind and optionally forces a fresh download.
func (s *Service) CheckGeoUpdates(force bool) (geoupdate.Result, error) {
	return s.geoUpdater.Check(context.Background(), force)
}

// StartGeoAutoUpdate performs at most one background check per 24 hours when
// the user has explicitly enabled automatic external requests.
//
// Deliberately a package-level function, NOT a *Service method (Phase B.1
// fix #7) — same reasoning as StartUpdateAutoCheck's own doc comment just
// below: Wails binds every exported method of the bound Service by
// reflection, with no way to mark one "backend-only", so a method taking
// context.Context here produced a real but useless JS binding no frontend
// could ever call meaningfully. App.startup is the only caller.
func StartGeoAutoUpdate(s *Service, ctx context.Context) {
	s.geoUpdater.StartAuto(ctx)
}

// UpdateStatus is what the Settings → Actualizaciones panel polls: the
// entire update lifecycle state at one instant (idle/checking/available/
// downloading/verifying/ready/installing/error), plus progress and the
// verified release info once known.
func (s *Service) UpdateStatus() update.StatusSnapshot {
	return s.updateMgr.Snapshot()
}

// CheckForUpdates queries the distribution channel — "Buscar ahora" always
// forces a fresh check; the automatic path (StartUpdateAutoCheck) does not.
func (s *Service) CheckForUpdates(force bool) (update.ReleaseInfo, error) {
	return s.updateMgr.Check(context.Background(), force)
}

// UpdateAutoCheckEnabled reports the user's current preference.
func (s *Service) UpdateAutoCheckEnabled() bool {
	return s.updateMgr.AutoCheck()
}

// SetUpdateAutoCheck persists whether TRAZIP may check for updates on its
// own. An update check is itself a network call and must always be a
// visible, user-controlled choice (Settings → Actualizaciones) — never
// hidden, even though the check alone sends no capture data, IPs analyzed,
// or telemetry of any kind.
func (s *Service) SetUpdateAutoCheck(enabled bool) error {
	return s.updateMgr.SetAutoCheck(enabled)
}

// DownloadUpdate starts the verified download in the background — "Actualizar
// ahora" fires this once and then polls UpdateStatus for progress
// (Downloaded/Total) and the terminal state (Ready, or back to Available on
// a failed or cancelled download).
func (s *Service) DownloadUpdate() {
	go func() { _ = s.updateMgr.Download(context.Background()) }()
}

// CancelUpdateDownload aborts an in-flight DownloadUpdate. A no-op if
// nothing is downloading.
func (s *Service) CancelUpdateDownload() {
	s.updateMgr.Cancel()
}

// StartUpdateAutoCheck, PrepareUpdateInstall, and MarkUpdateInstalling are
// deliberately package-level functions, NOT Service methods. Wails binds
// every exported method of every struct passed to wails.Bind (main.go
// binds the whole Service) purely by reflection — there is no way to mark
// a method "exported to other Go packages but not to the frontend". A
// package-level function sidesteps that entirely, since Wails only ever
// introspects the bound VALUES themselves, never arbitrary functions.
// This is the same fix already applied once in this codebase to
// AnalyzeVoIPWithContext (see CONTEXT-trazip.md §13): StartUpdateAutoCheck
// took a context.Context, which Wails would bind into a useless JS
// function no frontend could call meaningfully; PrepareUpdateInstall and
// MarkUpdateInstalling take currentExePath/portable/nothing at all, which
// have no reason to ever be supplied by frontend code — they belong
// entirely to App.InstallUpdate's own app-lifecycle orchestration.

// StartUpdateAutoCheck performs at most one background check per 24 hours
// against TRAZIP's own distribution channel (kerwilgil/trazip-releases),
// and only while the user has left auto-check enabled — see
// SetUpdateAutoCheck.
func StartUpdateAutoCheck(s *Service, ctx context.Context) {
	s.updateMgr.StartAuto(ctx)
}

// PrepareUpdateInstall returns the exact, locally-constructed arguments for
// cmd/trazip-updater once DownloadUpdate has reached StatusReady — called
// only from App.InstallUpdate, which owns spawning the helper and exiting
// TRAZIP (app-lifecycle work that belongs with the other Wails-runtime
// calls, not in this platform-agnostic facade).
func PrepareUpdateInstall(s *Service, currentExePath string, portable bool) (update.UpdaterArgs, error) {
	return s.updateMgr.PrepareInstall(currentExePath, portable)
}

// MarkUpdateInstalling transitions the update state machine to Installing.
// Call only after App.InstallUpdate has confirmed the updater process it
// spawned from PrepareUpdateInstall's result actually started — never
// before, so a helper that fails to even launch leaves the state at Ready
// (retryable) instead of stuck.
func MarkUpdateInstalling(s *Service) {
	s.updateMgr.MarkInstalling()
}

// Close releases long-lived offline dataset readers.
func (s *Service) Close() { s.geo.Close() }

// GeoLookup enriches a single address with offline GeoIP/ASN data. Used to
// annotate hop-by-hop views (Traceroute, MTR) with country/organization per
// destination, the way "Visual Traceroute"-style tools do. Returns a zero
// Result for invalid addresses or when no dataset matches (private ranges,
// missing datasets).
func (s *Service) GeoLookup(ip string) geoip.Result {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return geoip.Result{}
	}
	return s.geo.Lookup(addr)
}

// CaptureAvailable reports whether live capture is possible (Npcap present).
func (s *Service) CaptureAvailable() bool { return capture.Available() }

// CaptureDevices lists capturable interfaces.
func (s *Service) CaptureDevices() ([]capture.Device, error) { return capture.Devices() }

// WifiAvailable reports whether WiFi network scanning is possible on this
// platform (Windows WLAN API).
func (s *Service) WifiAvailable() bool { return wifi.Available() }

// WifiScan lists nearby WiFi networks via Windows' own cached scan results
// — no monitor mode, no special hardware. Windows requires the system
// Location privacy toggle to be on for this to return SSID names (since
// Windows 10 1803, for every app); the error message explains that
// directly when it's the cause.
func (s *Service) WifiScan() ([]wifi.Network, error) { return wifi.Scan() }

// WifiStatus reports the connection state of each WLAN interface — the UI
// uses it to warn "tu WiFi no está conectado a ninguna red" before the
// operator wastes time capturing on a link with no traffic.
func (s *Service) WifiStatus() ([]wifi.IfaceStatus, error) { return wifi.Status() }

func (s *Service) WifiPosture(networks []wifi.Network) (wifi.PostureResult, error) {
	return s.wifiPosture.Assess(networks)
}

func (s *Service) LanTrustAssess(hosts []lan.HostResult) (lan.TrustResult, error) {
	return s.lanTrust.Assess(hosts)
}

func (s *Service) ExposureCompare(observed, expected []int) serviceaudit.ExposureResult {
	return serviceaudit.CompareExposure(observed, expected)
}

// AnalyzeVoIP correlates SIP+SDP+RTP+RTCP in a capture file into calls
// (prompt maestro §9 Fase 3), enriching each call's Caller/Callee with the
// same offline GeoIP/ASN engine every other view uses — s.geo, not a second
// instance. App.StartVoIPAnalysis (the GUI's own entry point) also routes
// through this method rather than calling voip.Analyze directly, so the GUI
// and a future CLI built on Service never see different results for the same
// capture (prompt maestro §6, §15).
func (s *Service) AnalyzeVoIP(path string) (voip.Result, error) {
	return RunVoIPAnalysis(context.Background(), path, s)
}

// RunVoIPAnalysis is the shared implementation behind Service.AnalyzeVoIP
// (the JS-bound call, uncancellable) and App.StartVoIPAnalysis (the GUI's
// cancellable route, in package main) — a package-level function, not a
// *Service method, so App can call it directly with a real context.Context
// while it stays completely invisible to Wails' binding generator.
//
// Wails binds every exported method of the struct instances passed to
// options.App.Bind (main.go: app, app.Service()) purely by reflecting over
// their method sets — it has no way to see a package-level function, bound
// or not. A *Service method taking a context.Context would still be
// discovered and bound like any other exported method, producing a real
// entry in Service.d.ts/Service.js that JS can never actually call (JS has
// no way to construct a context.Context) — which is exactly what an earlier
// version of this (AnalyzeVoIPWithContext, a *Service method) did. Pulling
// the shared logic out into a plain function is what keeps App's
// cancellable path and this package's single validation/GeoIP-engine
// access from needing two copies, without ever producing that broken
// binding.
func RunVoIPAnalysis(ctx context.Context, path string, s *Service) (voip.Result, error) {
	if strings.TrimSpace(path) == "" {
		return voip.Result{}, fmt.Errorf("ruta vacía")
	}
	return voip.Analyze(ctx, path, s.geo)
}

// DNSResolvers lists the well-known resolvers the DNS Toolkit GUI offers,
// plus "Sistema" for the OS resolver (prompt maestro §9 Fase 4, módulo 19).
func (s *Service) DNSResolvers() []dnsintel.Resolver {
	return dnsintel.WellKnownResolvers
}

// DNSRecordTypes lists the record types the DNS Toolkit understands.
func (s *Service) DNSRecordTypes() []string {
	return dnsintel.SupportedTypes()
}

// DNSQuery runs one DNS Toolkit query against one resolver.
func (s *Service) DNSQuery(domain, recordType, resolverAddr string, dnssec bool) dnsintel.QueryResult {
	return dnsintel.Query(context.Background(), domain, recordType, resolverAddr, dnssec)
}

// DNSCompare runs the same query across the well-known resolvers and flags
// divergence.
func (s *Service) DNSCompare(domain, recordType string, dnssec bool) dnsintel.Comparison {
	return dnsintel.Compare(context.Background(), domain, recordType, dnsintel.WellKnownResolvers, dnssec)
}

// DNSReversePTR performs a PTR lookup for an IP address.
func (s *Service) DNSReversePTR(ip, resolverAddr string, dnssec bool) dnsintel.QueryResult {
	return dnsintel.ReversePTR(context.Background(), ip, resolverAddr, dnssec)
}

// DNSResolveSRVTargets resolves A/AAAA for each SRV target using the same
// resolver the SRV query itself used, so the GUI can show a target's current
// IPs without silently routing part of the lookup through a different
// provider.
func (s *Service) DNSResolveSRVTargets(targets []string, resolverAddr string) []dnsintel.TargetResolution {
	return dnsintel.ResolveSRVTargets(context.Background(), targets, resolverAddr)
}

// DNSDiscoverSRVSIP tries the standard SIP SRV names under name using the
// given resolver — used when a bare-name SRV query comes back empty, so the
// GUI can offer to discover the real SIP SRV name without silently
// substituting a different name into the query the user actually typed.
func (s *Service) DNSDiscoverSRVSIP(name, resolverAddr string, dnssec bool) []dnsintel.SRVDiscoveryCandidate {
	return dnsintel.DiscoverSRVSIP(context.Background(), name, resolverAddr, dnssec)
}

// TLSInspect completes a TLS handshake against host:port and reports the
// certificate chain, negotiated parameters and validation result (prompt
// maestro §9 Fase 4, módulo 20).
func (s *Service) TLSInspect(host string, port int, sni string) tlsintel.Result {
	return tlsintel.Inspect(context.Background(), host, port, sni)
}

// HTTPInspect performs a bounded GET/HEAD with redirect-chain timing,
// security-header analysis and CDN/WAF signal detection (prompt maestro §9
// Fase 4, módulo 21). The response body is never retained by this
// standalone tool — only the URL Analyzer pipeline opts into that.
func (s *Service) HTTPInspect(rawURL, method string, maxRedirects int) httpintel.Result {
	return httpintel.Inspect(context.Background(), rawURL, method, maxRedirects, 0, false)
}

// WebIntelAnalyze runs the full URL/domain analyzer pipeline (prompt maestro
// §9 Fase 4, módulo 18): DNS/CNAME chain, redirects, TLS, headers, CDN/WAF
// signals, extracted hostnames/IPs and the correlation graph.
func (s *Service) WebIntelAnalyze(rawInput, resolverAddr string) webintel.Result {
	return webintel.Analyze(context.Background(), s.geo, rawInput, resolverAddr)
}

// ListOSINTProviders returns read-only metadata for every provider registered
// in the OSINT Registry, sorted by ID for a deterministic UI. It never returns
// a runnable provider — the registry hands out ProviderMeta copies only, and
// the only route to execution is the Executor + ScopeGuard (not exposed here).
// V1.5-3 registers no real providers, so this returns an empty slice; the
// empty result is a valid "no sources registered yet" state, not an error.
// Always a non-nil slice so the frontend contract (an array, never null) holds.
func (s *Service) ListOSINTProviders() []OSINTProviderInfo {
	out := []OSINTProviderInfo{}
	if s.osintRegistry == nil {
		return out
	}
	for _, m := range s.osintRegistry.AllMetas() {
		caps := make([]string, 0, len(m.Capabilities))
		for _, c := range m.Capabilities {
			caps = append(caps, string(c))
		}
		out = append(out, OSINTProviderInfo{
			ID:              m.ID,
			Name:            m.Name,
			Capabilities:    caps,
			ActivityClass:   m.ActivityClass.String(),
			DisclosureClass: m.DisclosureClass.String(),
			RequiresScope:   m.RequiresScope,
			RateLimit:       m.RateLimit,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// PassiveOSINT keeps all enrichment offline unless external is explicitly
// true. With external enabled it performs system DNS and one RDAP lookup for
// the first public address, with the exact disclosed data returned to the UI.
func (s *Service) PassiveOSINT(rawInput string, external bool) (PassiveOSINTResult, error) {
	input := strings.TrimSpace(rawInput)
	if input == "" {
		return PassiveOSINTResult{}, fmt.Errorf("objetivo vacío")
	}
	host := input
	if strings.Contains(input, "://") {
		u, err := url.Parse(input)
		if err != nil || u.Hostname() == "" {
			return PassiveOSINTResult{}, fmt.Errorf("URL inválida")
		}
		host = u.Hostname()
	}
	r := PassiveOSINTResult{Input: input, Host: host, External: external, Addresses: []AddrReport{}}
	directIP := false
	if addr, err := netip.ParseAddr(host); err == nil {
		directIP = true
		r.Addresses = append(r.Addresses, s.addrReport(addr.Unmap()))
	} else if !external {
		r.Notes = append(r.Notes, "Modo offline: no se resolvió el dominio ni se envió información fuera del equipo.")
		return r, nil
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return r, err
		}
		seen := map[netip.Addr]bool{}
		for _, ip := range ips {
			a, ok := netip.AddrFromSlice(ip.IP)
			if !ok {
				continue
			}
			a = a.Unmap()
			if seen[a] {
				continue
			}
			seen[a] = true
			r.Addresses = append(r.Addresses, s.addrReport(a))
			if len(r.Addresses) >= 8 {
				break
			}
		}
	}
	if external {
		didDNS := !directIP
		didRDAP := false
		for _, a := range r.Addresses {
			addr, err := netip.ParseAddr(a.Addr)
			if err == nil && classify.IsPublic(addr) {
				rd, _ := s.rdapClient.LookupIP(context.Background(), a.Addr)
				r.RDAP = &rd
				didRDAP = true
				break
			}
		}
		switch {
		case didDNS && didRDAP:
			r.DataSent = "hostname al resolver del sistema; primera IP pública al RIR vía RDAP"
		case didDNS:
			r.DataSent = "hostname al resolver del sistema; no se encontró una IP pública para RDAP"
		case didRDAP:
			r.DataSent = "IP pública al RIR vía RDAP"
		default:
			r.Notes = append(r.Notes, "No hubo salida externa: la IP no es pública y no aplica una consulta RDAP.")
		}
		if didDNS || didRDAP {
			r.QueriedAt = time.Now().UTC().Format(time.RFC3339)
		}
	} else {
		r.Notes = append(r.Notes, "Clasificación y GeoIP/ASN realizados únicamente con datos locales.")
	}
	return r, nil
}

// RDAPLookupIP queries RDAP (via the IANA bootstrap registry) for the RIR
// record covering ip. On-demand only — never called automatically (prompt
// maestro módulo 4 "RDAP bajo demanda").
func (s *Service) RDAPLookupIP(ip string) rdap.Result {
	res, _ := s.rdapClient.LookupIP(context.Background(), ip)
	return res
}

// RDAPLookupASN queries RDAP for the RIR record covering an Autonomous
// System number.
func (s *Service) RDAPLookupASN(asn int) rdap.Result {
	res, _ := s.rdapClient.LookupASN(context.Background(), asn)
	return res
}

// RDAPLookupDomain queries RDAP for the registration record of a domain name:
// registrador, fechas de alta y vencimiento, estados y servidores de nombres.
//
// Responde el hueco que dejaba Quick Diagnose: un dominio puede estar
// perfectamente registrado y aun así no resolver —porque no tiene registro A,
// porque venció, o porque el registro lo retuvo— y hasta ahora la app solo
// sabía decir "no resuelve", que es el síntoma y no la causa.
func (s *Service) RDAPLookupDomain(name string) rdap.DomainResult {
	res, _ := s.rdapClient.LookupDomain(context.Background(), name)
	if res.Notes == nil {
		res.Notes = []string{}
	}
	return res
}

// bgpAggregateTimeout bounds both the v1.1 BGP Intelligence aggregate
// calls below (Overview/Prefixes/Security/Topology), which fan out to
// several RIPEstat datasource calls sequentially/bounded-concurrently,
// and the single-call bindings (RoutingStatus/RPKIValidate/Observatory/
// History/BGPlay/BogonLookup) — mirrors the WithTimeout pattern already
// used elsewhere in this file for other multi-step operations, so a
// single slow/unresponsive upstream call cannot hang a Wails-bound
// method indefinitely (the bgp.Client http.Client timeout alone would
// still apply, but the explicit deadline keeps every bound method on
// the same contract).
const bgpAggregateTimeout = 30 * time.Second

// BGPRoutingStatus reports which ASN(s) currently announce a resource, via
// RIPEstat.
func (s *Service) BGPRoutingStatus(resource string) bgp.RouteStatus {
	ctx, cancel := context.WithTimeout(context.Background(), bgpAggregateTimeout)
	defer cancel()
	return s.bgpClient.RoutingStatus(ctx, resource)
}

// BGPRPKIValidate checks RPKI Route Origin Validation for (asn, prefix).
func (s *Service) BGPRPKIValidate(asn int, prefix string) bgp.RPKIStatus {
	ctx, cancel := context.WithTimeout(context.Background(), bgpAggregateTimeout)
	defer cancel()
	return s.bgpClient.RPKIValidate(ctx, asn, prefix)
}

// BGPOverview aggregates as-overview/routing-status/announced-prefixes/
// asn-neighbours/rpki-validation into one summary for a resource (ASN,
// IP, or prefix). Pure delegation — no BGP logic lives in this package.
func (s *Service) BGPOverview(resource string) bgp.Overview {
	ctx, cancel := context.WithTimeout(context.Background(), bgpAggregateTimeout)
	defer cancel()
	return s.bgpClient.Overview(ctx, resource)
}

// BGPPrefixes returns one filtered/sorted/paginated, page-enriched view
// of an ASN's announced prefixes (bgp.Client.PrefixList, §10 roadmap).
func (s *Service) BGPPrefixes(req bgp.PrefixPageRequest) bgp.PrefixPage {
	ctx, cancel := context.WithTimeout(context.Background(), bgpAggregateTimeout)
	defer cancel()
	return s.bgpClient.PrefixList(ctx, req)
}

// BGPSecurity produces a point-in-time security analysis (full RPKI
// coverage + Health) for a resource (ASN, IP, or prefix).
func (s *Service) BGPSecurity(resource string) bgp.SecurityResult {
	ctx, cancel := context.WithTimeout(context.Background(), bgpAggregateTimeout)
	defer cancel()
	return s.bgpClient.Security(ctx, resource)
}

// BGPNeighbours reports RIS-observed direct adjacencies for one ASN —
// "left"/"right", never a commercial relationship.
func (s *Service) BGPNeighbours(asn int) bgp.ASNNeighboursResult {
	ctx, cancel := context.WithTimeout(context.Background(), bgpAggregateTimeout)
	defer cancel()
	return s.bgpClient.AsnNeighboursRaw(ctx, asn)
}

// BGPTopology builds a bounded AS-path graph for a resource (ASN, IP, or
// prefix) from bgp-state — the sole source of Nodes/Edges/Routes.
func (s *Service) BGPTopology(resource string) bgp.Graph {
	ctx, cancel := context.WithTimeout(context.Background(), bgpAggregateTimeout)
	defer cancel()
	return s.bgpClient.Topology(ctx, resource)
}

// BGPHistory queries bgp-updates for req.Resource over a closed
// [req.StartTime, req.EndTime) window (v1.2 Gate 4, BGP_INTELLIGENCE_
// ROADMAP.md §23.6) — pure delegation, same pattern as every other BGP
// method above: validation, limits/truncation and Evidence all stay
// entirely inside bgp.Client.BGPHistory, never duplicated or
// reinterpreted here.
func (s *Service) BGPHistory(req bgp.BGPHistoryRequest) bgp.BGPHistoryResult {
	ctx, cancel := context.WithTimeout(context.Background(), bgpAggregateTimeout)
	defer cancel()
	return s.bgpClient.BGPHistory(ctx, req)
}

// BGPlay queries the bgplay endpoint for req.Resource over a closed
// [req.StartTime, req.EndTime) window (v1.2 Gate 4) — pure delegation,
// same pattern as BGPHistory.
func (s *Service) BGPlay(req bgp.BGPlayRequest) bgp.BGPlayResult {
	ctx, cancel := context.WithTimeout(context.Background(), bgpAggregateTimeout)
	defer cancel()
	return s.bgpClient.BGPlay(ctx, req)
}

// BGPCountryObservatory queries RIPEstat country-resource-stats for
// req.Country over [req.StartTime, req.EndTime) at req.Resolution (v1.3
// Gate 1) — pure delegation, same pattern as every other BGP method
// above: validation, the registered/routed distinction, and Evidence all
// stay entirely inside bgp.Client.CountryObservatory, never duplicated
// or reinterpreted here.
func (s *Service) BGPCountryObservatory(req bgp.CountryObservatoryRequest) bgp.CountryObservatoryResult {
	ctx, cancel := context.WithTimeout(context.Background(), bgpAggregateTimeout)
	defer cancel()
	return s.bgpClient.CountryObservatory(ctx, req)
}

// BGPGlobalObservatory queries RIPEstat ris-asns/ris-peer-count for a
// global RIS snapshot (v1.3 Gate 2) — pure delegation. Takes no
// parameters: the underlying call is global, not resource-scoped.
func (s *Service) BGPGlobalObservatory() bgp.GlobalRISObservatoryResult {
	ctx, cancel := context.WithTimeout(context.Background(), bgpAggregateTimeout)
	defer cancel()
	return s.bgpClient.GlobalRISObservatory(ctx)
}

// BGPASNObservatory reports RIS-observed IPv4/IPv6 announced prefix
// counts for req.ASN (v1.3 Gate 2) — pure delegation to
// bgp.Client.ASNObservatory, which itself reuses ClassifyResource and
// AnnouncedPrefixesRaw rather than duplicating either.
func (s *Service) BGPASNObservatory(req bgp.ASNObservatoryRequest) bgp.ASNObservatoryResult {
	ctx, cancel := context.WithTimeout(context.Background(), bgpAggregateTimeout)
	defer cancel()
	return s.bgpClient.ASNObservatory(ctx, req)
}

// BGPRPKIObservatory queries RIPEstat rpki-history for req.Resource
// (ASN or ISO country) over req.Family/req.Resolution (v1.3 Gate 3) —
// pure delegation. VRP count is not route validity; see
// bgp.RPKIObservatoryResult.
func (s *Service) BGPRPKIObservatory(req bgp.RPKIObservatoryRequest) bgp.RPKIObservatoryResult {
	ctx, cancel := context.WithTimeout(context.Background(), bgpAggregateTimeout)
	defer cancel()
	return s.bgpClient.RPKIObservatory(ctx, req)
}

// BGPBogonLookup classifies req.Resource against IANA's special-purpose
// registry and Team Cymru's Fullbogons list (v1.3 Gate 4) — pure
// delegation. Special-purpose is not fullbogon, and fullbogon is not
// malicious; see bgp.BogonLookupResult.
func (s *Service) BGPBogonLookup(req bgp.BogonLookupRequest) bgp.BogonLookupResult {
	ctx, cancel := context.WithTimeout(context.Background(), bgpAggregateTimeout)
	defer cancel()
	return s.bgpClient.BogonLookup(ctx, req)
}

// feedWeight is how many points a hit on each kind of list costs.
//
// A DROP listing weighs the same as a bogon (70) and for the same reason: both
// mean "this address should not be carrying your traffic at all". Spamhaus is
// asserting the range is criminal infrastructure and its literal recommendation
// is to drop the traffic, so the verdict has to land in "alto riesgo" on its
// own. 60 was tried first and left it at exactly 40 — the boundary of merely
// "sospechoso", which understates what the source is saying.
//
// A Tor exit is deliberately mild: Tor carries legitimate traffic every day,
// and the only fact worth surfacing is that the real origin is unattributable.
var feedWeight = map[threatfeed.Category]int{
	threatfeed.CatMalicious: 70,
	threatfeed.CatTor:       30,
}

// ReputationAssess scores an address from offline data only (prompt maestro
// §9 Fase 4, módulo 23). No network call: the downloaded lists are consulted
// locally, so scoring never reveals which address is being looked at.
func (s *Service) ReputationAssess(ip string) (reputation.Score, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return reputation.Score{}, fmt.Errorf("IP inválida: %w", err)
	}
	score := reputation.AssessOffline(addr)
	if s.threatFeed == nil {
		return score, nil
	}

	for _, hit := range s.threatFeed.Lookup(addr) {
		detail := hit.Detail
		if hit.Prefix != "" {
			detail += " (rango " + hit.Prefix + ")"
		}
		if hit.Ref != "" {
			detail += " · " + hit.Ref
		}
		score = reputation.WithAdapterSignal(score, reputation.Signal{
			Source:     "feed:" + hit.Feed,
			Label:      string(hit.Category),
			Detail:     detail,
			Confidence: "alta",
		}, feedWeight[hit.Category])
	}

	// Sin esto, "limpio" es ambiguo: no distingue "se comprobó y no aparece" de
	// "no hay ninguna lista contra la que comprobar".
	if !s.threatFeed.Loaded() {
		score.Freshness += " — sin listas de amenazas descargadas: este resultado no incluye comprobación contra Spamhaus DROP ni nodos Tor (Settings / Datasets)"
	}
	return score, nil
}

// ThreatFeedSources lists every downloadable threat list and whether it is
// present locally.
func (s *Service) ThreatFeedSources() []threatfeed.SourceInfo {
	if s.threatFeed == nil {
		return []threatfeed.SourceInfo{}
	}
	return s.threatFeed.Sources()
}

// ThreatFeedUpdate downloads one threat list. Explicit external action, only
// ever triggered from Settings.
func (s *Service) ThreatFeedUpdate(id string) (threatfeed.SourceInfo, error) {
	if s.threatFeed == nil {
		return threatfeed.SourceInfo{}, errors.New("motor de listas no disponible")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return s.threatFeed.Update(ctx, id)
}

// ThreatFeedRemove deletes one threat list from the local store.
func (s *Service) ThreatFeedRemove(id string) error {
	if s.threatFeed == nil {
		return errors.New("motor de listas no disponible")
	}
	return s.threatFeed.Remove(id)
}

// PhoneAnalyze identifies a phone number: validity, country, line type and
// carrier. Entirely local — the libphonenumber metadata is compiled in, so a
// number, which is personal data, never leaves the machine.
func (s *Service) PhoneAnalyze(input, region string) phoneintel.Result {
	return phoneintel.Analyze(input, region)
}

// MonitorAddTarget registers a new historical-monitor target (prompt
// maestro §9 Fase 5, módulo 25).
func (s *Service) MonitorAddTarget(t monitor.Target) (monitor.Target, error) {
	return s.monitorMgr.AddTarget(t)
}

// MonitorListTargets lists every registered target and whether it's running.
func (s *Service) MonitorListTargets() []MonitorTargetInfo {
	targets := s.monitorMgr.ListTargets()
	out := make([]MonitorTargetInfo, 0, len(targets))
	for _, t := range targets {
		out = append(out, MonitorTargetInfo{Target: t, Running: s.monitorMgr.IsRunning(t.ID)})
	}
	return out
}

// MonitorRemoveTarget stops (if running) and deletes a monitored target.
func (s *Service) MonitorRemoveTarget(id string) error {
	return s.monitorMgr.RemoveTarget(id)
}

// MonitorHistory returns the persisted history for a target, optionally
// trimmed to the last sinceMs milliseconds (0 = everything on disk).
func (s *Service) MonitorHistory(id string, sinceMs int64) (monitor.History, error) {
	return s.monitorMgr.History(id, time.Duration(sinceMs)*time.Millisecond)
}

// MonitorCompareWindows contrasts the most recent window against the one
// before it (módulo 25 "comparación de ventanas").
func (s *Service) MonitorCompareWindows(id string, windowMs int64) (monitor.WindowComparison, error) {
	return s.monitorMgr.CompareWindows(id, time.Duration(windowMs)*time.Millisecond)
}

// MonitorPinBaseline fixes a historical window (ending sinceMs ago, spanning
// windowMs before that) as the target's reference "quiet network" profile —
// distinct from the rolling baseline degradation events already use, which
// drifts and absorbs sustained load as the new normal.
func (s *Service) MonitorPinBaseline(id string, sinceMs, windowMs int64) (monitor.BaselineProfile, error) {
	return s.monitorMgr.PinBaseline(id, time.Duration(sinceMs)*time.Millisecond, time.Duration(windowMs)*time.Millisecond)
}

// MonitorClearBaseline removes a target's pinned baseline, if any.
func (s *Service) MonitorClearBaseline(id string) error {
	return s.monitorMgr.ClearBaseline(id)
}

// MonitorCompareToBaseline contrasts the pinned baseline against the last
// hour of live samples.
func (s *Service) MonitorCompareToBaseline(id string) (monitor.BaselineComparison, error) {
	return s.monitorMgr.CompareToBaseline(id)
}

// MonitorReport builds a módulo-26 Report from a target's history — with a
// window comparison attached when windowMs > 0 — ready for the GUI to
// export as JSON/CSV/HTML/PDF.
func (s *Service) MonitorReport(id string, sinceMs, windowMs int64) (report.Report, error) {
	h, err := s.monitorMgr.History(id, time.Duration(sinceMs)*time.Millisecond)
	if err != nil {
		return report.Report{}, err
	}
	var cmp *monitor.WindowComparison
	if windowMs > 0 {
		c, err := s.monitorMgr.CompareWindows(id, time.Duration(windowMs)*time.Millisecond)
		if err == nil {
			cmp = &c
		}
	}
	return monitor.ToReport(h, cmp, Version), nil
}

// VoipQualityAddTarget registers a new tracked "línea" (VoIP destination) —
// every future VoIP analysis is checked against it, no history is required
// upfront.
func (s *Service) VoipQualityAddTarget(t quality.Target) (quality.Target, error) {
	return s.voipQualMgr.AddTarget(t)
}

// VoipQualityListTargets lists every registered línea.
func (s *Service) VoipQualityListTargets() []quality.Target {
	return s.voipQualMgr.ListTargets()
}

// VoipQualityRemoveTarget deletes a tracked línea and its stored history.
func (s *Service) VoipQualityRemoveTarget(id string) error {
	return s.voipQualMgr.RemoveTarget(id)
}

// VoipQualityHistory returns the persisted call-quality history for a línea,
// optionally trimmed to the last sinceMs milliseconds (0 = everything on
// disk).
func (s *Service) VoipQualityHistory(id string, sinceMs int64) (quality.History, error) {
	return s.voipQualMgr.History(id, time.Duration(sinceMs)*time.Millisecond)
}

// VoipQualityCompareWindows contrasts the most recent window of calls
// against the one before it, so a drop in quality (higher jitter/loss, lower
// MOS) shows up as a delta instead of requiring the user to eyeball numbers.
func (s *Service) VoipQualityCompareWindows(id string, windowMs int64) (quality.WindowComparison, error) {
	return s.voipQualMgr.CompareWindows(id, time.Duration(windowMs)*time.Millisecond)
}

// LabScenarios lists every available lab scenario (módulo 27), without
// generating any capture yet.
func (s *Service) LabScenarios() []lab.Scenario {
	return lab.List()
}

// LabRunScenario writes (or reuses) a scenario's deterministic synthetic
// capture under the user's config directory, analyzes it through the real
// TRAZIP engines and compares the findings against what the scenario
// expects. The written PCAP path is returned in the result so the student
// can also open it directly in PCAP Analyzer / VoIP Calls.
func (s *Service) LabRunScenario(id string) (lab.RunResult, error) {
	sc, ok := lab.Get(id)
	if !ok {
		return lab.RunResult{}, fmt.Errorf("escenario no encontrado: %s", id)
	}
	return sc.Run(context.Background(), labDir())
}

// LabReport builds a módulo-26 Report from a lab run — "exportación de
// evidencia para cursos."
func (s *Service) LabReport(id string) (report.Report, error) {
	sc, ok := lab.Get(id)
	if !ok {
		return report.Report{}, fmt.Errorf("escenario no encontrado: %s", id)
	}
	res, err := sc.Run(context.Background(), labDir())
	if err != nil {
		return report.Report{}, err
	}
	return lab.ToReport(sc, res, Version), nil
}

func labDir() string {
	return paths.Sub("lab")
}

// Capabilities reports what the current environment supports.
func (s *Service) Capabilities() Capabilities {
	c := Capabilities{
		Platform: runtime.GOOS,
		Arch:     runtime.GOARCH,
		Elevated: s.elevated,
		Version:  Version,
		Portable: paths.Portable(),
		DataDir:  paths.Root(),
	}
	switch runtime.GOOS {
	case "windows":
		c.LiveCapture = capture.Available()
		c.CaptureNote = "Captura en vivo requiere Npcap; lectura de PCAP no necesita driver."
		c.RawSockets = s.elevated
	case "darwin":
		c.LiveCapture = capture.Available()
		c.CaptureNote = "Captura en vivo aún no está disponible en la build pure-Go de macOS; lectura PCAP sí."
		c.RawSockets = s.elevated
	default:
		c.CaptureNote = "Plataforma no objetivo; funciones live limitadas."
	}
	return c
}

// StartSession creates a new work session and returns its info.
func (s *Service) StartSession(label string) SessionInfo {
	if strings.TrimSpace(label) == "" {
		label = "session"
	}
	sess := s.sessions.New(context.Background(), label)
	return toSessionInfo(sess)
}

// ListSessions returns all live sessions.
func (s *Service) ListSessions() []SessionInfo {
	live := s.sessions.List()
	out := make([]SessionInfo, 0, len(live))
	for _, sess := range live {
		out = append(out, toSessionInfo(sess))
	}
	return out
}

// CancelSession cancels a session by ID.
func (s *Service) CancelSession(id string) {
	s.sessions.Cancel(id)
}

// ClassifyIP returns the offline classification of a single IP string.
func (s *Service) ClassifyIP(ip string) (AddrReport, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return AddrReport{}, fmt.Errorf("dirección inválida: %q", ip)
	}
	return s.addrReport(addr), nil
}

// QuickDiagnose runs the coordinated, offline-safe diagnosis of a target that
// may be an IP, hostname, or URL: it extracts the host, resolves DNS, and
// classifies every resulting address. Active probes come from later phases.
func (s *Service) QuickDiagnose(input string) (DiagnoseResult, error) {
	start := time.Now()
	// Addrs arranca como arreglo vacío y no nil: hay varios retornos tempranos
	// —entrada vacía, fallo de DNS— y un slice nil marshalea a null, que revienta
	// el .length de la vista. El contrato es "addrs es un arreglo", siempre.
	res := DiagnoseResult{Input: input, Addrs: []AddrReport{}}
	target := strings.TrimSpace(input)
	if target == "" {
		return res, fmt.Errorf("entrada vacía")
	}

	host := target
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			host = u.Hostname()
			res.Kind = "url"
		}
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		res.Kind = "ip"
		res.Host = host
		res.Addrs = []AddrReport{s.addrReport(addr)}
		res.DurationMs = time.Since(start).Milliseconds()
		return res, nil
	}

	if res.Kind == "" {
		res.Kind = "host"
	}
	res.Host = host

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		res.Notes = append(res.Notes, "No se pudo resolver DNS: "+err.Error())
		res.DurationMs = time.Since(start).Milliseconds()
		return res, nil
	}
	seen := map[netip.Addr]bool{}
	for _, a := range ips {
		a = a.Unmap()
		if seen[a] {
			continue
		}
		seen[a] = true
		res.Addrs = append(res.Addrs, s.addrReport(a))
	}
	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}

// AnalyzePcap reads a capture file, returning file info, a bounded set of packet
// summaries, and the aggregated bidirectional flows. Shared by GUI and CLI.
func (s *Service) AnalyzePcap(path string) (PcapResult, error) {
	if strings.TrimSpace(path) == "" {
		return PcapResult{}, fmt.Errorf("ruta vacía")
	}
	ft := flow.New()
	detector := scandetect.New()
	l2 := netdiag.New()
	pkts := make([]packet.Summary, 0, 1024)
	info, err := pcap.Read(context.Background(), path, func(su packet.Summary) {
		ft.Add(su)
		detector.Add(su)
		l2.Add(su)
		if len(pkts) < pcapUILimit {
			pkts = append(pkts, su)
		}
	}, pcap.Options{})
	if err != nil {
		return PcapResult{}, err
	}
	flows := ft.Flows()
	totalFlows := len(flows)
	endpoints := s.endpointsFromFlows(flows)
	totalEndpoints := len(endpoints)
	hosts, countries, asns := s.topTalkers(flows)

	// res.Flows/res.Endpoints start out as the FULL slices — summarizePcap
	// below must see everything the analysis actually found, not whatever
	// happens to survive the Wails UI payload caps (V1 hardening finding
	// #3: a SIP flow or a TCP reset past flowUILimit/endpointUILimit was
	// silently invisible to the summary, even though TotalFlows/
	// TotalEndpoints already reported the true counts). applyPcapUILimits
	// caps them only after the summary is built.
	res := PcapResult{
		Info:           info,
		Packets:        pkts,
		Flows:          flows,
		TotalPackets:   info.Packets,
		ShownPackets:   len(pkts),
		TotalFlows:     totalFlows,
		TopHosts:       hosts,
		TopCountries:   countries,
		TopASN:         asns,
		GeoAvailable:   s.geo.Available(),
		Endpoints:      endpoints,
		TotalEndpoints: totalEndpoints,
		ScanDetection:  detector.Result(),
		NetDiag:        s.enrichNetDiag(l2.Result()),
	}
	res.Summary = summarizePcap(res)
	applyPcapUILimits(&res)
	return res, nil
}

// applyPcapUILimits caps Flows/Endpoints for the Wails payload — always
// AFTER summarizePcap has already read the full, untruncated data (V1
// hardening finding #3). TotalFlows/TotalEndpoints and every count inside
// Summary.Stats keep reflecting the true totals; only the raw slices
// returned to the UI are bounded. Split out from AnalyzePcap so the
// ordering itself — full data in, caps applied last — is directly
// unit-testable without a real PCAP file.
func applyPcapUILimits(res *PcapResult) {
	if len(res.Endpoints) > endpointUILimit {
		res.Endpoints = res.Endpoints[:endpointUILimit]
	}
	if len(res.Flows) > flowUILimit {
		res.Flows = res.Flows[:flowUILimit]
	}
}

// EnrichNetDiag is the exported form used by the live capture path in app.go,
// so file analysis and live capture annotate MACs identically.
func (s *Service) EnrichNetDiag(r netdiag.Result) netdiag.Result { return s.enrichNetDiag(r) }

// enrichNetDiag puts a manufacturer name next to every MAC. netdiag stays a
// pure detector with no dataset dependency — the same separation GeoIP has —
// so the lookup happens here. It matters in practice: "1c:0b:8b:… (Ubiquiti)"
// tells the operator which box to go look at, a bare MAC does not.
func (s *Service) enrichNetDiag(r netdiag.Result) netdiag.Result {
	if s.oui == nil {
		return r
	}
	for i := range r.Neighbors {
		r.Neighbors[i].Vendor = s.vendorOf(r.Neighbors[i].MAC)
	}
	for i := range r.Findings {
		if v := s.vendorOf(r.Findings[i].Subject); v != "" {
			r.Findings[i].Subject += " · " + v
		}
	}
	return r
}

type endpointAcc struct {
	endpoint model.Endpoint
	packets  int
	bytes    int64
}

// endpointsFromFlows materializes the central Endpoint/Evidence model from
// observed traffic, then converts it to stable DTOs for Wails and the CLI.
func (s *Service) endpointsFromFlows(flows []flow.Flow) []EndpointInfo {
	acc := make(map[netip.Addr]*endpointAcc)
	add := func(raw string, packets int, bytes int64, first, last string) {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return
		}
		addr = addr.Unmap()
		a := acc[addr]
		if a == nil {
			a = &endpointAcc{endpoint: model.Endpoint{Addr: addr, Classes: classify.Classify(addr)}}
			if classify.IsPublic(addr) {
				g := s.geo.Lookup(addr)
				if g.Country != "" || g.City != "" {
					a.endpoint.Geo = &model.GeoIP{Country: g.Country, CountryCode: g.CountryCode, City: g.City, Latitude: g.Lat, Longitude: g.Lon}
				}
				if g.ASN != 0 {
					a.endpoint.ASN = &model.ASN{Number: g.ASN, Organization: g.Org}
				}
			}
			acc[addr] = a
		}
		if ts, err := time.Parse(time.RFC3339Nano, first); err == nil && (a.endpoint.FirstSeen.IsZero() || ts.Before(a.endpoint.FirstSeen)) {
			a.endpoint.FirstSeen = ts
		}
		if last == "" {
			last = first
		}
		if ts, err := time.Parse(time.RFC3339Nano, last); err == nil && ts.After(a.endpoint.LastSeen) {
			a.endpoint.LastSeen = ts
		}
		a.packets += packets
		a.bytes += bytes
	}
	for _, f := range flows {
		add(f.AAddr, f.Packets, f.Bytes, f.Start, f.End)
		add(f.BAddr, f.Packets, f.Bytes, f.Start, f.End)
	}

	out := make([]EndpointInfo, 0, len(acc))
	for _, a := range acc {
		ts := a.endpoint.LastSeen
		if ts.IsZero() {
			ts = a.endpoint.FirstSeen
		}
		a.endpoint.Assessments = nil
		ev := model.Evidence{
			Type: "traffic_observation", Value: fmt.Sprintf("%d paquetes / %d bytes", a.packets, a.bytes),
			Source: "pcap", Provenance: model.ProvObserved, Timestamp: ts, Confidence: 100,
			Explain: "Dirección observada directamente en flujos decodificados de la captura.",
		}
		classes := make([]string, len(a.endpoint.Classes))
		for i, c := range a.endpoint.Classes {
			classes[i] = string(c)
		}
		row := EndpointInfo{
			Addr: a.endpoint.Addr.String(), Classes: classes, Packets: a.packets, Bytes: a.bytes,
			Evidence: []EvidenceInfo{{Type: ev.Type, Value: ev.Value, Source: ev.Source, Provenance: string(ev.Provenance), Timestamp: ev.Timestamp.Format(time.RFC3339Nano), Confidence: uint8(ev.Confidence), Explain: ev.Explain}},
		}
		if !a.endpoint.FirstSeen.IsZero() {
			row.FirstSeen = a.endpoint.FirstSeen.Format(time.RFC3339Nano)
		}
		if !a.endpoint.LastSeen.IsZero() {
			row.LastSeen = a.endpoint.LastSeen.Format(time.RFC3339Nano)
		}
		if a.endpoint.Geo != nil {
			row.Country, row.CountryCode, row.City = a.endpoint.Geo.Country, a.endpoint.Geo.CountryCode, a.endpoint.Geo.City
		}
		if a.endpoint.ASN != nil {
			row.ASN, row.Org = a.endpoint.ASN.Number, a.endpoint.ASN.Organization
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

// topTalkers aggregates flow endpoints into top hosts, countries and ASNs,
// enriching public addresses with offline GeoIP/ASN.
func (s *Service) topTalkers(flows []flow.Flow) (hosts, countries, asns []TalkerRow) {
	type acc struct {
		pkts    int
		bytes   int64
		country string
		asn     uint32
		org     string
	}
	hostM := map[string]*acc{}
	countryM := map[string]*acc{}
	asnM := map[string]*acc{}

	addHost := func(ip string, pkts int, bytes int64) {
		a := hostM[ip]
		if a == nil {
			a = &acc{}
			if addr, err := netip.ParseAddr(ip); err == nil && classify.IsPublic(addr) {
				g := s.geo.Lookup(addr)
				a.country = g.Country
				a.asn = g.ASN
				a.org = g.Org
			}
			hostM[ip] = a
		}
		a.pkts += pkts
		a.bytes += bytes
	}

	for _, f := range flows {
		addHost(f.AAddr, f.Packets, f.Bytes)
		addHost(f.BAddr, f.Packets, f.Bytes)
	}
	for ip, a := range hostM {
		if a.country != "" {
			c := countryM[a.country]
			if c == nil {
				c = &acc{country: a.country}
				countryM[a.country] = c
			}
			c.pkts += a.pkts
			c.bytes += a.bytes
		}
		if a.asn != 0 {
			key := "AS" + itoa(int(a.asn))
			c := asnM[key]
			if c == nil {
				c = &acc{asn: a.asn, org: a.org}
				asnM[key] = c
			}
			c.pkts += a.pkts
			c.bytes += a.bytes
		}
		_ = ip
	}

	toRows := func(m map[string]*acc, label func(k string, a *acc) string) []TalkerRow {
		rows := make([]TalkerRow, 0, len(m))
		for k, a := range m {
			rows = append(rows, TalkerRow{Key: k, Label: label(k, a), Packets: a.pkts, Bytes: a.bytes, Country: a.country, ASN: a.asn, Org: a.org})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Bytes > rows[j].Bytes })
		if len(rows) > 20 {
			rows = rows[:20]
		}
		return rows
	}

	hosts = toRows(hostM, func(k string, _ *acc) string { return k })
	countries = toRows(countryM, func(k string, _ *acc) string { return k })
	asns = toRows(asnM, func(k string, a *acc) string {
		if a.org != "" {
			return k + " · " + a.org
		}
		return k
	})
	return hosts, countries, asns
}

func itoa(n int) string { return strconv.Itoa(n) }

// ---- Categoría de red (netclass) ----

// NetClassSources lists every downloadable provider list and whether it is
// installed, for Settings/Datasets.
func (s *Service) NetClassSources() []netclass.SourceInfo {
	if s.netClass == nil {
		return nil
	}
	return s.netClass.Sources()
}

// NetClassUpdate downloads one provider list. This is an explicit external
// request (§5.7): it only ever runs when the operator clicks Download, and the
// returned SourceInfo records exactly what was fetched, when, and its hash.
func (s *Service) NetClassUpdate(id string) (netclass.SourceInfo, error) {
	if s.netClass == nil {
		return netclass.SourceInfo{}, fmt.Errorf("motor de categorías no disponible")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return s.netClass.Update(ctx, id)
}

// NetClassRemove deletes one provider list from the local store.
func (s *Service) NetClassRemove(id string) error {
	if s.netClass == nil {
		return fmt.Errorf("motor de categorías no disponible")
	}
	return s.netClass.Remove(id)
}

// ---- IP calculator (módulo "Calculadora IP") ----
//
// All of these are pure offline computation (see internal/ipcalc), so they are
// plain synchronous calls rather than cancellable sessions: there is nothing to
// stream and nothing to stop.

// IPCalcAnalyze breaks down an address or prefix.
func (s *Service) IPCalcAnalyze(input string) (ipcalc.Info, error) {
	return ipcalc.Analyze(input)
}

// IPCalcSplit divides a prefix into equal subnets of newBits length.
func (s *Service) IPCalcSplit(input string, newBits int) (ipcalc.SplitResult, error) {
	return ipcalc.Split(input, newBits)
}

// IPCalcVLSM plans variable-length subnets inside a prefix.
func (s *Service) IPCalcVLSM(input string, reqs []ipcalc.VLSMRequest) (ipcalc.VLSMResult, error) {
	return ipcalc.VLSM(input, reqs)
}

// IPCalcCustomerPlan calculates the smallest conventional IPv4 block that can
// deliver requested customer addresses plus an optional provider gateway.
func (s *Service) IPCalcCustomerPlan(requested uint64, reserveGateway bool) (ipcalc.CustomerPlan, error) {
	return ipcalc.PlanCustomerIPs(requested, reserveGateway)
}

// IPCalcAggregate merges a set of prefixes into the smallest equivalent set.
func (s *Service) IPCalcAggregate(inputs []string) ([]string, error) {
	return ipcalc.Aggregate(inputs)
}

// IPCalcContains reports whether an address falls inside a prefix.
func (s *Service) IPCalcContains(prefix, addr string) (bool, error) {
	return ipcalc.Contains(prefix, addr)
}

// ---- Fabricante por MAC (IEEE OUI) ----

// OUIInfo reports whether the IEEE registries are installed.
func (s *Service) OUIInfo() oui.Info {
	if s.oui == nil {
		return oui.Info{}
	}
	return s.oui.Info()
}

// OUIUpdate downloads the three IEEE registries. Explicit external request,
// same rule as every other dataset: it only runs when the operator asks.
func (s *Service) OUIUpdate() (oui.Info, error) {
	if s.oui == nil {
		return oui.Info{}, fmt.Errorf("motor OUI no disponible")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return s.oui.Update(ctx)
}

// OUIRemove deletes the downloaded registries, falling back to the built-in table.
func (s *Service) OUIRemove() error {
	if s.oui == nil {
		return fmt.Errorf("motor OUI no disponible")
	}
	return s.oui.Remove()
}

// MACVendor resolves a MAC to its manufacturer, preferring the downloaded IEEE
// registries over the small built-in table. Exported because the LAN scanner
// lives in app.go and needs the same resolution the passive views get —
// without it the scan results fall back to internal/lan's 24-entry table and
// nearly every device reads as "desconocido".
func (s *Service) MACVendor(mac string) string { return s.vendorOf(mac) }

// MACLookup resolves one MAC and explains the result, for the lookup tool in
// LAN Explorer. Pure local computation over the installed registries.
func (s *Service) MACLookup(mac string) oui.Detail {
	if s.oui == nil {
		return oui.Detail{Input: mac}
	}
	return s.oui.LookupDetail(mac)
}

func (s *Service) vendorOf(mac string) string {
	if s.oui == nil || mac == "" {
		return ""
	}
	return s.oui.Lookup(mac)
}

// LanDiscover enumerates local interfaces and reads the system ARP/NDP table
// (passive; no packets sent), then upgrades every vendor name with the IEEE
// registries when they are installed. internal/lan only knows its own small
// built-in table; the dataset lives here, next to the other downloadables.
func (s *Service) LanDiscover() lan.Report {
	r := lan.Discover()
	for i := range r.Interfaces {
		if v := s.vendorOf(r.Interfaces[i].MAC); v != "" {
			r.Interfaces[i].Vendor = v
		}
	}
	for i := range r.Neighbors {
		if v := s.vendorOf(r.Neighbors[i].MAC); v != "" {
			r.Neighbors[i].Vendor = v
		}
	}
	return r
}

// ConnMonSnapshot lists this machine's own active TCP/UDP sockets (module
// "Conexiones") and enriches each unique public remote address with the same
// classification/GeoIP addrReport() already builds for QuickDiagnose/Endpoints
// — cached per call so a snapshot with many sockets to the same host (e.g.
// several connections to one CDN edge) only looks that address up once.
// Entirely passive: connmon.List() only reads OS-provided socket tables.
func (s *Service) ConnMonSnapshot() (ConnMonSnapshot, error) {
	conns, err := connmon.List()
	if err != nil {
		return ConnMonSnapshot{}, err
	}

	cache := map[string]AddrReport{}
	rows := make([]ConnRow, len(conns))
	for i, c := range conns {
		row := ConnRow{
			Proto: c.Proto, LocalAddr: c.LocalAddr, LocalPort: c.LocalPort,
			RemoteAddr: c.RemoteAddr, RemotePort: c.RemotePort,
			State: c.State, PID: c.PID, Process: c.Process,
		}
		if addr, err := netip.ParseAddr(c.RemoteAddr); err == nil && !addr.IsUnspecified() {
			if rep, ok := cache[c.RemoteAddr]; ok {
				row.Remote = &rep
			} else {
				rep := s.addrReport(addr)
				cache[c.RemoteAddr] = rep
				row.Remote = &rep
			}
		}
		rows[i] = row
	}
	return ConnMonSnapshot{Connections: rows, Total: len(rows)}, nil
}

func (s *Service) addrReport(addr netip.Addr) AddrReport {
	classes := classify.Classify(addr)
	cs := make([]string, len(classes))
	for i, c := range classes {
		cs[i] = string(c)
	}
	fam := "IPv6"
	if addr.Is4() || addr.Is4In6() {
		fam = "IPv4"
	}
	r := AddrReport{
		Addr:     addr.String(),
		Family:   fam,
		Classes:  cs,
		IsPublic: classify.IsPublic(addr),
	}
	if r.IsPublic {
		g := s.geo.Lookup(addr)
		r.Country, r.CountryCode, r.City = g.Country, g.CountryCode, g.City
		r.ASN, r.Org = g.ASN, g.Org
		r.Lat, r.Lon = g.Lat, g.Lon
		// The org name from GeoIP feeds the heuristic fallback, so this has to
		// run after the lookup above, not before.
		if s.netClass != nil {
			if m, ok := s.netClass.Lookup(addr, g.Org); ok {
				r.NetClass = &m
			}
		}
	}
	return r
}

func toSessionInfo(s *session.Session) SessionInfo {
	return SessionInfo{
		ID:         s.ID,
		Label:      s.Label,
		State:      string(s.State()),
		Created:    s.Created.Format(time.RFC3339),
		ScopeLabel: s.Scope.Label(),
		Authorized: s.Scope.Authorized(),
	}
}
