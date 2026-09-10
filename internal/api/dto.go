// Package api exposes TRAZIP's backend to the Wails frontend and CLI through
// small, serialization-friendly DTOs. Domain types (net/netip, time.Time) are
// converted to strings here so the generated TypeScript bindings stay clean.
package api

import (
	"trazip/internal/correlation"
	"trazip/internal/detection/netdiag"
	"trazip/internal/detection/scandetect"
	"trazip/internal/flow"
	"trazip/internal/intel/netclass"
	"trazip/internal/monitor"
	"trazip/internal/packet"
	"trazip/internal/pcap"
	"trazip/internal/rdap"
)

// ConnRow is one local socket enriched for the GUI: raw connmon.Connection
// plus offline classification/GeoIP on the remote address when it's public
// (module "Conexiones" — reuses the same enrichment as AddrReport elsewhere).
type ConnRow struct {
	Proto      string      `json:"proto"`
	LocalAddr  string      `json:"localAddr"`
	LocalPort  int         `json:"localPort"`
	RemoteAddr string      `json:"remoteAddr"`
	RemotePort int         `json:"remotePort"`
	State      string      `json:"state,omitempty"`
	PID        int         `json:"pid,omitempty"`
	Process    string      `json:"process,omitempty"`
	Remote     *AddrReport `json:"remote,omitempty"`
}

// ConnMonSnapshot is one poll of the local machine's active sockets.
type ConnMonSnapshot struct {
	Connections []ConnRow `json:"connections"`
	Total       int       `json:"total"`
}

// MonitorTargetInfo pairs a monitor.Target with whether it's currently
// running, so the GUI never has to make a second call just to know.
type MonitorTargetInfo struct {
	Target  monitor.Target `json:"target"`
	Running bool           `json:"running"`
}

// EvidenceInfo is the serialization-safe API form of model.Evidence.
type EvidenceInfo struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Source     string `json:"source"`
	Provenance string `json:"provenance"`
	Timestamp  string `json:"timestamp"`
	Confidence uint8  `json:"confidence"`
	Explain    string `json:"explain,omitempty"`
}

// EndpointInfo is one correlated address observed in the analyzed capture.
// It is the first concrete consumer of the central Endpoint/Evidence model.
type EndpointInfo struct {
	Addr        string         `json:"addr"`
	Classes     []string       `json:"classes,omitempty"`
	FirstSeen   string         `json:"firstSeen,omitempty"`
	LastSeen    string         `json:"lastSeen,omitempty"`
	Packets     int            `json:"packets"`
	Bytes       int64          `json:"bytes"`
	Country     string         `json:"country,omitempty"`
	CountryCode string         `json:"countryCode,omitempty"`
	City        string         `json:"city,omitempty"`
	ASN         uint32         `json:"asn,omitempty"`
	Org         string         `json:"org,omitempty"`
	Evidence    []EvidenceInfo `json:"evidence"`
}

// TalkerRow is an aggregated top-talker entry (Raw Traffic GeoIP, §9 Fase 1 #6).
type TalkerRow struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Packets int    `json:"packets"`
	Bytes   int64  `json:"bytes"`
	Country string `json:"country,omitempty"`
	ASN     uint32 `json:"asn,omitempty"`
	Org     string `json:"org,omitempty"`
}

// PcapResult is the analysis of a capture file: file info, a bounded slice of
// packet summaries for the table, the aggregated flows, and top talkers enriched
// with offline GeoIP/ASN.
type PcapResult struct {
	Info           pcap.Info         `json:"info"`
	Packets        []packet.Summary  `json:"packets"`
	Flows          []flow.Flow       `json:"flows"`
	TotalPackets   int               `json:"totalPackets"`
	ShownPackets   int               `json:"shownPackets"`
	TotalFlows     int               `json:"totalFlows"`
	TopHosts       []TalkerRow       `json:"topHosts"`
	TopCountries   []TalkerRow       `json:"topCountries"`
	TopASN         []TalkerRow       `json:"topASN"`
	GeoAvailable   bool              `json:"geoAvailable"`
	Endpoints      []EndpointInfo    `json:"endpoints"`
	TotalEndpoints int               `json:"totalEndpoints"`
	ScanDetection  scandetect.Result `json:"scanDetection"`
	NetDiag        netdiag.Result    `json:"netDiag"`
	// Summary is "what should I look at in this capture" — correlated
	// entirely from the fields above (Phase C, "PCAP INCIDENT SUMMARY"),
	// never a second, independent analysis pass.
	Summary correlation.PcapIncidentSummary `json:"summary"`
}

type PassiveOSINTResult struct {
	Input     string       `json:"input"`
	Host      string       `json:"host"`
	External  bool         `json:"external"`
	Addresses []AddrReport `json:"addresses"`
	RDAP      *rdap.Result `json:"rdap,omitempty"`
	Notes     []string     `json:"notes,omitempty"`
	QueriedAt string       `json:"queriedAt,omitempty"`
	DataSent  string       `json:"dataSent,omitempty"`
}

// OSINTProviderInfo is the read-only, serialization-safe view of one entry in
// the OSINT Registry (internal/osint). It is metadata only: there is no field
// that exposes a runnable provider, and V1.5-3 ships no real providers, so
// Service.ListOSINTProviders returns an empty slice until a provider is
// registered. ActivityClass / DisclosureClass are the string forms
// ("passive"/"active", "local"/"passive"/"active") of the domain enums.
type OSINTProviderInfo struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Capabilities    []string `json:"capabilities"`
	ActivityClass   string   `json:"activityClass"`
	DisclosureClass string   `json:"disclosureClass"`
	RequiresScope   bool     `json:"requiresScope"`
	RateLimit       string   `json:"rateLimit,omitempty"`
}

// SessionInfo is a serializable view of a work session.
type SessionInfo struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	State      string `json:"state"`
	Created    string `json:"created"`
	ScopeLabel string `json:"scopeLabel"`
	Authorized bool   `json:"authorized"`
}

// Capabilities describes what the current environment can do, so the UI can show
// which features need elevation or drivers (prompt maestro §11, §5.6).
type Capabilities struct {
	Platform    string `json:"platform"`
	Arch        string `json:"arch"`
	Elevated    bool   `json:"elevated"`
	LiveCapture bool   `json:"liveCapture"`
	CaptureNote string `json:"captureNote"`
	RawSockets  bool   `json:"rawSockets"`
	Version     string `json:"version"`
	Portable    bool   `json:"portable"` // running in portable mode (portable.txt marker)
	DataDir     string `json:"dataDir"`  // where per-user data actually lives
}

// AddrReport is the offline classification + GeoIP enrichment of one address.
type AddrReport struct {
	Addr        string   `json:"addr"`
	Family      string   `json:"family"`
	Classes     []string `json:"classes"`
	IsPublic    bool     `json:"isPublic"`
	Reachable   *bool    `json:"reachable,omitempty"`
	Country     string   `json:"country,omitempty"`
	CountryCode string   `json:"countryCode,omitempty"`
	City        string   `json:"city,omitempty"`
	ASN         uint32   `json:"asn,omitempty"`
	Org         string   `json:"org,omitempty"`
	Lat         float64  `json:"lat,omitempty"`
	Lon         float64  `json:"lon,omitempty"`
	// NetClass is the kind of network (cloud/CDN/ISP/…) when it can be
	// established. Nil rather than an "unknown" category so the GUI shows no
	// legend at all instead of implying something was determined.
	NetClass *netclass.Match `json:"netClass,omitempty"`
}

// DiagnoseResult is the coordinated quick-diagnose output for a target
// (prompt maestro §9 Fase 1 #8). This offline-safe version does DNS resolution
// and IP classification; active probes are layered in later phases.
type DiagnoseResult struct {
	Input      string       `json:"input"`
	Kind       string       `json:"kind"` // ip | host | url
	Host       string       `json:"host,omitempty"`
	Addrs      []AddrReport `json:"addrs"`
	Notes      []string     `json:"notes,omitempty"`
	DurationMs int64        `json:"durationMs"`
}
