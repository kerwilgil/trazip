// Package model defines TRAZIP's central data model. Every screen and engine
// shares these entities so results stay correlatable across a session
// (see prompt maestro §8 "Modelo de datos central").
package model

import (
	"net/netip"
	"time"
)

// Confidence is a 0..100 score attached to inferred conclusions.
type Confidence uint8

// Level classifies the severity/importance of an Assessment.
type Level string

const (
	LevelInfo     Level = "informativo"
	LevelLow      Level = "bajo"
	LevelMedium   Level = "medio"
	LevelHigh     Level = "alto"
	LevelCritical Level = "critico"
)

// Provenance distinguishes how a piece of data was obtained. The prompt maestro
// (§10) requires never conflating observed vs. inferred vs. externally queried.
type Provenance string

const (
	ProvObserved Provenance = "observed" // seen directly in packets/probes
	ProvResolved Provenance = "resolved" // DNS/PTR resolution
	ProvInferred Provenance = "inferred" // internal heuristic
	ProvExternal Provenance = "external" // queried from a web/offline source
)

// NetClass categorizes an address's network nature.
type NetClass string

const (
	ClassPrivate       NetClass = "private"
	ClassPublic        NetClass = "public"
	ClassLoopback      NetClass = "loopback"
	ClassLinkLocal     NetClass = "link_local"
	ClassMulticast     NetClass = "multicast"
	ClassReserved      NetClass = "reserved"
	ClassBogon         NetClass = "bogon"
	ClassDocumentation NetClass = "documentation"
	ClassResidential   NetClass = "residential"
	ClassMobile        NetClass = "mobile"
	ClassHosting       NetClass = "hosting"
	ClassCDN           NetClass = "cdn"
	ClassVPN           NetClass = "vpn"
	ClassProxy         NetClass = "proxy"
	ClassTor           NetClass = "tor"
	ClassUnknown       NetClass = "unknown"
)

// GeoIP holds an approximate geographic location. Never present a GeoIP city as
// an exact location (§10).
type GeoIP struct {
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"countryCode,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	Dataset     string  `json:"dataset,omitempty"` // provider + version + date
}

// ASN describes autonomous-system context for an address.
type ASN struct {
	Number       uint32 `json:"number,omitempty"`
	Organization string `json:"organization,omitempty"`
	Prefix       string `json:"prefix,omitempty"` // announced CIDR
	Dataset      string `json:"dataset,omitempty"`
}

// Evidence is a single piece of support for or against a conclusion (§8).
type Evidence struct {
	Type       string     `json:"type"`
	Value      string     `json:"value"`
	Source     string     `json:"source"`
	Provenance Provenance `json:"provenance"`
	Timestamp  time.Time  `json:"timestamp"`
	Confidence Confidence `json:"confidence"`
	Explain    string     `json:"explain,omitempty"`
}

// Assessment is a reasoned conclusion. Every VPN/proxy/Tor/anomaly call must be
// an Assessment, never a bare boolean (§8).
type Assessment struct {
	Conclusion  string     `json:"conclusion"`
	Level       Level      `json:"level"`
	Confidence  Confidence `json:"confidence"`
	Evidence    []Evidence `json:"evidence,omitempty"`
	CounterEvid []Evidence `json:"counterEvidence,omitempty"`
	Limitations []string   `json:"limitations,omitempty"`
}

// Endpoint is a correlated network entity — the product's key differentiator (§2).
type Endpoint struct {
	Addr        netip.Addr   `json:"addr"`
	MAC         string       `json:"mac,omitempty"`
	Vendor      string       `json:"vendor,omitempty"`
	Hostnames   []string     `json:"hostnames,omitempty"`
	ASN         *ASN         `json:"asn,omitempty"`
	Geo         *GeoIP       `json:"geo,omitempty"`
	Classes     []NetClass   `json:"classes,omitempty"`
	Assessments []Assessment `json:"assessments,omitempty"`
	FirstSeen   time.Time    `json:"firstSeen"`
	LastSeen    time.Time    `json:"lastSeen"`
}

// Proto is a transport/network protocol identifier.
type Proto string

const (
	ProtoTCP    Proto = "tcp"
	ProtoUDP    Proto = "udp"
	ProtoICMP   Proto = "icmp"
	ProtoICMPv6 Proto = "icmpv6"
)

// Flow is a bidirectional aggregation keyed by 5-tuple (§8).
type Flow struct {
	SrcAddr     netip.Addr `json:"srcAddr"`
	SrcPort     uint16     `json:"srcPort"`
	DstAddr     netip.Addr `json:"dstAddr"`
	DstPort     uint16     `json:"dstPort"`
	Proto       Proto      `json:"proto"`
	LocalIsSrc  bool       `json:"localIsSrc"`
	Start       time.Time  `json:"start"`
	End         time.Time  `json:"end"`
	PktsOut     uint64     `json:"pktsOut"`
	PktsIn      uint64     `json:"pktsIn"`
	BytesOut    uint64     `json:"bytesOut"`
	BytesIn     uint64     `json:"bytesIn"`
	TCPFlags    string     `json:"tcpFlags,omitempty"`
	Retransmits uint64     `json:"retransmits,omitempty"`
	RTTms       float64    `json:"rttMs,omitempty"`
	AppProto    string     `json:"appProto,omitempty"`
	SNI         string     `json:"sni,omitempty"`
	HTTPHost    string     `json:"httpHost,omitempty"`
	DNSName     string     `json:"dnsName,omitempty"`
}

// Duration returns the observed flow duration.
func (f Flow) Duration() time.Duration { return f.End.Sub(f.Start) }
