// Package infrastructure provides models for Internet Infrastructure Intelligence (V1.5-6).
package infrastructure

import (
	"fmt"

	"trazip/internal/osint"
)

// ============================================================
// Infrastructure Source / Provenance
// ============================================================

// InfrastructureSource identifies the origin of infrastructure data.
type InfrastructureSource string

const (
	InfraSourceOSM        InfrastructureSource = "openstreetmap"
	InfraSourcePeeringDB  InfrastructureSource = "peeringdb"
	InfraSourceDerived    InfrastructureSource = "derived"
)

// InfrastructureProvenance records the origin and retrieval metadata for
// infrastructure data. It extends osint.Provenance with infrastructure-specific fields.
type InfrastructureProvenance struct {
	osint.Provenance
	InfraSource   InfrastructureSource `json:"infra_source"`
	InfraQuery    string               `json:"infra_query"`    // e.g., Overpass QL, PeeringDB endpoint
	InfraRawRef   string               `json:"infra_raw_ref"`  // OSM node/way/relation ID, PeeringDB ID
	InfraGeometry string               `json:"infra_geometry"` // WKT/GeoJSON summary for spatial data
}

// ============================================================
// IXP (Internet Exchange Point)
// ============================================================

// IXP represents an Internet Exchange Point.
type IXP struct {
	ID              string             `json:"id"`              // e.g., "peeringdb:123", "osm:node/12345"
	Name            string             `json:"name"`            // e.g., "AMS-IX", "DE-CIX Frankfurt"
	City            string             `json:"city"`            // e.g., "Amsterdam"
	Country         string             `json:"country"`         // ISO alpha-2, e.g., "NL"
	Region          string             `json:"region,omitempty"` // e.g., "North Holland"
	Latitude        float64            `json:"latitude,omitempty"`
	Longitude       float64            `json:"longitude,omitempty"`
	Website         string             `json:"website,omitempty"`
	PeeringDBID     int                `json:"peeringdbId,omitempty"`
	OSMID           string             `json:"osmId,omitempty"`   // OSM node/way/relation ID
	PeeringLANs     []IXPLAN           `json:"peeringLans,omitempty"`
	Provenance      osint.Provenance   `json:"provenance"`
	LastUpdated     string             `json:"lastUpdated"`       // RFC3339
	Notes           string             `json:"notes,omitempty"`
}

// IXPLAN represents a peering LAN at an IXP.
type IXPLAN struct {
	ID            string   `json:"id"`              // PeeringDB IXLAN ID
	Name          string   `json:"name"`            // e.g., "AMS-IX IPv4"
	VLAN          int      `json:"vlan,omitempty"`  // VLAN ID
	MTU           int      `json:"mtu,omitempty"`   // MTU
	IPv4Prefix    string   `json:"ipv4Prefix,omitempty"`
	IPv6Prefix    string   `json:"ipv6Prefix,omitempty"`
	Speed         int      `json:"speed,omitempty"` // Speed in Mbps
	Operational   bool     `json:"operational"`
	Members       []string `json:"members,omitempty"` // ASNs present on this LAN
}

// Validate checks that the IXP is well-formed.
func (i IXP) Validate() error {
	if i.ID == "" {
		return fmt.Errorf("ixp: missing ID")
	}
	if i.Name == "" {
		return fmt.Errorf("ixp: missing name")
	}
	if i.City == "" {
		return fmt.Errorf("ixp: missing city")
	}
	if i.Country == "" {
		return fmt.Errorf("ixp: missing country")
	}
	if len(i.Country) != 2 {
		return fmt.Errorf("ixp: country must be ISO alpha-2")
	}
	return nil
}

// ============================================================
// Facility (Colocation / Data Center)
// ============================================================

// Facility represents a network facility (colocation, data center, POP).
type Facility struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`           // e.g., "Equinix AM5"
	OrgName       string           `json:"orgName,omitempty"` // e.g., "Equinix"
	City          string           `json:"city"`
	Country       string           `json:"country"`        // ISO alpha-2
	Region        string           `json:"region,omitempty"`
	Address       string           `json:"address,omitempty"`
	Latitude      float64          `json:"latitude,omitempty"`
	Longitude     float64          `json:"longitude,omitempty"`
	CLLI          string           `json:"clli,omitempty"` // CLLI code if available
	PeeringDBID   int              `json:"peeringdbId,omitempty"`
	OSMID         string           `json:"osmId,omitempty"`
	Website       string           `json:"website,omitempty"`
	IXPs          []string         `json:"ixps,omitempty"` // IXP IDs present at this facility
	Provenance    osint.Provenance `json:"provenance"`
	LastUpdated   string           `json:"lastUpdated"`
	Notes         string           `json:"notes,omitempty"`
}

// Validate checks that the Facility is well-formed.
func (f Facility) Validate() error {
	if f.ID == "" {
		return fmt.Errorf("facility: missing ID")
	}
	if f.Name == "" {
		return fmt.Errorf("facility: missing name")
	}
	if f.City == "" {
		return fmt.Errorf("facility: missing city")
	}
	if f.Country == "" {
		return fmt.Errorf("facility: missing country")
	}
	if len(f.Country) != 2 {
		return fmt.Errorf("facility: country must be ISO alpha-2")
	}
	return nil
}

// ============================================================
// Cable Landing Station
// ============================================================

// LandingStation represents a submarine cable landing station.
type LandingStation struct {
	ID              string             `json:"id"`
	Name            string             `json:"name"`              // e.g., "Bude", "Porthcurno"
	City            string             `json:"city,omitempty"`
	Country         string             `json:"country"`           // ISO alpha-2
	Region          string             `json:"region,omitempty"`
	Latitude        float64            `json:"latitude,omitempty"`
	Longitude       float64            `json:"longitude,omitempty"`
	FacilityName    string             `json:"facilityName,omitempty"` // Associated facility name
	FacilityID      string             `json:"facilityId,omitempty"`   // Link to Facility if available
	Cables          []string           `json:"cables,omitempty"`        // Submarine cable IDs/names landing here
	PeeringDBID     int                `json:"peeringdbId,omitempty"`
	OSMID           string             `json:"osmId,omitempty"`        // OSM node/way/relation ID
	Website         string             `json:"website,omitempty"`
	Provenance      osint.Provenance   `json:"provenance"`
	LastUpdated     string             `json:"lastUpdated"`
	Notes           string             `json:"notes,omitempty"`
}

// Validate checks that the LandingStation is well-formed.
func (l LandingStation) Validate() error {
	if l.ID == "" {
		return fmt.Errorf("landing_station: missing ID")
	}
	if l.Name == "" {
		return fmt.Errorf("landing_station: missing name")
	}
	if l.Country == "" {
		return fmt.Errorf("landing_station: missing country")
	}
	if len(l.Country) != 2 {
		return fmt.Errorf("landing_station: country must be ISO alpha-2")
	}
	return nil
}

// ============================================================
// Submarine Cable Context
// ============================================================

// SubmarineCable represents a submarine cable system (contextual only).
// We do NOT assert cable traversal — this is contextual infrastructure metadata.
type SubmarineCable struct {
	ID              string               `json:"id"`                // e.g., "osm:way/123", "telegeography:ACE"
	Name            string               `json:"name"`              // e.g., "ACE", "SEA-ME-WE 5"
	Owners          []string             `json:"owners,omitempty"`  // Consortium members
	LandingPoints   []string             `json:"landingPoints,omitempty"` // Landing station IDs/names
	ReadyForService string               `json:"readyForService,omitempty"`     // RFS date if known
	LengthKm        float64              `json:"lengthKm,omitempty"`
	FiberPairs      int                  `json:"fiberPairs,omitempty"`
	DesignCapacity  string               `json:"designCapacity,omitempty"` // e.g., "100 Tbps"
	OSMIDs          []string             `json:"osmIds,omitempty"` // OSM way/relation IDs
	WikipediaURL    string               `json:"wikipediaUrl,omitempty"`
	Provenance      osint.Provenance     `json:"provenance"`
	LastUpdated     string               `json:"lastUpdated"`
	Notes           string               `json:"notes,omitempty"`
}

// Validate checks that the SubmarineCable is well-formed.
func (s SubmarineCable) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("submarine_cable: missing ID")
	}
	if s.Name == "" {
		return fmt.Errorf("submarine_cable: missing name")
	}
	return nil
}

// ============================================================
// Infrastructure Correlation (Contextual Only)
// ============================================================

// InfrastructureCorrelation represents a contextual link between
// network entities (ASN, Prefix, IP) and infrastructure entities.
// EvidenceClass MUST be set explicitly — NO automatic promotion.
type InfrastructureCorrelation struct {
	ID             string             `json:"id"`
	NetworkEntity  string             `json:"networkEntity"`   // ASN, Prefix, IP
	InfraEntity    string             `json:"infraEntity"`     // IXP, Facility, LandingStation, SubmarineCable ID
	RelationKind   string             `json:"relationKind"`    // e.g., "asn_at_ixp", "asn_at_facility", "prefix_lands_at"
	EvidenceClass  osint.EvidenceClass `json:"evidenceClass"`   // MUST be explicit
	ProvenanceRef  string             `json:"provenanceRef"`   // osint.Provenance ID or source reference
	Label          string             `json:"label,omitempty"`  // Human-readable description
	Confidence     string             `json:"confidence,omitempty"` // "alta" | "media" | "baja"
	RetrievedAt    string             `json:"retrievedAt"`     // RFC3339
}

// Validate checks that the correlation is well-formed.
func (c InfrastructureCorrelation) Validate() error {
	if c.ID == "" {
		return fmt.Errorf("infrastructure_correlation: missing ID")
	}
	if c.NetworkEntity == "" {
		return fmt.Errorf("infrastructure_correlation: missing network_entity")
	}
	if c.InfraEntity == "" {
		return fmt.Errorf("infrastructure_correlation: missing infra_entity")
	}
	if c.RelationKind == "" {
		return fmt.Errorf("infrastructure_correlation: missing relation_kind")
	}
	if !c.EvidenceClass.IsValid() {
		return fmt.Errorf("infrastructure_correlation: invalid evidence class %q", c.EvidenceClass)
	}
	if c.EvidenceClass == osint.EvidenceObserved && c.ProvenanceRef == "" {
		return fmt.Errorf("infrastructure_correlation: OBSERVED requires non-empty ProvenanceRef")
	}
	return nil
}

// SourceError represents an error from a specific source during correlation enrichment.
type SourceError struct {
	Provider  string `json:"provider"`   // e.g., "peeringdb", "osm"
	Operation string `json:"operation"`  // e.g., "netixlan", "netfac", "ixfac"
	Message   string `json:"message"`    // Sanitized error message
	ErrorType string `json:"errorType"`  // "timeout", "rate_limit", "server_error", "malformed", "cancelled"
}

// ============================================================
// Infrastructure Collection (Bounded, Deterministic)
// ============================================================

// InfrastructureCollection is a bounded, deterministically ordered
// collection of infrastructure entities and correlations.
type InfrastructureCollection struct {
	IXPs              []IXP                    `json:"ixps"`
	Facilities        []Facility             `json:"facilities"`
	LandingStations   []LandingStation       `json:"landingStations"`
	SubmarineCables   []SubmarineCable       `json:"submarineCables"`
	Correlations      []InfrastructureCorrelation `json:"correlations"`
	Provenance        []osint.Provenance     `json:"provenance"`
	SourceErrors      []SourceError          `json:"sourceErrors,omitempty"`
	RetrievedAt       string                 `json:"retrievedAt"` // RFC3339
	Query             string                 `json:"query"`        // Original query/input
	Bounds            InfraBounds            `json:"bounds"`
}

// InfraBounds enforces collection bounds.
type InfraBounds struct {
	MaxIXPs            int `json:"maxIxps"`
	MaxFacilities      int `json:"maxFacilities"`
	MaxLandingStations int `json:"maxLandingStations"`
	MaxSubmarineCables int `json:"maxSubmarineCables"`
	MaxCorrelations    int `json:"maxCorrelations"`
}

// DefaultInfraBounds returns sensible defaults for collection bounds.
func DefaultInfraBounds() InfraBounds {
	return InfraBounds{
		MaxIXPs:            500,
		MaxFacilities:      500,
		MaxLandingStations: 200,
		MaxSubmarineCables: 300,
		MaxCorrelations:    1000,
	}
}

// Truncate enforces bounds by truncating collections deterministically.
func (c *InfrastructureCollection) Truncate(b InfraBounds) {
	if len(c.IXPs) > b.MaxIXPs {
		c.IXPs = c.IXPs[:b.MaxIXPs]
	}
	if len(c.Facilities) > b.MaxFacilities {
		c.Facilities = c.Facilities[:b.MaxFacilities]
	}
	if len(c.LandingStations) > b.MaxLandingStations {
		c.LandingStations = c.LandingStations[:b.MaxLandingStations]
	}
	if len(c.SubmarineCables) > b.MaxSubmarineCables {
		c.SubmarineCables = c.SubmarineCables[:b.MaxSubmarineCables]
	}
	if len(c.Correlations) > b.MaxCorrelations {
		c.Correlations = c.Correlations[:b.MaxCorrelations]
	}
}

// EnsureNonNil ensures all slices are non-nil for JSON serialization.
func (c *InfrastructureCollection) EnsureNonNil() {
	if c.IXPs == nil {
		c.IXPs = []IXP{}
	}
	if c.Facilities == nil {
		c.Facilities = []Facility{}
	}
	if c.LandingStations == nil {
		c.LandingStations = []LandingStation{}
	}
	if c.SubmarineCables == nil {
		c.SubmarineCables = []SubmarineCable{}
	}
	if c.Correlations == nil {
		c.Correlations = []InfrastructureCorrelation{}
	}
	if c.Provenance == nil {
		c.Provenance = []osint.Provenance{}
	}
}