// Package infrastructure provides OSM client for querying OpenStreetMap infrastructure data.
package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trazip/internal/osint"
)

const (
	// maxOSMResponseSize limits the HTTP response body size to 10MB
	maxOSMResponseSize = 10 * 1024 * 1024
)

// OSMClient queries OpenStreetMap Overpass API for infrastructure data.
// All requests are bounded, timeout-controlled, and cancellable.
type OSMClient struct {
	httpClient *http.Client
	baseURL    string
	rateLimiter *RateLimiter
	userAgent  string
}

// OSMConfig configures the OSM client.
type OSMConfig struct {
	Timeout    time.Duration // request timeout
	RateLimit  float64       // requests per second (0 = unlimited)
	BaseURL    string        // Overpass API endpoint (default: overpass-api.de)
	UserAgent  string        // User-Agent string
}

// DefaultOSMConfig returns a sensible default configuration.
func DefaultOSMConfig() OSMConfig {
	return OSMConfig{
		Timeout:    30 * time.Second,
		RateLimit:  1.0, // 1 request/second - conservative per OSM policy
		BaseURL:    "https://overpass-api.de/api/interpreter",
		UserAgent:  "TRAZIP/1.0 (infrastructure-intelligence; +https://github.com/kerwilgil/trazip)",
	}
}

// NewOSMClient creates a new OSM client with the given config.
func NewOSMClient(cfg OSMConfig) *OSMClient {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://overpass-api.de/api/interpreter"
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "TRAZIP/1.0"
	}
	return &OSMClient{
		httpClient:  &http.Client{Timeout: cfg.Timeout},
		baseURL:     cfg.BaseURL,
		rateLimiter: NewRateLimiter(cfg.RateLimit),
		userAgent:   cfg.UserAgent,
	}
}

// OverpassResponse represents the JSON response from Overpass API.
type OverpassResponse struct {
	Version  float64           `json:"version"`
	Generator string           `json:"generator"`
	OSM3S    OverpassOSM3S     `json:"osm3s"`
	Elements []OverpassElement `json:"elements"`
}

// OverpassOSM3S contains metadata from Overpass.
type OverpassOSM3S struct {
	TimestampOsmBase string  `json:"timestamp_osm_base"`
	Copyright        string  `json:"copyright"`
	Areas            OverpassAreas `json:"areas"`
}

// OverpassAreas contains area metadata.
type OverpassAreas struct {
	Free int `json:"free"`
}

// OverpassElement represents a single OSM element (node, way, relation).
type OverpassElement struct {
	Type        string                 `json:"type"` // "node", "way", "relation"
	ID          int64                  `json:"id"`
	Lat         float64                `json:"lat,omitempty"`
	Lon         float64                `json:"lon,omitempty"`
	Tags        map[string]string      `json:"tags,omitempty"`
	Members     []OverpassMember       `json:"members,omitempty"` // for relations
	Geometry    []OverpassGeometry     `json:"geometry,omitempty"` // for ways
	Center      *OverpassCenter        `json:"center,omitempty"`   // for ways/relations
}

// OverpassMember represents a member of a relation.
type OverpassMember struct {
	Type string `json:"type"` // "node", "way", "relation"
	Ref  int64  `json:"ref"`
	Role string `json:"role,omitempty"`
}

// OverpassGeometry represents a geometry point.
type OverpassGeometry struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// OverpassCenter represents the center of a way/relation.
type OverpassCenter struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// QueryOSM executes an Overpass QL query and returns parsed elements.
// The query must be a valid Overpass QL string.
func (c *OSMClient) QueryOSM(ctx context.Context, overpassQL string) (*OverpassResponse, error) {
	// Rate limiting with proper serializing rate limiter
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	// Build request
	data := url.Values{}
	data.Set("data", overpassQL)
	data.Set("format", "json")

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("osm: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.userAgent)

	// Execute
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osm: request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle rate limiting
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("osm: rate limited (HTTP 429)")
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("osm: server error HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("osm: HTTP %d", resp.StatusCode)
	}

	// Read response with size limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOSMResponseSize))
	if err != nil {
		return nil, fmt.Errorf("osm: read response: %w", err)
	}

	// Check if response was truncated
	if len(body) >= maxOSMResponseSize {
		// Try to read one more byte to confirm truncation
		var buf [1]byte
		if n, _ := resp.Body.Read(buf[:]); n > 0 {
			return nil, fmt.Errorf("osm: response exceeds maximum size of %d bytes", maxOSMResponseSize)
		}
	}

	var result OverpassResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("osm: decode response: %w", err)
	}

	return &result, nil
}

// CableLandingStationQuery builds an Overpass QL query for cable landing stations.
// Tags: telecom=cable_landing_station
// Requires a non-empty bbox - no global search allowed.
func CableLandingStationQuery(bbox string) string {
	if bbox == "" {
		// This should not be called with empty bbox - caller must validate
		return ""
	}
	// bbox format: "south,west,north,east"
	return fmt.Sprintf(`[out:json][timeout:25];
(
  node["telecom"="cable_landing_station"](%s);
  way["telecom"="cable_landing_station"](%s);
  relation["telecom"="cable_landing_station"](%s);
);
out body center;`, bbox, bbox, bbox)
}

// SubmarineCableQuery builds an Overpass QL query for submarine cables.
// Tags: communication=line + location=underwater, or submarine=yes
// Requires a non-empty bbox - no global search allowed.
func SubmarineCableQuery(bbox string) string {
	if bbox == "" {
		return ""
	}
	return fmt.Sprintf(`[out:json][timeout:25];
(
  way["communication"="line"]["location"="underwater"](%s);
  way["submarine"="yes"](%s);
  relation["communication"="line"]["location"="underwater"](%s);
  relation["submarine"="yes"](%s);
);
out body center;`, bbox, bbox, bbox, bbox)
}

// IXPQuery builds an Overpass QL query for Internet Exchange Points.
// Tags: internet_exchange_point=yes, or network_type=ixp
// Requires a non-empty bbox - no global search allowed.
func IXPQuery(bbox string) string {
	if bbox == "" {
		return ""
	}
	return fmt.Sprintf(`[out:json][timeout:25];
(
  node["internet_exchange_point"="yes"](%s);
  way["internet_exchange_point"="yes"](%s);
  relation["internet_exchange_point"="yes"](%s);
  node["network_type"="ixp"](%s);
  way["network_type"="ixp"](%s);
  relation["network_type"="ixp"](%s);
);
out body center;`, bbox, bbox, bbox, bbox, bbox, bbox)
}

// FacilityQuery builds an Overpass QL query for network facilities.
// Tags: building=data_center, telecom=datacenter, etc.
// Requires a non-empty bbox - no global search allowed.
func FacilityQuery(bbox string) string {
	if bbox == "" {
		return ""
	}
	return fmt.Sprintf(`[out:json][timeout:25];
(
  node["building"="data_center"](%s);
  way["building"="data_center"](%s);
  relation["building"="data_center"](%s);
  node["telecom"="data_center"](%s);
  way["telecom"="data_center"](%s);
  node["amenity"="data_center"](%s);
  way["amenity"="data_center"](%s);
);
out body center;`, bbox, bbox, bbox, bbox, bbox, bbox, bbox)
}

// ParseCableLandingStation converts an OSM element to a LandingStation.
func ParseCableLandingStation(elem OverpassElement, prov osint.Provenance) (LandingStation, error) {
	if elem.Type != "node" && elem.Type != "way" && elem.Type != "relation" {
		return LandingStation{}, fmt.Errorf("unexpected element type: %s", elem.Type)
	}

	tags := elem.Tags
	if tags == nil {
		tags = map[string]string{}
	}

	name := tags["name"]
	if name == "" {
		name = tags["official_name"]
	}
	if name == "" {
		name = tags["alt_name"]
	}

	city := tags["addr:city"]
	if city == "" {
		city = tags["city"]
	}
	country := tags["addr:country"]
	if country == "" {
		country = tags["country"]
	}
	if country == "" {
		country = tags["ISO3166-1:alpha2"]
	}

	lat, lon := elem.Lat, elem.Lon
	if lat == 0 && lon == 0 && elem.Center != nil {
		lat, lon = elem.Center.Lat, elem.Center.Lon
	}

	ls := LandingStation{
		ID:          fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID),
		Name:        name,
		City:        city,
		Country:     country,
		Region:      tags["addr:state"],
		Latitude:    lat,
		Longitude:   lon,
		OSMID:       fmt.Sprintf("%s/%d", elem.Type, elem.ID),
		Provenance:  prov,
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
	}

	// Try to extract cables from tags
	if cables := tags["cable"]; cables != "" {
		ls.Cables = strings.Split(cables, ";")
	}
	if cables := tags["submarine_cable"]; cables != "" {
		ls.Cables = append(ls.Cables, strings.Split(cables, ";")...)
	}

	if err := ls.Validate(); err != nil {
		return LandingStation{}, err
	}
	return ls, nil
}

// ParseIXP converts an OSM element to an IXP.
func ParseIXP(elem OverpassElement, prov osint.Provenance) (IXP, error) {
	if elem.Type != "node" && elem.Type != "way" && elem.Type != "relation" {
		return IXP{}, fmt.Errorf("unexpected element type: %s", elem.Type)
	}

	tags := elem.Tags
	if tags == nil {
		tags = map[string]string{}
	}

	name := tags["name"]
	if name == "" {
		name = tags["official_name"]
	}

	city := tags["addr:city"]
	if city == "" {
		city = tags["city"]
	}
	country := tags["addr:country"]
	if country == "" {
		country = tags["country"]
	}
	if country == "" {
		country = tags["ISO3166-1:alpha2"]
	}

	lat, lon := elem.Lat, elem.Lon
	if lat == 0 && lon == 0 && elem.Center != nil {
		lat, lon = elem.Center.Lat, elem.Center.Lon
	}

	ixp := IXP{
		ID:         fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID),
		Name:       name,
		City:       city,
		Country:    country,
		Region:     tags["addr:state"],
		Latitude:   lat,
		Longitude:  lon,
		OSMID:      fmt.Sprintf("%s/%d", elem.Type, elem.ID),
		Provenance: prov,
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
	}

	if website := tags["website"]; website != "" {
		ixp.Website = website
	}
	if url := tags["contact:website"]; url != "" {
		ixp.Website = url
	}

	if err := ixp.Validate(); err != nil {
		return IXP{}, err
	}
	return ixp, nil
}

// ParseFacility converts an OSM element to a Facility.
func ParseFacility(elem OverpassElement, prov osint.Provenance) (Facility, error) {
	if elem.Type != "node" && elem.Type != "way" && elem.Type != "relation" {
		return Facility{}, fmt.Errorf("unexpected element type: %s", elem.Type)
	}

	tags := elem.Tags
	if tags == nil {
		tags = map[string]string{}
	}

	name := tags["name"]
	if name == "" {
		name = tags["official_name"]
	}
	orgName := tags["operator"]
	if orgName == "" {
		orgName = tags["brand"]
	}

	city := tags["addr:city"]
	if city == "" {
		city = tags["city"]
	}
	country := tags["addr:country"]
	if country == "" {
		country = tags["country"]
	}
	if country == "" {
		country = tags["ISO3166-1:alpha2"]
	}

	lat, lon := elem.Lat, elem.Lon
	if lat == 0 && lon == 0 && elem.Center != nil {
		lat, lon = elem.Center.Lat, elem.Center.Lon
	}

	fac := Facility{
		ID:         fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID),
		Name:       name,
		OrgName:    orgName,
		City:       city,
		Country:    country,
		Region:     tags["addr:state"],
		Address:    tags["addr:full"],
		Latitude:   lat,
		Longitude:  lon,
		OSMID:      fmt.Sprintf("%s/%d", elem.Type, elem.ID),
		Provenance: prov,
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
	}

	if website := tags["website"]; website != "" {
		fac.Website = website
	}
	if clli := tags["clli"]; clli != "" {
		fac.CLLI = clli
	}

	if err := fac.Validate(); err != nil {
		return Facility{}, err
	}
	return fac, nil
}

// ParseSubmarineCable converts an OSM element to a SubmarineCable.
func ParseSubmarineCable(elem OverpassElement, prov osint.Provenance) (SubmarineCable, error) {
	if elem.Type != "way" && elem.Type != "relation" {
		return SubmarineCable{}, fmt.Errorf("unexpected element type for submarine cable: %s", elem.Type)
	}

	tags := elem.Tags
	if tags == nil {
		tags = map[string]string{}
	}

	name := tags["name"]
	if name == "" {
		name = tags["official_name"]
	}

	// Extract landing points from relation members if relation
	var landingPoints []string
	if elem.Type == "relation" && elem.Members != nil {
		for _, m := range elem.Members {
			if m.Role == "landing_point" || m.Role == "landing_station" {
				landingPoints = append(landingPoints, fmt.Sprintf("%s/%d", m.Type, m.Ref))
			}
		}
	}

	// Try to extract length from tags
	var lengthKm float64
	if l := tags["length"]; l != "" {
		fmt.Sscanf(l, "%f", &lengthKm)
	}

	cable := SubmarineCable{
		ID:           fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID),
		Name:         name,
		LandingPoints: landingPoints,
		OSMIDs:       []string{fmt.Sprintf("%s/%d", elem.Type, elem.ID)},
		LengthKm:     lengthKm,
		Provenance:   prov,
		LastUpdated:  time.Now().UTC().Format(time.RFC3339),
	}

	if owners := tags["operator"]; owners != "" {
		cable.Owners = strings.Split(owners, ";")
	}
	if rfs := tags["start_date"]; rfs != "" {
		cable.ReadyForService = rfs
	}
	if pairs := tags["fiber_pairs"]; pairs != "" {
		fmt.Sscanf(pairs, "%d", &cable.FiberPairs)
	}
	if cap := tags["capacity"]; cap != "" {
		cable.DesignCapacity = cap
	}
	if wiki := tags["wikipedia"]; wiki != "" {
		cable.WikipediaURL = "https://en.wikipedia.org/wiki/" + strings.ReplaceAll(wiki, " ", "_")
	}

	if err := cable.Validate(); err != nil {
		return SubmarineCable{}, err
	}
	return cable, nil
}