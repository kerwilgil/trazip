// Package infrastructure provides PeeringDB client for querying IXP, facility, and network data.
package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"trazip/internal/intel/external"
	"trazip/internal/osint"
)

const (
	// maxPeeringDBResponseSize limits the HTTP response body size to 10MB
	maxPeeringDBResponseSize = 10 * 1024 * 1024
	// maxPageSize limits the number of results per page
	maxPageSize = 1000
)

// PeeringDBClient queries PeeringDB API for IXP, facility, and network data.
// All requests are bounded, timeout-controlled, and cancellable.
// Respects PeeringDB AUP: no bulk redistribution, no contact harvesting.
type PeeringDBClient struct {
	httpClient   *http.Client
	baseURL      string
	apiKey       string // optional, for authenticated requests
	rateLimiter  *RateLimiter
	userAgent    string
}

// PeeringDBConfig configures the PeeringDB client.
type PeeringDBConfig struct {
	Timeout   time.Duration // request timeout
	RateLimit float64       // requests per second (0 = unlimited, default 0.5 = 1 req/2s)
	BaseURL   string        // API base URL (default: https://peeringdb.com/api)
	APIKey    string        // optional API key for higher rate limits
	UserAgent string        // User-Agent string
}

// DefaultPeeringDBConfig returns a sensible default configuration.
// Conservative rate limit - TRAZIP conservative policy.
func DefaultPeeringDBConfig() PeeringDBConfig {
	return PeeringDBConfig{
		Timeout:   30 * time.Second,
		RateLimit: 0.5, // 1 request per 2 seconds
		BaseURL:   "https://peeringdb.com/api",
		UserAgent: "TRAZIP/1.0 (infrastructure-intelligence; +https://github.com/kerwilgil/trazip)",
	}
}

// NewPeeringDBClient creates a new PeeringDB client with the given config.
func NewPeeringDBClient(cfg PeeringDBConfig) *PeeringDBClient {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://peeringdb.com/api"
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "TRAZIP/1.0"
	}
	return &PeeringDBClient{
		httpClient:  &http.Client{Timeout: cfg.Timeout},
		baseURL:     cfg.BaseURL,
		apiKey:      cfg.APIKey,
		rateLimiter: NewRateLimiter(cfg.RateLimit),
		userAgent:   cfg.UserAgent,
	}
}

// PeeringDBResponse wraps the standard PeeringDB API response.
type PeeringDBResponse struct {
	Data json.RawMessage `json:"data"`
	Meta PeeringDBMeta   `json:"meta"`
}

// PeeringDBMeta contains pagination and metadata.
type PeeringDBMeta struct {
	Limit      int    `json:"limit"`
	Offset     int    `json:"offset"`
	Total      int    `json:"total"`
	Columns    string `json:"columns,omitempty"`
	Order      string `json:"order,omitempty"`
}

// PeeringDBIXP represents an IXP from PeeringDB.
type PeeringDBIXP struct {
	ID              int    `json:"id"`
	Name            string `json:"name"`
	NameLong        string `json:"name_long"`
	City            string `json:"city"`
	Country         string `json:"country"`
	Region          string `json:"region_continent"`
	Website         string `json:"website"`
	Notes           string `json:"notes"`
	Created         string `json:"created"`
	Updated         string `json:"updated"`
	Status          string `json:"status"`
	OrgID           int    `json:"org_id"`
	IPv4Prefix      string `json:"ipv4_prefix"`
	IPv6Prefix      string `json:"ipv6_prefix"`
}

// PeeringDBFacility represents a facility from PeeringDB.
type PeeringDBFacility struct {
	ID              int    `json:"id"`
	Name            string `json:"name"`
	NameLong        string `json:"name_long"`
	City            string `json:"city"`
	Country         string `json:"country"`
	Region          string `json:"region_continent"`
	Address         string `json:"address1"`
	Suite           string `json:"suite"`
	Zipcode         string `json:"zipcode"`
	Latitude        float64 `json:"latitude"`
	Longitude       float64 `json:"longitude"`
	CLLI            string `json:"clli"`
	NPA             string `json:"npa"`
	NXX             string `json:"nxx"`
	Website         string `json:"website"`
	Notes           string `json:"notes"`
	Created         string `json:"created"`
	Updated         string `json:"updated"`
	Status          string `json:"status"`
	OrgID           int    `json:"org_id"`
	SuggestedIXPs   []int  `json:"suggested_ixps,omitempty"` // IXP IDs at this facility
}

// PeeringDBNet represents a network (ASN) from PeeringDB.
type PeeringDBNet struct {
	ID       int    `json:"id"`        // PeeringDB internal network ID (net_id)
	ASN      int    `json:"asn"`
	Name     string `json:"name"`
	Website  string `json:"website"`
	InfoType string `json:"info_type"` // "NSP", "Content", "Enterprise", "Educational/Research", etc.
	Policy   string `json:"policy"`    // "Open", "Selective", "Restrictive"
	Notes    string `json:"notes"`
	Created  string `json:"created"`
	Updated  string `json:"updated"`
	Status   string `json:"status"`
	OrgID    int    `json:"org_id"`
}

// PeeringDBIXLAN represents an IXP LAN (peering LAN).
type PeeringDBIXLAN struct {
	ID           int    `json:"id"`
	IXPID        int    `json:"ixp_id"`
	Name         string `json:"name"`
	VLAN         int    `json:"vlan"`
	MTU          int    `json:"mtu"`
	IPv4Prefix   string `json:"ipv4_prefix"`
	IPv6Prefix   string `json:"ipv6_prefix"`
	Speed        int    `json:"speed"` // Mbps
	Operational  bool   `json:"operational"`
	Created      string `json:"created"`
	Updated      string `json:"updated"`
}

// PeeringDBNetIXLAN represents a network's presence at an IXLAN.
type PeeringDBNetIXLAN struct {
	ID          int    `json:"id"`
	NetID        int    `json:"net_id"`
	IXLANID      int    `json:"ixlan_id"`
	IPv4Address  string `json:"ipaddr4"`
	IPv6Address  string `json:"ipaddr6"`
	ASN          int    `json:"asn"`
	Speed        int    `json:"speed"` // Mbps
	Operational  bool   `json:"operational"`
	IsRS         bool   `json:"is_rs_peer"` // Route Server peer
	Created      string `json:"created"`
	Updated      string `json:"updated"`
}

// PeeringDBFacilityIX represents an IXP at a facility (ixfac endpoint).
type PeeringDBFacilityIX struct {
	FacilityID int `json:"fac_id"`
	IXPID      int `json:"ix_id"`
}

// PeeringDBNetFac represents a network's presence at a facility (netfac endpoint).
type PeeringDBNetFac struct {
	ID         int    `json:"id"`
	NetID      int    `json:"net_id"`
	FacID      int    `json:"fac_id"`
	AVGbps     int    `json:"avg_bps,omitempty"`
	Created    string `json:"created"`
	Updated    string `json:"updated"`
}

// QueryPeeringDB executes a GET request to PeeringDB API with response size bounds.
// path is the API endpoint (e.g., "/ix", "/fac", "/net").
// params are query parameters (e.g., "id=123", "org_id=456").
func (c *PeeringDBClient) QueryPeeringDB(ctx context.Context, path string, params url.Values) ([]byte, error) {
	// Rate limiting with proper serializing rate limiter
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}

	// Build URL with pagination limit
	if !params.Has("limit") {
		params.Set("limit", fmt.Sprintf("%d", maxPageSize))
	}
	if !params.Has("offset") {
		params.Set("offset", "0")
	}

	u := c.baseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("peeringdb: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	if c.apiKey != "" {
		req.Header.Set("Authorization", "Api-Key "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("peeringdb: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("peeringdb: rate limited (HTTP 429)")
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("peeringdb: server error HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("peeringdb: HTTP %d", resp.StatusCode)
	}

	// Read response with size limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPeeringDBResponseSize))
	if err != nil {
		return nil, fmt.Errorf("peeringdb: read response: %w", err)
	}

	// Check if response was truncated
	if len(body) >= maxPeeringDBResponseSize {
		// Try to read one more byte to confirm truncation
		var buf [1]byte
		if n, _ := resp.Body.Read(buf[:]); n > 0 {
			return nil, fmt.Errorf("peeringdb: response exceeds maximum size of %d bytes", maxPeeringDBResponseSize)
		}
	}

	var respData PeeringDBResponse
	if err := json.Unmarshal(body, &respData); err != nil {
		return nil, fmt.Errorf("peeringdb: decode response: %w", err)
	}

	return respData.Data, nil
}

// GetIXP fetches a single IXP by ID.
func (c *PeeringDBClient) GetIXP(ctx context.Context, id int) (*PeeringDBIXP, error) {
	data, err := c.QueryPeeringDB(ctx, "/ix", url.Values{"id": {fmt.Sprintf("%d", id)}})
	if err != nil {
		return nil, err
	}
	var ixps []PeeringDBIXP
	if err := json.Unmarshal(data, &ixps); err != nil {
		return nil, fmt.Errorf("peeringdb: unmarshal ixp: %w", err)
	}
	if len(ixps) == 0 {
		return nil, fmt.Errorf("peeringdb: ixp %d not found", id)
	}
	return &ixps[0], nil
}

// GetFacility fetches a single facility by ID.
func (c *PeeringDBClient) GetFacility(ctx context.Context, id int) (*PeeringDBFacility, error) {
	data, err := c.QueryPeeringDB(ctx, "/fac", url.Values{"id": {fmt.Sprintf("%d", id)}})
	if err != nil {
		return nil, err
	}
	var facs []PeeringDBFacility
	if err := json.Unmarshal(data, &facs); err != nil {
		return nil, fmt.Errorf("peeringdb: unmarshal facility: %w", err)
	}
	if len(facs) == 0 {
		return nil, fmt.Errorf("peeringdb: facility %d not found", id)
	}
	return &facs[0], nil
}

// GetNetwork fetches a single network (ASN) by ASN.
func (c *PeeringDBClient) GetNetwork(ctx context.Context, asn int) (*PeeringDBNet, error) {
	data, err := c.QueryPeeringDB(ctx, "/net", url.Values{"asn": {fmt.Sprintf("%d", asn)}})
	if err != nil {
		return nil, err
	}
	var nets []PeeringDBNet
	if err := json.Unmarshal(data, &nets); err != nil {
		return nil, fmt.Errorf("peeringdb: unmarshal net: %w", err)
	}
	if len(nets) == 0 {
		return nil, fmt.Errorf("peeringdb: network AS%d not found", asn)
	}
	return &nets[0], nil
}

// GetIXLAN fetches a single IXLAN by ID.
func (c *PeeringDBClient) GetIXLAN(ctx context.Context, id int) (*PeeringDBIXLAN, error) {
	data, err := c.QueryPeeringDB(ctx, "/ixlan", url.Values{"id": {fmt.Sprintf("%d", id)}})
	if err != nil {
		return nil, err
	}
	var ixlan []PeeringDBIXLAN
	if err := json.Unmarshal(data, &ixlan); err != nil {
		return nil, fmt.Errorf("peeringdb: unmarshal ixlan: %w", err)
	}
	if len(ixlan) == 0 {
		return nil, fmt.Errorf("peeringdb: ixlan %d not found", id)
	}
	return &ixlan[0], nil
}

// ListIXPsByFacility returns IXP IDs present at a facility using ixfac endpoint.
func (c *PeeringDBClient) ListIXPsByFacility(ctx context.Context, facilityID int) ([]int, error) {
	data, err := c.QueryPeeringDB(ctx, "/ixfac", url.Values{"fac_id": {fmt.Sprintf("%d", facilityID)}})
	if err != nil {
		return nil, err
	}
	var links []PeeringDBFacilityIX
	if err := json.Unmarshal(data, &links); err != nil {
		return nil, fmt.Errorf("peeringdb: unmarshal ixfac: %w", err)
	}
	ixpIDs := make([]int, 0, len(links))
	for _, l := range links {
		ixpIDs = append(ixpIDs, l.IXPID)
	}
	return ixpIDs, nil
}

// ListNetIXLANsByASN returns IXLAN memberships for an ASN.
func (c *PeeringDBClient) ListNetIXLANsByASN(ctx context.Context, asn int) ([]PeeringDBNetIXLAN, error) {
	data, err := c.QueryPeeringDB(ctx, "/netixlan", url.Values{"asn": {fmt.Sprintf("%d", asn)}})
	if err != nil {
		return nil, err
	}
	var netixlans []PeeringDBNetIXLAN
	if err := json.Unmarshal(data, &netixlans); err != nil {
		return nil, fmt.Errorf("peeringdb: unmarshal netixlan: %w", err)
	}
	return netixlans, nil
}

// ListNetworksAtIXP returns networks present at an IXP.
func (c *PeeringDBClient) ListNetworksAtIXP(ctx context.Context, ixpID int) ([]PeeringDBNetIXLAN, error) {
	data, err := c.QueryPeeringDB(ctx, "/netixlan", url.Values{"ix_id": {fmt.Sprintf("%d", ixpID)}})
	if err != nil {
		return nil, err
	}
	var netixlans []PeeringDBNetIXLAN
	if err := json.Unmarshal(data, &netixlans); err != nil {
		return nil, fmt.Errorf("peeringdb: unmarshal netixlan: %w", err)
	}
	return netixlans, nil
}

// GetNetworkIDByASN resolves an ASN to its PeeringDB internal network ID (net_id).
func (c *PeeringDBClient) GetNetworkIDByASN(ctx context.Context, asn int) (int, error) {
	net, err := c.GetNetwork(ctx, asn)
	if err != nil {
		return 0, err
	}
	// The PeeringDB Net object doesn't expose net_id directly in the API response
	// We need to query /net?asn=... which returns the net object with id field
	// Actually, the GetNetwork already queries /net?asn=... and returns the net object
	// The net_id is the same as the id field in the net object
	return net.ID, nil
}

// ListFacilitiesByNetwork returns facility IDs where a network (ASN) is present.
// First resolves ASN to net_id, then queries netfac endpoint.
func (c *PeeringDBClient) ListFacilitiesByNetwork(ctx context.Context, asn int) ([]int, error) {
	netID, err := c.GetNetworkIDByASN(ctx, asn)
	if err != nil {
		return nil, fmt.Errorf("resolve ASN %d to net_id: %w", asn, err)
	}
	data, err := c.QueryPeeringDB(ctx, "/netfac", url.Values{"net_id": {fmt.Sprintf("%d", netID)}})
	if err != nil {
		return nil, err
	}
	var links []PeeringDBNetFac
	if err := json.Unmarshal(data, &links); err != nil {
		return nil, fmt.Errorf("peeringdb: unmarshal netfac: %w", err)
	}
	facIDs := make([]int, 0, len(links))
	for _, l := range links {
		facIDs = append(facIDs, l.FacID)
	}
	return facIDs, nil
}

// GetNetFacByASN returns full netfac records for a given ASN.
// This includes all fields needed to create proper correlations.
func (c *PeeringDBClient) GetNetFacByASN(ctx context.Context, asn int) ([]PeeringDBNetFac, error) {
	netID, err := c.GetNetworkIDByASN(ctx, asn)
	if err != nil {
		return nil, fmt.Errorf("resolve ASN %d to net_id: %w", asn, err)
	}
	data, err := c.QueryPeeringDB(ctx, "/netfac", url.Values{"net_id": {fmt.Sprintf("%d", netID)}})
	if err != nil {
		return nil, err
	}
	var links []PeeringDBNetFac
	if err := json.Unmarshal(data, &links); err != nil {
		return nil, fmt.Errorf("peeringdb: unmarshal netfac: %w", err)
	}
	return links, nil
}

// ConvertPeeringDBIXP converts a PeeringDB IXP to our internal IXP model.
func ConvertPeeringDBIXP(pdb *PeeringDBIXP, prov osint.Provenance) (IXP, error) {
	if pdb == nil {
		return IXP{}, fmt.Errorf("peeringdb: nil ixp")
	}
	if pdb.Name == "" {
		return IXP{}, fmt.Errorf("peeringdb: ixp missing name")
	}

	country := pdb.Country
	if len(country) != 2 {
		// Try to map common country names to ISO alpha-2
		country = mapCountryNameToAlpha2(pdb.Country)
	}
	// If country is still not a valid 2-letter code, use "XX" as unknown
	if len(country) != 2 {
		country = "XX"
	}

	// Use PeeringDB-specific provenance
	peeringDBProv := osint.Provenance{
		ProviderID:      "peeringdb",
		ProviderName:    "PeeringDB",
		Capability:      "ixp",
		ActivityClass:   osint.ActivityPassive,
		DisclosureClass: osint.DisclosurePassive,
		RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
		Endpoint:        fmt.Sprintf("https://peeringdb.com/api/ix?id=%d", pdb.ID),
		Confidence:      "alta",
		Disclosure: external.Disclosure{
			Source:      "PeeringDB",
			QueriedAt:   time.Now().UTC().Format(time.RFC3339),
			DataSent:    fmt.Sprintf("https://peeringdb.com/api/ix?id=%d", pdb.ID),
			CachePolicy: "none",
			Confidence:  "alta",
			RateLimit:   "0.5 req/s (TRAZIP conservative)",
		},
	}

	ixp := IXP{
		ID:          fmt.Sprintf("peeringdb:%d", pdb.ID),
		Name:        pdb.Name,
		City:        pdb.City,
		Country:     country,
		Region:      pdb.Region,
		Website:     pdb.Website,
		PeeringDBID: pdb.ID,
		Provenance:  peeringDBProv,
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
		Notes:       pdb.Notes,
	}

	if err := ixp.Validate(); err != nil {
		return IXP{}, err
	}
	return ixp, nil
}

// ConvertPeeringDBFacility converts a PeeringDB facility to our internal Facility model.
func ConvertPeeringDBFacility(pdb *PeeringDBFacility, prov osint.Provenance) (Facility, error) {
	if pdb == nil {
		return Facility{}, fmt.Errorf("peeringdb: nil facility")
	}
	if pdb.Name == "" {
		return Facility{}, fmt.Errorf("peeringdb: facility missing name")
	}

	country := pdb.Country
	if len(country) != 2 {
		country = mapCountryNameToAlpha2(pdb.Country)
	}
	// If country is still not a valid 2-letter code, use "XX" as unknown
	if len(country) != 2 {
		country = "XX"
	}

	// Use PeeringDB-specific provenance
	peeringDBProv := osint.Provenance{
		ProviderID:      "peeringdb",
		ProviderName:    "PeeringDB",
		Capability:      "facility",
		ActivityClass:   osint.ActivityPassive,
		DisclosureClass: osint.DisclosurePassive,
		RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
		Endpoint:        fmt.Sprintf("https://peeringdb.com/api/fac?id=%d", pdb.ID),
		Confidence:      "alta",
		Disclosure: external.Disclosure{
			Source:      "PeeringDB",
			QueriedAt:   time.Now().UTC().Format(time.RFC3339),
			DataSent:    fmt.Sprintf("https://peeringdb.com/api/fac?id=%d", pdb.ID),
			CachePolicy: "none",
			Confidence:  "alta",
			RateLimit:   "0.5 req/s (TRAZIP conservative)",
		},
	}

	fac := Facility{
		ID:           fmt.Sprintf("peeringdb:%d", pdb.ID),
		Name:         pdb.Name,
		OrgName:      "", // PeeringDB doesn't expose org name directly here
		City:         pdb.City,
		Country:      country,
		Region:       pdb.Region,
		Address:      pdb.Address,
		Latitude:     pdb.Latitude,
		Longitude:    pdb.Longitude,
		CLLI:         pdb.CLLI,
		PeeringDBID:  pdb.ID,
		Website:      pdb.Website,
		Provenance:   peeringDBProv,
		LastUpdated:  time.Now().UTC().Format(time.RFC3339),
		Notes:        pdb.Notes,
	}

	if pdb.Suite != "" {
		fac.Address = fac.Address + " " + pdb.Suite
	}
	if pdb.Zipcode != "" {
		fac.Address = fac.Address + " " + pdb.Zipcode
	}

	if err := fac.Validate(); err != nil {
		return Facility{}, err
	}
	return fac, nil
}

// ConvertPeeringDBNetIXLAN converts a PeeringDB NetIXLAN to an InfrastructureCorrelation.
func ConvertPeeringDBNetIXLAN(pdb *PeeringDBNetIXLAN, ixpID string, prov osint.Provenance) (InfrastructureCorrelation, error) {
	corr := InfrastructureCorrelation{
		ID:            fmt.Sprintf("peeringdb:netixlan:%d", pdb.ID),
		NetworkEntity: fmt.Sprintf("AS%d", pdb.ASN),
		InfraEntity:   ixpID,
		RelationKind:  "asn_at_ixp",
		EvidenceClass: osint.EvidenceObserved, // PeeringDB explicitly lists presence
		ProvenanceRef: fmt.Sprintf("peeringdb:netixlan:%d", pdb.ID),
		Label:         fmt.Sprintf("AS%d present at IXP (PeeringDB)", pdb.ASN),
		Confidence:    "alta",
		RetrievedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	return corr, nil
}

// ConvertPeeringDBNetFac converts a PeeringDB NetFac to an InfrastructureCorrelation.
// Requires the actual ASN (not PeeringDB net_id) for the NetworkEntity field.
func ConvertPeeringDBNetFac(pdb *PeeringDBNetFac, facID string, asn int, prov osint.Provenance) (InfrastructureCorrelation, error) {
	corr := InfrastructureCorrelation{
		ID:            fmt.Sprintf("peeringdb:netfac:%d", pdb.ID),
		NetworkEntity: fmt.Sprintf("AS%d", asn),
		InfraEntity:   facID,
		RelationKind:  "asn_at_facility",
		EvidenceClass: osint.EvidenceObserved, // PeeringDB explicitly lists presence
		ProvenanceRef: fmt.Sprintf("peeringdb:netfac:%d", pdb.ID),
		Label:         fmt.Sprintf("AS%d present at Facility (PeeringDB)", asn),
		Confidence:    "alta",
		RetrievedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	return corr, nil
}

// mapCountryNameToAlpha2 maps common country names to ISO alpha-2 codes.
// Returns empty string if not found (caller must handle).
func mapCountryNameToAlpha2(name string) string {
	m := map[string]string{
		"United States": "US",
		"United Kingdom": "GB",
		"Germany": "DE",
		"France": "FR",
		"Netherlands": "NL",
		"Japan": "JP",
		"Singapore": "SG",
		"Hong Kong": "HK",
		"Australia": "AU",
		"Canada": "CA",
		"Brazil": "BR",
		"India": "IN",
		"China": "CN",
		"Spain": "ES",
		"Italy": "IT",
		"Sweden": "SE",
		"Norway": "NO",
		"Denmark": "DK",
		"Finland": "FI",
		"Poland": "PL",
		"Switzerland": "CH",
		"Austria": "AT",
		"Belgium": "BE",
		"Ireland": "IE",
		"Portugal": "PT",
		"South Africa": "ZA",
		"United Arab Emirates": "AE",
		"Israel": "IL",
		"Turkey": "TR",
		"Russia": "RU",
		"Mexico": "MX",
		"Argentina": "AR",
		"Chile": "CL",
		"Colombia": "CO",
		"Peru": "PE",
		"New Zealand": "NZ",
		"South Korea": "KR",
		"Taiwan": "TW",
		"Indonesia": "ID",
		"Malaysia": "MY",
		"Thailand": "TH",
		"Vietnam": "VN",
		"Philippines": "PH",
	}
	if code, ok := m[name]; ok {
		return code
	}
	return "" // Return empty if not found - caller must handle
}