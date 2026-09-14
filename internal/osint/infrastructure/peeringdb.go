// Package infrastructure provides PeeringDB client for querying IXP, facility, and network data.
package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"trazip/internal/osint"
)

// PeeringDBClient queries PeeringDB API for IXP, facility, and network data.
// All requests are bounded, timeout-controlled, and cancellable.
// Respects PeeringDB AUP: no bulk redistribution, no contact harvesting.
type PeeringDBClient struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string // optional, for authenticated requests
	rateLimit  float64
	lastReq    time.Time
	mu         sync.Mutex
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
// Conservative rate limit per PeeringDB AUP.
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
		httpClient: &http.Client{Timeout: cfg.Timeout},
		baseURL:    cfg.BaseURL,
		apiKey:     cfg.APIKey,
		rateLimit:  cfg.RateLimit,
		lastReq:    time.Time{},
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

// PeeringDBFacilityIX represents an IXP at a facility.
type PeeringDBFacilityIX struct {
	FacilityID int `json:"fac_id"`
	IXPID      int `json:"ix_id"`
}

// QueryPeeringDB executes a GET request to PeeringDB API.
// path is the API endpoint (e.g., "/ix", "/fac", "/net").
// params are query parameters (e.g., "id=123", "org_id=456").
func (c *PeeringDBClient) QueryPeeringDB(ctx context.Context, path string, params url.Values) ([]byte, error) {
	// Rate limiting with proper locking and no timer leaks
	if c.rateLimit > 0 {
		c.mu.Lock()
		elapsed := time.Since(c.lastReq)
		minInterval := time.Duration(float64(time.Second) / c.rateLimit)
		if elapsed < minInterval {
			wait := minInterval - elapsed
			c.mu.Unlock()
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return nil, ctx.Err()
			}
			c.mu.Lock()
		} else {
			c.mu.Unlock()
			c.mu.Lock()
		}
		c.lastReq = time.Now()
		c.mu.Unlock()
	} else {
		c.mu.Lock()
		c.lastReq = time.Now()
		c.mu.Unlock()
	}

	// Build URL
	u := c.baseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("peeringdb: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "TRAZIP/1.0")

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

	var respData PeeringDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
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

// ListIXPsByFacility returns IXP IDs present at a facility.
func (c *PeeringDBClient) ListIXPsByFacility(ctx context.Context, facilityID int) ([]int, error) {
	data, err := c.QueryPeeringDB(ctx, "/fac_ix", url.Values{"fac_id": {fmt.Sprintf("%d", facilityID)}})
	if err != nil {
		return nil, err
	}
	var links []PeeringDBFacilityIX
	if err := json.Unmarshal(data, &links); err != nil {
		return nil, fmt.Errorf("peeringdb: unmarshal fac_ix: %w", err)
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

	ixp := IXP{
		ID:          fmt.Sprintf("peeringdb:%d", pdb.ID),
		Name:        pdb.Name,
		City:        pdb.City,
		Country:     country,
		Region:      pdb.Region,
		Website:     pdb.Website,
		PeeringDBID: pdb.ID,
		Provenance:  osint.Provenance{
			ProviderID:      "peeringdb",
			ProviderName:    "PeeringDB",
			Capability:      "ixp",
			ActivityClass:   osint.ActivityPassive,
			DisclosureClass: osint.DisclosurePassive,
			RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
			Endpoint:        fmt.Sprintf("https://peeringdb.com/api/ix?id=%d", pdb.ID),
			Confidence:      "alta",
		},
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
		Provenance: osint.Provenance{
			ProviderID:      "peeringdb",
			ProviderName:    "PeeringDB",
			Capability:      "facility",
			ActivityClass:   osint.ActivityPassive,
			DisclosureClass: osint.DisclosurePassive,
			RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
			Endpoint:        fmt.Sprintf("https://peeringdb.com/api/fac?id=%d", pdb.ID),
			Confidence:      "alta",
		},
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
		Notes:       pdb.Notes,
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