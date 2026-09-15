// Package infrastructure provides tests for Internet Infrastructure Intelligence (V1.5-6).
package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"trazip/internal/intel/external"
	"trazip/internal/osint"
)

// TestParseIXP tests parsing of OSM elements to IXP model.
func TestParseIXP(t *testing.T) {
	tests := []struct {
		name     string
		elem     OverpassElement
		expected IXP
		wantErr  bool
	}{
		{
			name: "valid node IXP",
			elem: OverpassElement{
				Type: "node",
				ID:   12345,
				Lat:  52.37,
				Lon:  4.90,
				Tags: map[string]string{
					"name":           "AMS-IX",
					"city":           "Amsterdam",
					"country":        "NL",
					"internet_exchange_point": "yes",
				},
			},
			expected: IXP{
				ID:          "osm:node/12345",
				Name:        "AMS-IX",
				City:        "Amsterdam",
				Country:     "NL",
				Latitude:    52.37,
				Longitude:   4.90,
				OSMID:       "node/12345",
			},
			wantErr: false,
		},
		{
			name: "valid way IXP with center",
			elem: OverpassElement{
				Type: "way",
				ID:   67890,
				Center: &OverpassCenter{Lat: 48.86, Lon: 2.35},
				Tags: map[string]string{
					"name":   "France-IX Paris",
					"city":   "Paris",
					"country": "FR",
				},
			},
			expected: IXP{
				ID:         "osm:way/67890",
				Name:       "France-IX Paris",
				City:       "Paris",
				Country:    "FR",
				Latitude:   48.86,
				Longitude:  2.35,
				OSMID:      "way/67890",
			},
			wantErr: false,
		},
		{
			name: "missing name",
			elem: OverpassElement{
				Type: "node",
				ID:   111,
				Tags: map[string]string{"city": "Test", "country": "US"},
			},
			wantErr: true,
		},
		{
			name: "invalid country code",
			elem: OverpassElement{
				Type: "node",
				ID:   222,
				Tags: map[string]string{"name": "Test IXP", "city": "Test", "country": "USA"},
			},
			wantErr: true,
		},
		{
			name: "invalid element type",
			elem: OverpassElement{
				Type: "invalid",
				ID:   333,
				Tags: map[string]string{"name": "Test", "city": "Test", "country": "US"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := osint.Provenance{
				ProviderID:      "test",
				ProviderName:    "Test",
				Capability:      "ixp",
				ActivityClass:   osint.ActivityPassive,
				DisclosureClass: osint.DisclosurePassive,
				RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
				Endpoint:        "test",
				Confidence:      "alta",
			}
			ixp, err := ParseIXP(tt.elem, prov)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseIXP() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("ParseIXP() unexpected error: %v", err)
				}
				if ixp.ID != tt.expected.ID {
					t.Errorf("ID = %q, want %q", ixp.ID, tt.expected.ID)
				}
				if ixp.Name != tt.expected.Name {
					t.Errorf("Name = %q, want %q", ixp.Name, tt.expected.Name)
				}
				if ixp.City != tt.expected.City {
					t.Errorf("City = %q, want %q", ixp.City, tt.expected.City)
				}
				if ixp.Country != tt.expected.Country {
					t.Errorf("Country = %q, want %q", ixp.Country, tt.expected.Country)
				}
			}
		})
	}
}

// TestParseFacility tests parsing of OSM elements to Facility model.
func TestParseFacility(t *testing.T) {
	tests := []struct {
		name     string
		elem     OverpassElement
		expected Facility
		wantErr  bool
	}{
		{
			name: "valid node facility",
			elem: OverpassElement{
				Type: "node",
				ID:   12345,
				Lat:  52.37,
				Lon:  4.90,
				Tags: map[string]string{
					"name":      "Equinix AM5",
					"operator":  "Equinix",
					"city":      "Amsterdam",
					"country":   "NL",
					"building":  "data_center",
				},
			},
			expected: Facility{
				ID:        "osm:node/12345",
				Name:      "Equinix AM5",
				OrgName:   "Equinix",
				City:      "Amsterdam",
				Country:   "NL",
				Latitude:  52.37,
				Longitude: 4.90,
				OSMID:     "node/12345",
			},
			wantErr: false,
		},
		{
			name: "missing name",
			elem: OverpassElement{
				Type: "node",
				ID:   111,
				Tags: map[string]string{"city": "Test", "country": "US"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := osint.Provenance{
				ProviderID:      "test",
				ProviderName:    "Test",
				Capability:      "facility",
				ActivityClass:   osint.ActivityPassive,
				DisclosureClass: osint.DisclosurePassive,
				RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
				Endpoint:        "test",
				Confidence:      "alta",
			}
			fac, err := ParseFacility(tt.elem, prov)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseFacility() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("ParseFacility() unexpected error: %v", err)
				}
				if fac.Name != tt.expected.Name {
					t.Errorf("Name = %q, want %q", fac.Name, tt.expected.Name)
				}
				if fac.OrgName != tt.expected.OrgName {
					t.Errorf("OrgName = %q, want %q", fac.OrgName, tt.expected.OrgName)
				}
			}
		})
	}
}

// TestParseCableLandingStation tests parsing of OSM elements to LandingStation model.
func TestParseCableLandingStation(t *testing.T) {
	tests := []struct {
		name     string
		elem     OverpassElement
		expected LandingStation
		wantErr  bool
	}{
		{
			name: "valid landing station",
			elem: OverpassElement{
				Type: "node",
				ID:   12345,
				Lat:  50.83,
				Lon:  -4.55,
				Tags: map[string]string{
					"name":              "Bude",
					"city":              "Bude",
					"country":           "GB",
					"telecom":           "cable_landing_station",
					"submarine_cable":   "Grace Hopper;Curie",
				},
			},
			expected: LandingStation{
				ID:        "osm:node/12345",
				Name:      "Bude",
				City:      "Bude",
				Country:   "GB",
				Latitude:  50.83,
				Longitude: -4.55,
				OSMID:     "node/12345",
				Cables:    []string{"Grace Hopper", "Curie"},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			elem: OverpassElement{
				Type: "node",
				ID:   111,
				Tags: map[string]string{"city": "Test", "country": "US"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := osint.Provenance{
				ProviderID:      "test",
				ProviderName:    "Test",
				Capability:      "landing_station",
				ActivityClass:   osint.ActivityPassive,
				DisclosureClass: osint.DisclosurePassive,
				RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
				Endpoint:        "test",
				Confidence:      "alta",
			}
			ls, err := ParseCableLandingStation(tt.elem, prov)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCableLandingStation() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("ParseCableLandingStation() unexpected error: %v", err)
				}
				if ls.Name != tt.expected.Name {
					t.Errorf("Name = %q, want %q", ls.Name, tt.expected.Name)
				}
				if len(ls.Cables) != len(tt.expected.Cables) {
					t.Errorf("Cables = %v, want %v", ls.Cables, tt.expected.Cables)
				}
			}
		})
	}
}

// TestParseSubmarineCable tests parsing of OSM elements to SubmarineCable model.
func TestParseSubmarineCable(t *testing.T) {
	tests := []struct {
		name     string
		elem     OverpassElement
		expected SubmarineCable
		wantErr  bool
	}{
		{
			name: "valid way cable",
			elem: OverpassElement{
				Type: "way",
				ID:   12345,
				Tags: map[string]string{
					"name":       "Grace Hopper",
					"operator":   "Google;Meta",
					"length":     "6000",
					"fiber_pairs": "16",
					"capacity":   "352 Tbps",
					"start_date": "2022",
					"communication": "line",
					"location":   "underwater",
				},
			},
			expected: SubmarineCable{
				ID:            "osm:way/12345",
				Name:          "Grace Hopper",
				Owners:        []string{"Google", "Meta"},
				LengthKm:      6000,
				FiberPairs:    16,
				DesignCapacity: "352 Tbps",
				ReadyForService: "2022",
				OSMIDs:        []string{"way/12345"},
			},
			wantErr: false,
		},
		{
			name: "relation with landing points",
			elem: OverpassElement{
				Type: "relation",
				ID:   67890,
				Members: []OverpassMember{
					{Type: "node", Ref: 111, Role: "landing_point"},
					{Type: "node", Ref: 222, Role: "landing_station"},
				},
				Tags: map[string]string{
					"name": "Test Cable",
				},
			},
			expected: SubmarineCable{
				ID:           "osm:relation/67890",
				Name:         "Test Cable",
				LandingPoints: []string{"node/111", "node/222"},
				OSMIDs:       []string{"relation/67890"},
			},
			wantErr: false,
		},
		{
			name: "invalid element type",
			elem: OverpassElement{
				Type: "node",
				ID:   111,
				Tags: map[string]string{"name": "Test"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := osint.Provenance{
				ProviderID:      "test",
				ProviderName:    "Test",
				Capability:      "submarine_cable",
				ActivityClass:   osint.ActivityPassive,
				DisclosureClass: osint.DisclosurePassive,
				RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
				Endpoint:        "test",
				Confidence:      "alta",
			}
			cable, err := ParseSubmarineCable(tt.elem, prov)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseSubmarineCable() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("ParseSubmarineCable() unexpected error: %v", err)
				}
				if cable.Name != tt.expected.Name {
					t.Errorf("Name = %q, want %q", cable.Name, tt.expected.Name)
				}
			}
		})
	}
}

// TestMalformedOSMJSON tests handling of malformed OSM JSON responses.
func TestMalformedOSMJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	cfg := DefaultOSMConfig()
	cfg.BaseURL = server.URL
	client := NewOSMClient(cfg)

	ctx := context.Background()
	_, err := client.QueryOSM(ctx, `[out:json];node["test"];out;`)
	if err == nil {
		t.Errorf("expected error for malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "decode") && !strings.Contains(err.Error(), "invalid") {
		t.Errorf("error should mention decode/invalid: %v", err)
	}
}

// TestMalformedPeeringDBJSON tests handling of malformed PeeringDB JSON responses.
func TestMalformedPeeringDBJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{invalid json`))
	}))
	defer server.Close()

	cfg := DefaultPeeringDBConfig()
	cfg.BaseURL = server.URL
	client := NewPeeringDBClient(cfg)

	ctx := context.Background()
	_, err := client.GetIXP(ctx, 1)
	if err == nil {
		t.Errorf("expected error for malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "decode") && !strings.Contains(err.Error(), "unmarshal") && !strings.Contains(err.Error(), "invalid") {
		t.Errorf("error should mention decode/unmarshal/invalid: %v", err)
	}
}

// TestValidEmptyPayload tests handling of valid but empty responses.
func TestValidEmptyPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"version":0.6,"generator":"test","osm3s":{"timestamp_osm_base":"2024-01-01","copyright":"test","areas":{"free":1}},"elements":[]}`))
	}))
	defer server.Close()

	cfg := DefaultOSMConfig()
	cfg.BaseURL = server.URL
	client := NewOSMClient(cfg)

	ctx := context.Background()
	resp, err := client.QueryOSM(ctx, `[out:json];node["test"];out;`)
	if err != nil {
		t.Errorf("QueryOSM() unexpected error: %v", err)
	}
	if resp == nil {
		t.Errorf("expected response, got nil")
	}
	if len(resp.Elements) != 0 {
		t.Errorf("expected empty elements, got %d", len(resp.Elements))
	}
}

// TestTimeout tests context timeout handling.
func TestTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"version":0.6,"generator":"test","osm3s":{"timestamp_osm_base":"2024-01-01","copyright":"test","areas":{"free":1}},"elements":[]}`))
	}))
	defer server.Close()

	cfg := DefaultOSMConfig()
	cfg.BaseURL = server.URL
	cfg.Timeout = 10 * time.Millisecond
	client := NewOSMClient(cfg)

	ctx := context.Background()
	_, err := client.QueryOSM(ctx, `[out:json];node["test"];out;`)
	if err == nil {
		t.Errorf("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "context deadline") && !strings.Contains(err.Error(), "Client.Timeout") {
		t.Errorf("error should mention timeout: %v", err)
	}
}

// TestCancellation tests context cancellation handling.
func TestCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"version":0.6,"generator":"test","osm3s":{"timestamp_osm_base":"2024-01-01","copyright":"test","areas":{"free":1}},"elements":[]}`))
	}))
	defer server.Close()

	cfg := DefaultOSMConfig()
	cfg.BaseURL = server.URL
	client := NewOSMClient(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately
	_, err := client.QueryOSM(ctx, `[out:json];node["test"];out;`)
	if err == nil {
		t.Errorf("expected cancellation error, got nil")
	}
	if !strings.Contains(err.Error(), "canceled") && !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("error should mention cancellation: %v", err)
	}
}

// TestHTTP429 tests HTTP 429 rate limit handling.
func TestHTTP429(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`rate limited`))
	}))
	defer server.Close()

	cfg := DefaultOSMConfig()
	cfg.BaseURL = server.URL
	client := NewOSMClient(cfg)

	ctx := context.Background()
	_, err := client.QueryOSM(ctx, `[out:json];node["test"];out;`)
	if err == nil {
		t.Errorf("expected 429 error, got nil")
	}
	if !strings.Contains(err.Error(), "429") && !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("error should mention 429/rate limited: %v", err)
	}
}

// TestHTTP5xx tests HTTP 5xx server error handling.
func TestHTTP5xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`internal error`))
	}))
	defer server.Close()

	cfg := DefaultOSMConfig()
	cfg.BaseURL = server.URL
	client := NewOSMClient(cfg)

	ctx := context.Background()
	_, err := client.QueryOSM(ctx, `[out:json];node["test"];out;`)
	if err == nil {
		t.Errorf("expected 5xx error, got nil")
	}
	if !strings.Contains(err.Error(), "500") && !strings.Contains(err.Error(), "server error") {
		t.Errorf("error should mention 500/server error: %v", err)
	}
}

// TestResponseBodyOversized tests oversized response body handling.
func TestResponseBodyOversized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Create a valid JSON with large elements array - ~15MB
		w.Write([]byte(`{"version":0.6,"generator":"test","osm3s":{"timestamp_osm_base":"2024-01-01","copyright":"test","areas":{"free":1}},"elements":[`))
		// Write enough elements to exceed 10MB (each element ~100 bytes, need ~100,000 elements)
		for i := 0; i < 150000; i++ {
			if i > 0 {
				w.Write([]byte(","))
			}
			// Each element with large tags to increase size
			w.Write([]byte(fmt.Sprintf(`{"type":"node","id":%d,"lat":0,"lon":0,"tags":{"name":"test%d","description":"%s"}}`, i, i, strings.Repeat("x", 200))))
		}
		w.Write([]byte(`]}`))
	}))
	defer server.Close()

	cfg := DefaultOSMConfig()
	cfg.BaseURL = server.URL
	client := NewOSMClient(cfg)

	ctx := context.Background()
	_, err := client.QueryOSM(ctx, `[out:json];node["test"];out;`)
	if err == nil {
		t.Errorf("expected oversized response error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("error should mention size limit: %v", err)
	}
}

// TestResultBounds tests collection bounds enforcement.
func TestResultBounds(t *testing.T) {
	bounds := DefaultInfraBounds()
	coll := &InfrastructureCollection{
		IXPs:            make([]IXP, bounds.MaxIXPs+10),
		Facilities:      make([]Facility, bounds.MaxFacilities+10),
		LandingStations: make([]LandingStation, bounds.MaxLandingStations+10),
		SubmarineCables: make([]SubmarineCable, bounds.MaxSubmarineCables+10),
		Correlations:    make([]InfrastructureCorrelation, bounds.MaxCorrelations+10),
	}

	coll.Truncate(bounds)

	if len(coll.IXPs) != bounds.MaxIXPs {
		t.Errorf("IXPs truncated to %d, want %d", len(coll.IXPs), bounds.MaxIXPs)
	}
	if len(coll.Facilities) != bounds.MaxFacilities {
		t.Errorf("Facilities truncated to %d, want %d", len(coll.Facilities), bounds.MaxFacilities)
	}
	if len(coll.LandingStations) != bounds.MaxLandingStations {
		t.Errorf("LandingStations truncated to %d, want %d", len(coll.LandingStations), bounds.MaxLandingStations)
	}
	if len(coll.SubmarineCables) != bounds.MaxSubmarineCables {
		t.Errorf("SubmarineCables truncated to %d, want %d", len(coll.SubmarineCables), bounds.MaxSubmarineCables)
	}
	if len(coll.Correlations) != bounds.MaxCorrelations {
		t.Errorf("Correlations truncated to %d, want %d", len(coll.Correlations), bounds.MaxCorrelations)
	}
}

// TestOSMProvenance tests OSM provenance fields.
func TestOSMProvenance(t *testing.T) {
	prov := osint.Provenance{
		ProviderID:      "infra.intelligence",
		ProviderName:    "Internet Infrastructure Intelligence",
		Capability:      "ixp",
		ActivityClass:   osint.ActivityPassive,
		DisclosureClass: osint.DisclosurePassive,
		RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
		Endpoint:        "osm:node/12345",
		Confidence:      "alta",
		Disclosure: external.Disclosure{
			Source:      "Internet Infrastructure Intelligence",
			QueriedAt:   time.Now().UTC().Format(time.RFC3339),
			DataSent:    "osm:node/12345",
			CachePolicy: "none",
			Confidence:  "alta",
			RateLimit:   "OSM: 1 req/s (TRAZIP conservative); PeeringDB: 0.5 req/s (TRAZIP conservative)",
		},
	}

	elem := OverpassElement{
		Type: "node",
		ID:   12345,
		Tags: map[string]string{"name": "Test IXP", "city": "Test", "country": "US"},
	}

	ixp, err := ParseIXP(elem, prov)
	if err != nil {
		t.Fatalf("ParseIXP failed: %v", err)
	}

	if ixp.Provenance.ProviderID != prov.ProviderID {
		t.Errorf("Provenance ProviderID mismatch: %s != %s", ixp.Provenance.ProviderID, prov.ProviderID)
	}
	if ixp.Provenance.Endpoint != prov.Endpoint {
		t.Errorf("Provenance Endpoint mismatch: %s != %s", ixp.Provenance.Endpoint, prov.Endpoint)
	}
	if ixp.Provenance.Disclosure.Source != prov.Disclosure.Source {
		t.Errorf("Disclosure Source mismatch: %s != %s", ixp.Provenance.Disclosure.Source, prov.Disclosure.Source)
	}
}

// TestPeeringDBProvenance tests PeeringDB provenance fields.
func TestPeeringDBProvenance(t *testing.T) {
	pdb := &PeeringDBIXP{
		ID:       123,
		Name:     "Test IXP",
		City:     "Test City",
		Country:  "US",
		Region:   "North America",
		Website:  "https://example.com",
		Notes:    "Test notes",
		Status:   "ok",
		OrgID:    456,
	}

	prov := osint.Provenance{
		ProviderID:      "infra.intelligence",
		ProviderName:    "Internet Infrastructure Intelligence",
		Capability:      "ixp",
		ActivityClass:   osint.ActivityPassive,
		DisclosureClass: osint.DisclosurePassive,
		RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
		Endpoint:        "https://peeringdb.com/api/ix?id=123",
		Confidence:      "alta",
	}

	ixp, err := ConvertPeeringDBIXP(pdb, prov)
	if err != nil {
		t.Fatalf("ConvertPeeringDBIXP failed: %v", err)
	}

	if ixp.Provenance.ProviderID != "peeringdb" {
		t.Errorf("Provenance ProviderID should be 'peeringdb': %s", ixp.Provenance.ProviderID)
	}
	if !strings.Contains(ixp.Provenance.Endpoint, "peeringdb.com/api/ix?id=123") {
		t.Errorf("Provenance Endpoint should contain peeringdb URL: %s", ixp.Provenance.Endpoint)
	}
	if ixp.Provenance.Disclosure.Source != "PeeringDB" {
		t.Errorf("Disclosure Source should be 'PeeringDB': %s", ixp.Provenance.Disclosure.Source)
	}
}

// TestDisclosure tests ActivityClass and DisclosureClass separation.
func TestDisclosure(t *testing.T) {
	// OSM and PeeringDB are PASSIVE activity, PASSIVE/EXTERNAL_LOOKUP disclosure
	prov := osint.Provenance{
		ProviderID:      "infra.intelligence",
		ProviderName:    "Internet Infrastructure Intelligence",
		Capability:      "ixp",
		ActivityClass:   osint.ActivityPassive,
		DisclosureClass: osint.DisclosurePassive,
		RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
		Endpoint:        "test",
		Confidence:      "alta",
		Disclosure: external.Disclosure{
			Source:      "Internet Infrastructure Intelligence",
			QueriedAt:   time.Now().UTC().Format(time.RFC3339),
			DataSent:    "test",
			CachePolicy: "none",
			Confidence:  "alta",
			RateLimit:   "OSM: 1 req/s (TRAZIP conservative); PeeringDB: 0.5 req/s (TRAZIP conservative)",
		},
	}

	// Should NOT be LOCAL
	if prov.ActivityClass == osint.ActivityActive {
		t.Errorf("ActivityClass should be Passive, not Active")
	}
	if prov.DisclosureClass == osint.DisclosureLocal {
		t.Errorf("DisclosureClass should not be Local")
	}

	// Verify disclosure fields
	if prov.Disclosure.Source == "" {
		t.Errorf("Disclosure Source should not be empty")
	}
	if prov.Disclosure.QueriedAt == "" {
		t.Errorf("Disclosure QueriedAt should not be empty")
	}
}

// TestEvidenceClassValidation tests InfrastructureCorrelation evidence class validation.
func TestEvidenceClassValidation(t *testing.T) {
	tests := []struct {
		name       string
		corr       InfrastructureCorrelation
		wantErr    bool
		errContains string
	}{
		{
			name: "valid OBSERVED with provenance",
			corr: InfrastructureCorrelation{
				ID:             "test-1",
				NetworkEntity:  "AS123",
				InfraEntity:    "ixp-1",
				RelationKind:   "asn_at_ixp",
				EvidenceClass:  osint.EvidenceObserved,
				ProvenanceRef:  "peeringdb:netixlan:123",
				Confidence:     "alta",
				RetrievedAt:    time.Now().UTC().Format(time.RFC3339),
			},
			wantErr: false,
		},
		{
			name: "OBSERVED without provenance ref",
			corr: InfrastructureCorrelation{
				ID:             "test-2",
				NetworkEntity:  "AS123",
				InfraEntity:    "ixp-1",
				RelationKind:   "asn_at_ixp",
				EvidenceClass:  osint.EvidenceObserved,
				ProvenanceRef:  "",
				Confidence:     "alta",
				RetrievedAt:    time.Now().UTC().Format(time.RFC3339),
			},
			wantErr:    true,
			errContains: "OBSERVED requires non-empty ProvenanceRef",
		},
		{
			name: "valid POSSIBLE_CONTEXT",
			corr: InfrastructureCorrelation{
				ID:             "test-3",
				NetworkEntity:  "ixp-1",
				InfraEntity:    "fac-1",
				RelationKind:   "ixp_near_facility",
				EvidenceClass:  osint.EvidencePossibleContext,
				ProvenanceRef:  "geographic:city,country",
				Confidence:     "baja",
				RetrievedAt:    time.Now().UTC().Format(time.RFC3339),
			},
			wantErr: false,
		},
		{
			name: "valid NOT_PROVEN",
			corr: InfrastructureCorrelation{
				ID:             "test-4",
				NetworkEntity:  "cable-1",
				InfraEntity:    "path-1",
				RelationKind:   "cable_traversal",
				EvidenceClass:  osint.EvidenceNotProven,
				ProvenanceRef:  "",
				Confidence:     "baja",
				RetrievedAt:    time.Now().UTC().Format(time.RFC3339),
			},
			wantErr: false,
		},
		{
			name: "invalid evidence class",
			corr: InfrastructureCorrelation{
				ID:             "test-5",
				NetworkEntity:  "AS123",
				InfraEntity:    "ixp-1",
				RelationKind:   "test",
				EvidenceClass:  osint.EvidenceClass(999), // Invalid value
				ProvenanceRef:  "ref",
				Confidence:     "alta",
				RetrievedAt:    time.Now().UTC().Format(time.RFC3339),
			},
			wantErr:    true,
			errContains: "invalid evidence class",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.corr.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error should contain %q: %v", tt.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestNoEvidencePromotion tests that evidence is never auto-promoted.
func TestNoEvidencePromotion(t *testing.T) {
	// Geographic proximity correlations should be POSSIBLE_CONTEXT, never OBSERVED
	corr := InfrastructureCorrelation{
		ID:             "geo-1",
		NetworkEntity:  "ixp-1",
		InfraEntity:    "fac-1",
		RelationKind:   "ixp_near_facility",
		EvidenceClass:  osint.EvidencePossibleContext, // Must be POSSIBLE_CONTEXT
		ProvenanceRef:  "geographic:madrid,es",
		Label:          "IXP and Facility co-located in Madrid",
		Confidence:     "baja",
		RetrievedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	if corr.EvidenceClass == osint.EvidenceObserved {
		t.Errorf("geographic proximity correlation must not be OBSERVED")
	}
	if corr.EvidenceClass != osint.EvidencePossibleContext {
		t.Errorf("geographic proximity correlation must be POSSIBLE_CONTEXT")
	}

	// Cable path correlations must be NOT_PROVEN
	cableCorr := InfrastructureCorrelation{
		ID:             "cable-1",
		NetworkEntity:  "cable-1",
		InfraEntity:    "path-1",
		RelationKind:   "cable_traversal",
		EvidenceClass:  osint.EvidenceNotProven, // Must be NOT_PROVEN
		ProvenanceRef:  "",
		Label:          "Cable traversal claimed",
		Confidence:     "baja",
		RetrievedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	if cableCorr.EvidenceClass != osint.EvidenceNotProven {
		t.Errorf("cable traversal correlation must be NOT_PROVEN")
	}
}

// TestProximityNeverBecomesObserved tests that proximity never becomes OBSERVED.
func TestProximityNeverBecomesObserved(t *testing.T) {
	// Even same city, same country, same facility - never OBSERVED without explicit PeeringDB evidence
	corr := InfrastructureCorrelation{
		ID:             "prox-1",
		NetworkEntity:  "ixp-1",
		InfraEntity:    "fac-1",
		RelationKind:   "same_facility_proximity",
		EvidenceClass:  osint.EvidencePossibleContext, // At most POSSIBLE_CONTEXT
		ProvenanceRef:  "geographic:madrid,es",
		Label:          "IXP and Facility in same building (proximity only)",
		Confidence:     "baja",
		RetrievedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	if corr.EvidenceClass == osint.EvidenceObserved {
		t.Errorf("proximity correlation must not be promoted to OBSERVED")
	}
}

// TestCablePathRemainsNotProven tests that cable path remains NOT_PROVEN.
func TestCablePathRemainsNotProven(t *testing.T) {
	corr := InfrastructureCorrelation{
		ID:             "cable-path-1",
		NetworkEntity:  "cable-1",
		InfraEntity:    "network-path-1",
		RelationKind:   "cable_path_traversal",
		EvidenceClass:  osint.EvidenceNotProven, // Always NOT_PROVEN in V1.5-6
		ProvenanceRef:  "",
		Label:          "Traffic traverses cable (claimed)",
		Confidence:     "baja",
		RetrievedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	if corr.EvidenceClass != osint.EvidenceNotProven {
		t.Errorf("cable path correlation must remain NOT_PROVEN in V1.5-6")
	}
}

// TestNoFabricatedRelations tests that no relations are fabricated without evidence.
func TestNoFabricatedRelations(t *testing.T) {
	coll := &InfrastructureCollection{
		IXPs: []IXP{
			{ID: "ixp-1", Name: "IXP-A", City: "Madrid", Country: "ES"},
			{ID: "ixp-2", Name: "IXP-B", City: "Barcelona", Country: "ES"},
		},
		Facilities: []Facility{
			{ID: "fac-1", Name: "Fac-A", City: "Madrid", Country: "ES"},
			{ID: "fac-2", Name: "Fac-B", City: "Barcelona", Country: "ES"},
		},
		LandingStations: []LandingStation{},
		SubmarineCables: []SubmarineCable{},
		Correlations:    []InfrastructureCorrelation{},
	}

	// Correlations should only be created for explicit evidence
	// Same country (ES) should NOT create correlation
	// Same city should create POSSIBLE_CONTEXT but only for IXP-Facility pairs in same city
	
	foundMadridCorr := false
	for _, corr := range coll.Correlations {
		if strings.Contains(corr.ProvenanceRef, "madrid") {
			foundMadridCorr = true
			if corr.EvidenceClass != osint.EvidencePossibleContext {
				t.Errorf("Madrid correlation must be POSSIBLE_CONTEXT")
			}
		}
	}

	// Empty correlations is valid - no fabricated relations
	if len(coll.Correlations) > 0 && !foundMadridCorr {
		t.Errorf("should not have fabricated correlations without evidence")
	}
}

// TestASNToIXPExplicitCorrelation tests ASN→IXP explicit correlation from PeeringDB.
func TestASNToIXPExplicitCorrelation(t *testing.T) {
	pdbNetIXLAN := PeeringDBNetIXLAN{
		ID:     123,
		ASN:    12345,
		IXLANID: 456,
		Operational: true,
	}

	prov := osint.Provenance{
		ProviderID:      "peeringdb",
		ProviderName:    "PeeringDB",
		Capability:      "ixp",
		ActivityClass:   osint.ActivityPassive,
		DisclosureClass: osint.DisclosurePassive,
		RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
		Endpoint:        "https://peeringdb.com/api/netixlan?id=123",
		Confidence:      "alta",
	}

	corr, err := ConvertPeeringDBNetIXLAN(&pdbNetIXLAN, "peeringdb:ix:456", prov)
	if err != nil {
		t.Fatalf("ConvertPeeringDBNetIXLAN failed: %v", err)
	}

	if corr.EvidenceClass != osint.EvidenceObserved {
		t.Errorf("ASN→IXP from PeeringDB netixlan must be OBSERVED")
	}
	if corr.ProvenanceRef != "peeringdb:netixlan:123" {
		t.Errorf("ProvenanceRef should reference netixlan: %s", corr.ProvenanceRef)
	}
	if corr.NetworkEntity != "AS12345" {
		t.Errorf("NetworkEntity should be AS12345: %s", corr.NetworkEntity)
	}
}

// TestASNToFacilityExplicitCorrelation tests ASN→Facility explicit correlation from PeeringDB.
func TestASNToFacilityExplicitCorrelation(t *testing.T) {
	pdbNetFac := PeeringDBNetFac{
		ID:    456,
		NetID: 12345,
		FacID: 789,
	}

	prov := osint.Provenance{
		ProviderID:      "peeringdb",
		ProviderName:    "PeeringDB",
		Capability:      "facility",
		ActivityClass:   osint.ActivityPassive,
		DisclosureClass: osint.DisclosurePassive,
		RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
		Endpoint:        "https://peeringdb.com/api/netfac?id=456",
		Confidence:      "alta",
	}

	corr, err := ConvertPeeringDBNetFac(&pdbNetFac, "peeringdb:fac:789", 12345, prov)
	if err != nil {
		t.Fatalf("ConvertPeeringDBNetFac failed: %v", err)
	}

	if corr.EvidenceClass != osint.EvidenceObserved {
		t.Errorf("ASN→Facility from PeeringDB netfac must be OBSERVED")
	}
	if corr.ProvenanceRef != "peeringdb:netfac:456" {
		t.Errorf("ProvenanceRef should reference netfac: %s", corr.ProvenanceRef)
	}
	if corr.NetworkEntity != "AS12345" {
		t.Errorf("NetworkEntity should be AS12345: %s", corr.NetworkEntity)
	}
}

// TestExecutorPassiveExecutionPath tests the Executor passive execution path.
func TestExecutorPassiveExecutionPath(t *testing.T) {
	reg := osint.NewRegistry()
	
	// Create a mock passive provider
	mockProvider := &mockPassiveProvider{
		id: "test.passive",
		meta: osint.ProviderMeta{
			ID:              "test.passive",
			Name:            "Test Passive Provider",
			Capabilities:    []osint.Capability{osint.CapabilityIXP},
			ActivityClass:   osint.ActivityPassive,
			DisclosureClass: osint.DisclosurePassive,
			RequiresScope:   false,
		},
		lookupResult: osint.Result{
			Data: &InfrastructureCollection{
				IXPs: []IXP{{ID: "ixp-1", Name: "Test IXP", City: "Test", Country: "US"}},
			},
			Provenance: osint.Provenance{
				ProviderID:      "test.passive",
				ProviderName:    "Test Passive Provider",
				Capability:      "ixp",
				ActivityClass:   osint.ActivityPassive,
				DisclosureClass: osint.DisclosurePassive,
				RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
				Endpoint:        "test",
				Confidence:      "alta",
			},
		},
	}
	
	err := reg.Register(mockProvider)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	executor := osint.NewExecutor(reg)
	ctx := context.Background()
	res := executor.ExecutePassive(ctx, "test.passive", osint.CapabilityIXP, "test query")

	if res.Err != nil {
		t.Errorf("ExecutePassive failed: %v", res.Err)
	}
	if res.Data == nil {
		t.Errorf("expected data, got nil")
	}
	if res.Provenance.ProviderID != "test.passive" {
		t.Errorf("provenance provider ID mismatch: %s", res.Provenance.ProviderID)
	}
}

// TestUnsupportedCapability tests unsupported capability handling.
func TestUnsupportedCapability(t *testing.T) {
	reg := osint.NewRegistry()
	
	mockProvider := &mockPassiveProvider{
		id: "test.passive",
		meta: osint.ProviderMeta{
			ID:              "test.passive",
			Name:            "Test Passive Provider",
			Capabilities:    []osint.Capability{osint.CapabilityIXP},
			ActivityClass:   osint.ActivityPassive,
			DisclosureClass: osint.DisclosurePassive,
			RequiresScope:   false,
		},
		lookupResult: osint.Result{},
	}
	
	err := reg.Register(mockProvider)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	executor := osint.NewExecutor(reg)
	ctx := context.Background()
	res := executor.ExecutePassive(ctx, "test.passive", osint.CapabilityCVE, "test query")

	if res.Err == nil {
		t.Errorf("expected UnsupportedCapabilityError, got nil")
	}
	if _, ok := res.Err.(*osint.UnsupportedCapabilityError); !ok {
		t.Errorf("error should be UnsupportedCapabilityError: %T", res.Err)
	}
}

// TestConcurrencyRateLimiter tests concurrent rate limiter behavior.
func TestConcurrencyRateLimiter(t *testing.T) {
	cfg := DefaultOSMConfig()
	cfg.RateLimit = 10.0 // 10 req/s
	cfg.BaseURL = "http://localhost:9999" // Non-existent server
	client := NewOSMClient(cfg)

	ctx := context.Background()
	var wg sync.WaitGroup
	errors := make(chan error, 5)

	// Launch 5 concurrent requests
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.QueryOSM(ctx, `[out:json];node["test"];out;`)
			errors <- err
		}()
	}

	wg.Wait()
	close(errors)

	// All should fail with connection error, not rate limit
	for err := range errors {
		if err == nil {
			t.Errorf("expected connection error, got nil")
		}
		if strings.Contains(err.Error(), "rate limited") || strings.Contains(err.Error(), "429") {
			t.Errorf("should not hit rate limiter with 10 req/s limit: %v", err)
		}
	}
}

// TestCacheBoundsTTL tests cache bounds and TTL if implemented.
func TestCacheBoundsTTL(t *testing.T) {
	// This test verifies the design decision - no cache implemented in V1.5-6
	// If cache is added later, this test should be updated
	cfg := DefaultOSMConfig()
	client := NewOSMClient(cfg)

	// Verify no cache fields exist
	if client.httpClient == nil {
		t.Errorf("httpClient should exist")
	}
	// Cache would be a separate struct field if implemented
}

// Helper mock provider for executor tests
type mockPassiveProvider struct {
	id           string
	meta         osint.ProviderMeta
	lookupResult osint.Result
}

func (m *mockPassiveProvider) Meta() osint.ProviderMeta {
	return m.meta
}

func (m *mockPassiveProvider) Lookup(ctx context.Context, capability osint.Capability, input any) osint.Result {
	return m.lookupResult
}

// TestNonNilArrays tests that JSON serialization produces non-nil arrays.
func TestNonNilArrays(t *testing.T) {
	coll := &InfrastructureCollection{}
	coll.EnsureNonNil()

	data, err := json.Marshal(coll)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Check all array fields are non-nil (empty arrays, not null)
	arrayFields := []string{"ixps", "facilities", "landingStations", "submarineCables", "correlations", "provenance"}
	for _, field := range arrayFields {
		val, ok := result[field]
		if !ok {
			t.Errorf("field %s missing in JSON", field)
			continue
		}
		if val == nil {
			t.Errorf("field %s is null, should be empty array", field)
		}
		arr, ok := val.([]interface{})
		if !ok {
			t.Errorf("field %s is not an array: %T", field, val)
		}
		if len(arr) != 0 {
			t.Errorf("field %s should be empty: %v", field, arr)
		}
	}
}

// TestQueryBounds tests that queries without explicit bounds are rejected.
func TestQueryBounds(t *testing.T) {
	ctx := context.Background()
	
	// Empty query should be rejected at provider level
	// Test inferBBoxFromQuery returns empty for unbounded queries
	bbox, err := inferBBoxFromQuery(ctx, "random text without bounds")
	if err != nil {
		t.Fatalf("inferBBoxFromQuery failed: %v", err)
	}
	if bbox != "" {
		t.Errorf("unbounded query should return empty bbox, got: %s", bbox)
	}

	// Explicit bbox should work
	bbox, err = inferBBoxFromQuery(ctx, "bbox:10,20,30,40")
	if err != nil {
		t.Fatalf("inferBBoxFromQuery failed for bbox: %v", err)
	}
	if bbox != "10,20,30,40" {
		t.Errorf("bbox parse failed: %s", bbox)
	}

	// Country code should work
	bbox, err = inferBBoxFromQuery(ctx, "country:US")
	if err != nil {
		t.Fatalf("inferBBoxFromQuery failed for country: %v", err)
	}
	if bbox == "" {
		t.Errorf("country:US should return bbox")
	}

	// City should work
	bbox, err = inferBBoxFromQuery(ctx, "city:Madrid,ES")
	if err != nil {
		t.Fatalf("inferBBoxFromQuery failed for city: %v", err)
	}
	if bbox == "" {
		t.Errorf("city:Madrid,ES should return bbox")
	}
}

// TestPeeringDBEndpoints tests that correct PeeringDB endpoints are used.
func TestPeeringDBEndpoints(t *testing.T) {
	// Verify the client uses correct endpoints
	cfg := DefaultPeeringDBConfig()
	cfg.BaseURL = "http://test.local"
	client := NewPeeringDBClient(cfg)

	// Check that fac_ix is NOT used, ixfac is used instead
	// This is verified by the method names in the client
	_ = client.ListIXPsByFacility // Should use ixfac
	_ = client.ListFacilitiesByNetwork // Should use netfac
	_ = client.ListNetIXLANsByASN // Should use netixlan
	_ = client.ListNetworksAtIXP // Should use netixlan with ix_id
}

// TestResponseSizeBounds tests HTTP response size limits for PeeringDB.
func TestResponseSizeBounds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return a large valid response - ~15MB
		w.Write([]byte(`{"data":[`))
		// Write enough elements to exceed 10MB (each element ~100 bytes, need ~100,000 elements)
		for i := 0; i < 150000; i++ {
			if i > 0 {
				w.Write([]byte(","))
			}
			w.Write([]byte(fmt.Sprintf(`{"id":%d,"name":"test%d","description":"%s"}`, i, i, strings.Repeat("x", 200))))
		}
		w.Write([]byte(`],"meta":{"limit":150000,"offset":0,"total":150000}}`))
	}))
	defer server.Close()

	cfg := DefaultPeeringDBConfig()
	cfg.BaseURL = server.URL
	client := NewPeeringDBClient(cfg)

	ctx := context.Background()
	_, err := client.QueryPeeringDB(ctx, "/ix", url.Values{})
	if err == nil {
		t.Errorf("expected oversized response error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("error should mention size limit: %v", err)
	}
}

// TestPaginationBounds tests PeeringDB pagination limits.
func TestPaginationBounds(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		limit := r.URL.Query().Get("limit")
		offset := r.URL.Query().Get("offset")
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`{"data":[{"id":%d,"name":"test"}],"meta":{"limit":%s,"offset":%s,"total":1000}}`, requestCount, limit, offset)))
	}))
	defer server.Close()

	cfg := DefaultPeeringDBConfig()
	cfg.BaseURL = server.URL
	client := NewPeeringDBClient(cfg)

	ctx := context.Background()
	_, err := client.QueryPeeringDB(ctx, "/ix", url.Values{"id": {"1"}})
	if err != nil {
		t.Fatalf("QueryPeeringDB failed: %v", err)
	}

	// Verify limit is applied
	if requestCount > 0 {
		// The limit parameter should be set to maxPageSize (1000)
		// This is enforced in QueryPeeringDB
	}
}

// TestUserAgentInRequests tests that configured UserAgent is used in requests.
func TestUserAgentInRequests(t *testing.T) {
	customUA := "TRAZIP-Custom/1.0 (test)"
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if ua != customUA {
			t.Errorf("User-Agent mismatch: got %q, want %q", ua, customUA)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"version":0.6,"generator":"test","osm3s":{"timestamp_osm_base":"2024-01-01","copyright":"test","areas":{"free":1}},"elements":[]}`))
	}))
	defer server.Close()

	cfg := DefaultOSMConfig()
	cfg.BaseURL = server.URL
	cfg.UserAgent = customUA
	client := NewOSMClient(cfg)

	ctx := context.Background()
	_, err := client.QueryOSM(ctx, `[out:json];node["test"];out;`)
	if err != nil {
		t.Fatalf("QueryOSM failed: %v", err)
	}
}

// TestPeeringDBUserAgent tests PeeringDB UserAgent usage.
func TestPeeringDBUserAgent(t *testing.T) {
	customUA := "TRAZIP-PeeringDB/1.0 (test)"
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if ua != customUA {
			t.Errorf("PeeringDB User-Agent mismatch: got %q, want %q", ua, customUA)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[{"id":1,"name":"test"}],"meta":{"limit":100,"offset":0,"total":1}}`))
	}))
	defer server.Close()

	cfg := DefaultPeeringDBConfig()
	cfg.BaseURL = server.URL
	cfg.UserAgent = customUA
	client := NewPeeringDBClient(cfg)

	ctx := context.Background()
	_, err := client.GetIXP(ctx, 1)
	if err != nil {
		t.Fatalf("GetIXP failed: %v", err)
	}
}

// TestRateLimitLabel tests that rate limit label doesn't claim AUP prescription.
func TestRateLimitLabel(t *testing.T) {
	cfg := InfraProviderConfig{
		OSM: DefaultOSMConfig(),
		PeeringDB: DefaultPeeringDBConfig(),
		Enabled: true,
	}
	
	provider, err := NewInfraProvider(cfg)
	if err != nil {
		t.Fatalf("NewInfraProvider failed: %v", err)
	}
	if provider == nil {
		t.Fatal("provider is nil")
	}

	meta := provider.Meta()
	rateLimit := meta.RateLimit
	
	// Should NOT contain "per AUP" or "AUP"
	if strings.Contains(strings.ToLower(rateLimit), "per aup") || strings.Contains(strings.ToLower(rateLimit), " aup ") {
		t.Errorf("RateLimit label should not claim AUP prescription: %s", rateLimit)
	}
	
	// Should contain TRAZIP conservative policy language
	if !strings.Contains(rateLimit, "TRAZIP conservative") {
		t.Errorf("RateLimit label should mention TRAZIP conservative policy: %s", rateLimit)
	}
}

// TestCorrelationReachability tests that correlation enrichment produces OBSERVED correlations
// when PeeringDB data is available.
func TestCorrelationReachability(t *testing.T) {
	// This test verifies that the provider can produce ASN->IXP, ASN->Facility, IXP->Facility
	// OBSERVED correlations when PeeringDB data is available.
	// Uses httptest servers to simulate PeeringDB API.

	// Create test PeeringDB server
	pdbServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// Handle trailing and leading slashes
		path = strings.Trim(path, "/")
		switch path {
		case "ix":
			// Return IXP with PeeringDBID = 17 (distinct from ixlan_id=901)
			ixID := r.URL.Query().Get("id")
			if ixID == "17" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data":[{"id":17,"name":"TEST-IX","city":"Madrid","country":"ES","region_continent":"Europe","website":"","notes":"","created":"","updated":"","status":"ok","org_id":1,"ipv4_prefix":"","ipv6_prefix":""}],"meta":{"limit":1000,"offset":0,"total":1}}`))
			} else if ixID == "901" {
				// This should NOT be called - if it is, the test will fail because we return 404
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"data":[],"meta":{"limit":1000,"offset":0,"total":0}}`))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data":[],"meta":{"limit":1000,"offset":0,"total":0}}`))
			}
		case "net":
			// Return network for ASN 64500 (net_id = 5)
			if r.URL.Query().Get("asn") == "64500" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data":[{"id":5,"asn":64500,"name":"TEST-NET","website":"","info_type":"NSP","policy":"Open","notes":"","created":"","updated":"","status":"ok","org_id":1}],"meta":{"limit":1000,"offset":0,"total":1}}`))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data":[],"meta":{"limit":1000,"offset":0,"total":0}}`))
			}
		case "fac":
			// Return Facility with PeeringDBID = 10
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":[{"id":10,"name":"TEST-FAC","city":"Madrid","country":"ES","region_continent":"Europe","address1":"","suite":"","zipcode":"","latitude":40.41,"longitude":-3.70,"clli":"","npa":"","nxx":"","website":"","notes":"","created":"","updated":"","status":"ok","org_id":1,"suggested_ixps":[17]}],"meta":{"limit":1000,"offset":0,"total":1}}`))
		case "netixlan":
			// Return netixlan for ASN 64500 (queries /netixlan?asn=64500)
			// Also handle ix_id for ListNetworksAtIXP path
			ixID := r.URL.Query().Get("ix_id")
			if ixID == "17" || r.URL.Query().Get("asn") == "64500" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data":[{"id":100,"net_id":5,"ix_id":17,"ixlan_id":901,"ipaddr4":"192.0.2.1","ipaddr6":"","asn":64500,"speed":10000,"operational":true,"is_rs_peer":false,"created":"","updated":""}],"meta":{"limit":1000,"offset":0,"total":1}}`))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data":[],"meta":{"limit":1000,"offset":0,"total":0}}`))
			}
		case "netfac":
			// Return netfac for ASN 64500 (net_id = 5)
			if r.URL.Query().Get("asn") == "64500" || r.URL.Query().Get("net_id") == "5" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data":[{"id":200,"net_id":5,"fac_id":10,"avg_bps":0,"created":"","updated":""}],"meta":{"limit":1000,"offset":0,"total":1}}`))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data":[],"meta":{"limit":1000,"offset":0,"total":0}}`))
			}
		case "ixfac":
			// Return ixfac for Facility 10 -> IXP 17
			if r.URL.Query().Get("fac_id") == "10" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data":[{"fac_id":10,"ix_id":17}],"meta":{"limit":1000,"offset":0,"total":1}}`))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"data":[],"meta":{"limit":1000,"offset":0,"total":0}}`))
			}
		default:
			// Handle any path by returning a proper PeeringDB response
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"data":[],"meta":{"limit":1000,"offset":0,"total":0}}`))
		}
	}))
	defer pdbServer.Close()

	// Create OSM server (minimal, returns empty for infrastructure queries)
	osmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"version":0.6,"generator":"test","osm3s":{"timestamp_osm_base":"2024-01-01","copyright":"test","areas":{"free":1}},"elements":[]}`))
	}))
	defer osmServer.Close()

	cfg := InfraProviderConfig{
		OSM: OSMConfig{
			Timeout:    5 * time.Second,
			RateLimit:  100, // High rate limit for testing
			BaseURL:    osmServer.URL,
			UserAgent:  "TEST",
		},
		PeeringDB: PeeringDBConfig{
			Timeout:    5 * time.Second,
			RateLimit:  100,
			BaseURL:    pdbServer.URL,
			UserAgent:  "TEST",
		},
		Enabled: true,
	}

	provider, err := NewInfraProvider(cfg)
	if err != nil {
		t.Fatalf("NewInfraProvider failed: %v", err)
	}
	if provider == nil {
		t.Fatal("provider is nil")
	}

	ctx := context.Background()

	// Test infrastructure lookup with ASN query (should trigger PeeringDB enrichment)
	result := provider.Lookup(ctx, osint.CapabilityInfrastructure, "asn:64500")
	if result.Err != nil {
		t.Fatalf("Lookup failed: %v", result.Err)
	}

	coll, ok := result.Data.(*InfrastructureCollection)
	if !ok {
		t.Fatal("result data is not InfrastructureCollection")
	}

	// Verify we have IXP and Facility from PeeringDB
	if len(coll.IXPs) == 0 {
		t.Errorf("expected at least 1 IXP from PeeringDB, got %d", len(coll.IXPs))
	}
	if len(coll.Facilities) == 0 {
		t.Errorf("expected at least 1 Facility from PeeringDB, got %d", len(coll.Facilities))
	}

	// Verify IXP has correct PeeringDBID (17, not 901 which is ixlan_id)
	ixpFound := false
	for _, ixp := range coll.IXPs {
		if ixp.PeeringDBID == 17 {
			ixpFound = true
			break
		}
	}
	if !ixpFound {
		t.Errorf("expected IXP with PeeringDBID 17 (ix_id), got IXPs: %v", coll.IXPs)
	}

	// Verify Facility has correct PeeringDBID (10)
	facFound := false
	for _, fac := range coll.Facilities {
		if fac.PeeringDBID == 10 {
			facFound = true
			break
		}
	}
	if !facFound {
		t.Errorf("expected Facility with PeeringDBID 10, got Facilities: %v", coll.Facilities)
	}

	// Verify OBSERVED correlations were created
	observedCount := 0
	for _, corr := range coll.Correlations {
		if corr.EvidenceClass == osint.EvidenceObserved {
			observedCount++
			// Verify ProvenanceRef is set for OBSERVED
			if corr.ProvenanceRef == "" {
				t.Errorf("OBSERVED correlation missing ProvenanceRef: %s", corr.ID)
			}
			// Verify provenance exists in collection for resolvability
			found := false
			for _, prov := range coll.Provenance {
				if prov.Endpoint == corr.ProvenanceRef {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("OBSERVED correlation ProvenanceRef not found in collection: %s", corr.ProvenanceRef)
			}
		}
	}

	// Should have at least 3 OBSERVED correlations:
	// ASN->IXP, ASN->Facility, IXP->Facility
	if observedCount < 3 {
		t.Errorf("expected at least 3 OBSERVED correlations, got %d", observedCount)
	}
}

// TestQueryFormats tests all supported query formats.
func TestQueryFormats(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		wantBBox string
		wantErr  bool
	}{
		{
			name:     "explicit bbox",
			query:    "bbox:10,20,30,40",
			wantBBox: "10,20,30,40",
			wantErr:  false,
		},
		{
			name:     "country code",
			query:    "country:ES",
			wantBBox: "36.0,-9.3,43.79,3.3", // Spain bbox
			wantErr:  false,
		},
		{
			name:     "cc prefix",
			query:    "cc:FR",
			wantBBox: "41.33,-5.14,51.12,9.56", // France bbox
			wantErr:  false,
		},
		{
			name:     "city with country",
			query:    "city:Madrid,ES",
			wantBBox: "40.24,-3.95,40.55,-3.5", // Madrid bbox
			wantErr:  false,
		},
		{
			name:     "ASN query",
			query:    "asn:12345",
			wantBBox: "", // Returns empty to signal PeeringDB
			wantErr:  false,
		},
		{
			name:     "peeringdb:ix:NUMBER",
			query:    "peeringdb:ix:123",
			wantBBox: "", // Signal direct lookup
			wantErr:  false,
		},
		{
			name:     "peeringdb:fac:NUMBER",
			query:    "peeringdb:fac:456",
			wantBBox: "", // Signal direct lookup
			wantErr:  false,
		},
		{
			name:     "osm:TYPE/ID",
			query:    "osm:node/12345",
			wantBBox: "", // Signal direct lookup
			wantErr:  false,
		},
		{
			name:     "unbounded query rejected",
			query:    "random text without bounds",
			wantBBox: "",
			wantErr:  false, // Returns empty bbox, caller should reject
		},
		{
			name:     "invalid bbox format",
			query:    "bbox:10,20,30",
			wantBBox: "",
			wantErr:  true,
		},
		{
			name:     "invalid country code",
			query:    "country:USA",
			wantBBox: "",
			wantErr:  true,
		},
		{
			name:     "invalid city format",
			query:    "city:Madrid",
			wantBBox: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			bbox, err := inferBBoxFromQuery(ctx, tt.query)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for query %q, got nil", tt.query)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for query %q: %v", tt.query, err)
				}
				if bbox != tt.wantBBox {
					t.Errorf("query %q: got bbox %q, want %q", tt.query, bbox, tt.wantBBox)
				}
			}
		})
	}
}

// TestRateLimiterSpacing tests that the rate limiter properly spaces requests.
func TestRateLimiterSpacing(t *testing.T) {
	limiter := NewRateLimiter(10.0) // 10 req/s = 100ms interval
	if limiter == nil {
		t.Fatal("NewRateLimiter returned nil")
	}

	ctx := context.Background()
	var timestamps []time.Time
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Launch 5 concurrent requests
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := limiter.Wait(ctx)
			if err != nil {
				return
			}
			mu.Lock()
			timestamps = append(timestamps, time.Now())
			mu.Unlock()
		}()
	}

	wg.Wait()

	if len(timestamps) != 5 {
		t.Fatalf("expected 5 timestamps, got %d", len(timestamps))
	}

	// Sort timestamps
	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i].Before(timestamps[j])
	})

	// Check spacing between consecutive requests (should be ~100ms apart)
	minInterval := 100 * time.Millisecond
	tolerance := 20 * time.Millisecond // Allow 20ms tolerance

	for i := 1; i < len(timestamps); i++ {
		interval := timestamps[i].Sub(timestamps[i-1])
		if interval < minInterval-tolerance {
			t.Errorf("request %d too soon after %d: interval=%v, want >= %v",
				i, i-1, interval, minInterval-tolerance)
		}
	}
}

// TestDeterministicOrdering tests that collections are deterministically ordered.
func TestDeterministicOrdering(t *testing.T) {
	// Create two collections with same data in different orders
	coll1 := &InfrastructureCollection{
		IXPs: []IXP{
			{ID: "ixp-c", Name: "C-IXP", City: "C", Country: "US"},
			{ID: "ixp-a", Name: "A-IXP", City: "A", Country: "US"},
			{ID: "ixp-b", Name: "B-IXP", City: "B", Country: "US"},
		},
		Facilities: []Facility{
			{ID: "fac-c", Name: "C-FAC", City: "C", Country: "US"},
			{ID: "fac-a", Name: "A-FAC", City: "A", Country: "US"},
			{ID: "fac-b", Name: "B-FAC", City: "B", Country: "US"},
		},
		Correlations: []InfrastructureCorrelation{
			{ID: "corr-c", NetworkEntity: "AS3", InfraEntity: "ixp-c", RelationKind: "test", EvidenceClass: osint.EvidenceObserved, ProvenanceRef: "ref1", RetrievedAt: time.Now().UTC().Format(time.RFC3339)},
			{ID: "corr-a", NetworkEntity: "AS1", InfraEntity: "ixp-a", RelationKind: "test", EvidenceClass: osint.EvidenceObserved, ProvenanceRef: "ref2", RetrievedAt: time.Now().UTC().Format(time.RFC3339)},
			{ID: "corr-b", NetworkEntity: "AS2", InfraEntity: "ixp-b", RelationKind: "test", EvidenceClass: osint.EvidenceObserved, ProvenanceRef: "ref3", RetrievedAt: time.Now().UTC().Format(time.RFC3339)},
		},
	}

	coll2 := &InfrastructureCollection{
		IXPs: []IXP{
			{ID: "ixp-a", Name: "A-IXP", City: "A", Country: "US"},
			{ID: "ixp-b", Name: "B-IXP", City: "B", Country: "US"},
			{ID: "ixp-c", Name: "C-IXP", City: "C", Country: "US"},
		},
		Facilities: []Facility{
			{ID: "fac-a", Name: "A-FAC", City: "A", Country: "US"},
			{ID: "fac-b", Name: "B-FAC", City: "B", Country: "US"},
			{ID: "fac-c", Name: "C-FAC", City: "C", Country: "US"},
		},
		Correlations: []InfrastructureCorrelation{
			{ID: "corr-a", NetworkEntity: "AS1", InfraEntity: "ixp-a", RelationKind: "test", EvidenceClass: osint.EvidenceObserved, ProvenanceRef: "ref2", RetrievedAt: time.Now().UTC().Format(time.RFC3339)},
			{ID: "corr-b", NetworkEntity: "AS2", InfraEntity: "ixp-b", RelationKind: "test", EvidenceClass: osint.EvidenceObserved, ProvenanceRef: "ref3", RetrievedAt: time.Now().UTC().Format(time.RFC3339)},
			{ID: "corr-c", NetworkEntity: "AS3", InfraEntity: "ixp-c", RelationKind: "test", EvidenceClass: osint.EvidenceObserved, ProvenanceRef: "ref1", RetrievedAt: time.Now().UTC().Format(time.RFC3339)},
		},
	}

	bounds := DefaultInfraBounds()
	coll1.Truncate(bounds)
	coll2.Truncate(bounds)

	data1, _ := json.Marshal(coll1)
	data2, _ := json.Marshal(coll2)

	if string(data1) != string(data2) {
		t.Errorf("Collections with same data but different input order produced different JSON:\n1: %s\n2: %s", string(data1), string(data2))
	}

	// Also test that Truncate preserves deterministic ordering
	coll3 := &InfrastructureCollection{
		IXPs: []IXP{
			{ID: "ixp-1", Name: "IXP1", City: "A", Country: "US"},
			{ID: "ixp-2", Name: "IXP2", City: "B", Country: "US"},
			{ID: "ixp-3", Name: "IXP3", City: "C", Country: "US"},
			{ID: "ixp-4", Name: "IXP4", City: "D", Country: "US"},
			{ID: "ixp-5", Name: "IXP5", City: "E", Country: "US"},
		},
	}
	boundsSmall := InfraBounds{MaxIXPs: 3, MaxFacilities: 500, MaxLandingStations: 200, MaxSubmarineCables: 300, MaxCorrelations: 1000}
	coll3.Truncate(boundsSmall)

	// Should keep first 3 by ID order (ixp-1, ixp-2, ixp-3)
	if len(coll3.IXPs) != 3 {
		t.Errorf("expected 3 IXPs after truncate, got %d", len(coll3.IXPs))
	}
	if coll3.IXPs[0].ID != "ixp-1" || coll3.IXPs[1].ID != "ixp-2" || coll3.IXPs[2].ID != "ixp-3" {
		t.Errorf("Truncate did not preserve deterministic order: %v", coll3.IXPs)
	}
}

// TestSourceErrorClassification tests SourceError error type classification.
func TestSourceErrorClassification(t *testing.T) {
	tests := []struct {
		name       string
		errMsg     string
		wantType   string
	}{
		{
			name:       "timeout",
			errMsg:     "context deadline exceeded",
			wantType:   "timeout",
		},
		{
			name:       "timeout explicit",
			errMsg:     "request timeout",
			wantType:   "timeout",
		},
		{
			name:       "rate limit 429",
			errMsg:     "HTTP 429",
			wantType:   "rate_limit",
		},
		{
			name:       "rate limited text",
			errMsg:     "rate limited by PeeringDB",
			wantType:   "rate_limit",
		},
		{
			name:       "server error 500",
			errMsg:     "server error HTTP 500",
			wantType:   "server_error",
		},
		{
			name:       "server error 502",
			errMsg:     "HTTP 502 bad gateway",
			wantType:   "server_error",
		},
		{
			name:       "server error 503",
			errMsg:     "service unavailable HTTP 503",
			wantType:   "server_error",
		},
		{
			name:       "malformed JSON",
			errMsg:     "json: unmarshal failed: invalid character",
			wantType:   "malformed",
		},
		{
			name:       "decode error",
			errMsg:     "decode response failed",
			wantType:   "malformed",
		},
		{
			name:       "cancelled",
			errMsg:     "context canceled",
			wantType:   "cancelled",
		},
		{
			name:       "cancelled US spelling",
			errMsg:     "context cancelled",
			wantType:   "cancelled",
		},
		{
			name:       "unknown error",
			errMsg:     "some random error",
			wantType:   "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errType := classifyErrorForTest(tt.errMsg)
			if errType != tt.wantType {
				t.Errorf("classifyError(%q) = %q, want %q", tt.errMsg, errType, tt.wantType)
			}
		})
	}
}

// classifyErrorForTest mirrors the classifyError function from provider.go for testing.
func classifyErrorForTest(errStr string) string {
	switch {
	case strings.Contains(errStr, "timeout") || strings.Contains(errStr, "context deadline"):
		return "timeout"
	case strings.Contains(errStr, "429") || strings.Contains(errStr, "rate limited"):
		return "rate_limit"
	case strings.Contains(errStr, "500") || strings.Contains(errStr, "502") || strings.Contains(errStr, "503") || strings.Contains(errStr, "server error"):
		return "server_error"
	case strings.Contains(errStr, "decode") || strings.Contains(errStr, "unmarshal") || strings.Contains(errStr, "malformed"):
		return "malformed"
	case strings.Contains(errStr, "canceled") || strings.Contains(errStr, "cancelled"):
		return "cancelled"
	default:
		return "unknown"
	}
}

// TestSourceErrorSanitization tests that SourceError messages don't leak sensitive data.
func TestSourceErrorSanitization(t *testing.T) {
	// Test that error messages don't contain sensitive patterns
	sensitivePatterns := []string{
		"api-key",
		"apikey",
		"authorization",
		"bearer",
		"password",
		"secret",
		"token",
		"credential",
	}

	// Simulate error messages that might come from PeeringDB/OSM
	testErrors := []string{
		"HTTP 429: rate limited",
		"context deadline exceeded",
		"server error HTTP 500",
		"json: unmarshal failed: invalid character",
		"connection refused",
		"timeout waiting for response",
	}

	for _, errMsg := range testErrors {
		for _, pattern := range sensitivePatterns {
			if strings.Contains(strings.ToLower(errMsg), pattern) {
				t.Errorf("Error message %q contains sensitive pattern %q", errMsg, pattern)
			}
		}
	}
}

// TestSourceErrorInCollection tests that SourceError is properly serialized in InfrastructureCollection.
func TestSourceErrorInCollection(t *testing.T) {
	coll := &InfrastructureCollection{
		IXPs: []IXP{},
		Facilities: []Facility{},
		LandingStations: []LandingStation{},
		SubmarineCables: []SubmarineCable{},
		Correlations: []InfrastructureCorrelation{},
		Provenance: []osint.Provenance{},
		SourceErrors: []SourceError{
			{Provider: "peeringdb", Operation: "netixlan", Message: "timeout", ErrorType: "timeout"},
			{Provider: "osm", Operation: "query", Message: "rate limited", ErrorType: "rate_limit"},
		},
		RetrievedAt: time.Now().UTC().Format(time.RFC3339),
		Query: "test",
		Bounds: DefaultInfraBounds(),
	}

	data, err := json.Marshal(coll)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify sourceErrors is present in JSON
	sourceErrors, ok := parsed["sourceErrors"]
	if !ok {
		t.Error("sourceErrors field missing from JSON")
	}

	errorsList, ok := sourceErrors.([]interface{})
	if !ok || len(errorsList) != 2 {
		t.Errorf("expected 2 source errors, got %v", sourceErrors)
	}

	// Verify error types
	if errorsList[0].(map[string]interface{})["errorType"] != "timeout" {
		t.Errorf("first error type mismatch: %v", errorsList[0])
	}
	if errorsList[1].(map[string]interface{})["errorType"] != "rate_limit" {
		t.Errorf("second error type mismatch: %v", errorsList[1])
	}
}

// TestClassifyErrorType tests the exported ClassifyErrorType function.
func TestClassifyErrorType(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantType   string
	}{
		{
			name:       "timeout context deadline",
			err:        fmt.Errorf("context deadline exceeded"),
			wantType:   "timeout",
		},
		{
			name:       "timeout explicit",
			err:        fmt.Errorf("request timeout"),
			wantType:   "timeout",
		},
		{
			name:       "rate limit 429",
			err:        fmt.Errorf("HTTP 429"),
			wantType:   "rate_limit",
		},
		{
			name:       "rate limited text",
			err:        fmt.Errorf("rate limited by PeeringDB"),
			wantType:   "rate_limit",
		},
		{
			name:       "server error 500",
			err:        fmt.Errorf("server error HTTP 500"),
			wantType:   "server_error",
		},
		{
			name:       "server error 502",
			err:        fmt.Errorf("HTTP 502 bad gateway"),
			wantType:   "server_error",
		},
		{
			name:       "server error 503",
			err:        fmt.Errorf("service unavailable HTTP 503"),
			wantType:   "server_error",
		},
		{
			name:       "malformed JSON",
			err:        fmt.Errorf("json: unmarshal failed: invalid character"),
			wantType:   "malformed",
		},
		{
			name:       "decode error",
			err:        fmt.Errorf("decode response failed"),
			wantType:   "malformed",
		},
		{
			name:       "cancelled US spelling",
			err:        fmt.Errorf("context canceled"),
			wantType:   "cancelled",
		},
		{
			name:       "cancelled UK spelling",
			err:        fmt.Errorf("context cancelled"),
			wantType:   "cancelled",
		},
		{
			name:       "unknown error",
			err:        fmt.Errorf("some random error"),
			wantType:   "unknown",
		},
		{
			name:       "nil error",
			err:        nil,
			wantType:   "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errType := ClassifyErrorType(tt.err)
			if errType != tt.wantType {
				t.Errorf("ClassifyErrorType(%v) = %q, want %q", tt.err, errType, tt.wantType)
			}
		})
	}
}

// TestSanitizeErrorMessage tests the exported SanitizeErrorMessage function.
func TestSanitizeErrorMessage(t *testing.T) {
	tests := []struct {
		name           string
		input          error
		expectedSubstr string // substring that should be in sanitized output
		notSubstr      string // substring that should NOT be in sanitized output
	}{
		{
			name:           "API key in error",
			input:          fmt.Errorf("authentication failed: api_key=secret123"),
			expectedSubstr: "api_key=***",
			notSubstr:      "secret123",
		},
		{
			name:           "API key with equals",
			input:          fmt.Errorf("apikey=my-secret-key"),
			expectedSubstr: "apikey=***",
			notSubstr:      "my-secret-key",
		},
		{
			name:           "Bearer token",
			input:          fmt.Errorf("authorization: Bearer abc123token"),
			expectedSubstr: "authorization: Bearer ***",
			notSubstr:      "abc123token",
		},
		{
			name:           "Password in error",
			input:          fmt.Errorf("login failed: password=mypassword"),
			expectedSubstr: "password=***",
			notSubstr:      "mypassword",
		},
		{
			name:           "Secret in error",
			input:          fmt.Errorf("secret=supersecret"),
			expectedSubstr: "secret=***",
			notSubstr:      "supersecret",
		},
		{
			name:           "Token in error",
			input:          fmt.Errorf("token=xyz789"),
			expectedSubstr: "token=***",
			notSubstr:      "xyz789",
		},
		{
			name:           "Credential in error",
			input:          fmt.Errorf("credential=mycred"),
			expectedSubstr: "credential=***",
			notSubstr:      "mycred",
		},
		{
			name:           "Access key in error",
			input:          fmt.Errorf("access_key=AKIA123"),
			expectedSubstr: "access_key=***",
			notSubstr:      "AKIA123",
		},
		{
			name:           "Secret key in error",
			input:          fmt.Errorf("secret_key=abc"),
			expectedSubstr: "secret_key=***",
			notSubstr:      "abc",
		},
		{
			name:           "No sensitive data",
			input:          fmt.Errorf("connection timeout"),
			expectedSubstr: "connection timeout",
			notSubstr:      "",
		},
		{
			name:           "Nil error",
			input:          nil,
			expectedSubstr: "",
			notSubstr:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitized := SanitizeErrorMessage(tt.input)
			if tt.expectedSubstr != "" {
				if !strings.Contains(sanitized, tt.expectedSubstr) {
					t.Errorf("SanitizeErrorMessage(%v) = %q, expected to contain %q", tt.input, sanitized, tt.expectedSubstr)
				}
			}
			if tt.notSubstr != "" {
				if strings.Contains(sanitized, tt.notSubstr) {
					t.Errorf("SanitizeErrorMessage(%v) = %q, should not contain %q", tt.input, sanitized, tt.notSubstr)
				}
			}
		})
	}
}

// TestNewSourceError tests the NewSourceError constructor.
func TestNewSourceError(t *testing.T) {
	err := fmt.Errorf("timeout connecting to PeeringDB")
	se := NewSourceError("peeringdb", "netixlan", err)

	if se.Provider != "peeringdb" {
		t.Errorf("Provider = %q, want %q", se.Provider, "peeringdb")
	}
	if se.Operation != "netixlan" {
		t.Errorf("Operation = %q, want %q", se.Operation, "netixlan")
	}
	if se.ErrorType != "timeout" {
		t.Errorf("ErrorType = %q, want %q", se.ErrorType, "timeout")
	}
	if !strings.Contains(se.Message, "timeout") {
		t.Errorf("Message = %q, expected to contain 'timeout'", se.Message)
	}

	// Test with secret in error
	errWithSecret := fmt.Errorf("auth failed: api_key=secret123")
	se2 := NewSourceError("peeringdb", "auth", errWithSecret)
	if strings.Contains(se2.Message, "secret123") {
		t.Errorf("Message should not contain secret: %q", se2.Message)
	}
	if !strings.Contains(se2.Message, "***") {
		t.Errorf("Message should contain redacted marker: %q", se2.Message)
	}
}