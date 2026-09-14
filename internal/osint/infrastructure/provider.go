// Package infrastructure provides the infrastructure intelligence provider.
package infrastructure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"trazip/internal/intel/external"
	"trazip/internal/osint"
)

// InfraProvider implements the passive infrastructure intelligence provider.
type InfraProvider struct {
	*osint.BaseProvider
	osmClient *OSMClient
	pdbClient *PeeringDBClient
}

// InfraProviderConfig configures the infrastructure provider.
type InfraProviderConfig struct {
	OSM      OSMConfig
	PeeringDB PeeringDBConfig
	Enabled  bool // whether to enable this provider
}

// NewInfraProvider creates a new infrastructure intelligence provider.
func NewInfraProvider(cfg InfraProviderConfig) (*InfraProvider, error) {
	if !cfg.Enabled {
		return nil, nil // Provider disabled
	}

	osmClient := NewOSMClient(cfg.OSM)
	pdbClient := NewPeeringDBClient(cfg.PeeringDB)

	meta := osint.ProviderMeta{
		ID:              "infra.intelligence",
		Name:            "Internet Infrastructure Intelligence",
		Capabilities: []osint.Capability{
			osint.CapabilityIXP,
			osint.CapabilityFacility,
			osint.CapabilityLandingStation,
			osint.CapabilitySubmarineCable,
			osint.CapabilityInfrastructure,
		},
		ActivityClass:   osint.ActivityPassive,
		DisclosureClass: osint.DisclosurePassive,
		RequiresScope:   false,
		RateLimit:       "OSM: 1 req/s; PeeringDB: 0.5 req/s (per AUP)",
	}

	p := &InfraProvider{
		BaseProvider: &osint.BaseProvider{MetaVal: meta},
		osmClient:    osmClient,
		pdbClient:    pdbClient,
	}
	return p, nil
}

// Lookup implements osint.PassiveRunner for infrastructure intelligence.
// Supports capabilities: ixp, facility, landing_station, submarine_cable, infrastructure.
func (p *InfraProvider) Lookup(ctx context.Context, capability osint.Capability, input any) osint.Result {
	// Base provenance for this lookup
	baseProv := ProvenanceFor(p.MetaVal, capability, "infra-lookup")

	switch capability {
	case osint.CapabilityIXP:
		return p.lookupIXP(ctx, input, baseProv)
	case osint.CapabilityFacility:
		return p.lookupFacility(ctx, input, baseProv)
	case osint.CapabilityLandingStation:
		return p.lookupLandingStation(ctx, input, baseProv)
	case osint.CapabilitySubmarineCable:
		return p.lookupSubmarineCable(ctx, input, baseProv)
	case osint.CapabilityInfrastructure:
		return p.lookupInfrastructure(ctx, input, baseProv)
	default:
		return osint.Result{
			Err: &osint.UnsupportedCapabilityError{Provider: p.MetaVal.ID, Capability: capability},
		}
	}
}

// lookupIXP searches for IXPs by name, city, country, or ASN presence.
func (p *InfraProvider) lookupIXP(ctx context.Context, input any, baseProv osint.Provenance) osint.Result {
	query, ok := input.(string)
	if !ok {
		return osint.Result{Err: fmt.Errorf("ixp lookup: input must be string query")}
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return osint.Result{Err: fmt.Errorf("ixp lookup: empty query")}
	}

	coll := &InfrastructureCollection{}

	// Try PeeringDB first if query looks like an ID
	if id := parseID(query); id > 0 {
		ixp, err := p.pdbClient.GetIXP(ctx, id)
		if err != nil {
			return osint.Result{Err: fmt.Errorf("peeringdb ixp lookup: %w", err)}
		}
		prov := ProvenanceFor(p.MetaVal, osint.CapabilityIXP, fmt.Sprintf("peeringdb:ix:%d", id))
		i, err := ConvertPeeringDBIXP(ixp, prov)
		if err != nil {
			return osint.Result{Err: fmt.Errorf("convert peeringdb ixp: %w", err)}
		}
		coll.IXPs = append(coll.IXPs, i)
		coll.Provenance = append(coll.Provenance, prov)
	} else {
		// Search via OSM
		bbox := inferBBoxFromQuery(query)
		resp, err := p.osmClient.QueryOSM(ctx, IXPQuery(bbox))
		if err != nil {
			return osint.Result{Err: fmt.Errorf("osm ixp query: %w", err)}
		}
		for _, elem := range resp.Elements {
			ixp, err := ParseIXP(elem, ProvenanceFor(p.MetaVal, osint.CapabilityIXP, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
			if err != nil {
				continue // Skip invalid elements
			}
			if matchesQuery(ixp.Name, ixp.City, ixp.Country, query) {
				coll.IXPs = append(coll.IXPs, ixp)
				coll.Provenance = append(coll.Provenance, ProvenanceFor(p.MetaVal, osint.CapabilityIXP, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
			}
		}
	}

	coll.EnsureNonNil()
	coll.Truncate(DefaultInfraBounds())
	coll.Query = query
	coll.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

	return osint.Result{
		Data:       coll,
		Provenance: ProvenanceFor(p.MetaVal, osint.CapabilityIXP, "infra-lookup:ixp"),
	}
}

// lookupFacility searches for facilities by name, city, country, or CLLI.
func (p *InfraProvider) lookupFacility(ctx context.Context, input any, prov osint.Provenance) osint.Result {
	query, ok := input.(string)
	if !ok {
		return osint.Result{Err: fmt.Errorf("facility lookup: input must be string query")}
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return osint.Result{Err: fmt.Errorf("facility lookup: empty query")}
	}

	coll := &InfrastructureCollection{}
	prov.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

	// Try PeeringDB first
	if id := parseID(query); id > 0 {
		if fac, err := p.pdbClient.GetFacility(ctx, id); err == nil {
			if f, err := ConvertPeeringDBFacility(fac, prov); err == nil {
				coll.Facilities = append(coll.Facilities, f)
				coll.Provenance = append(coll.Provenance, prov)
			}
		}
	} else {
		if bbox := inferBBoxFromQuery(query); bbox != "" {
			if resp, err := p.osmClient.QueryOSM(ctx, FacilityQuery(bbox)); err == nil {
				for _, elem := range resp.Elements {
					if fac, err := ParseFacility(elem, prov); err == nil {
						if matchesQuery(fac.Name, fac.City, fac.Country, query) {
							coll.Facilities = append(coll.Facilities, fac)
							coll.Provenance = append(coll.Provenance, prov)
						}
					}
				}
			}
		}
	}

	coll.EnsureNonNil()
	coll.Truncate(DefaultInfraBounds())
	coll.Query = query
	coll.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

	return osint.Result{
		Data:       coll,
		Provenance: prov,
	}
}

// lookupLandingStation searches for cable landing stations by name, city, or country.
func (p *InfraProvider) lookupLandingStation(ctx context.Context, input any, prov osint.Provenance) osint.Result {
	query, ok := input.(string)
	if !ok {
		return osint.Result{Err: fmt.Errorf("landing_station lookup: input must be string query")}
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return osint.Result{Err: fmt.Errorf("landing_station lookup: empty query")}
	}

	coll := &InfrastructureCollection{}
	prov.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

	if bbox := inferBBoxFromQuery(query); bbox != "" {
		if resp, err := p.osmClient.QueryOSM(ctx, CableLandingStationQuery(bbox)); err == nil {
			for _, elem := range resp.Elements {
				if ls, err := ParseCableLandingStation(elem, prov); err == nil {
					if matchesQuery(ls.Name, ls.City, ls.Country, query) {
						coll.LandingStations = append(coll.LandingStations, ls)
						coll.Provenance = append(coll.Provenance, prov)
					}
				}
			}
		}
	}

	coll.EnsureNonNil()
	coll.Truncate(DefaultInfraBounds())
	coll.Query = query
	coll.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

	return osint.Result{
		Data:       coll,
		Provenance: prov,
	}
}

// lookupSubmarineCable searches for submarine cables by name or landing point.
func (p *InfraProvider) lookupSubmarineCable(ctx context.Context, input any, prov osint.Provenance) osint.Result {
	query, ok := input.(string)
	if !ok {
		return osint.Result{Err: fmt.Errorf("submarine_cable lookup: input must be string query")}
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return osint.Result{Err: fmt.Errorf("submarine_cable lookup: empty query")}
	}

	coll := &InfrastructureCollection{}
	prov.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

	// Global query for submarine cables (no bbox filtering for global cables)
	// Use a wide bbox covering oceans
	if resp, err := p.osmClient.QueryOSM(ctx, SubmarineCableQuery("-90,-180,90,180")); err == nil {
		for _, elem := range resp.Elements {
			if cable, err := ParseSubmarineCable(elem, prov); err == nil {
				if matchesQuery(cable.Name, "", "", query) {
					coll.SubmarineCables = append(coll.SubmarineCables, cable)
					coll.Provenance = append(coll.Provenance, prov)
				}
			}
		}
	}

	coll.EnsureNonNil()
	coll.Truncate(DefaultInfraBounds())
	coll.Query = query
	coll.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

	return osint.Result{
		Data:       coll,
		Provenance: prov,
	}
}

// lookupInfrastructure performs a comprehensive infrastructure lookup.
// Returns IXPs, facilities, landing stations, submarine cables, and correlations.
func (p *InfraProvider) lookupInfrastructure(ctx context.Context, input any, prov osint.Provenance) osint.Result {
	query, ok := input.(string)
	if !ok {
		return osint.Result{Err: fmt.Errorf("infrastructure lookup: input must be string query")}
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return osint.Result{Err: fmt.Errorf("infrastructure lookup: empty query")}
	}

	coll := &InfrastructureCollection{}
	prov.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

	// Try to infer what the query is about and search accordingly
	// For comprehensive search, we do multiple targeted searches
	bbox := inferBBoxFromQuery(query)

	// Search IXPs
	if resp, err := p.osmClient.QueryOSM(ctx, IXPQuery(bbox)); err == nil {
		for _, elem := range resp.Elements {
			if ixp, err := ParseIXP(elem, prov); err == nil {
				if matchesQuery(ixp.Name, ixp.City, ixp.Country, query) {
					coll.IXPs = append(coll.IXPs, ixp)
					coll.Provenance = append(coll.Provenance, prov)
				}
			}
		}
	}

	// Search facilities
	if resp, err := p.osmClient.QueryOSM(ctx, FacilityQuery(bbox)); err == nil {
		for _, elem := range resp.Elements {
			if fac, err := ParseFacility(elem, prov); err == nil {
				if matchesQuery(fac.Name, fac.City, fac.Country, query) {
					coll.Facilities = append(coll.Facilities, fac)
					coll.Provenance = append(coll.Provenance, prov)
				}
			}
		}
	}

	// Search landing stations
	if resp, err := p.osmClient.QueryOSM(ctx, CableLandingStationQuery(bbox)); err == nil {
		for _, elem := range resp.Elements {
			if ls, err := ParseCableLandingStation(elem, prov); err == nil {
				if matchesQuery(ls.Name, ls.City, ls.Country, query) {
					coll.LandingStations = append(coll.LandingStations, ls)
					coll.Provenance = append(coll.Provenance, prov)
				}
			}
		}
	}

	// Search submarine cables (global)
	if resp, err := p.osmClient.QueryOSM(ctx, SubmarineCableQuery("-90,-180,90,180")); err == nil {
		for _, elem := range resp.Elements {
			if cable, err := ParseSubmarineCable(elem, prov); err == nil {
				if matchesQuery(cable.Name, "", "", query) {
					coll.SubmarineCables = append(coll.SubmarineCables, cable)
					coll.Provenance = append(coll.Provenance, prov)
				}
			}
		}
	}

	// Build correlations if we have both network entities and infrastructure
	// This is a placeholder - real correlation would need ASN/Prefix data
	// For now, we just return the infrastructure entities

	coll.EnsureNonNil()
	coll.Truncate(DefaultInfraBounds())
	coll.Query = "infrastructure:" + query
	coll.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

	return osint.Result{
		Data:       coll,
		Provenance: prov,
	}
}

// ProvenanceFor generates provenance for a capability lookup.
func ProvenanceFor(meta osint.ProviderMeta, cap osint.Capability, endpoint string) osint.Provenance {
	return osint.Provenance{
		ProviderID:      meta.ID,
		ProviderName:    meta.Name,
		Capability:      string(cap),
		ActivityClass:   meta.ActivityClass,
		DisclosureClass: meta.DisclosureClass,
		RetrievedAt:     time.Now().UTC().Format(time.RFC3339),
		Endpoint:        endpoint,
		Confidence:      "alta",
		Disclosure: external.Disclosure{
			Source:      meta.Name,
			QueriedAt:   time.Now().UTC().Format(time.RFC3339),
			DataSent:    endpoint,
			CachePolicy: "memory (TTL)",
			Confidence:  "alta",
			RateLimit:   "OSM: 1 req/s; PeeringDB: 0.5 req/s",
		},
	}
}

// Helper functions

func parseID(s string) int {
	var id int
	fmt.Sscanf(s, "%d", &id)
	return id
}

func matchesQuery(name, city, country, query string) bool {
	q := strings.ToLower(query)
	if q == "" {
		return true
	}
	haystack := strings.ToLower(name + " " + city + " " + country)
	return strings.Contains(haystack, q)
}

func inferBBoxFromQuery(query string) string {
	// Try to infer a bounding box from the query
	// For now, return empty string to use global search
	// In a real implementation, this would geocode the query
	return ""
}