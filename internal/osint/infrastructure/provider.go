// Package infrastructure provides the infrastructure intelligence provider.
package infrastructure

import (
	"context"
	"fmt"
	"sort"
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

// QueryType identifies the type of query for semantic matching.
type QueryType int

const (
	QueryTypeUnknown QueryType = iota
	QueryTypeBBox       // bbox:s,w,n,e - no textual filtering after spatial query
	QueryTypeCountry    // country:XX - filter by country code exactly
	QueryTypeCity       // city:Name,CC - filter by city AND country exactly
	QueryTypeASN        // asn:NUMBER - handled by PeeringDB directly
	QueryTypePeeringDB  // peeringdb:TYPE:ID - direct provider lookup
	QueryTypeOSM        // osm:TYPE/ID - direct OSM lookup
)

// QuerySpec holds the parsed query specification for semantic matching.
type QuerySpec struct {
	Type       QueryType
	Country    string // ISO alpha-2 for country/city queries
	City       string // City name for city queries
	RawQuery   string // Original query string
}

func (q QuerySpec) IsCountryQuery() bool { return q.Type == QueryTypeCountry }
func (q QuerySpec) IsCityQuery() bool    { return q.Type == QueryTypeCity }
func (q QuerySpec) IsBBoxQuery() bool    { return q.Type == QueryTypeBBox }

// InfraProviderConfig configures the infrastructure provider.
type InfraProviderConfig struct {
	OSM       OSMConfig
	PeeringDB PeeringDBConfig
	Enabled   bool // whether to enable this provider
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
		RateLimit:       "OSM: 1 req/s (TRAZIP conservative); PeeringDB: 0.5 req/s (TRAZIP conservative)",
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

	// Check for peeringdb:ix:NUMBER format - direct PeeringDB IXP lookup
	if pdbType, id, ok := parsePeeringDBQuery(query); ok && pdbType == "ix" {
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
	} else if osmType, osmID, ok := parseOSMQuery(query); ok && (osmType == "node" || osmType == "way" || osmType == "relation") {
		// Direct OSM element lookup - use specific element query, not bbox with id filter
		prov := ProvenanceFor(p.MetaVal, osint.CapabilityIXP, fmt.Sprintf("osm:%s/%d", osmType, osmID))
		resp, err := p.osmClient.QueryOSM(ctx, OSMElementQuery(osmType, osmID))
		if err != nil {
			return osint.Result{Err: fmt.Errorf("osm ixp direct lookup: %w", err)}
		}
		for _, elem := range resp.Elements {
			if elem.Type == osmType && elem.ID == osmID {
				ixp, err := ParseIXP(elem, ProvenanceFor(p.MetaVal, osint.CapabilityIXP, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
				if err != nil {
					continue
				}
				coll.IXPs = append(coll.IXPs, ixp)
				coll.Provenance = append(coll.Provenance, prov)
				break
			}
		}
	} else if id := parseID(query); id > 0 {
		// Try PeeringDB first if query looks like an ID
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
		// Search via OSM with bounded query
		bbox, spec, err := inferBBoxFromQuery(ctx, query)
		if err != nil {
			return osint.Result{Err: fmt.Errorf("bbox inference failed: %w", err)}
		}
		if bbox == "" {
			return osint.Result{Err: fmt.Errorf("ixp lookup: query requires explicit location context (country, city, or bbox)")}
		}
		resp, err := p.osmClient.QueryOSM(ctx, IXPQuery(bbox))
		if err != nil {
			return osint.Result{Err: fmt.Errorf("osm ixp query: %w", err)}
		}
		for _, elem := range resp.Elements {
			ixp, err := ParseIXP(elem, ProvenanceFor(p.MetaVal, osint.CapabilityIXP, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
			if err != nil {
				continue // Skip invalid elements
			}
			if matchesQuerySemantic(ixp.Name, ixp.City, ixp.Country, spec) {
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
func (p *InfraProvider) lookupFacility(ctx context.Context, input any, baseProv osint.Provenance) osint.Result {
	query, ok := input.(string)
	if !ok {
		return osint.Result{Err: fmt.Errorf("facility lookup: input must be string query")}
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return osint.Result{Err: fmt.Errorf("facility lookup: empty query")}
	}

	coll := &InfrastructureCollection{}

	// Check for peeringdb:fac:NUMBER format - direct PeeringDB facility lookup
	if pdbType, id, ok := parsePeeringDBQuery(query); ok && pdbType == "fac" {
		fac, err := p.pdbClient.GetFacility(ctx, id)
		if err != nil {
			return osint.Result{Err: fmt.Errorf("peeringdb facility lookup: %w", err)}
		}
		prov := ProvenanceFor(p.MetaVal, osint.CapabilityFacility, fmt.Sprintf("peeringdb:fac:%d", id))
		f, err := ConvertPeeringDBFacility(fac, prov)
		if err != nil {
			return osint.Result{Err: fmt.Errorf("convert peeringdb facility: %w", err)}
		}
		coll.Facilities = append(coll.Facilities, f)
		coll.Provenance = append(coll.Provenance, prov)
	} else if osmType, osmID, ok := parseOSMQuery(query); ok && (osmType == "node" || osmType == "way" || osmType == "relation") {
		// Direct OSM element lookup - use specific element query, not bbox with id filter
		prov := ProvenanceFor(p.MetaVal, osint.CapabilityFacility, fmt.Sprintf("osm:%s/%d", osmType, osmID))
		resp, err := p.osmClient.QueryOSM(ctx, OSMElementQuery(osmType, osmID))
		if err != nil {
			return osint.Result{Err: fmt.Errorf("osm facility direct lookup: %w", err)}
		}
		for _, elem := range resp.Elements {
			if elem.Type == osmType && elem.ID == osmID {
				fac, err := ParseFacility(elem, ProvenanceFor(p.MetaVal, osint.CapabilityFacility, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
				if err != nil {
					continue
				}
				coll.Facilities = append(coll.Facilities, fac)
				coll.Provenance = append(coll.Provenance, prov)
				break
			}
		}
	} else if id := parseID(query); id > 0 {
		// Try PeeringDB first if query looks like an ID
		fac, err := p.pdbClient.GetFacility(ctx, id)
		if err != nil {
			return osint.Result{Err: fmt.Errorf("peeringdb facility lookup: %w", err)}
		}
		prov := ProvenanceFor(p.MetaVal, osint.CapabilityFacility, fmt.Sprintf("peeringdb:fac:%d", id))
		f, err := ConvertPeeringDBFacility(fac, prov)
		if err != nil {
			return osint.Result{Err: fmt.Errorf("convert peeringdb facility: %w", err)}
		}
		coll.Facilities = append(coll.Facilities, f)
		coll.Provenance = append(coll.Provenance, prov)
	} else {
		bbox, spec, err := inferBBoxFromQuery(ctx, query)
		if err != nil {
			return osint.Result{Err: fmt.Errorf("bbox inference failed: %w", err)}
		}
		if bbox == "" {
			return osint.Result{Err: fmt.Errorf("facility lookup: query requires explicit location context (country, city, or bbox)")}
		}
		resp, err := p.osmClient.QueryOSM(ctx, FacilityQuery(bbox))
		if err != nil {
			return osint.Result{Err: fmt.Errorf("osm facility query: %w", err)}
		}
		for _, elem := range resp.Elements {
			fac, err := ParseFacility(elem, ProvenanceFor(p.MetaVal, osint.CapabilityFacility, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
			if err != nil {
				continue
			}
			if matchesQuerySemantic(fac.Name, fac.City, fac.Country, spec) {
				coll.Facilities = append(coll.Facilities, fac)
				coll.Provenance = append(coll.Provenance, ProvenanceFor(p.MetaVal, osint.CapabilityFacility, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
			}
		}
	}

	coll.EnsureNonNil()
	coll.Truncate(DefaultInfraBounds())
	coll.Query = query
	coll.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

	return osint.Result{
		Data:       coll,
		Provenance: ProvenanceFor(p.MetaVal, osint.CapabilityFacility, "infra-lookup:facility"),
	}
}

// lookupLandingStation searches for cable landing stations by name, city, or country.
func (p *InfraProvider) lookupLandingStation(ctx context.Context, input any, baseProv osint.Provenance) osint.Result {
	query, ok := input.(string)
	if !ok {
		return osint.Result{Err: fmt.Errorf("landing_station lookup: input must be string query")}
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return osint.Result{Err: fmt.Errorf("landing_station lookup: empty query")}
	}

	coll := &InfrastructureCollection{}

	// Check for osm:TYPE/ID format - direct OSM element lookup
	if osmType, osmID, ok := parseOSMQuery(query); ok && (osmType == "node" || osmType == "way" || osmType == "relation") {
		prov := ProvenanceFor(p.MetaVal, osint.CapabilityLandingStation, fmt.Sprintf("osm:%s/%d", osmType, osmID))
		resp, err := p.osmClient.QueryOSM(ctx, OSMElementQuery(osmType, osmID))
		if err != nil {
			return osint.Result{Err: fmt.Errorf("osm landing_station direct lookup: %w", err)}
		}
		for _, elem := range resp.Elements {
			if elem.Type == osmType && elem.ID == osmID {
				ls, err := ParseCableLandingStation(elem, ProvenanceFor(p.MetaVal, osint.CapabilityLandingStation, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
				if err != nil {
					continue
				}
				coll.LandingStations = append(coll.LandingStations, ls)
				coll.Provenance = append(coll.Provenance, prov)
				break
			}
		}
	} else {
		bbox, spec, err := inferBBoxFromQuery(ctx, query)
		if err != nil {
			return osint.Result{Err: fmt.Errorf("bbox inference failed: %w", err)}
		}
		if bbox == "" {
			return osint.Result{Err: fmt.Errorf("landing_station lookup: query requires explicit location context (country, city, or bbox)")}
		}

		resp, err := p.osmClient.QueryOSM(ctx, CableLandingStationQuery(bbox))
		if err != nil {
			return osint.Result{Err: fmt.Errorf("osm landing_station query: %w", err)}
		}
		for _, elem := range resp.Elements {
			ls, err := ParseCableLandingStation(elem, ProvenanceFor(p.MetaVal, osint.CapabilityLandingStation, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
			if err != nil {
				continue
			}
			if matchesQuerySemantic(ls.Name, ls.City, ls.Country, spec) {
				coll.LandingStations = append(coll.LandingStations, ls)
				coll.Provenance = append(coll.Provenance, ProvenanceFor(p.MetaVal, osint.CapabilityLandingStation, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
			}
		}
	}

	coll.EnsureNonNil()
	coll.Truncate(DefaultInfraBounds())
	coll.Query = query
	coll.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

	return osint.Result{
		Data:       coll,
		Provenance: ProvenanceFor(p.MetaVal, osint.CapabilityLandingStation, "infra-lookup:landing_station"),
	}
}

// lookupSubmarineCable searches for submarine cables by name or landing point.
func (p *InfraProvider) lookupSubmarineCable(ctx context.Context, input any, baseProv osint.Provenance) osint.Result {
	query, ok := input.(string)
	if !ok {
		return osint.Result{Err: fmt.Errorf("submarine_cable lookup: input must be string query")}
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return osint.Result{Err: fmt.Errorf("submarine_cable lookup: empty query")}
	}

	coll := &InfrastructureCollection{}

	// Check for osm:TYPE/ID format - direct OSM element lookup
	if osmType, osmID, ok := parseOSMQuery(query); ok && (osmType == "way" || osmType == "relation") {
		prov := ProvenanceFor(p.MetaVal, osint.CapabilitySubmarineCable, fmt.Sprintf("osm:%s/%d", osmType, osmID))
		resp, err := p.osmClient.QueryOSM(ctx, OSMElementQuery(osmType, osmID))
		if err != nil {
			return osint.Result{Err: fmt.Errorf("osm submarine_cable direct lookup: %w", err)}
		}
		for _, elem := range resp.Elements {
			if elem.Type == osmType && elem.ID == osmID {
				cable, err := ParseSubmarineCable(elem, ProvenanceFor(p.MetaVal, osint.CapabilitySubmarineCable, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
				if err != nil {
					continue
				}
				coll.SubmarineCables = append(coll.SubmarineCables, cable)
				coll.Provenance = append(coll.Provenance, prov)
				break
			}
		}
	} else {
		bbox, spec, err := inferBBoxFromQuery(ctx, query)
		if err != nil {
			return osint.Result{Err: fmt.Errorf("bbox inference failed: %w", err)}
		}
		if bbox == "" {
			return osint.Result{Err: fmt.Errorf("submarine_cable lookup: query requires explicit location context (country, city, or bbox)")}
		}

		resp, err := p.osmClient.QueryOSM(ctx, SubmarineCableQuery(bbox))
		if err != nil {
			return osint.Result{Err: fmt.Errorf("osm submarine_cable query: %w", err)}
		}
		for _, elem := range resp.Elements {
			cable, err := ParseSubmarineCable(elem, ProvenanceFor(p.MetaVal, osint.CapabilitySubmarineCable, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
			if err != nil {
				continue
			}
			// Submarine cables: NO textual filtering by country/bbox - spatial query already did the work
			if spec.Type == QueryTypeUnknown || spec.Type == QueryTypeASN || spec.Type == QueryTypePeeringDB {
				if matchesQuerySemantic(cable.Name, "", "", spec) {
					coll.SubmarineCables = append(coll.SubmarineCables, cable)
					coll.Provenance = append(coll.Provenance, ProvenanceFor(p.MetaVal, osint.CapabilitySubmarineCable, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
				}
			} else {
				// For country/city/bbox queries, spatial query already filtered - accept all
				coll.SubmarineCables = append(coll.SubmarineCables, cable)
				coll.Provenance = append(coll.Provenance, ProvenanceFor(p.MetaVal, osint.CapabilitySubmarineCable, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
			}
		}
	}

	coll.EnsureNonNil()
	coll.Truncate(DefaultInfraBounds())
	coll.Query = query
	coll.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

	return osint.Result{
		Data:       coll,
		Provenance: ProvenanceFor(p.MetaVal, osint.CapabilitySubmarineCable, "infra-lookup:submarine_cable"),
	}
}

// lookupInfrastructure performs a comprehensive infrastructure lookup.
// Returns IXPs, facilities, landing stations, submarine cables, and correlations.
func (p *InfraProvider) lookupInfrastructure(ctx context.Context, input any, baseProv osint.Provenance) osint.Result {
	query, ok := input.(string)
	if !ok {
		return osint.Result{Err: fmt.Errorf("infrastructure lookup: input must be string query")}
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return osint.Result{Err: fmt.Errorf("infrastructure lookup: empty query")}
	}

coll := &InfrastructureCollection{}

	// Handle "asn:NUMBER" queries - direct PeeringDB ASN lookup without bbox
	if asn := parseASN(query); asn > 0 {
		// Query PeeringDB for networks with this ASN (validates ASN exists)
		_, err := p.pdbClient.GetNetwork(ctx, asn)
		if err != nil {
			return osint.Result{Err: fmt.Errorf("peeringdb network lookup: %w", err)}
		}

		// Get IXLANs where this ASN is present (queries /netixlan?asn=...)
		netixlans, err := p.pdbClient.ListNetIXLANsByASN(ctx, asn)
		if err == nil {
			for _, nixlan := range netixlans {
				if nixlan.Operational {
					// Use IXID (ix_id from PeeringDB) to fetch IXP details, not IXLANID
					ixp, err := p.pdbClient.GetIXP(ctx, nixlan.IXID)
					if err == nil {
						ixpProv := ProvenanceFor(p.MetaVal, osint.CapabilityIXP, fmt.Sprintf("peeringdb:ix:%d", ixp.ID))
						ixpConv, err := ConvertPeeringDBIXP(ixp, ixpProv)
						if err == nil {
							coll.IXPs = append(coll.IXPs, ixpConv)
							coll.Provenance = append(coll.Provenance, ixpProv)
						}
					}
				}
			}
		}

		// Get facilities where this ASN is present
		netfacs, err := p.pdbClient.GetNetFacByASN(ctx, asn)
		if err == nil {
			for _, netfac := range netfacs {
				fac, err := p.pdbClient.GetFacility(ctx, netfac.FacID)
				if err == nil {
					facProv := ProvenanceFor(p.MetaVal, osint.CapabilityFacility, fmt.Sprintf("peeringdb:fac:%d", fac.ID))
					facConv, err := ConvertPeeringDBFacility(fac, facProv)
					if err == nil {
						coll.Facilities = append(coll.Facilities, facConv)
						coll.Provenance = append(coll.Provenance, facProv)
					}
				}
			}
		}

		// The correlation engine will use this ASN for ASN->IXP and ASN->Facility correlations
		coll.Query = "infrastructure:" + query
		coll.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

		// Build correlations with explicit evidence (will use the ASN for PeeringDB queries)
		correlations, sourceErrors := p.buildCorrelations(ctx, coll, query)
		coll.Correlations = correlations
		coll.SourceErrors = sourceErrors

		coll.EnsureNonNil()
		p.sortCollections(coll)
		coll.Truncate(DefaultInfraBounds())
		coll.Query = "infrastructure:" + query
		coll.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

		return osint.Result{
			Data:       coll,
			Provenance: ProvenanceFor(p.MetaVal, osint.CapabilityInfrastructure, "infra-lookup:infrastructure"),
		}
	}

	// For comprehensive search, we do multiple targeted searches with bounded queries
	bbox, spec, err := inferBBoxFromQuery(ctx, query)
	if err != nil {
		return osint.Result{Err: fmt.Errorf("bbox inference failed: %w", err)}
	}
	if bbox == "" {
		return osint.Result{Err: fmt.Errorf("infrastructure lookup: query requires explicit location context (country, city, or bbox)")}
	}

	// Search IXPs
	resp, err := p.osmClient.QueryOSM(ctx, IXPQuery(bbox))
	if err != nil {
		return osint.Result{Err: fmt.Errorf("osm ixp query: %w", err)}
	}
	for _, elem := range resp.Elements {
		ixp, err := ParseIXP(elem, ProvenanceFor(p.MetaVal, osint.CapabilityIXP, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
		if err != nil {
			continue
		}
		if matchesQuerySemantic(ixp.Name, ixp.City, ixp.Country, spec) {
			coll.IXPs = append(coll.IXPs, ixp)
			coll.Provenance = append(coll.Provenance, ProvenanceFor(p.MetaVal, osint.CapabilityIXP, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
		}
	}

	// Search facilities
	resp, err = p.osmClient.QueryOSM(ctx, FacilityQuery(bbox))
	if err != nil {
		return osint.Result{Err: fmt.Errorf("osm facility query: %w", err)}
	}
	for _, elem := range resp.Elements {
		fac, err := ParseFacility(elem, ProvenanceFor(p.MetaVal, osint.CapabilityFacility, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
		if err != nil {
			continue
		}
		if matchesQuerySemantic(fac.Name, fac.City, fac.Country, spec) {
			coll.Facilities = append(coll.Facilities, fac)
			coll.Provenance = append(coll.Provenance, ProvenanceFor(p.MetaVal, osint.CapabilityFacility, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
		}
	}

	// Search landing stations
	resp, err = p.osmClient.QueryOSM(ctx, CableLandingStationQuery(bbox))
	if err != nil {
		return osint.Result{Err: fmt.Errorf("osm landing_station query: %w", err)}
	}
	for _, elem := range resp.Elements {
		ls, err := ParseCableLandingStation(elem, ProvenanceFor(p.MetaVal, osint.CapabilityLandingStation, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
		if err != nil {
			continue
		}
		if matchesQuerySemantic(ls.Name, ls.City, ls.Country, spec) {
			coll.LandingStations = append(coll.LandingStations, ls)
			coll.Provenance = append(coll.Provenance, ProvenanceFor(p.MetaVal, osint.CapabilityLandingStation, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
		}
	}

	// Search submarine cables (using same bbox) - NO textual filtering by country/bbox
	resp, err = p.osmClient.QueryOSM(ctx, SubmarineCableQuery(bbox))
	if err != nil {
		return osint.Result{Err: fmt.Errorf("osm submarine_cable query: %w", err)}
	}
	for _, elem := range resp.Elements {
		cable, err := ParseSubmarineCable(elem, ProvenanceFor(p.MetaVal, osint.CapabilitySubmarineCable, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
		if err != nil {
			continue
		}
		// Submarine cables: NO textual filtering by country/bbox - spatial query already did the work
		// Only filter by query if it's a name-based query (not country/city/bbox)
		if spec.Type == QueryTypeUnknown || spec.Type == QueryTypeASN || spec.Type == QueryTypePeeringDB {
			if matchesQuerySemantic(cable.Name, "", "", spec) {
				coll.SubmarineCables = append(coll.SubmarineCables, cable)
				coll.Provenance = append(coll.Provenance, ProvenanceFor(p.MetaVal, osint.CapabilitySubmarineCable, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
			}
		} else {
			// For country/city/bbox queries, spatial query already filtered - accept all
			coll.SubmarineCables = append(coll.SubmarineCables, cable)
			coll.Provenance = append(coll.Provenance, ProvenanceFor(p.MetaVal, osint.CapabilitySubmarineCable, fmt.Sprintf("osm:%s/%d", elem.Type, elem.ID)))
		}
	}

	// Build correlations with explicit evidence
	correlations, sourceErrors := p.buildCorrelations(ctx, coll, query)
	coll.Correlations = correlations
	coll.SourceErrors = sourceErrors

	coll.EnsureNonNil()
	// Sort collections for deterministic ordering before truncation
	p.sortCollections(coll)
	coll.Truncate(DefaultInfraBounds())
	coll.Query = "infrastructure:" + query
	coll.RetrievedAt = time.Now().UTC().Format(time.RFC3339)

	return osint.Result{
		Data:       coll,
		Provenance: ProvenanceFor(p.MetaVal, osint.CapabilityInfrastructure, "infra-lookup:infrastructure"),
	}
}

// buildCorrelations builds explicit correlations from infrastructure entities.
// Only creates correlations with explicit evidence (OBSERVED from PeeringDB, POSSIBLE_CONTEXT from geographic proximity).
// Returns correlations and any source errors encountered during correlation enrichment (fail-visible).
func (p *InfraProvider) buildCorrelations(ctx context.Context, coll *InfrastructureCollection, query string) ([]InfrastructureCorrelation, []SourceError) {
	var correlations []InfrastructureCorrelation
	var sourceErrors []SourceError
retrievedAt := time.Now().UTC().Format(time.RFC3339)

	// ASN -> IXP correlations from PeeringDB netixlan (OBSERVED)
	// For each IXP from PeeringDB, query netixlan for ASNs present
	for _, ixp := range coll.IXPs {
		if ixp.PeeringDBID > 0 {
			netixlans, err := p.pdbClient.ListNetworksAtIXP(ctx, ixp.PeeringDBID)
			if err != nil {
				sourceErrors = append(sourceErrors, NewSourceError("peeringdb", "netixlan", fmt.Errorf("ASN->IXP correlation for IXP %s: %w", ixp.ID, err)))
			} else {
				for _, nixlan := range netixlans {
					if nixlan.Operational {
						prov := ProvenanceFor(p.MetaVal, osint.CapabilityInfrastructure, fmt.Sprintf("peeringdb:netixlan:%d", nixlan.ID))
						corr, err := ConvertPeeringDBNetIXLAN(&nixlan, ixp.ID, prov)
						if err != nil {
							sourceErrors = append(sourceErrors, NewSourceError("peeringdb", "netixlan", fmt.Errorf("convert ASN->IXP correlation: %w", err)))
						} else {
							corr.RetrievedAt = retrievedAt
							// Add provenance to collection for OBSERVED correlation resolvability
							coll.Provenance = append(coll.Provenance, prov)
							correlations = append(correlations, corr)
						}
					}
				}
			}
		}
	}

	// ASN -> Facility correlations from PeeringDB netfac (OBSERVED)
	// Collect ASNs from query and from IXP netixlan data
	asnSet := make(map[int]bool)

	// Extract ASN from query if present (e.g., "asn:12345")
	if asn := parseASN(query); asn > 0 {
		asnSet[asn] = true
	}

	// Extract ASNs from IXP netixlan correlations (already fetched above)
	for _, ixp := range coll.IXPs {
		if ixp.PeeringDBID > 0 {
			netixlans, err := p.pdbClient.ListNetworksAtIXP(ctx, ixp.PeeringDBID)
			if err == nil {
				for _, nixlan := range netixlans {
					if nixlan.Operational && nixlan.ASN > 0 {
						asnSet[nixlan.ASN] = true
					}
				}
			}
		}
	}

	// For each unique ASN, query netfac for facilities
	for asn := range asnSet {
		netfacs, err := p.pdbClient.GetNetFacByASN(ctx, asn)
		if err != nil {
			sourceErrors = append(sourceErrors, NewSourceError("peeringdb", "netfac", fmt.Errorf("ASN->Facility correlation for AS%d: %w", asn, err)))
		} else {
			for _, netfac := range netfacs {
				// Find matching facility in collection
				for _, fac := range coll.Facilities {
					if fac.PeeringDBID == netfac.FacID {
						prov := ProvenanceFor(p.MetaVal, osint.CapabilityInfrastructure, fmt.Sprintf("peeringdb:netfac:%d", netfac.ID))
						corr, err := ConvertPeeringDBNetFac(&netfac, fac.ID, asn, prov)
						if err != nil {
							sourceErrors = append(sourceErrors, NewSourceError("peeringdb", "netfac", fmt.Errorf("convert ASN->Facility correlation: %w", err)))
						} else {
							// Add provenance to collection for OBSERVED correlation resolvability
							coll.Provenance = append(coll.Provenance, prov)
							correlations = append(correlations, corr)
						}
						break
					}
				}
			}
		}
	}

	// IXP -> Facility correlations from PeeringDB ixfac (OBSERVED)
	// For each Facility from PeeringDB, query ixfac for IXPs present
	for _, fac := range coll.Facilities {
		if fac.PeeringDBID > 0 {
			ixpIDs, err := p.pdbClient.ListIXPsByFacility(ctx, fac.PeeringDBID)
			if err != nil {
				sourceErrors = append(sourceErrors, NewSourceError("peeringdb", "ixfac", fmt.Errorf("IXP->Facility correlation for Facility %s: %w", fac.ID, err)))
			} else {
				for _, ixpID := range ixpIDs {
					// Find matching IXP in collection
					for _, ixp := range coll.IXPs {
						if ixp.PeeringDBID == ixpID {
							prov := ProvenanceFor(p.MetaVal, osint.CapabilityInfrastructure, fmt.Sprintf("peeringdb:ixfac:%d:%d", fac.PeeringDBID, ixpID))
							corr := InfrastructureCorrelation{
								ID:             fmt.Sprintf("peeringdb:ixfac:%d:%d", fac.PeeringDBID, ixpID),
								NetworkEntity:  ixp.ID,
								InfraEntity:    fac.ID,
								RelationKind:   "ixp_at_facility",
								EvidenceClass:  osint.EvidenceObserved,
								ProvenanceRef:  fmt.Sprintf("peeringdb:ixfac:%d:%d", fac.PeeringDBID, ixpID),
								Label:          fmt.Sprintf("IXP %s at Facility %s (PeeringDB)", ixp.Name, fac.Name),
								Confidence:     "alta",
								RetrievedAt:    time.Now().UTC().Format(time.RFC3339),
							}
							// Add provenance to collection for OBSERVED correlation resolvability
							coll.Provenance = append(coll.Provenance, prov)
							correlations = append(correlations, corr)
						}
					}
				}
			}
		}
	}

	// Correlate Landing Stations with Submarine Cables (POSSIBLE_CONTEXT via cable name match)
	// Only when there's an explicit cable name reference in the landing station tags
	for _, ls := range coll.LandingStations {
		for _, cable := range coll.SubmarineCables {
			for _, lsCable := range ls.Cables {
				if strings.EqualFold(strings.TrimSpace(lsCable), strings.TrimSpace(cable.Name)) {
					corr := InfrastructureCorrelation{
						ID:             fmt.Sprintf("ctx:ls-cable:%s:%s", ls.ID, cable.ID),
						NetworkEntity:  ls.ID,
						InfraEntity:    cable.ID,
						RelationKind:   "landing_station_cable",
						EvidenceClass:  osint.EvidencePossibleContext,
						ProvenanceRef:  fmt.Sprintf("cable_name_match:%s", lsCable),
						Label:          fmt.Sprintf("Landing Station %s associated with Cable %s", ls.Name, cable.Name),
						Confidence:     "media",
						RetrievedAt:    time.Now().UTC().Format(time.RFC3339),
					}
					correlations = append(correlations, corr)
				}
			}
		}
	}

	// Cable -> Network Path correlations are ALWAYS NOT_PROVEN in V1.5-6
	// We do NOT create these correlations

	return correlations, sourceErrors
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
			CachePolicy: "none",
			Confidence:  "alta",
			RateLimit:   "OSM: 1 req/s (TRAZIP conservative); PeeringDB: 0.5 req/s (TRAZIP conservative)",
		},
	}
}

// Helper functions

func parseID(s string) int {
	var id int
	fmt.Sscanf(s, "%d", &id)
	return id
}

// parsePeeringDBQuery extracts an ID from a peeringdb:TYPE:NUMBER query.
// Returns (type, id, true) if the query matches the format, otherwise ("", 0, false).
func parsePeeringDBQuery(s string) (string, int, bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "peeringdb:") {
		s = strings.TrimPrefix(s, "peeringdb:")
		parts := strings.SplitN(s, ":", 2)
		if len(parts) == 2 {
			var id int
			n, _ := fmt.Sscanf(parts[1], "%d", &id)
			if n == 1 {
				return parts[0], id, true
			}
		}
	}
	return "", 0, false
}

// parseOSMQuery extracts type and ID from an osm:TYPE/ID query.
// Returns (type, id, true) if the query matches the format, otherwise ("", 0, false).
func parseOSMQuery(s string) (string, int64, bool) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "osm:") {
		s = strings.TrimPrefix(s, "osm:")
		parts := strings.SplitN(s, "/", 2)
		if len(parts) == 2 {
			var id int64
			n, _ := fmt.Sscanf(parts[1], "%d", &id)
			if n == 1 {
				return parts[0], id, true
			}
		}
	}
	return "", 0, false
}

// parseASN extracts an ASN from a query string like "asn:12345" or "AS12345".
func parseASN(s string) int {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "asn:")
	s = strings.TrimPrefix(s, "AS")
	s = strings.TrimPrefix(s, "as")
	var asn int
	fmt.Sscanf(s, "%d", &asn)
	return asn
}

// extractSearchTerms extracts the actual search terms from a formatted query.
// Handles formats like: country:CC, city:City,CC, bbox:..., asn:N, peeringdb:..., osm:...
// matchesQuerySemantic performs semantic matching based on the query type.
// For bbox queries: no additional textual filtering (spatial query already did the work).
// For country queries: filter by exact country code match.
// For city queries: filter by exact city name AND country code match.
// For other queries: fallback to substring matching on name/city/country.
func matchesQuerySemantic(name, city, country string, spec QuerySpec) bool {
	switch spec.Type {
	case QueryTypeBBox:
		// BBox queries: spatial query already filtered, no additional textual filtering
		return true
	case QueryTypeCountry:
		// Country queries: exact country code match
		return strings.EqualFold(country, spec.Country)
	case QueryTypeCity:
		// City queries: exact city name AND country code match
		return strings.EqualFold(city, spec.City) && strings.EqualFold(country, spec.Country)
	default:
		// Fallback: substring matching on name/city/country (legacy behavior)
		searchTerm := extractSearchTerms(spec.RawQuery)
		if searchTerm == "" {
			return true
		}
		q := strings.ToLower(searchTerm)
		haystack := strings.ToLower(name + " " + city + " " + country)
		return strings.Contains(haystack, q)
	}
}

// extractSearchTerms extracts the actual search terms from a formatted query.
// Handles formats like: country:CC, city:City,CC, bbox:..., asn:N, peeringdb:..., osm:...
func extractSearchTerms(query string) string {
	q := strings.TrimSpace(query)
	if q == "" {
		return ""
	}

	// Remove known prefixes and return the searchable part
	prefixes := []string{"country:", "cc:", "city:", "bbox:", "asn:", "peeringdb:", "osm:"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(q, prefix) {
			// Return the part after the prefix
			return strings.TrimPrefix(q, prefix)
		}
	}

	// No recognized prefix, return as-is
	return q
}
func parseQuerySpec(query string) (QuerySpec, error) {
	q := strings.TrimSpace(query)
	if q == "" {
		return QuerySpec{Type: QueryTypeUnknown, RawQuery: query}, nil
	}

	// Explicit bbox: "south,west,north,east" or "bbox:south,west,north,east"
	if strings.HasPrefix(q, "bbox:") {
		bbox := strings.TrimPrefix(q, "bbox:")
		parts := strings.Split(bbox, ",")
		if len(parts) != 4 {
			return QuerySpec{}, fmt.Errorf("invalid bbox format, expected 'south,west,north,east'")
		}
		// Validate numeric
		for _, p := range parts {
			if _, err := fmt.Sscanf(strings.TrimSpace(p), "%f", new(float64)); err != nil {
				return QuerySpec{}, fmt.Errorf("invalid bbox coordinate: %s", p)
			}
		}
		return QuerySpec{Type: QueryTypeBBox, RawQuery: query}, nil
	}

	// Check for "country:XX" or "cc:XX" pattern (ISO alpha-2)
	if strings.HasPrefix(q, "country:") || strings.HasPrefix(q, "cc:") {
		prefix := "country:"
		if strings.HasPrefix(q, "cc:") {
			prefix = "cc:"
		}
		cc := strings.ToUpper(strings.TrimPrefix(q, prefix))
		if len(cc) != 2 {
			return QuerySpec{}, fmt.Errorf("invalid country code format, expected ISO alpha-2")
		}
		if _, ok := countryBBox[cc]; !ok {
			return QuerySpec{}, fmt.Errorf("unsupported country code: %s", cc)
		}
		return QuerySpec{Type: QueryTypeCountry, Country: cc, RawQuery: query}, nil
	}

	// Check for "city:Name,CC" pattern
	if strings.HasPrefix(q, "city:") {
		citySpec := strings.TrimPrefix(q, "city:")
		parts := strings.Split(citySpec, ",")
		if len(parts) != 2 {
			return QuerySpec{}, fmt.Errorf("invalid city format, expected 'city:CityName,CC'")
		}
		city := strings.TrimSpace(parts[0])
		cc := strings.ToUpper(strings.TrimSpace(parts[1]))
		if len(cc) != 2 {
			return QuerySpec{}, fmt.Errorf("invalid country code format, expected ISO alpha-2")
		}
		if _, ok := cityBBox[cc+":"+city]; !ok {
			// Fallback to country bbox is handled by caller
			if _, ok := countryBBox[cc]; !ok {
				return QuerySpec{}, fmt.Errorf("unsupported city: %s, %s", city, cc)
			}
		}
		return QuerySpec{Type: QueryTypeCity, City: city, Country: cc, RawQuery: query}, nil
	}

	// Check for "asn:NUMBER" pattern - for ASN-based lookups we use PeeringDB directly
	if strings.HasPrefix(q, "asn:") {
		return QuerySpec{Type: QueryTypeASN, RawQuery: query}, nil
	}

	// Check for "peeringdb:ix:NUMBER" or similar explicit provider IDs
	if strings.HasPrefix(q, "peeringdb:") || strings.HasPrefix(q, "osm:") {
		return QuerySpec{Type: QueryTypePeeringDB, RawQuery: query}, nil
	}

	// No recognized prefix - treat as unknown
	return QuerySpec{Type: QueryTypeUnknown, RawQuery: query}, nil
}

// inferBBoxFromQuery infers a bounding box from the query string.
// Returns the bbox string and the parsed QuerySpec.
func inferBBoxFromQuery(ctx context.Context, query string) (string, QuerySpec, error) {
	spec, err := parseQuerySpec(query)
	if err != nil {
		return "", QuerySpec{}, err
	}

	q := strings.TrimSpace(query)
	if q == "" {
		return "", spec, nil
	}

	// Explicit bbox: "south,west,north,east" or "bbox:south,west,north,east"
	if strings.HasPrefix(q, "bbox:") {
		bbox := strings.TrimPrefix(q, "bbox:")
		return bbox, spec, nil
	}

	// Check for "country:XX" or "cc:XX" pattern (ISO alpha-2)
	if strings.HasPrefix(q, "country:") || strings.HasPrefix(q, "cc:") {
		prefix := "country:"
		if strings.HasPrefix(q, "cc:") {
			prefix = "cc:"
		}
		cc := strings.ToUpper(strings.TrimPrefix(q, prefix))
		if bbox, ok := countryBBox[cc]; ok {
			return bbox, spec, nil
		}
		return "", spec, fmt.Errorf("unsupported country code: %s", cc)
	}

	// Check for "city:Name,CC" pattern
	if strings.HasPrefix(q, "city:") {
		citySpec := strings.TrimPrefix(q, "city:")
		parts := strings.Split(citySpec, ",")
		if len(parts) == 2 {
			city := strings.TrimSpace(parts[0])
			cc := strings.ToUpper(strings.TrimSpace(parts[1]))
			if bbox, ok := cityBBox[cc+":"+city]; ok {
				return bbox, spec, nil
			}
			// Fallback to country bbox
			if bbox, ok := countryBBox[cc]; ok {
				return bbox, spec, nil
			}
			return "", spec, fmt.Errorf("unsupported city: %s, %s", city, cc)
		}
		return "", spec, fmt.Errorf("invalid city format, expected 'city:CityName,CC'")
	}

	// Check for "asn:NUMBER" pattern - for ASN-based lookups we use PeeringDB directly
	if strings.HasPrefix(q, "asn:") {
		return "", spec, nil // Signal to use PeeringDB
	}

	// Check for "peeringdb:ix:NUMBER" or similar explicit provider IDs
	if strings.HasPrefix(q, "peeringdb:") || strings.HasPrefix(q, "osm:") {
		return "", spec, nil // Signal to use direct provider lookup
	}

	// No bounded query - reject global search
	return "", spec, nil
}

// countryBBox provides country-level bounding boxes for major countries.
// Values are approximate [south, west, north, east].
var countryBBox = map[string]string{
	"US": "24.396308,-125.0,49.384358,-66.93457",
	"GB": "49.9,-8.65,60.85,1.77",
	"DE": "47.27,5.87,55.06,15.04",
	"FR": "41.33,-5.14,51.12,9.56",
	"NL": "50.75,3.35,53.55,7.23",
	"JP": "24.39,122.93,45.52,153.99",
	"SG": "1.16,103.6,1.47,104.05",
	"HK": "22.15,113.83,22.56,114.43",
	"AU": "-43.63,113.33,-10.66,153.56",
	"CA": "41.68,-141.0,83.11,-52.62",
	"BR": "-33.75,-73.99,5.27,-34.79",
	"IN": "6.75,68.11,35.5,97.4",
	"CN": "18.16,73.5,53.56,134.77",
	"ES": "36.0,-9.3,43.79,3.3",
	"IT": "36.65,6.62,47.09,18.52",
	"SE": "55.34,11.12,69.06,24.17",
	"NO": "57.98,4.58,71.19,31.1",
	"DK": "54.56,8.07,57.75,15.16",
	"FI": "59.81,20.54,70.09,31.59",
	"PL": "49.0,14.12,54.84,24.15",
	"CH": "45.82,5.96,47.81,10.49",
	"AT": "46.38,9.53,49.02,17.16",
	"BE": "49.5,2.54,51.51,6.41",
	"IE": "51.43,-10.55,55.38,-6.0",
	"PT": "36.96,-9.5,42.15,-6.19",
	"ZA": "-34.83,16.47,-22.13,32.89",
	"AE": "22.63,51.58,26.09,56.38",
	"IL": "29.45,34.27,33.28,35.9",
	"TR": "35.81,25.67,42.11,44.82",
	"RU": "41.19,19.65,81.86,169.0",
	"MX": "14.53,-118.46,32.72,-86.72",
	"AR": "-55.05,-73.56,-21.78,-53.64",
	"CL": "-56.0,-75.7,-17.5,-66.42",
	"CO": "-4.23,-79.03,12.47,-66.87",
	"PE": "-18.35,-81.33,-0.04,-68.68",
	"NZ": "-47.29,166.45,-34.17,178.55",
	"KR": "33.1,124.6,38.61,131.88",
	"TW": "21.9,119.3,25.3,122.0",
	"ID": "-11.0,95.0,6.0,141.0",
	"MY": "0.85,99.64,7.36,119.27",
	"TH": "5.61,97.34,20.46,105.64",
	"VN": "8.18,102.15,23.39,109.46",
	"PH": "4.64,116.93,21.12,126.6",
}

// cityBBox provides city-level bounding boxes for major cities.
// Key format: "CC:CityName"
var cityBBox = map[string]string{
	"US:New York":    "40.47,-74.27,40.92,-73.7",
	"US:Los Angeles": "33.7,-118.67,34.34,-118.16",
	"US:Chicago":     "41.64,-87.94,42.02,-87.52",
	"US:San Francisco": "37.7,-123.0,37.83,-122.35",
	"US:Seattle":     "47.48,-122.43,47.73,-122.23",
	"US:Miami":       "25.7,-80.3,25.92,-80.1",
	"US:Dallas":      "32.62,-96.99,32.98,-96.46",
	"US:Atlanta":     "33.65,-84.55,33.89,-84.29",
	"GB:London":      "51.28,-0.51,51.69,0.33",
	"GB:Manchester":  "53.35,-2.3,53.58,-2.12",
	"DE:Frankfurt":   "50.0,8.46,50.17,8.8",
	"DE:Berlin":      "52.34,13.09,52.68,13.5",
	"DE:Munich":      "48.06,11.34,48.25,11.7",
	"FR:Paris":       "48.81,2.22,48.9,2.47",
	"NL:Amsterdam":   "52.28,4.73,52.44,5.08",
	"JP:Tokyo":       "35.53,139.51,35.82,139.91",
	"JP:Osaka":       "34.53,135.34,34.73,135.64",
	"SG:Singapore":   "1.16,103.6,1.47,104.05",
	"HK:Hong Kong":   "22.15,113.83,22.56,114.43",
	"AU:Sydney":      "-34.1,150.52,-33.58,151.34",
	"AU:Melbourne":   "-38.2,144.59,-37.5,145.3",
	"CA:Toronto":     "43.58,-79.64,43.85,-79.12",
	"CA:Vancouver":   "49.19,-123.25,49.34,-122.91",
	"BR:Sao Paulo":   "-24.0,-46.8,-23.3,-46.35",
	"IN:Mumbai":      "18.89,72.77,19.27,72.99",
	"IN:Delhi":       "28.4,76.84,28.88,77.35",
	"CN:Shanghai":    "30.68,120.87,31.87,121.9",
	"CN:Beijing":     "39.44,115.42,41.06,117.41",
	"ES:Madrid":      "40.24,-3.95,40.55,-3.5",
	"ES:Barcelona":   "41.27,2.05,41.47,2.32",
	"IT:Rome":        "41.71,12.3,42.0,12.65",
	"IT:Milan":       "45.35,9.0,45.57,9.3",
	"SE:Stockholm":   "59.2,17.8,59.45,18.2",
	"NO:Oslo":        "59.8,10.5,59.98,10.9",
	"DK:Copenhagen":  "55.55,12.4,55.75,12.7",
	"FI:Helsinki":    "60.0,24.7,60.3,25.1",
	"PL:Warsaw":      "52.08,20.8,52.37,21.2",
	"CH:Zurich":      "47.22,8.4,47.45,8.7",
	"AT:Vienna":      "48.06,16.15,48.34,16.55",
	"BE:Brussels":    "50.73,4.2,50.95,4.5",
	"IE:Dublin":      "53.23,-6.4,53.43,-6.1",
	"PT:Lisbon":      "38.63,-9.27,38.85,-9.0",
	"ZA:Johannesburg": "-26.4,27.8,-26.0,28.2",
	"AE:Dubai":       "24.9,55.0,25.3,55.5",
	"IL:Tel Aviv":    "32.0,34.7,32.15,34.9",
	"TR:Istanbul":    "40.8,28.7,41.1,29.3",
	"RU:Moscow":      "55.55,37.35,55.9,37.85",
	"MX:Mexico City": "19.05,-99.36,19.59,-98.94",
	"AR:Buenos Aires": "-34.7,-58.53,-34.52,-58.33",
	"CL:Santiago":    "-33.6,-70.8,-33.2,-70.4",
	"CO:Bogota":      "4.47,-74.2,4.8,-73.9",
	"PE:Lima":        "-12.15,-77.15,-11.9,-76.9",
	"NZ:Auckland":    "-37.2,174.5,-36.7,175.0",
	"KR:Seoul":       "37.4,126.8,37.7,127.2",
	"TW:Taipei":      "24.96,121.37,25.13,121.67",
	"ID:Jakarta":     "-6.37,106.65,-6.0,107.0",
	"MY:Kuala Lumpur": "3.0,101.55,3.27,101.85",
	"TH:Bangkok":     "13.6,100.4,13.9,100.7",
	"VN:Ho Chi Minh": "10.6,106.5,10.9,106.8",
	"PH:Manila":      "14.4,120.8,14.7,121.1",
}

// sortCollections sorts all collections deterministically by ID before truncation.
func (p *InfraProvider) sortCollections(coll *InfrastructureCollection) {
	// Sort by ID for deterministic ordering
	sort.Slice(coll.IXPs, func(i, j int) bool { return coll.IXPs[i].ID < coll.IXPs[j].ID })
	sort.Slice(coll.Facilities, func(i, j int) bool { return coll.Facilities[i].ID < coll.Facilities[j].ID })
	sort.Slice(coll.LandingStations, func(i, j int) bool { return coll.LandingStations[i].ID < coll.LandingStations[j].ID })
	sort.Slice(coll.SubmarineCables, func(i, j int) bool { return coll.SubmarineCables[i].ID < coll.SubmarineCables[j].ID })
	sort.Slice(coll.Correlations, func(i, j int) bool { return coll.Correlations[i].ID < coll.Correlations[j].ID })
	sort.Slice(coll.Provenance, func(i, j int) bool { return coll.Provenance[i].Endpoint < coll.Provenance[j].Endpoint })
	sort.Slice(coll.SourceErrors, func(i, j int) bool {
		if coll.SourceErrors[i].Provider != coll.SourceErrors[j].Provider {
			return coll.SourceErrors[i].Provider < coll.SourceErrors[j].Provider
		}
		return coll.SourceErrors[i].Operation < coll.SourceErrors[j].Operation
	})
}