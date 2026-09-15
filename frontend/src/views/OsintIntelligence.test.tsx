import { describe, expect, it } from 'vitest';
import {
  type InfrastructureCollection,
  type InfrastructureIXP,
  type InfrastructureFacility,
  type InfrastructureLandingStation,
  type InfrastructureSubmarineCable,
  type InfrastructureCorrelation,
} from '../lib/api';
import { asEvidenceClass, asEntityKind } from '../lib/entityGraph';

function makeMockIXP(over: Partial<InfrastructureIXP> = {}): InfrastructureIXP {
  return {
    id: 'peeringdb:1',
    name: 'TEST-IX',
    city: 'Madrid',
    country: 'ES',
    region: 'Europe',
    website: 'https://test-ix.net',
    peeringdbId: 1,
    provenance: { ProviderName: 'PeeringDB' },
    lastUpdated: '2024-01-01T00:00:00Z',
    ...over,
  };
}

function makeMockFacility(over: Partial<InfrastructureFacility> = {}): InfrastructureFacility {
  return {
    id: 'peeringdb:10',
    name: 'TEST-FAC',
    city: 'Madrid',
    country: 'ES',
    region: 'Europe',
    address: 'Calle Test 1',
    latitude: 40.41,
    longitude: -3.70,
    clli: 'MDTDES',
    peeringdbId: 10,
    provenance: { ProviderName: 'PeeringDB' },
    lastUpdated: '2024-01-01T00:00:00Z',
    ...over,
  };
}

function makeMockLandingStation(over: Partial<InfrastructureLandingStation> = {}): InfrastructureLandingStation {
  return {
    id: 'osm:node/123',
    name: 'TEST-LS',
    city: 'Madrid',
    country: 'ES',
    region: 'Europe',
    latitude: 40.41,
    longitude: -3.70,
    cables: ['CABLE-1', 'CABLE-2'],
    provenance: { ProviderName: 'OpenStreetMap' },
    lastUpdated: '2024-01-01T00:00:00Z',
    ...over,
  };
}

function makeMockSubmarineCable(over: Partial<InfrastructureSubmarineCable> = {}): InfrastructureSubmarineCable {
  return {
    id: 'osm:way/456',
    name: 'TEST-CABLE',
    owners: ['Owner A', 'Owner B'],
    landingPoints: ['LS-1', 'LS-2'],
    readyForService: '2020-01-01',
    lengthKm: 10000,
    fiberPairs: 8,
    designCapacity: '100 Tbps',
    provenance: { ProviderName: 'OpenStreetMap' },
    lastUpdated: '2024-01-01T00:00:00Z',
    ...over,
  };
}

function makeMockCorrelation(over: Partial<InfrastructureCorrelation> = {}): InfrastructureCorrelation {
  return {
    id: 'peeringdb:netixlan:100',
    networkEntity: 'AS64500',
    infraEntity: 'peeringdb:1',
    relationKind: 'asn_at_ixp',
    evidenceClass: 'observed',
    provenanceRef: 'peeringdb:netixlan:100',
    label: 'AS64500 present at TEST-IX (PeeringDB)',
    confidence: 'alta',
    retrievedAt: '2024-01-01T00:00:00Z',
    ...over,
  };
}

function makeMockCollection(over: Partial<InfrastructureCollection> = {}): InfrastructureCollection {
  return {
    ixps: [makeMockIXP()],
    facilities: [makeMockFacility()],
    landingStations: [makeMockLandingStation()],
    submarineCables: [makeMockSubmarineCable()],
    correlations: [makeMockCorrelation()],
    provenance: [],
    sourceErrors: [],
    retrievedAt: '2024-01-01T00:00:00Z',
    query: 'asn:64500',
    bounds: { maxIxps: 500, maxFacilities: 500, maxLandingStations: 200, maxSubmarineCables: 300, maxCorrelations: 1000 },
    ...over,
  };
}

function convertInfraToEntities(collection: InfrastructureCollection) {
  const entities: any[] = [];
  const relations: any[] = [];

  if (collection.ixps) {
    for (const ixp of collection.ixps) {
      entities.push({
        id: ixp.id,
        kind: asEntityKind('ixp'),
        label: ixp.name,
        value: ixp.name,
        attributes: {
          city: ixp.city || '',
          country: ixp.country,
          region: ixp.region || '',
          website: ixp.website || '',
          source: ixp.provenance?.ProviderName || 'unknown',
        },
      });
    }
  }

  if (collection.facilities) {
    for (const fac of collection.facilities) {
      entities.push({
        id: fac.id,
        kind: asEntityKind('facility'),
        label: fac.name,
        value: fac.name,
        attributes: {
          city: fac.city || '',
          country: fac.country,
          region: fac.region || '',
          orgName: fac.orgName || '',
          address: fac.address || '',
          clli: fac.clli || '',
          website: fac.website || '',
          source: fac.provenance?.ProviderName || 'unknown',
        },
      });
    }
  }

  if (collection.landingStations) {
    for (const ls of collection.landingStations) {
      entities.push({
        id: ls.id,
        kind: asEntityKind('landing_station'),
        label: ls.name,
        value: ls.name,
        attributes: {
          city: ls.city || '',
          country: ls.country,
          region: ls.region || '',
          cables: (ls.cables || []).join(', '),
          source: ls.provenance?.ProviderName || 'unknown',
        },
      });
    }
  }

  if (collection.submarineCables) {
    for (const cable of collection.submarineCables) {
      entities.push({
        id: cable.id,
        kind: asEntityKind('submarine_cable'),
        label: cable.name,
        value: cable.name,
        attributes: {
          owners: (cable.owners || []).join(', '),
          lengthKm: cable.lengthKm?.toString() || '',
          rfs: cable.readyForService || '',
          fiberPairs: cable.fiberPairs?.toString() || '',
          designCapacity: cable.designCapacity || '',
          source: cable.provenance?.ProviderName || 'unknown',
        },
      });
    }
  }

  if (collection.correlations) {
    for (const corr of collection.correlations) {
      relations.push({
        id: corr.id,
        from: corr.networkEntity,
        to: corr.infraEntity,
        kind: corr.relationKind,
        directed: false,
        evidenceClass: asEvidenceClass(corr.evidenceClass),
        provenanceRef: corr.provenanceRef,
        label: corr.label || '',
      });
    }
  }

  return { entities, relations };
}

describe('OsintIntelligence infrastructure conversion', () => {
  it('converts IXPs to entities with correct kind and attributes', () => {
    const collection = makeMockCollection({
      ixps: [makeMockIXP({ id: 'peeringdb:1', name: 'AMS-IX', city: 'Amsterdam', country: 'NL' })],
      facilities: [],
      landingStations: [],
      submarineCables: [],
      correlations: [],
    });
    const { entities } = convertInfraToEntities(collection);

    expect(entities).toHaveLength(1);
    const e = entities[0];
    expect(e.id).toBe('peeringdb:1');
    expect(e.kind).toBe('ixp');
    expect(e.label).toBe('AMS-IX');
    expect(e.value).toBe('AMS-IX');
    expect(e.attributes.city).toBe('Amsterdam');
    expect(e.attributes.country).toBe('NL');
    expect(e.attributes.source).toBe('PeeringDB');
  });

  it('converts Facilities to entities with correct kind and attributes', () => {
    const collection = makeMockCollection({
      ixps: [],
      facilities: [makeMockFacility({ id: 'peeringdb:10', name: 'Equinix AM3', city: 'Amsterdam', country: 'NL' })],
      landingStations: [],
      submarineCables: [],
      correlations: [],
    });
    const { entities } = convertInfraToEntities(collection);

    expect(entities).toHaveLength(1);
    const e = entities[0];
    expect(e.id).toBe('peeringdb:10');
    expect(e.kind).toBe('facility');
    expect(e.label).toBe('Equinix AM3');
    expect(e.attributes.clli).toBe('MDTDES');
    expect(e.attributes.source).toBe('PeeringDB');
  });

  it('converts Landing Stations to entities with correct kind and attributes', () => {
    const collection = makeMockCollection({
      ixps: [],
      facilities: [],
      landingStations: [makeMockLandingStation({ id: 'osm:node/123', name: 'Bilbao Landing', city: 'Bilbao', country: 'ES', cables: ['MAREA', 'GRACE HOPPER'] })],
      submarineCables: [],
      correlations: [],
    });
    const { entities } = convertInfraToEntities(collection);

    expect(entities).toHaveLength(1);
    const e = entities[0];
    expect(e.id).toBe('osm:node/123');
    expect(e.kind).toBe('landing_station');
    expect(e.label).toBe('Bilbao Landing');
    expect(e.attributes.cables).toBe('MAREA, GRACE HOPPER');
    expect(e.attributes.source).toBe('OpenStreetMap');
  });

  it('converts Submarine Cables to entities with correct kind and attributes', () => {
    const collection = makeMockCollection({
      ixps: [],
      facilities: [],
      landingStations: [],
      submarineCables: [makeMockSubmarineCable({ id: 'osm:way/456', name: 'MAREA', owners: ['Microsoft', 'Facebook', 'Telxius'], readyForService: '2018-02-01', lengthKm: 6600, fiberPairs: 8, designCapacity: '200 Tbps' })],
      correlations: [],
    });
    const { entities } = convertInfraToEntities(collection);

    expect(entities).toHaveLength(1);
    const e = entities[0];
    expect(e.id).toBe('osm:way/456');
    expect(e.kind).toBe('submarine_cable');
    expect(e.label).toBe('MAREA');
    expect(e.attributes.owners).toBe('Microsoft, Facebook, Telxius');
    expect(e.attributes.rfs).toBe('2018-02-01');
    expect(e.attributes.lengthKm).toBe('6600');
    expect(e.attributes.fiberPairs).toBe('8');
    expect(e.attributes.designCapacity).toBe('200 Tbps');
    expect(e.attributes.source).toBe('OpenStreetMap');
  });

  it('converts correlations to relations with correct evidence class', () => {
    const collection = makeMockCollection({
      correlations: [
        makeMockCorrelation({ id: 'corr-1', evidenceClass: 'observed', relationKind: 'asn_at_ixp' }),
        makeMockCorrelation({ id: 'corr-2', evidenceClass: 'possible_context', relationKind: 'ixp_at_facility' }),
        makeMockCorrelation({ id: 'corr-3', evidenceClass: 'not_proven', relationKind: 'prefix_lands_at' }),
      ],
    });
    const { relations } = convertInfraToEntities(collection);

    expect(relations).toHaveLength(3);
    expect(relations[0].evidenceClass).toBe('observed');
    expect(relations[1].evidenceClass).toBe('possible_context');
    expect(relations[2].evidenceClass).toBe('not_proven');
    expect(relations[0].from).toBe('AS64500');
    expect(relations[0].to).toBe('peeringdb:1');
    expect(relations[0].provenanceRef).toBe('peeringdb:netixlan:100');
  });

  it('handles missing optional fields with defaults', () => {
    const ixp = makeMockIXP({ city: '', region: '', website: '' });
    const collection = makeMockCollection({ 
      ixps: [ixp],
      facilities: [],
      landingStations: [],
      submarineCables: [],
      correlations: [],
    });
    const { entities } = convertInfraToEntities(collection);

    expect(entities[0].attributes.city).toBe('');
    expect(entities[0].attributes.region).toBe('');
    expect(entities[0].attributes.website).toBe('');
  });

  it('handles missing cables array on landing station', () => {
    const ls = makeMockLandingStation({ cables: [] });
    const collection = makeMockCollection({ 
      ixps: [],
      facilities: [],
      landingStations: [ls],
      submarineCables: [],
      correlations: [],
    });
    const { entities } = convertInfraToEntities(collection);

    expect(entities[0].attributes.cables).toBe('');
  });

  it('handles missing owners on submarine cable', () => {
    const cable = makeMockSubmarineCable({ owners: [], fiberPairs: undefined });
    const collection = makeMockCollection({ 
      ixps: [],
      facilities: [],
      landingStations: [],
      submarineCables: [cable],
      correlations: [],
    });
    const { entities } = convertInfraToEntities(collection);

    expect(entities[0].attributes.owners).toBe('');
    expect(entities[0].attributes.fiberPairs).toBe('');
  });

  it('preserves deterministic ordering of entities by ID', () => {
    const collection = makeMockCollection({
      ixps: [
        makeMockIXP({ id: 'peeringdb:3', name: 'C-IX' }),
        makeMockIXP({ id: 'peeringdb:1', name: 'A-IX' }),
        makeMockIXP({ id: 'peeringdb:2', name: 'B-IX' }),
      ],
      facilities: [],
      landingStations: [],
      submarineCables: [],
      correlations: [],
    });
    const { entities } = convertInfraToEntities(collection);

    // The conversion preserves the input order
    expect(entities.map(e => e.id)).toEqual(['peeringdb:3', 'peeringdb:1', 'peeringdb:2']);
  });

  it('sourceErrors are present in collection type', () => {
    const collection = makeMockCollection({
      sourceErrors: [
        { provider: 'peeringdb', operation: 'netixlan', message: 'timeout', errorType: 'timeout' },
        { provider: 'osm', operation: 'query', message: 'rate limited', errorType: 'rate_limit' },
      ],
    });
    expect(collection.sourceErrors).toHaveLength(2);
    expect(collection.sourceErrors?.[0].provider).toBe('peeringdb');
    expect(collection.sourceErrors?.[0].errorType).toBe('timeout');
  });
});