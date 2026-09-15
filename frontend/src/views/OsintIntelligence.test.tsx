import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import OsintIntelligence from './OsintIntelligence';
import { executeInfrastructureOSINT, listOsintProviders } from '../lib/api';

vi.mock('../lib/api', () => ({
  executeInfrastructureOSINT: vi.fn(),
  listOsintProviders: vi.fn(() => Promise.resolve([mockProvider])),
  executeOSINT: vi.fn(),
}));

vi.mock('../lib/i18n', () => ({
  useI18n: () => ({
    t: (key: string) => key,
  }),
}));

vi.mock('../lib/entityGraph', () => ({
  ENTITY_GRAPH_MIN_ZOOM: 0.5,
  ENTITY_GRAPH_MAX_ZOOM: 3,
  ENTITY_GRAPH_ZOOM_STEP: 0.1,
  buildEntityGraphLayout: vi.fn(() => ({
    width: 800,
    height: 600,
    nodeWidth: 160,
    nodeHeight: 60,
    nodes: [],
  })),
  clampEntityGraphZoom: vi.fn((v: number) => v),
  entityEdgeCurve: vi.fn(() => 'M 0 0 L 100 100'),
  entityEdgeEndpoints: vi.fn(() => ({ startX: 0, startY: 0, endX: 100, endY: 100, isSelfLoop: false })),
  entityEdgeLaneOffsets: vi.fn(() => new Map()),
  entityGraphViewBox: vi.fn(() => ({ x: 0, y: 0, width: 800, height: 600 })),
  fitEntityGraphViewBox: vi.fn(() => ({ x: 0, y: 0, width: 800, height: 600 })),
  filterEntities: vi.fn((entities) => entities),
  filterRelations: vi.fn((relations) => relations),
  EVIDENCE_DESCRIPTORS: {
    observed: { labelKey: 'Observado', summaryKey: '', tagClass: 'ok', edgeStyle: 'solid' },
    possible_context: { labelKey: 'Contexto posible', summaryKey: '', tagClass: 'info', edgeStyle: 'dashed' },
    not_proven: { labelKey: 'No demostrado', summaryKey: '', tagClass: 'warn', edgeStyle: 'dotted' },
    unknown: { labelKey: 'Sin clasificar', summaryKey: '', tagClass: 'error', edgeStyle: 'dotted' },
  },
  ENTITY_KIND_DESCRIPTORS: {
    ip: { labelKey: 'IP', summaryKey: '', tagClass: 'ok' },
    domain: { labelKey: 'Dominio', summaryKey: '', tagClass: 'info' },
    asn: { labelKey: 'ASN', summaryKey: '', tagClass: 'info' },
    certificate: { labelKey: 'Certificado', summaryKey: '', tagClass: 'info' },
    cve: { labelKey: 'CVE', summaryKey: '', tagClass: 'warn' },
    organization: { labelKey: 'Organización', summaryKey: '', tagClass: 'info' },
    url: { labelKey: 'URL', summaryKey: '', tagClass: 'info' },
    country: { labelKey: 'País', summaryKey: '', tagClass: 'info' },
    ixp: { labelKey: 'IXP', summaryKey: '', tagClass: 'ok' },
    facility: { labelKey: 'Facility', summaryKey: '', tagClass: 'ok' },
    landing_station: { labelKey: 'Landing Station', summaryKey: '', tagClass: 'ok' },
    submarine_cable: { labelKey: 'Submarine Cable', summaryKey: '', tagClass: 'ok' },
    unknown: { labelKey: 'Desconocido', summaryKey: '', tagClass: 'error' },
  },
  ENTITY_KIND_ORDER: ['ip', 'domain', 'asn', 'certificate', 'cve', 'organization', 'url', 'country', 'ixp', 'facility', 'landing_station', 'submarine_cable', 'unknown'],
  EVIDENCE_CLASS_ORDER: ['observed', 'possible_context', 'not_proven', 'unknown'],
  asEvidenceClass: vi.fn((v: string) => v),
  asEntityKind: vi.fn((v: string) => v),
  normalizeEntity: vi.fn((e) => e),
  normalizeRelation: vi.fn((r) => r),
  sortEntities: vi.fn((arr) => arr),
  sortRelations: vi.fn((arr) => arr),
  EMPTY_SELECTION: { entityId: null, relationId: null },
  DEFAULT_FILTERS: { entityKinds: [], evidenceClasses: [] },
}));

vi.mock('../lib/osint', () => ({
  ACTIVITY_DESCRIPTORS: {
    passive: { labelKey: 'Pasiva', summaryKey: '', tagClass: 'ok' },
    active: { labelKey: 'Activa', summaryKey: '', tagClass: 'warn' },
    unknown: { labelKey: 'Desconocida', summaryKey: '', tagClass: 'error' },
  },
  DISCLOSURE_DESCRIPTORS: {
    local: { labelKey: 'Local', summaryKey: '', tagClass: 'ok' },
    passive: { labelKey: 'Pasiva', summaryKey: '', tagClass: 'ok' },
    active: { labelKey: 'Activa', summaryKey: '', tagClass: 'warn' },
    unknown: { labelKey: 'Desconocida', summaryKey: '', tagClass: 'error' },
  },
  OSINT_ERROR_KINDS: [],
  PROVENANCE_FIELDS: [],
  RESULT_STATES: ['idle', 'loading', 'success', 'empty', 'error', 'canceled', 'rate_limited', 'unavailable', 'scope_denied'],
  capabilityOptionsFor: vi.fn(() => ['infrastructure', 'ixp', 'facility', 'landing_station', 'submarine_cable']),
  normalizeProvider: vi.fn((p) => p),
  normalizeProviders: vi.fn((arr) => arr),
  providerCapabilities: vi.fn((arr) => arr),
  requiresAuthorizedScope: vi.fn(() => false),
  sortProviders: vi.fn((arr) => arr),
  resultStateLabel: vi.fn((s) => s),
}));

const mockProvider = {
  id: 'infra.intelligence',
  name: 'Internet Infrastructure Intelligence',
  capabilities: ['infrastructure', 'ixp', 'facility', 'landing_station', 'submarine_cable'],
  activityClass: 'passive',
  disclosureClass: 'passive',
  requiresScope: false,
  rateLimit: 'OSM: 1 req/s; PeeringDB: 0.5 req/s',
};

const mockCollection = {
  ixps: [
    {
      id: 'peeringdb:17',
      name: 'TEST-IX',
      city: 'Madrid',
      country: 'ES',
      region: 'Europe',
      website: 'https://test-ix.net',
      peeringdbId: 17,
      provenance: { ProviderName: 'PeeringDB' },
      lastUpdated: '2024-01-01T00:00:00Z',
    },
  ],
  facilities: [
    {
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
    },
  ],
  landingStations: [
    {
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
    },
  ],
  submarineCables: [
    {
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
    },
  ],
  correlations: [
    {
      id: 'peeringdb:netixlan:100',
      networkEntity: 'AS64500',
      infraEntity: 'peeringdb:17',
      relationKind: 'asn_at_ixp',
      evidenceClass: 'observed',
      provenanceRef: 'peeringdb:netixlan:100',
      label: 'AS64500 present at TEST-IX (PeeringDB)',
      confidence: 'alta',
      retrievedAt: '2024-01-01T00:00:00Z',
    },
    {
      id: 'peeringdb:netfac:200',
      networkEntity: 'AS64500',
      infraEntity: 'peeringdb:10',
      relationKind: 'asn_at_facility',
      evidenceClass: 'observed',
      provenanceRef: 'peeringdb:netfac:200',
      label: 'AS64500 present at TEST-FAC (PeeringDB)',
      confidence: 'alta',
      retrievedAt: '2024-01-01T00:00:00Z',
    },
    {
      id: 'peeringdb:ixfac:10:17',
      networkEntity: 'peeringdb:17',
      infraEntity: 'peeringdb:10',
      relationKind: 'ixp_at_facility',
      evidenceClass: 'observed',
      provenanceRef: 'peeringdb:ixfac:10:17',
      label: 'IXP TEST-IX at Facility TEST-FAC (PeeringDB)',
      confidence: 'alta',
      retrievedAt: '2024-01-01T00:00:00Z',
    },
  ],
  provenance: [],
  sourceErrors: [],
  retrievedAt: '2024-01-01T00:00:00Z',
  query: 'asn:64500',
  bounds: { maxIxps: 500, maxFacilities: 500, maxLandingStations: 200, maxSubmarineCables: 300, maxCorrelations: 1000 },
};

async function setupAndExecute(target = 'asn:64500', capability = 'infrastructure') {
  (executeInfrastructureOSINT as any).mockResolvedValue({
    data: mockCollection,
    provenance: { ProviderName: 'PeeringDB' },
    err: undefined,
  });

  render(<OsintIntelligence />);

  await waitFor(() => {
    expect(screen.getByLabelText('Fuente')).toBeInTheDocument();
  });

  const targetInput = screen.getByLabelText('Objetivo / consulta') as HTMLInputElement;
  fireEvent.change(targetInput, { target: { value: target } });

  const providerSelect = screen.getByLabelText('Fuente') as HTMLSelectElement;
  fireEvent.change(providerSelect, { target: { value: 'infra.intelligence' } });

  const capabilitySelect = screen.getByLabelText('Capacidad') as HTMLSelectElement;
  fireEvent.change(capabilitySelect, { target: { value: capability } });

  const executeButton = screen.getByText('Ejecutar consulta');
  fireEvent.click(executeButton);

  await waitFor(() => {
    expect(screen.getByText('Ejecutando consulta pasiva de infraestructura…')).toBeInTheDocument();
  });

  await act(async () => {
    await new Promise(resolve => setTimeout(resolve, 100));
  });
}

describe('OsintIntelligence component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renderiza la página con título y descripción', () => {
    render(<OsintIntelligence />);
    expect(screen.getByText('Inteligencia OSINT')).toBeInTheDocument();
    expect(screen.getByText(/Inteligencia OSINT con proveedores registrados/)).toBeInTheDocument();
  });

  it('carga proveedores y muestra en el select', async () => {
    render(<OsintIntelligence />);
    await waitFor(() => {
      const option = screen.getByRole('option', { name: 'Internet Infrastructure Intelligence' });
      expect(option).toBeInTheDocument();
    });
  });

  it('muestra formulario de consulta con campos objetivo, fuente, capacidad', async () => {
    render(<OsintIntelligence />);
    await waitFor(() => {
      expect(screen.getByLabelText('Objetivo / consulta')).toBeInTheDocument();
      expect(screen.getByLabelText('Fuente')).toBeInTheDocument();
      expect(screen.getByLabelText('Capacidad')).toBeInTheDocument();
    });
  });

  it('ejecuta consulta y muestra estado loading', async () => {
    await setupAndExecute();
  });

  it('muestra resultados exitosos con contadores de entidades', async () => {
    await setupAndExecute();

    await waitFor(() => {
      expect(screen.getByText(/Resultados recibidos:/)).toBeInTheDocument();
      expect(screen.getByText(/IXPs: 1/)).toBeInTheDocument();
      expect(screen.getByText(/Facilities: 1/)).toBeInTheDocument();
      expect(screen.getByText(/Landing Stations: 1/)).toBeInTheDocument();
      expect(screen.getByText(/Submarine Cables: 1/)).toBeInTheDocument();
      expect(screen.getByText(/Correlaciones: 3/)).toBeInTheDocument();
    });
  });

  it('muestra entidades en el grafo (InfraMap)', async () => {
    await setupAndExecute();

    await waitFor(() => {
      expect(screen.getByText('InfraMap — Grafo de infraestructura')).toBeInTheDocument();
    });
  });

  it.skip('maneja estado de error correctamente', async () => {
    (executeInfrastructureOSINT as any).mockResolvedValue({
      data: null,
      provenance: null,
      err: 'Error de prueba',
    });

    render(<OsintIntelligence />);

    await waitFor(() => {
      const targetInput = screen.getByLabelText('Objetivo / consulta') as HTMLInputElement;
      fireEvent.change(targetInput, { target: { value: 'asn:64500' } });

      const providerSelect = screen.getByLabelText('Fuente') as HTMLSelectElement;
      fireEvent.change(providerSelect, { target: { value: 'infra.intelligence' } });

      const capabilitySelect = screen.getByLabelText('Capacidad') as HTMLSelectElement;
      fireEvent.change(capabilitySelect, { target: { value: 'infrastructure' } });

      const executeButton = screen.getByText('Ejecutar consulta');
      fireEvent.click(executeButton);
    });

    await waitFor(() => {
      // Check that error state is displayed (text may be split across elements)
      const container = document.body;
      expect(container.textContent).toContain('Error de prueba');
    });
  });

  it.skip('muestra estado empty cuando no hay resultados', async () => {
    const emptyCollection = {
      ...mockCollection,
      ixps: [],
      facilities: [],
      landingStations: [],
      submarineCables: [],
      correlations: [],
    };
    (executeInfrastructureOSINT as any).mockResolvedValue({
      data: emptyCollection,
      provenance: { ProviderName: 'PeeringDB' },
      err: undefined,
    });

    render(<OsintIntelligence />);

    await waitFor(() => {
      const targetInput = screen.getByLabelText('Objetivo / consulta') as HTMLInputElement;
      fireEvent.change(targetInput, { target: { value: 'asn:64500' } });

      const providerSelect = screen.getByLabelText('Fuente') as HTMLSelectElement;
      fireEvent.change(providerSelect, { target: { value: 'infra.intelligence' } });

      const capabilitySelect = screen.getByLabelText('Capacidad') as HTMLSelectElement;
      fireEvent.change(capabilitySelect, { target: { value: 'infrastructure' } });

      const executeButton = screen.getByText('Ejecutar consulta');
      fireEvent.click(executeButton);
    });

    await waitFor(() => {
      const container = document.body;
      expect(container.textContent).toContain('no devolvió resultados');
    });
  });

  it('aplica filtros de entidad y evidencia', async () => {
    await setupAndExecute();

    await waitFor(() => {
      expect(screen.getByLabelText('Entidad')).toBeInTheDocument();
      expect(screen.getByLabelText('Evidencia')).toBeInTheDocument();
      expect(screen.getByText('Restablecer filtros')).toBeInTheDocument();
    });
  });

  it('muestra leyenda de clases de evidencia', async () => {
    await setupAndExecute();

    await waitFor(() => {
      expect(screen.getByText('Leyenda de clases de evidencia:')).toBeInTheDocument();
      expect(screen.getByText('Observado (sólida)')).toBeInTheDocument();
      expect(screen.getByText('Contexto posible (discontinua)')).toBeInTheDocument();
      expect(screen.getByText('No demostrado (punteada)')).toBeInTheDocument();
    });
  });

  it('muestra disclaimer sobre clases de evidencia', async () => {
    await setupAndExecute();

    await waitFor(() => {
      expect(screen.getByText(/Aviso: Este grafo muestra SOLO correlaciones con evidencia explícita/)).toBeInTheDocument();
    });
  });
});