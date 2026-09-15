import { useEffect, useMemo, useRef, useState } from 'react';
import { executeOSINT, listOsintProviders } from '../lib/api';
import { useI18n } from '../lib/i18n';
import {
  ACTIVITY_DESCRIPTORS,
  DISCLOSURE_DESCRIPTORS,
  OSINT_ERROR_KINDS,
  PROVENANCE_FIELDS,
  RESULT_STATES,
  capabilityOptionsFor,
  normalizeProviders,
  requiresAuthorizedScope,
  type MetadataState,
  type OsintProvider,
} from '../lib/osint';
import {
  ENTITY_GRAPH_MAX_ZOOM,
  ENTITY_GRAPH_MIN_ZOOM,
  ENTITY_GRAPH_ZOOM_STEP,
  buildEntityGraphLayout,
  clampEntityGraphZoom,
  entityEdgeCurve,
  entityEdgeEndpoints,
  entityEdgeLaneOffsets,
  entityGraphViewBox,
  fitEntityGraphViewBox,
  filterEntities,
  filterRelations,
  type EntityGraphFilters,
  type EntityGraphSelection,
  type EntityGraphViewBox,
  type EntityLayoutNode,
  type EntityGraphLayout,
  type OsintEntity,
  type OsintRelation,
  EVIDENCE_DESCRIPTORS,
  ENTITY_KIND_DESCRIPTORS,
  EVIDENCE_CLASS_ORDER,
  ENTITY_KIND_ORDER,
  EMPTY_SELECTION,
  DEFAULT_FILTERS,
} from '../lib/entityGraph';
import { asEvidenceClass, asEntityKind } from '../lib/entityGraph';

// OSINT Intelligence workspace (V1.5-6).
//
// This surface exposes the V1.5-2 OSINT foundation: it lists the providers in
// the backend Registry with their real metadata, and provides execution via
// the Executor (ExecuteOSINT) for passive infrastructure intelligence.
// Entity Graph (V1.5-4) visualizes explicit entity relationships — no inference.
export default function OsintIntelligence() {
  const { t } = useI18n();
  const [state, setState] = useState<MetadataState>('idle');
  const [providers, setProviders] = useState<OsintProvider[]>([]);
  const [target, setTarget] = useState('');
  const [providerId, setProviderId] = useState('');
  const [capability, setCapability] = useState('');

  // Execution state
  const [execState, setExecState] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [execError, setExecError] = useState<string>('');
  const [execData, setExecData] = useState<any>(null);
  const [execProvenance, setExecProvenance] = useState<any>(null);

  // Entity Graph state (V1.5-4) — populated from infrastructure intelligence results
  const [graphZoom, setGraphZoom] = useState(1);
  const [graphViewBox, setGraphViewBox] = useState<EntityGraphViewBox>({
    x: 0,
    y: 0,
    width: 800,
    height: 600,
  });
  const [selection, setSelection] = useState<EntityGraphSelection>(EMPTY_SELECTION);
  const [filters, setFilters] = useState<EntityGraphFilters>(DEFAULT_FILTERS);
  const graphContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let alive = true;
    setState('loading');
    listOsintProviders()
      .then((raw) => {
        if (!alive) return;
        setProviders(normalizeProviders(raw));
        setState('ready');
      })
      .catch((e) => {
        if (!alive) return;
        setState('error');
      });
    return () => {
      alive = false;
    };
  }, []);

  const capabilityOptions = useMemo(
    () => capabilityOptionsFor(providerId, providers),
    [providerId, providers],
  );

  // Keep the capability selection coherent with the chosen provider: a
  // provider only ever offers the capabilities its own metadata declares.
  useEffect(() => {
    if (capability && !capabilityOptions.includes(capability)) setCapability('');
  }, [capability, capabilityOptions]);

  // Convert infrastructure collection to entity graph data
  const { entities: infraEntities, relations: infraRelations } = useMemo(() => {
    if (!execData) return { entities: [] as OsintEntity[], relations: [] as OsintRelation[] };

    const entities: OsintEntity[] = [];
    const relations: OsintRelation[] = [];

    // Process IXPs
    if (execData.ixps) {
      for (const ixp of execData.ixps) {
        entities.push({
          id: ixp.id,
          kind: asEntityKind('ixp'),
          label: ixp.name,
          value: ixp.name,
          attributes: {
            city: ixp.city,
            country: ixp.country,
            region: ixp.region || '',
            website: ixp.website || '',
            source: ixp.provenance?.ProviderName || 'unknown',
          },
        });
      }
    }

    // Process Facilities
    if (execData.facilities) {
      for (const fac of execData.facilities) {
        entities.push({
          id: fac.id,
          kind: asEntityKind('facility'),
          label: fac.name,
          value: fac.name,
          attributes: {
            city: fac.city,
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

    // Process Landing Stations
    if (execData.landingStations) {
      for (const ls of execData.landingStations) {
        entities.push({
          id: ls.id,
          kind: asEntityKind('landing_station'),
          label: ls.name,
          value: ls.name,
          attributes: {
            city: ls.city,
            country: ls.country,
            region: ls.region || '',
            cables: (ls.cables || []).join(', '),
            source: ls.provenance?.ProviderName || 'unknown',
          },
        });
      }
    }

    // Process Submarine Cables
    if (execData.submarineCables) {
      for (const cable of execData.submarineCables) {
        entities.push({
          id: cable.id,
          kind: asEntityKind('submarine_cable'),
          label: cable.name,
          value: cable.name,
          attributes: {
            owners: (cable.owners || []).join(', '),
            lengthKm: cable.lengthKm?.toString() || '',
            rfs: cable.rfs || '',
            fiberPairs: cable.fiberPairs?.toString() || '',
            designCapacity: cable.designCapacity || '',
            source: cable.provenance?.ProviderName || 'unknown',
          },
        });
      }
    }

    // Process Correlations
    if (execData.correlations) {
      for (const corr of execData.correlations) {
        relations.push({
          id: corr.id,
          from: corr.networkEntity,
          to: corr.infraEntity,
          kind: corr.relationKind,
          directed: false,
          evidenceClass: asEvidenceClass(corr.evidenceClass),
          provenanceRef: corr.provenanceRef,
          label: corr.label,
        });
      }
    }

    return { entities, relations };
  }, [execData]);

  // Apply filters to derive renderable data
  const filteredEntities = useMemo(
    () => filterEntities(infraEntities, filters),
    [infraEntities, filters],
  );
  const entitySet = useMemo(
    () => new Set(filteredEntities.map((e) => e.id)),
    [filteredEntities],
  );
  const filteredRelations = useMemo(
    () => filterRelations(infraRelations, filters, entitySet),
    [infraRelations, filters, entitySet],
  );

  const layout = useMemo(
    () => buildEntityGraphLayout(filteredEntities, filteredRelations),
    [filteredEntities, filteredRelations],
  );

  // Pre-compute lane offsets for all filtered relations (batch processing)
  const laneOffsets = useMemo(
    () => entityEdgeLaneOffsets(filteredRelations),
    [filteredRelations],
  );

  const handleZoomIn = () => {
    const next = clampEntityGraphZoom(graphZoom + ENTITY_GRAPH_ZOOM_STEP);
    setGraphZoom(next);
    setGraphViewBox(entityGraphViewBox(layout.width, layout.height, next));
  };

  const handleZoomOut = () => {
    const next = clampEntityGraphZoom(graphZoom - ENTITY_GRAPH_ZOOM_STEP);
    setGraphZoom(next);
    setGraphViewBox(entityGraphViewBox(layout.width, layout.height, next));
  };

  const handleFitView = () => {
    // Use actual container dimensions via ref
    const container = graphContainerRef.current;
    if (!container) return;
    const containerWidth = container.clientWidth;
    const containerHeight = container.clientHeight;
    if (containerWidth <= 0 || containerHeight <= 0) return;
    const vb = fitEntityGraphViewBox(layout, containerWidth, containerHeight);
    setGraphZoom(clampEntityGraphZoom(
      Math.min(containerWidth / vb.width, containerHeight / vb.height)
    ));
    setGraphViewBox(vb);
  };

  const handleResetView = () => {
    setGraphZoom(1);
    setGraphViewBox(entityGraphViewBox(layout.width, layout.height, 1));
  };

  const handleWheel = (e: React.WheelEvent) => {
    if (!e.ctrlKey && !e.metaKey) return;
    e.preventDefault();
    const next = clampEntityGraphZoom(graphZoom - e.deltaY * 0.001);
    setGraphZoom(next);
    setGraphViewBox(entityGraphViewBox(layout.width, layout.height, next));
  };

  const handleCanvasClick = () => {
    setSelection(EMPTY_SELECTION);
  };

  // Keyboard activation handler for accessible selection
  const handleKeyDown = (e: React.KeyboardEvent, onActivate: () => void) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onActivate();
    }
  };

  // Execute OSINT query
  const handleExecute = async () => {
    if (!providerId || !capability || !target.trim()) return;

    setExecState('loading');
    setExecError('');
    setExecData(null);
    setExecProvenance(null);

    try {
      const result = await executeOSINT(providerId, capability, target.trim());
      if (result.err) {
        setExecState('error');
        setExecError(result.err);
      } else {
        setExecState('success');
        setExecData(result.data);
        setExecProvenance(result.provenance);
      }
    } catch (e) {
      setExecState('error');
      setExecError(e instanceof Error ? e.message : 'Error desconocido');
    }
  };

  // Selection detail renderers
  const renderEntityDetails = () => {
    if (!selection.entityId) return null;
    const entity = filteredEntities.find((e) => e.id === selection.entityId);
    if (!entity) return null;
    const kindDesc = ENTITY_KIND_DESCRIPTORS[entity.kind];
    const relatedRelations = filteredRelations.filter((r) => r.from === entity.id || r.to === entity.id);
    return (
      <div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap', marginBottom: 8 }}>
          <strong>{t('Entidad')}: {entity.id}</strong>
          <span className={`tag ${kindDesc.tagClass}`}>{t(kindDesc.labelKey)}</span>
        </div>
        <div className="kv" style={{ marginBottom: 4 }}>
          <span className="k">{t('Valor')}</span>
          <span className="v mono">{entity.value}</span>
        </div>
        <div className="kv" style={{ marginBottom: 4 }}>
          <span className="k">{t('ID')}</span>
          <span className="v mono" style={{ fontSize: 10 }}>{entity.id}</span>
        </div>
        {Object.keys(entity.attributes).length > 0 && (
          <div className="kv" style={{ marginBottom: 4 }}>
            <span className="k">{t('Atributos')}</span>
            <span className="v mono" style={{ fontSize: 10 }}>
              {Object.entries(entity.attributes).map(([k, v]) => `${k}=${v}`).join(', ')}
            </span>
          </div>
        )}
        <div className="kv" style={{ marginBottom: 4 }}>
          <span className="k">{t('Relaciones asociadas')}</span>
          <span className="v" style={{ fontSize: 11 }}>
            {relatedRelations.length === 0
              ? t('Ninguna')
              : relatedRelations.map((r) => (
                  <span key={r.id} style={{ marginRight: 8, fontFamily: 'monospace', fontSize: 10 }}>
                    {r.from} → {r.to} ({t(EVIDENCE_DESCRIPTORS[r.evidenceClass].labelKey)})
                  </span>
                ))}
          </span>
        </div>
      </div>
    );
  };

  const renderRelationDetails = () => {
    if (!selection.relationId) return null;
    const rel = filteredRelations.find((r) => r.id === selection.relationId);
    if (!rel) return null;
    const fromEntity = filteredEntities.find((e) => e.id === rel.from);
    const toEntity = filteredEntities.find((e) => e.id === rel.to);
    const desc = EVIDENCE_DESCRIPTORS[rel.evidenceClass];
    return (
      <div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap', marginBottom: 8 }}>
          <strong>{t('Relación')}: {rel.id}</strong>
          <span className={`tag ${desc.tagClass}`}>{t(desc.labelKey)}</span>
        </div>
        <div className="kv" style={{ marginBottom: 4 }}>
          <span className="k">{t('Tipo de relación')}</span>
          <span className="v mono">{rel.kind}</span>
        </div>
        <div className="kv" style={{ marginBottom: 4 }}>
          <span className="k">{t('Desde')}</span>
          <span className="v">{rel.from}{fromEntity ? ` (${fromEntity.value})` : ''}</span>
        </div>
        <div className="kv" style={{ marginBottom: 4 }}>
          <span className="k">{t('Hasta')}</span>
          <span className="v">{rel.to}{toEntity ? ` (${toEntity.value})` : ''}</span>
        </div>
        <div className="kv" style={{ marginBottom: 4 }}>
          <span className="k">{t('Dirigida')}</span>
          <span className="v">{rel.directed ? t('Sí') : t('No')}</span>
        </div>
        <div className="kv" style={{ marginBottom: 4 }}>
          <span className="k">{t('Evidencia')}</span>
          <span className="v">{t(desc.labelKey)}</span>
        </div>
        <div className="kv" style={{ marginBottom: 4 }}>
          <span className="k">{t('Provenance')}</span>
          <span className="v mono" style={{ fontSize: 10 }}>
            {rel.provenanceRef || t('No disponible')}
          </span>
        </div>
        {rel.label && (
          <div className="kv" style={{ marginBottom: 4 }}>
            <span className="k">{t('Etiqueta')}</span>
            <span className="v">{rel.label}</span>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Inteligencia OSINT')}</h2>
        <p className="body-text">
          {t(
            'Inteligencia OSINT con proveedores registrados y ejecución de consultas pasivas (V1.5-6). ' +
            'Infraestructura de Internet: IXPs, facilities, cable landing stations, cables submarinos. ' +
            'La separación pasivo/activo, el control de capacidades y la autorización de alcance los aplica el backend (Executor y ScopeGuard).'
          )}
        </p>
      </div>

      {/* ---- Query workspace (executable in V1.5-6) ---- */}
      <section className="card" aria-labelledby="osint-query-h">
        <h3 id="osint-query-h">{t('Consulta')}</h3>
        <div className="field-grid cols-2" style={{ marginTop: 4 }}>
          <label>
            {t('Objetivo / consulta')}
            <input
              className="input mono"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={t('Ej: country:ES, city:Madrid, asn:12345, bbox:...')}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <label>
            {t('Fuente')}
            <select
              value={providerId}
              onChange={(e) => {
                setProviderId(e.target.value);
                setCapability('');
              }}
              disabled={providers.length === 0}
            >
              <option value="">
                {providers.length === 0 ? t('Sin fuentes disponibles') : t('Selecciona una fuente')}
              </option>
              {providers.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            {t('Capacidad')}
            <select
              value={capability}
              onChange={(e) => setCapability(e.target.value)}
              disabled={capabilityOptions.length === 0}
            >
              <option value="">
                {capabilityOptions.length === 0
                  ? t('Elige primero una fuente')
                  : t('Selecciona una capacidad')}
              </option>
              {capabilityOptions.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </label>
          <label>
            {' '}
            <button className="btn" type="button" onClick={handleExecute} disabled={execState === 'loading'}>
              {execState === 'loading' ? t('Ejecutando…') : t('Ejecutar consulta')}
            </button>
          </label>
        </div>
        <p className="note" style={{ marginTop: 12 }}>
          {t(
            'Formatos de consulta soportados: country:CC, city:CityName,CC, bbox:south,west,north,east, asn:NUMBER, peeringdb:ix:NUMBER, osm:TYPE/ID. ' +
            'Las consultas sin contexto geográfico explícito son rechazadas para evitar búsquedas globales.'
          )}
        </p>

        {/* Execution status */}
        {execState === 'loading' && (
          <div className="note" role="status" aria-live="polite" style={{ marginTop: 8 }}>
            {t('Ejecutando consulta pasiva de infraestructura…')}
          </div>
        )}
        {execState === 'error' && (
          <div className="note" role="alert" style={{ marginTop: 8 }}>
            {t('Error:')} {execError}
          </div>
        )}
{execState === 'success' && execData && (
            <div className="note" style={{ marginTop: 8 }}>
              {t('Resultados recibidos:')} {t('IXPs')}: {execData.ixps?.length || 0}, {t('Facilities')}: {execData.facilities?.length || 0}, {t('Landing Stations')}: {execData.landingStations?.length || 0}, {t('Submarine Cables')}: {execData.submarineCables?.length || 0}, {t('Correlaciones')}: {execData.correlations?.length || 0}
            </div>
          )}
      </section>

      {/* ---- Registered providers (real metadata) ---- */}
      <section className="card" aria-labelledby="osint-sources-h" style={{ marginTop: 16 }}>
        <h3 id="osint-sources-h">{t('Fuentes registradas')}</h3>

        {state === 'loading' && (
          <p className="dim" role="status" aria-live="polite" style={{ marginTop: 8 }}>
            {t('Cargando metadata de fuentes OSINT…')}
          </p>
        )}

        {state === 'error' && (
          <div className="note" role="alert" style={{ marginTop: 8 }}>
            {t('No se pudo cargar la metadata de fuentes OSINT.')}
          </div>
        )}

        {state === 'ready' && providers.length === 0 && (
          <div className="empty" style={{ marginTop: 8 }}>
            <div className="big" aria-hidden="true">
              ∅
            </div>
            <p>{t('No hay fuentes OSINT registradas todavía.')}</p>
          </div>
        )}

        {state === 'ready' && providers.length > 0 && (
          <div className="grid cols-2" style={{ marginTop: 12 }}>
            {providers.map((p) => (
              <ProviderCard key={p.id} provider={p} />
            ))}
          </div>
        )}
      </section>

      {/* ---- InfraMap - Entity Graph (V1.5-6) ---- */}
      <section className="card" aria-labelledby="osint-graph-h" style={{ marginTop: 16 }}>
        <h3 id="osint-graph-h">{t('InfraMap — Grafo de infraestructura')}</h3>
        <p className="dim" style={{ marginTop: 4 }}>
          {t(
            'Visualización de entidades de infraestructura de Internet y sus correlaciones explícitas. ' +
            'Cada relación declara su clase de evidencia: Observado (respaldo directo), Contexto posible (plausible pero no demostrado), No demostrado. ' +
            'No hay inferencia automática por proximidad geográfica. Los datos provienen de OpenStreetMap y PeeringDB.'
          )}
        </p>

        <div style={{ marginTop: 12 }}>
          <div className="field-grid cols-3" style={{ marginBottom: 8 }}>
            <label>
              {t('Entidad')}
              <select
                value={filters.entityKinds.join(',')}
                onChange={(e) => {
                  const kinds = e.target.value ? e.target.value.split(',') : [];
                  setFilters({ ...filters, entityKinds: kinds as any });
                }}
                style={{ maxWidth: 240 }}
              >
                <option value="">{t('Todos los tipos')}</option>
                {ENTITY_KIND_ORDER.filter((k) => k !== 'unknown').map((k) => (
                  <option key={k} value={k}>
                    {t(ENTITY_KIND_DESCRIPTORS[k].labelKey)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              {t('Evidencia')}
              <select
                value={filters.evidenceClasses.join(',')}
                onChange={(e) => {
                  const classes = e.target.value ? e.target.value.split(',') : [];
                  setFilters({ ...filters, evidenceClasses: classes as any });
                }}
                style={{ maxWidth: 240 }}
              >
                <option value="">{t('Todas las clases')}</option>
                {EVIDENCE_CLASS_ORDER.filter((c) => c !== 'unknown').map((c) => (
                  <option key={c} value={c}>
                    {t(EVIDENCE_DESCRIPTORS[c].labelKey)}
                  </option>
                ))}
              </select>
            </label>
            <label style={{ alignSelf: 'end' }}>
              <button className="btn" type="button" onClick={() => setFilters(DEFAULT_FILTERS)}>
                {t('Restablecer filtros')}
              </button>
            </label>
          </div>

          <div
            ref={graphContainerRef}
            className="graph-canvas"
            style={{
              position: 'relative',
              width: '100%',
              height: 420,
              border: '1px solid var(--border)',
              borderRadius: 4,
              background: 'var(--surface-2)',
              overflow: 'hidden',
            }}
            onWheel={handleWheel}
            onClick={handleCanvasClick}
            role="img"
            aria-label={filteredEntities.length === 0 ? t('No hay entidades de infraestructura para visualizar. Ejecute una consulta.') : t('InfraMap - Grafo de infraestructura de Internet')}
          >
            {filteredEntities.length === 0 ? (
              <div
                className="empty"
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  height: '100%',
                  padding: 24,
                }}
              >
                <div className="big" aria-hidden="true" style={{ fontSize: 48, marginBottom: 12 }}>
                  ∅
                </div>
                <p style={{ textAlign: 'center', maxWidth: 320 }}>
                  {execState === 'idle'
                    ? t('No hay entidades de infraestructura para visualizar todavía.')
                    : t('La consulta no devolvió resultados.')}
                </p>
                <p className="dim" style={{ textAlign: 'center', maxWidth: 320, marginTop: 8 }}>
                  {execState === 'idle'
                    ? t('Seleccione una fuente, capacidad y objetivo, luego ejecute la consulta.')
                    : t('Intente con una consulta más amplia o diferente contexto geográfico.')}
                </p>
              </div>
            ) : (
              <svg
                viewBox={`${graphViewBox.x} ${graphViewBox.y} ${graphViewBox.width} ${graphViewBox.height}`}
                preserveAspectRatio="xMidYMid meet"
                style={{ width: '100%', height: '100%' }}
              >
                <defs>
                  <marker
                    id="arrowhead"
                    markerWidth={10}
                    markerHeight={7}
                    refX={9}
                    refY={3.5}
                    orient="auto"
                    markerUnits="strokeWidth"
                  >
                    <path d="M0,0 L0,7 L10,3.5 Z" fill="var(--text-dim)" />
                  </marker>
                </defs>
                {/* Edges */}
                <g className="graph-edges">
                  {filteredRelations.map((rel) => {
                    const fromNode = layout.nodes.find((n) => n.id === rel.from);
                    const toNode = layout.nodes.find((n) => n.id === rel.to);
                    if (!fromNode || !toNode) return null;
                    const endpoints = entityEdgeEndpoints(fromNode, toNode, layout.nodeWidth, layout.nodeHeight);
                    const laneOffset = laneOffsets.get(`${rel.from}-${rel.to}-${rel.kind}-${rel.id}`) ?? 0;
                    const desc = EVIDENCE_DESCRIPTORS[rel.evidenceClass];
                    const curve = entityEdgeCurve(endpoints, laneOffset);
                    const isSelected = selection.relationId === rel.id;
                    return (
                      <path
                        key={rel.id}
                        d={curve}
                        stroke={isSelected ? 'var(--accent)' : 'var(--text-dim)'}
                        strokeWidth={isSelected ? 2.5 : 1.5}
                        fill="none"
                        style={{
                          strokeDasharray: desc.edgeStyle === 'dashed' ? '6,4' : desc.edgeStyle === 'dotted' ? '2,4' : 'none',
                        }}
                        markerEnd={rel.directed ? 'url(#arrowhead)' : undefined}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelection({ ...selection, relationId: rel.id, entityId: null });
                        }}
                        onKeyDown={(e) => handleKeyDown(e, () => {
                          e.stopPropagation();
                          setSelection({ ...selection, relationId: rel.id, entityId: null });
                        })}
                        tabIndex={0}
                        role="button"
                        aria-label={`${t('Relación')}: ${t(rel.kind)} — ${t('Desde')}: ${rel.from} — ${t('Hasta')}: ${rel.to} — ${t('Evidencia')}: ${t(desc.labelKey)}`}
                        aria-pressed={isSelected}
                      />
                    );
                  })}
                </g>
                {/* Nodes */}
                <g className="graph-nodes">
                  {filteredEntities.map((entity) => {
                    const node = layout.nodes.find((n) => n.id === entity.id);
                    if (!node) return null;
                    const kindDesc = ENTITY_KIND_DESCRIPTORS[entity.kind];
                    const isSelected = selection.entityId === entity.id;
                    return (
                      <g
                        key={entity.id}
                        transform={`translate(${node.x}, ${node.y})`}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelection({ ...selection, entityId: entity.id, relationId: null });
                        }}
                        onKeyDown={(e) => handleKeyDown(e, () => {
                          e.stopPropagation();
                          setSelection({ ...selection, entityId: entity.id, relationId: null });
                        })}
                        tabIndex={0}
                        role="button"
                        aria-label={`${t('Entidad')}: ${t(kindDesc.labelKey)} — ${t('Valor')}: ${entity.value} — ${t('ID')}: ${entity.id}`}
                        aria-pressed={isSelected}
                        style={{ cursor: 'pointer' }}
                      >
                        <rect
                          x={0}
                          y={0}
                          width={layout.nodeWidth}
                          height={layout.nodeHeight}
                          rx={6}
                          ry={6}
                          fill={isSelected ? 'var(--accent-bg)' : 'var(--surface-3)'}
                          stroke={isSelected ? 'var(--accent)' : 'var(--border)'}
                          strokeWidth={isSelected ? 2 : 1}
                        />
                        <text
                          x={layout.nodeWidth / 2}
                          y={18}
                          textAnchor="middle"
                          dominantBaseline="middle"
                          fill="var(--text-faint)"
                          fontSize={10}
                          fontWeight={600}
                          style={{ textTransform: 'uppercase', letterSpacing: '0.5px' }}
                        >
                          {t(kindDesc.labelKey)}
                        </text>
                        <text
                          x={layout.nodeWidth / 2}
                          y={38}
                          textAnchor="middle"
                          dominantBaseline="middle"
                          fill="var(--text)"
                          fontSize={12}
                          fontFamily="monospace"
                        >
                          {entity.value.length > 24 ? entity.value.slice(0, 21) + '…' : entity.value}
                        </text>
                        <text
                          x={layout.nodeWidth / 2}
                          y={52}
                          textAnchor="middle"
                          dominantBaseline="middle"
                          fill="var(--text-dim)"
                          fontSize={9}
                        >
                          {entity.id}
                        </text>
                      </g>
                    );
                  })}
                </g>
              </svg>
            )}

            {/* Zoom controls */}
            <div
              style={{
                position: 'absolute',
                bottom: 12,
                right: 12,
                display: 'flex',
                gap: 4,
                background: 'var(--surface-3)',
                border: '1px solid var(--border)',
                borderRadius: 4,
                padding: 4,
              }}
            >
              <button
                className="btn"
                type="button"
                onClick={handleZoomOut}
                disabled={graphZoom <= ENTITY_GRAPH_MIN_ZOOM}
                aria-label={t('Alejar')}
                style={{ padding: '4px 8px', fontSize: 14, lineHeight: 1 }}
              >
                −
              </button>
              <span
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  padding: '0 8px',
                  fontSize: 12,
                  fontFamily: 'monospace',
                  color: 'var(--text)',
                }}
              >
                {Math.round(graphZoom * 100)}%
              </span>
              <button
                className="btn"
                type="button"
                onClick={handleZoomIn}
                disabled={graphZoom >= ENTITY_GRAPH_MAX_ZOOM}
                aria-label={t('Acercar')}
                style={{ padding: '4px 8px', fontSize: 14, lineHeight: 1 }}
              >
                +
              </button>
              <button
                className="btn"
                type="button"
                onClick={handleFitView}
                aria-label={t('Ajustar')}
                style={{ padding: '4px 8px', fontSize: 12, lineHeight: 1 }}
              >
                ⌂
              </button>
            </div>
          </div>

          {/* Selection details */}
          {(selection.entityId || selection.relationId) && (
            <div className="card" style={{ marginTop: 12, background: 'var(--surface-2)' }}>
              <h4 style={{ marginBottom: 8 }}>{t('Detalles de selección')}</h4>
              {selection.entityId && renderEntityDetails()}
              {selection.relationId && renderRelationDetails()}
            </div>
          )}

          {/* Evidence Class Legend */}
          <div style={{ marginTop: 12, padding: 8, background: 'var(--surface-2)', borderRadius: 4 }}>
            <strong>{t('Leyenda de clases de evidencia:')}</strong>
            <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginTop: 8, fontSize: 12 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 16, height: 2, background: 'var(--text)', borderBottom: '2px solid var(--text)' }} />
                {t('Observado (sólida)')}
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 16, height: 2, background: 'var(--text)', borderBottom: '2px dashed var(--text)' }} />
                {t('Contexto posible (discontinua)')}
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 16, height: 2, background: 'transparent', borderBottom: '2px dotted var(--text)' }} />
                {t('No demostrado (punteada)')}
              </span>
            </div>
          </div>

          {/* Disclaimer */}
          <div className="note" style={{ marginTop: 12, fontSize: 11 }}>
            {t(
              'Aviso: Este grafo muestra SOLO correlaciones con evidencia explícita. ' +
              'La proximidad geográfica NO implica recorrido de tráfico por cables submarinos. ' +
              'Clases de evidencia: OBSERVED = respaldo directo (PeeringDB); POSSIBLE_CONTEXT = contexto plausible (co-ubicación); NOT_PROVEN = sin evidencia. ' +
              'Fuentes: OpenStreetMap (ODbL), PeeringDB (AUP).'
            )}
          </div>

          {/* Source Errors / Warnings */}
          {execData && execData.sourceErrors && execData.sourceErrors.length > 0 && (
            <div className="note" style={{ marginTop: 12, fontSize: 11, border: '1px solid var(--warn)', background: 'var(--warn-bg)', borderRadius: 4, padding: 8 }}>
              <strong>{t('Advertencias de correlación (resultado parcial):')}</strong>
              <ul style={{ marginTop: 8, marginBottom: 0, paddingLeft: 20 }}>
                {execData.sourceErrors.map((err: any, idx: number) => (
                  <li key={idx} style={{ marginBottom: 4, fontSize: 11 }}>
                    <strong>{err.provider}:{err.operation}</strong> — {err.message} ({err.errorType})
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </section>

      {/* ---- Results area (executed) ---- */}
      <section className="card" aria-labelledby="osint-results-h" style={{ marginTop: 16 }}>
        <h3 id="osint-results-h">{t('Resultados')}</h3>
        {execState === 'success' && execData && (
          <div className="list-reset" style={{ marginTop: 10 }}>
            {RESULT_STATES.map((s) => (
              <div className="kv" key={s}>
                <span className="k">{t(resultStateLabel(s))}</span>
                <span className="v" style={{ fontFamily: 'inherit' }}>
                  {s === 'success' ? t('Datos recibidos y procesados') : t('preparado')}
                </span>
              </div>
            ))}
          </div>
        )}
        {execState === 'idle' && (
          <p className="dim" style={{ marginTop: 4 }}>
            {t('Ejecute una consulta para ver resultados aquí.')}
          </p>
        )}
      </section>

      {/* ---- Provenance area (executed) ---- */}
      <section className="card" aria-labelledby="osint-prov-h" style={{ marginTop: 16 }}>
        <h3 id="osint-prov-h">{t('Procedencia')}</h3>
        {execProvenance && (
          <div className="list-reset" style={{ marginTop: 10 }}>
            {PROVENANCE_FIELDS.map((f) => (
              <div className="kv" key={f.id}>
                <span className="k">{t(f.labelKey)}</span>
                <span className="v mono" style={{ fontSize: 10 }}>
                  {(execProvenance as any)[f.id] || t('—')}
                </span>
              </div>
            ))}
          </div>
        )}
        {!execProvenance && (
          <p className="dim" style={{ marginTop: 4 }}>
            {t('Ejecute una consulta para ver la procedencia completa.')}
          </p>
        )}
      </section>

      {/* ---- Error presentation reference ---- */}
      <section className="card" aria-labelledby="osint-errors-h" style={{ marginTop: 16 }}>
        <h3 id="osint-errors-h">{t('Errores contemplados')}</h3>
        <p className="dim" style={{ marginTop: 4 }}>
          {t(
            'Estados de error que la interfaz muestra de forma legible cuando existe ejecución.'
          )}
        </p>
        <div className="list-reset" style={{ marginTop: 10 }}>
          {OSINT_ERROR_KINDS.map((k) => (
            <div className="kv" key={k.id}>
              <span className="k">{t(k.titleKey)}</span>
              <span className="v" style={{ fontFamily: 'inherit', color: 'var(--text-dim)' }}>
                {t(k.bodyKey)}
              </span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function ProviderCard({ provider }: { provider: OsintProvider }) {
  const { t } = useI18n();
  const act = ACTIVITY_DESCRIPTORS[provider.activityClass];
  const disc = DISCLOSURE_DESCRIPTORS[provider.disclosureClass];
  const needsScope = requiresAuthorizedScope(provider);

  return (
    <div className="card" style={{ background: 'var(--surface-2)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
        <strong style={{ fontSize: 14 }}>{provider.name}</strong>
        <span className="mono dim" style={{ fontSize: 11.5 }}>
          {provider.id}
        </span>
      </div>

      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10 }}>
        <span className={`tag ${act.tagClass}`} title={t(act.summaryKey)} aria-label={`${t('Actividad')}: ${t(act.labelKey)} — ${t(act.summaryKey)}`}>
          {t(act.labelKey)}
        </span>
        <span className={`tag ${disc.tagClass}`} title={t(disc.summaryKey)} aria-label={`${t('Divulgación')}: ${t(disc.labelKey)} — ${t(disc.summaryKey)}`}>
          {t(disc.labelKey)}
        </span>
        {needsScope && (
          <span className="tag warn" aria-label={t('Requiere alcance autorizado')}>
            {t('Requiere alcance autorizado')}
          </span>
        )}
      </div>

      <div className="list-reset" style={{ marginTop: 12 }}>
        <div className="kv">
          <span className="k">{t('Capacidades')}</span>
          <span className="v mono" style={{ overflowWrap: 'anywhere' }}>
            {provider.capabilities.length > 0 ? provider.capabilities.join(', ') : '—'}
          </span>
        </div>
        <div className="kv">
          <span className="k">{t('Actividad')}</span>
          <span className="v" style={{ fontFamily: 'inherit' }}>
            {t(act.labelKey)} · {t(act.summaryKey)}
          </span>
        </div>
        <div className="kv">
          <span className="k">{t('Divulgación')}</span>
          <span className="v" style={{ fontFamily: 'inherit' }}>
            {t(disc.labelKey)} · {t(disc.summaryKey)}
          </span>
        </div>
        <div className="kv">
          <span className="k">{t('Requiere alcance')}</span>
          <span className="v" style={{ fontFamily: 'inherit' }}>
            {needsScope ? t('Sí') : t('No')}
          </span>
        </div>
        {provider.rateLimit && (
          <div className="kv">
            <span className="k">{t('Límite de frecuencia')}</span>
            <span className="v" style={{ fontFamily: 'inherit' }}>
              {provider.rateLimit}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

function resultStateLabel(s: (typeof RESULT_STATES)[number]): string {
  switch (s) {
    case 'idle':
      return 'En espera';
    case 'loading':
      return 'Cargando';
    case 'success':
      return 'Correcto';
    case 'empty':
      return 'Sin datos';
    case 'error':
      return 'Error';
    case 'canceled':
      return 'Cancelado';
    case 'rate_limited':
      return 'Límite de frecuencia';
    case 'unavailable':
      return 'No disponible';
    case 'scope_denied':
      return 'Fuera de alcance';
  }
}