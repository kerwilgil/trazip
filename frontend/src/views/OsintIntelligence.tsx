import { useEffect, useMemo, useState } from 'react';
import { listOsintProviders } from '../lib/api';
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

// OSINT Intelligence workspace (V1.5-4).
//
// This surface exposes the V1.5-2 OSINT foundation: it lists the providers in
// the backend Registry with their real metadata, and lays out — but does not
// run — the query, results and provenance areas. There are no real external
// providers and no execution API yet; the empty Registry is the expected
// state. Passive/active separation, capability gating and scope authorization
// are enforced by the Go Executor + ScopeGuard, never by this view.
// Entity Graph (V1.5-4) visualizes explicit entity relationships — no inference.
export default function OsintIntelligence() {
  const { t } = useI18n();
  const [state, setState] = useState<MetadataState>('idle');
  const [providers, setProviders] = useState<OsintProvider[]>([]);
  const [target, setTarget] = useState('');
  const [providerId, setProviderId] = useState('');
  const [capability, setCapability] = useState('');

  // Entity Graph state (V1.5-4) — empty in this version, no runtime data
  const [graphZoom, setGraphZoom] = useState(1);
  const [graphViewBox, setGraphViewBox] = useState<EntityGraphViewBox>({
    x: 0,
    y: 0,
    width: 800,
    height: 600,
  });
  const [selection, setSelection] = useState<EntityGraphSelection>(EMPTY_SELECTION);
  const [filters, setFilters] = useState<EntityGraphFilters>(DEFAULT_FILTERS);

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

  // Empty entity graph in V1.5-4 — no runtime data yet
  const emptyEntities: OsintEntity[] = [];
  const emptyRelations: OsintRelation[] = [];

  const layout = useMemo(
    () => buildEntityGraphLayout(emptyEntities, emptyRelations),
    [],
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

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Inteligencia OSINT')}</h2>
        <p className="body-text">
          {t(
            'Fundación de inteligencia OSINT: los proveedores registrados en el backend y su metadata real. Esta versión no integra proveedores externos ni ejecuta consultas — el registro vacío es el estado esperado. La separación pasivo/activo, el control de capacidades y la autorización de alcance los aplica el backend (Executor y ScopeGuard), no esta pantalla.',
          )}
        </p>
      </div>

      {/* ---- Query workspace (laid out, not executable in this version) ---- */}
      <section className="card" aria-labelledby="osint-query-h">
        <h3 id="osint-query-h">{t('Consulta')}</h3>
        <div className="field-grid cols-2" style={{ marginTop: 4 }}>
          <label>
            {t('Objetivo / consulta')}
            <input
              className="input mono"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={t('IP, dominio, ASN, CVE…')}
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
            <button className="btn" type="button" disabled aria-disabled="true">
              {t('Ejecutar consulta')}
            </button>
          </label>
        </div>
        <p className="note" style={{ marginTop: 12 }}>
          {t(
            'La ejecución de proveedores OSINT llega en una fase posterior. Aquí solo se muestra la metadata registrada.',
          )}
        </p>
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

      {/* ---- Results area (prepared, not executed) ---- */}
      <section className="card" aria-labelledby="osint-results-h" style={{ marginTop: 16 }}>
        <h3 id="osint-results-h">{t('Resultados')}</h3>
        <p className="dim" style={{ marginTop: 4 }}>
          {t(
            'Área preparada para presentar el resultado de una consulta y sus estados. No se simula ningún resultado en esta versión.',
          )}
        </p>
        <div className="list-reset" style={{ marginTop: 10 }}>
          {RESULT_STATES.map((s) => (
            <div className="kv" key={s}>
              <span className="k">{t(resultStateLabel(s))}</span>
              <span className="v" style={{ fontFamily: 'inherit', color: 'var(--text-faint)' }}>
                {t('preparado')}
              </span>
            </div>
          ))}
        </div>
      </section>

      {/* ---- Provenance area (prepared) ---- */}
      <section className="card" aria-labelledby="osint-prov-h" style={{ marginTop: 16 }}>
        <h3 id="osint-prov-h">{t('Procedencia')}</h3>
        <p className="dim" style={{ marginTop: 4 }}>
          {t(
            'Cada resultado exitoso llevará su procedencia. El endpoint se mostrará saneado y nunca se muestran tokens ni credenciales.',
          )}
        </p>
        <div className="list-reset" style={{ marginTop: 10 }}>
          {PROVENANCE_FIELDS.map((f) => (
            <div className="kv" key={f.id}>
              <span className="k">{t(f.labelKey)}</span>
              <span className="v" style={{ fontFamily: 'inherit', color: 'var(--text-faint)' }}>
                {t('preparado')}
              </span>
            </div>
          ))}
        </div>
      </section>

      {/* ---- Error presentation reference (prepared) ---- */}
      <section className="card" aria-labelledby="osint-errors-h" style={{ marginTop: 16 }}>
        <h3 id="osint-errors-h">{t('Errores contemplados')}</h3>
        <p className="dim" style={{ marginTop: 4 }}>
          {t(
            'Estados de error que la interfaz mostrará de forma legible cuando exista ejecución. No se provocan en esta versión.',
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

      {/* ---- Entity Graph (V1.5-4) ---- */}
      <section className="card" aria-labelledby="osint-graph-h" style={{ marginTop: 16 }}>
        <h3 id="osint-graph-h">{t('Grafo de entidades')}</h3>
        <p className="dim" style={{ marginTop: 4 }}>
          {t(
            'Visualización de relaciones entre entidades OSINT. Cada edge declara explícitamente su clase de evidencia (Observado / Contexto posible / No demostrado). No hay inferencia automática. El grafo vacío es el estado esperado en esta versión.',
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
            aria-label={emptyEntities.length === 0 ? t('No hay entidades OSINT para visualizar todavía.') : t('Grafo de entidades OSINT')}
          >
            {emptyEntities.length === 0 ? (
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
                  {t('No hay entidades OSINT para visualizar todavía.')}
                </p>
                <p className="dim" style={{ textAlign: 'center', maxWidth: 320, marginTop: 8 }}>
                  {t('Cuando existan resultados OSINT con relaciones explícitas, aparecerán aquí. No se muestran datos de ejemplo.')}
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
                  {emptyRelations.map((rel) => {
                    const fromNode = layout.nodes.find((n) => n.id === rel.from);
                    const toNode = layout.nodes.find((n) => n.id === rel.to);
                    if (!fromNode || !toNode) return null;
                    const endpoints = entityEdgeEndpoints(fromNode, toNode, layout.nodeWidth, layout.nodeHeight);
                    const lanes = entityEdgeLaneOffsets([rel]);
                    const laneOffset = lanes.get(`${rel.from}-${rel.to}-${rel.kind}`) ?? 0;
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
                  {emptyEntities.map((entity) => {
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
                onClick={handleResetView}
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
              {selection.entityId && (
                <div>
                  <strong>{t('Entidad')}: {selection.entityId}</strong>
                  <p className="dim" style={{ marginTop: 4 }}>
                    {t('Selecciona una entidad en el grafo para ver sus atributos y relaciones.')}
                  </p>
                </div>
              )}
              {selection.relationId && (
                <div>
                  <strong>{t('Relación')}: {selection.relationId}</strong>
                  <p className="dim" style={{ marginTop: 4 }}>
                    {t('Selecciona una relación en el grafo para ver su evidencia y provenance.')}
                  </p>
                </div>
              )}
            </div>
          )}
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
