import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import {
  backendAvailable,
  bgpOverview,
  bgpPrefixes,
  bgpSecurity,
  bgpNeighbours,
  bgpTopology,
  startBGPRealtime,
  stopBGPRealtime,
  bgpRealtimeInfo,
  subscribeBGPRealtime,
  bgpHistory,
  bgPlay,
  bgpCountryObservatory,
  bgpGlobalObservatory,
  bgpASNObservatory,
  bgpRPKIObservatory,
  bgpBogonLookup,
  type bgp,
  type BGPPath,
  type BGPOriginResolution,
  type BGPRealtimeEvent,
} from '../lib/api';
import {
  isTerminalRealtimeState,
  appendRealtimeEvent,
  decidePollCommit,
  EMPTY_REALTIME_TIMELINE,
  type RealtimeTimelineState,
} from '../lib/realtimeSession';
import { useI18n } from '../lib/i18n';
import { ariaTabIds, nextTabIndex } from '../lib/tabs';
import { buildTopologyLayout, clampTopologyZoom, sanitizeTopologyFilename, topologyEdgeCurve, topologyEdgeEndpoints, topologyEdgeLaneOffsets, topologyEdgeWidth, TOPOLOGY_MAX_ZOOM, TOPOLOGY_MIN_ZOOM, TOPOLOGY_ZOOM_STEP, topologyViewBox } from '../lib/topologyGraph';

const NO_BACKEND = 'Necesita el runtime Wails (app de escritorio). En el preview del navegador no hay backend.';

type Tab = 'resumen' | 'prefijos' | 'vecinos' | 'topologia' | 'seguridad' | 'realtime' | 'history' | 'bgplay' | 'observatorio';

const TOPOLOGY_PAN_THRESHOLD_PX = 5;

type TopologyPanGesture = {
  pointerId: number;
  x: number;
  y: number;
  panX: number;
  panY: number;
  scaleX: number;
  scaleY: number;
  active: boolean;
};

function BGPErrorNotice({ error }: { error: string }) {
  const { t } = useI18n();
  const isTimeout = /context deadline exceeded|client\.timeout exceeded|i\/o timeout|request timed out/i.test(error);

  // Siempre: primario humano + secundario técnico plegable — nunca un error
  // Go/HTTP crudo como único mensaje visible. El detalle crudo sigue
  // disponible dentro de <details> (transparencia), solo que nunca como
  // mensaje principal.
  return (
    <div className="note bgp-error-notice" role="alert">
      <strong>{isTimeout
        ? t('No se pudo obtener información BGP desde RIPEstat.')
        : t('No se pudo completar la consulta BGP.')}</strong>
      <p>{isTimeout
        ? t('El servicio no respondió dentro del tiempo esperado. Puede ser una demora temporal del servicio externo o de la conexión.')
        : t('La operación no pudo completarse. Amplía los detalles técnicos para ver la causa exacta e inténtalo de nuevo.')}</p>
      <details className="bgp-error-details">
        <summary>{t('Detalles técnicos')}</summary>
        <code>{error}</code>
      </details>
    </div>
  );
}

// ---------------- Tiempo real: constantes y helpers ----------------
// (la lógica pura de timeline/generación de sesión vive en
// lib/realtimeSession.ts — ver su propio doc comment; aquí solo quedan
// helpers puramente de presentación.)

const REALTIME_POLL_MS = 1000;

const REALTIME_STATE_LABEL: Record<string, string> = {
  connecting: 'Conectando',
  connected: 'Conectado',
  reconnecting: 'Reconectando',
  stopping: 'Deteniendo',
  stopped: 'Detenido',
  failed: 'Fallido',
};

// Las etiquetas son claves i18n (español como key, traducibles vía t()).
// Un estado desconocido del backend se muestra crudo — nunca se fabrica
// una etiqueta que prometa certidumbre que no existe.
function realtimeStateLabel(t: (s: string) => string, state: string): string {
  const label = REALTIME_STATE_LABEL[state];
  return label ? t(label) : state;
}

function realtimeStatePillClass(state: string): string {
  switch (state) {
    case 'connected': return 'ok';
    case 'connecting':
    case 'reconnecting': return 'warn';
    case 'failed': return 'danger';
    default: return ''; // stopped/stopping — neutral, ni éxito ni fallo
  }
}

const EVENT_TYPE_LABEL: Record<string, string> = {
  announcement: 'Anuncio',
  withdrawal: 'Retiro',
  path_changed: 'Cambio de AS-path',
  origin_changed: 'Cambio de origen',
  moas_appeared: 'MOAS apareció',
  moas_disappeared: 'MOAS desapareció',
  rpki_transition: 'Transición RPKI',
};

// Igual que realtimeStateLabel: claves i18n, fallback al tipo crudo.
function eventTypeLabel(t: (s: string) => string, type: string): string {
  const label = EVENT_TYPE_LABEL[type];
  return label ? t(label) : type;
}

function eventTypeClass(t: string): string {
  switch (t) {
    case 'withdrawal': return 'warn';
    case 'moas_appeared':
    case 'moas_disappeared':
    case 'rpki_transition': return 'accent-t';
    default: return '';
  }
}

function formatBGPPath(path?: BGPPath): string {
  if (!path || path.length === 0) return '—';
  return path.map((el) => (el.Kind === 'as_set' ? '{' + (el.set || []).map((n) => 'AS' + n).join(', ') + '}' : 'AS' + el.asn)).join(' → ');
}

function formatOrigin(t: (s: string) => string, o?: BGPOriginResolution): string {
  if (!o) return '—';
  if (o.Determinate) return 'AS' + o.ASN;
  return o.Reason ? `${t('indeterminado')} (${o.Reason})` : t('indeterminado');
}

// Nunca "01/01/1970" ni "ahora": Timestamp vacío/no-RFC3339 → "—".
function formatTimestamp(ts?: string): string {
  if (!ts) return '—';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString();
}

// Convierte el valor local de <input type="datetime-local"> (interpretado
// por el navegador como hora LOCAL del usuario — la conversión estándar,
// nunca reinterpretada) a RFC3339 UTC. null si la fecha es inválida/vacía —
// nunca fabrica un rango.
function localDateTimeToRFC3339(v: string): string | null {
  if (!v) return null;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

// displayOptionalNumber/triStateLabel (Observatorio, v1.3 Gate 6): nil/undefined
// is a distinct, real "no determinado" outcome — never coerced to 0/false via
// `??`/`||`, which would hide a datasource failure behind a fabricated value.
function displayOptionalNumber(v?: number | null): string {
  return v === undefined || v === null ? '—' : String(v);
}

function triStateLabel(t: (s: string, v?: Record<string, string | number>) => string, v?: boolean | null): string {
  if (v === undefined || v === null) return t('No determinado');
  return v ? t('Sí') : t('No');
}

function historyTypeLabel(t: (s: string, v?: Record<string, string | number>) => string, type: string): string {
  if (type === 'A') return t('A · Anuncio');
  if (type === 'W') return t('W · Retiro');
  return type;
}

function RealtimeEventDetail({ ev }: { ev: BGPRealtimeEvent }) {
  const { t } = useI18n();
  switch (ev.Type) {
    case 'announcement':
      return <span className="dim" style={{ fontSize: 11.5 }}>{t('AS-path')}: {formatBGPPath(ev.Path)} · {t('Origen')}: {formatOrigin(t, ev.Origin)}</span>;
    case 'withdrawal':
      return <span className="dim" style={{ fontSize: 11.5 }}>{t('Sin AS-path (retiro)')}</span>;
    case 'path_changed':
      return <span className="dim" style={{ fontSize: 11.5 }}>{formatBGPPath(ev.Previous?.Path)} → {formatBGPPath(ev.Current?.Path)}</span>;
    case 'origin_changed':
      return <span className="dim" style={{ fontSize: 11.5 }}>{formatOrigin(t, ev.Previous?.Origin)} → {formatOrigin(t, ev.Current?.Origin)}</span>;
    case 'rpki_transition':
      return <span className="dim" style={{ fontSize: 11.5 }}>{ev.Previous?.RPKIState || '—'} → {ev.Current?.RPKIState || '—'}</span>;
    case 'moas_appeared':
    case 'moas_disappeared': {
      const ids = ev.Evidence?.[0]?.sourceEventIds;
      return (
        <span className="dim" style={{ fontSize: 11.5 }}>
          {t('Origen que disparó el recálculo')}: {formatOrigin(t, ev.Current?.Origin)}
          {ids?.length ? ` · ${t('{count} eventos fuente', { count: ids.length })}` : ''}
        </span>
      );
    }
    default:
      return null;
  }
}

function statusPillClass(status: string): string {
  switch (status) {
    case 'ok': return 'ok';
    case 'degraded': return 'danger';
    case 'unavailable': return 'warn';
    default: return ''; // not_applicable — neutral, never a claim of failure
  }
}

function rpkiPillClass(state: string | undefined): string {
  switch (state) {
    case 'VALID': return 'ok';
    case 'UNKNOWN': return 'warn';
    case 'INVALID_ASN':
    case 'INVALID_LENGTH': return 'danger';
    default: return ''; // no evaluado — nunca "seguro" por defecto
  }
}

function healthPillClass(state: string): string {
  switch (state) {
    case 'normal': return 'ok';
    case 'atencion': return 'warn';
    case 'riesgo': return 'danger';
    default: return ''; // degradado — ni ok ni riesgo, dato insuficiente
  }
}

function EvidenceList({ evidence }: { evidence?: bgp.ComponentEvidence[] }) {
  const { t } = useI18n();
  if (!evidence || evidence.length === 0) return null;
  const failures = evidence.filter((e) => e.err);
  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h3>{t('Evidencia')}</h3>
      <div className="mtr-table-wrap">
        <table className="mtr-table">
          <thead><tr>
            <th className="l">{t('Componente')}</th>
            <th className="l">{t('Estado')}</th>
            <th className="l">{t('Caché')}</th>
            <th className="l">{t('Consultado')}</th>
          </tr></thead>
          <tbody>
            {evidence.map((e, i) => (
              <tr key={i}>
                <td className="l mono">{e.component}</td>
                <td className="l"><span className={'pill ' + statusPillClass(e.status)}><span className="dot" /> {e.status}</span></td>
                <td className="l">{e.fromCache ? t('sí') : t('no')}</td>
                <td className="l dim" style={{ fontSize: 11 }}>{e.disclosure?.queriedAt || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {failures.length > 0 && (
        <div style={{ marginTop: 10 }}>
          {failures.map((e, i) => <p key={i} className="dim" style={{ fontSize: 12 }}>{e.component}: {e.err}</p>)}
        </div>
      )}
    </div>
  );
}

function HealthPanel({ health }: { health: bgp.HealthResult }) {
  const { t } = useI18n();
  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h3>{t('Estado de seguridad (Health)')}</h3>
      <p>
        <span className={'pill ' + healthPillClass(health.state)}><span className="dot" /> {health.state.toUpperCase()}</span>{' '}
        <span className="dim" style={{ fontSize: 12 }}>
          {health.dataSufficient ? t('datos suficientes para evaluar') : t('datos insuficientes — la evaluación no pudo completarse')}
        </span>
      </p>
      <div className="hop-list">
        {health.rules.map((r, i) => (
          <div className="hop-row" key={i}>
            <span className="hop-ttl">{r.applicable ? (r.fired ? '●' : '○') : '—'}</span>
            <span className="hop-host mono">{r.id}</span>
            <span className="dim" style={{ fontSize: 11.5 }}>{r.detail}</span>
          </div>
        ))}
      </div>
      <p className="dim" style={{ fontSize: 11, marginTop: 8 }}>
        {t('Reglas deterministas, sin score ni ML. Nunca etiqueta "HIJACK" automáticamente.')}
      </p>
    </div>
  );
}

// ---------------- Resumen ----------------
function ResumenPanel() {
  const { t } = useI18n();
  const [input, setInput] = useState('13335');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<bgp.Overview | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function consultar() {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    setError(null);
    setLoading(true);
    setResult(null);
    try {
      const r = await bgpOverview(input.trim());
      setResult(r);
      if (r.err) setError(r.err);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" placeholder={t('ASN, IP o prefijo (ej. AS13335, 1.1.1.1, 1.1.1.0/24)')} value={input}
            onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && !loading && consultar()} />
          <button className="btn" onClick={consultar} disabled={loading || !input.trim()}>
            {loading ? <span className="spin" /> : '📡'} {t('Consultar')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Agrega as-overview, routing-status, announced-prefixes, asn-neighbours y RPKI en un solo resumen por recurso. Cada componente conserva su propia evidencia.')}
        </p>
      </div>

      {error && <BGPErrorNotice error={error} />}

      {result && !result.err && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat">
              <span className="label">{t('Recurso')}</span>
              <span className="value accent">{result.resource}</span>
              <span className="sub">{result.kind}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Holder')}</span>
              <span className="value">{result.holder || '—'}</span>
              <span className="sub">{result.asn ? 'AS' + result.asn : ''}</span>
            </div>
            <div className="card stat">
              <span className="label">MOAS</span>
              <span className={'value ' + (result.moas ? 'accent' : '')}>{result.moas ? t('sí') : t('no')}</span>
              <span className="sub">{(result.origins || []).map((o) => 'AS' + o).join(', ') || '—'}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Prefijos')}</span>
              <span className="value">{result.prefixes?.length ?? 0}</span>
              <span className="sub">{t('anunciados')}</span>
            </div>
          </div>

          {(result.visibilityV4 || result.visibilityV6) && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>{t('Visibilidad')}</h3>
              <div className="grid cols-4">
                {result.visibilityV4 && (
                  <div className="card stat">
                    <span className="label">IPv4</span>
                    <span className="value">{result.visibilityV4.classification}</span>
                    <span className="sub">{result.visibilityV4.risPeersSeeing}/{result.visibilityV4.totalRisPeers} RIS peers</span>
                  </div>
                )}
                {result.visibilityV6 && (
                  <div className="card stat">
                    <span className="label">IPv6</span>
                    <span className="value">{result.visibilityV6.classification}</span>
                    <span className="sub">{result.visibilityV6.risPeersSeeing}/{result.visibilityV6.totalRisPeers} RIS peers</span>
                  </div>
                )}
              </div>
              <p className="dim" style={{ fontSize: 11, marginTop: 8 }}>
                {t('Clasificación propia de TRAZIP sobre la proporción de RIS peers que observan el anuncio — no es una clasificación oficial de RIPE NCC.')}
              </p>
            </div>
          )}

          {(result.rpki?.results?.length ?? 0) > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>RPKI</h3>
              <div className="hop-list">
                {result.rpki!.results!.map((r, i) => (
                  <div className="hop-row" key={i}>
                    <span className="hop-ttl">AS{r.asn}</span>
                    <span className="hop-host mono">{r.prefix}</span>
                    <span className={'pill ' + rpkiPillClass(r.state)}><span className="dot" /> {r.state || '—'}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.neighbors && result.neighbors.count > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>{t('Vecinos observados')}</h3>
              <p className="dim" style={{ fontSize: 12.5 }}>
                {t('{count} vecinos · {left} left · {right} right · {uncertain} uncertain · {unknown} unknown', {
                  count: result.neighbors.count, left: result.neighbors.left, right: result.neighbors.right,
                  uncertain: result.neighbors.uncertain, unknown: result.neighbors.unknown,
                })}
              </p>
            </div>
          )}

          <EvidenceList evidence={result.evidence} />
        </>
      )}
    </>
  );
}

// ---------------- Prefijos ----------------
function PrefijosPanel() {
  const { t } = useI18n();
  const [asn, setAsn] = useState(13335);
  const [family, setFamily] = useState<'all' | 'ipv4' | 'ipv6'>('all');
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState<'prefix_asc' | 'prefix_desc' | 'family'>('prefix_asc');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<bgp.PrefixPage | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load(nextPage: number) {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    setError(null);
    setLoading(true);
    try {
      const r = await bgpPrefixes({ ASN: asn, Page: nextPage, Family: family, Search: search.trim(), Sort: sort } as bgp.PrefixPageRequest);
      setResult(r);
      setPage(nextPage);
      if (r.Err) setError(r.Err);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" style={{ maxWidth: 140 }} type="number" placeholder="ASN" value={asn}
            onChange={(e) => setAsn(Number(e.target.value) || 0)} onKeyDown={(e) => e.key === 'Enter' && !loading && load(1)} />
          <select className="input" style={{ maxWidth: 150 }} value={family} onChange={(e) => setFamily(e.target.value as 'all' | 'ipv4' | 'ipv6')}>
            <option value="all">{t('Todas las familias')}</option>
            <option value="ipv4">IPv4</option>
            <option value="ipv6">IPv6</option>
          </select>
          <input className="input" placeholder={t('buscar prefijo')} value={search} onChange={(e) => setSearch(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && !loading && load(1)} />
          <select className="input" style={{ maxWidth: 150 }} value={sort} onChange={(e) => setSort(e.target.value as 'prefix_asc' | 'prefix_desc' | 'family')}>
            <option value="prefix_asc">{t('Prefijo ↑')}</option>
            <option value="prefix_desc">{t('Prefijo ↓')}</option>
            <option value="family">{t('Familia')}</option>
          </select>
          <button className="btn" onClick={() => load(1)} disabled={loading || asn <= 0}>
            {loading ? <span className="spin" /> : '📋'} {t('Consultar')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Página fija de 25 prefijos. El filtro/orden es local sobre el listado ya obtenido; solo la página visible se enriquece con routing-status + RPKI (máximo 50 llamadas por página).')}
        </p>
      </div>

      {error && <BGPErrorNotice error={error} />}

      {result && !result.Err && (
        <div className="card" style={{ marginTop: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
            <h3 style={{ margin: 0 }}>{t('{count} prefijos', { count: result.TotalItems })}</h3>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <button className="btn ghost" onClick={() => load(page - 1)} disabled={loading || page <= 1}>← {t('Anterior')}</button>
              <span className="dim" style={{ fontSize: 12.5 }}>{t('Página {page} de {total}', { page: result.Page, total: result.TotalPages || 1 })}</span>
              <button className="btn ghost" onClick={() => load(page + 1)} disabled={loading || page >= (result.TotalPages || 1)}>{t('Siguiente')} →</button>
            </div>
          </div>
          <div className="mtr-table-wrap" style={{ marginTop: 12 }}>
            <table className="mtr-table">
              <thead><tr>
                <th className="l">{t('Prefijo')}</th>
                <th className="l">{t('Familia')}</th>
                <th>MOAS</th>
                <th className="l">{t('Orígenes')}</th>
                <th className="l">RPKI</th>
                <th className="l">{t('Visibilidad')}</th>
                <th className="l">{t('Estado')}</th>
              </tr></thead>
              <tbody>
                {result.Items.map((row, i) => (
                  <tr key={i}>
                    <td className="l mono">{row.prefix}</td>
                    <td className="l">{row.family}</td>
                    <td className={row.moas ? 'accent-t' : 'dim'}>{row.moas ? t('sí') : t('no')}</td>
                    <td className="l mono" style={{ fontSize: 11.5 }}>{(row.origins || []).map((o) => 'AS' + o).join(', ') || '—'}</td>
                    <td className="l">
                      {row.rpki?.state
                        ? <span className={'pill ' + rpkiPillClass(row.rpki.state)}><span className="dot" /> {row.rpki.state}</span>
                        : '—'}
                    </td>
                    <td className="l">{row.visibility?.classification || '—'}</td>
                    <td className="l">{row.state}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}

// ---------------- Vecinos ----------------
function VecinosPanel() {
  const { t } = useI18n();
  const [asn, setAsn] = useState(13335);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<bgp.ASNNeighboursResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function consultar() {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    setError(null);
    setLoading(true);
    setResult(null);
    try {
      const r = await bgpNeighbours(asn);
      setResult(r);
      if (r.err) setError(r.err);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" style={{ maxWidth: 160 }} type="number" placeholder="ASN" value={asn}
            onChange={(e) => setAsn(Number(e.target.value) || 0)} onKeyDown={(e) => e.key === 'Enter' && !loading && consultar()} />
          <button className="btn" onClick={consultar} disabled={loading || asn <= 0}>
            {loading ? <span className="spin" /> : '🤝'} {t('Consultar')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Adyacencias observadas directamente por RIS (izquierda/derecha en el AS-path) — nunca una relación comercial provider/customer.')}
        </p>
      </div>

      {error && <BGPErrorNotice error={error} />}

      {result && !result.err && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat"><span className="label">Left</span><span className="value">{result.neighbourCounts.left}</span></div>
            <div className="card stat"><span className="label">Right</span><span className="value">{result.neighbourCounts.right}</span></div>
            <div className="card stat"><span className="label">{t('Únicos')}</span><span className="value">{result.neighbourCounts.unique}</span></div>
            <div className="card stat"><span className="label">Uncertain</span><span className="value">{result.neighbourCounts.uncertain}</span></div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Vecinos ({count})', { count: result.neighbours?.length ?? 0 })}</h3>
            <div className="mtr-table-wrap">
              <table className="mtr-table">
                <thead><tr>
                  <th className="l">ASN</th>
                  <th className="l">{t('Posición')}</th>
                  <th className="l">{t('Valor crudo')}</th>
                  <th>{t('Rutas')}</th>
                  <th>{t('Peers v4')}</th>
                  <th>{t('Peers v6')}</th>
                </tr></thead>
                <tbody>
                  {(result.neighbours || []).length === 0 && (
                    <tr><td colSpan={6} className="l dim">{t('Sin vecinos observados.')}</td></tr>
                  )}
                  {(result.neighbours || []).map((n, i) => (
                    <tr key={i}>
                      <td className="l mono">AS{n.asn}</td>
                      <td className="l">{n.position}</td>
                      <td className="l dim mono" style={{ fontSize: 11 }}>{n.rawPosition}</td>
                      <td>{n.pathCount}</td>
                      <td>{n.peerCountV4}</td>
                      <td>{n.peerCountV6}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </>
  );
}

// ---------------- Topología ----------------
function topologyDisplayLabel(value: string, maximum = 26): string {
  return value.length > maximum ? `${value.slice(0, maximum - 1)}…` : value;
}

function downloadTopologyBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

const TOPOLOGY_EXPORT_STYLE_PROPERTIES = [
  'fill', 'stroke', 'stroke-width', 'stroke-linecap', 'opacity',
  'font-family', 'font-size', 'font-weight', 'filter',
] as const;

function copyTopologyComputedStyles(source: SVGElement, target: SVGElement): void {
  const computed = window.getComputedStyle(source);
  for (const property of TOPOLOGY_EXPORT_STYLE_PROPERTIES) {
    const value = computed.getPropertyValue(property);
    if (value) target.style.setProperty(property, value);
  }
}

function serializeTopologySVG(svg: SVGSVGElement, canonicalViewBox: string): string {
  const clone = svg.cloneNode(true) as SVGSVGElement;
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  clone.setAttribute('viewBox', canonicalViewBox);
  const sourceElements = [svg, ...Array.from(svg.querySelectorAll<SVGElement>('*'))];
  const cloneElements = [clone, ...Array.from(clone.querySelectorAll<SVGElement>('*'))];
  sourceElements.forEach((source, index) => copyTopologyComputedStyles(source, cloneElements[index]));
  return new XMLSerializer().serializeToString(clone);
}

function TopologiaPanel() {
  const { t } = useI18n();
  const [input, setInput] = useState('13335');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<bgp.Graph | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedASN, setSelectedASN] = useState<number | null>(null);
  const [hoveredASN, setHoveredASN] = useState<number | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [spacePanMode, setSpacePanMode] = useState(false);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const panRef = useRef<TopologyPanGesture | null>(null);
  const suppressNodeClickRef = useRef(false);
  const [dragging, setDragging] = useState(false);
  const layout = useMemo(() => result ? buildTopologyLayout(result.nodes || [], result.edges || []) : null, [result]);
  const zoomViewBox = useMemo(() => layout ? topologyViewBox(layout.width, layout.height, zoom) : null, [layout, zoom]);
  const viewBox = useMemo(() => zoomViewBox ? { ...zoomViewBox, x: zoomViewBox.x + pan.x, y: zoomViewBox.y + pan.y } : null, [zoomViewBox, pan]);
  const canonicalViewBox = layout ? `0 0 ${layout.width} ${layout.height}` : '';
  const selectedNode = result?.nodes.find((node) => node.asn === selectedASN) ?? null;
  const nodesByASN = useMemo(() => new Map((result?.nodes || []).map((node) => [node.asn, node])), [result]);
  const maximumObservationCount = useMemo(() => Math.max(1, ...(result?.edges || []).map((edge) => edge.observationCount)), [result]);
  const edgeLanes = useMemo(() => topologyEdgeLaneOffsets(result?.edges || []), [result]);
  const queriedASN = result && /^(?:AS)?\d+$/i.test(result.resource) ? Number(result.resource.replace(/^AS/i, '')) : null;
  const focusedASN = hoveredASN ?? selectedASN;

  useEffect(() => {
    // El modo pan con Espacio es global, pero nunca debe interceptar la
    // tecla mientras el usuario escribe en un campo de texto.
    const isFormTarget = (event: KeyboardEvent) =>
      event.target instanceof HTMLElement && event.target.closest('input, textarea, select, [contenteditable]') !== null;
    const onKeyDown = (event: KeyboardEvent) => { if (event.code === 'Space' && !isFormTarget(event)) setSpacePanMode(true); };
    const onKeyUp = (event: KeyboardEvent) => { if (event.code === 'Space') setSpacePanMode(false); };
    const onWindowBlur = () => setSpacePanMode(false);
    window.addEventListener('keydown', onKeyDown);
    window.addEventListener('keyup', onKeyUp);
    window.addEventListener('blur', onWindowBlur);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('keyup', onKeyUp);
      window.removeEventListener('blur', onWindowBlur);
    };
  }, []);

  async function consultar() {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    setError(null);
    setExportError(null);
    setSelectedASN(null);
    setHoveredASN(null);
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setLoading(true);
    setResult(null);
    try {
      const r = await bgpTopology(input.trim());
      setResult(r);
      if (r.err) setError(r.err);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  function fitView() {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }

  function startPan(event: React.PointerEvent<HTMLDivElement>) {
    if (event.button !== 0 || !svgRef.current || !zoomViewBox) return;
    const bounds = svgRef.current.getBoundingClientRect();
    if (!bounds.width || !bounds.height) return;
    panRef.current = {
      pointerId: event.pointerId,
      x: event.clientX,
      y: event.clientY,
      panX: pan.x,
      panY: pan.y,
      scaleX: zoomViewBox.width / bounds.width,
      scaleY: zoomViewBox.height / bounds.height,
      active: spacePanMode,
    };
    if (spacePanMode) {
      suppressNodeClickRef.current = true;
      event.currentTarget.setPointerCapture(event.pointerId);
      setDragging(true);
    }
  }
  function movePan(event: React.PointerEvent<HTMLDivElement>) {
    const gesture = panRef.current;
    if (!gesture || gesture.pointerId !== event.pointerId) return;
    const deltaX = event.clientX - gesture.x;
    const deltaY = event.clientY - gesture.y;
    if (!gesture.active && Math.hypot(deltaX, deltaY) < TOPOLOGY_PAN_THRESHOLD_PX) return;
    if (!gesture.active) {
      gesture.active = true;
      suppressNodeClickRef.current = true;
      event.currentTarget.setPointerCapture(event.pointerId);
      setDragging(true);
    }
    setPan({ x: gesture.panX - deltaX * gesture.scaleX, y: gesture.panY - deltaY * gesture.scaleY });
  }
  function endPan(event: React.PointerEvent<HTMLDivElement>) {
    const gesture = panRef.current;
    if (!gesture || gesture.pointerId !== event.pointerId) return;
    if (gesture.active) window.setTimeout(() => { suppressNodeClickRef.current = false; }, 0);
    panRef.current = null;
    setDragging(false);
  }

  function selectTopologyNode(asn: number) {
    if (suppressNodeClickRef.current) return;
    setSelectedASN(asn);
  }

  function exportSVG() {
    if (!svgRef.current || !result || !layout) return;
    setExportError(null);
    downloadTopologyBlob(new Blob([serializeTopologySVG(svgRef.current, canonicalViewBox)], { type: 'image/svg+xml;charset=utf-8' }), `trazip-bgp-topology-${sanitizeTopologyFilename(result.resource)}.svg`);
  }

  async function exportPNG() {
    if (!svgRef.current || !result || !layout) return;
    setExportError(null);
    const svgURL = URL.createObjectURL(new Blob([serializeTopologySVG(svgRef.current, canonicalViewBox)], { type: 'image/svg+xml;charset=utf-8' }));
    try {
      const image = new Image();
      await new Promise<void>((resolve, reject) => {
        image.onload = () => resolve();
        image.onerror = () => reject(new Error(t('No se pudo convertir el SVG a PNG.')));
        image.src = svgURL;
      });
      const scale = 2;
      const canvas = document.createElement('canvas');
      canvas.width = Math.ceil(layout.width * scale);
      canvas.height = Math.ceil(layout.height * scale);
      const context = canvas.getContext('2d');
      if (!context) throw new Error(t('Canvas no disponible para exportar PNG.'));
      context.scale(scale, scale);
      context.drawImage(image, 0, 0, layout.width, layout.height);
      const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/png'));
      if (!blob) throw new Error(t('No se pudo generar el PNG.'));
      downloadTopologyBlob(blob, `trazip-bgp-topology-${sanitizeTopologyFilename(result.resource)}.png`);
    } catch (e) {
      setExportError(String(e));
    } finally {
      URL.revokeObjectURL(svgURL);
    }
  }

  const visualTopologyCard = result && !result.err && (
    <div className="card topology-visual-card">
      <div className="topology-visual-head">
        <div>
          <h3>{t('TOPOLOGÍA VISUAL')}</h3>
          <p className="dim">{t('Las flechas representan adyacencias consecutivas observadas en AS-paths de bgp-state; no implican relaciones comerciales.')}</p>
        </div>
        <div className="topology-controls">
          <button className="btn ghost" onClick={fitView}>{t('Ajustar vista')}</button>
          <div className="topology-zoom-controls" role="group" aria-label={t('Controles de zoom de topología')}>
            <button className="btn ghost" onClick={() => setZoom((current) => clampTopologyZoom(current - TOPOLOGY_ZOOM_STEP))} disabled={zoom <= TOPOLOGY_MIN_ZOOM} title={t('Alejar topología')} aria-label={t('Alejar topología')}>−</button>
            <output className="topology-zoom-indicator" aria-live="polite" aria-label={t('Zoom de topología: {pct}%', { pct: Math.round(zoom * 100) })}>{Math.round(zoom * 100)}%</output>
            <button className="btn ghost" onClick={() => setZoom((current) => clampTopologyZoom(current + TOPOLOGY_ZOOM_STEP))} disabled={zoom >= TOPOLOGY_MAX_ZOOM} title={t('Acercar topología')} aria-label={t('Acercar topología')}>+</button>
          </div>
          <button className="btn ghost" onClick={exportSVG} disabled={result.nodes.length === 0}>{t('Exportar SVG')}</button>
          <button className="btn ghost" onClick={() => void exportPNG()} disabled={result.nodes.length === 0}>{t('Exportar PNG')}</button>
        </div>
      </div>
      {result.nodes.length === 0 ? (
        <p className="topology-empty">{t('Sin topología observable para este recurso.')}</p>
      ) : layout && (
        <>
          <div className={`topology-svg-wrap${dragging ? ' dragging' : ''}${spacePanMode ? ' hand-mode' : ''}`} onPointerDown={startPan} onPointerMove={movePan} onPointerUp={endPan} onPointerCancel={endPan} onPointerLeave={endPan}>
            {/* role="group" (nunca role="img"): los nodos del grafo son
                elementos interactivos (role="button" con teclado) y una
                imagen ARIA opaca los convertiría en contenido presentacional
                inalcanzable para tecnologías asistivas. El aria-label sigue
                describiendo la topología global. */}
            <svg ref={svgRef} className="topology-svg" viewBox={viewBox ? `${viewBox.x} ${viewBox.y} ${viewBox.width} ${viewBox.height}` : canonicalViewBox} role="group" aria-label={t('Grafo de topología BGP observada')} preserveAspectRatio="xMidYMid meet">
              <defs><marker id="topology-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" className="topology-arrow" /></marker></defs>
              <rect className="topology-background" x="0" y="0" width={layout.width} height={layout.height} rx="10" />
              {result.edges.map((edge) => {
                const from = layout.nodes.find((node) => node.asn === edge.from);
                const to = layout.nodes.find((node) => node.asn === edge.to);
                if (!from || !to) return null;
                const endpoints = topologyEdgeEndpoints(from, to, layout.nodeWidth, layout.nodeHeight);
                const related = focusedASN === null || edge.from === focusedASN || edge.to === focusedASN;
                return <path key={`${edge.from}-${edge.to}`} className={`topology-edge${related ? ' related' : ' muted'}`} d={topologyEdgeCurve(endpoints, edgeLanes.get(`${edge.from}-${edge.to}`) ?? 0)} strokeWidth={topologyEdgeWidth(edge.observationCount, maximumObservationCount)} markerEnd="url(#topology-arrow)"><title>{`AS${edge.from} → AS${edge.to}: ${edge.observationCount} observaciones`}</title></path>;
              })}
              {layout.nodes.map((position) => {
                const node = nodesByASN.get(position.asn);
                if (!node) return null;
                const selected = node.asn === selectedASN;
                const adjacent = focusedASN !== null && result.edges.some((edge) => (edge.from === focusedASN && edge.to === node.asn) || (edge.to === focusedASN && edge.from === node.asn));
                const queried = queriedASN === node.asn;
                const tooltip = [`AS${node.asn}`, node.displayName, `${t('Rol observado')}: ${node.observedRole}`, `${t('Rutas')}: ${node.pathCount}`, node.originRpki ? `RPKI: ${node.originRpki.state} · ${node.originRpki.prefix}` : ''].filter(Boolean).join('\n');
                return <g key={node.asn} className={`topology-node topology-role-${node.observedRole}${selected ? ' selected' : ''}${hoveredASN === node.asn ? ' active' : ''}${adjacent ? ' adjacent' : ''}${queried ? ' queried-node' : ''}`} transform={`translate(${position.x} ${position.y})`} role="button" tabIndex={0} aria-label={tooltip} onMouseEnter={() => setHoveredASN(node.asn)} onMouseLeave={() => setHoveredASN(null)} onFocus={() => setHoveredASN(node.asn)} onBlur={() => setHoveredASN(null)} onClick={() => selectTopologyNode(node.asn)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelectedASN(node.asn); } }}>
                  <title>{tooltip}</title>
                  <rect width={layout.nodeWidth} height={layout.nodeHeight} rx="8" />
                  <text className="topology-asn" x="13" y="25">AS{node.asn}</text>
                  {node.displayName && <text className="topology-holder" x="13" y="47">{topologyDisplayLabel(node.displayName)}</text>}
                  <text className="topology-role" x="13" y={node.displayName ? 67 : 49}>{node.observedRole}</text>
                </g>;
              })}
            </svg>
          </div>
          {selectedNode && <div className="topology-details"><strong>AS{selectedNode.asn}</strong>{selectedNode.displayName && <span>{selectedNode.displayName}</span>}<span>{t('Rol observado')}: {selectedNode.observedRole}</span><span>{t('Rutas')}: {selectedNode.pathCount}</span>{selectedNode.originRpki && <span>RPKI: {selectedNode.originRpki.state} · {selectedNode.originRpki.prefix}</span>}</div>}
        </>
      )}
      {exportError && <p className="topology-export-error">{exportError}</p>}
    </div>
  );

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" placeholder={t('ASN, IP o prefijo')} value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && !loading && consultar()} />
          <button className="btn" onClick={consultar} disabled={loading || !input.trim()}>
            {loading ? <span className="spin" /> : '🕸️'} {t('Consultar')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Nodos y edges derivados únicamente de bgp-state (AS-paths reales observados) — nunca reconstruidos combinando routing-status/asn-neighbours. Vista acotada a 100 nodos / 250 edges.')}
        </p>
      </div>

      {error && <BGPErrorNotice error={error} />}

      {result && !result.err && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            {visualTopologyCard}
            <div className="card stat"><span className="label">{t('Rutas observadas')}</span><span className="value">{result.observedRoutes}</span></div>
            <div className="card stat">
              <span className="label">{t('Nodos observados')}</span>
              <span className="value">{result.observedNodes}</span>
              <span className="sub">{t('{shown} mostrados', { shown: result.nodes.length })}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Edges observados')}</span>
              <span className="value">{result.observedEdges}</span>
              <span className="sub">{t('{shown} mostrados', { shown: result.edges.length })}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Vista')}</span>
              <span className={'value ' + (result.viewTruncated ? '' : 'accent')}>{result.viewTruncated ? t('recortada') : t('completa')}</span>
            </div>
          </div>

          {result.viewTruncated && (
            <div className="note" style={{ marginTop: 16 }}>
              {t('Vista resumida: se muestran {nodes} de {observedNodes} nodos y {edges} de {observedEdges} edges observados, ordenados por volumen de rutas/observaciones.', {
                nodes: result.nodes.length, observedNodes: result.observedNodes, edges: result.edges.length, observedEdges: result.observedEdges,
              })}
            </div>
          )}

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Nodos ({count})', { count: result.nodes.length })}</h3>
            <div className="mtr-table-wrap">
              <table className="mtr-table">
                <thead><tr>
                  <th className="l">ASN</th>
                  <th className="l">{t('Rol observado')}</th>
                  <th>{t('Rutas')}</th>
                  <th className="l">RPKI (origin)</th>
                </tr></thead>
                <tbody>
                  {result.nodes.map((n, i) => (
                    <tr key={i}>
                      <td className="l mono">AS{n.asn}</td>
                      <td className="l">{n.observedRole}</td>
                      <td>{n.pathCount}</td>
                      <td className="l">
                        {n.originRpki
                          ? <span className={'pill ' + rpkiPillClass(n.originRpki.state)}><span className="dot" /> {n.originRpki.state} · {n.originRpki.prefix}</span>
                          : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Edges ({count})', { count: result.edges.length })}</h3>
            <div className="hop-list">
              {result.edges.map((e, i) => (
                <div className="hop-row" key={i}>
                  <span className="mono" style={{ fontSize: 12.5 }}>AS{e.from} → AS{e.to}</span>
                  <span className="dim" style={{ fontSize: 11 }}>{t('{count} observaciones', { count: e.observationCount })}</span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </>
  );
}

// ---------------- Seguridad ----------------
function SeguridadPanel() {
  const { t } = useI18n();
  const [input, setInput] = useState('1.1.1.1');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<bgp.SecurityResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function consultar() {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    setError(null);
    setLoading(true);
    setResult(null);
    try {
      const r = await bgpSecurity(input.trim());
      setResult(r);
      if (r.err) setError(r.err);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" placeholder={t('ASN, IP o prefijo')} value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && !loading && consultar()} />
          <button className="btn" onClick={consultar} disabled={loading || !input.trim()}>
            {loading ? <span className="spin" /> : '🛡️'} {t('Analizar')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Para IP/prefijo valida RPKI de TODOS los orígenes observados. Para un ASN puro, RPKI queda sin evaluar (es prefix-scoped) — nunca se fabrica un estado global.')}
        </p>
      </div>

      {error && <BGPErrorNotice error={error} />}

      {result && !result.err && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat">
              <span className="label">{t('Recurso')}</span>
              <span className="value accent">{result.resource}</span>
              <span className="sub">{result.kind}</span>
            </div>
            <div className="card stat">
              <span className="label">MOAS</span>
              <span className="value">{result.moas ? t('sí') : t('no')}</span>
              <span className="sub">{(result.origins || []).map((o) => 'AS' + o).join(', ') || '—'}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Cobertura RPKI')}</span>
              <span className={'value ' + (result.complete ? 'accent' : '')}>{result.complete ? t('completa') : t('incompleta')}</span>
            </div>
            <div className="card stat">
              <span className="label">Health</span>
              <span className="sub"><span className={'pill ' + healthPillClass(result.health.state)}><span className="dot" /> {result.health.state.toUpperCase()}</span></span>
            </div>
          </div>

          {(result.rpki?.results?.length ?? 0) > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>RPKI ({result.rpki!.results!.length})</h3>
              <div className="hop-list">
                {result.rpki!.results!.map((r, i) => (
                  <div className="hop-row" key={i}>
                    <span className="hop-ttl">AS{r.asn}</span>
                    <span className="hop-host mono">{r.prefix}</span>
                    <span className={'pill ' + rpkiPillClass(r.state)}><span className="dot" /> {r.state || t('sin evaluar')}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <HealthPanel health={result.health} />
          <EvidenceList evidence={result.evidence} />
        </>
      )}
    </>
  );
}

// ---------------- Tiempo real ----------------
function RealtimePanel() {
  const { t } = useI18n();
  const [resource, setResource] = useState('');
  const [info, setInfo] = useState<bgp.RealtimeSessionInfo | null>(null);
  const [startError, setStartError] = useState<string | null>(null);
  const [stopError, setStopError] = useState<string | null>(null);
  const [infoError, setInfoError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [timelineState, setTimelineState] = useState<RealtimeTimelineState>(EMPTY_REALTIME_TIMELINE);

  // Refs, no state: leídos desde closures async (poll/start/stop) y desde
  // el cleanup de unmount, donde un valor de estado capturado por closure
  // podría estar obsoleto.
  const sessionIdRef = useRef<string | null>(null);
  // infoRef SIEMPRE se escribe sincrónicamente junto con setInfo, nunca
  // vía un useEffect([info]) separado (Gate 6 P1-1) — un efecto pasivo
  // corre DESPUÉS del commit y de cualquier return anticipado (incluido
  // un unmount entre medio), dejando una ventana donde infoRef todavía
  // apunta a la sesión anterior mientras sessionIdRef ya apunta a la
  // nueva. commitInfo() es el único lugar que escribe info — nunca
  // setInfo(...) directo en ningún otro punto de este componente.
  const infoRef = useRef<bgp.RealtimeSessionInfo | null>(null);
  // generationRef distingue épocas de sesión/poll (Gate 6 P1-2): cada
  // Start la incrementa; Stop la incrementa ANTES de esperar al backend.
  // Un poll solo puede comprometer su resultado si generationRef sigue
  // siendo la misma que capturó al lanzarse — así un BGPRealtimeInfo
  // lento de una sesión ya reemplazada o detenida no puede aterrizar
  // tarde y pisar un estado terminal ya comprometido.
  const generationRef = useRef(0);
  const unsubscribeRef = useRef<(() => void) | null>(null);
  const intervalRef = useRef<number | undefined>(undefined);
  const mountedRef = useRef(true);
  // Evita apilar un segundo BGPRealtimeInfo mientras el anterior sigue en
  // vuelo — sigue habiendo EXACTAMENTE un setInterval de 1000ms; esto solo
  // hace que un tick se salte si el poll previo todavía no resolvió,
  // nunca serializa Stop() contra un poll en curso (eso ya lo resuelve
  // generationRef, no este flag).
  const pollInFlightRef = useRef(false);

  function commitInfo(next: bgp.RealtimeSessionInfo) {
    infoRef.current = next;
    setInfo(next);
  }

  function clearIntervalIfAny() {
    if (intervalRef.current !== undefined) {
      window.clearInterval(intervalRef.current);
      intervalRef.current = undefined;
    }
  }

  function unsubscribeIfAny() {
    if (unsubscribeRef.current) {
      unsubscribeRef.current();
      unsubscribeRef.current = null;
    }
  }

  // Contrato §7/§29: cuando el backend reporta un estado terminal, cancelar
  // el interval y el subscriber — pero NUNCA borrar la timeline.
  function handleTerminal(finalInfo: bgp.RealtimeSessionInfo) {
    commitInfo(finalInfo);
    clearIntervalIfAny();
    unsubscribeIfAny();
  }

  async function pollOnce(id: string, generation: number) {
    if (pollInFlightRef.current) return; // ya hay un Info en vuelo — este tick se salta, nunca se apila
    pollInFlightRef.current = true;
    try {
      const fresh = await bgpRealtimeInfo(id);
      const action = decidePollCommit({
        mounted: mountedRef.current,
        currentSessionId: sessionIdRef.current,
        pollSessionId: id,
        currentGeneration: generationRef.current,
        pollGeneration: generation,
        currentState: infoRef.current?.State,
        freshState: fresh.State,
      });
      if (action === 'ignore') return;
      setInfoError(null);
      if (action === 'terminal') handleTerminal(fresh);
      else commitInfo(fresh);
    } catch (e) {
      if (!mountedRef.current || sessionIdRef.current !== id || generationRef.current !== generation) return;
      // §31: un fallo transitorio de observability nunca se convierte en
      // "failed" ni auto-detiene la sesión — solo se muestra localmente,
      // conservando el último RealtimeSessionInfo conocido.
      setInfoError(String(e));
    } finally {
      pollInFlightRef.current = false;
    }
  }

  async function start() {
    if (!backendAvailable()) return setStartError(t(NO_BACKEND));
    const target = resource.trim();
    if (!target) return;
    setStartError(null);
    setStopError(null);
    setInfoError(null);
    setStarting(true);
    try {
      const snapshot = await startBGPRealtime(target);
      if (!mountedRef.current) {
        void stopBGPRealtime(snapshot.SessionID); // el panel se desmontó mientras Start estaba en vuelo — nunca dejar la sesión huérfana
        return;
      }
      clearIntervalIfAny();
      unsubscribeIfAny();
      const generation = ++generationRef.current; // invalida cualquier poll todavía en vuelo de la sesión anterior
      sessionIdRef.current = snapshot.SessionID;
      setTimelineState(EMPTY_REALTIME_TIMELINE);
      commitInfo(snapshot); // sincrónico: ref+state juntos — nunca una ventana stale entre sessionIdRef e infoRef
      unsubscribeRef.current = subscribeBGPRealtime(snapshot.SessionID, (ev) => {
        if (sessionIdRef.current !== snapshot.SessionID) return;
        setTimelineState((prev) => appendRealtimeEvent(prev, ev)); // updater puro — nunca un segundo setState anidado (Gate 6 P1-3)
      });
      if (!isTerminalRealtimeState(snapshot.State)) {
        intervalRef.current = window.setInterval(() => { void pollOnce(snapshot.SessionID, generation); }, REALTIME_POLL_MS);
      }
    } catch (e) {
      if (mountedRef.current) setStartError(String(e));
    } finally {
      if (mountedRef.current) setStarting(false);
    }
  }

  async function stop() {
    const id = sessionIdRef.current;
    if (!id) return;
    setStopError(null);
    setStopping(true);
    // §5/Gate 6 P1-2: cancelar el interval e invalidar la generación ANTES
    // de esperar al backend — ningún poll ya lanzado para esta sesión
    // puede comprometer su resultado después de este punto, sin importar
    // cuándo resuelva ("stopping" es solo un flag de UI local; nunca se
    // escribe sobre RealtimeSessionInfo.State).
    clearIntervalIfAny();
    generationRef.current++;
    try {
      await stopBGPRealtime(id);
    } catch (e) {
      // La sesión pudo haber terminado de forma autónoma entre el click y
      // esta llamada — igual seguimos al BGPRealtimeInfo final de abajo
      // para reflejar el estado real (failed/stopped), nunca tratamos
      // este error como bloqueante.
      if (mountedRef.current) setStopError(String(e));
    } finally {
      if (mountedRef.current) setStopping(false);
    }
    try {
      const final = await bgpRealtimeInfo(id);
      if (mountedRef.current && sessionIdRef.current === id) handleTerminal(final);
    } catch (e) {
      if (mountedRef.current && sessionIdRef.current === id) setInfoError(String(e));
    }
  }

  // §6/Gate 6 unmount hardening: exactamente un cleanup, al desmontar
  // (deps vacío) — invalida cualquier poll en vuelo, cancela interval +
  // subscription y, si la sesión seguía activa, la detiene best-effort
  // sin bloquear el desmontaje de React. infoRef ya está garantizado
  // sincrónico con sessionIdRef (ver commitInfo) para todo lo que este
  // componente controla, pero igual se verifica explícitamente que
  // infoRef.current.SessionID corresponda a sessionIdRef.current antes de
  // confiar en su State — si no corresponde, política conservadora: nunca
  // asumir terminalidad de una sesión que no se puede verificar, mejor un
  // Stop() de más (idempotente/seguro) que dejar una sesión RIS Live
  // oculta.
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      generationRef.current++; // ningún poll en vuelo puede comprometer su resultado tras el unmount
      clearIntervalIfAny();
      unsubscribeIfAny();
      const id = sessionIdRef.current;
      if (!id) return;
      const current = infoRef.current;
      if (current && current.SessionID === id) {
        if (!isTerminalRealtimeState(current.State)) void stopBGPRealtime(id);
      } else {
        void stopBGPRealtime(id);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const activeNonTerminal = info != null && !isTerminalRealtimeState(info.State);

  return (
    <>
      <div className="card">
        <div className="field">
          <input
            className="input"
            placeholder={t('IP o prefijo (ej. 1.1.1.1, 1.1.1.0/24, 2606:4700::/32)')}
            value={resource}
            disabled={activeNonTerminal || starting}
            onChange={(e) => setResource(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !starting && !activeNonTerminal && start()}
          />
          <button className="btn" onClick={start} disabled={starting || activeNonTerminal || !resource.trim()}>
            {starting ? <span className="spin" /> : '📡'} {t('Iniciar')}
          </button>
          <button className="btn ghost" onClick={stop} disabled={!activeNonTerminal || stopping}>
            {stopping ? <span className="spin" /> : '⏹'} {stopping ? t('Deteniendo…') : t('Detener')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Tiempo real admite IP o prefijo. ASN no está soportado en v1.2.')}
        </p>
      </div>

      {startError && <BGPErrorNotice error={startError} />}
      {stopError && <BGPErrorNotice error={stopError} />}
      {infoError && <div className="note" role="alert">{t('Fallo local consultando el estado de la sesión (IPC): {err}', { err: infoError })}</div>}

      {info && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat">
              <span className="label">{t('Estado')}</span>
              <span className="sub"><span className={'pill ' + realtimeStatePillClass(info.State)}><span className="dot" /> {realtimeStateLabel(t, info.State)}</span></span>
              <span className="sub mono" style={{ fontSize: 10.5 }}>{info.SessionID}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Recurso')}</span>
              <span className="value accent" style={{ fontSize: 18 }}>{info.Resource}</span>
              <span className="sub">{info.ResourceKind} · {info.ResolvedPrefix || '—'}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Eventos recibidos')}</span>
              <span className="value">{info.ReceivedEvents}</span>
              <span className="sub">{t('Reconexiones: {count}', { count: info.ReconnectCount })}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Iniciada')}</span>
              <span className="value" style={{ fontSize: 14 }}>{formatTimestamp(info.StartedAt)}</span>
              <span className="sub">{t('Último evento')}: {formatTimestamp(info.LastEventAt)}</span>
            </div>
          </div>

          {info.LastError && <div className="note" style={{ marginTop: 16 }}>{t('Último error del backend')}: {info.LastError}</div>}

          {/* Contrato crítico §7: DroppedEventsTotal SIEMPRE visible junto a la timeline, incluso 0 — nunca condicionado por falsy. */}
          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Descartes y visibilidad')}</h3>
            <div className="grid cols-4">
              <div className="card stat"><span className="label">QueueDroppedEvents</span><span className="value">{info.QueueDroppedEvents}</span></div>
              <div className="card stat"><span className="label">TransportDroppedEvents</span><span className="value">{info.TransportDroppedEvents}</span></div>
              <div className="card stat"><span className="label">DroppedEventsTotal</span><span className={'value ' + (info.DroppedEventsTotal > 0 ? '' : 'accent')}>{info.DroppedEventsTotal}</span></div>
              <div className="card stat"><span className="label">{t('No retenidos por la UI')}</span><span className="value">{timelineState.evicted}</span></div>
            </div>
            {info.DroppedEventsTotal > 0 && (
              <div className="note" style={{ marginTop: 12 }}>
                {t('La timeline puede ser incompleta: el backend reporta {count} eventos descartados.', { count: info.DroppedEventsTotal })}
              </div>
            )}
            {timelineState.evicted > 0 && (
              <p className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>
                {t('Backend descartados: {backend} — No retenidos por límite local de la UI: {ui} (capas distintas, nunca sumadas).', { backend: info.DroppedEventsTotal, ui: timelineState.evicted })}
              </p>
            )}
            {info.DerivedStateEvictions > 0 && (
              <div className="note" style={{ marginTop: 12 }}>
                {t('Parte del estado usado para derivar cambios fue descartado para mantener la sesión acotada; eventos derivados posteriores pueden basarse en visibilidad parcial.')}
              </div>
            )}
            <p className="dim" style={{ fontSize: 11, marginTop: 8 }}>DerivedStateEvictions: {info.DerivedStateEvictions}</p>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>Disclosure</h3>
            <div className="hop-list">
              <div className="hop-row"><span className="hop-host">{t('Fuente')}</span><span className="dim mono" style={{ fontSize: 11.5 }}>{info.Disclosure?.source || '—'}</span></div>
              <div className="hop-row"><span className="hop-host">{t('Consultado')}</span><span className="dim mono" style={{ fontSize: 11.5 }}>{info.Disclosure?.queriedAt || '—'}</span></div>
              <div className="hop-row"><span className="hop-host">{t('Caché')}</span><span className="dim mono" style={{ fontSize: 11.5 }}>{info.Disclosure?.cachePolicy || '—'}</span></div>
              <div className="hop-row"><span className="hop-host">{t('Enviado')}</span><span className="dim mono" style={{ fontSize: 11.5 }}>{info.Disclosure?.dataSent || '—'}</span></div>
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Timeline ({count})', { count: timelineState.events.length })}</h3>
            <div className="mtr-table-wrap">
              <table className="mtr-table realtime-timeline">
                <thead><tr>
                  <th className="l">{t('Hora')}</th>
                  <th className="l">{t('Tipo')}</th>
                  <th className="l">{t('Prefijo')}</th>
                  <th className="l">Peer ASN</th>
                  <th className="l">Peer</th>
                  <th className="l">{t('Fuente')}</th>
                </tr></thead>
                <tbody>
                  {timelineState.events.length === 0 && (
                    <tr><td colSpan={6} className="l dim">{t('Sin eventos todavía.')}</td></tr>
                  )}
                  {timelineState.events.map((ev) => (
                    <Fragment key={ev.ID}>
                      <tr>
                        <td className="l" title={ev.Timestamp || undefined}>{formatTimestamp(ev.Timestamp)}</td>
                        <td className="l"><span className={'event-type ' + eventTypeClass(ev.Type)}>{eventTypeLabel(t, ev.Type)}</span></td>
                        <td className="l mono">{ev.Prefix || '—'}</td>
                        <td className="l mono">{ev.PeerASN ? 'AS' + ev.PeerASN : '—'}</td>
                        <td className="l mono">{ev.Peer || '—'}</td>
                        <td className="l dim">{ev.Source || '—'}</td>
                      </tr>
                      {EVENT_TYPE_LABEL[ev.Type] !== undefined && (
                        <tr className="realtime-detail-row">
                          {/* RealtimeEventDetail devuelve null para tipos
                              desconocidos — la fila solo existe si hay
                              contenido real que mostrar. */}
                          <td colSpan={6} className="l"><RealtimeEventDetail ev={ev} /></td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </>
  );
}

// ---------------- Histórico ----------------
function HistoricoPanel() {
  const { t } = useI18n();
  const [resource, setResource] = useState('1.1.1.0/24');
  const [startLocal, setStartLocal] = useState('');
  const [endLocal, setEndLocal] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<bgp.BGPHistoryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  async function consultar() {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    const startRFC = localDateTimeToRFC3339(startLocal);
    const endRFC = localDateTimeToRFC3339(endLocal);
    if (!resource.trim() || !startRFC || !endRFC) {
      setFormError(t('Completa recurso, inicio y fin con fechas válidas.'));
      return;
    }
    setFormError(null);
    setError(null);
    setLoading(true);
    setResult(null);
    try {
      const r = await bgpHistory({ Resource: resource.trim(), StartTime: startRFC, EndTime: endRFC } as bgp.BGPHistoryRequest);
      setResult(r);
      if (r.err) setError(r.err);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" placeholder={t('ASN, IP o prefijo')} value={resource} onChange={(e) => setResource(e.target.value)} />
          <input className="input" type="datetime-local" value={startLocal} onChange={(e) => setStartLocal(e.target.value)} aria-label={t('Inicio')} />
          <input className="input" type="datetime-local" value={endLocal} onChange={(e) => setEndLocal(e.target.value)} aria-label={t('Fin')} />
          <button className="btn" onClick={consultar} disabled={loading || !resource.trim() || !startLocal || !endLocal}>
            {loading ? <span className="spin" /> : '🕓'} {t('Consultar')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Consulta explícita a RIPEstat bgp-updates para un rango de tiempo cerrado — nunca automática al abrir la pestaña, nunca un rango oculto de 24h.')}
        </p>
      </div>

      {formError && <div className="note" role="alert">{formError}</div>}
      {error && <BGPErrorNotice error={error} />}

      {result && !result.err && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat"><span className="label">{t('Recurso')}</span><span className="value accent">{result.Resource}</span></div>
            <div className="card stat"><span className="label">{t('Rango')}</span><span className="value" style={{ fontSize: 13 }}>{formatTimestamp(result.StartTime)} → {formatTimestamp(result.EndTime)}</span></div>
            <div className="card stat">
              <span className="label">{t('Eventos observados')}</span>
              <span className="value">{result.observedUpdates}</span>
              <span className="sub">{t('{shown} mostrados', { shown: result.updates?.length ?? 0 })}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Vista')}</span>
              <span className={'value ' + (result.truncated ? '' : 'accent')}>{result.truncated ? t('recortada') : t('completa')}</span>
            </div>
          </div>

          {result.truncated && (
            <div className="note" style={{ marginTop: 16 }}>
              {t('Se muestran los primeros {shown} eventos de {total} observados.', { shown: result.updates?.length ?? 0, total: result.observedUpdates })}
            </div>
          )}

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Eventos ({count})', { count: result.updates?.length ?? 0 })}</h3>
            <div className="mtr-table-wrap">
              <table className="mtr-table">
                <thead><tr>
                  <th className="l">{t('Hora')}</th>
                  <th className="l">{t('Tipo')}</th>
                  <th className="l">Source ID</th>
                  <th className="l">{t('Prefijo destino')}</th>
                  <th className="l">AS-path</th>
                  <th className="l">Community</th>
                </tr></thead>
                <tbody>
                  {(result.updates || []).map((u, i) => (
                    <tr key={u.Seq ?? i}>
                      <td className="l" title={u.Timestamp || undefined}>{formatTimestamp(u.Timestamp)}</td>
                      <td className="l">{historyTypeLabel(t, u.Type)}</td>
                      <td className="l mono">{u.SourceID || '—'}</td>
                      <td className="l mono">{u.targetPrefix || '—'}</td>
                      <td className="l mono" style={{ fontSize: 11.5 }}>{u.path && u.path.length ? u.path.map((p) => 'AS' + p).join(' → ') : '—'}</td>
                      <td className="l mono" style={{ fontSize: 11.5 }}>{u.community && u.community.length ? u.community.join(', ') : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <EvidenceList evidence={result.evidence} />
        </>
      )}
    </>
  );
}

// ---------------- BGPlay ----------------
function BGPlayPanel() {
  const { t } = useI18n();
  const [resource, setResource] = useState('1.1.1.0/24');
  const [startLocal, setStartLocal] = useState('');
  const [endLocal, setEndLocal] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<bgp.BGPlayResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  async function consultar() {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    const startRFC = localDateTimeToRFC3339(startLocal);
    const endRFC = localDateTimeToRFC3339(endLocal);
    if (!resource.trim() || !startRFC || !endRFC) {
      setFormError(t('Completa recurso, inicio y fin con fechas válidas.'));
      return;
    }
    setFormError(null);
    setError(null);
    setLoading(true);
    setResult(null);
    try {
      const r = await bgPlay({ Resource: resource.trim(), StartTime: startRFC, EndTime: endRFC } as bgp.BGPlayRequest);
      setResult(r);
      if (r.err) setError(r.err);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" placeholder={t('ASN, IP o prefijo')} value={resource} onChange={(e) => setResource(e.target.value)} />
          <input className="input" type="datetime-local" value={startLocal} onChange={(e) => setStartLocal(e.target.value)} aria-label={t('Inicio')} />
          <input className="input" type="datetime-local" value={endLocal} onChange={(e) => setEndLocal(e.target.value)} aria-label={t('Fin')} />
          <button className="btn" onClick={consultar} disabled={loading || !resource.trim() || !startLocal || !endLocal}>
            {loading ? <span className="spin" /> : '🎞️'} {t('Consultar')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Consulta explícita a RIPEstat bgplay para un rango de tiempo cerrado — estado inicial + eventos + nodos + fuentes observadas.')}
        </p>
      </div>

      {formError && <div className="note" role="alert">{formError}</div>}
      {error && <BGPErrorNotice error={error} />}

      {result && !result.err && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat"><span className="label">{t('Recurso')}</span><span className="value accent">{result.Resource}</span></div>
            <div className="card stat"><span className="label">{t('Rango')}</span><span className="value" style={{ fontSize: 13 }}>{formatTimestamp(result.StartTime)} → {formatTimestamp(result.EndTime)}</span></div>
            <div className="card stat">
              <span className="label">{t('Eventos')}</span>
              <span className="value">{result.observedEvents}</span>
              <span className="sub">{t('{shown} mostrados', { shown: result.events?.length ?? 0 })}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Vista')}</span>
              <span className={'value ' + (result.truncated ? '' : 'accent')}>{result.truncated ? t('recortada') : t('completa')}</span>
            </div>
          </div>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat"><span className="label">{t('Estado inicial')}</span><span className="value">{result.observedInitialState}</span><span className="sub">{t('{shown} mostrados', { shown: result.initialState?.length ?? 0 })}</span></div>
            <div className="card stat"><span className="label">{t('Nodos')}</span><span className="value">{result.observedNodes}</span><span className="sub">{t('{shown} mostrados', { shown: result.nodes?.length ?? 0 })}</span></div>
            <div className="card stat"><span className="label">{t('Fuentes')}</span><span className="value">{result.sources?.length ?? 0}</span></div>
          </div>

          {result.truncated && (
            <div className="note" style={{ marginTop: 16 }}>
              {t('Vista recortada por límites del backend — algunos elementos observados no se muestran.')}
            </div>
          )}

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Estado inicial al comienzo del rango ({count})', { count: result.initialState?.length ?? 0 })}</h3>
            <div className="mtr-table-wrap">
              <table className="mtr-table">
                <thead><tr>
                  <th className="l">Source ID</th>
                  <th className="l">{t('Prefijo destino')}</th>
                  <th className="l">AS-path</th>
                  <th className="l">Community</th>
                </tr></thead>
                <tbody>
                  {(result.initialState || []).map((p, i) => (
                    <tr key={i}>
                      <td className="l mono">{p.SourceID || '—'}</td>
                      <td className="l mono">{p.TargetPrefix || '—'}</td>
                      <td className="l mono" style={{ fontSize: 11.5 }}>{p.Path && p.Path.length ? p.Path.map((n) => 'AS' + n).join(' → ') : '—'}</td>
                      <td className="l mono" style={{ fontSize: 11.5 }}>{p.Community && p.Community.length ? p.Community.join(', ') : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Eventos ({count})', { count: result.events?.length ?? 0 })}</h3>
            <div className="mtr-table-wrap">
              <table className="mtr-table">
                <thead><tr>
                  <th className="l">{t('Hora')}</th>
                  <th className="l">{t('Tipo')}</th>
                  <th className="l">Source ID</th>
                  <th className="l">{t('Prefijo destino')}</th>
                  <th className="l">AS-path</th>
                  <th className="l">Community</th>
                </tr></thead>
                <tbody>
                  {(result.events || []).map((u, i) => (
                    <tr key={u.Seq ?? i}>
                      <td className="l" title={u.Timestamp || undefined}>{formatTimestamp(u.Timestamp)}</td>
                      <td className="l">{historyTypeLabel(t, u.Type)}</td>
                      <td className="l mono">{u.SourceID || '—'}</td>
                      <td className="l mono">{u.targetPrefix || '—'}</td>
                      <td className="l mono" style={{ fontSize: 11.5 }}>{u.path && u.path.length ? u.path.map((p) => 'AS' + p).join(' → ') : '—'}</td>
                      <td className="l mono" style={{ fontSize: 11.5 }}>{u.community && u.community.length ? u.community.join(', ') : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Nodos ({count})', { count: result.nodes?.length ?? 0 })}</h3>
            <div className="hop-list">
              {(result.nodes || []).map((n, i) => (
                <div className="hop-row" key={i}>
                  <span className="hop-ttl mono">AS{n.ASN}</span>
                  <span className="dim" style={{ fontSize: 11.5 }}>{n.Owner || '—'}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Fuentes ({count})', { count: result.sources?.length ?? 0 })}</h3>
            <div className="mtr-table-wrap">
              <table className="mtr-table">
                <thead><tr>
                  <th className="l">ASN</th>
                  <th className="l">ID</th>
                  <th className="l">IP</th>
                  <th className="l">RRC</th>
                </tr></thead>
                <tbody>
                  {(result.sources || []).map((s, i) => (
                    <tr key={i}>
                      <td className="l mono">AS{s.ASN}</td>
                      <td className="l mono">{s.ID}</td>
                      <td className="l mono">{s.IP}</td>
                      <td className="l mono">{s.RRC}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <EvidenceList evidence={result.evidence} />
        </>
      )}
    </>
  );
}

// ---------------- Observatorio (v1.3 Gate 6) ----------------
// Cinco secciones independientes (país/global/ASN/RPKI/bogons), cada una
// pura delegación a su binding de Gate 5 — sin cálculos derivados (%,
// score, health, risk), sin auto-consulta al entrar/cambiar de sub-tab,
// sin polling. Ver contrato completo en cada bgp.*Observatory*/BogonLookup.

type ObservatorioSubTab = 'pais' | 'global' | 'asn' | 'rpki' | 'bogons';

// ---- A) País ----
function ObservatorioPaisPanel() {
  const { t } = useI18n();
  const [country, setCountry] = useState('PA');
  const [startLocal, setStartLocal] = useState('');
  const [endLocal, setEndLocal] = useState('');
  const [resolution, setResolution] = useState<'5m' | '1h' | '1d' | '1w'>('1d');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<bgp.CountryObservatoryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  async function consultar() {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    const startRFC = localDateTimeToRFC3339(startLocal);
    const endRFC = localDateTimeToRFC3339(endLocal);
    if (!country.trim() || !startRFC || !endRFC) {
      setFormError(t('Completa país, inicio y fin con fechas válidas.'));
      return;
    }
    setFormError(null);
    setError(null);
    setLoading(true);
    setResult(null);
    try {
      const r = await bgpCountryObservatory({
        Country: country.trim(), StartTime: startRFC, EndTime: endRFC, Resolution: resolution,
      } as bgp.CountryObservatoryRequest);
      setResult(r);
      if (r.err) setError(r.err);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" style={{ maxWidth: 110 }} placeholder={t('País (ISO alpha-2)')} value={country} onChange={(e) => setCountry(e.target.value)} />
          <select className="input" style={{ maxWidth: 110 }} value={resolution} onChange={(e) => setResolution(e.target.value as '5m' | '1h' | '1d' | '1w')}>
            <option value="5m">5m</option>
            <option value="1h">1h</option>
            <option value="1d">1d</option>
            <option value="1w">1w</option>
          </select>
          <input className="input" type="datetime-local" value={startLocal} onChange={(e) => setStartLocal(e.target.value)} aria-label={t('Inicio')} />
          <input className="input" type="datetime-local" value={endLocal} onChange={(e) => setEndLocal(e.target.value)} aria-label={t('Fin')} />
          <button className="btn" onClick={consultar} disabled={loading || !country.trim() || !startLocal || !endLocal}>
            {loading ? <span className="spin" /> : '🌎'} {t('Consultar')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Consulta explícita a RIPEstat country-resource-stats para un rango de tiempo cerrado y una resolución exacta.')}
        </p>
      </div>

      {formError && <div className="note" role="alert">{formError}</div>}
      {error && <BGPErrorNotice error={error} />}

      {result && !result.err && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat"><span className="label">{t('País')}</span><span className="value accent">{result.country}</span></div>
            <div className="card stat"><span className="label">{t('Resolución')}</span><span className="value">{result.resolution}</span></div>
            <div className="card stat"><span className="label">{t('Datos suficientes')}</span><span className="value">{result.dataSufficient ? t('sí') : t('no')}</span></div>
            <div className="card stat"><span className="label">{t('Puntos')}</span><span className="value">{result.points?.length ?? 0}</span></div>
          </div>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat"><span className="label">QueryStartTime</span><span className="value" style={{ fontSize: 13 }}>{formatTimestamp(result.queryStartTime)}</span></div>
            <div className="card stat"><span className="label">QueryEndTime</span><span className="value" style={{ fontSize: 13 }}>{formatTimestamp(result.queryEndTime)}</span></div>
            <div className="card stat"><span className="label">EarliestTime</span><span className="value" style={{ fontSize: 13 }}>{formatTimestamp(result.earliestTime)}</span></div>
            <div className="card stat"><span className="label">LatestTime</span><span className="value" style={{ fontSize: 13 }}>{formatTimestamp(result.latestTime)}</span></div>
          </div>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat"><span className="label">HDLatestTime</span><span className="value" style={{ fontSize: 13 }}>{formatTimestamp(result.hdLatestTime)}</span></div>
          </div>

          <div className="note" style={{ marginTop: 16 }}>
            {t('Registro RIR y observación RIS son métricas distintas; una diferencia entre ambas no implica inactividad, problema o riesgo.')}
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Puntos ({count})', { count: result.points?.length ?? 0 })}</h3>
            <div className="mtr-table-wrap">
              <table className="mtr-table">
                <thead><tr>
                  <th className="l">{t('Inicio')}</th>
                  <th className="l">{t('Fin')}</th>
                  <th className="l">StatsData</th>
                  <th>{t('ASN observados por RIS')}</th>
                  <th>{t('ASN registrados')}</th>
                  <th>{t('Prefijos IPv4 observados por RIS')}</th>
                  <th>{t('Prefijos IPv4 registrados')}</th>
                  <th>{t('Prefijos IPv6 observados por RIS')}</th>
                  <th>{t('Prefijos IPv6 registrados')}</th>
                </tr></thead>
                <tbody>
                  {(result.points || []).length === 0 && (
                    <tr><td colSpan={9} className="l dim">{t('Sin puntos en el rango consultado.')}</td></tr>
                  )}
                  {(result.points || []).map((p, i) => (
                    <tr key={i}>
                      <td className="l" title={p.startTime || undefined}>{formatTimestamp(p.startTime)}</td>
                      <td className="l" title={p.endTime || undefined}>{formatTimestamp(p.endTime)}</td>
                      <td className="l dim mono" style={{ fontSize: 11 }}>{p.statsData || '—'}</td>
                      <td>{p.asnsRis}</td>
                      <td>{p.asnsRegistered}</td>
                      <td>{p.ipv4PrefixesRis}</td>
                      <td>{p.ipv4PrefixesRegistered}</td>
                      <td>{p.ipv6PrefixesRis}</td>
                      <td>{p.ipv6PrefixesRegistered}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <EvidenceList evidence={result.evidence} />
        </>
      )}
    </>
  );
}

// ---- B) Global / RIS ----
function ObservatorioGlobalPanel() {
  const { t } = useI18n();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<bgp.GlobalRISObservatoryResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function consultar() {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    setError(null);
    setLoading(true);
    setResult(null);
    try {
      const r = await bgpGlobalObservatory();
      setResult(r);
      if (r.err) setError(r.err);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <button className="btn" onClick={consultar} disabled={loading}>
            {loading ? <span className="spin" /> : '🌐'} {t('Consultar snapshot RIS')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Snapshot observado por RIPE RIS; no representa una autoridad global absoluta de todo Internet.')}
        </p>
      </div>

      {error && <BGPErrorNotice error={error} />}

      {/* result siempre se renderiza si existe — un fallo parcial (ej. ris-asns
          OK, ris-peer-count Degraded) preserva los valores de la fuente sana;
          `!result.err` como gate hubiera escondido ese snapshot parcial
          entero (Gate 6 P1 fix). El error ya se muestra arriba. */}
      {result && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat">
              <span className="label">{t('ASN visibles por RIS')}</span>
              <span className="value">{displayOptionalNumber(result.visibleAsns)}</span>
              <span className="sub">{result.asnsQueryTime ? formatTimestamp(result.asnsQueryTime) : '—'}</span>
            </div>
            <div className="card stat"><span className="label">{t('Peers RIS IPv4 · total')}</span><span className="value">{displayOptionalNumber(result.risPeersIPv4Total)}</span></div>
            <div className="card stat"><span className="label">{t('Peers RIS IPv4 · full feed')}</span><span className="value">{displayOptionalNumber(result.risPeersIPv4FullFeed)}</span></div>
            <div className="card stat"><span className="label">{t('Datos suficientes')}</span><span className="value">{result.dataSufficient ? t('sí') : t('no')}</span></div>
          </div>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat"><span className="label">{t('Peers RIS IPv6 · total')}</span><span className="value">{displayOptionalNumber(result.risPeersIPv6Total)}</span></div>
            <div className="card stat"><span className="label">{t('Peers RIS IPv6 · full feed')}</span><span className="value">{displayOptionalNumber(result.risPeersIPv6FullFeed)}</span></div>
            <div className="card stat"><span className="label">PeersStartTime</span><span className="value" style={{ fontSize: 13 }}>{formatTimestamp(result.peersStartTime)}</span></div>
            <div className="card stat"><span className="label">PeersEndTime</span><span className="value" style={{ fontSize: 13 }}>{formatTimestamp(result.peersEndTime)}</span></div>
          </div>

          <EvidenceList evidence={result.evidence} />
        </>
      )}
    </>
  );
}

// ---- C) ASN ----
function ObservatorioASNPanel() {
  const { t } = useI18n();
  const [asn, setAsn] = useState('AS13335');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<bgp.ASNObservatoryResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function consultar() {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    setError(null);
    setLoading(true);
    setResult(null);
    try {
      const r = await bgpASNObservatory({ ASN: asn.trim() } as bgp.ASNObservatoryRequest);
      setResult(r);
      if (r.err) setError(r.err);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" placeholder="AS13335" value={asn} onChange={(e) => setAsn(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && !loading && consultar()} />
          <button className="btn" onClick={consultar} disabled={loading || !asn.trim()}>
            {loading ? <span className="spin" /> : '🔢'} {t('Consultar')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Conteos derivados de prefijos observados por el datasource; no implican propiedad, importancia ni relación comercial.')}
        </p>
      </div>

      {error && <BGPErrorNotice error={error} />}

      {result && !result.err && (
        <div className="grid cols-4" style={{ marginTop: 16 }}>
          <div className="card stat"><span className="label">ASN</span><span className="value accent">AS{result.asn}</span></div>
          <div className="card stat">
            <span className="label">{t('Prefijos IPv4 observados')}</span>
            <span className="value">{result.dataSufficient ? result.announcedIPv4Prefixes : '—'}</span>
          </div>
          <div className="card stat">
            <span className="label">{t('Prefijos IPv6 observados')}</span>
            <span className="value">{result.dataSufficient ? result.announcedIPv6Prefixes : '—'}</span>
          </div>
          <div className="card stat"><span className="label">{t('Datos suficientes')}</span><span className="value">{result.dataSufficient ? t('sí') : t('no')}</span></div>
        </div>
      )}

      {result && !result.err && <EvidenceList evidence={result.evidence} />}
    </>
  );
}

// ---- D) RPKI ----
function ObservatorioRPKIPanel() {
  const { t } = useI18n();
  const [resource, setResource] = useState('AS13335');
  const [family, setFamily] = useState<4 | 6>(4);
  const [resolution, setResolution] = useState<'d' | 'w' | 'm' | 'y'>('d');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<bgp.RPKIObservatoryResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function consultar() {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    if (!resource.trim()) return;
    setError(null);
    setLoading(true);
    setResult(null);
    try {
      const r = await bgpRPKIObservatory({
        Resource: resource.trim(), Family: family, Resolution: resolution,
      } as bgp.RPKIObservatoryRequest);
      setResult(r);
      if (r.err) setError(r.err);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  const isDaily = result?.resolution === 'd';

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" placeholder="AS13335" value={resource} onChange={(e) => setResource(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && !loading && consultar()} />
          <select className="input" style={{ maxWidth: 90 }} value={family} onChange={(e) => setFamily(Number(e.target.value) as 4 | 6)}>
            <option value={4}>IPv4</option>
            <option value={6}>IPv6</option>
          </select>
          <select className="input" style={{ maxWidth: 90 }} value={resolution} onChange={(e) => setResolution(e.target.value as 'd' | 'w' | 'm' | 'y')}>
            <option value="d">d</option>
            <option value="w">w</option>
            <option value="m">m</option>
            <option value="y">y</option>
          </select>
          <button className="btn" onClick={consultar} disabled={loading || !resource.trim()}>
            {loading ? <span className="spin" /> : '📈'} {t('Consultar')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Gate 3 solo admite ASN o país ISO alpha-2 — los prefijos quedan fuera de v1.3.')}
        </p>
      </div>

      {error && <BGPErrorNotice error={error} />}

      {/* result.resourceKind != "" es la única señal inequívoca de "el
          request pasó validación local" — a diferencia de !result.err, que
          escondería puntos ya decodificados de una serie estructuralmente
          incompleta (rpki-history preserva Points antes de detectar el
          punto incompleto). Un request rechazado localmente nunca llega a
          setear ResourceKind (Gate 6 P1 fix). */}
      {result && result.resourceKind && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat"><span className="label">{t('Recurso')}</span><span className="value accent">{result.resource}</span></div>
            <div className="card stat"><span className="label">{t('Tipo')}</span><span className="value">{result.resourceKind}</span></div>
            <div className="card stat"><span className="label">Family</span><span className="value">IPv{result.family}</span></div>
            <div className="card stat"><span className="label">Resolution</span><span className="value">{result.resolution}</span></div>
          </div>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat"><span className="label">{t('Datos suficientes')}</span><span className="value">{result.dataSufficient ? t('sí') : t('no')}</span></div>
          </div>

          <div className="note" style={{ marginTop: 16 }}>
            {t('RPKI Observatory muestra historial de cantidad de VRPs. VRP count no equivale al estado VALID/INVALID de una ruta BGP.')}
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Puntos ({count})', { count: result.points?.length ?? 0 })}</h3>
            <div className="mtr-table-wrap">
              {isDaily ? (
                <table className="mtr-table">
                  <thead><tr>
                    <th className="l">Time</th>
                    <th>VRPCount</th>
                  </tr></thead>
                  <tbody>
                    {(result.points || []).length === 0 && (
                      <tr><td colSpan={2} className="l dim">{t('Sin puntos en la serie devuelta.')}</td></tr>
                    )}
                    {(result.points || []).map((p, i) => (
                      <tr key={i}>
                        <td className="l" title={p.time || undefined}>{formatTimestamp(p.time)}</td>
                        <td>{displayOptionalNumber(p.vrpCount)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <table className="mtr-table">
                  <thead><tr>
                    <th className="l">Time</th>
                    <th>Min</th>
                    <th>Max</th>
                    <th>Avg</th>
                    <th>First</th>
                    <th>Last</th>
                    <th>Samples</th>
                  </tr></thead>
                  <tbody>
                    {(result.points || []).length === 0 && (
                      <tr><td colSpan={7} className="l dim">{t('Sin puntos en la serie devuelta.')}</td></tr>
                    )}
                    {(result.points || []).map((p, i) => (
                      <tr key={i}>
                        <td className="l" title={p.time || undefined}>{formatTimestamp(p.time)}</td>
                        <td>{displayOptionalNumber(p.min)}</td>
                        <td>{displayOptionalNumber(p.max)}</td>
                        <td>{displayOptionalNumber(p.avg)}</td>
                        <td>{displayOptionalNumber(p.first)}</td>
                        <td>{displayOptionalNumber(p.last)}</td>
                        <td>{displayOptionalNumber(p.samples)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          <EvidenceList evidence={result.evidence} />
        </>
      )}
    </>
  );
}

// ---- E) Bogons ----
function ObservatorioBogonPanel() {
  const { t } = useI18n();
  const [resource, setResource] = useState('8.8.8.8');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<bgp.BogonLookupResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function consultar() {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    if (!resource.trim()) return;
    setError(null);
    setLoading(true);
    setResult(null);
    try {
      const r = await bgpBogonLookup({ Resource: resource.trim() } as bgp.BogonLookupRequest);
      setResult(r);
      if (r.err) setError(r.err);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" placeholder="8.8.8.8" value={resource} onChange={(e) => setResource(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && !loading && consultar()} />
          <button className="btn" onClick={consultar} disabled={loading || !resource.trim()}>
            {loading ? <span className="spin" /> : '🧭'} {t('Consultar')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('IANA Special-Purpose y Team Cymru Fullbogons son fuentes independientes — se muestran por separado, nunca combinadas en un veredicto único.')}
        </p>
      </div>

      {error && <BGPErrorNotice error={error} />}

      {/* result.resourceKind != "" es la única señal inequívoca de "el
          request pasó validación local" — a diferencia de !result.err, que
          escondería un resultado parcial válido (ej. IANA OK / Cymru
          Degraded: classifyIANA/classifyCymru setean sus campos de forma
          independiente, cada uno sobrevive al fallo del otro). Un request
          rechazado localmente nunca llega a setear ResourceKind (Gate 6 P1
          fix). */}
      {result && result.resourceKind && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat"><span className="label">{t('Recurso')}</span><span className="value accent">{result.resource}</span></div>
            <div className="card stat"><span className="label">{t('Tipo')}</span><span className="value">{result.resourceKind}</span></div>
            <div className="card stat"><span className="label">Family</span><span className="value">IPv{result.family}</span></div>
            <div className="card stat"><span className="label">{t('Datos suficientes')}</span><span className="value">{result.dataSufficient ? t('sí') : t('no')}</span></div>
          </div>

          <div className="grid cols-2" style={{ marginTop: 16 }}>
            <div className="card">
              <h3>IANA Special-Purpose</h3>
              <div className="hop-list">
                <div className="hop-row"><span className="hop-host">{t('Coincidencia')}</span><span className="value">{triStateLabel(t, result.ianaSpecialPurpose)}</span></div>
                {result.ianaMatch && (
                  <>
                    <div className="hop-row"><span className="hop-host">Prefix</span><span className="dim mono" style={{ fontSize: 11.5 }}>{result.ianaMatch.prefix}</span></div>
                    <div className="hop-row"><span className="hop-host">Name</span><span className="dim" style={{ fontSize: 11.5 }}>{result.ianaMatch.name}</span></div>
                    <div className="hop-row"><span className="hop-host">RFC</span><span className="dim mono" style={{ fontSize: 11.5 }}>{result.ianaMatch.rfc || '—'}</span></div>
                    <div className="hop-row"><span className="hop-host">AllocationDate</span><span className="dim" style={{ fontSize: 11.5 }}>{result.ianaMatch.allocationDate || '—'}</span></div>
                    <div className="hop-row"><span className="hop-host">TerminationDate</span><span className="dim" style={{ fontSize: 11.5 }}>{result.ianaMatch.terminationDate || '—'}</span></div>
                    <div className="hop-row"><span className="hop-host">Source</span><span className="dim" style={{ fontSize: 11.5 }}>{triStateLabel(t, result.ianaMatch.source)}</span></div>
                    <div className="hop-row"><span className="hop-host">Destination</span><span className="dim" style={{ fontSize: 11.5 }}>{triStateLabel(t, result.ianaMatch.destination)}</span></div>
                    <div className="hop-row"><span className="hop-host">Forwardable</span><span className="dim" style={{ fontSize: 11.5 }}>{triStateLabel(t, result.ianaMatch.forwardable)}</span></div>
                    <div className="hop-row"><span className="hop-host">GloballyReachable</span><span className="dim" style={{ fontSize: 11.5 }}>{triStateLabel(t, result.ianaMatch.globallyReachable)}</span></div>
                    <div className="hop-row"><span className="hop-host">ReservedByProtocol</span><span className="dim" style={{ fontSize: 11.5 }}>{triStateLabel(t, result.ianaMatch.reservedByProtocol)}</span></div>
                  </>
                )}
              </div>
              <p className="dim" style={{ fontSize: 11, marginTop: 8 }}>
                {t('IANA Special-Purpose describe propiedades registradas por IANA. No es una clasificación de amenaza.')}
              </p>
            </div>

            <div className="card">
              <h3>Team Cymru Fullbogons</h3>
              <div className="hop-list">
                <div className="hop-row"><span className="hop-host">{t('Coincidencia')}</span><span className="value">{triStateLabel(t, result.cymruFullBogon)}</span></div>
                {result.cymruFullBogon && result.cymruMatchPrefix && (
                  <div className="hop-row"><span className="hop-host">Prefix</span><span className="dim mono" style={{ fontSize: 11.5 }}>{result.cymruMatchPrefix}</span></div>
                )}
              </div>
              <p className="dim" style={{ fontSize: 11, marginTop: 8 }}>
                {t('Team Cymru Fullbogons es una clasificación independiente de IANA. Una coincidencia no significa que la dirección sea maliciosa, atacante o comprometida.')}
              </p>
            </div>
          </div>

          <EvidenceList evidence={result.evidence} />
        </>
      )}
    </>
  );
}

function ObservatorioPanel() {
  const { t } = useI18n();
  const [sub, setSub] = useState<ObservatorioSubTab>('pais');

  const subtabs: { id: ObservatorioSubTab; label: string }[] = [
    { id: 'pais', label: t('País') },
    { id: 'global', label: 'Global / RIS' },
    { id: 'asn', label: 'ASN' },
    { id: 'rpki', label: 'RPKI' },
    { id: 'bogons', label: 'Bogons' },
  ];

  // Patrón WAI-ARIA Tabs con activación automática: las flechas mueven
  // foco Y selección. Es seguro aquí porque los paneles permanecen
  // montados (solo display:none) — cambiar de sub-tab nunca descarta
  // resultados ya consultados.
  function onSubTabKeyDown(event: React.KeyboardEvent<HTMLButtonElement>, index: number) {
    const next = nextTabIndex(event.key, index, subtabs.length);
    if (next === null) return;
    event.preventDefault();
    const id = subtabs[next].id;
    setSub(id);
    document.getElementById(ariaTabIds('obs', id).tab)?.focus();
  }

  return (
    <>
      <div className="tabs" role="tablist" aria-label={t('Observatorio')}>
        {subtabs.map((s, i) => {
          const ids = ariaTabIds('obs', s.id);
          return (
            <button key={s.id} role="tab" id={ids.tab} aria-selected={sub === s.id} aria-controls={ids.panel}
              tabIndex={sub === s.id ? 0 : -1}
              className={'tab' + (sub === s.id ? ' active' : '')}
              onClick={() => setSub(s.id)} onKeyDown={(event) => onSubTabKeyDown(event, i)}>
              {s.label}
            </button>
          );
        })}
      </div>

      {subtabs.map((s) => {
        const ids = ariaTabIds('obs', s.id);
        return (
          <div key={s.id} id={ids.panel} role="tabpanel" aria-labelledby={ids.tab}
            style={{ display: sub === s.id ? 'block' : 'none' }}>
            {s.id === 'pais' && <ObservatorioPaisPanel />}
            {s.id === 'global' && <ObservatorioGlobalPanel />}
            {s.id === 'asn' && <ObservatorioASNPanel />}
            {s.id === 'rpki' && <ObservatorioRPKIPanel />}
            {s.id === 'bogons' && <ObservatorioBogonPanel />}
          </div>
        );
      })}
    </>
  );
}

// ---------------- Tabbed view ----------------
export default function BgpIntelligence() {
  const { t } = useI18n();
  const [tab, setTab] = useState<Tab>('resumen');
  const [panelEpochs, setPanelEpochs] = useState<Record<Tab, number>>({
    resumen: 0, prefijos: 0, vecinos: 0, topologia: 0, seguridad: 0, realtime: 0, history: 0, bgplay: 0, observatorio: 0,
  });

  const tabs: { id: Tab; label: string }[] = [
    { id: 'resumen', label: t('Resumen') },
    { id: 'prefijos', label: t('Prefijos') },
    { id: 'vecinos', label: t('Vecinos') },
    { id: 'topologia', label: t('Topología') },
    { id: 'seguridad', label: t('Seguridad') },
    { id: 'realtime', label: t('Tiempo real') },
    { id: 'history', label: t('Histórico') },
    { id: 'bgplay', label: 'BGPlay' },
    { id: 'observatorio', label: t('Observatorio') },
  ];

  function clearActiveTab() {
    setPanelEpochs((prev) => ({ ...prev, [tab]: prev[tab] + 1 }));
  }

  // WAI-ARIA Tabs con activación automática: seguro porque los paneles
  // quedan montados (solo display:none) — ni flechas ni foco descartan
  // resultados ni sesiones activas.
  function onTabKeyDown(event: React.KeyboardEvent<HTMLButtonElement>, index: number) {
    const next = nextTabIndex(event.key, index, tabs.length);
    if (next === null) return;
    event.preventDefault();
    const id = tabs[next].id;
    setTab(id);
    document.getElementById(ariaTabIds('bgp', id).tab)?.focus();
  }

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('BGP Intelligence')}</h2>
        <p className="body-text">
          {t('Resumen, prefijos anunciados, vecinos observados, topología de AS-paths y análisis de seguridad RPKI para un ASN, IP o prefijo — vía RIPEstat, sin fuentes propietarias ni inferencias comerciales.')}
        </p>
      </div>

      <div className="tabs">
        {/* tablist en un contenedor display:contents para que el botón
            "Limpiar pestaña" (una acción, no una pestaña) quede fuera de
            la lista de tabs sin alterar el layout flex existente. */}
        <div role="tablist" aria-label={t('BGP Intelligence')} style={{ display: 'contents' }}>
          {tabs.map((entry, i) => {
            const ids = ariaTabIds('bgp', entry.id);
            return (
              <button key={entry.id} role="tab" id={ids.tab} aria-selected={tab === entry.id} aria-controls={ids.panel}
                tabIndex={tab === entry.id ? 0 : -1}
                className={'tab' + (tab === entry.id ? ' active' : '')}
                onClick={() => setTab(entry.id)} onKeyDown={(event) => onTabKeyDown(event, i)}>
                {entry.label}
              </button>
            );
          })}
        </div>
        <button className="btn ghost tab-clear" onClick={clearActiveTab}>🗑 {t('Limpiar pestaña')}</button>
      </div>

      {/* Montados siempre, solo ocultos con CSS: cambiar de pestaña no
          descarta los resultados de la consulta anterior. "Limpiar pestaña"
          remonta el panel activo vía panelEpochs — el único caso en que
          RealtimePanel se desmonta mientras una sesión sigue activa, y su
          propio cleanup de efecto (ver RealtimePanel) es lo que la detiene. */}
      {tabs.map((entry) => {
        const ids = ariaTabIds('bgp', entry.id);
        return (
          <div key={entry.id} id={ids.panel} role="tabpanel" aria-labelledby={ids.tab}
            style={{ display: tab === entry.id ? 'block' : 'none' }}>
            {entry.id === 'resumen' && <ResumenPanel key={panelEpochs.resumen} />}
            {entry.id === 'prefijos' && <PrefijosPanel key={panelEpochs.prefijos} />}
            {entry.id === 'vecinos' && <VecinosPanel key={panelEpochs.vecinos} />}
            {entry.id === 'topologia' && <TopologiaPanel key={panelEpochs.topologia} />}
            {entry.id === 'seguridad' && <SeguridadPanel key={panelEpochs.seguridad} />}
            {entry.id === 'realtime' && <RealtimePanel key={panelEpochs.realtime} />}
            {entry.id === 'history' && <HistoricoPanel key={panelEpochs.history} />}
            {entry.id === 'bgplay' && <BGPlayPanel key={panelEpochs.bgplay} />}
            {entry.id === 'observatorio' && <ObservatorioPanel key={panelEpochs.observatorio} />}
          </div>
        );
      })}
    </div>
  );
}
