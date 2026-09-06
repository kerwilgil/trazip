import { createContext, useContext, useEffect, useState } from 'react';
import CopyButton from '../components/CopyButton';
import { useCaptureSession } from '../lib/session';
import {
  backendAvailable,
  dnsResolvers,
  dnsRecordTypes,
  dnsQuery,
  dnsCompare,
  dnsReversePTR,
  dnsResolveSRVTargets,
  dnsDiscoverSRVSIP,
  tlsInspect,
  httpInspect,
  webIntelAnalyze,
  rdapLookupIP,
  rdapLookupASN,
  bgpRoutingStatus,
  bgpRPKIValidate,
  reputationAssess,
	passiveOSINT,
	type PassiveOSINTResult,
  type dnsintel,
  type tlsintel,
  type httpintel,
  type webintel,
  type rdap,
  type bgp,
  type reputation,
} from '../lib/api';
import DomainRegistration from '../components/DomainRegistration';
import { useI18n } from '../lib/i18n';
import { csvEscape } from '../lib/csv';

const NO_BACKEND = 'Necesita el runtime Wails (app de escritorio). En el preview del navegador no hay backend.';

function safeArray<T>(value: readonly T[] | null | undefined): readonly T[] {
  return Array.isArray(value) ? value : [];
}

function webIntelStageLabel(stage: string | undefined, t: (source: string) => string): string {
  switch (stage) {
    case 'Analysis': return t('Análisis');
    case 'DNS': return 'DNS';
    case 'HTTP': return 'HTTP';
    case 'TLS': return 'TLS';
    case 'Redirect': return t('Redirección');
    default: return stage ?? t('Análisis');
  }
}

type Tab = 'url' | 'dns' | 'tls' | 'http' | 'rdap' | 'reputation' | 'osint' | 'historial';

// ---------------- Historial compartido entre pestañas ----------------
interface HistoryEntry {
  time: string;
  tool: string;
  query: string;
  summary: string;
}

const HistoryContext = createContext<(tool: string, query: string, summary: string) => void>(() => {});

function useAddHistory() {
  return useContext(HistoryContext);
}

function historyToCSV(entries: HistoryEntry[]): string {
  const header = 'hora,herramienta,consulta,resumen';
  const rows = entries.map((e) => [e.time, e.tool, e.query, e.summary].map(csvEscape).join(','));
  return [header, ...rows].join('\n');
}

function downloadText(filename: string, text: string, mime: string) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function HistorialPanel({ history, onClear }: { history: HistoryEntry[]; onClear: () => void }) {
  const { t } = useI18n();
  return (
    <div className="card">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
        <h3 style={{ margin: 0 }}>{t('Historial de consultas ({count})', { count: history.length })}</h3>
        <div style={{ display: 'flex', gap: 8 }}>
          <CopyButton label={t('Copiar CSV')} disabled={history.length === 0} getText={() => historyToCSV(history)} />
          <button
            className="btn ghost"
            disabled={history.length === 0}
            onClick={() => downloadText(`trazip-webintel-${Date.now()}.csv`, historyToCSV(history), 'text/csv')}
          >
            ⬇ {t('Descargar CSV')}
          </button>
          <button className="btn ghost" disabled={history.length === 0} onClick={onClear}>🗑 {t('Limpiar')}</button>
        </div>
      </div>
      <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
        {t('El historial se guarda solo en memoria durante esta sesión, con un máximo de 200 entradas. Se elimina al cerrar la aplicación.')}
      </p>
      {history.length === 0 ? (
        <p className="dim" style={{ marginTop: 12 }}>{t('Todavía no hay consultas en esta sesión.')}</p>
      ) : (
        <div className="mtr-table-wrap" style={{ marginTop: 12 }}>
          <table className="mtr-table">
            <thead><tr><th className="l">{t('Hora')}</th><th className="l">{t('Herramienta')}</th><th className="l">{t('Consulta')}</th><th className="l">{t('Resumen')}</th></tr></thead>
            <tbody>
              {history.map((h, i) => (
                <tr key={i}>
                  <td className="l dim mono" style={{ fontSize: 11 }}>{h.time}</td>
                  <td className="l">{h.tool}</td>
                  <td className="l mono">{h.query}</td>
                  <td className="l" style={{ whiteSpace: 'normal', fontSize: 12 }}>{h.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function DisclosureNote({ d }: { d: { source: string; queriedAt: string; dataSent: string; cachePolicy: string; confidence: string; rateLimit: string } }) {
  const { t } = useI18n();
  return (
    <div className="note" style={{ color: 'var(--text-dim)', background: 'var(--surface-2)', borderColor: 'var(--border)' }}>
      <strong>{d.source}</strong> · {t('consultado')} {d.queriedAt} · {t('datos enviados')}: {d.dataSent} · {t('caché')}: {d.cachePolicy} · {t('confianza')}: {d.confidence}
      <div style={{ fontSize: 11, marginTop: 4 }}>{d.rateLimit}</div>
    </div>
  );
}

// ---------------- URL Analyzer ----------------
function UrlAnalyzerPanel() {
  const { locale, t } = useI18n();
  const [input, setInput] = useState('cloudflare.com');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<webintel.Result | null>(null);
  const [requestError, setRequestError] = useState<string | null>(null);
  const addHistory = useAddHistory();

  async function analyze() {
    if (!backendAvailable()) return setRequestError(NO_BACKEND);
    setRequestError(null);
    setLoading(true);
    setResult(null);
    try {
      const r = await webIntelAnalyze(input.trim(), '');
      setResult(r);
      addHistory(t('Analizador URL'), input.trim(), r.error?.code || r.err || `${r.http.finalStatus} · ${safeArray(r.contactedEndpoints).length} endpoints · ${r.tls ? (r.tls.validationOK ? 'TLS OK' : t('TLS no confiable')) : t('sin HTTPS')}`);
    } catch (e) {
      setRequestError(String(e));
    } finally {
      setLoading(false);
    }
  }

  const analysisError = result?.error;
  const errorTitle = analysisError
    ? (locale === 'en-US' ? analysisError.friendlyMessageEN : analysisError.friendlyMessageES)
    : (requestError ? t('No fue posible completar el análisis.') : null);
  const technicalDetail = analysisError?.technicalDetail ?? requestError;
  const graphEdges = safeArray(result?.graph?.edges);
  const dnsChain = safeArray(result?.dnsChain);
  const redirects = safeArray(result?.http?.redirects);
  const signals = safeArray(result?.http?.signals);
  const endpoints = safeArray(result?.contactedEndpoints);
  const extractedHostnames = safeArray(result?.extractedHostnames);
  const extractedIPs = safeArray(result?.extractedIPs);
  const certificateChain = safeArray(result?.tls?.chain);

  return (
    <>
      <div className="card">
        <div className="field">
          <input
            className="input"
            placeholder={t('dominio o URL (cloudflare.com, https://ejemplo.com/ruta)')}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !loading && analyze()}
          />
          <button className="btn" onClick={analyze} disabled={loading || !input.trim()} aria-busy={loading}>
            {loading ? <span className="spin" /> : '🔎'} {t('Analizar')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Normaliza la URL, resuelve la cadena DNS/CNAME, sigue las redirecciones, inspecciona el TLS del host final, detecta señales CDN/WAF y correlaciona cada IP contactada con GeoIP/ASN sin conexión. No ejecuta JavaScript ni rastreo recursivo.')}
        </p>
      </div>

      {errorTitle && (
        <div className="note" role="alert" style={{ marginTop: 16 }}>
          <strong>{errorTitle}</strong>
          {analysisError?.stage && <div className="dim" style={{ marginTop: 4 }}>{t('Etapa')}: {webIntelStageLabel(analysisError.stage, t)}</div>}
          {analysisError?.retryable && <button className="btn ghost" style={{ marginTop: 8 }} onClick={analyze}>{t('Reintentar')}</button>}
          {technicalDetail && <details style={{ marginTop: 8 }}><summary>{t('Detalles técnicos')}</summary><pre className="mono" style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>{technicalDetail}</pre></details>}
        </div>
      )}

      {result && !result.err && (
        <>
          {analysisError && (
            <div className="note" style={{ marginTop: 16 }}>
              <strong>{t('Resultado parcial')}</strong>
              <div className="dim" style={{ marginTop: 4 }}>{t('Se muestran los datos disponibles; el análisis no se completó.')}</div>
            </div>
          )}
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat">
              <span className="label">{t('Estado final')}</span>
              <span className="value accent">{result.http.finalStatus}</span>
              <span className="sub">{t('{count} saltos', { count: redirects.length })}</span>
            </div>
            <div className="card stat">
              <span className="label">TLS</span>
              <span className="value">{result.tls ? (result.tls.validationOK ? t('válido') : t('no confiable')) : '—'}</span>
              <span className="sub">{result.tls?.protocol ?? t('sin HTTPS')}</span>
            </div>
            <div className="card stat">
              <span className="label">Endpoints</span>
              <span className="value">{endpoints.length}</span>
              <span className="sub">{t('IP contactadas')}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Duración')}</span>
              <span className="value">{(result.durationMs / 1000).toFixed(2)}s</span>
              <span className="sub">{result.resolver}</span>
            </div>
          </div>

          {dnsChain.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>{t('Cadena DNS')}</h3>
              <div className="hop-list">
                {dnsChain.map((h, i) => (
                  <div className="hop-row" key={i}>
                    <span className="hop-ttl">{h.type}</span>
                    <span className="hop-host mono">{h.name} → {h.value}</span>
                    <span className="dim" style={{ fontSize: 11 }}>ttl {h.ttl}s</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {redirects.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>{t('Redirecciones')}</h3>
              <div className="hop-list">
                {redirects.map((h, i) => (
                  <div className="hop-row" key={i}>
                    <span className="hop-ttl">{h.statusCode}</span>
                    <span className="hop-host mono">{h.url}{h.location ? ' → ' + h.location : ''}</span>
                    <span className="dim" style={{ fontSize: 11 }}>
                      DNS {h.timing.dnsMs}ms · conn {h.timing.connectMs}ms · TLS {h.timing.tlsMs}ms · TTFB {h.timing.ttfbMs}ms
                    </span>
                  </div>
                ))}
              </div>
              {signals.length > 0 && (
                <div style={{ marginTop: 10 }}>
                  {signals.map((s, i) => (
                    <span key={i} className="tag" style={{ marginRight: 6 }} title={s.evidence}>{s.label}</span>
                  ))}
                </div>
              )}
            </div>
          )}

          {endpoints.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>{t('Endpoints contactados')}</h3>
              <div className="mtr-table-wrap">
                <table className="mtr-table">
                  <thead>
                    <tr>
                      <th className="l">Host</th>
                      <th className="l">IP</th>
                      <th className="l">{t('País / ASN')}</th>
                      <th className="l">{t('Clases')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {endpoints.map((e, i) => (
                      <tr key={i}>
                        <td className="l mono">{e.hostname || '—'}</td>
                        <td className="l mono">{e.ip}</td>
                        <td className="l dim" style={{ fontSize: 11.5 }}>
                          {e.country ? '🌐 ' + e.country : ''}{e.country && e.asn ? ' · ' : ''}{e.asn ? 'AS' + e.asn + (e.org ? ' ' + e.org : '') : ''}
                        </td>
                        <td className="l">{safeArray(e.classes).map((c) => <span key={c} className="tag" style={{ marginRight: 4 }}>{c}</span>)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {result.tls && certificateChain.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>{t('Certificado (host final)')}</h3>
              <div className="mono" style={{ fontSize: 12.5 }}>
                <div>{certificateChain[0].subject}</div>
                <div className="dim">{t('emitido por')} {certificateChain[0].issuer}</div>
                <div className="dim">{t('válido')} {certificateChain[0].notBefore} → {certificateChain[0].notAfter}</div>
                <div className="dim">SHA-256 {certificateChain[0].sha256Fingerprint}</div>
              </div>
            </div>
          )}

          {(extractedHostnames.length || extractedIPs.length) ? (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>{t('Extraído de HTML/headers')}</h3>
              <p className="dim" style={{ fontSize: 12 }}>
                {t('{hosts} hostnames, {ips} IP (heurística, sin verificar)', { hosts: extractedHostnames.length, ips: extractedIPs.length })}
              </p>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {extractedHostnames.slice(0, 40).map((h) => <span key={h} className="tag">{h}</span>)}
                {extractedIPs.slice(0, 40).map((ip) => <span key={ip} className="tag">{ip}</span>)}
              </div>
            </div>
          ) : null}

          {graphEdges.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>{t('Grafo de correlación')}</h3>
              <div className="hop-list">
                {graphEdges.map((e, i) => (
                  <div className="hop-row" key={i}>
                    <span className="mono" style={{ fontSize: 12.5 }}>{e.from} —[{e.kind}]→ {e.to}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </>
  );
}

// ---------------- DNS Toolkit ----------------

// Los tres nombres SIP que se publican en la práctica. TLS aparece como
// _sips._tcp; _sip._tls existió en borradores pero no llegó al RFC 3263.
const SRV_SIP = ['_sip._udp', '_sip._tcp', '_sips._tcp'];

// srvCandidates propone los tres nombres SIP estándar sobre el nombre EXACTO
// que el usuario escribió — nunca sobre un dominio padre inferido. Ofrecer
// también el padre generaba hasta seis botones ambiguos, y a veces uno que
// apuntaba a un dominio distinto del que realmente interesaba. Probar el
// dominio padre, si hace falta, es una decisión explícita del usuario, no
// algo que la sugerencia deba adivinar.
function srvCandidates(domain: string): string[] {
  const base = domain.replace(/\.$/, '').toLowerCase();
  return SRV_SIP.map((p) => `${p}.${base}`);
}

function DnsToolkitPanel() {
  const { t } = useI18n();
  const [domain, setDomain] = useState('cloudflare.com');
  const [recordType, setRecordType] = useState('A');
  const [resolverAddr, setResolverAddr] = useState('system');
  const [dnssec, setDnssec] = useState(false);
  const [resolvers, setResolvers] = useState<dnsintel.Resolver[]>([]);
  const [types, setTypes] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<dnsintel.QueryResult | null>(null);
  const [comparison, setComparison] = useState<dnsintel.Comparison | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ptrIP, setPtrIP] = useState('1.1.1.1');
  const [ptrResult, setPtrResult] = useState<dnsintel.QueryResult | null>(null);
  const [ptrLoading, setPtrLoading] = useState(false);
  const [ptrError, setPtrError] = useState<string | null>(null);
  const [srvTargets, setSrvTargets] = useState<dnsintel.TargetResolution[]>([]);
  const [srvDiscovery, setSrvDiscovery] = useState<dnsintel.SRVDiscoveryCandidate[] | null>(null);
  const [srvDiscoveryFor, setSrvDiscoveryFor] = useState<string | null>(null);
  const [srvDiscoveryLoading, setSrvDiscoveryLoading] = useState(false);
  const addHistory = useAddHistory();

  useEffect(() => {
    if (!backendAvailable()) return;
    dnsResolvers().then(setResolvers).catch(() => {});
    dnsRecordTypes().then(setTypes).catch(() => {});
  }, []);

  // Parametrized so a suggestion click can query its exact name immediately
  // instead of going through setDomain(name) + reading the (still-stale)
  // domain state on the same tick.
  async function runQuery(name: string, type: string) {
    if (!backendAvailable()) return setError(NO_BACKEND);
    setError(null);
    setLoading(true);
    setResult(null);
    setComparison(null);
    setSrvTargets([]);
    setSrvDiscovery(null);
    setSrvDiscoveryFor(null);
    try {
      const r = await dnsQuery(name, type, resolverAddr, dnssec);
      setResult(r);
      if (r.err) setError(r.err);
      addHistory('DNS Toolkit', `${name} ${type} (${r.resolver})`, r.err || t('{count} registros, RCODE {rcode}', { count: r.records.length, rcode: r.rcode }));

      if (!r.err && r.type === 'SRV' && r.records.length > 0) {
        const targets = Array.from(new Set(r.records.map((rec) => rec.srv?.target).filter((v): v is string => !!v)));
        if (targets.length > 0) {
          // Best-effort: a target A/AAAA lookup failing must never affect
          // the SRV result already shown above.
          try {
            setSrvTargets(await dnsResolveSRVTargets(targets, resolverAddr));
          } catch {
            // ignore — SRV table just renders without target IPs
          }
        }
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  function query() {
    return runQuery(domain.trim(), recordType);
  }

  // Discovers the standard SIP SRV names under baseName using the same
  // resolver already selected — never a different one, never a parent
  // domain. If exactly one candidate returns records, that name becomes the
  // active query (enriched table included); the raw exact-name query that
  // triggered discovery stays visible above as what it actually was.
  async function discoverSRV(baseName: string) {
    if (!backendAvailable()) return setError(NO_BACKEND);
    setSrvDiscoveryLoading(true);
    setSrvDiscovery(null);
    setSrvDiscoveryFor(baseName);
    try {
      const candidates = await dnsDiscoverSRVSIP(baseName, resolverAddr, dnssec);
      setSrvDiscovery(candidates);
      const hit = candidates.find((c) => !c.result.err && c.result.records.length > 0);
      if (hit) {
        setDomain(hit.name);
        setRecordType('SRV');
        await runQuery(hit.name, 'SRV');
        // runQuery clears srvDiscovery — restore it so the "SRV SIP
        // encontrado" summary stays visible alongside the enriched table.
        setSrvDiscovery(candidates);
        setSrvDiscoveryFor(baseName);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setSrvDiscoveryLoading(false);
    }
  }

  async function compare() {
    if (!backendAvailable()) return setError(NO_BACKEND);
    setError(null);
    setLoading(true);
    setResult(null);
    setComparison(null);
    try {
      const c = await dnsCompare(domain.trim(), recordType, dnssec);
      setComparison(c);
      addHistory(t('DNS Toolkit (comparar)'), `${domain.trim()} ${recordType}`, c.consistent ? t('consistente entre resolvers') : t('divergencia: {count} entradas', { count: (c.divergences || []).length }));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function reverse() {
    if (!backendAvailable()) return setPtrError(NO_BACKEND);
    setPtrError(null);
    setPtrResult(null);
    setPtrLoading(true);
    try {
      const r = await dnsReversePTR(ptrIP.trim(), 'system', false);
      setPtrResult(r);
      addHistory(t('DNS PTR inverso'), ptrIP.trim(), r.err || (r.records[0]?.value ?? t('sin registro PTR')));
    } catch (e) {
      setPtrError(String(e));
    } finally {
      setPtrLoading(false);
    }
  }

  // showDiscovery is scoped to the single-query panel only — a comparison
  // row or the PTR panel showing an SRV-typed domain must never surface
  // discovery info from an unrelated resolver/context.
  function renderResult(r: dnsintel.QueryResult, targetIPs: dnsintel.TargetResolution[] = [], showDiscovery = false) {
    const srvRecords = r.type === 'SRV' ? r.records.filter((rec) => rec.srv) : [];
    const discoveryHit = srvDiscovery?.find((c) => !c.result.err && c.result.records.length > 0);
    // Discovery applies to the currently shown result either while it's
    // still displaying the original bare-name query (srvDiscoveryFor) or,
    // once a hit auto-selected it, while it's displaying that discovered
    // name — never to an unrelated result the user queried afterwards.
    const discoveryAppliesHere = showDiscovery && r.type === 'SRV' && srvDiscovery !== null && (
      r.domain === srvDiscoveryFor || (discoveryHit !== undefined && r.domain === discoveryHit.name)
    );
    return (
      <div className="card" style={{ marginTop: 16 }}>
        <h3>{r.domain} · {r.type} · {r.resolver}</h3>
        <p className="dim" style={{ fontSize: 12 }}>
          RCODE {r.rcode || '—'} · {r.durationMs}ms{r.truncated ? ` · ${t('truncado (falló el reintento por TCP)')}` : ''}
          {r.dnssec.requested && ` · DNSSEC: AD=${r.dnssec.authenticated} RRSIG=${r.dnssec.hasRRSIG}`}
        </p>
        {r.err && <div className="note">{r.err}</div>}
        {!r.err && r.records.length === 0 && (
          <p className="dim" style={{ fontSize: 12.5 }}>{t('La consulta se completó, pero el resolver no tiene un registro como respuesta.')}</p>
        )}
        {((r.err || r.records.length === 0)) && r.type === 'SRV' && !r.domain.startsWith('_') && (
          <div className="note" style={{ marginTop: 10 }}>
            <p style={{ margin: 0, fontSize: 12.5 }}>
              {r.err
                ? t('La consulta SRV con el resolver {resolver} no pudo obtener registros para el nombre consultado. El error original se muestra arriba.', { resolver: r.resolver })
                : t('No hay SRV bajo este nombre.')}
              {' '}
              {t('Los servicios SIP suelen publicarse bajo nombres específicos como {form}, no directamente bajo el nombre consultado.', {
                form: '_servicio._proto.dominio',
              })}
            </p>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 8 }}>
              {showDiscovery && (
                <button className="btn" style={{ fontSize: 11.5, padding: '3px 8px' }}
                  onClick={() => discoverSRV(r.domain)} disabled={srvDiscoveryLoading}>
                  {srvDiscoveryLoading ? <span className="spin" /> : null} {t('Descubrir SRV SIP')}
                </button>
              )}
              {srvCandidates(r.domain).map((name) => (
                <button key={name} className="btn ghost mono" style={{ fontSize: 11.5, padding: '3px 8px' }}
                  onClick={() => { setDomain(name); setRecordType('SRV'); runQuery(name, 'SRV'); }}>
                  {name}
                </button>
              ))}
              <button className="btn ghost" style={{ fontSize: 11.5, padding: '3px 8px' }} onClick={compare}>
                {t('Comparar resolvers')}
              </button>
            </div>
          </div>
        )}
        {discoveryAppliesHere && srvDiscovery && !discoveryHit && (
          <p className="dim" style={{ fontSize: 12 }}>
            {t('Se probaron {count} nombres SIP estándar y ninguno tiene registros SRV: {names}', {
              count: srvDiscovery.length,
              names: srvDiscovery.map((c) => c.name).join(', '),
            })}
          </p>
        )}
        {discoveryAppliesHere && discoveryHit && (
          <p className="dim" style={{ fontSize: 12 }}>
            {t('SRV SIP encontrado: {name} · {count} registros', { name: discoveryHit.name, count: discoveryHit.result.records.length })}
          </p>
        )}
        {srvRecords.length > 0 && (
          <div className="mtr-table-wrap">
            <table className="mtr-table">
              <thead><tr>
                <th>{t('Prioridad')}</th>
                <th>{t('Peso')}</th>
                <th>{t('Puerto')}</th>
                <th className="l">Target</th>
                <th className="l">IP</th>
                <th>TTL</th>
              </tr></thead>
              <tbody>
                {srvRecords.map((rec, i) => {
                  const entry = targetIPs.find((tgt) => tgt.target === rec.srv?.target);
                  const ips = entry?.ips ?? [];
                  return (
                    <tr key={i}>
                      <td>{rec.srv?.priority}</td>
                      <td>{rec.srv?.weight}</td>
                      <td>{rec.srv?.port}</td>
                      <td className="l mono">{rec.srv?.target}</td>
                      <td className="l mono" style={{ whiteSpace: 'normal' }}>
                        {ips.length > 0 ? (
                          ips.map((ip) => <div key={ip}>{ip}</div>)
                        ) : entry === undefined ? (
                          <span className="dim">{t('No consultado')}</span>
                        ) : entry.err ? (
                          <span title={entry.err}>{t('Error de resolución')}: {entry.err}</span>
                        ) : (
                          <span className="dim">{t('Sin A/AAAA')}</span>
                        )}
                      </td>
                      <td className="dim">{rec.ttl}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {r.records.length > 0 && srvRecords.length === 0 && (
          <div className="mtr-table-wrap">
            <table className="mtr-table">
              <thead><tr><th className="l">{t('Nombre')}</th><th className="l">{t('Tipo')}</th><th>TTL</th><th className="l">{t('Valor')}</th></tr></thead>
              <tbody>
                {r.records.map((rec, i) => (
                  <tr key={i}>
                    <td className="l mono">{rec.name}</td>
                    <td className="l">{rec.type}</td>
                    <td className="dim">{rec.ttl}</td>
                    <td className="l mono" style={{ whiteSpace: 'normal' }}>{rec.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" placeholder={t('dominio')} value={domain} onChange={(e) => setDomain(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && !loading && query()} />
          <select className="input" style={{ maxWidth: 110 }} value={recordType} onChange={(e) => setRecordType(e.target.value)}>
            {(types.length ? types : ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA', 'PTR']).map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <select className="input" style={{ maxWidth: 180 }} value={resolverAddr} onChange={(e) => setResolverAddr(e.target.value)}>
            {(resolvers.length ? resolvers : [{ addr: 'system', label: 'Sistema' }]).map((r) => (
              <option key={r.addr} value={r.addr}>{r.label}</option>
            ))}
          </select>
          <button className="btn" onClick={query} disabled={loading || !domain.trim()}>
            {loading ? <span className="spin" /> : '▶'} {t('Consultar')}
          </button>
          <button className="btn ghost" onClick={compare} disabled={loading || !domain.trim()}>{t('Comparar resolvers')}</button>
        </div>
        <label className="check-inline">
          <input type="checkbox" checked={dnssec} onChange={(e) => setDnssec(e.target.checked)} />
          {t('Solicitar DNSSEC (bit DO). Solo se aplica a resolvers explícitos, no a "Sistema".')}
        </label>
      </div>

      {error && <div className="note">{error}</div>}
      {result && renderResult(result, srvTargets, true)}

      {comparison && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>{t('Comparación')} · {comparison.domain} {comparison.type}</h3>
          <p className={comparison.consistent ? 'dim' : ''} style={{ fontSize: 12, color: comparison.consistent ? undefined : 'var(--warn)' }}>
            {comparison.consistent ? t('Las respuestas son consistentes entre resolvers.') : t('Se detectó una divergencia entre resolvers:')}
          </p>
          {!comparison.consistent && comparison.divergences && (
            <ul style={{ margin: '6px 0 0 18px', fontSize: 12.5 }}>
              {comparison.divergences.map((d, i) => <li key={i} className="mono">{d}</li>)}
            </ul>
          )}
          {comparison.results.map((r, i) => <div key={i}>{renderResult(r)}</div>)}
        </div>
      )}

      <div className="card" style={{ marginTop: 16 }}>
        <h3>{t('PTR inverso')}</h3>
        <div className="field">
          <input className="input" placeholder="IP" value={ptrIP} onChange={(e) => setPtrIP(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && !ptrLoading && reverse()} />
          <button className="btn ghost" onClick={reverse} disabled={!ptrIP.trim() || ptrLoading}>
            {ptrLoading ? <span className="spin" /> : null} {t('Resolver')}
          </button>
        </div>
        {ptrError && <div className="note">{ptrError}</div>}
        {ptrResult && renderResult(ptrResult)}
      </div>
    </>
  );
}

// ---------------- TLS Inspector ----------------
function TlsInspectorPanel() {
  const { t } = useI18n();
  const [host, setHost] = useState('cloudflare.com');
  const [port, setPort] = useState(443);
  const [sni, setSni] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<tlsintel.Result | null>(null);
  const [error, setError] = useState<string | null>(null);
  const addHistory = useAddHistory();

  async function inspect() {
    if (!backendAvailable()) return setError(NO_BACKEND);
    setError(null);
    setLoading(true);
    setResult(null);
    try {
      const r = await tlsInspect(host.trim(), port, sni.trim());
      setResult(r);
      if (r.err) setError(r.err);
      addHistory('TLS Inspector', `${host.trim()}:${port}`, r.err || `${r.protocol} · ${t('validación')} ${r.validationOK ? 'OK' : t('falla')}`);
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
          <input className="input" placeholder="host" value={host} onChange={(e) => setHost(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && !loading && inspect()} />
          <input className="input" style={{ maxWidth: 90 }} type="number" placeholder={t('puerto')} value={port} onChange={(e) => setPort(Number(e.target.value) || 443)} />
          <input className="input" placeholder={t('SNI (opcional; valor predeterminado: host)')} value={sni} onChange={(e) => setSni(e.target.value)} />
          <button className="btn" onClick={inspect} disabled={loading || !host.trim()}>
            {loading ? <span className="spin" /> : '🔒'} {t('Inspeccionar')}
          </button>
        </div>
      </div>

      {error && <div className="note">{error}</div>}

      {result && !result.err && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat">
              <span className="label">{t('Protocolo')}</span>
              <span className="value accent">{result.protocol}</span>
              <span className="sub">{result.cipherSuite}</span>
            </div>
            <div className="card stat">
              <span className="label">ALPN</span>
              <span className="value">{result.alpn || '—'}</span>
              <span className="sub">SNI {result.sni}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Validación')}</span>
              <span className={'value ' + (result.validationOK ? 'accent' : '')}>{result.validationOK ? 'OK' : t('falla')}</span>
              <span className="sub">{result.validationError || t('confiable')}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Cadena')}</span>
              <span className="value">{result.chain?.length ?? 0}</span>
              <span className="sub">{t('certificados')}</span>
            </div>
          </div>

          {result.chain?.map((c, i) => (
            <div className="card" style={{ marginTop: 16 }} key={i}>
              <h3>{i === 0 ? t('Certificado del servidor') : t('Emisor #{number}', { number: i })}</h3>
              <div className="mono" style={{ fontSize: 12.5 }}>
                <div>Subject: {c.subject}</div>
                <div className="dim">Issuer: {c.issuer}</div>
                {c.dnsNames && c.dnsNames.length > 0 && <div className="dim">SAN: {c.dnsNames.join(', ')}</div>}
                <div className={c.expired ? '' : 'dim'} style={{ color: c.expired ? 'var(--danger)' : undefined }}>
                  {t('Vigencia')}: {c.notBefore} → {c.notAfter} {c.expired ? `(${t('EXPIRADO')})` : `(${t('{days} días restantes', { days: c.daysUntilExpiry })})`}
                </div>
                <div className="dim">{t('Serie')}: {c.serialNumber}</div>
                <div className="dim">{t('Firma')}: {c.signatureAlgorithm} · {t('Clave')}: {c.publicKeyAlgorithm}</div>
                <div className="dim">SHA-256: {c.sha256Fingerprint}</div>
                {c.isCA && <span className="tag" style={{ marginTop: 6, display: 'inline-block' }}>CA</span>}
              </div>
            </div>
          ))}
        </>
      )}
    </>
  );
}

// ---------------- HTTP Inspector ----------------
function HttpInspectorPanel() {
  const { t } = useI18n();
  const [url, setUrl] = useState('https://cloudflare.com');
  const [method, setMethod] = useState('GET');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<httpintel.Result | null>(null);
  const [error, setError] = useState<string | null>(null);
  const addHistory = useAddHistory();

  async function inspect() {
    if (!backendAvailable()) return setError(NO_BACKEND);
    setError(null);
    setLoading(true);
    setResult(null);
    try {
      const r = await httpInspect(url.trim(), method, 0);
      setResult(r);
      if (r.err) setError(r.err);
      addHistory('HTTP Inspector', `${method} ${url.trim()}`, r.err || `${r.finalStatus} · ${t('{count} saltos', { count: r.redirects?.length ?? 0 })} · ${r.durationMs}ms`);
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
          <input className="input" placeholder="URL" value={url} onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && !loading && inspect()} />
          <select className="input" style={{ maxWidth: 100 }} value={method} onChange={(e) => setMethod(e.target.value)}>
            <option value="GET">GET</option>
            <option value="HEAD">HEAD</option>
          </select>
          <button className="btn" onClick={inspect} disabled={loading || !url.trim()}>
            {loading ? <span className="spin" /> : '🌐'} {t('Inspeccionar')}
          </button>
        </div>
      </div>

      {error && <div className="note">{error}</div>}

      {result && !result.err && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat">
              <span className="label">{t('Estado final')}</span>
              <span className="value accent">{result.finalStatus}</span>
              <span className="sub">{t('{count} saltos', { count: result.redirects?.length ?? 0 })}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Cuerpo')}</span>
              <span className="value">{(result.bodyBytesRead / 1024).toFixed(1)} KB</span>
              <span className="sub">{result.bodyTruncated ? t('truncado') : t('completo')}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Duración')}</span>
              <span className="value">{result.durationMs}ms</span>
              <span className="sub">{t('total')}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Señales')}</span>
              <span className="value">{result.signals?.length ?? 0}</span>
              <span className="sub">CDN/WAF</span>
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Cadena de redirecciones')}</h3>
            <div className="hop-list">
              {result.redirects?.map((h, i) => (
                <div className="hop-row" key={i}>
                  <span className="hop-ttl">{h.statusCode}</span>
                  <span className="hop-host mono">{h.url}{h.location ? ' → ' + h.location : ''}</span>
                  <span className="dim" style={{ fontSize: 11 }}>
                    DNS {h.timing.dnsMs}ms · conn {h.timing.connectMs}ms · TLS {h.timing.tlsMs}ms · TTFB {h.timing.ttfbMs}ms
                  </span>
                </div>
              ))}
            </div>
          </div>

          {result.signals && result.signals.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>{t('Señales CDN/WAF')}</h3>
              {result.signals.map((s, i) => (
                <div key={i} style={{ marginBottom: 6 }}>
                  <span className="tag" style={{ marginRight: 8 }}>{s.label}</span>
                  <span className="dim mono" style={{ fontSize: 11.5 }}>{s.evidence}</span>
                </div>
              ))}
            </div>
          )}

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Cabeceras de seguridad')}</h3>
            <div className="mtr-table-wrap">
              <table className="mtr-table">
                <thead><tr><th className="l">Header</th><th>{t('Presente')}</th><th className="l">{t('Valor')}</th></tr></thead>
                <tbody>
                  {result.securityHeaders?.map((h, i) => (
                    <tr key={i}>
                      <td className="l mono">{h.name}</td>
                      <td className={h.present ? 'accent-t' : ''}>{h.present ? t('sí') : t('no')}</td>
                      <td className="l mono" style={{ whiteSpace: 'normal', fontSize: 11 }}>{h.value || '—'}</td>
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

// ---------------- RDAP / BGP ----------------
function RdapBgpPanel() {
  const { t } = useI18n();
  const [ip, setIp] = useState('1.1.1.1');
  const [domain, setDomain] = useState('cloudflare.com');
  const [domainQuery, setDomainQuery] = useState('');
  const [asn, setAsn] = useState(13335);
  const [prefix, setPrefix] = useState('1.1.1.0/24');
  const [loading, setLoading] = useState(false);
  const [rdapResult, setRdapResult] = useState<rdap.Result | null>(null);
  const [routeStatus, setRouteStatus] = useState<bgp.RouteStatus | null>(null);
  const [rpkiStatus, setRpkiStatus] = useState<bgp.RPKIStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const addHistory = useAddHistory();

  async function lookupIP() {
    if (!backendAvailable()) return setError(NO_BACKEND);
    setError(null);
    setLoading(true);
    try {
      const r = await rdapLookupIP(ip.trim());
      setRdapResult(r);
      if (r.err) setError(r.err);
      addHistory('RDAP (IP)', ip.trim(), r.err || `${r.rir} · ${r.name}`);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function lookupASN() {
    if (!backendAvailable()) return setError(NO_BACKEND);
    setError(null);
    setLoading(true);
    try {
      const r = await rdapLookupASN(asn);
      setRdapResult(r);
      if (r.err) setError(r.err);
      addHistory('RDAP (ASN)', `AS${asn}`, r.err || `${r.rir} · ${r.name}`);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function checkRouting() {
    if (!backendAvailable()) return setError(NO_BACKEND);
    setError(null);
    try {
      const r = await bgpRoutingStatus(prefix.trim());
      setRouteStatus(r);
      if (r.err) setError(r.err);
      addHistory('BGP routing-status', prefix.trim(), r.err || (r.announced ? t('anunciado por {origins}', { origins: (r.origins || []).map((o) => 'AS' + o).join(', ') }) : t('no anunciado')));
    } catch (e) {
      setError(String(e));
    }
  }

  async function checkRPKI() {
    if (!backendAvailable()) return setError(NO_BACKEND);
    setError(null);
    try {
      const r = await bgpRPKIValidate(asn, prefix.trim());
      setRpkiStatus(r);
      if (r.err) setError(r.err);
      addHistory('RPKI validate', `AS${asn} → ${prefix.trim()}`, r.err || r.status || '');
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" placeholder="IP" value={ip} onChange={(e) => setIp(e.target.value)} />
          <button className="btn" onClick={lookupIP} disabled={loading || !ip.trim()}>
            {loading ? <span className="spin" /> : '📋'} {t('RDAP de IP')}
          </button>
        </div>
        <div className="field" style={{ marginTop: 10 }}>
          <input
            className="input"
            placeholder={t('dominio (registrador, vencimiento, DNS)')}
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && domain.trim() && setDomainQuery(domain.trim())}
          />
          <button className="btn" onClick={() => setDomainQuery(domain.trim())} disabled={!domain.trim()}>
            📋 {t('RDAP de dominio')}
          </button>
        </div>
        <div className="field" style={{ marginTop: 10 }}>
          <input className="input" style={{ maxWidth: 140 }} type="number" placeholder="ASN" value={asn} onChange={(e) => setAsn(Number(e.target.value) || 0)} />
          <input className="input" placeholder={t('prefijo (para BGP/RPKI)')} value={prefix} onChange={(e) => setPrefix(e.target.value)} />
          <button className="btn ghost" onClick={lookupASN} disabled={loading || asn <= 0}>{t('RDAP de ASN')}</button>
          <button className="btn ghost" onClick={checkRouting} disabled={!prefix.trim()}>{t('Estado BGP')}</button>
          <button className="btn ghost" onClick={checkRPKI} disabled={!prefix.trim() || asn <= 0}>{t('Validar RPKI')}</button>
        </div>
      </div>

      {error && <div className="note">{error}</div>}

      {domainQuery && <DomainRegistration key={domainQuery} name={domainQuery} auto />}

      {rdapResult && !rdapResult.err && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>{rdapResult.query} · {rdapResult.rir}</h3>
          <div className="mono" style={{ fontSize: 12.5 }}>
            <div>{rdapResult.name} {rdapResult.handle && `(${rdapResult.handle})`}</div>
            {rdapResult.country && <div className="dim">{t('País')}: {rdapResult.country}</div>}
            {(rdapResult.startAddress || rdapResult.startASN) && (
              <div className="dim">
                {t('Rango')}: {rdapResult.startAddress ? `${rdapResult.startAddress} - ${rdapResult.endAddress}` : `AS${rdapResult.startASN} - AS${rdapResult.endASN}`}
              </div>
            )}
            {rdapResult.abuseEmail && <div className="dim">{t('Abuso')}: {rdapResult.abuseEmail}</div>}
            {rdapResult.registered && <div className="dim">{t('Registrado')}: {rdapResult.registered}</div>}
            {rdapResult.lastChanged && <div className="dim">{t('Último cambio')}: {rdapResult.lastChanged}</div>}
          </div>
          {rdapResult.contacts && rdapResult.contacts.length > 0 && (
            <div style={{ marginTop: 10 }}>
              {rdapResult.contacts.map((c, i) => (
                <div key={i} className="dim" style={{ fontSize: 12 }}>
                  {c.roles?.join('/')}: {c.name || c.org} {c.email && `· ${c.email}`}
                </div>
              ))}
            </div>
          )}
          {rdapResult.remarks && rdapResult.remarks.length > 0 && (
            <p className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>{rdapResult.remarks.join(' · ')}</p>
          )}
          <DisclosureNote d={rdapResult.disclosure} />
        </div>
      )}

      {routeStatus && !routeStatus.err && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>{t('Estado BGP')} · {routeStatus.resource}</h3>
          <p>
            <span className={'pill ' + (routeStatus.announced ? 'ok' : 'danger')}><span className="dot" /> {routeStatus.announced ? t('Anunciado') : t('No anunciado')}</span>
          </p>
          {routeStatus.origins && routeStatus.origins.length > 0 && (
            <p className="mono" style={{ fontSize: 12.5 }}>{t('ASN de origen')}: {routeStatus.origins.map((o) => 'AS' + o).join(', ')}</p>
          )}
          <DisclosureNote d={routeStatus.disclosure} />
        </div>
      )}

      {rpkiStatus && !rpkiStatus.err && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>RPKI · AS{rpkiStatus.asn} → {rpkiStatus.prefix}</h3>
          <p>
            <span className={'pill ' + (rpkiStatus.status === 'valid' ? 'ok' : rpkiStatus.status === 'invalid' ? 'danger' : 'warn')}>
              <span className="dot" /> {rpkiStatus.status}
            </span>
          </p>
          {rpkiStatus.reason && <p className="dim mono" style={{ fontSize: 12 }}>{rpkiStatus.reason}</p>}
          <DisclosureNote d={rpkiStatus.disclosure} />
        </div>
      )}
    </>
  );
}

// ---------------- Reputación ----------------
function ReputationPanel() {
  const { t } = useI18n();
  const [ip, setIp] = useState('1.1.1.1');
  const [result, setResult] = useState<reputation.Score | null>(null);
  const [error, setError] = useState<string | null>(null);
  const addHistory = useAddHistory();

  async function assess() {
    if (!backendAvailable()) return setError(NO_BACKEND);
    setError(null);
    try {
      const r = await reputationAssess(ip.trim());
      setResult(r);
      addHistory(t('Reputación (sin conexión)'), ip.trim(), `${r.value}/100 · ${t(r.level)}`);
    } catch (e) {
      setError(String(e));
    }
  }

  const levelClass = result?.level === 'limpio' ? 'ok' : result?.level === 'alto riesgo' ? 'danger' : 'warn';

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" placeholder="IP" value={ip} onChange={(e) => setIp(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && assess()} />
          <button className="btn" onClick={assess} disabled={!ip.trim()}>⚖️ {t('Evaluar (sin conexión)')}</button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Utiliza únicamente listas offline. Incluye rangos bogon, reservados y de documentación, más las listas de amenazas que hayas descargado en Settings / Datasets (Spamhaus DROP y nodos de salida Tor). Cada señal dice qué afirma su fuente y cuánto restó. Ningún proveedor externo se considera fuente única.')}
        </p>
      </div>

      {error && <div className="note">{error}</div>}

      {result && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat">
              <span className="label">{t('Puntuación')}</span>
              <span className="value accent">{result.value}/100</span>
              <span className="sub"><span className={'pill ' + levelClass}><span className="dot" /> {t(result.level)}</span></span>
            </div>
          </div>

          {result.signals && result.signals.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>{t('Señales')}</h3>
              {result.signals.map((s, i) => (
                <div key={i} style={{ marginBottom: 6 }}>
                  <span className="tag vpn" style={{ marginRight: 8 }}>{s.label} ({s.delta})</span>
                  <span className="dim" style={{ fontSize: 12 }}>{s.detail}</span>
                </div>
              ))}
            </div>
          )}

          <div className="note" style={{ marginTop: 16 }}>{result.falsePositiveNote}</div>
          <p className="dim" style={{ fontSize: 11, marginTop: 6 }}>{result.freshness}</p>
        </>
      )}
    </>
  );
}

function PassiveOSINTPanel() {
  const { t } = useI18n();
	const [input,setInput]=useState('1.1.1.1');
	const [external,setExternal]=useState(false);
	const [loading,setLoading]=useState(false);
	const [result,setResult]=useState<PassiveOSINTResult|null>(null);
	const [error,setError]=useState<string|null>(null);
	const addHistory=useAddHistory();
	async function run(){if(!backendAvailable())return setError(NO_BACKEND);setLoading(true);setError(null);try{const r=await passiveOSINT(input.trim(),external);setResult(r);addHistory(t('OSINT pasivo'),input.trim(),`${r.addresses.length} IP · ${external?t('DNS/RDAP explícito'):t('solo local')}`)}catch(e){setError(String(e))}finally{setLoading(false)}}
	return <>
		<div className="card"><div className="field"><input className="input" value={input} onChange={(e)=>setInput(e.target.value)} placeholder={t('IP, dominio o URL')}/><button className="btn" onClick={run} disabled={loading||!input.trim()}>{loading?<span className="spin"/>:'🔎'} {t('Consultar')}</button></div>
		<label className="check-inline" style={{marginTop:10,color:external?'var(--warn)':'var(--text-dim)'}}><input type="checkbox" checked={external} onChange={(e)=>setExternal(e.target.checked)}/>{t('Incluir fuentes externas bajo demanda (DNS del sistema + RDAP del RIR)')}</label>
		<p className="dim" style={{fontSize:11.5,marginTop:8}}>{t('Está desactivado de forma predeterminada. Las IP directas se clasifican con datos RFC/GeoIP/ASN locales y los dominios no se resuelven. Al activarlo, TRAZIP muestra exactamente qué datos salieron del equipo.')}</p></div>
		{error&&<div className="note">{error}</div>}
		{result&&<div className="card" style={{marginTop:16}}><h3>{t('Resultado OSINT')} · {result.host}</h3>
			{result.dataSent&&result.queriedAt&&<div className="note"><strong>{t('Salida externa explícita')}:</strong> {result.dataSent}<div className="dim" style={{fontSize:11}}>{result.queriedAt}</div></div>}
			{result.notes?.map((n,i)=><p key={i} className="dim">{n}</p>)}
			<div className="hop-list">{result.addresses.map((a)=><div className="hop-row" key={a.addr}><span className="mono">{a.addr}</span><span>{a.country||t('local/sin GeoIP')} {a.asn?`· AS${a.asn} ${a.org||''}`:''}</span><span className="dim">{a.classes.join(', ')}</span></div>)}</div>
			{result.rdap&&<div style={{marginTop:10}}><strong>RDAP:</strong> {result.rdap.rir} · {result.rdap.name||result.rdap.handle}<DisclosureNote d={result.rdap.disclosure}/></div>}
		</div>}
	</>
}

// ---------------- Tabbed view ----------------
export default function WebIntelligence() {
  const { t } = useI18n();
  const [tab, setTab] = useState<Tab>('url');
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [panelEpochs, setPanelEpochs] = useState<Record<Exclude<Tab, 'historial'>, number>>({
    url: 0, dns: 0, tls: 0, http: 0, rdap: 0, reputation: 0, osint: 0,
  });
  const { pushActivity } = useCaptureSession();

  const addHistory = (tool: string, query: string, summary: string) => {
    setHistory((prev) => [{ time: new Date().toLocaleTimeString(), tool, query, summary }, ...prev].slice(0, 200));
    // Also feed Overview's cross-module "últimas consultas" — one wire-up
    // point here covers every panel (DNS/TLS/HTTP/RDAP/Reputation/URL)
    // since they all already call addHistory.
    pushActivity(tool, query, summary);
  };

  function clearActiveTab() {
    if (tab === 'historial') {
      setHistory([]);
      return;
    }
    setPanelEpochs((prev) => ({ ...prev, [tab]: prev[tab] + 1 }));
  }

  return (
    <HistoryContext.Provider value={addHistory}>
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Web Intelligence')}</h2>
        <p className="body-text">
          {t('Analizador de URL/dominio con correlación DNS→IP→ASN→país→certificado, DNS Toolkit, TLS/HTTP Inspector, RDAP/BGP/RPKI y reputación offline. Cada consulta externa muestra qué se envió y con qué confianza.')}
        </p>
      </div>

      <div className="tabs">
        <button className={'tab' + (tab === 'url' ? ' active' : '')} onClick={() => setTab('url')}>{t('Analizador URL')}</button>
        <button className={'tab' + (tab === 'dns' ? ' active' : '')} onClick={() => setTab('dns')}>DNS Toolkit</button>
        <button className={'tab' + (tab === 'tls' ? ' active' : '')} onClick={() => setTab('tls')}>TLS Inspector</button>
        <button className={'tab' + (tab === 'http' ? ' active' : '')} onClick={() => setTab('http')}>HTTP Inspector</button>
        <button className={'tab' + (tab === 'rdap' ? ' active' : '')} onClick={() => setTab('rdap')}>RDAP / BGP</button>
        <button className={'tab' + (tab === 'reputation' ? ' active' : '')} onClick={() => setTab('reputation')}>{t('Reputación')}</button>
		<button className={'tab' + (tab === 'osint' ? ' active' : '')} onClick={() => setTab('osint')}>{t('OSINT pasivo')}</button>
        <button className={'tab' + (tab === 'historial' ? ' active' : '')} onClick={() => setTab('historial')}>{t('Historial ({count})', { count: history.length })}</button>
        <button className="btn ghost tab-clear" onClick={clearActiveTab}>🗑 {t('Limpiar pestaña')}</button>
      </div>

      {/* Montados siempre, solo ocultos con CSS: cambiar de pestaña ya no
          descarta los resultados de la consulta anterior. */}
      <div style={{ display: tab === 'url' ? 'block' : 'none' }}><UrlAnalyzerPanel key={panelEpochs.url} /></div>
      <div style={{ display: tab === 'dns' ? 'block' : 'none' }}><DnsToolkitPanel key={panelEpochs.dns} /></div>
      <div style={{ display: tab === 'tls' ? 'block' : 'none' }}><TlsInspectorPanel key={panelEpochs.tls} /></div>
      <div style={{ display: tab === 'http' ? 'block' : 'none' }}><HttpInspectorPanel key={panelEpochs.http} /></div>
      <div style={{ display: tab === 'rdap' ? 'block' : 'none' }}><RdapBgpPanel key={panelEpochs.rdap} /></div>
      <div style={{ display: tab === 'reputation' ? 'block' : 'none' }}><ReputationPanel key={panelEpochs.reputation} /></div>
		<div style={{ display: tab === 'osint' ? 'block' : 'none' }}><PassiveOSINTPanel key={panelEpochs.osint} /></div>
      <div style={{ display: tab === 'historial' ? 'block' : 'none' }}>
        <HistorialPanel history={history} onClear={() => setHistory([])} />
      </div>
    </div>
    </HistoryContext.Provider>
  );
}
