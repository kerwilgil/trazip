import { useRef, useState } from 'react';
import {
  backendAvailable,
  startHTTPLoad,
  stopHTTPLoad,
  subscribeHTTPLoad,
  type HTTPLoadProgressTick,
  type HTTPLoadResult,
} from '../lib/api';
import { useI18n } from '../lib/i18n';

const NO_BACKEND = 'Necesita el runtime Wails (app de escritorio). En el preview del navegador no hay backend.';
const MAX_TICKS = 200;

function humanBytes(n: number): string {
  if (n < 1024) return `${Math.round(n)} B`;
  const units = ['KB', 'MB', 'GB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

function hostOf(rawUrl: string): string | null {
  try {
    return new URL(rawUrl).hostname;
  } catch {
    return null;
  }
}

// looksPrivateHost mirrors Lan.tsx's looksPrivateRange: only warns when the
// host is confidently a non-private IPv4 literal — fails open (no nag) on
// domain names or anything it can't parse, since a hostname alone says
// nothing about who operates it.
function looksPrivateHost(host: string | null): boolean {
  if (!host) return true;
  if (host === 'localhost') return true;
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return true;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

function parseHeaders(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const k = line.slice(0, idx).trim();
    const v = line.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

function statusClass(code: number): string {
  if (code >= 500) return 'bad';
  if (code >= 400) return 'warn';
  if (code >= 200 && code < 300) return '';
  return 'dim';
}

// RPSChart plots requests-per-second across the progress ticks received
// while a test runs — same hand-built-SVG convention as PingMTR.tsx's
// LatencyChart, kept simple since ticks land on a fixed ~500ms cadence
// (index-based x-axis is fine, no need for a real time axis).
function RPSChart({ ticks }: { ticks: HTTPLoadProgressTick[] }) {
  const { t } = useI18n();
  if (ticks.length < 2) return null;
  const width = 900;
  const height = 160;
  const plot = { left: 40, right: 884, top: 12, bottom: 138 };
  const ceiling = Math.max(1, ...ticks.map((t) => t.rps)) * 1.15;
  const xFor = (i: number) => plot.left + (i / (ticks.length - 1)) * (plot.right - plot.left);
  const yFor = (rps: number) => plot.bottom - (Math.min(rps, ceiling) / ceiling) * (plot.bottom - plot.top);
  const line = ticks.map((t, i) => `${i === 0 ? 'M' : 'L'} ${xFor(i).toFixed(1)} ${yFor(t.rps).toFixed(1)}`).join(' ');

  return (
    <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={t('Solicitudes por segundo a lo largo del tiempo')} style={{ width: '100%', height: 'auto' }}>
      {[0, 0.5, 1].map((r) => (
        <g key={r}>
          <line x1={plot.left} y1={plot.top + r * (plot.bottom - plot.top)} x2={plot.right} y2={plot.top + r * (plot.bottom - plot.top)} stroke="var(--border)" strokeWidth={1} />
          <text x={plot.left - 8} y={plot.top + r * (plot.bottom - plot.top) + 4} textAnchor="end" fontSize={10} fill="var(--text-dim)">{Math.round(ceiling * (1 - r))}</text>
        </g>
      ))}
      <path d={line} fill="none" stroke="var(--accent)" strokeWidth={2} />
    </svg>
  );
}

export default function HttpLoad() {
  const { t } = useI18n();
  const [url, setUrl] = useState('http://127.0.0.1:8080/');
  const [method, setMethod] = useState('GET');
  const [concurrency, setConcurrency] = useState(10);
  const [durationSec, setDurationSec] = useState(10);
  const [targetRps, setTargetRps] = useState(0);
  const [headersText, setHeadersText] = useState('');
  const [body, setBody] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const [running, setRunning] = useState(false);
  const [ticks, setTicks] = useState<HTTPLoadProgressTick[]>([]);
  const [result, setResult] = useState<HTTPLoadResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runRef = useRef<string | null>(null);
  const offRef = useRef<(() => void) | null>(null);

  async function run() {
    if (!backendAvailable()) return setError(NO_BACKEND);
    setRunning(true);
    setTicks([]);
    setResult(null);
    setError(null);
    try {
      const id = await startHTTPLoad({
        url: url.trim(),
        method,
        concurrency,
        durationMs: Math.round(durationSec * 1000),
        headers: parseHeaders(headersText),
        body,
        targetRps,
      });
      runRef.current = id;
      offRef.current = subscribeHTTPLoad(
        id,
        (tick) => setTicks((prev) => [...prev, tick].slice(-MAX_TICKS)),
        (res, err) => {
          setRunning(false);
          runRef.current = null;
          setResult(res);
          if (err) setError(err);
        },
      );
    } catch (e) {
      setRunning(false);
      setError(String(e));
    }
  }

  function stop() {
    if (runRef.current) stopHTTPLoad(runRef.current);
    if (offRef.current) offRef.current();
    offRef.current = null;
    runRef.current = null;
    setRunning(false);
  }

  const latest = ticks.length ? ticks[ticks.length - 1] : null;
  const statusEntries = Object.entries((result?.statusCounts ?? latest?.statusCounts ?? {}) as Record<string, number>)
    .map(([code, count]) => [Number(code), count] as [number, number])
    .sort((a, b) => a[0] - b[0]);

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Prueba de carga HTTP')}</h2>
        <p className="body-text">
          {t('Herramienta de TRAZIP para simular tráfico concurrente contra una URL durante un tiempo limitado, con RPS, latencia y errores en vivo. Úsala solo contra servicios propios o con autorización explícita.')}
        </p>
        <p className="dim" style={{ fontSize: 11.5, marginTop: 6 }}>
          {t('Mide cuántas solicitudes por segundo admite el servidor y con qué latencia responde bajo carga. Cada solicitud descarga el cuerpo completo de la respuesta y también informa el rendimiento de descarga en Mbps. No es una prueba de velocidad para descargar un archivo; para eso está Throughput. Aquí se mide la capacidad del servidor para atender solicitudes concurrentes.')}
        </p>
      </div>

      <div className="card pad-lg">
        <div className="field">
          <input className="input mono" placeholder="http://host:puerto/ruta" value={url} onChange={(e) => setUrl(e.target.value)} disabled={running} />
          {running ? <button className="btn ghost" onClick={stop}>■ {t('Detener')}</button> : <button className="btn" onClick={run} disabled={!url.trim()}>▶ {t('Correr')}</button>}
        </div>
        {!running && url.trim() && !looksPrivateHost(hostOf(url.trim())) && (
          <p className="note" style={{ fontSize: 11.5, marginTop: 8 }}>
            ⚠ {t('"{host}" no parece una dirección privada/local — vas a enviar tráfico concurrente real. Usalo solo con autorización.', { host: hostOf(url.trim()) ?? '' })}
          </p>
        )}

        <div className="field-grid" style={{ marginTop: 14 }}>
          <label>{t('Método')}
            <select value={method} onChange={(e) => setMethod(e.target.value)} disabled={running}>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
              <option value="HEAD">HEAD</option>
            </select>
          </label>
          <label>{t('Concurrencia')}
            <input type="number" min={1} max={100} value={concurrency} onChange={(e) => setConcurrency(+e.target.value)} disabled={running} />
          </label>
          <label>{t('Duración (s)')}
            <input type="number" min={1} max={300} value={durationSec} onChange={(e) => setDurationSec(+e.target.value)} disabled={running} />
          </label>
          <label>{t('RPS objetivo (0 = sin límite)')}
            <input type="number" min={0} value={targetRps} onChange={(e) => setTargetRps(+e.target.value)} disabled={running} />
          </label>
        </div>

        <button className="btn ghost" style={{ marginTop: 12 }} onClick={() => setShowAdvanced((v) => !v)}>
          {showAdvanced ? '▲' : '▼'} {t('Headers / body (opcional)')}
        </button>
        {showAdvanced && (
          <div className="grid cols-2" style={{ marginTop: 10 }}>
            <div>
              <label className="dim" style={{ fontSize: 12 }}>{t('Headers (uno por línea, "Nombre: valor")')}</label>
              <textarea className="input mono" style={{ width: '100%', minHeight: 80, marginTop: 4 }} value={headersText} onChange={(e) => setHeadersText(e.target.value)} disabled={running} placeholder={'Authorization: Bearer ...\nContent-Type: application/json'} />
            </div>
            <div>
              <label className="dim" style={{ fontSize: 12 }}>{t('Body (para POST/PUT)')}</label>
              <textarea className="input mono" style={{ width: '100%', minHeight: 80, marginTop: 4 }} value={body} onChange={(e) => setBody(e.target.value)} disabled={running} />
            </div>
          </div>
        )}
      </div>

      {error && <div className="note">{error}</div>}

      {(running || latest) && (
        <div className="grid cols-5" style={{ marginTop: 16 }}>
          <div className="card stat">
            <span className="label">{t('Requests')}</span>
            <span className="value accent">{(result?.totalRequests ?? latest?.requests ?? 0).toLocaleString()}</span>
            <span className="sub">{running ? t('en vivo') : t('total')}</span>
          </div>
          <div className="card stat">
            <span className="label">{t('RPS')}</span>
            <span className="value">{(result?.avgRps ?? latest?.rps ?? 0).toFixed(1)}</span>
            <span className="sub">{running ? t('actual') : t('promedio')}</span>
          </div>
          <div className="card stat">
            <span className="label">{t('Latencia p95')}</span>
            <span className="value">{(result?.p95LatencyMs ?? latest?.p95LatencyMs ?? 0).toFixed(0)} ms</span>
            <span className="sub">{t('promedio')}: {(result?.p50LatencyMs ?? latest?.avgLatencyMs ?? 0).toFixed(0)} ms</span>
          </div>
          <div className="card stat">
            <span className="label">{t('Descarga')}</span>
            <span className="value">{(result?.throughputMbps ?? latest?.throughputMbps ?? 0).toFixed(1)}</span>
            <span className="sub">{t('Mbps de cuerpos')}</span>
          </div>
          <div className="card stat">
            <span className="label">{t('Errores')}</span>
            <span className={'value ' + ((result?.errorRatePct ?? latest?.errorRatePct ?? 0) > 0 ? '' : 'accent')}>
              {(result?.errorRatePct ?? latest?.errorRatePct ?? 0).toFixed(1)}%
            </span>
            <span className="sub">{t('tasa')}</span>
          </div>
        </div>
      )}

      {ticks.length >= 2 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3 style={{ marginTop: 0 }}>{t('RPS en el tiempo')}</h3>
          <RPSChart ticks={ticks} />
        </div>
      )}

      {statusEntries.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>{t('Códigos de respuesta')}</h3>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            {statusEntries.map(([code, count]) => (
              <span key={code} className={'tag ' + statusClass(code)}>{code || t('sin respuesta')}: {count}</span>
            ))}
          </div>
        </div>
      )}

      {result && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>{t('Resumen final')}</h3>
          <p>{t('{requests} solicitudes en {seconds} s · {rps} RPS promedio · {errors}% de errores', {
            requests: result.totalRequests.toLocaleString(),
            seconds: result.durationSec.toFixed(1),
            rps: result.avgRps.toFixed(1),
            errors: result.errorRatePct.toFixed(1),
          })}</p>
          <p className="dim" style={{ fontSize: 12 }}>
            {t('Percentiles de latencia: p50 {p50} ms · p90 {p90} ms · p95 {p95} ms · p99 {p99} ms', {
              p50: result.p50LatencyMs.toFixed(0), p90: result.p90LatencyMs.toFixed(0),
              p95: result.p95LatencyMs.toFixed(0), p99: result.p99LatencyMs.toFixed(0),
            })}
          </p>
          <p className="dim" style={{ fontSize: 12 }}>
            {t('Descarga: {total} en total ({average} por solicitud en promedio) · {throughput} Mbps agregados', {
              total: humanBytes(result.totalBytes), average: humanBytes(result.avgBytesPerReq),
              throughput: result.throughputMbps.toFixed(1),
            })}
          </p>
        </div>
      )}
    </div>
  );
}
