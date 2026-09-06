import { useEffect, useRef, useState } from 'react';
import CopyButton from '../components/CopyButton';
import {
  startPing,
  stopPing,
  subscribePing,
  startTrace,
  stopTrace,
  subscribeTrace,
  startMTR,
  stopMTR,
  subscribeMTR,
  backendAvailable,
  type PingReply,
  type PingStats,
  type TraceHop,
  type MtrHop,
} from '../lib/api';
import { countryFlag } from '../lib/flags';
import { useI18n, type Translate } from '../lib/i18n';

const MAX_REPLIES = 200;
const MAX_SAMPLES = 60;

type Tab = 'ping' | 'trace' | 'mtr';

const NO_BACKEND = 'Necesita el runtime Wails (app de escritorio). En el preview del navegador no hay backend.';

function formatPingSummary(target: string, stats: PingStats, replies: PingReply[], t: Translate): string {
  const lines = [
    `TRAZIP · ${t('Ping a {target}', { target })}`,
    t('Pérdida: {loss}% ({recv}/{sent} recibidos)', { loss: stats.lossPct, recv: stats.recv, sent: stats.sent }),
    t('Promedio: {avg} ms · Último: {last} ms', { avg: stats.avgMs, last: stats.lastMs }),
    t('Mín/Máx: {min} / {max} ms', { min: stats.minMs, max: stats.maxMs }),
    t('Jitter: {jitter} ms (desv. {stddev} ms)', { jitter: stats.jitterMs, stddev: stats.stdDevMs }),
    '',
    // replies is stored oldest-last (unshifted on arrival) — reverse so the
    // copied summary reads chronologically, and include all of them (not
    // just a preview slice) since this is meant to be pasted as evidence.
    t('Todas las respuestas ({count}):', { count: replies.length }),
    ...replies.slice().reverse().map((r) => (r.ok ? `  #${r.seq} ${r.from} ${r.rttMs} ms TTL ${r.ttl}` : `  #${r.seq} ${t('perdido')}: ${r.err || ''}`)),
  ];
  return lines.join('\n');
}

function formatMtrSummary(target: string, hops: MtrHop[], t: Translate): string {
  const lines = [`TRAZIP · ${t('MTR a {target}', { target })}`, t('#  Host                          Pérd.  Env  Últ  Prom  Mej  Peor  Jitter')];
  for (const h of hops) {
    const host = (h.hostname || h.addr || '???').padEnd(28).slice(0, 28);
    lines.push(
      `${String(h.ttl).padStart(2)} ${host} ${String(h.lossPct + '%').padStart(5)} ${String(h.sent).padStart(4)} ` +
        `${String(h.addr ? h.lastMs : '—').padStart(4)} ${String(h.addr ? h.avgMs : '—').padStart(5)} ` +
        `${String(h.addr ? h.bestMs : '—').padStart(4)} ${String(h.addr ? h.worstMs : '—').padStart(5)} ${String(h.addr ? h.jitterMs : '—').padStart(6)}`,
    );
  }
  return lines.join('\n');
}

function classChips(classes?: string[]) {
  if (!classes || classes.length === 0) return null;
  const known = ['public', 'private', 'bogon', 'reserved', 'documentation', 'vpn', 'proxy', 'tor', 'hosting'];
  return (
    <span className="hop-tags">
      {classes.map((c) => (
        <span key={c} className={'tag ' + (known.includes(c) ? c : '')}>
          {c}
        </span>
      ))}
    </span>
  );
}

type LatencySample = { rtt: number | null; at: number };

function latencyClass(rtt: number | null): string {
  if (rtt === null) return 'lost';
  if (rtt < 80) return 'ok';
  if (rtt < 180) return 'warn';
  return 'bad';
}

function timeLabel(at?: number): string {
  if (!at) return '--:--:--';
  return new Date(at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function chartCeiling(samples: LatencySample[]): number {
  const peak = Math.max(0, ...samples.map((sample) => sample.rtt ?? 0));
  return [20, 50, 100, 200, 500, 1000, 2000].find((step) => peak <= step) ?? Math.ceil(peak / 1000) * 1000;
}

function LatencyChart({ samples, average, running }: { samples: LatencySample[]; average: number; running: boolean }) {
  const { t } = useI18n();
  const width = 1000;
  const height = 250;
  const plot = { left: 58, right: 984, top: 18, bottom: 204 };
  const ceiling = chartCeiling(samples);
  const xFor = (index: number) => {
    const slot = MAX_SAMPLES - samples.length + index;
    return plot.left + (slot / (MAX_SAMPLES - 1)) * (plot.right - plot.left);
  };
  const yFor = (rtt: number) => plot.bottom - (Math.min(rtt, ceiling) / ceiling) * (plot.bottom - plot.top);
  const segments: { line: string; area: string }[] = [];
  let points: [number, number][] = [];
  const flush = () => {
    if (points.length === 0) return;
    const line = points.map(([x, y], i) => `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`).join(' ');
    const first = points[0];
    const last = points[points.length - 1];
    segments.push({ line, area: `${line} L ${last[0].toFixed(1)} ${plot.bottom} L ${first[0].toFixed(1)} ${plot.bottom} Z` });
    points = [];
  };
  samples.forEach((sample, index) => {
    if (sample.rtt === null) {
      flush();
    } else {
      points.push([xFor(index), yFor(sample.rtt)]);
    }
  });
  flush();
  const middle = samples[Math.floor(samples.length / 2)];
  const latestIndex = samples.length - 1;
  const latest = samples[latestIndex];

  const windowRtts = samples.map((s) => s.rtt).filter((v): v is number => v !== null);
  const windowAvg = windowRtts.length ? windowRtts.reduce((a, b) => a + b, 0) / windowRtts.length : null;
  const windowMin = windowRtts.length ? Math.min(...windowRtts) : null;
  const windowMax = windowRtts.length ? Math.max(...windowRtts) : null;
  const windowLossPct = samples.length ? (samples.filter((s) => s.rtt === null).length / samples.length) * 100 : 0;

  return (
    <div className="latency-monitor">
      <div className="latency-monitor-head">
        <span className="latency-legend"><span className="latency-legend-swatch" /> {t('Latencia promedio')}</span>
        <strong>{average.toFixed(1)} ms</strong>
        <span className="latency-window">{t('Últimos 60 s')} {running && <span className="live-dot" />}</span>
      </div>
      <div className="latency-svg-wrap">
        <svg className="latency-svg" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={t('Latencia de ping durante los últimos 60 segundos')}>
          <defs>
            <linearGradient id="latencyArea" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--ok)" stopOpacity="0.3" />
              <stop offset="100%" stopColor="var(--ok)" stopOpacity="0.02" />
            </linearGradient>
          </defs>
          {[0, 0.25, 0.5, 0.75, 1].map((ratio) => {
            const y = plot.top + ratio * (plot.bottom - plot.top);
            return (
              <g key={ratio}>
                <line className="latency-grid-line" x1={plot.left} y1={y} x2={plot.right} y2={y} />
                <text className="latency-axis-label" x={plot.left - 10} y={y + 4} textAnchor="end">
                  {Math.round(ceiling * (1 - ratio))}
                </text>
              </g>
            );
          })}
          {[0, 0.2, 0.4, 0.6, 0.8, 1].map((ratio) => {
            const x = plot.left + ratio * (plot.right - plot.left);
            return <line className="latency-grid-line" key={ratio} x1={x} y1={plot.top} x2={x} y2={plot.bottom} />;
          })}
          {segments.map((segment, index) => <path key={`area-${index}`} className="latency-area" d={segment.area} />)}
          {segments.map((segment, index) => <path key={`line-${index}`} className="latency-line" d={segment.line} />)}
          {latest?.rtt !== null && latest?.rtt !== undefined && (
            <circle className="latency-current" cx={xFor(latestIndex)} cy={yFor(latest.rtt)} r="4.5" />
          )}
          {samples.map((sample, index) => sample.rtt === null && (
            <circle key={sample.at} className="latency-loss" cx={xFor(index)} cy={plot.bottom - 4} r="4" />
          ))}
          {samples.map((sample, index) => (
            <circle
              key={'hit-' + sample.at}
              cx={xFor(index)}
              cy={sample.rtt !== null ? yFor(sample.rtt) : plot.bottom - 4}
              r={9}
              fill="transparent"
              style={{ cursor: 'crosshair' }}
            >
              <title>
                {`${timeLabel(sample.at)}\n` +
                  `${t('Latencia: {value}', { value: sample.rtt !== null ? sample.rtt + ' ms' : t('perdido') })}\n` +
                  `${t('Estado')}: ${sample.rtt === null ? t('perdido') : latencyClass(sample.rtt)}\n` +
                  `${t('Promedio del período: {value}', { value: windowAvg !== null ? windowAvg.toFixed(1) + ' ms' : '—' })}\n` +
                  `${t('Mín/Máx del período: {min} / {max} ms', { min: windowMin ?? '—', max: windowMax ?? '—' })}\n` +
                  t('Pérdida del período: {loss}%', { loss: windowLossPct.toFixed(0) })}
              </title>
            </circle>
          ))}
          <text className="latency-axis-title" x="15" y={(plot.top + plot.bottom) / 2} transform={`rotate(-90 15 ${(plot.top + plot.bottom) / 2})`}>ms</text>
          <text className="latency-time-label" x={plot.left} y="232">{timeLabel(samples[0]?.at)}</text>
          <text className="latency-time-label" x={(plot.left + plot.right) / 2} y="232" textAnchor="middle">{timeLabel(middle?.at)}</text>
          <text className="latency-time-label" x={plot.right} y="232" textAnchor="end">{t('ahora')}</text>
        </svg>
      </div>
      <div className="heartbeat-strip" aria-label={t('Disponibilidad de los últimos paquetes')}>
        {samples.map((sample) => (
          <span
            key={sample.at}
            className={`heartbeat-pulse ${latencyClass(sample.rtt)}`}
            title={sample.rtt === null ? `${timeLabel(sample.at)} · ${t('perdido')}` : `${timeLabel(sample.at)} · ${sample.rtt} ms`}
          />
        ))}
      </div>
      <div className="heartbeat-caption"><span>{t('hace {seconds} s', { seconds: Math.min(samples.length, MAX_SAMPLES) })}</span><span>{t('ahora')}</span></div>
    </div>
  );
}

// ---------------- Ping panel ----------------
function PingPanel() {
  const { t } = useI18n();
  const [target, setTarget] = useState('8.8.8.8');
  const [continuous, setContinuous] = useState(true);
  const [running, setRunning] = useState(false);
  const [stats, setStats] = useState<PingStats | null>(null);
  const [replies, setReplies] = useState<PingReply[]>([]);
  const [resolved, setResolved] = useState('');
  const [samples, setSamples] = useState<LatencySample[]>([]);
  const [error, setError] = useState<string | null>(null);

  const runIdRef = useRef<string | null>(null);
  const unsubRef = useRef<(() => void) | null>(null);

  useEffect(() => () => {
    if (unsubRef.current) unsubRef.current();
    if (runIdRef.current) stopPing(runIdRef.current);
  }, []);

  async function start() {
    if (running) return;
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    setError(null);
    setStats(null);
    setReplies([]);
    setResolved('');
    setSamples([]);
    try {
      const id = await startPing({
        target: target.trim(),
        count: continuous ? 0 : 10,
        intervalMs: 1000,
        timeoutMs: 2000,
        payload: 32,
      });
      runIdRef.current = id;
      setRunning(true);
      unsubRef.current = subscribePing(
        id,
        (reply, s) => {
          setStats(s);
          setReplies((prev) => [reply, ...prev].slice(0, MAX_REPLIES));
          setSamples((prev) => {
            const next = [...prev, { rtt: reply.ok ? reply.rttMs : null, at: Date.now() }];
            return next.length > MAX_SAMPLES ? next.slice(next.length - MAX_SAMPLES) : next;
          });
        },
        (addr, err) => {
          setRunning(false);
          runIdRef.current = null;
          if (addr) setResolved(addr);
          if (err) setError(err);
        },
        (addr, err) => {
          // Llega antes de la primera sonda: así la IP de destino se ve aunque
          // el host no conteste ni una vez, igual que hace `ping` en consola.
          if (addr) setResolved(addr);
          if (err) setError(err);
        },
      );
    } catch (e) {
      setError(String(e));
      setRunning(false);
    }
  }

  function stop() {
    if (unsubRef.current) unsubRef.current();
    if (runIdRef.current) stopPing(runIdRef.current);
    unsubRef.current = null;
    runIdRef.current = null;
    setRunning(false);
  }

  function clear() {
    stop();
    setStats(null);
    setReplies([]);
    setResolved('');
    setSamples([]);
    setError(null);
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <input
            className="input"
            placeholder={t('IP o dominio (8.8.8.8, cloudflare.com)')}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !running && start()}
            disabled={running}
          />
          {running ? (
            <button className="btn ghost" onClick={stop}>■ {t('Detener')}</button>
          ) : (
            <button className="btn" onClick={start} disabled={!target.trim()}>▶ {t('Iniciar')}</button>
          )}
        </div>
        <label className="check-inline">
          <input type="checkbox" checked={continuous} onChange={(e) => setContinuous(e.target.checked)} disabled={running} />
          {t('Modo continuo')} ({continuous ? t('hasta detener') : t('10 paquetes')})
        </label>
      </div>

      {/* Se muestra apenas resuelve, antes de la primera respuesta: con un
          destino que no contesta, esto es lo único que el operador obtiene y
          sigue siendo útil (confirma que el DNS resolvió y a qué IP). */}
      {resolved && (
        <p className="dim" style={{ marginTop: 12, fontSize: 13 }}>
          {t('Enviando a')} <span className="mono" style={{ color: 'var(--text)' }}>{resolved}</span>
          {target.trim() && target.trim() !== resolved && <span className="mono"> · {target.trim()}</span>}
        </p>
      )}

      {error && <div className="note">{error}</div>}

      {stats && (
        <>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
            <CopyButton
              label={t('Copiar resumen')}
              getText={() => formatPingSummary(target, stats, replies, t)}
            />
            <button className="btn ghost" onClick={clear}>🗑 {t('Limpiar')}</button>
          </div>
          <div className="grid cols-4" style={{ marginTop: 10 }}>
            <div className="card stat">
              <span className="label">{t('Pérdida')}</span>
              <span className={'value ' + (stats.lossPct > 0 ? '' : 'accent')}>{stats.lossPct}%</span>
              <span className="sub">{t('{recv}/{sent} recibidos', { recv: stats.recv, sent: stats.sent })}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Promedio')}</span>
              <span className="value accent">{stats.avgMs} ms</span>
              <span className="sub">{t('último {last} ms', { last: stats.lastMs })}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Mín / Máx')}</span>
              <span className="value">{stats.minMs} / {stats.maxMs}</span>
              <span className="sub">ms</span>
            </div>
            <div className="card stat">
              <span className="label">Jitter</span>
              <span className="value">{stats.jitterMs} ms</span>
              <span className="sub">{t('desv. {stddev} ms', { stddev: stats.stdDevMs })}</span>
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Latencia en vivo')}</h3>
            <LatencyChart samples={samples} average={stats.avgMs} running={running} />
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Respuestas')}</h3>
            <div className="reply-log">
              {replies.map((r, i) => (
                <div className={'reply-row' + (r.ok ? '' : ' lost')} key={replies.length - i}>
                  <span className="seq">#{r.seq}</span>
                  {r.ok ? (
                    <>
                      <span className="mono">{r.from}</span>
                      <span className="rtt">{r.rttMs} ms</span>
                      <span className="ttl">TTL {r.ttl}</span>
                    </>
                  ) : (
                    <span className="err">{r.err}</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </>
  );
}

// ---------------- Traceroute panel ----------------
function TracePanel() {
  const { t } = useI18n();
  const [target, setTarget] = useState('cloudflare.com');
  const [resolveDNS, setResolveDNS] = useState(true);
  const [running, setRunning] = useState(false);
  const [hops, setHops] = useState<TraceHop[]>([]);
  const [resolved, setResolved] = useState('');
  const [error, setError] = useState<string | null>(null);

  const runIdRef = useRef<string | null>(null);
  const unsubRef = useRef<(() => void) | null>(null);

  useEffect(() => () => {
    if (unsubRef.current) unsubRef.current();
    if (runIdRef.current) stopTrace(runIdRef.current);
  }, []);

  async function start() {
    if (running) return;
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    setError(null);
    setHops([]);
    setResolved('');
    try {
      const id = await startTrace(target.trim(), 30, 3, 1500, resolveDNS);
      runIdRef.current = id;
      setRunning(true);
      unsubRef.current = subscribeTrace(
        id,
        (hop) => setHops((prev) => [...prev, hop]),
        (addr, err) => {
          setRunning(false);
          runIdRef.current = null;
          if (addr) setResolved(addr);
          if (err) setError(err);
        },
        (addr, err) => {
          if (addr) setResolved(addr);
          if (err) setError(err);
        },
      );
    } catch (e) {
      setError(String(e));
      setRunning(false);
    }
  }

  function stop() {
    if (unsubRef.current) unsubRef.current();
    if (runIdRef.current) stopTrace(runIdRef.current);
    unsubRef.current = null;
    runIdRef.current = null;
    setRunning(false);
  }

  function clear() {
    stop();
    setHops([]);
    setResolved('');
    setError(null);
  }

  const geoHops = hops.filter((h) => h.country);
  const countryRoute = geoHops.reduce<{ key: string; country: string; code?: string; first: number; last: number }[]>((route, hop) => {
    const key = hop.countryCode || hop.country || '';
    const previous = route[route.length - 1];
    if (previous?.key === key) {
      previous.last = hop.ttl;
    } else {
      route.push({ key, country: hop.country!, code: hop.countryCode, first: hop.ttl, last: hop.ttl });
    }
    return route;
  }, []);

  return (
    <>
      <div className="card">
        <div className="field">
          <input
            className="input"
            placeholder={t('IP o dominio (cloudflare.com, 8.8.8.8)')}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !running && start()}
            disabled={running}
          />
          {running ? (
            <button className="btn ghost" onClick={stop}>■ {t('Detener')}</button>
          ) : (
            <button className="btn" onClick={start} disabled={!target.trim()}>▶ {t('Trazar')}</button>
          )}
        </div>
        <label className="check-inline">
          <input type="checkbox" checked={resolveDNS} onChange={(e) => setResolveDNS(e.target.checked)} disabled={running} />
          {t('Resolver DNS inverso por salto')}
        </label>
      </div>

      {resolved && (
        <p className="dim" style={{ marginTop: 12, fontSize: 13 }}>
          {t('Enviando a')} <span className="mono" style={{ color: 'var(--text)' }}>{resolved}</span>
        </p>
      )}

      {error && <div className="note">{error}</div>}

      {(hops.length > 0 || running) && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="result-card-head">
            <div>
              <h3>{t('Ruta geográfica y saltos')} {running && <span className="spin" />}</h3>
              <p className="dim">{t('La ubicación GeoIP es aproximada y puede representar el registro del operador, no la posición física del router.')}</p>
            </div>
            <button className="btn ghost" onClick={clear}>🗑 {t('Limpiar')}</button>
          </div>

          {countryRoute.length > 0 && (
            <div className="country-route" aria-label={t('Secuencia de países de la ruta')}>
              {countryRoute.map((segment, index) => (
                <span className="country-route-step" key={`${segment.key}-${segment.first}`}>
                  {index > 0 && <span className="country-route-arrow" aria-hidden="true">→</span>}
                  <span className="country-route-flag">{countryFlag(segment.code)}</span>
                  <span>
                    <strong>{segment.country}</strong>
                    <small>{t(segment.first === segment.last ? 'salto' : 'saltos')} {segment.first === segment.last ? segment.first : `${segment.first}–${segment.last}`}</small>
                  </span>
                </span>
              ))}
            </div>
          )}

          <div className="mtr-table-wrap trace-table-wrap">
            <table className="mtr-table trace-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th className="l">Host / IP</th>
                  <th className="l">{t('País / localidad')}</th>
                  <th className="l">{t('Red / ASN')}</th>
                  <th>{t('Mejor')}</th>
                  <th>{t('Prom.')}</th>
                  <th>{t('Estado')}</th>
                </tr>
              </thead>
              <tbody>
                {hops.map((h) => (
                  <tr className={(h.reached ? 'reached ' : '') + (h.timeout ? 'timeout' : '')} key={h.ttl}>
                    <td className="ttl">{h.ttl}</td>
                    <td className="l host">
                      {h.timeout ? <span className="err">* * *</span> : (
                        <>
                          <span className="mono">{h.hostname || h.addr}</span>
                          {h.hostname && <span className="hop-ip"> {h.addr}</span>}
                          {classChips(h.classes)}
                        </>
                      )}
                    </td>
                    <td className="l">
                      {h.country ? (
                        <>
                          <span className="route-location-main">{countryFlag(h.countryCode)} {h.country}</span>
                          {(h.city || h.region) && <span className="route-location-sub">{[h.city, h.region].filter(Boolean).join(', ')}</span>}
                        </>
                      ) : <span className="dim">{t('Sin dato GeoIP')}</span>}
                    </td>
                    <td className="l">
                      {h.asn ? (
                        <>
                          <span className="mono">AS{h.asn}</span>
                          {h.org && <span className="route-location-sub">{h.org}</span>}
                        </>
                      ) : <span className="dim">—</span>}
                    </td>
                    <td>{h.timeout ? '—' : `${h.bestMs} ms`}</td>
                    <td className="accent-t">{h.timeout ? '—' : `${h.avgMs} ms`}</td>
                    <td>{h.reached ? <span className="tag public">{t('destino')}</span> : h.timeout ? <span className="dim">{t('sin respuesta')}</span> : <span className="dim">{t('tránsito')}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {countryRoute.length === 0 && hops.some((h) => !h.timeout) && (
            <p className="dim route-no-geo">{t('No hay ubicación GeoIP disponible para estos saltos; la tabla conserva la ruta técnica completa.')}</p>
          )}
        </div>
      )}
    </>
  );
}

// ---------------- MTR panel ----------------
function lossClass(loss: number): string {
  if (loss <= 0) return '';
  if (loss < 20) return 'warn';
  return 'bad';
}

function MtrPanel() {
  const { t } = useI18n();
  const [target, setTarget] = useState('8.8.8.8');
  const [resolveDNS, setResolveDNS] = useState(true);
  const [running, setRunning] = useState(false);
  const [hops, setHops] = useState<MtrHop[]>([]);
  const [resolved, setResolved] = useState('');
  const [error, setError] = useState<string | null>(null);

  const runIdRef = useRef<string | null>(null);
  const unsubRef = useRef<(() => void) | null>(null);

  useEffect(() => () => {
    if (unsubRef.current) unsubRef.current();
    if (runIdRef.current) stopMTR(runIdRef.current);
  }, []);

  async function start() {
    if (running) return;
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    setError(null);
    setHops([]);
    setResolved('');
    try {
      const id = await startMTR(target.trim(), 30, 1200, 1000, resolveDNS);
      runIdRef.current = id;
      setRunning(true);
      unsubRef.current = subscribeMTR(
        id,
        (rows) => setHops(rows),
        (addr, err) => {
          setRunning(false);
          runIdRef.current = null;
          if (addr) setResolved(addr);
          if (err) setError(err);
        },
        (addr, err) => {
          if (addr) setResolved(addr);
          if (err) setError(err);
        },
      );
    } catch (e) {
      setError(String(e));
      setRunning(false);
    }
  }

  function stop() {
    if (unsubRef.current) unsubRef.current();
    if (runIdRef.current) stopMTR(runIdRef.current);
    unsubRef.current = null;
    runIdRef.current = null;
    setRunning(false);
  }

  function clear() {
    stop();
    setHops([]);
    setResolved('');
    setError(null);
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <input
            className="input"
            placeholder={t('IP o dominio (8.8.8.8, cloudflare.com)')}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !running && start()}
            disabled={running}
          />
          {running ? (
            <button className="btn ghost" onClick={stop}>■ {t('Detener')}</button>
          ) : (
            <button className="btn" onClick={start} disabled={!target.trim()}>▶ {t('Iniciar MTR')}</button>
          )}
        </div>
        <label className="check-inline">
          <input type="checkbox" checked={resolveDNS} onChange={(e) => setResolveDNS(e.target.checked)} disabled={running} />
          {t('Resolver DNS inverso por salto')}
        </label>
      </div>

      {resolved && (
        <p className="dim" style={{ marginTop: 12, fontSize: 13 }}>
          {t('Enviando a')} <span className="mono" style={{ color: 'var(--text)' }}>{resolved}</span>
        </p>
      )}

      {error && <div className="note">{error}</div>}

      {(hops.length > 0 || running) && (
        <div className="card" style={{ marginTop: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <h3 style={{ margin: 0 }}>{t('Ruta continua')} {running && <span className="spin" style={{ marginLeft: 8, verticalAlign: 'middle' }} />}</h3>
            <div style={{ display: 'flex', gap: 8 }}>
              <CopyButton label={t('Copiar tabla')} getText={() => formatMtrSummary(target, hops, t)} />
              <button className="btn ghost" onClick={clear}>🗑 {t('Limpiar')}</button>
            </div>
          </div>
          <div className="mtr-table-wrap" style={{ marginTop: 10 }}>
            <table className="mtr-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th className="l">Host</th>
                  <th className="l">{t('País / ASN')}</th>
                  <th>{t('Pérd.')}</th>
                  <th>{t('Env')}</th>
                  <th>{t('Últ')}</th>
                  <th>{t('Prom')}</th>
                  <th>{t('Mej')}</th>
                  <th>{t('Peor')}</th>
                  <th>Jitter</th>
                </tr>
              </thead>
              <tbody>
                {hops.map((h) => (
                  <tr key={h.ttl} className={h.reached ? 'reached' : ''}>
                    <td className="ttl">{h.ttl}</td>
                    <td className="l host">
                      {h.addr ? (
                        <>
                          <span className="mono">{h.hostname || h.addr}</span>
                          {h.hostname && <span className="hop-ip"> {h.addr}</span>}
                        </>
                      ) : (
                        <span className="err">???</span>
                      )}
                    </td>
                    <td className="l dim" style={{ fontSize: 11.5 }}>
                      {h.country && <>{countryFlag(h.countryCode)} {h.country}</>}
                      {h.country && h.asn ? ' · ' : ''}
                      {h.asn ? 'AS' + h.asn : ''}
                    </td>
                    <td className={lossClass(h.lossPct)}>{h.lossPct}%</td>
                    <td className="dim">{h.sent}</td>
                    <td>{h.addr ? h.lastMs : '—'}</td>
                    <td className="accent-t">{h.addr ? h.avgMs : '—'}</td>
                    <td className="dim">{h.addr ? h.bestMs : '—'}</td>
                    <td className="dim">{h.addr ? h.worstMs : '—'}</td>
                    <td>{h.addr ? h.jitterMs : '—'}</td>
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

// ---------------- Tabbed view ----------------
export default function PingMTR() {
  const { t } = useI18n();
  const [tab, setTab] = useState<Tab>('ping');
  const [panelEpochs, setPanelEpochs] = useState<Record<Tab, number>>({ ping: 0, trace: 0, mtr: 0 });

  function clearActiveTab() {
    setPanelEpochs((prev) => ({ ...prev, [tab]: prev[tab] + 1 }));
  }

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Ping / MTR')}</h2>
        <p className="body-text">
          {t('Motores propios sobre ICMP. En Windows usan la API IcmpSendEcho (sin privilegios); en macOS/Linux sockets ICMP con TTL. Ping mide latencia/pérdida/jitter en vivo; Traceroute descubre la ruta salto a salto con DNS inverso y clasificación. MTR (probing continuo por salto) se suma sobre el mismo motor.')}
        </p>
      </div>

      <div className="tabs">
        <button className={'tab' + (tab === 'ping' ? ' active' : '')} onClick={() => setTab('ping')}>Ping</button>
        <button className={'tab' + (tab === 'trace' ? ' active' : '')} onClick={() => setTab('trace')}>Traceroute</button>
        <button className={'tab' + (tab === 'mtr' ? ' active' : '')} onClick={() => setTab('mtr')}>MTR</button>
        <button className="btn ghost tab-clear" onClick={clearActiveTab}>🗑 {t('Limpiar pestaña')}</button>
      </div>

      {/* Los tres paneles quedan siempre montados (solo se oculta con CSS) para
          que el estado (resultados, corridas en curso) no se pierda al
          cambiar de pestaña — antes se desmontaban por completo. */}
      <div style={{ display: tab === 'ping' ? 'block' : 'none' }}><PingPanel key={panelEpochs.ping} /></div>
      <div style={{ display: tab === 'trace' ? 'block' : 'none' }}><TracePanel key={panelEpochs.trace} /></div>
      <div style={{ display: tab === 'mtr' ? 'block' : 'none' }}><MtrPanel key={panelEpochs.mtr} /></div>
    </div>
  );
}
