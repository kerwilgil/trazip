import { useEffect, useRef, useState } from 'react';
import {
  backendAvailable,
  monitorAddTarget,
  monitorListTargets,
  monitorRemoveTarget,
  monitorHistory,
  monitorCompareWindows,
  monitorStart,
  monitorStop,
  monitorExportReport,
  monitorPinBaseline,
  monitorClearBaseline,
  monitorCompareToBaseline,
  subscribeMonitor,
  investigationAddMonitorEvent,
  type api,
  type monitor,
} from '../lib/api';
import AddToInvestigation from '../components/AddToInvestigation';
import { useI18n } from '../lib/i18n';

const NO_BACKEND = 'Necesita el runtime Wails (app de escritorio). En el preview del navegador no hay backend.';
const MAX_SAMPLES = 300;

function lossClass(loss: number): string {
  if (loss <= 0) return '';
  if (loss < 20) return 'warn';
  return 'bad';
}

function eventClass(kind: string): string {
  if (kind === 'recovery') return 'ok';
  if (kind === 'route_change') return 'warn';
  return 'danger';
}

function windowHops(hops: monitor.RouteHop[], center: number, radius = 2): monitor.RouteHop[] {
  return (hops || []).filter((h) => h.ttl >= center - radius && h.ttl <= center + radius);
}

function HopMiniList({ hops }: { hops: monitor.RouteHop[] }) {
  if (hops.length === 0) return <p className="dim" style={{ fontSize: 12 }}>—</p>;
  return (
    <div className="hop-list">
      {hops.map((h) => (
        <div className="hop-row" key={h.ttl}>
          <span className="hop-ttl">{h.ttl}</span>
          <span className="hop-host">
            <span className="mono">{h.host || h.addr || '* * *'}</span>
            {h.host && h.addr && <span className="hop-ip">{h.addr}</span>}
          </span>
        </div>
      ))}
    </div>
  );
}

function RouteChangeEventRow({ e }: { e: monitor.DegradationEvent }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const rc = e.routeChange;
  if (!rc) return null;
  const hasRttDelta = rc.rttBefore !== undefined && rc.rttAfter !== undefined;
  const hasLossDelta = rc.lossBefore !== undefined && rc.lossAfter !== undefined;

  return (
    <div className="hop-row" style={{ flexDirection: 'column', alignItems: 'stretch', cursor: 'pointer' }} onClick={() => setOpen((v) => !v)}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <span className={'pill ' + eventClass(e.kind)}><span className="dot" /> {t('cambio de ruta')}</span>
        <span className="dim mono" style={{ fontSize: 11 }}>{e.time.slice(11, 19)}</span>
        <span>{e.detail}</span>
        {rc.coincidentDegradation && <span className="tag warn">{t('Coincide con degradación')}</span>}
        <span className="dim" style={{ marginLeft: 'auto' }}>{open ? '▲' : '▼'}</span>
      </div>

      {open && (
        <div style={{ marginTop: 10 }} onClick={(ev) => ev.stopPropagation()}>
          <div className="grid cols-2">
            <div>
              <p className="dim" style={{ fontSize: 12 }}>{t('Antes')}</p>
              <HopMiniList hops={windowHops(rc.before, rc.firstChangedTtl)} />
            </div>
            <div>
              <p className="dim" style={{ fontSize: 12 }}>{t('Después')}</p>
              <HopMiniList hops={windowHops(rc.after, rc.firstChangedTtl)} />
            </div>
          </div>

          {(hasRttDelta || hasLossDelta) && (
            <p style={{ marginTop: 8, fontSize: 12 }}>
              {hasRttDelta && <>RTT: {rc.rttBefore!.toFixed(0)} ms → {rc.rttAfter!.toFixed(0)} ms</>}
              {hasRttDelta && hasLossDelta && ' · '}
              {hasLossDelta && <>Loss: {rc.lossBefore!.toFixed(0)}% → {rc.lossAfter!.toFixed(0)}%</>}
            </p>
          )}

          {rc.coincidentDegradation && (
            <p className="note" style={{ marginTop: 8 }}>
              {t('Coincidencia temporal; no demuestra causalidad.')}
            </p>
          )}

          <div style={{ marginTop: 8 }}>
            <AddToInvestigation onAdd={(id) => investigationAddMonitorEvent(id, e)} />
          </div>
        </div>
      )}
    </div>
  );
}

function fmtDuration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}

// Uptime-Kuma-style status strip: current state, a bar per recent sample
// (reusing the same heartbeat-pulse classes as the Ping panel's chart, so
// the two look consistent), and time online/down within the shown window.
// "Tiempo en línea/caído" is necessarily scoped to the visible window (bar
// count × sampling interval), not the target's whole lifetime — the app
// only retains recent samples, so anything claiming a lifetime total would
// be a guess dressed up as a number.
function UptimeBar({ samples, intervalMs }: { samples: monitor.Sample[]; intervalMs: number }) {
  const { t } = useI18n();
  const BAR_COUNT = 50;
  const recent = samples.slice(-BAR_COUNT);
  if (recent.length === 0) return null;

  const current = recent[recent.length - 1];
  const upCount = recent.filter((s) => s.ok).length;
  const downCount = recent.length - upCount;
  const uptimePct = (upCount / recent.length) * 100;

  let runStart = recent.length - 1;
  for (let i = recent.length - 2; i >= 0; i--) {
    if (recent[i].ok !== current.ok) break;
    runStart = i;
  }
  const lastChangeAt = recent[runStart].time;
  const sinceChangeMs = Date.now() - Date.parse(lastChangeAt);

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className={'pill ' + (current.ok ? 'ok' : 'danger')}><span className="dot" /> {current.ok ? t('En línea') : t('Caído')}</span>
          <span className="dim" style={{ fontSize: 12 }}>{t('desde hace')} {fmtDuration(sinceChangeMs)} · {t('último cambio')} {lastChangeAt.slice(11, 19)}</span>
        </div>
        <span className="dim" style={{ fontSize: 12 }}>{t('{uptime}% activo · últimas {count} muestras', { uptime: uptimePct.toFixed(1), count: recent.length })}</span>
      </div>
      <div className="heartbeat-strip" style={{ marginTop: 10, justifyContent: 'flex-start' }}>
        {recent.map((s, i) => (
          <span
            key={i}
            className={'heartbeat-pulse' + (s.ok ? '' : ' lost')}
            title={`${s.time.slice(11, 19)} · ${s.ok ? s.rttMs.toFixed(1) + ' ms' : t('caído')}${s.lossPct ? ` · ${t('pérdida')} ${s.lossPct.toFixed(0)}%` : ''}`}
          />
        ))}
      </div>
      <div className="heartbeat-caption" style={{ marginTop: 6 }}>
        <span>{t('Tiempo activo (ventana)')}: {fmtDuration(upCount * intervalMs)}</span>
        <span>{t('Tiempo inactivo (ventana)')}: {fmtDuration(downCount * intervalMs)}</span>
      </div>
    </div>
  );
}

// BaselineCard fixes or shows a target's pinned reference profile — a fixed
// window the operator marks as "this is what normal looks like", separate
// from the rolling 20-sample baseline degradation events already use (which
// drifts upward under sustained load and silently treats it as the new
// normal).
function BaselineCard({
  targetId,
  baseline,
  onChanged,
}: {
  targetId: string;
  baseline: monitor.BaselineProfile | null;
  onChanged: (b: monitor.BaselineProfile | null) => void;
}) {
  const { t } = useI18n();
  const [agoHours, setAgoHours] = useState(0);
  const [spanHours, setSpanHours] = useState(1);
  const [comparison, setComparison] = useState<monitor.BaselineComparison | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function pin() {
    setBusy(true);
    setError(null);
    try {
      const profile = await monitorPinBaseline(targetId, agoHours * 3600_000, spanHours * 3600_000);
      onChanged(profile);
      setComparison(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function clear() {
    setBusy(true);
    setError(null);
    try {
      await monitorClearBaseline(targetId);
      onChanged(null);
      setComparison(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function compare() {
    setError(null);
    try {
      setComparison(await monitorCompareToBaseline(targetId));
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h3>{t('Perfil base')}</h3>
      <p className="dim" style={{ fontSize: 12 }}>
        {t('A diferencia de la línea base móvil de las últimas 20 muestras, este perfil permanece fijo hasta que lo reemplazas o eliminas. Permite comparar con una ventana conocida de red estable en lugar de usar el promedio reciente.')}
      </p>

      {!baseline ? (
        <>
          <div className="field" style={{ marginTop: 8 }}>
            <label className="dim" style={{ fontSize: 12 }}>
              {t('Desde hace')}
              <input className="input" type="number" min={0} style={{ maxWidth: 80, marginLeft: 6 }} value={agoHours} onChange={(e) => setAgoHours(Math.max(0, Number(e.target.value) || 0))} /> h
            </label>
            <label className="dim" style={{ fontSize: 12 }}>
              {t('Duración')}
              <input className="input" type="number" min={1} style={{ maxWidth: 80, marginLeft: 6 }} value={spanHours} onChange={(e) => setSpanHours(Math.max(1, Number(e.target.value) || 1))} /> h
            </label>
            <button className="btn" onClick={pin} disabled={busy}>{busy ? <span className="spin" /> : null} {t('Fijar como perfil base')}</button>
          </div>
          <p className="dim" style={{ fontSize: 11, marginTop: 4 }}>
            {t('Ejemplo: "desde hace 20 h, duración 2 h" usa como referencia la ventana comprendida entre hace 20 y 18 horas. Esa ventana debe contener muestras guardadas.')}
          </p>
        </>
      ) : (
        <>
          <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 16, alignItems: 'center' }}>
            <span className="pill ok"><span className="dot" /> {t('Fijado')} {baseline.pinnedAt.slice(0, 19).replace('T', ' ')}</span>
            <span className="dim" style={{ fontSize: 12 }}>
              {t('ventana')} {baseline.windowFrom.slice(11, 19)}–{baseline.windowTo.slice(11, 19)} ({baseline.samples} {t('muestras')})
            </span>
            <span>{t('RTT promedio')}: <strong>{baseline.avgRttMs.toFixed(1)} ms</strong> · {t('pérdida')}: {baseline.lossPct.toFixed(1)}%</span>
          </div>
          <div style={{ marginTop: 10, display: 'flex', gap: 8 }}>
            <button className="btn ghost" onClick={compare} disabled={busy}>{t('Comparar con la última hora')}</button>
            <button className="btn ghost" onClick={clear} disabled={busy}>🗑 {t('Quitar perfil')}</button>
          </div>
          {comparison && (
            <div className="list-reset" style={{ marginTop: 10 }}>
              <div className="kv">
                <span className="k">{t('Última hora')}</span>
                <span className="v">{comparison.current.avgRttMs.toFixed(1)} ms · {comparison.current.samples} {t('muestras')} · {comparison.current.lossPct.toFixed(1)}% {t('pérdida')}</span>
              </div>
              <div className="kv">
                <span className="k">{t('Diferencia respecto al perfil base')}</span>
                <span className={'v ' + (comparison.deltaAvgRttMs > 0 ? 'err' : '')}>{comparison.deltaAvgRttMs >= 0 ? '+' : ''}{comparison.deltaAvgRttMs.toFixed(1)} ms · {comparison.deltaLossPct >= 0 ? '+' : ''}{comparison.deltaLossPct.toFixed(1)}% {t('pérdida')}</span>
              </div>
            </div>
          )}
        </>
      )}
      {error && <div className="note" style={{ marginTop: 8 }}>{error}</div>}
    </div>
  );
}

export default function Monitor() {
  const { t } = useI18n();
  const [targets, setTargets] = useState<api.MonitorTargetInfo[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [samples, setSamples] = useState<monitor.Sample[]>([]);
  const [events, setEvents] = useState<monitor.DegradationEvent[]>([]);
  const [comparison, setComparison] = useState<monitor.WindowComparison | null>(null);
  const [baseline, setBaseline] = useState<monitor.BaselineProfile | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  const [label, setLabel] = useState('');
  const [address, setAddress] = useState('');
  const [mode, setMode] = useState<'ping' | 'mtr'>('ping');
  const [intervalSec, setIntervalSec] = useState(5);
  const [retentionHours, setRetentionHours] = useState(24);

  const unsubRef = useRef<(() => void) | null>(null);

  const refreshTargets = async () => {
    if (!backendAvailable()) return;
    try {
      setTargets(await monitorListTargets());
    } catch (e) {
      setError(String(e));
    }
  };

  useEffect(() => {
    refreshTargets();
  }, []);

  useEffect(() => () => {
    if (unsubRef.current) unsubRef.current();
  }, []);

  async function addTarget() {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    if (!address.trim()) return;
    setError(null);
    try {
      await monitorAddTarget({
        label: label.trim() || address.trim(),
        address: address.trim(),
        mode,
        intervalMs: Math.max(1, intervalSec) * 1000,
        retentionHours: Math.max(1, retentionHours),
      });
      setLabel('');
      setAddress('');
      await refreshTargets();
    } catch (e) {
      setError(String(e));
    }
  }

  async function removeTarget(id: string) {
    try {
      await monitorRemoveTarget(id);
      if (selected === id) {
        if (unsubRef.current) unsubRef.current();
        setSelected(null);
      }
      await refreshTargets();
    } catch (e) {
      setError(String(e));
    }
  }

  async function select(id: string) {
    if (unsubRef.current) unsubRef.current();
    setSelected(id);
    setSamples([]);
    setEvents([]);
    setComparison(null);
    setBaseline(null);
    setError(null);
    try {
      const h = await monitorHistory(id, 0);
      setSamples(h.samples?.slice(-MAX_SAMPLES) ?? []);
      setEvents(h.events ?? []);
      setBaseline(h.baseline ?? null);
    } catch (e) {
      setError(String(e));
    }
    unsubRef.current = subscribeMonitor(
      id,
      (s) => setSamples((prev) => [...prev, s].slice(-MAX_SAMPLES)),
      (e) => setEvents((prev) => [e, ...prev].slice(0, 100)),
    );
  }

  async function start(id: string) {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    setError(null);
    try {
      await monitorStart(id);
      if (selected !== id) await select(id);
      await refreshTargets();
    } catch (e) {
      setError(String(e));
    }
  }

  async function stop(id: string) {
    try {
      await monitorStop(id);
      await refreshTargets();
    } catch (e) {
      setError(String(e));
    }
  }

  async function compare(id: string) {
    try {
      setComparison(await monitorCompareWindows(id, 30 * 60 * 1000));
    } catch (e) {
      setError(String(e));
    }
  }

  async function exportReport(id: string, format: string) {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    setExporting(true);
    try {
      const path = await monitorExportReport(id, format, 0, 30 * 60 * 1000);
      if (path) setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setExporting(false);
    }
  }

  const selectedInfo = targets.find((t) => t.target.id === selected);

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Monitor histórico')}</h2>
        <p className="body-text">
          {t('Ping/MTR continuo por target, con retención configurable, detección de degradación respecto a una línea base móvil y comparación entre ventanas de tiempo. El historial se guarda en tu perfil de usuario y sobrevive a reinicios de la app.')}
        </p>
      </div>

      <div className="card">
        <h3>{t('Agregar target')}</h3>
        <div className="field">
          <input className="input" placeholder={t('Etiqueta (opcional)')} value={label} onChange={(e) => setLabel(e.target.value)} style={{ maxWidth: 160 }} />
          <input className="input" placeholder={t('IP o dominio')} value={address} onChange={(e) => setAddress(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addTarget()} />
          <select className="input" style={{ maxWidth: 100 }} value={mode} onChange={(e) => setMode(e.target.value as 'ping' | 'mtr')}>
            <option value="ping">Ping</option>
            <option value="mtr">MTR</option>
          </select>
          <input className="input" type="number" style={{ maxWidth: 90 }} title={t('Intervalo (s)')} aria-label={t('Intervalo (s)')} value={intervalSec} onChange={(e) => setIntervalSec(Number(e.target.value) || 5)} />
          <input className="input" type="number" style={{ maxWidth: 90 }} title={t('Retención (h)')} aria-label={t('Retención (h)')} value={retentionHours} onChange={(e) => setRetentionHours(Number(e.target.value) || 24)} />
          <button className="btn" onClick={addTarget} disabled={!address.trim()}>+ {t('Agregar')}</button>
        </div>
        <p className="dim" style={{ fontSize: 11.5, marginTop: 4 }}>{t('Intervalo en segundos · retención en horas.')}</p>
      </div>

      {error && <div className="note">{error}</div>}

      <div className="card" style={{ marginTop: 16 }}>
        <h3>{t('Targets')}</h3>
        {targets.length === 0 ? (
          <p className="dim">{t('Sin targets todavía.')}</p>
        ) : (
          <div className="hop-list">
            {targets.map((targetInfo) => (
              <div className={'hop-row' + (selected === targetInfo.target.id ? ' reached' : '')} key={targetInfo.target.id} style={{ cursor: 'pointer' }} onClick={() => select(targetInfo.target.id)}>
                <span className={'pill ' + (targetInfo.running ? 'ok' : 'warn')}><span className="dot" /> {targetInfo.running ? t('corriendo') : t('detenido')}</span>
                <span className="hop-host mono">{targetInfo.target.label} — {targetInfo.target.address}</span>
                <span className="dim" style={{ fontSize: 11 }}>{targetInfo.target.mode} · {t('cada {seconds}s · retención {hours}h', { seconds: targetInfo.target.intervalMs / 1000, hours: targetInfo.target.retentionHours })}</span>
                <span style={{ marginLeft: 'auto', display: 'flex', gap: 6 }} onClick={(e) => e.stopPropagation()}>
                  {targetInfo.running ? (
                    <button className="btn ghost" style={{ padding: '3px 10px', fontSize: 12 }} onClick={() => stop(targetInfo.target.id)}>■ {t('Detener')}</button>
                  ) : (
                    <button className="btn ghost" style={{ padding: '3px 10px', fontSize: 12 }} onClick={() => start(targetInfo.target.id)}>▶ {t('Iniciar')}</button>
                  )}
                  <button className="btn ghost" style={{ padding: '3px 10px', fontSize: 12 }} onClick={() => removeTarget(targetInfo.target.id)}>🗑</button>
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {selected && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat">
              <span className="label">{t('Muestras')}</span>
              <span className="value accent">{samples.length}</span>
              <span className="sub">{selectedInfo?.running ? t('en vivo') : t('histórico')}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Último RTT')}</span>
              <span className="value">{samples.length ? samples[samples.length - 1].rttMs.toFixed(1) : '—'} ms</span>
              <span className="sub">{samples.length && !samples[samples.length - 1].ok ? t('perdido') : 'OK'}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Eventos')}</span>
              <span className={'value ' + (events.length ? '' : 'accent')}>{events.length}</span>
              <span className="sub">{t('de degradación')}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Reporte')}</span>
              <span className="sub" style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 4 }}>
                {['json', 'csv', 'html', 'pdf'].map((f) => (
                  <button key={f} className="btn ghost" style={{ padding: '3px 8px', fontSize: 11 }} disabled={exporting} onClick={() => exportReport(selected, f)}>{f.toUpperCase()}</button>
                ))}
              </span>
            </div>
          </div>

          {selectedInfo && <UptimeBar samples={samples} intervalMs={selectedInfo.target.intervalMs} />}

          <BaselineCard targetId={selected} baseline={baseline} onChanged={setBaseline} />

          <div className="card" style={{ marginTop: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0 }}>{t('Muestras')}</h3>
              <button className="btn ghost" onClick={() => compare(selected)}>{t('Comparar últimos 30 min')}</button>
            </div>
            <div className="mtr-table-wrap pkt-scroll" style={{ marginTop: 10 }}>
              <table className="mtr-table pkt-table">
                <thead><tr><th className="l">{t('Hora')}</th><th>{t('Estado')}</th><th>RTT (ms)</th><th>{t('Pérdida')}</th><th>{t('Saltos')}</th></tr></thead>
                <tbody>
                  {samples.slice().reverse().slice(0, 200).map((s, i) => (
                    <tr key={i}>
                      <td className="l dim mono">{s.time.slice(11, 19)}</td>
                      <td className={s.ok ? '' : 'err'}>{s.ok ? 'OK' : t('perdido')}</td>
                      <td className="accent-t">{s.ok ? s.rttMs.toFixed(1) : '—'}</td>
                      <td className={lossClass(s.lossPct)}>{s.lossPct.toFixed(0)}%</td>
                      <td className="dim">{s.hopCount || ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {comparison && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>{t('Comparación de ventanas')}</h3>
              <div className="grid cols-2">
                <div>
                  <p className="dim" style={{ fontSize: 12 }}>{t('Reciente')} ({comparison.recent.samples} {t('muestras')})</p>
                  <p>{t('RTT promedio')}: <strong>{comparison.recent.avgRttMs.toFixed(1)} ms</strong> · {t('Pérdida')}: {comparison.recent.lossPct.toFixed(1)}%</p>
                </div>
                <div>
                  <p className="dim" style={{ fontSize: 12 }}>{t('Anterior')} ({comparison.previous.samples} {t('muestras')})</p>
                  <p>{t('RTT promedio')}: <strong>{comparison.previous.avgRttMs.toFixed(1)} ms</strong> · {t('Pérdida')}: {comparison.previous.lossPct.toFixed(1)}%</p>
                </div>
              </div>
              <p className={comparison.deltaAvgRttMs > 0 ? 'err' : 'dim'} style={{ marginTop: 8 }}>
                {t('Diferencia de RTT')}: {comparison.deltaAvgRttMs >= 0 ? '+' : ''}{comparison.deltaAvgRttMs.toFixed(1)} ms · {t('Diferencia de pérdida')}: {comparison.deltaLossPct >= 0 ? '+' : ''}{comparison.deltaLossPct.toFixed(1)}%
              </p>
            </div>
          )}

          {events.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3>{t('Eventos')}</h3>
              <div className="hop-list">
                {events.map((e, i) =>
                  e.kind === 'route_change' && e.routeChange ? (
                    <RouteChangeEventRow e={e} key={i} />
                  ) : (
                    <div className="hop-row" key={i}>
                      <span className={'pill ' + eventClass(e.kind)}><span className="dot" /> {e.kind}</span>
                      <span className="dim mono" style={{ fontSize: 11 }}>{e.time.slice(11, 19)}</span>
                      <span>{e.detail}</span>
                    </div>
                  )
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
