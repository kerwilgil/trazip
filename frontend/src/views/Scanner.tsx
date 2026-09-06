import { useEffect, useRef, useState } from 'react';
import {
  startScan,
  stopScan,
  subscribeScan,
  backendAvailable,
  auditService,
  compareExposure,
  type ScanResult,
  type ScanSummary,
  type ServiceAuditResult,
  type ExposureResult,
} from '../lib/api';
import { useI18n } from '../lib/i18n';

type Preset = 'quick' | 'top100' | 'extended' | 'range';
interface ExposureDrift { newlyOpen: number[]; nowClosed: number[] }

const PRESET_TOTAL: Record<Preset, number> = {
  quick: 25,
  top100: 0,
  extended: 1000,
  range: 0,
};

export default function Scanner() {
  const { t } = useI18n();
  const [target, setTarget] = useState('127.0.0.1');
  const [preset, setPreset] = useState<Preset>('quick');
  const [lo, setLo] = useState(1);
  const [hi, setHi] = useState(1024);
  const [ratePerSec, setRatePerSec] = useState(250);
  const [concurrency, setConcurrency] = useState(128);
  const [timeoutMs, setTimeoutMs] = useState(1500);
  const [running, setRunning] = useState(false);
  const [scanned, setScanned] = useState(0);
  const [total, setTotal] = useState(0);
  const [open, setOpen] = useState<ScanResult[]>([]);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expectedText, setExpectedText] = useState('');
  const [exposure, setExposure] = useState<ExposureResult | null>(null);
  const [audits, setAudits] = useState<Record<number, ServiceAuditResult>>({});
  const [auditingPort, setAuditingPort] = useState<number | null>(null);
  const [drift, setDrift] = useState<ExposureDrift | null>(null);

  const runIdRef = useRef<string | null>(null);
  const unsubRef = useRef<(() => void) | null>(null);
  const openPortsRef = useRef<number[]>([]);
  const previousPortsRef = useRef<Record<string, number[]>>({});

  useEffect(() => () => {
    if (unsubRef.current) unsubRef.current();
    if (runIdRef.current) stopScan(runIdRef.current);
  }, []);

  async function start() {
    if (running) return;
    if (!backendAvailable()) {
      setError(t('Necesita el runtime Wails (app de escritorio).'));
      return;
    }
    if (preset === 'range' && (lo < 1 || hi > 65535 || hi < lo)) {
      setError(t('El rango debe estar entre 1 y 65535 y el puerto final no puede ser menor que el inicial.'));
      return;
    }
    setError(null);
    setOpen([]);
    setSummary(null);
    setExposure(null);
    setAudits({});
    setDrift(null);
    openPortsRef.current = [];
    setScanned(0);
    setTotal(preset === 'range' ? hi - lo + 1 : PRESET_TOTAL[preset]);
    try {
      const id = await startScan(target.trim(), preset, lo, hi, { ratePerSec, concurrency, timeoutMs });
      runIdRef.current = id;
      setRunning(true);
      unsubRef.current = subscribeScan(
        id,
        (r, sc, tot) => {
          setScanned(sc);
          setTotal(tot);
          if (r.state === 'open') {
            openPortsRef.current.push(r.port);
            setOpen((prev) => [...prev, r].sort((a, b) => a.port - b.port));
          }
        },
        (sum, err) => {
          setRunning(false);
          runIdRef.current = null;
          setSummary(sum);
          if (err) setError(err);
          const expected = expectedText.split(/[\s,;]+/).map(Number).filter((p) => p >= 1 && p <= 65535);
          if (expected.length > 0) compareExposure(openPortsRef.current, expected).then(setExposure).catch((e) => setError(String(e)));
          const key = target.trim().toLowerCase();
          const previous = previousPortsRef.current[key] ?? [];
          const current = [...new Set(openPortsRef.current)].sort((a, b) => a - b);
          if (previous.length > 0) {
            setDrift({
              newlyOpen: current.filter((p) => !previous.includes(p)),
              nowClosed: previous.filter((p) => !current.includes(p)),
            });
          }
          previousPortsRef.current[key] = current;
        },
      );
    } catch (e) {
      setError(String(e));
      setRunning(false);
    }
  }

  async function validatePort(port: number) {
    setAuditingPort(port); setError(null);
    try { const r = await auditService(target.trim(), port); setAudits((prev) => ({ ...prev, [port]: r })); }
    catch (e) { setError(String(e)); } finally { setAuditingPort(null); }
  }

  function stop() {
    if (unsubRef.current) unsubRef.current();
    if (runIdRef.current) stopScan(runIdRef.current);
    unsubRef.current = null;
    runIdRef.current = null;
    setRunning(false);
  }

  const pct = total > 0 ? Math.min(100, Math.round((scanned / total) * 100)) : 0;
  const broadOrFast = (preset === 'range' && hi - lo + 1 > 1000) || ratePerSec > 1000;

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Scanner')}</h2>
        <p className="body-text">
          {t('Inventario TCP connect propio y 100% local. Cada ejecución queda limitada al objetivo escrito, con velocidad, concurrencia, timeout y cancelación visibles. La etiqueta del servicio se infiere por el puerto; no se ejecutan payloads ni herramientas externas.')}
        </p>
      </div>

      <div className="card">
        <div className="field">
          <input
            className="input"
            placeholder={t('IP o dominio del objetivo autorizado')}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={running}
          />
          {running ? (
            <button className="btn ghost" onClick={stop}>■ {t('Detener')}</button>
          ) : (
            <button className="btn" onClick={start} disabled={!target.trim()}>▶ {t('Escanear')}</button>
          )}
        </div>

        <div className="field-grid cols-4">
          <label>
            {t('Perfil')}
            <select className="input" value={preset} onChange={(e) => setPreset(e.target.value as Preset)} disabled={running}>
              <option value="quick">{t('Rápido · 25 puertos')}</option>
              <option value="top100">{t('Estándar · Top 100')}</option>
              <option value="extended">{t('Extendido · 1–1000')}</option>
              <option value="range">{t('Rango personalizado')}</option>
            </select>
          </label>
          <label>
            {t('Velocidad máxima · puertos/s')}
            <input className="input" type="number" min={1} max={5000} value={ratePerSec} onChange={(e) => setRatePerSec(+e.target.value)} disabled={running} />
          </label>
          <label>
            {t('Concurrencia')}
            <input className="input" type="number" min={1} max={512} value={concurrency} onChange={(e) => setConcurrency(+e.target.value)} disabled={running} />
          </label>
          <label>
            Timeout · ms
            <input className="input" type="number" min={100} max={10000} step={100} value={timeoutMs} onChange={(e) => setTimeoutMs(+e.target.value)} disabled={running} />
          </label>
        </div>

        {preset === 'range' && (
          <div className="field-grid cols-2">
            <label>
              {t('Puerto inicial')}
              <input className="input" type="number" value={lo} min={1} max={65535} onChange={(e) => setLo(+e.target.value)} disabled={running} />
            </label>
            <label>
              {t('Puerto final')}
              <input className="input" type="number" value={hi} min={1} max={65535} onChange={(e) => setHi(+e.target.value)} disabled={running} />
            </label>
          </div>
        )}

        <label className="settings-label" htmlFor="scanner-expected-ports">{t('Política esperada · puertos permitidos')}</label>
        <input id="scanner-expected-ports" className="input mono" value={expectedText} onChange={(e) => setExpectedText(e.target.value)} disabled={running} placeholder={t('Ej. 22,80,443 (opcional)')} />

        <p className="dim" style={{ fontSize: 11.5, marginTop: 12 }}>
          {t('Alcance activo: únicamente {target}. TRAZIP registra el perfil efectivo en el resultado y no amplía el objetivo automáticamente.', { target: target.trim() || t('sin objetivo') })}
        </p>
        {broadOrFast && (
          <div className="note" style={{ marginTop: 10 }}>
            {t('Perfil de impacto elevado: use esta configuración solo en infraestructura propia o expresamente autorizada.')}
          </div>
        )}
      </div>

      {error && <div className="note">{error}</div>}

      {(running || summary) && (
        <div className="card" style={{ marginTop: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
            <h3 style={{ margin: 0 }}>
              {t('Progreso')} {running && <span className="spin" style={{ marginLeft: 8, verticalAlign: 'middle' }} />}
            </h3>
            <span className="dim mono" style={{ fontSize: 13 }}>{t('{count} puertos', { count: `${scanned}${total ? ` / ${total}` : ''}` })}</span>
          </div>
          <div className="progress"><div className="progress-fill" style={{ width: `${pct}%` }} /></div>
          {summary && (
            <div className="dim" style={{ fontSize: 13, marginTop: 10 }}>
              <strong style={{ color: 'var(--ok)' }}>{t('{open} abiertos · {closed} cerrados · {filtered} filtrados · {duration}s', { open: summary.open, closed: summary.closed, filtered: summary.filtered, duration: summary.durationSec.toFixed(1) })}</strong>
              <br />{t('Telemetría: {rate} puertos/s · límite {limit}/s · concurrencia {concurrency} · timeout {timeout} ms', { rate: summary.actualRate.toFixed(1), limit: summary.ratePerSec, concurrency: summary.concurrency, timeout: summary.timeoutMs })}
            </div>
          )}
        </div>
      )}

      {open.length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>{t('Puertos abiertos ({count})', { count: open.length })}</h3>
          <div className="grid cols-4">
            {open.map((p) => (
              <div className="port-card" key={p.port}>
                <span className="port-num">{p.port}</span>
                <span className="port-svc">{p.service || t('desconocido')}</span>
                {p.rttMs ? <span className="port-rtt">{p.rttMs} ms</span> : null}
                <button className="btn ghost" style={{ marginTop: 6, padding: '4px 8px', fontSize: 11 }} onClick={() => validatePort(p.port)} disabled={auditingPort === p.port}>{auditingPort === p.port ? <span className="spin" /> : t('Validar servicio')}</button>
              </div>
            ))}
          </div>
        </div>
      )}

      {(exposure || drift) && (
        <div className="card" style={{ marginTop: 16, borderColor: exposure ? (exposure.compliant ? 'var(--ok)' : 'var(--warn)') : 'var(--border)' }}>
          <h3 style={{ marginTop: 0 }}>{t('Validación de exposición')}</h3>
          {exposure && (
            <p style={{ margin: '0 0 8px' }}>
              <span className={'pill ' + (exposure.compliant ? 'ok' : 'warn')}><span className="dot" />{exposure.compliant ? t('Cumple la política') : t('Desviación detectada')}</span>
            </p>
          )}
          <div className="list-reset">
            {exposure && exposure.unexpected.length > 0 && (
              <div className="kv"><span className="k">{t('Inesperados')}</span><span className="v mono">{exposure.unexpected.join(', ')}</span></div>
            )}
            {exposure && exposure.missing.length > 0 && (
              <div className="kv"><span className="k">{t('Esperados no observados')}</span><span className="v mono">{exposure.missing.join(', ')}</span></div>
            )}
            {drift && (
              <div className="kv"><span className="k">{t('Nuevos abiertos')}</span><span className="v mono">{drift.newlyOpen.join(', ') || t('ninguno')}</span></div>
            )}
            {drift && (
              <div className="kv"><span className="k">{t('Ya no abiertos')}</span><span className="v mono">{drift.nowClosed.join(', ') || t('ninguno')}</span></div>
            )}
          </div>
          <p className="dim" style={{ fontSize: 11.5, marginTop: 10 }}>{t('Compara el resultado con la política escrita; no modifica reglas del firewall.')}</p>
        </div>
      )}

      {Object.values(audits).length > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <h3>{t('Validaciones seguras de servicio')}</h3>
          {Object.values(audits).sort((a, b) => a.port - b.port).map((a) => (
            <div className="hop-row" key={a.port} style={{ flexWrap: 'wrap' }}>
              <span className="tag active">{a.protocol.toUpperCase()}/{a.port}</span><span className="mono">{a.target}</span>
              <span className={a.err ? 'err' : 'dim'}>{a.err || t('{count} evidencia(s) · {duration} ms', { count: (a.findings ?? []).length, duration: a.durationMs })}</span>
              {(a.findings ?? []).map((f, i) => <span key={i} style={{ flexBasis: '100%', fontSize: 12 }}><strong>{f.title}:</strong> {f.detail}{f.evidence ? ` · ${f.evidence}` : ''}</span>)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
