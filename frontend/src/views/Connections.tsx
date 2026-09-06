import { useMemo, useState } from 'react';
import { backendAvailable, type ConnRow } from '../lib/api';
import { useCaptureSession } from '../lib/session';
import { countryFlag } from '../lib/flags';
import CopyButton from '../components/CopyButton';
import { useI18n } from '../lib/i18n';

function csvEscape(v: string): string {
  if (/[",\n]/.test(v)) return '"' + v.replace(/"/g, '""') + '"';
  return v;
}

function connectionsToCSV(rows: ConnRow[]): string {
  const header = 'proto,local,remoto,estado,pid,proceso,pais,organizacion';
  const lines = rows.map((c) =>
    [
      c.proto,
      `${c.localAddr}:${c.localPort}`,
      c.remoteAddr ? `${c.remoteAddr}:${c.remotePort}` : '',
      c.state || '',
      c.pid ?? '',
      c.process || '',
      c.remote?.country || '',
      c.remote?.org || '',
    ]
      .map((v) => csvEscape(String(v)))
      .join(','),
  );
  return [header, ...lines].join('\n');
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

const INTERVAL_OPTIONS = [
  { label: '1 s', ms: 1000 },
  { label: '2 s', ms: 2000 },
  { label: '5 s', ms: 5000 },
  { label: '10 s', ms: 10000 },
];

export default function Connections() {
  const { locale, t } = useI18n();
  const { connMonRunning: running, connMonSnapshot: snapshot, connMonError, startConnMonSession, stopConnMonSession, clearConnMon } = useCaptureSession();
  const [intervalMs, setIntervalMs] = useState(2000);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const error = dialogError ?? connMonError;

  async function start() {
    if (!backendAvailable()) {
      setDialogError(t('Necesita el runtime Wails (app de escritorio).'));
      return;
    }
    setDialogError(null);
    await startConnMonSession(intervalMs);
  }

  const rows = snapshot?.connections ?? [];
  // Established/active first, then listeners — a live "what's talking right
  // now" view is more useful with the noisy always-on listen sockets pushed
  // to the bottom instead of interleaved.
  const sorted = useMemo(
    () => [...rows].sort((a, b) => {
      const aListen = a.state === 'listen' || !a.remoteAddr ? 1 : 0;
      const bListen = b.state === 'listen' || !b.remoteAddr ? 1 : 0;
      if (aListen !== bListen) return aListen - bListen;
      return (a.process || '').localeCompare(b.process || '');
    }),
    [rows],
  );
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return sorted;
    return sorted.filter((c) =>
      (c.process || '').toLowerCase().includes(q) ||
      c.remoteAddr.toLowerCase().includes(q) ||
      c.localAddr.toLowerCase().includes(q) ||
      (c.remote?.country || '').toLowerCase().includes(q) ||
      (c.remote?.org || '').toLowerCase().includes(q),
    );
  }, [sorted, search]);

  const uniqueProcesses = useMemo(() => new Set(rows.filter((c) => c.process).map((c) => c.process)).size, [rows]);
  const publicRemote = useMemo(() => rows.filter((c) => c.remote?.isPublic), [rows]);
  const uniqueCountries = useMemo(() => new Set(publicRemote.map((c) => c.remote?.country).filter(Boolean)).size, [publicRemote]);

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Conexiones')}</h2>
        <p className="body-text">
          {t('Sockets TCP/UDP activos de esta PC ahora mismo, con el proceso dueño de cada uno cuando el sistema operativo lo permite resolver, y país/organización offline para cada IP remota pública. Lectura pasiva de tablas del sistema operativo — TRAZIP no envía nada a la red para esto.')}
        </p>
      </div>

      <div className="card">
        <div className="field">
          <select className="input" style={{ maxWidth: 140 }} value={intervalMs} onChange={(e) => setIntervalMs(+e.target.value)} disabled={running}>
            {INTERVAL_OPTIONS.map((o) => <option key={o.ms} value={o.ms}>{t('Cada {interval}', { interval: o.label })}</option>)}
          </select>
          {running ? (
            <button className="btn ghost" onClick={stopConnMonSession}>■ {t('Detener')}</button>
          ) : (
            <button className="btn" onClick={start}>▶ {t('Monitorear')}</button>
          )}
          {snapshot && <button className="btn ghost" onClick={clearConnMon}>🗑 {t('Limpiar')}</button>}
          {running && <span className="dim" style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}><span className="live-dot" /> {t('en vivo')}</span>}
        </div>
        <p className="dim" style={{ fontSize: 11.5, marginTop: 10 }}>
          {t('Los nombres de proceso se resuelven localmente (sin admin) y nunca salen de esta PC.')}
        </p>
      </div>

      {error && <div className="note">{error}</div>}

      {snapshot && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat">
              <span className="label">{t('Conexiones')}</span>
              <span className="value accent">{snapshot.total}</span>
              <span className="sub">TCP + UDP</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Procesos')}</span>
              <span className="value">{uniqueProcesses}</span>
              <span className="sub">{t('identificados')}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Remotos públicos')}</span>
              <span className="value">{publicRemote.length}</span>
              <span className="sub">{t('con GeoIP/ASN')}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Países')}</span>
              <span className="value">{uniqueCountries}</span>
              <span className="sub">{t('distintos')}</span>
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0 }}>{t('Sockets ({count})', { count: filtered.length.toLocaleString(locale) })}</h3>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <input
                  className="input"
                  style={{ maxWidth: 220 }}
                  placeholder={t('Buscar proceso, IP, país…')}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
                <CopyButton label={t('Copiar CSV')} disabled={filtered.length === 0} getText={() => connectionsToCSV(filtered)} />
                <button
                  className="btn ghost"
                  disabled={filtered.length === 0}
                  onClick={() => downloadText(`trazip-conexiones-${Date.now()}.csv`, connectionsToCSV(filtered), 'text/csv')}
                >
                  ⬇ {t('Descargar CSV')}
                </button>
              </div>
            </div>

            <div className="mtr-table-wrap" style={{ marginTop: 10 }}>
              <table className="mtr-table">
                <thead>
                  <tr>
                    <th className="l">{t('Proceso')}</th>
                    <th className="l">Local</th>
                    <th className="l">{t('Remoto')}</th>
                    <th className="l">{t('País / Org')}</th>
                    <th className="l">Proto</th>
                    <th className="l">{t('Estado')}</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((c, i) => (
                    <tr key={`${c.proto}-${c.localAddr}-${c.localPort}-${c.remoteAddr}-${c.remotePort}-${i}`}>
                      <td className="l">{c.process ? <>{c.process}{c.pid ? <span className="dim mono" style={{ fontSize: 11 }}> · {c.pid}</span> : null}</> : <span className="dim">—</span>}</td>
                      <td className="l mono" style={{ fontSize: 12 }}>{c.localAddr}:{c.localPort}</td>
                      <td className="l mono" style={{ fontSize: 12 }}>{c.remoteAddr ? `${c.remoteAddr}:${c.remotePort}` : <span className="dim">—</span>}</td>
                      <td className="l">
                        {c.remote?.isPublic
                          ? <>{countryFlag(c.remote.countryCode)} {c.remote.org || c.remote.country || <span className="dim">—</span>}</>
                          : c.remoteAddr ? <span className="tag private">{t('privado')}</span> : <span className="dim">—</span>}
                      </td>
                      <td className="l dim">{c.proto.toUpperCase()}</td>
                      <td className="l dim">{c.state || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {!snapshot && !running && (
        <div className="empty" style={{ marginTop: 16 }}>
          <div className="big">🔌</div>
          {t('Presioná "Monitorear" para ver los sockets activos de esta PC.')}
        </div>
      )}
    </div>
  );
}
