import { Fragment, useMemo, useState } from 'react';
import { backendAvailable, type EndpointInfo } from '../lib/api';
import { useCaptureSession } from '../lib/session';
import { countryFlag } from '../lib/flags';
import CopyButton from '../components/CopyButton';
import { useI18n, type Locale } from '../lib/i18n';

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

function fmtDate(iso: string | undefined, locale: Locale): string {
  if (!iso) return '—';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return '—';
  return new Date(t).toLocaleString(locale, { dateStyle: 'short', timeStyle: 'medium' });
}

function classChips(classes?: string[]) {
  if (!classes || classes.length === 0) return null;
  const known = ['public', 'private', 'bogon', 'reserved', 'documentation', 'vpn', 'proxy', 'tor', 'hosting'];
  return (
    <>
      {classes.map((c) => (
        <span key={c} className={'tag ' + (known.includes(c) ? c : '')} style={{ marginRight: 4 }}>{c}</span>
      ))}
    </>
  );
}

function csvEscape(v: string): string {
  if (/[",\n]/.test(v)) return '"' + v.replace(/"/g, '""') + '"';
  return v;
}

function endpointsToCSV(rows: EndpointInfo[]): string {
  const header = 'ip,clases,pais,ciudad,asn,organizacion,primeraVez,ultimaVez,paquetes,bytes';
  const lines = rows.map((e) =>
    [
      e.addr,
      (e.classes || []).join(' '),
      e.country || '',
      e.city || '',
      e.asn ?? '',
      e.org || '',
      e.firstSeen || '',
      e.lastSeen || '',
      e.packets,
      e.bytes,
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

export default function Endpoints() {
  const { locale, t } = useI18n();
  const { pcapPath: path, pcapResult: result, pcapLoading: loading, pcapError, openPcap, clearPcap } = useCaptureSession();
  const [dialogError, setDialogError] = useState<string | null>(null);
  const error = dialogError ?? pcapError;
  const [search, setSearch] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  async function open() {
    if (!backendAvailable()) {
      setDialogError(t('Necesita el runtime Wails (app de escritorio). En el navegador no hay backend ni diálogo de archivos.'));
      return;
    }
    setDialogError(null);
    await openPcap();
  }

  const endpoints = result?.endpoints ?? [];
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return endpoints;
    return endpoints.filter((e) =>
      e.addr.toLowerCase().includes(q) ||
      (e.org || '').toLowerCase().includes(q) ||
      (e.country || '').toLowerCase().includes(q) ||
      (e.city || '').toLowerCase().includes(q) ||
      (e.classes || []).some((c) => c.includes(q)),
    );
  }, [endpoints, search]);

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Endpoints')}</h2>
        <p className="body-text">
          {t('Cada dirección observada en la captura, correlacionada en una sola entidad: clases de red, GeoIP/ASN offline, primera/última vez vista, volumen de tráfico y la evidencia que sustenta cada dato — misma captura que PCAP Analyzer, Flows y GeoIP Map (pestaña Captura).')}
        </p>
      </div>

      <div className="card">
        <div className="field">
          <input className="input" placeholder={t('Ningún archivo abierto')} value={path} readOnly />
          <button className="btn" onClick={open} disabled={loading}>
            {loading ? <span className="spin" /> : '📂'} {t('Abrir captura')}
          </button>
          {path && <button className="btn ghost" onClick={clearPcap} disabled={loading}>🗑 {t('Cerrar')}</button>}
        </div>
      </div>

      {error && <div className="note">{error}</div>}

      {result && (
        <>
          <div className="grid cols-3" style={{ marginTop: 16 }}>
            <div className="card stat">
              <span className="label">Endpoints</span>
              <span className="value accent">{result.totalEndpoints.toLocaleString()}</span>
              <span className="sub">{endpoints.length < result.totalEndpoints ? t('mostrando {count}', { count: endpoints.length.toLocaleString(locale) }) : t('direcciones únicas')}</span>
            </div>
            <div className="card stat">
              <span className="label">GeoIP/ASN</span>
              <span className="value">{result.geoAvailable ? t('disponible') : t('no instalado')}</span>
              <span className="sub">{result.geoAvailable ? t('enriquecimiento offline activo') : t('instala GeoLite2 en Configuración')}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Paquetes analizados')}</span>
              <span className="value">{result.totalPackets.toLocaleString()}</span>
              <span className="sub">{t('{count} flujos', { count: result.totalFlows.toLocaleString(locale) })}</span>
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0 }}>{t('Direcciones ({count})', { count: filtered.length.toLocaleString(locale) })}</h3>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <input
                  className="input"
                  style={{ maxWidth: 240 }}
                  placeholder={t('Buscar IP, país, org, clase…')}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
                <CopyButton label={t('Copiar CSV')} disabled={filtered.length === 0} getText={() => endpointsToCSV(filtered)} />
                <button
                  className="btn ghost"
                  disabled={filtered.length === 0}
                  onClick={() => downloadText(`trazip-endpoints-${Date.now()}.csv`, endpointsToCSV(filtered), 'text/csv')}
                >
                  ⬇ {t('Descargar CSV')}
                </button>
              </div>
            </div>
            <p className="dim" style={{ fontSize: 11, marginTop: 6 }}>{t('Click en una fila para ver la evidencia que sustenta sus datos.')}</p>

            <div className="mtr-table-wrap" style={{ marginTop: 10 }}>
              <table className="mtr-table">
                <thead>
                  <tr>
                    <th className="l">IP</th>
                    <th className="l">{t('Clases')}</th>
                    <th className="l">{t('País / Ciudad')}</th>
                    <th className="l">ASN / Org</th>
                    <th className="l">{t('Primera vez')}</th>
                    <th className="l">{t('Última vez')}</th>
                    <th>Pkts</th>
                    <th>Bytes</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((e) => (
                    <Fragment key={e.addr}>
                      <tr style={{ cursor: 'pointer' }} onClick={() => setExpanded(expanded === e.addr ? null : e.addr)}>
                        <td className="l mono">{e.addr}</td>
                        <td className="l">{classChips(e.classes)}</td>
                        <td className="l">
                          {e.country ? <>{countryFlag(e.countryCode)} {e.city ? `${e.city}, ` : ''}{e.country}</> : <span className="dim">—</span>}
                        </td>
                        <td className="l dim">{e.asn ? `AS${e.asn}${e.org ? ' ' + e.org : ''}` : '—'}</td>
                        <td className="l dim mono" style={{ fontSize: 11.5 }}>{fmtDate(e.firstSeen, locale)}</td>
                        <td className="l dim mono" style={{ fontSize: 11.5 }}>{fmtDate(e.lastSeen, locale)}</td>
                        <td className="dim">{e.packets.toLocaleString()}</td>
                        <td className="accent-t">{humanBytes(e.bytes)}</td>
                      </tr>
                      {expanded === e.addr && (
                        <tr>
                          <td colSpan={8} style={{ background: 'var(--bg)' }}>
                            {e.evidence.length === 0 ? (
                              <span className="dim" style={{ fontSize: 11.5 }}>{t('Sin evidencia registrada.')}</span>
                            ) : (
                              <div className="hop-list">
                                {e.evidence.map((ev, i) => (
                                  <div className="hop-row" key={i} style={{ flexWrap: 'wrap', alignItems: 'flex-start' }}>
                                    <span className="tag" style={{ fontSize: 10.5 }}>{ev.type}</span>
                                    <span className="hop-host" style={{ fontSize: 12.5 }}>{ev.value}</span>
                                    <span className="dim" style={{ fontSize: 11 }}>{ev.source} · {ev.provenance} · {t('confianza {confidence}%', { confidence: ev.confidence })}</span>
                                    {ev.explain && <span className="dim" style={{ fontSize: 11, flexBasis: '100%', marginTop: 4 }}>{ev.explain}</span>}
                                  </div>
                                ))}
                              </div>
                            )}
                          </td>
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
    </div>
  );
}
