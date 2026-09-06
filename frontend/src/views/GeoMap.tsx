import { useEffect, useState } from 'react';
import {
  geoStatus,
  quickDiagnose,
  rdapLookupIP,
  backendAvailable,
  type GeoDataset,
  type TalkerRow,
  type api,
  type rdap,
  type NetClassMatch,
} from '../lib/api';
import NetClassBadge from '../components/NetClassBadge';
import DomainRegistration from '../components/DomainRegistration';
import { countryFlag } from '../lib/flags';
import { useCaptureSession } from '../lib/session';
import { useI18n } from '../lib/i18n';

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

function Talkers({ title, rows, showGeo }: { title: string; rows: TalkerRow[]; showGeo?: boolean }) {
  if (rows.length === 0) return null;
  const max = Math.max(...rows.map((r) => r.bytes), 1);
  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h3>{title}</h3>
      {rows.map((r) => (
        <div className="talker-row" key={r.key}>
          <span className="talker-label" title={r.label}>{r.label}</span>
          {showGeo && <span className="talker-meta">{r.country || (r.asn ? 'AS' + r.asn : '')}</span>}
          <span className="talker-bar-wrap"><span className="talker-bar" style={{ width: `${(r.bytes / max) * 100}%` }} /></span>
          <span className="talker-bytes">{humanBytes(r.bytes)}</span>
        </div>
      ))}
    </div>
  );
}

// ---------------- Consulta (whois-style) ----------------
function ContactBlock({ c }: { c: rdap.Contact }) {
  return (
    <div style={{ marginTop: 6, paddingLeft: 8, borderLeft: '2px solid var(--border)' }}>
      {c.roles && c.roles.length > 0 && (
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 2 }}>
          {c.roles.map((r) => <span key={r} className="tag" style={{ fontSize: 10 }}>{r}</span>)}
        </div>
      )}
      {(c.name || c.org) && <div>{c.name}{c.name && c.org ? ' · ' : ''}{c.org}</div>}
      {c.email && <div>✉ {c.email}</div>}
      {c.phone && <div>☎ {c.phone}</div>}
      {c.address && <div className="dim" style={{ fontSize: 11 }}>{c.address}</div>}
    </div>
  );
}

function AddrRdap({ addr }: { addr: string }) {
  const { t } = useI18n();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<rdap.Result | null>(null);

  async function lookup() {
    if (!backendAvailable()) return;
    setLoading(true);
    try {
      const r = await rdapLookupIP(addr);
      setResult(r);
    } finally {
      setLoading(false);
    }
  }

  if (result) {
    return (
      <div className="dim" style={{ fontSize: 12, marginTop: 8, borderTop: '1px solid var(--border)', paddingTop: 8 }}>
        {result.err ? (
          <span className="err">{result.err}</span>
        ) : (
          <>
            <div><strong>{result.rir}</strong> · {result.name} {result.handle && `(${result.handle})`}</div>
            {(result.cidr || result.startAddress) && (
              <div>{t('Rango')}: {result.cidr || `${result.startAddress} - ${result.endAddress}`}</div>
            )}
            {result.status && result.status.length > 0 && (
              <div style={{ marginTop: 2 }}>
                {result.status.map((s) => <span key={s} className="tag" style={{ marginRight: 4, fontSize: 10 }}>{s}</span>)}
              </div>
            )}
            {(result.registered || result.lastChanged) && (
              <div>
                {result.registered && t('Creado: {date}', { date: result.registered.slice(0, 10) })}
                {result.registered && result.lastChanged ? ' · ' : ''}
                {result.lastChanged && t('Modificado: {date}', { date: result.lastChanged.slice(0, 10) })}
              </div>
            )}
            {result.nameservers && result.nameservers.length > 0 && (
              <div>{t('DNS')}: {result.nameservers.join(', ')}</div>
            )}
            {result.abuseEmail && <div>{t('Abuso')}: {result.abuseEmail}</div>}
            {result.contacts && result.contacts.length > 0 && (
              <div style={{ marginTop: 6 }}>
                <div className="dim" style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: '0.04em' }}>{t('Contactos')}</div>
                {result.contacts.map((c, i) => <ContactBlock key={i} c={c} />)}
              </div>
            )}
            <div style={{ fontSize: 10.5, marginTop: 6 }}>{result.disclosure.source} · {t('consultado')} {result.disclosure.queriedAt}</div>
          </>
        )}
      </div>
    );
  }

  return (
    <button className="btn ghost" style={{ padding: '3px 10px', fontSize: 11.5, marginTop: 6 }} onClick={lookup} disabled={loading}>
      {loading ? <span className="spin" /> : '📋'} RDAP (RIR/IANA)
    </button>
  );
}

// looksLikeDomain distingue un nombre de una IP para saber si tiene sentido
// ofrecer la consulta al registro: las direcciones no se registran en un TLD.
function looksLikeDomain(s: string): boolean {
  return s.includes('.') && /[a-z]/i.test(s) && !/^\[?[0-9a-f:]+\]?$/i.test(s);
}

function ConsultaPanel() {
  const { t } = useI18n();
  const [input, setInput] = useState('1.1.1.1');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<api.DiagnoseResult | null>(null);
  const [queried, setQueried] = useState('');
  const [error, setError] = useState<string | null>(null);

  async function query() {
    if (!backendAvailable()) return setError(t('Necesita el runtime Wails (app de escritorio).'));
    setError(null);
    setLoading(true);
    setResult(null);
    const target = input.trim();
    setQueried(target);
    try {
      const r = await quickDiagnose(target);
      setResult(r);
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
          <input
            className="input"
            placeholder={t('IP, dominio o URL (1.1.1.1, cloudflare.com, https://ejemplo.com)')}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !loading && query()}
          />
          <button className="btn" onClick={query} disabled={loading || !input.trim()}>
            {loading ? <span className="spin" /> : '🔎'} {t('Consultar')}
          </button>
        </div>
        <p className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          {t('Resuelve el objetivo, clasifica cada dirección (RFC sin conexión) y la enriquece con GeoIP/ASN. No realiza llamadas externas hasta que solicitas RDAP para una dirección. La ubicación siempre es aproximada, nunca exacta.')}
        </p>
      </div>

      {error && <div className="note">{error}</div>}
      {result?.notes && result.notes.length > 0 && <div className="note">{result.notes.join(' · ')}</div>}

      {result && result.addrs.length > 0 && (
        <div className="grid cols-2" style={{ marginTop: 16 }}>
          {result.addrs.map((a, i) => (
            <div className="card" key={i}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <div className="mono" style={{ fontWeight: 700, fontSize: 15 }}>{a.addr}</div>
                {a.reachable !== undefined && (
                  <span className={'tag ' + (a.reachable ? 'private' : 'bogon')}>
                    {a.reachable ? t('responde') : t('sin respuesta')}
                  </span>
                )}
              </div>

              <ul className="list-reset" style={{ marginTop: 10 }}>
                <li className="kv"><span className="k">{t('Familia')}</span><span className="v">{a.family}</span></li>
                <li className="kv"><span className="k">{t('Alcance')}</span><span className="v">{a.isPublic ? t('pública') : t('no pública')}</span></li>
                {a.country && (
                  <li className="kv">
                    <span className="k">{t('País')}</span>
                    <span className="v">{countryFlag(a.countryCode)} {a.country}</span>
                  </li>
                )}
                {a.city && <li className="kv"><span className="k">{t('Ciudad')}</span><span className="v">{a.city}</span></li>}
                {a.asn ? <li className="kv"><span className="k">ASN</span><span className="v">AS{a.asn}</span></li> : null}
                {a.org && <li className="kv"><span className="k">{t('Organización')}</span><span className="v" style={{ textAlign: 'right' }}>{a.org}</span></li>}
                {a.netClass && (
                  <li className="kv">
                    <span className="k">{t('Tipo de red')}</span>
                    <span className="v" style={{ fontFamily: 'inherit', fontWeight: 400, textAlign: 'right' }}>
                      <NetClassBadge m={a.netClass as unknown as NetClassMatch} />
                    </span>
                  </li>
                )}
                {!!a.lat && !!a.lon && (
                  <li className="kv">
                    <span className="k">{t('Coordenadas (aprox.)')}</span>
                    <span className="v">{a.lat.toFixed(2)}, {a.lon.toFixed(2)}</span>
                  </li>
                )}
              </ul>

              {a.classes && a.classes.length > 0 && (
                <div style={{ marginTop: 10 }}>
                  {a.classes.map((c) => <span key={c} className="tag" style={{ marginRight: 4 }}>{c}</span>)}
                </div>
              )}

              {a.isPublic && <AddrRdap addr={a.addr} />}
            </div>
          ))}
        </div>
      )}

      {result && looksLikeDomain(queried) && (
        <DomainRegistration
          key={queried}
          name={queried}
          autoOpen={result.addrs.length === 0}
        />
      )}
    </>
  );
}

// ---------------- Captura (Raw Traffic GeoIP) ----------------
function CapturaPanel() {
  const { t } = useI18n();
  const { pcapPath: path, pcapResult: result, pcapLoading: loading, pcapError, openPcap, clearPcap } = useCaptureSession();
  const [dialogError, setDialogError] = useState<string | null>(null);
  const error = dialogError ?? pcapError;

  async function open() {
    if (!backendAvailable()) {
      setDialogError(t('Necesita el runtime Wails (app de escritorio).'));
      return;
    }
    setDialogError(null);
    await openPcap();
  }

  return (
    <>
      <div className="card">
        <div className="field">
          <input className="input" placeholder={t('Abre una captura para ver el tráfico geolocalizado')} value={path} readOnly />
          <button className="btn" onClick={open} disabled={loading}>
            {loading ? <span className="spin" /> : '📂'} {t('Abrir captura')}
          </button>
          {path && <button className="btn ghost" onClick={clearPcap} disabled={loading}>🗑 {t('Cerrar')}</button>}
        </div>
        {path && (
          <p className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>
            {t('Es la misma captura que usa PCAP Analyzer / Flows. Se comparte automáticamente; no necesitas abrirla dos veces.')}
          </p>
        )}
      </div>

      {error && <div className="note">{error}</div>}

      {result && (
        <>
          <Talkers title={t('Hosts principales (por bytes)')} rows={result.topHosts} showGeo />
          <Talkers title={t('Países principales')} rows={result.topCountries} />
          <Talkers title={t('ASN / organizaciones principales')} rows={result.topASN} />
          {result.topHosts.length === 0 && (
            <div className="empty"><div className="big">🌐</div>{t('No hay endpoints con tráfico que se pueda agregar en esta captura.')}</div>
          )}
        </>
      )}
    </>
  );
}

// ---------------- Tabbed view ----------------
type Tab = 'consulta' | 'captura';

export default function GeoMap() {
  const { t } = useI18n();
  const [tab, setTab] = useState<Tab>('consulta');
  const [panelEpochs, setPanelEpochs] = useState<Record<Tab, number>>({ consulta: 0, captura: 0 });
  const [datasets, setDatasets] = useState<GeoDataset[]>([]);
  const { clearPcap } = useCaptureSession();

  useEffect(() => {
    geoStatus().then(setDatasets).catch(() => setDatasets([]));
  }, []);

  const geoLoaded = datasets.some((d) => d.present);

  function clearActiveTab() {
    if (tab === 'captura') clearPcap();
    setPanelEpochs((prev) => ({ ...prev, [tab]: prev[tab] + 1 }));
  }

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('GeoIP Map')}</h2>
        <p className="body-text">
          {t('Consulta directa estilo whois (IP/dominio/URL) o Raw Traffic GeoIP sobre una captura: en ambos casos enriquece con país, ciudad aproximada, ASN y organización usando bases offline, y RDAP bajo demanda.')}
        </p>
      </div>

      <div style={{ marginBottom: 12, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        {datasets.map((d) => (
          <span key={d.name} className={'pill ' + (d.present ? 'ok' : 'warn')}>
            <span className="dot" />
            {d.name}: {d.present ? t('cargado') : t('ausente')}
          </span>
        ))}
      </div>

      {!geoLoaded && (
        <div className="note">
          {t('Los datasets GeoLite2 no están instalados. Abre Settings / Datasets para descargarlos y activar su actualización automática. Sin ellos verás clasificación y RDAP, pero sin país/ciudad/ASN.')}
        </div>
      )}

      <div className="tabs">
        <button className={'tab' + (tab === 'consulta' ? ' active' : '')} onClick={() => setTab('consulta')}>{t('Consulta (whois)')}</button>
        <button className={'tab' + (tab === 'captura' ? ' active' : '')} onClick={() => setTab('captura')}>{t('Captura (Raw Traffic)')}</button>
        <button className="btn ghost tab-clear" onClick={clearActiveTab}>🗑 {t('Limpiar pestaña')}</button>
      </div>

      <div style={{ display: tab === 'consulta' ? 'block' : 'none' }}><ConsultaPanel key={panelEpochs.consulta} /></div>
      <div style={{ display: tab === 'captura' ? 'block' : 'none' }}><CapturaPanel key={panelEpochs.captura} /></div>
    </div>
  );
}
