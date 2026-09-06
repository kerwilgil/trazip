import { useCallback, useEffect, useRef, useState } from 'react';
import {
  checkGeoUpdates,
  geoUpdateStatus,
  saveGeoUpdateSettings,
  getCapabilities,
  netClassSources,
  threatFeedSources,
  threatFeedUpdate,
  threatFeedRemove,
  netClassUpdate,
  netClassRemove,
  ouiInfo,
  ouiUpdate,
  ouiRemove,
  updateStatus,
  checkForUpdates,
  updateAutoCheckEnabled,
  setUpdateAutoCheck,
  downloadUpdate,
  cancelUpdateDownload,
  installUpdate,
  openExternal,
  type OUIInfo,
  type GeoUpdateStatus,
  type NetClassSource,
  type ThreatFeedSource,
  type UpdateStatusSnapshot,
  type api,
} from '../lib/api';
import { useI18n, type Locale, type Translate } from '../lib/i18n';

function formatDate(value: string | undefined, locale: Locale, t: Translate): string {
  if (!value || value.startsWith('0001-')) return t('Nunca');
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? t('Nunca') : date.toLocaleString(locale);
}

export default function Settings() {
  const { locale, t } = useI18n();
  const [status, setStatus] = useState<GeoUpdateStatus | null>(null);
  const [accountID, setAccountID] = useState('');
  const [licenseKey, setLicenseKey] = useState('');
  const [autoUpdate, setAutoUpdate] = useState(false);
  const [working, setWorking] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [caps, setCaps] = useState<api.Capabilities | null>(null);

  async function refresh() {
    const next = await geoUpdateStatus();
    setStatus(next);
    setAccountID(next.accountId || '');
    setAutoUpdate(next.autoUpdate);
  }

  useEffect(() => {
    refresh().catch((e) => setError(String(e)));
    getCapabilities().then(setCaps).catch(() => undefined);
  }, []);

  async function save() {
    setWorking(true);
    setError(null);
    setMessage(null);
    try {
      const next = await saveGeoUpdateSettings(accountID, licenseKey, autoUpdate);
      setStatus(next);
      setLicenseKey('');
      setMessage(
        caps?.platform === 'darwin'
          ? t('Configuración guardada. La License Key quedó protegida en el Llavero de macOS.')
          : caps?.platform === 'windows'
            ? t('Configuración guardada. La License Key quedó cifrada con DPAPI para este usuario de Windows.')
            : t('Configuración guardada. La License Key quedó protegida en el almacén seguro del sistema.'),
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setWorking(false);
    }
  }

  async function run(force: boolean) {
    setWorking(true);
    setError(null);
    setMessage(null);
    try {
      const result = await checkGeoUpdates(force);
      await refresh();
      setMessage(result.updated.length > 0
        ? t('Actualizados y recargados: {datasets}.', { datasets: result.updated.join(', ') })
        : t('Los datasets instalados ya están al día.'));
    } catch (e) {
      setError(String(e));
      await refresh().catch(() => undefined);
    } finally {
      setWorking(false);
    }
  }

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Settings / Datasets')}</h2>
        <p className="body-text">
          {t('Gestiona las bases offline GeoLite2 City y ASN. TRAZIP solo se conecta a MaxMind para comprobar y descargar estos archivos; no envía capturas, direcciones analizadas ni resultados de diagnóstico.')}
        </p>
      </div>

      {caps && (
        <div className="card pad-lg" style={{ marginBottom: 16 }}>
          <h3>{t('Almacenamiento')}</h3>
          <p className="dim" style={{ fontSize: 12.5, marginTop: 4 }}>
            {t('Modo:')} <strong>{caps.portable ? 'Portable' : t('Instalado')}</strong>
            {caps.portable
              ? t(' — todos los datos (config, monitores, histórico VoIP, GeoLite2) viven junto al ejecutable. No se escribe nada fuera de esta carpeta; ideal para USB.')
              : t(' — los datos se guardan por usuario de Windows y sobreviven al mover el ejecutable.')}
          </p>
          <p className="mono" style={{ fontSize: 11.5, marginTop: 8, wordBreak: 'break-all' }}>{caps.dataDir}</p>
          {!caps.portable && (
            <p className="dim" style={{ fontSize: 11, marginTop: 8 }}>
              {t('Para modo portable: creá un archivo vacío llamado portable.txt junto a TRAZIP.exe y reiniciá la app.')}
            </p>
          )}
        </div>
      )}

      <UpdateSection platform={caps?.platform} />

      <div className="grid cols-2 settings-grid">
        <div className="card pad-lg">
          <h3>{t('Credenciales de MaxMind')}</h3>
          <label className="settings-label" htmlFor="maxmind-account">Account ID</label>
          <input
            id="maxmind-account"
            className="input"
            inputMode="numeric"
            autoComplete="off"
            value={accountID}
            onChange={(e) => setAccountID(e.target.value)}
            placeholder="Ej. 1234567"
          />
          <label className="settings-label" htmlFor="maxmind-key">License Key</label>
          <input
            id="maxmind-key"
            className="input"
            type="password"
            autoComplete="new-password"
            value={licenseKey}
            onChange={(e) => setLicenseKey(e.target.value)}
            placeholder={status?.hasLicenseKey ? t('Guardada — deja vacío para conservarla') : t('Introduce una License Key')}
          />
          <label className="settings-label" style={{ marginBottom: 0 }}>{t('Actualización automática')}</label>
          <label className="settings-check" style={{ marginTop: 6 }}>
            <input type="checkbox" checked={autoUpdate} onChange={(e) => setAutoUpdate(e.target.checked)} />
            <span>
              <strong>{autoUpdate ? t('Activada') : t('Desactivada')}</strong>
              <span className="dim" style={{ display: 'block', fontSize: 11.5, marginTop: 2 }}>
                {t('Comprueba una vez cada 24 h y solo descarga si MaxMind publicó una versión nueva (lo hace martes y viernes). No hay costo por consulta: el .mmdb es un archivo local.')}
              </span>
            </span>
          </label>
          <button className="btn" onClick={save} disabled={working || !accountID.trim()}>
            {working ? <span className="spin" /> : null} {t('Guardar configuración')}
          </button>
          <p className="settings-help">
            {caps?.platform === 'darwin'
              ? t('La clave se guarda en el Llavero de macOS y queda fuera del repositorio.')
              : caps?.platform === 'windows'
                ? t('La clave se cifra mediante Windows DPAPI y queda fuera del repositorio.')
                : t('La clave se protege con el almacén seguro disponible y queda fuera del repositorio.')}
            {' '}{t('Nunca se muestra de nuevo en la interfaz.')}
          </p>
        </div>

        <div className="card pad-lg">
          <h3>{t('Estado de actualización')}</h3>
          <div className="settings-status-row"><span>{t('Carpeta de datos')}</span><strong className="mono">{status?.dataDir || caps?.dataDir || '—'}</strong></div>
          <div className="settings-status-row">
            <span>{t('Actualización automática')}</span>
            <strong className={status?.autoUpdate ? 'status-ok' : 'status-warn'}>
              {status?.autoUpdate ? t('Activada · cada 24 h') : t('Desactivada — activala en Credenciales')}
            </strong>
          </div>
          <div className="settings-status-row"><span>{t('Última comprobación')}</span><strong>{formatDate(status?.lastCheck, locale, t)}</strong></div>
          <div className="settings-status-row"><span>{t('Última actualización')}</span><strong>{formatDate(status?.lastSuccess, locale, t)}</strong></div>
          {(status?.datasets || []).map((dataset) => (
            <div className="settings-status-row" key={dataset.name}>
              <span>{dataset.name}</span>
              <strong className={dataset.present ? 'status-ok' : 'status-warn'}>
                {dataset.present
                  ? t('Instalado · {date}', { date: formatDate(new Date((dataset.buildEpoch || 0) * 1000).toISOString(), locale, t) })
                  : t('No instalado')}
              </strong>
            </div>
          ))}
          <div className="settings-actions">
            <button className="btn ghost" onClick={() => run(false)} disabled={working || !status?.hasLicenseKey}>
              {t('Buscar actualizaciones')}
            </button>
            <button className="btn" onClick={() => run(true)} disabled={working || !status?.hasLicenseKey}>
              {working ? <span className="spin" /> : null} {t('Actualizar ahora')}
            </button>
          </div>
        </div>
      </div>

      <NetClassSection />
      <ThreatFeedSection />
      <OUISection />

      {message && <div className="note settings-success">{message}</div>}
      {(error || status?.lastError) && <div className="note">{error || status?.lastError}</div>}
    </div>
  );
}

function formatBytes(n: number | undefined): string {
  if (!n || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

// UpdateSection checks only kerwilgil/trazip-releases — a public,
// binaries-only distribution repo separate from TRAZIP's private source
// repo. The check itself is a network call, so it is always visible here
// (Buscar ahora) and its automatic form is a visible, default-on toggle
// the user can turn off at any time; nothing about the capture, the
// network being analyzed, or the user is ever sent along with it.
function UpdateSection({ platform }: { platform?: string }) {
  const { t } = useI18n();
  const supported = platform === undefined || platform === 'windows';
  const [status, setStatus] = useState<UpdateStatusSnapshot>({ status: 'idle' });
  const [autoCheck, setAutoCheckState] = useState(true);
  const [checked, setChecked] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refresh = useCallback(async () => {
    const snap = await updateStatus();
    setStatus(snap);
    return snap;
  }, []);

  useEffect(() => {
    refresh().catch(() => undefined);
    updateAutoCheckEnabled().then(setAutoCheckState).catch(() => undefined);
  }, [refresh]);

  // Poll only while something is actually moving — no point hammering the
  // backend while idle/available/ready, which only change on user action.
  useEffect(() => {
    const active = status.status === 'downloading' || status.status === 'verifying' || status.status === 'checking' || status.status === 'installing';
    if (active && !pollRef.current) {
      pollRef.current = setInterval(() => { refresh().catch(() => undefined); }, 500);
    } else if (!active && pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    return () => {
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    };
  }, [status.status, refresh]);

  async function onCheckNow() {
    setBusy(true);
    setErr(null);
    setDismissed(false);
    try {
      await checkForUpdates(true);
      setChecked(true);
    } catch (e) {
      setErr(String(e).replace(/^Error:\s*/, ''));
    } finally {
      setBusy(false);
      await refresh().catch(() => undefined);
    }
  }

  async function onToggleAuto(next: boolean) {
    setAutoCheckState(next);
    try {
      await setUpdateAutoCheck(next);
    } catch (e) {
      setErr(String(e).replace(/^Error:\s*/, ''));
    }
  }

  async function onDownload() {
    setErr(null);
    try {
      await downloadUpdate();
      await refresh().catch(() => undefined);
    } catch (e) {
      setErr(String(e).replace(/^Error:\s*/, ''));
    }
  }

  async function onCancel() {
    try {
      await cancelUpdateDownload();
    } finally {
      await refresh().catch(() => undefined);
    }
  }

  async function onInstall() {
    setBusy(true);
    setErr(null);
    try {
      await installUpdate(); // TRAZIP exits on success — nothing left to update in this session
    } catch (e) {
      setErr(String(e).replace(/^Error:\s*/, ''));
      setBusy(false);
    }
  }

  const info = status.info;
  const showAvailable = status.status === 'available' && info?.available && !dismissed;
  const pct = status.total ? Math.min(100, Math.round(((status.downloaded ?? 0) / status.total) * 100)) : 0;

  if (!supported) {
    return (
      <div className="card pad-lg" style={{ marginBottom: 16 }}>
        <h3 style={{ margin: 0 }}>{t('Actualizaciones')}</h3>
        <p className="settings-help">
          {t('Actualización automática integrada disponible actualmente en Windows. En otras plataformas, descargá la versión nueva manualmente desde la página de releases.')}
        </p>
      </div>
    );
  }

  return (
    <div className="card pad-lg" style={{ marginBottom: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <h3 style={{ margin: 0 }}>{t('Actualizaciones')}</h3>
        <label className="settings-check" style={{ marginTop: 0 }}>
          <input type="checkbox" checked={autoCheck} onChange={(e) => onToggleAuto(e.target.checked)} />
          <span>{t('Buscar actualizaciones automáticamente')}</span>
        </label>
      </div>
      <p className="settings-help">
        {t('TRAZIP consulta únicamente su canal oficial de releases (kerwilgil/trazip-releases) para saber si hay una versión nueva. No envía capturas, direcciones analizadas, IPs, ni ningún otro dato — solo pregunta cuál es la última versión publicada. La descarga y la instalación siempre requieren un clic explícito.')}
      </p>

      {status.status === 'idle' && !showAvailable && (
        <div className="settings-status-row">
          <span className={checked ? 'status-ok' : 'dim'}>
            {checked ? t('✓ Estás usando la versión más reciente') : t('Sin comprobar en esta sesión')}
          </span>
          <button className="btn ghost" onClick={onCheckNow} disabled={busy}>
            {busy ? <span className="spin" /> : null} {t('Buscar ahora')}
          </button>
        </div>
      )}

      {status.status === 'checking' && (
        <div className="settings-status-row"><span className="dim"><span className="spin" /> {t('Comprobando…')}</span></div>
      )}

      {showAvailable && info && (
        <div className="card pad-lg" style={{ marginTop: 12 }}>
          <div className="settings-status-row">
            <span><strong>{t('Nueva versión disponible: {version}', { version: info.latestVersion })}</strong></span>
          </div>
          <div className="settings-actions">
            {info.notesUrl && (
              <button className="btn ghost" onClick={() => openExternal(info.notesUrl)}>{t('Ver novedades')}</button>
            )}
            <button className="btn ghost" onClick={() => setDismissed(true)}>{t('Más tarde')}</button>
            <button className="btn" onClick={onDownload}>{t('Actualizar ahora')}</button>
          </div>
        </div>
      )}

      {status.status === 'downloading' && (
        <div style={{ marginTop: 12 }}>
          <div className="settings-status-row">
            <span>{t('Descargando… {pct}%', { pct: String(pct) })}</span>
            <strong className="mono">{formatBytes(status.downloaded)} / {formatBytes(status.total)}</strong>
          </div>
          <div className="progress"><div className="progress-fill" style={{ width: `${pct}%` }} /></div>
          <div className="settings-actions"><button className="btn ghost" onClick={onCancel}>{t('Cancelar')}</button></div>
        </div>
      )}

      {status.status === 'verifying' && (
        <div className="settings-status-row"><span className="dim"><span className="spin" /> {t('Verificando integridad…')}</span></div>
      )}

      {status.status === 'ready' && (
        <div className="settings-status-row">
          <span className="status-ok">{t('Actualización lista para instalar')}</span>
          <button className="btn" onClick={onInstall} disabled={busy}>
            {busy ? <span className="spin" /> : null} {t('Instalar y reiniciar')}
          </button>
        </div>
      )}

      {status.status === 'installing' && (
        <div className="settings-status-row"><span className="dim"><span className="spin" /> {t('Instalando… TRAZIP se reiniciará en un momento.')}</span></div>
      )}

      {/* status.error is populated for any real download failure (hash
          mismatch, network, disk) even though Manager returns to
          'available' rather than 'error' — that state is retryable, but
          the reason it failed must still be visible. A deliberate
          cancellation clears status.error instead of setting it, so this
          never shows an alarming message for a plain "Cancelar" click. */}
      {(err || status.error) && (
        <div className="note">{err || status.error}</div>
      )}
    </div>
  );
}

// OUISection manages the IEEE registries that turn a MAC address into a
// manufacturer name. Three registries rather than one because IEEE assigns
// blocks at three sizes, and matching only the first 24 bits credits a device
// to the registrar that resold the block instead of to whoever built it.
function OUISection() {
  const { locale, t } = useI18n();
  const [info, setInfo] = useState<OUIInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const refresh = useCallback(() => {
    ouiInfo().then(setInfo).catch((e) => setErr(String(e)));
  }, []);
  useEffect(refresh, [refresh]);

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      refresh();
    } catch (e) {
      setErr(String(e).replace(/^Error:\s*/, ''));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card pad-lg" style={{ marginTop: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <h3 style={{ margin: 0 }}>{t('Fabricante por MAC')}</h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button className="btn" onClick={() => run(ouiUpdate)} disabled={busy}>
            {busy ? <span className="spin" /> : '⬇ '}
            {info?.present ? t('Actualizar') : t('Descargar')}
          </button>
          {info?.present && (
            <button className="btn ghost" style={{ padding: '3px 10px', fontSize: 12 }} disabled={busy} onClick={() => run(ouiRemove)}>
              {t('Quitar')}
            </button>
          )}
        </div>
      </div>
      <p className="settings-help">
        {t('Registros oficiales del IEEE que traducen una MAC al fabricante del equipo. Se descargan los tres tamaños de bloque (MA-L, MA-M y MA-S) porque una MAC de un bloque pequeño comparte sus primeros 24 bits con el registrador que se lo revendió: mirando solo esos bits, el equipo se le atribuiría a la empresa equivocada.')}
      </p>
      <div className="settings-status-row">
        <span>{t('Estado')}</span>
        <strong className={info?.present ? 'status-ok' : 'status-warn'}>
          {info?.present
            ? t('Instalado · {count} prefijos · {date}', {
                count: info.prefixCount.toLocaleString(locale),
                date: formatDate(info.fetchedAt, locale, t),
              })
            : t('No instalado — solo se reconocen fabricantes comunes')}
        </strong>
      </div>
      {info?.present && info.registries && (
        <div className="settings-status-row">
          <span>{t('Registros')}</span>
          <strong>{info.registries}</strong>
        </div>
      )}
      <p className="settings-help">
        {t('Fuente: IEEE Registration Authority. Pesa menos de 2 MB y sirve a LAN Explorer y a Salud de red.')}
      </p>
      {err && <div className="note">{err}</div>}
    </div>
  );
}

// ThreatFeedSection manages the published abuse lists the reputation scorer
// consults. Same shape as NetClassSection on purpose: both are "lists you
// download on purpose and then use offline", and making them look and behave
// alike means learning one teaches the other.
function ThreatFeedSection() {
  const { locale, t } = useI18n();
  const [sources, setSources] = useState<ThreatFeedSource[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [allBusy, setAllBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(() => {
    threatFeedSources().then(setSources).catch((e) => setErr(String(e)));
  }, []);
  useEffect(refresh, [refresh]);

  async function download(id: string) {
    setBusy(id);
    setErr(null);
    setNotice(null);
    try {
      await threatFeedUpdate(id);
      refresh();
    } catch (e) {
      setErr(String(e).replace(/^Error:\s*/, ''));
    } finally {
      setBusy(null);
    }
  }

  async function downloadAll() {
    setAllBusy(true);
    setErr(null);
    setNotice(null);
    const failed: Array<{ name: string; error: string }> = [];
    for (const s of sources) {
      setBusy(s.id);
      try {
        await threatFeedUpdate(s.id);
      } catch (e) {
        failed.push({ name: s.name, error: String(e).replace(/^Error:\s*/, '') });
      }
    }
    setBusy(null);
    setAllBusy(false);
    refresh();
    if (failed.length === 0) {
      setNotice(t('Todas las fuentes se instalaron correctamente.'));
    } else {
      const detail = failed.map((item) => `${item.name}: ${item.error}`).join(' · ');
      if (failed.length === sources.length) {
        setErr(t('No se pudo descargar ninguna fuente. Detalle: {detail}', { detail }));
      } else {
        setErr(t('No se pudieron descargar: {list}. Detalle: {detail}. Las demás sí se instalaron.', { list: failed.map((item) => item.name).join(', '), detail }));
      }
    }
  }

  async function remove(id: string) {
    setBusy(id);
    try {
      await threatFeedRemove(id);
      refresh();
    } catch (e) {
      setErr(String(e).replace(/^Error:\s*/, ''));
    } finally {
      setBusy(null);
    }
  }

  const installed = sources.filter((s) => s.present).length;
  const missing = sources.length - installed;
  // Estas listas cambian a diario, al revés que los rangos de un proveedor
  // cloud: una copia de hace semanas ya no representa lo que afirma la fuente.
  const stale = sources.filter((s) => s.present && s.ageDays >= 14);

  return (
    <div className="card pad-lg" style={{ marginTop: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <h3 style={{ margin: 0 }}>{t('Listas de amenazas')}</h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {allBusy && busy && (
            <span className="dim" style={{ fontSize: 11.5 }}>
              {t('Descargando {name}…', { name: sources.find((s) => s.id === busy)?.name ?? busy })}
            </span>
          )}
          <button className="btn" onClick={downloadAll} disabled={allBusy || busy !== null || sources.length === 0}>
            {allBusy ? <span className="spin" /> : '⬇ '}
            {sources.length > 0 && missing === 0 ? t('Actualizar todas') : t('Descargar todas')}
          </button>
        </div>
      </div>
      <p className="settings-help">
        {t('Listas públicas de rangos con abuso conocido. Con ellas, el módulo de Reputación puede decir si una IP aparece en Spamhaus DROP o es un nodo de salida de Tor, citando siempre qué afirma cada fuente. Una vez descargadas se consultan en local: comprobar una dirección nunca revela cuál estás mirando. Cada descarga es una petición externa explícita: nada se baja solo.')}
      </p>
      {sources.map((s) => (
        <div className="settings-status-row" key={s.id}>
          <span>
            {s.name}
            {s.present && s.prefixCount ? <span className="dim"> · {t('{count} rangos', { count: s.prefixCount.toLocaleString(locale) })}</span> : null}
          </span>
          <strong style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className={s.present ? (s.ageDays >= 14 ? 'status-warn' : 'status-ok') : 'status-warn'}>
              {s.present ? t('Instalada · {date}', { date: formatDate(s.fetchedAt, locale, t) }) : t('No instalada')}
            </span>
            <button className="btn ghost" style={{ padding: '3px 10px', fontSize: 12 }} disabled={busy !== null} onClick={() => download(s.id)}>
              {busy === s.id ? <span className="spin" /> : s.present ? t('Actualizar') : t('Descargar')}
            </button>
            {s.present && (
              <button className="btn ghost" style={{ padding: '3px 10px', fontSize: 12 }} disabled={busy !== null} onClick={() => remove(s.id)}>
                {t('Quitar')}
              </button>
            )}
          </strong>
        </div>
      ))}
      <p className="settings-help">
        {installed === 0
          ? t('Ninguna lista instalada — Reputación funciona igual, pero su resultado no incluye ninguna comprobación contra listas de abuso. Ambas juntas pesan unos 120 KB.')
          : t('{installed} de {total} listas instaladas.', { installed, total: sources.length })}
        {stale.length > 0 && (
          ' ' + t('{list} tiene más de dos semanas: estas listas cambian a diario, conviene actualizarla.', { list: stale.map((s) => s.name).join(', ') })
        )}
      </p>
      {err && <div className="note">{err}</div>}
      {notice && <div className="note settings-success">{notice}</div>}
    </div>
  );
}

// NetClassSection manages the provider prefix lists that power the network
// category legend. Kept apart from the MaxMind card above because these need
// no credentials and no auto-update: they are one-click, one-file downloads
// the operator triggers deliberately.
function NetClassSection() {
  const { locale, t } = useI18n();
  const [sources, setSources] = useState<NetClassSource[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [allBusy, setAllBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(() => {
    netClassSources().then(setSources).catch((e) => setErr(String(e)));
  }, []);
  useEffect(refresh, [refresh]);

  async function download(id: string) {
    setBusy(id);
    setErr(null);
    setNotice(null);
    try {
      await netClassUpdate(id);
      refresh();
    } catch (e) {
      setErr(String(e).replace(/^Error:\s*/, ''));
    } finally {
      setBusy(null);
    }
  }

  // downloadAll va una por una a propósito: el backend serializa la escritura
  // del almacén, y en secuencia se puede señalar cuál está en curso y seguir
  // con las demás cuando una falla, en vez de abortar todo por un proveedor
  // caído. El resumen final dice exactamente cuáles no entraron.
  async function downloadAll() {
    setAllBusy(true);
    setErr(null);
    setNotice(null);
    const failed: Array<{ name: string; error: string }> = [];
    for (const s of sources) {
      setBusy(s.id);
      try {
        await netClassUpdate(s.id);
      } catch (e) {
        failed.push({ name: s.name, error: String(e).replace(/^Error:\s*/, '') });
      }
    }
    setBusy(null);
    setAllBusy(false);
    refresh();
    if (failed.length === 0) {
      setNotice(t('Todas las fuentes se instalaron correctamente.'));
    } else {
      const detail = failed.map((item) => `${item.name}: ${item.error}`).join(' · ');
      if (failed.length === sources.length) {
        setErr(t('No se pudo descargar ninguna fuente. Detalle: {detail}', { detail }));
      } else {
        setErr(t('No se pudieron descargar: {list}. Detalle: {detail}. Las demás sí se instalaron.', { list: failed.map((item) => item.name).join(', '), detail }));
      }
    }
  }

  async function remove(id: string) {
    setBusy(id);
    try {
      await netClassRemove(id);
      refresh();
    } catch (e) {
      setErr(String(e).replace(/^Error:\s*/, ''));
    } finally {
      setBusy(null);
    }
  }

  const installed = sources.filter((s) => s.present).length;
  const missing = sources.length - installed;

  return (
    <div className="card pad-lg" style={{ marginTop: 16 }}>
      {/* Título a la izquierda y acción a la derecha: el mismo encabezado que
          usan PCAP Analyzer y Conexiones, en vez de un botón suelto debajo del
          párrafo. */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <h3 style={{ margin: 0 }}>{t('Categorías de red')}</h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {allBusy && busy && (
            <span className="dim" style={{ fontSize: 11.5 }}>
              {t('Descargando {name}…', { name: sources.find((s) => s.id === busy)?.name ?? busy })}
            </span>
          )}
          <button className="btn" onClick={downloadAll} disabled={allBusy || busy !== null || sources.length === 0}>
            {allBusy ? <span className="spin" /> : '⬇ '}
            {/* "Actualizar" solo cuando de verdad están todas instaladas: con la
                lista aún vacía, missing es 0 y decía "Actualizar" sin haber
                descargado nada. */}
            {sources.length > 0 && missing === 0 ? t('Actualizar todas') : t('Descargar todas')}
          </button>
        </div>
      </div>
      <p className="settings-help">
        {t('Listas de prefijos que cada proveedor publica sobre su propio espacio de direcciones. Con ellas, TRAZIP puede decir si una IP es de un cloud, una CDN o un ISP con dato autoritativo en vez de adivinarlo por el nombre de la organización. Sin ellas el módulo sigue funcionando, pero solo con esa heurística, siempre marcada como inferida. Cada descarga es una petición externa explícita: nada se baja solo.')}
      </p>
      {sources.map((s) => (
        <div className="settings-status-row" key={s.id}>
          <span>
            {s.name}
            {s.present && s.prefixCount ? <span className="dim"> · {t('{count} prefijos', { count: s.prefixCount.toLocaleString(locale) })}</span> : null}
          </span>
          <strong style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className={s.present ? 'status-ok' : 'status-warn'}>
              {s.present ? t('Instalada · {date}', { date: formatDate(s.fetchedAt, locale, t) }) : t('No instalada')}
            </span>
            <button className="btn ghost" style={{ padding: '3px 10px', fontSize: 12 }} disabled={busy !== null} onClick={() => download(s.id)}>
              {busy === s.id ? <span className="spin" /> : s.present ? t('Actualizar') : t('Descargar')}
            </button>
            {s.present && (
              <button className="btn ghost" style={{ padding: '3px 10px', fontSize: 12 }} disabled={busy !== null} onClick={() => remove(s.id)}>
                {t('Quitar')}
              </button>
            )}
          </strong>
        </div>
      ))}
      <p className="settings-help">
        {installed === 0
          ? t('Ninguna lista instalada — el tipo de red se infiere solo por el nombre de la organización. Todas juntas pesan menos de 1 MB.')
          : t('{installed} de {total} listas instaladas.', { installed, total: sources.length })}
        {' '}{t('Azure no está disponible: Microsoft rota semanalmente la URL de descarga de sus Service Tags y no publica un enlace directo estable al que apuntar.')}
      </p>
      {err && <div className="note">{err}</div>}
      {notice && <div className="note settings-success">{notice}</div>}
    </div>
  );
}
