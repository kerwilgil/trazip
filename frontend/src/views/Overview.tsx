import { useEffect, useState } from 'react';
import banner from '../assets/images/trazip-logo.png';
import { backendAvailable, monitorListTargets, monitorHistory, geoUpdateStatus, exportSessionReport, type api, type GeoUpdateStatus } from '../lib/api';
import { buildSessionReport, hasSessionData } from '../lib/sessionReport';
import { useCaptureSession } from '../lib/session';
import type { ViewId } from '../lib/nav';
import { Icon } from '../components/icons';
import { useI18n } from '../lib/i18n';

interface Props {
  caps: api.Capabilities | null;
  active: boolean;
}

interface Alert {
  module: string;
  view: ViewId | null;
  message: string;
}

const STALE_DAYS = 35; // GeoLite2 republishes roughly every 2 weeks — 35 days gives margin before nagging.

function daysSince(epochSec: number): number {
  return Math.floor((Date.now() / 1000 - epochSec) / 86400);
}

export default function Overview({ caps, active }: Props) {
  const { locale, t } = useI18n();
  const {
    pcapPath, pcapResult, voipPath, voipResult, voipRunning,
    captureRunning, capturePackets, captureTotal,
    lanScanRange, lanScanHosts, lanScanRunning, lanScanSummary,
    pcapError, voipError, captureError, lanScanError,
    navigateTo,
  } = useCaptureSession();

  const [targets, setTargets] = useState<api.MonitorTargetInfo[]>([]);
  const [degradations, setDegradations] = useState<{ label: string; time: string; kind: string; detail: string }[]>([]);
  const [geo, setGeo] = useState<GeoUpdateStatus | null>(null);

  useEffect(() => {
    if (!active || !backendAvailable()) return;
    monitorListTargets().then(async (ts) => {
      setTargets(ts);
      const running = ts.filter((t) => t.running);
      const perTarget = await Promise.all(
        running.map((t) =>
          monitorHistory(t.target.id, 2 * 60 * 60 * 1000)
            .then((h) => h.events.map((e) => ({ label: t.target.label, time: e.time, kind: e.kind, detail: e.detail })))
            .catch(() => []),
        ),
      );
      setDegradations(perTarget.flat().sort((a, b) => Date.parse(b.time) - Date.parse(a.time)).slice(0, 8));
    }).catch(() => undefined);
    geoUpdateStatus().then(setGeo).catch(() => undefined);
  }, [active]);

  const monitorsRunning = targets.filter((t) => t.running).length;

  // ---- Informe de sesión: exporta en un documento lo cargado ahora mismo ----
  const sessionInput = { pcapPath, pcapResult, voipPath, voipResult, lanScanRange, lanScanHosts, lanScanSummary };
  const [exportStatus, setExportStatus] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  async function doExportSession(format: string) {
    setExporting(true);
    setExportStatus(null);
    try {
      const path = await exportSessionReport(buildSessionReport(sessionInput), format);
      setExportStatus(path ? t('Guardado en {path}', { path }) : t('Export cancelado.'));
    } catch (e) {
      setExportStatus(String(e));
    } finally {
      setExporting(false);
    }
  }

  // "Alertas" = things that need the operator's attention: real module
  // errors, degradations detected by any running monitor, missing/stale
  // GeoIP datasets, and missing Npcap — never simulated, only what the
  // backend actually reports.
  const alerts: Alert[] = [];
  if (pcapError) alerts.push({ module: 'PCAP Analyzer / Flows', view: 'pcap', message: pcapError });
  if (voipError) alerts.push({ module: 'VoIP Calls', view: 'voip', message: voipError });
  if (captureError) alerts.push({ module: 'Live Capture', view: 'capture', message: captureError });
  if (lanScanError) alerts.push({ module: 'LAN Explorer', view: 'lan', message: lanScanError });
  if (caps && !caps.liveCapture) {
    alerts.push({ module: t('Captura en vivo'), view: 'capture', message: t('Npcap no está instalado. Instálalo desde npcap.com para habilitar la captura en vivo.') });
  }

  if (geo) {
    if (geo.lastError) {
      alerts.push({ module: 'GeoIP/ASN', view: 'settings', message: t('Falló la última sincronización: {error}', { error: geo.lastError }) });
    }
    for (const d of geo.datasets) {
      if (!d.present) {
        alerts.push({ module: 'GeoIP/ASN', view: 'settings', message: t('{dataset} no está instalado.', { dataset: d.name }) });
      } else if (d.buildEpoch) {
        const age = daysSince(d.buildEpoch);
        if (age > STALE_DAYS) alerts.push({ module: 'GeoIP/ASN', view: 'settings', message: t('{dataset} lleva {days} días desactualizado. Actualízalo en Configuración.', { dataset: d.name, days: age }) });
      }
    }
  }

  for (const d of degradations) {
    alerts.push({
      module: t('Monitor: {label}', { label: d.label }),
      view: 'monitor',
      message: `${d.kind === 'recovery' ? t('Recuperado') : t('Degradación')} · ${d.detail}`,
    });
  }

  // Freshest present dataset, for the small positive status line below.
  const freshestDays = geo?.datasets.filter((d) => d.present && d.buildEpoch).map((d) => daysSince(d.buildEpoch!));
  const geoFreshDays = freshestDays && freshestDays.length > 0 ? Math.min(...freshestDays) : null;

  const hasActivity = Boolean(
    pcapPath || voipPath || voipRunning || captureRunning || capturePackets.length > 0 ||
    monitorsRunning > 0 || lanScanRunning || lanScanHosts.length > 0,
  );

  return (
    <div className="content-inner">
      <div className="hero">
        <img className="hero-logo" src={banner} alt="" />
        <div className="kicker">{t('Motor de observaciones de red · local-first')}</div>
        <h2>{t('Diagnóstico, tráfico e inteligencia de red en una sola sesión')}</h2>
        <p>
          {t('TRAZIP correlaciona paquetes, flujos, hosts, dominios, rutas y evidencia externa como entidades únicas. Todo el procesamiento es local y con privacidad por defecto: sin telemetría, sin analytics. La única llamada de red automática es la comprobación opcional de actualizaciones, desactivable en Settings.')}
        </p>
      </div>

      {hasSessionData(sessionInput) && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
            <div>
              <h3 style={{ margin: 0 }}>{t('Informe de sesión')}</h3>
              <p className="dim" style={{ fontSize: 11.5, marginTop: 4 }}>
                {t('Exporta en un solo documento lo que está cargado ahora mismo (PCAP, VoIP, escaneo LAN) — listo para entregar a un colega o cliente.')}
              </p>
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {['html', 'pdf', 'csv', 'json'].map((f) => (
                <button key={f} className="btn ghost" disabled={exporting} onClick={() => doExportSession(f)}>
                  {exporting ? <span className="spin" /> : '⬇'} {f.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
          {exportStatus && <p className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>{exportStatus}</p>}
        </div>
      )}

      <div className="grid cols-3">
        <div className="card stat">
          <span className="label"><Icon name="capture" size={18} /> {t('Captura en vivo')}</span>
          <span className="value" style={{ fontSize: 19, color: caps?.liveCapture ? 'var(--accent)' : 'var(--danger)' }}>
            {caps?.liveCapture ? t('Disponible') : t('No disponible')}
          </span>
          <span className="sub">{caps?.liveCapture ? t('Npcap detectado') : t('instala Npcap para habilitarla')}</span>
        </div>
        <div className="card stat">
          <span className="label"><Icon name="pcap" size={18} /> {t('Lectura PCAP')}</span>
          <span className="value accent" style={{ fontSize: 19 }}>{t('Sin driver')}</span>
          <span className="sub">{t('no requiere Npcap para analizar archivos')}</span>
        </div>
        <div className="card stat">
          <span className="label"><Icon name="geomap" size={18} /> GeoLite2</span>
          {geoFreshDays !== null ? (
            <>
              <span className="value accent" style={{ fontSize: 19 }}>{t(geoFreshDays === 1 ? 'hace {days} día' : 'hace {days} días', { days: geoFreshDays })}</span>
              <span className="sub">{t('actualizado')}</span>
            </>
          ) : (
            <>
              <span className="value" style={{ fontSize: 19, color: 'var(--warn)' }}>{t('Sin datos')}</span>
              <span className="sub">{t('instálalo en Configuración')}</span>
            </>
          )}
        </div>
      </div>

      <div className="section-title" style={{ marginTop: 24 }}>{t('Actividad en curso')}</div>
      {!hasActivity ? (
        <div className="card">
          <p className="dim" style={{ fontSize: 12.5, margin: 0 }}>{t('No hay actividad en curso. Las tarjetas aparecen aquí mientras mantienes una captura, un monitor, un escaneo o un análisis en ejecución.')}</p>
        </div>
      ) : (
        <div className="grid cols-3">
          {pcapPath && (
            <div className="card" style={{ cursor: 'pointer' }} onClick={() => navigateTo('pcap')}>
              <span className="label dim">{t('Captura PCAP')}</span>
              <div className="mono" style={{ fontSize: 12.5, marginTop: 6, wordBreak: 'break-all' }}>{pcapPath.split(/[\\/]/).pop()}</div>
              <p className="dim" style={{ fontSize: 11.5, marginTop: 4 }}>
                {pcapResult ? t('{packets} paquetes · {flows} flujos', { packets: pcapResult.totalPackets.toLocaleString(locale), flows: pcapResult.totalFlows.toLocaleString(locale) }) : t('analizando…')}
              </p>
            </div>
          )}

          {(voipPath || voipRunning) && (
            <div className="card" style={{ cursor: 'pointer' }} onClick={() => navigateTo('voip')}>
              <span className="label dim">VoIP Calls</span>
              <div className="mono" style={{ fontSize: 12.5, marginTop: 6, wordBreak: 'break-all' }}>{voipPath.split(/[\\/]/).pop()}</div>
              <p className="dim" style={{ fontSize: 11.5, marginTop: 4 }}>
                {voipRunning ? t('correlacionando…') : voipResult ? t('{calls} llamada(s) · {established} establecidas', { calls: voipResult.totalCalls, established: voipResult.established }) : ''}
              </p>
            </div>
          )}

          {(captureRunning || capturePackets.length > 0) && (
            <div className="card" style={{ cursor: 'pointer' }} onClick={() => navigateTo('capture')}>
              <span className="label dim">Live Capture</span>
              <span className={'pill ' + (captureRunning ? 'ok' : 'warn')} style={{ marginTop: 6 }}>
                <span className="dot" /> {captureRunning ? t('capturando') : t('detenida')}
              </span>
              <p className="dim" style={{ fontSize: 11.5, marginTop: 4 }}>{t('{packets} paquetes', { packets: captureTotal.toLocaleString(locale) })}</p>
            </div>
          )}

          {monitorsRunning > 0 && (
            <div className="card" style={{ cursor: 'pointer' }} onClick={() => navigateTo('monitor')}>
              <span className="label dim">{t('Monitores')}</span>
              <span className="value accent" style={{ fontSize: 20 }}>{monitorsRunning} / {targets.length}</span>
              <p className="dim" style={{ fontSize: 11.5, marginTop: 4 }}>{t('corriendo')}</p>
            </div>
          )}

          {(lanScanRunning || lanScanHosts.length > 0) && (
            <div className="card" style={{ cursor: 'pointer' }} onClick={() => navigateTo('lan')}>
              <span className="label dim">{t('Dispositivos LAN')}</span>
              <span className="value accent" style={{ fontSize: 20 }}>{lanScanHosts.length}</span>
              <p className="dim" style={{ fontSize: 11.5, marginTop: 4 }}>
                {lanScanRunning ? t('escaneando…') : lanScanSummary ? t('encontrados de {total} probadas', { total: lanScanSummary.totalIPs }) : t('encontrados')}
              </p>
            </div>
          )}
        </div>
      )}

      <div className="card pad-lg" style={{ marginTop: 16 }}>
        <h3>{t('Alertas')}</h3>
        {alerts.length === 0 ? (
          <p className="dim" style={{ fontSize: 12.5 }}>{t('Sin alertas — módulos activos sin errores, datasets al día, Npcap disponible.')}</p>
        ) : (
          <div className="hop-list">
            {alerts.map((a, i) => (
              <div className="hop-row" key={i} style={a.view ? { cursor: 'pointer' } : undefined} onClick={() => a.view && navigateTo(a.view)}>
                <span className="pill danger"><span className="dot" /> {a.module}</span>
                <span className="dim" style={{ fontSize: 12 }}>{a.message}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
