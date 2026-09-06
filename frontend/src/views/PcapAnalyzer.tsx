import { useState } from 'react';
import { backendAvailable, investigationAddPcap, type GPSFix, type PcapFinding } from '../lib/api';
import { useCaptureSession } from '../lib/session';
import AddToInvestigation from '../components/AddToInvestigation';
import { useI18n } from '../lib/i18n';

const MAX_ROWS = 1500;

type Tab = 'summary' | 'packets' | 'flows' | 'detections' | 'health';

// Same 5-level → 3-badge-class mapping VoipDiagnosis.tsx uses for
// model.Assessment, so a PcapFinding (which reuses the same model.Level
// vocabulary) reads identically wherever it's shown.
const LEVEL_CLASS: Record<string, string> = {
  informativo: 'ok',
  bajo: 'warn',
  medio: 'warn',
  alto: 'danger',
  critico: 'danger',
};

// Phase C's own three-state vocabulary for the capture's overall status —
// coarser than the 5-level model.Level, deliberately: a reader scanning
// captures doesn't need "bajo" vs "medio", just "should I look at this".
// "bajo" is still a REAL finding, never lumped in with "informativo" (Phase
// C.1 fix #3) — only the true absence of any above-Info finding earns "SIN
// HALLAZGOS IMPORTANTES".
function estadoLabel(level: string, t: (s: string) => string): string {
  if (level === 'alto' || level === 'critico') return t('PROBLEMA');
  if (level === 'medio' || level === 'bajo') return t('ATENCIÓN');
  return t('SIN HALLAZGOS IMPORTANTES');
}

// PcapFinding.sourceArea is domain-neutral (which engine produced it, not
// which tab shows it) — the frontend is what decides netdiag findings
// surface under "health", scan_detection under "detections", and so on
// (Phase E.0: "QUITAR UI CONCERN DEL CORE"). This mapping is that decision.
const SOURCE_AREA_TAB: Record<string, Tab> = {
  netdiag: 'health',
  scan_detection: 'detections',
  flows: 'flows',
  packets: 'packets',
};

const SOURCE_AREA_LABEL: Record<string, string> = {
  netdiag: 'Ver salud de red →',
  scan_detection: 'Ver detecciones →',
  flows: 'Ver flujos →',
  packets: 'Ver paquetes →',
};

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

function protoTag(proto: string) {
  const map: Record<string, string> = { TCP: 'public', UDP: 'private', DNS: 'reserved', ARP: 'documentation', TLS: 'public', HTTP: 'public', WS: 'private', ICMP: 'bogon', ICMPv6: 'bogon' };
  return <span className={'tag ' + (map[proto] || '')}>{proto}</span>;
}

function timeOnly(t: string): string {
  const i = t.indexOf('T');
  if (i < 0) return t;
  return t.slice(i + 1, i + 13); // HH:MM:SS.mmm
}

// Cinco decimales: algo más de un metro. Más cifras darían una falsa impresión
// de precisión sobre un GPS de consumo en movimiento.
function fixText(f?: GPSFix): string {
  if (!f || f.latitude === undefined || f.longitude === undefined) return '';
  const alt = f.altitudeM !== undefined ? ` · ${Math.round(f.altitudeM)} m` : '';
  return `${f.latitude.toFixed(5)}, ${f.longitude.toFixed(5)}${alt}`;
}

// Una captura estática (antena fija) empieza y acaba en el mismo sitio; repetir
// la coordenada dos veces solo hace ruido.
function sameFix(a?: GPSFix, b?: GPSFix): boolean {
  return fixText(a) === fixText(b);
}

export default function PcapAnalyzer({ initialTab = 'packets' }: { initialTab?: Tab }) {
  const { locale, t } = useI18n();
  const [tab, setTab] = useState<Tab>(initialTab);
  const { pcapPath: path, pcapResult: result, pcapLoading: loading, pcapError, openPcap, clearPcap, loadVoip, navigateTo } = useCaptureSession();
  const [dialogError, setDialogError] = useState<string | null>(null);
  const error = dialogError ?? pcapError;

  // Port 5060/5061 (UDP/TCP) is the SIP well-known port — the same signal
  // VoIP tools use for auto-detection. Cheap client-side check over flows
  // already loaded; no new backend analysis triggered just to show the banner.
  const hasSipTraffic = (result?.flows || []).some((f) => f.aPort === 5060 || f.bPort === 5060 || f.aPort === 5061 || f.bPort === 5061);
  const scanFindings = result?.scanDetection?.findings || [];
  // Los arreglos del backend ya vienen como [] y nunca null (ver netdiag
  // Result), pero el || [] cubre capturas analizadas por una versión anterior.
  const healthFindings = result?.netDiag?.findings || [];
  const neighbors = result?.netDiag?.neighbors || [];

  function viewAsVoip() {
    navigateTo('voip');
    loadVoip(path);
  }

  async function open() {
    if (!backendAvailable()) {
      setDialogError(t('Necesita el runtime Wails (app de escritorio). En el navegador no hay backend ni diálogo de archivos.'));
      return;
    }
    setDialogError(null);
    await openPcap();
  }

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Analizador PCAP')}</h2>
        <p className="body-text">
          {t('Lee capturas .pcap y .pcapng sin drivers ni privilegios. Decodifica por capas, resume cada paquete y agrega el tráfico en flujos bidireccionales por 5-tupla. Los archivos grandes se procesan por streaming.')}
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
        {path && (
          <p className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>
            {t('Esta captura queda cargada mientras la app esté abierta — GeoIP Map (pestaña "Captura") la reusa sin pedirla de nuevo.')}
          </p>
        )}
      </div>

      {error && <div className="note">{error}</div>}

      {result && hasSipTraffic && (
        <div className="card" style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <span>{t('📞 Se detectó tráfico en el puerto SIP (5060/5061) en esta captura.')}</span>
          <button className="btn ghost" onClick={viewAsVoip}>{t('Ver como llamadas VoIP →')}</button>
        </div>
      )}

      {result && scanFindings.length > 0 && (
        <div className="note" style={{ marginTop: 16, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
          <span>{t('Se detectaron {count} patrón(es) de reconocimiento TCP con evidencia en la captura.', { count: scanFindings.length })}</span>
          <button className="btn ghost" onClick={() => setTab('detections')}>{t('Revisar detecciones →')}</button>
        </div>
      )}

      {/* Una captura de un medio que no sabemos leer produce una lista de fallos
          por paquete y ninguna explicación. El número de link type es lo que el
          operador puede buscar; el nombre que da la librería es "desconocido". */}
      {result && result.info.packets > 0 && result.info.undecodable === result.info.packets && (
        <div className="note" style={{ marginTop: 16 }}>
          {t('Ningún paquete pudo decodificarse: la captura es de un medio (link type {n}) que TRAZIP no sabe leer. El archivo se abrió bien y los {count} registros están ahí, pero sin decodificador no hay direcciones, flujos ni protocolos que mostrar.', {
            n: String(result.info.linkTypeNum),
            count: result.info.packets.toLocaleString(locale),
          })}
        </div>
      )}

      {/* Una captura de reconocimiento WiFi con GPS: decir dónde se tomó es
          media respuesta, y las coordenadas las grabó quien capturó, en su
          propio equipo — no se consulta ningún servicio para interpretarlas. */}
      {result && result.info.gpsFixes > 0 && result.info.firstFix?.latitude !== undefined && (
        <div className="note" style={{ marginTop: 16 }}>
          {t('Captura con posición: {count} tramas llegaron con coordenadas GPS. Inicio {from}{to}.', {
            count: result.info.gpsFixes.toLocaleString(locale),
            from: fixText(result.info.firstFix),
            to: sameFix(result.info.firstFix, result.info.lastFix) ? '' : t(', fin {p}', { p: fixText(result.info.lastFix) }),
          })}
        </div>
      )}

      {/* Sin decirlo, el operador creería estar viendo el tráfico entre el router
          y el colector, cuando lo que se analiza es lo que iba dentro. */}
      {result && result.info.tzspDecapsulated > 0 && (
        <div className="note" style={{ marginTop: 16 }}>
          {t('Se abrieron {count} sobres TZSP: la captura se tomó en la máquina que recibe el stream, así que lo analizado es el tráfico transportado, no la conversación con el colector.', {
            count: result.info.tzspDecapsulated.toLocaleString(locale),
          })}
        </div>
      )}

      {result && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat">
              <span className="label">{t('Formato')}</span>
              <span className="value accent" style={{ fontSize: 20 }}>{result.info.format.toUpperCase()}</span>
              <span className="sub">{result.info.linkType}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Paquetes')}</span>
              <span className="value">{result.totalPackets.toLocaleString()}</span>
              <span className="sub">{humanBytes(result.info.bytes)}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Flujos')}</span>
              <span className="value">{result.totalFlows.toLocaleString()}</span>
              <span className="sub">{t('conversaciones')}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Duración')}</span>
              <span className="value">{result.info.durationSec.toFixed(1)}s</span>
              <span className="sub">{result.info.truncated ? t('truncado') : t('completo')}</span>
            </div>
          </div>

          <div className="tabs" style={{ marginTop: 16 }}>
            <button className={'tab' + (tab === 'summary' ? ' active' : '')} onClick={() => setTab('summary')}>
              {t('Resumen')}
            </button>
            <button className={'tab' + (tab === 'packets' ? ' active' : '')} onClick={() => setTab('packets')}>
              {t('Paquetes ({count})', { count: result.shownPackets.toLocaleString(locale) })}
            </button>
            <button className={'tab' + (tab === 'flows' ? ' active' : '')} onClick={() => setTab('flows')}>
              {t('Flujos ({count})', { count: result.flows.length.toLocaleString(locale) })}
            </button>
            <button className={'tab' + (tab === 'detections' ? ' active' : '')} onClick={() => setTab('detections')}>
              {t('Detecciones ({count})', { count: scanFindings.length.toLocaleString(locale) })}
            </button>
            <button className={'tab' + (tab === 'health' ? ' active' : '')} onClick={() => setTab('health')}>
              {t('Salud de red ({count})', { count: healthFindings.length.toLocaleString(locale) })}
            </button>
          </div>

          {tab === 'summary' ? (
            <div>
              <div className="card">
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                  <span className={'pill ' + (LEVEL_CLASS[result.summary.level] || '')}>
                    <span className="dot" /> {estadoLabel(result.summary.level, t)}
                  </span>
                  <strong style={{ fontSize: 13.5 }}>{t(result.summary.summary)}</strong>
                  <span className="dim" style={{ fontSize: 11, marginLeft: 'auto' }}>
                    {t('Confianza')}: {result.summary.confidence}%
                  </span>
                </div>
              </div>

              <div style={{ marginTop: 8 }}>
                <AddToInvestigation onAdd={(id) => investigationAddPcap(id, result.summary, path, '', '')} />
              </div>

              {result.summary.findings.length > 0 && (
                <div style={{ marginTop: 16 }}>
                  <span className="label dim" style={{ fontSize: 11 }}>{t('Hallazgos principales')}</span>
                  <div className="grid" style={{ marginTop: 8 }}>
                    {result.summary.findings.map((f: PcapFinding) => (
                      <div
                        className="card"
                        key={f.id}
                        style={{ borderColor: f.level === 'alto' || f.level === 'critico' ? 'var(--danger)' : f.level === 'medio' ? 'var(--warn)' : undefined }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                          <span className={'pill ' + (LEVEL_CLASS[f.level] || '')}>
                            <span className="dot" /> {t(f.level)}
                          </span>
                          <strong style={{ fontSize: 12.5 }}>{t(f.summary)}</strong>
                          <span className="dim" style={{ marginLeft: 'auto', fontSize: 11 }}>
                            {t('confianza')} {f.confidence}%
                          </span>
                        </div>
                        {f.evidence && f.evidence.length > 0 && (
                          <p className="dim" style={{ fontSize: 11.5, marginTop: 6 }}>
                            {t(f.evidence[0].explain || f.evidence[0].value)}
                          </p>
                        )}
                        {f.limitations?.map((l, i) => (
                          <p key={i} className="dim" style={{ fontSize: 11, marginTop: 4 }}>⚠ {t(l)}</p>
                        ))}
                        <button className="btn ghost" style={{ marginTop: 8, fontSize: 11.5 }} onClick={() => setTab(SOURCE_AREA_TAB[f.sourceArea] || 'packets')}>
                          {t(SOURCE_AREA_LABEL[f.sourceArea] || 'Ver evidencia →')}
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="card" style={{ marginTop: 16 }}>
                <span className="label dim" style={{ fontSize: 11 }}>{t('Contexto')}</span>
                <div className="grid cols-3" style={{ marginTop: 10 }}>
                  <div className="stat">
                    <span className="label">{t('Paquetes')}</span>
                    <span className="value">{result.summary.stats.packets.toLocaleString(locale)}</span>
                  </div>
                  <div className="stat">
                    <span className="label">{t('Flujos')}</span>
                    <span className="value">{result.summary.stats.flows.toLocaleString(locale)}</span>
                  </div>
                  <div className="stat">
                    <span className="label">{t('Endpoints')}</span>
                    <span className="value">{result.summary.stats.endpoints.toLocaleString(locale)}</span>
                    <span className="sub">
                      {result.summary.stats.otherEndpoints > 0
                        ? t('{pub} públicos · {priv} privados · {other} otros', {
                            pub: String(result.summary.stats.publicEndpoints),
                            priv: String(result.summary.stats.privateEndpoints),
                            other: String(result.summary.stats.otherEndpoints),
                          })
                        : t('{pub} públicos · {priv} privados', { pub: String(result.summary.stats.publicEndpoints), priv: String(result.summary.stats.privateEndpoints) })}
                    </span>
                  </div>
                </div>
                <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {result.summary.stats.sipDetected && <span className="dim" style={{ fontSize: 11.5 }}>📞 {t('Tráfico SIP detectado')}</span>}
                  {result.summary.stats.topTalker && (
                    <span className="dim" style={{ fontSize: 11.5 }}>{t('Top talker')}: <span className="mono">{result.summary.stats.topTalker}</span></span>
                  )}
                  {result.summary.stats.topASN && (
                    <span className="dim" style={{ fontSize: 11.5 }}>{t('Top ASN')}: <span className="mono">{result.summary.stats.topASN}</span></span>
                  )}
                  {result.summary.stats.tcpResets > 0 && (
                    <span className="dim" style={{ fontSize: 11.5 }}>{t('Resets TCP')}: {result.summary.stats.tcpResets.toLocaleString(locale)}</span>
                  )}
                  {!result.summary.stats.geoAvailable && (
                    <span className="dim" style={{ fontSize: 11.5 }}>{t('GeoIP/ASN no disponible — instálalo en Configuración para más contexto.')}</span>
                  )}
                </div>
              </div>
            </div>
          ) : tab === 'packets' ? (
            <div className="card">
              <div className="mtr-table-wrap pkt-scroll">
                <table className="mtr-table pkt-table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th className="l">{t('Tiempo')}</th>
                      <th className="l">{t('Origen')}</th>
                      <th className="l">{t('Destino')}</th>
                      <th className="l">Proto</th>
                      <th>Long</th>
                      <th className="l">Info</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.packets.slice(0, MAX_ROWS).map((p) => (
                      <tr key={p.index}>
                        <td className="ttl">{p.index}</td>
                        <td className="l dim mono">{timeOnly(p.time)}</td>
                        {/* En una captura 802.11 la mayoría de tramas no tienen
                            capa de red: una baliza es todo capa 2. Sin recurrir
                            a la MAC, media tabla saldría vacía. */}
                        <td className="l mono">{p.src || p.srcMAC}{p.srcPort ? ':' + p.srcPort : ''}</td>
                        <td className="l mono">{p.dst || p.dstMAC}{p.dstPort ? ':' + p.dstPort : ''}</td>
                        <td className="l">{protoTag(p.proto)}</td>
                        <td className="dim">{p.length}</td>
                        <td className="l mono info-cell">
                          {p.app && <span className="tag active" style={{ marginRight: 6 }}>{p.app}</span>}
                          {p.info}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {result.packets.length > MAX_ROWS && (
                <p className="dim" style={{ fontSize: 12, marginTop: 10 }}>
                  {t('Mostrando {shown} de {total} paquetes cargados.', { shown: MAX_ROWS.toLocaleString(locale), total: result.shownPackets.toLocaleString(locale) })}
                </p>
              )}
            </div>
          ) : tab === 'flows' ? (
            <div className="card">
              <div className="mtr-table-wrap">
                <table className="mtr-table">
                  <thead>
                    <tr>
                      <th className="l">Proto</th>
                      <th className="l">{t('Extremo A')}</th>
                      <th className="l">{t('Extremo B')}</th>
                      <th>A→B</th>
                      <th>B→A</th>
                      <th>Bytes</th>
                      <th>Dur</th>
                      <th className="l">Apps</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.flows.map((f, i) => (
                      <tr key={i}>
                        <td className="l">{protoTag(f.proto.toUpperCase())}</td>
                        <td className="l mono">{f.aAddr}{f.aPort ? ':' + f.aPort : ''}</td>
                        <td className="l mono">{f.bAddr}{f.bPort ? ':' + f.bPort : ''}</td>
                        <td className="dim">{f.pktsAB}</td>
                        <td className="dim">{f.pktsBA}</td>
                        <td className="accent-t">{humanBytes(f.bytes)}</td>
                        <td className="dim">{f.durationSec.toFixed(1)}s</td>
                        <td className="l">
                          {f.apps?.map((a) => (
                            <span key={a} className="tag" style={{ marginRight: 4 }}>{a}</span>
                          ))}
                          {f.resets ? <span className="tag vpn">RST×{f.resets}</span> : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : tab === 'detections' ? (
            <div className="card">
              <div className="grid cols-3" style={{ marginBottom: 14 }}>
                <div className="stat">
                  <span className="label">{t('SYN iniciales')}</span>
                  <span className="value">{result.scanDetection.initialSyn.toLocaleString()}</span>
                </div>
                <div className="stat">
                  <span className="label">{t('Barridos verticales')}</span>
                  <span className="value">{result.scanDetection.vertical}</span>
                </div>
                <div className="stat">
                  <span className="label">{t('Barridos horizontales')}</span>
                  <span className="value">{result.scanDetection.horizontal}</span>
                </div>
              </div>
              {scanFindings.length === 0 ? (
                <p className="dim">{t('No se observaron patrones que superen los umbrales defensivos. Esto no demuestra ausencia de reconocimiento; indica que esta captura no contiene evidencia suficiente.')}</p>
              ) : (
                <div className="mtr-table-wrap">
                  <table className="mtr-table">
                    <thead><tr><th className="l">{t('Tipo')}</th><th className="l">{t('Origen')}</th><th className="l">{t('Objetivo / puerto')}</th><th>{t('Distintos')}</th><th>{t('Intentos')}</th><th>{t('Confianza')}</th><th className="l">{t('Evidencia')}</th></tr></thead>
                    <tbody>
                      {scanFindings.map((f) => (
                        <tr key={f.id}>
                          <td className="l"><span className={'tag ' + (f.severity === 'high' ? 'vpn' : 'reserved')}>{f.kind === 'vertical' ? 'Vertical' : 'Horizontal'}</span></td>
                          <td className="l mono">{f.source}</td>
                          <td className="l mono">{f.kind === 'vertical' ? f.target : `TCP/${f.port}`}</td>
                          <td>{f.distinct}</td>
                          <td>{f.attempts}</td>
                          <td className="accent-t">{f.confidence}%</td>
                          <td className="l" style={{ whiteSpace: 'normal', minWidth: 300 }}>
                            <strong>{f.summary}</strong>
                            <div className="dim" style={{ fontFamily: 'var(--font-sans)', marginTop: 4 }}>{f.explain}</div>
                            <div className="dim mono" style={{ marginTop: 4 }}>
                              {f.kind === 'vertical' ? t('Puertos: {ports}', { ports: (f.ports || []).join(', ') }) : t('Objetivos: {targets}', { targets: (f.targets || []).join(', ') })}
                              {' · '}{f.mitre}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {result.scanDetection.truncated && <div className="note" style={{ marginTop: 10 }}>{t('La evidencia fue limitada para mantener acotado el uso de memoria.')}</div>}
            </div>
          ) : null}

          {tab === 'health' && (
            <div>
              <div className="grid cols-3">
                <div className="card stat">
                  <span className="label">{t('Tramas con capa 2')}</span>
                  <span className="value">{result.netDiag.frames.toLocaleString(locale)}</span>
                  <span className="sub">{t('analizadas')}</span>
                </div>
                <div className="card stat">
                  <span className="label">{t('Broadcasts')}</span>
                  <span className="value">{result.netDiag.broadcasts.toLocaleString(locale)}</span>
                  <span className="sub">{t('a ff:ff:ff:ff:ff:ff')}</span>
                </div>
                <div className="card stat">
                  <span className="label">{t('Tramas en bucle')}</span>
                  <span className={'value' + (result.netDiag.loopedFrames > 0 ? ' accent' : '')}>
                    {result.netDiag.loopedFrames.toLocaleString(locale)}
                  </span>
                  <span className="sub">{t('repeticiones idénticas')}</span>
                </div>
              </div>

              {healthFindings.length === 0 ? (
                <div className="empty" style={{ marginTop: 16 }}>
                  <div className="big">✅</div>
                  {t('Sin fallos de capa 2 en esta captura. Si el problema persiste, capturá durante el fallo: una captura de red sana no lo puede mostrar.')}
                </div>
              ) : (
                <div className="grid" style={{ marginTop: 16 }}>
                  {/* .grid sin cols-* es una columna con gap de 16px. Antes
                      esto usaba .hop-list, cuyo gap de 2px está pensado para
                      filas compactas y dejaba las tarjetas pegadas. */}
                  {healthFindings.map((f) => (
                    <div className="card" key={f.id} style={{ borderColor: f.severity === 'high' ? 'var(--danger)' : 'var(--warn)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                        <span className={'tag ' + (f.severity === 'high' ? 'vpn' : 'reserved')}>{t(f.kind)}</span>
                        <strong>{f.summary}</strong>
                        <span className="dim" style={{ marginLeft: 'auto', fontSize: 11.5 }}>
                          {t('confianza {n}%', { n: f.confidence })}
                          {f.ratePerSec ? ` · ${f.ratePerSec.toFixed(1)}/s` : ''}
                        </span>
                      </div>
                      <p className="body-text" style={{ marginTop: 8 }}>{f.explain}</p>
                      {f.evidence.length > 0 && (
                        <div className="list-reset" style={{ marginTop: 8 }}>
                          {f.evidence.map((e, i) => (
                            <div className="kv" key={i}><span className="k">{t('Evidencia')}</span><span className="v mono" style={{ fontSize: 11.5 }}>{e}</span></div>
                          ))}
                        </div>
                      )}
                      {f.caveat && <p className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>⚠ {f.caveat}</p>}
                    </div>
                  ))}
                </div>
              )}

              {neighbors.length > 0 && (
                <div className="card" style={{ marginTop: 16 }}>
                  <h3>{t('Equipos que se anuncian ({count})', { count: neighbors.length.toLocaleString(locale) })}</h3>
                  <p className="dim" style={{ fontSize: 11.5, marginTop: 0 }}>
                    {t('Descubrimiento pasivo: estos equipos emiten anuncios de gestión. Sirve para encontrar switches y APs que no están en el inventario.')}
                  </p>
                  <div className="mtr-table-wrap" style={{ marginTop: 10 }}>
                    <table className="mtr-table">
                      <thead>
                        <tr>
                          <th className="l">MAC</th>
                          <th className="l">{t('Fabricante')}</th>
                          <th className="l">IP</th>
                          <th className="l">{t('Protocolo')}</th>
                          <th>{t('Anuncios')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {neighbors.map((n) => (
                          <tr key={n.mac + n.protocol}>
                            <td className="l mono">{n.mac}</td>
                            <td className="l">{n.vendor || <span className="dim">—</span>}</td>
                            <td className="l mono dim">{n.ip || '—'}</td>
                            <td className="l"><span className="tag">{n.protocol}</span></td>
                            <td className="dim">{n.count.toLocaleString(locale)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {result.netDiag.truncated && <div className="note" style={{ marginTop: 10 }}>{t('La evidencia fue limitada para mantener acotado el uso de memoria.')}</div>}
            </div>
          )}
        </>
      )}
    </div>
  );
}
