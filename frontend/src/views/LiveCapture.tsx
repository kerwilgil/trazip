import { Fragment, useEffect, useMemo, useState } from 'react';
import { captureAvailable, captureDevices, wifiStatus, backendAvailable, type CaptureDevice, type PktSummary, type wifi } from '../lib/api';
import { useCaptureSession } from '../lib/session';
import CopyButton from '../components/CopyButton';
import { useI18n } from '../lib/i18n';
import { decodePayloadHex, interpretPacket } from '../lib/packetInterpretation';

type PacketDetailTab = 'summary' | 'strings' | 'hex';

function protoTag(proto: string) {
  const map: Record<string, string> = { TCP: 'public', UDP: 'private', DNS: 'reserved', ARP: 'documentation', TLS: 'public', HTTP: 'public', WS: 'private', ICMP: 'bogon', ICMPv6: 'bogon' };
  return <span className={'tag ' + (map[proto] || '')}>{proto}</span>;
}

function timeOnly(t: string): string {
  const i = t.indexOf('T');
  return i < 0 ? t : t.slice(i + 1, i + 13);
}

function rowText(p: PktSummary): string {
  const src = p.src + (p.srcPort ? ':' + p.srcPort : '');
  const dst = p.dst + (p.dstPort ? ':' + p.dstPort : '');
  const flags = p.tcpFlags && p.tcpFlags.length > 0 ? ` [${p.tcpFlags.join(',')}]` : '';
  const ttl = p.ttl ? ` ttl=${p.ttl}` : '';
  const app = p.app ? ` [${p.app}]` : '';
  return `[${timeOnly(p.time)}] ${src} -> ${dst}  ${p.proto}${app}${flags} len=${p.length}${ttl}  ${p.info}`;
}

function csvEscape(v: string): string {
  if (/[",\n]/.test(v)) return '"' + v.replace(/"/g, '""') + '"';
  return v;
}

function rowsToCSV(rows: PktSummary[]): string {
  const header = 'tiempo,origen,puertoOrigen,destino,puertoDestino,protocolo,app,transporte,ttl,flagsTCP,longitud,payloadBytes,info';
  const lines = rows.map((p) =>
    [
      p.time,
      p.src,
      p.srcPort ?? '',
      p.dst,
      p.dstPort ?? '',
      p.proto,
      p.app || '',
      p.transport || '',
      p.ttl ?? '',
      (p.tcpFlags || []).join(' '),
      p.length,
      p.payloadLen ?? '',
      p.info,
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

// Classic 16-bytes-per-row hex + ASCII dump, like Wireshark's bytes pane.
function hexDumpLines(hex: string, totalLen?: number): string[] {
  const { bytes } = decodePayloadHex(hex);
  const lines: string[] = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const chunk = bytes.slice(off, off + 16);
    const hexPart = chunk.map((b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
    const asciiPart = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    lines.push(`${off.toString(16).padStart(4, '0')}  ${hexPart}  ${asciiPart}`);
  }
  if (totalLen != null && totalLen > bytes.length) {
    lines.push(`… (${totalLen - bytes.length} bytes más, no incluidos en la vista previa)`);
  }
  return lines;
}

// Top Talkers is a pure client-side aggregation of the same packets already
// flowing into the table — no backend changes needed, since PktSummary
// already carries src/length/app. Works identically for Npcap and TZSP
// sources: with TZSP the router forwards traffic for the whole segment, so
// this is what actually answers "who on my network is talking, and to what"
// (Npcap-only capture mostly shows this machine's own traffic — a switch
// never sends other hosts' unicast frames to your port).
interface Talker {
  ip: string;
  bytes: number;
  packets: number;
  apps: string[];
}

function computeTopTalkers(packets: PktSummary[]): Talker[] {
  const agg = new Map<string, { bytes: number; packets: number; apps: Map<string, number> }>();
  for (const p of packets) {
    if (!p.src) continue;
    let e = agg.get(p.src);
    if (!e) {
      e = { bytes: 0, packets: 0, apps: new Map() };
      agg.set(p.src, e);
    }
    e.bytes += p.length;
    e.packets += 1;
    if (p.app) e.apps.set(p.app, (e.apps.get(p.app) ?? 0) + 1);
  }
  return Array.from(agg.entries())
    .map(([ip, e]) => ({
      ip,
      bytes: e.bytes,
      packets: e.packets,
      apps: Array.from(e.apps.entries()).sort((a, b) => b[1] - a[1]).map(([name]) => name),
    }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 25);
}

function fmtBytes(n: number): string {
  if (n < 1024) return n + ' B';
  const units = ['KB', 'MB', 'GB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return v.toFixed(v < 10 ? 1 : 0) + ' ' + units[i];
}

export default function LiveCapture() {
  const { t, locale } = useI18n();
  const {
    captureDevice: device, setCaptureDevice: setDevice,
    capturePromisc: promisc, setCapturePromisc: setPromisc,
    captureRunning: running, capturePackets: packets, captureTotal: total, captureProtos: protos,
    captureScanDetection,
    captureNetDiag,
    captureError, captureRunningSinceMs, startLiveCapture, startTZSPCapture, stopLiveCapture, clearLiveCapture,
  } = useCaptureSession();
  const [available, setAvailable] = useState<boolean | null>(null);
  const [devices, setDevices] = useState<CaptureDevice[]>([]);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const error = dialogError ?? captureError;
  const [protoFilter, setProtoFilter] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [expanded, setExpanded] = useState<number | null>(null);
  const [detailTab, setDetailTab] = useState<PacketDetailTab>('summary');
  const [source, setSource] = useState<'npcap' | 'tzsp'>('npcap');
  const [tzspPort, setTzspPort] = useState(37008);
  const [showTalkers, setShowTalkers] = useState(false);
  const [monitorMode, setMonitorMode] = useState(false);
  const [wifiIfaces, setWifiIfaces] = useState<wifi.IfaceStatus[]>([]);

  const [runningForMs, setRunningForMs] = useState(0);

  // WiFi connectivity: if the machine has a WLAN interface and none is
  // connected to a network, there's simply no traffic to capture — surface
  // that plainly instead of letting the user stare at an empty capture.
  const wifiPresent = wifiIfaces.length > 0;
  const wifiConnected = wifiIfaces.some((i) => i.connected);
  const wifiOffline = wifiPresent && !wifiConnected;
  const connectedSSIDs = wifiIfaces.filter((i) => i.connected).map((i) => i.ssid).filter(Boolean);

  useEffect(() => {
    if (!backendAvailable()) return;
    let cancelled = false;
    const poll = () => wifiStatus().then((s) => { if (!cancelled) setWifiIfaces(s || []); }).catch(() => undefined);
    poll();
    // Re-check periodically so connecting/disconnecting WiFi updates the hint
    // without needing to leave and re-enter the tab.
    const t = setInterval(poll, 5000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  useEffect(() => {
    if (!running || !captureRunningSinceMs) {
      setRunningForMs(0);
      return;
    }
    const t = setInterval(() => setRunningForMs(Date.now() - captureRunningSinceMs), 1000);
    return () => clearInterval(t);
  }, [running, captureRunningSinceMs]);

  useEffect(() => {
    if (!backendAvailable()) {
      setAvailable(false);
      return;
    }
    captureAvailable().then((a) => {
      setAvailable(a);
      if (a) {
        captureDevices()
          .then((d) => {
            setDevices(d);
            if (d[0] && !device) setDevice(d[0].name);
          })
          .catch((e) => setDialogError(String(e)));
      }
    });
    // No cleanup that stops the capture here — the subscription lives in
    // CaptureSessionProvider (mounted at the app root), so leaving this tab
    // no longer kills a running capture; it keeps accumulating in the
    // background until the user explicitly stops it.
  }, []);

  async function start() {
    if (running) return;
    setDialogError(null);
    setProtoFilter(null);
    setSearch('');
    if (source === 'tzsp') {
      await startTZSPCapture('0.0.0.0:' + tzspPort);
    } else {
      if (!device) return;
      await startLiveCapture(device, promisc, monitorMode);
    }
  }

  function stop() {
    stopLiveCapture();
  }

  const protoList = Object.entries(protos).sort((a, b) => b[1] - a[1]);

  const filteredPackets = useMemo(() => {
    const q = search.trim().toLowerCase();
    return packets.filter((p) => {
      if (protoFilter && p.proto !== protoFilter) return false;
      if (!q) return true;
      return (
        p.src.toLowerCase().includes(q) ||
        p.dst.toLowerCase().includes(q) ||
        p.proto.toLowerCase().includes(q) ||
        p.info.toLowerCase().includes(q) ||
        String(p.srcPort ?? '').includes(q) ||
        String(p.dstPort ?? '').includes(q)
      );
    });
  }, [packets, protoFilter, search]);

  const visibleRows = filteredPackets.slice(0, 800);
  const topTalkers = useMemo(() => computeTopTalkers(packets), [packets]);
  const expandedPacket = useMemo(() => visibleRows.find((packet) => packet.index === expanded) ?? null, [expanded, visibleRows]);
  const expandedInterpretation = useMemo(() => expandedPacket ? interpretPacket(expandedPacket) : null, [expandedPacket]);

  return (
    <div className="content-inner content-inner-wide">
      <div className="page-head">
        <h2>{t('Live Capture')}</h2>
        <p className="body-text">
          {t('Captura de paquetes en tiempo real desde una interfaz local (Npcap) o desde un router por TZSP. La captura sigue corriendo en segundo plano al cambiar de pestaña y solo se detiene con “Detener”.')}
        </p>
      </div>

      <div className="card">
        <div className="field">
          <label className="check-inline">
            <input type="radio" name="capsource" checked={source === 'npcap'} onChange={() => setSource('npcap')} disabled={running} />
            {t('Interfaz local (Npcap)')}
          </label>
          <label className="check-inline">
            <input type="radio" name="capsource" checked={source === 'tzsp'} onChange={() => setSource('tzsp')} disabled={running} />
            {t('TZSP (router remoto)')}
          </label>
        </div>

        {source === 'npcap' ? (
          <>
            {available === false && (
              <div className="note" style={{ marginTop: 10 }}>
                {t('Npcap no está instalado o no hay backend. Instálalo desde npcap.com o usa TZSP.')}
              </div>
            )}
            <div className="field" style={{ marginTop: 10 }}>
              <select className="input" value={device} onChange={(e) => setDevice(e.target.value)} disabled={running || available === false}>
                {devices.map((d) => (
                  <option key={d.name} value={d.name}>{d.description || d.name}</option>
                ))}
              </select>
              {running ? (
                <button className="btn ghost" onClick={stop}>■ {t('Detener')}</button>
              ) : (
                <button className="btn" onClick={start} disabled={!device || available === false}>▶ {t('Capturar')}</button>
              )}
            </div>
            {wifiPresent && (
              <p className="dim" style={{ fontSize: 11.5, marginTop: 10 }}>
                {wifiConnected
                  ? <>📶 {t('WiFi conectado')}{connectedSSIDs.length > 0 ? <> {t('a')} <strong>{connectedSSIDs.join(', ')}</strong></> : ''}.</>
                  : <span style={{ color: 'var(--warn)' }}>📶 {t('WiFi encendido pero sin conexión a una red.')}</span>}
              </p>
            )}
            <label className="check-inline" style={{ marginTop: 12, color: promisc ? 'var(--warn)' : 'var(--text-dim)' }}>
              <input type="checkbox" checked={promisc} onChange={(e) => setPromisc(e.target.checked)} disabled={running} />
              {t('Modo promiscuo')}
            </label>
            <label className="check-inline" style={{ marginTop: 8, color: monitorMode ? 'var(--warn)' : 'var(--text-dim)' }}>
              <input type="checkbox" checked={monitorMode} onChange={(e) => setMonitorMode(e.target.checked)} disabled={running} />
              {t('Modo monitor')}
            </label>
            <p className="dim" style={{ fontSize: 11.5, marginTop: 10 }}>
              {t('¿Quieres ver el tráfico de otros equipos de tu red, además del de esta máquina? Conecta esta interfaz a un puerto reflejado (SPAN/mirror) de tu switch. Funciona con cualquier marca (MikroTik, Cisco, Huawei, TP-Link, UniFi, etc.) porque el puerto entrega Ethernet sin encapsulación del fabricante y Npcap lo decodifica sin configuración adicional. TZSP es una alternativa cuando no quieres instalar ese cable y tu router lo admite; actualmente, MikroTik.')}
            </p>
          </>
        ) : (
          <>
            <div className="field" style={{ marginTop: 10 }}>
              <span className="dim" style={{ display: 'flex', alignItems: 'center' }}>{t('Escuchando en')} 0.0.0.0:</span>
              <input className="input mono" type="number" style={{ maxWidth: 120 }} value={tzspPort} onChange={(e) => setTzspPort(+e.target.value || 37008)} disabled={running} />
              {running ? (
                <button className="btn ghost" onClick={stop}>■ {t('Detener')}</button>
              ) : (
                <button className="btn" onClick={start}>▶ {t('Escuchar')}</button>
              )}
            </div>
            <p className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>
              {t('En el router (por ejemplo, MikroTik RouterOS)')}: <span className="mono">/tool sniffer set streaming-enabled=yes streaming-server=&lt;{t('IP-de-este-equipo')}&gt;:{tzspPort}</span>, {t('después')} <span className="mono">/tool sniffer start</span>. {t('Tu propio router exporta el tráfico que ya pasa por él; no requiere Npcap ni privilegios especiales en esta máquina.')}
            </p>
          </>
        )}
      </div>

      {error && <div className="note">{error}</div>}

      {source === 'npcap' && wifiOffline && (
        <div className="note" style={{ borderColor: 'var(--warn)' }}>
          <strong>⚠ {t('Tu WiFi no está conectado a ninguna red.')}</strong> {t('El adaptador inalámbrico está encendido, pero no está asociado a una red. Conéctate a una red WiFi o captura desde una interfaz Ethernet con enlace.')}
        </div>
      )}

      {running && total === 0 && runningForMs > 6000 && (
        <div className="note">
          {t('Han transcurrido {seconds} s en modo {mode} y aún no llega ningún paquete.', { seconds: Math.round(runningForMs / 1000), mode: source === 'tzsp' ? t('escucha') : t('captura') })}
          {source === 'tzsp'
            ? t(' Confirma que el sniffer del router está en ejecución, que apunta a la IP y al puerto de este equipo y que el firewall no bloquea el tráfico UDP entrante.')
            : wifiOffline
              ? t(' Tu WiFi no está conectado a una red. Conéctate o usa una interfaz Ethernet con enlace para capturar tráfico.')
              : promisc
                ? t(' Muchos adaptadores WiFi no admiten el modo promiscuo y pueden bloquear incluso el tráfico del propio equipo. Prueba sin ese modo o usa una interfaz Ethernet.')
                : t(' Verifica que elegiste la interfaz que tiene tráfico y que existe actividad de red durante la captura.')}
        </div>
      )}

      {(running || total > 0) && (
        <>
          <div className="card" style={{ marginTop: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
              <span className="stat" style={{ minWidth: 120 }}>
                <span className="label">{t('Capturados')} {running && <span className="spin" style={{ marginLeft: 6 }} />}</span>
                <span className="value accent">{total.toLocaleString()}</span>
              </span>
              <span className="stat">
                <span className="label">{t('Protocolos')} {protoFilter && <button className="btn ghost" style={{ padding: '1px 8px', fontSize: 10.5 }} onClick={() => setProtoFilter(null)}>{t('quitar filtro ✕')}</button>}</span>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {protoList.map(([p, n]) => (
                    <button
                      key={p}
                      className={'tag' + (protoFilter === p ? ' active' : '')}
                      onClick={() => setProtoFilter(protoFilter === p ? null : p)}
                      title={protoFilter === p ? t('Haz clic para quitar el filtro') : t('Filtrar por {protocol}', { protocol: p })}
                    >
                      {p}: {n.toLocaleString()}
                    </button>
                  ))}
                </div>
              </span>
            </div>
          </div>

          {captureNetDiag.findings.length > 0 && (
            <div className="card" style={{ marginTop: 16, borderColor: 'var(--danger)' }}>
              <h3 style={{ marginTop: 0 }}>{t('Salud de red ({count})', { count: captureNetDiag.findings.length })}</h3>
              <p className="dim" style={{ fontSize: 12 }}>
                {t('Fallos de capa 2 sobre {frames} tramas y {bcast} broadcasts observados. Ningún hallazgo identifica el puerto físico: eso necesita SNMP o el propio switch.', {
                  frames: captureNetDiag.frames.toLocaleString(locale),
                  bcast: captureNetDiag.broadcasts.toLocaleString(locale),
                })}
              </p>
              <div className="hop-list" style={{ marginTop: 8 }}>
                {captureNetDiag.findings.slice(0, 20).map((f) => (
                  <div className="hop-row" key={f.id} style={{ flexWrap: 'wrap' }}>
                    <span className={'tag ' + (f.severity === 'high' ? 'vpn' : 'reserved')}>{t(f.kind)}</span>
                    <span className="mono">{f.subject}</span>
                    <span className="dim" style={{ fontSize: 12 }}>{f.summary}</span>
                    <span className="accent-t" style={{ marginLeft: 'auto' }}>
                      {f.ratePerSec ? `${f.ratePerSec.toFixed(0)}/s · ` : ''}{f.confidence}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {captureNetDiag.neighbors.length > 0 && (
            <div className="card" style={{ marginTop: 16 }}>
              <h3 style={{ marginTop: 0 }}>{t('Equipos que se anuncian ({count})', { count: captureNetDiag.neighbors.length })}</h3>
              <p className="dim" style={{ fontSize: 12 }}>
                {t('Descubrimiento pasivo: sirve para encontrar switches y APs que no están en el inventario.')}
              </p>
              <div className="hop-list" style={{ marginTop: 8 }}>
                {captureNetDiag.neighbors.map((n) => (
                  <div className="hop-row" key={n.mac + n.protocol}>
                    <span className="tag">{n.protocol}</span>
                    <span className="mono">{n.mac}</span>
                    <span className="dim mono" style={{ fontSize: 12 }}>{n.ip || '—'}</span>
                    <span className="dim" style={{ marginLeft: 'auto', fontSize: 12 }}>×{n.count.toLocaleString(locale)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {captureScanDetection.findings.length > 0 && (
            <div className="card" style={{ marginTop: 16, borderColor: 'var(--warn)' }}>
              <h3 style={{ marginTop: 0 }}>{t('Detecciones de reconocimiento ({count})', { count: captureScanDetection.findings.length })}</h3>
              <p className="dim" style={{ fontSize: 12 }}>
                {t('Análisis pasivo de la captura actual ({count} SYN iniciales). Una coincidencia indica un patrón que debes validar; no confirma por sí sola una actividad maliciosa.', { count: captureScanDetection.initialSyn.toLocaleString() })}
              </p>
              <div className="hop-list" style={{ marginTop: 8 }}>
                {captureScanDetection.findings.slice(0, 20).map((f) => (
                  <div className="hop-row" key={f.id}>
                    <span className={'tag ' + (f.severity === 'high' ? 'vpn' : 'reserved')}>{f.kind === 'vertical' ? 'Vertical' : 'Horizontal'}</span>
                    <span className="mono">{f.source}</span>
                    <span className="dim" style={{ fontSize: 12 }}>{f.summary}</span>
                    <span className="accent-t" style={{ marginLeft: 'auto' }}>{f.confidence}%</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="card" style={{ marginTop: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0 }}>{t('Principales emisores ({count})', { count: topTalkers.length })}</h3>
              <button className="btn ghost" onClick={() => setShowTalkers((v) => !v)}>{showTalkers ? `▲ ${t('Ocultar')}` : `▼ ${t('Mostrar')}`}</button>
            </div>
            <p className="dim" style={{ fontSize: 11.5, marginTop: 6 }}>
              {t('Muestra qué direcciones IP de origen generaron más tráfico y las aplicaciones o dominios detectados. Con una fuente TZSP, cubre toda la red y no solo este equipo.')}
            </p>
            {showTalkers && (
              topTalkers.length === 0 ? (
                <p className="dim" style={{ marginTop: 8 }}>{t('Todavía no hay datos suficientes.')}</p>
              ) : (
                <div className="hop-list" style={{ marginTop: 8 }}>
                  {topTalkers.map((talker) => (
                    <div className="hop-row" key={talker.ip}>
                      <span className="hop-host mono">{talker.ip}</span>
                      <span className="dim" style={{ fontSize: 12 }}>{fmtBytes(talker.bytes)} · {talker.packets.toLocaleString()} {t('paquetes')}</span>
                      {talker.apps.length > 0 && (
                        <span style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginLeft: 'auto' }}>
                          {talker.apps.slice(0, 5).map((a) => <span key={a} className="tag active">{a}</span>)}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )
            )}
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0 }}>
                {t('Paquetes')} ({filteredPackets.length.toLocaleString()}{filteredPackets.length !== packets.length ? ` ${t('de')} ${packets.length.toLocaleString()}` : ''})
              </h3>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <input
                  className="input"
                  style={{ maxWidth: 260 }}
                  placeholder={t('Buscar IP, puerto, info…')}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
                <CopyButton
                  label={t('Copiar seleccionadas ({count})', { count: selected.size })}
                  disabled={selected.size === 0}
                  getText={() => visibleRows.filter((p) => selected.has(p.index)).map(rowText).join('\n')}
                />
                <CopyButton label={t('Copiar tabla')} disabled={visibleRows.length === 0} getText={() => visibleRows.map(rowText).join('\n')} />
                <button
                  className="btn ghost"
                  disabled={visibleRows.length === 0}
                  onClick={() => downloadText(`trazip-livecapture-${Date.now()}.csv`, rowsToCSV(visibleRows), 'text/csv')}
                >
                  ⬇ {t('Descargar CSV')}
                </button>
                {!running && <button className="btn ghost" onClick={() => { clearLiveCapture(); setSelected(new Set()); setExpanded(null); }}>🗑 {t('Limpiar')}</button>}
              </div>
            </div>
            <p className="dim" style={{ fontSize: 11, marginTop: 6 }}>{t('Haz clic en una fila para ver el resumen, cadenas y carga útil hexadecimal/ASCII. Se muestran hasta 800 filas a la vez.')}</p>
            <div className="mtr-table-wrap pkt-scroll">
              <table className="mtr-table pkt-table">
                <colgroup>
                  <col className="pkt-col-select" /><col className="pkt-col-time" /><col className="pkt-col-address" /><col className="pkt-col-address" />
                  <col className="pkt-col-proto" /><col className="pkt-col-length" /><col className="pkt-col-ttl" /><col className="pkt-col-flags" /><col className="pkt-col-info" />
                </colgroup>
                <thead>
                  <tr>
                    <th>
                      <input
                        type="checkbox"
                        checked={visibleRows.length > 0 && visibleRows.every((p) => selected.has(p.index))}
                        onChange={(e) => setSelected(e.target.checked ? new Set(visibleRows.map((p) => p.index)) : new Set())}
                      />
                    </th>
                    <th className="l">{t('Tiempo')}</th>
                    <th className="l">{t('Origen')}</th>
                    <th className="l">{t('Destino')}</th>
                    <th className="l">Proto</th>
                    <th>Long</th>
                    <th>TTL</th>
                    <th className="l">Flags</th>
                    <th className="l">Info</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleRows.map((p, i) => (
                    <Fragment key={p.index + '-' + i}>
                      <tr
                        className={expanded === p.index ? 'reached' : undefined}
                        style={{ cursor: 'pointer' }}
                        onClick={() => {
                          const next = expanded === p.index ? null : p.index;
                          setExpanded(next);
                          if (next !== null) setDetailTab('summary');
                        }}
                      >
                        <td onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            checked={selected.has(p.index)}
                            onChange={(e) =>
                              setSelected((prev) => {
                                const next = new Set(prev);
                                if (e.target.checked) next.add(p.index);
                                else next.delete(p.index);
                                return next;
                              })
                            }
                          />
                        </td>
                        <td className="l dim mono">{timeOnly(p.time)}</td>
                        <td className="l mono packet-address-cell" title={`${p.src}${p.srcPort ? ':' + p.srcPort : ''}`}>{p.src}{p.srcPort ? ':' + p.srcPort : ''}</td>
                        <td className="l mono packet-address-cell" title={`${p.dst}${p.dstPort ? ':' + p.dstPort : ''}`}>{p.dst}{p.dstPort ? ':' + p.dstPort : ''}</td>
                        <td className="l">{protoTag(p.proto)}</td>
                        <td className="dim">{p.length}</td>
                        <td className="dim">{p.ttl ?? '—'}</td>
                        <td className="l dim mono packet-flags-cell" title={(p.tcpFlags || []).join(',') || '—'}>{(p.tcpFlags || []).join(',') || '—'}</td>
                        <td className="l mono info-cell" title={p.info}>
                          {p.app && <span className="tag active" style={{ marginRight: 6 }}>{p.app}</span>}
                          {p.info}
                        </td>
                      </tr>
                      {expanded === p.index && (
                        <tr key={p.index + '-' + i + '-payload'}>
                          <td colSpan={9} className="packet-detail-cell">
                            {expandedInterpretation && (
                              <div className="packet-detail">
                                <div className="packet-detail-toolbar">
                                  <div className="packet-detail-tabs" role="tablist" aria-label={t('Detalle del paquete')}>
                                    {(['summary', 'strings', 'hex'] as const).map((tab) => {
                                      const label = tab === 'summary' ? t('Resumen') : tab === 'strings' ? t('Cadenas') : t('Hexadecimal');
                                      return <button key={tab} id={`packet-tab-${p.index}-${tab}`} type="button" className={`btn ghost packet-detail-tab${detailTab === tab ? ' active' : ''}`} role="tab" aria-controls={`packet-panel-${p.index}`} aria-selected={detailTab === tab} onClick={() => setDetailTab(tab)}>{label}</button>;
                                    })}
                                  </div>
                                  {detailTab === 'hex' && p.payloadHex && <CopyButton label={t('Copiar hexadecimal')} getText={() => hexDumpLines(p.payloadHex!, p.payloadLen).join('\n')} className="btn ghost" />}
                                </div>

                                <div id={`packet-panel-${p.index}`} role="tabpanel" aria-labelledby={`packet-tab-${p.index}-${detailTab}`}>
                                {detailTab === 'summary' && (
                                  <div className="packet-summary">
                                    <h4>{t('Interpretación del paquete')}</h4>
                                    <div className="packet-summary-grid">
                                      <section><h5>{t('CAPA 2')}</h5><strong>{expandedInterpretation.link.protocol || t('No identificado')}</strong>{expandedInterpretation.link.etherType && <span>{t('EtherType')}: {expandedInterpretation.link.etherType}</span>}{expandedInterpretation.link.sourceMAC && <span>{t('MAC origen')}: <code>{expandedInterpretation.link.sourceMAC}</code></span>}{expandedInterpretation.link.destinationMAC && <span>{t('MAC destino')}: <code>{expandedInterpretation.link.destinationMAC}</code></span>}{expandedInterpretation.link.protocol === 'Ethernet' && expandedInterpretation.link.destination === 'broadcast' && <span>{t('Destino')}: {t('Broadcast Ethernet')}</span>}{expandedInterpretation.link.protocol === 'Ethernet' && expandedInterpretation.link.destination === 'multicast' && <span>{t('Destino')}: {t('Multicast Ethernet')}</span>}</section>
                                      <section><h5>{t('CAPA 3')}</h5><strong>{expandedInterpretation.network.protocol || t('No identificado')}</strong>{expandedInterpretation.network.source && <span>{t('Origen')}: <code>{expandedInterpretation.network.source}</code></span>}{expandedInterpretation.network.destination && <span>{t('Destino')}: <code>{expandedInterpretation.network.destination}</code></span>}{expandedInterpretation.network.ttl !== null && <span>{t('TTL / Hop Limit')}: {expandedInterpretation.network.ttl}</span>}{expandedInterpretation.network.scope === 'ipv4-broadcast' && <span>{t('Alcance')}: {t('Broadcast IPv4 limitado')}</span>}{expandedInterpretation.network.scope === 'ipv4-multicast' && <span>{t('Alcance')}: {t('Multicast IPv4')}</span>}{expandedInterpretation.network.scope === 'ipv6-multicast' && <span>{t('Alcance')}: {t('Multicast IPv6')}</span>}</section>
                                      <section><h5>{t('CAPA 4')}</h5><strong>{expandedInterpretation.transport.protocol || t('No identificado')}</strong>{expandedInterpretation.transport.sourcePort !== null && <span>{t('Puerto origen')}: {expandedInterpretation.transport.sourcePort}</span>}{expandedInterpretation.transport.destinationPort !== null && <span>{t('Puerto destino')}: {expandedInterpretation.transport.destinationPort}</span>}{expandedInterpretation.transport.tcpFlags.length > 0 && <span>{t('Flags TCP')}: {expandedInterpretation.transport.tcpFlags.join(', ')}</span>}<span>{t('Carga útil')}: {t('{count} bytes', { count: expandedInterpretation.transport.payloadBytes })}</span></section>
                                      <section><h5>{t('APLICACIÓN')}</h5><strong>{expandedInterpretation.application.protocol || t('No identificado')}</strong>{expandedInterpretation.application.app && <span>{t('Aplicación')}: {expandedInterpretation.application.app}</span>}{expandedInterpretation.application.info && <span>{t('Metadata visible')}: {expandedInterpretation.application.info}</span>}{!expandedInterpretation.application.protocol && <span>{t('No hay evidencia suficiente para identificar el protocolo de aplicación.')}</span>}{expandedInterpretation.application.encrypted && <span>{t('Contenido')}: {t('Cifrado / no interpretable después del handshake.')}</span>}</section>
                                      <section><h5>{t('CONTENIDO')}</h5><strong>{expandedInterpretation.payload.kind === 'empty' ? t('Vacío') : expandedInterpretation.payload.kind === 'text' ? t('Texto') : t('Binario')}</strong>{expandedInterpretation.payload.kind === 'empty' ? <span>{t('Sin carga útil de aplicación.')}</span> : <><span>{t('Vista previa')}: {t('{available} de {total} bytes', { available: expandedInterpretation.payload.availableBytes, total: expandedInterpretation.payload.totalBytes })}</span>{expandedInterpretation.payload.truncated && <span>{t('Vista previa truncada')}</span>}{expandedInterpretation.payload.kind === 'binary' && <span>{t('Binario / no interpretable con la evidencia disponible.')}</span>}{expandedInterpretation.payload.kind === 'text' && <span>{t('Texto en vista previa.')}</span>}</>}</section>
                                    </div>
                                  </div>
                                )}

                                {detailTab === 'strings' && (
                                  <div className="packet-strings">
                                    {expandedInterpretation.payload.strings.length > 0 ? <ul>{expandedInterpretation.payload.strings.map((value, index) => <li key={`${index}-${value}`}><code>{value}</code></li>)}</ul> : <p className="dim">{t('No se encontraron cadenas ASCII legibles en la vista previa.')}</p>}
                                  </div>
                                )}

                                {detailTab === 'hex' && (p.payloadHex ? <div className="packet-hex-wrap"><pre className="mono">{hexDumpLines(p.payloadHex, p.payloadLen).join('\n')}</pre></div> : <p className="dim">{t('Este paquete no contiene carga útil de aplicación.')}</p>)}
                                </div>
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
