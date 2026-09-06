import { useEffect, useRef, useState } from 'react';
import {
  backendAvailable,
  lanDiscover,
  startThroughput,
  startThroughputServer,
  stopThroughput,
  stopThroughputServer,
  subscribeThroughput,
  throughputAccessCode,
  throughputServerAddr,
  type ThroughputDirectionResult,
  type ThroughputResult,
} from '../lib/api';
import CopyButton from '../components/CopyButton';
import { useI18n } from '../lib/i18n';

type Proto = 'tcp' | 'udp';
type Direction = 'download' | 'upload' | 'bidir';

// Best-effort first non-loopback IPv4 across active interfaces — used to
// build the address the OTHER machine needs to type into its own TRAZIP
// (Throughput has no separate CLI; both sides run the desktop app).
function firstLanIPv4(addrs: { addrs: string[]; loopback: boolean; up: boolean }[]): string | null {
  for (const it of addrs) {
    if (!it.up || it.loopback) continue;
    for (const a of it.addrs) {
      const ip = a.split('/')[0];
      if (/^\d+\.\d+\.\d+\.\d+$/.test(ip) && !ip.startsWith('169.254.')) return ip;
    }
  }
  return null;
}

function ResultCard({ title, value }: { title: string; value?: ThroughputDirectionResult }) {
  if (!value) return null;
  return (
    <div className="card throughput-result">
      <span className="label">{title}</span>
      <span className="value accent">{value.mbps.toFixed(2)} Mbps</span>
      <span className="sub">{(value.bytes / 1_000_000).toFixed(2)} MB · {value.durationSec.toFixed(2)} s</span>
      {(value.packetsSent ?? 0) > 0 && (
        <span className="sub">{(value.packetsRecv ?? 0).toLocaleString()} / {(value.packetsSent ?? 0).toLocaleString()} paquetes · pérdida {(value.lossPct ?? 0).toFixed(2)}% · jitter {(value.jitterMs ?? 0).toFixed(2)} ms</span>
      )}
    </div>
  );
}

export default function Throughput() {
  const { t } = useI18n();
  const [server, setServer] = useState('127.0.0.1:5330');
  const [listen, setListen] = useState('127.0.0.1:5330');
  const [serverActive, setServerActive] = useState('');
  const [serverCode, setServerCode] = useState('');
  const [clientCode, setClientCode] = useState('');
  const [proto, setProto] = useState<Proto>('tcp');
  const [direction, setDirection] = useState<Direction>('download');
  const [duration, setDuration] = useState(10);
  const [streams, setStreams] = useState(1);
  const [bufferKB, setBufferKB] = useState(128);
  const [udpPacket, setUDPPacket] = useState(1200);
  const [targetMbps, setTargetMbps] = useState(50);
  const [running, setRunning] = useState(false);
  const [serverBusy, setServerBusy] = useState(false);
  const [result, setResult] = useState<ThroughputResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lanIP, setLanIP] = useState<string | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);
  const runRef = useRef<string | null>(null);
  const offRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    if (!backendAvailable()) return;
    throughputServerAddr().then((addr) => {
      setServerActive(addr);
      if (addr) throughputAccessCode().then(setServerCode).catch(() => undefined);
    }).catch(() => undefined);
    lanDiscover().then((r) => setLanIP(firstLanIPv4(r.interfaces))).catch(() => undefined);
    return () => {
      if (offRef.current) offRef.current();
      if (runRef.current) stopThroughput(runRef.current);
    };
  }, []);

  useEffect(() => {
    if (!running) {
      setElapsedMs(0);
      return;
    }
    const start = Date.now();
    const t = setInterval(() => setElapsedMs(Date.now() - start), 250);
    return () => clearInterval(t);
  }, [running]);

  async function toggleServer() {
    if (!backendAvailable()) return setError('Necesita el runtime Wails (app de escritorio).');
    setServerBusy(true);
    setError(null);
    try {
      if (serverActive) {
        await stopThroughputServer();
        setServerActive('');
        setServerCode('');
      } else {
        const addr = await startThroughputServer(listen.trim());
        setServerActive(addr);
        setServer(addr);
        throughputAccessCode().then(setServerCode).catch(() => undefined);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setServerBusy(false);
    }
  }

  async function run() {
    if (!backendAvailable()) return setError('Necesita el runtime Wails (app de escritorio).');
    setRunning(true);
    setResult(null);
    setError(null);
    try {
      const params = {
        proto,
        direction,
        durationMs: Math.round(duration * 1000),
        streams: proto === 'tcp' ? streams : 1,
        bufferKB,
        udpPacket,
        targetMbps: proto === 'udp' ? targetMbps : 0,
        accessCode: clientCode.trim() || undefined,
      };
      const id = await startThroughput(server.trim(), params);
      runRef.current = id;
      offRef.current = subscribeThroughput(id, (next, err) => {
        setRunning(false);
        runRef.current = null;
        setResult(next);
        if (err) setError(err);
      });
    } catch (e) {
      setRunning(false);
      setError(String(e));
    }
  }

  function stop() {
    if (offRef.current) offRef.current();
    if (runRef.current) stopThroughput(runRef.current);
    offRef.current = null;
    runRef.current = null;
    setRunning(false);
  }

  const listenIsLocalOnly = serverActive.startsWith('127.0.0.1');
  const listenPort = (serverActive || listen).split(':').pop() || '5330';
  const shareAddr = lanIP ? `${lanIP}:${listenPort}` : null;

  function useLANAddress() {
    setListen(`0.0.0.0:${listenPort}`);
  }

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>Throughput</h2>
        <p className="body-text">
          {t('Mide capacidad TCP o UDP entre dos instancias de TRAZIP — ambos extremos usan la misma app. Los datos de prueba son sintéticos; no se transmite tráfico de capturas ni telemetría.')}
        </p>
      </div>

      <div className="grid cols-2 throughput-grid">
        <div className="card pad-lg">
          <h3>{t('1. Servidor (recibe la prueba)')}</h3>
          <p className="dim throughput-note">
            {t('127.0.0.1 solo acepta conexiones de este mismo equipo — para que el otro equipo se pueda conectar, escuchá en 0.0.0.0 (todas las interfaces).')}
          </p>
          <div className="field">
            <input className="input mono" value={listen} onChange={(e) => setListen(e.target.value)} disabled={Boolean(serverActive) || serverBusy} />
            <button className="btn ghost" onClick={useLANAddress} disabled={Boolean(serverActive) || serverBusy} title={t('Permite conexiones desde otros equipos de tu red')}>
              Usar 0.0.0.0
            </button>
            <button className={'btn ' + (serverActive ? 'ghost' : '')} onClick={toggleServer} disabled={serverBusy}>
              {serverBusy ? <span className="spin" /> : null}{serverActive ? t('Detener servidor') : t('Iniciar servidor')}
            </button>
          </div>
          <div className="throughput-server-state">
            <span className={'pill ' + (serverActive ? 'ok' : 'warn')}>
              <span className="dot" />
              {serverActive
                ? listenIsLocalOnly
                  ? t('Escuchando en {address} — solo este equipo', { address: serverActive })
                  : t('Escuchando en {address} — accesible desde tu red', { address: serverActive })
                : t('Servidor apagado')}
            </span>
          </div>
          {serverActive && !listenIsLocalOnly && (
            <div className="field" style={{ marginTop: 10 }}>
              <input className="input mono" readOnly value={shareAddr ?? t('No se detectó una IP de LAN. Revisa tu conexión de red.')} />
              {shareAddr && <CopyButton label={t('Copiar dirección')} getText={() => shareAddr} />}
            </div>
          )}
          {serverActive && !listenIsLocalOnly && shareAddr && (
            <p className="dim" style={{ fontSize: 11.5, marginTop: 6 }}>
              {t('Pega esa dirección en el campo "host:puerto" de la tarjeta "Prueba" del otro equipo, con TRAZIP abierto también allí.')}
            </p>
          )}
          {serverActive && serverCode && (
            <div className="field" style={{ marginTop: 10 }}>
              <input className="input mono" readOnly value={serverCode} style={{ fontWeight: 700, letterSpacing: 2 }} />
              <CopyButton label={t('Copiar código')} getText={() => serverCode} />
            </div>
          )}
          {serverActive && serverCode && (
            <p className="dim" style={{ fontSize: 11.5, marginTop: 6 }}>
              {t('Código de acceso — compartíselo solo a quien vaya a medir contra este servidor.')}
            </p>
          )}
        </div>

        <div className="card pad-lg">
          <h3>{t('2. Prueba (mide contra un servidor)')}</h3>
          <p className="dim throughput-note">{t('Apuntá esto al servidor TRAZIP del otro equipo o a 127.0.0.1 para una prueba local.')}</p>
          <div className="field">
            <input className="input mono" placeholder="host:puerto" value={server} onChange={(e) => setServer(e.target.value)} disabled={running} />
            {running ? <button className="btn ghost" onClick={stop}>■ {t('Detener')}</button> : <button className="btn" onClick={run} disabled={!server.trim()}>▶ {t('Medir')}</button>}
          </div>
          <div className="field" style={{ marginTop: 10 }}>
            <input
              className="input mono"
              placeholder={t('Código de acceso (si el servidor lo pide)')}
              value={clientCode}
              onChange={(e) => setClientCode(e.target.value)}
              disabled={running}
              maxLength={6}
            />
          </div>
          <div className="field-grid">
            <label>{t('Protocolo')}<select value={proto} onChange={(e) => setProto(e.target.value as Proto)} disabled={running}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
            <label>{t('Dirección')}<select value={direction} onChange={(e) => setDirection(e.target.value as Direction)} disabled={running}><option value="download">{t('Descarga')}</option><option value="upload">{t('Subida')}</option><option value="bidir">{t('Bidireccional')}</option></select></label>
            <label>{t('Duración (s)')}<input type="number" min={1} max={300} value={duration} onChange={(e) => setDuration(+e.target.value)} disabled={running} /></label>
            {proto === 'tcp' ? <label>Streams<input type="number" min={1} max={32} value={streams} onChange={(e) => setStreams(+e.target.value)} disabled={running} /></label> : <label>{t('Objetivo Mbps')}<input type="number" min={1} max={100000} value={targetMbps} onChange={(e) => setTargetMbps(+e.target.value)} disabled={running} /></label>}
            <label>Buffer KB<input type="number" min={1} max={1024} value={bufferKB} onChange={(e) => setBufferKB(+e.target.value)} disabled={running} /></label>
            {proto === 'udp' && <label>{t('Paquete UDP')}<input type="number" min={32} max={65507} value={udpPacket} onChange={(e) => setUDPPacket(+e.target.value)} disabled={running} /></label>}
          </div>
        </div>
      </div>

      {error && <div className="note">{error}</div>}
      {running && (
        <div className="card throughput-running">
          <span className="spin" /> {t('Midiendo {proto} {direction} contra {server}', { proto: proto.toUpperCase(), direction: t(direction === 'download' ? 'Descarga' : direction === 'upload' ? 'Subida' : 'Bidireccional'), server })}
          {' · '}{(elapsedMs / 1000).toFixed(1)}s / {duration}s
        </div>
      )}
      {result && (
        <div className="grid cols-2" style={{ marginTop: 16 }}>
          <ResultCard title={t('Descarga')} value={result.downStream} />
          <ResultCard title={t('Subida')} value={result.upStream} />
        </div>
      )}
    </div>
  );
}
