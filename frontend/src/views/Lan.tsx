import { useEffect, useRef, useState } from 'react';
import { lanDiscover, backendAvailable, wifiAvailable, wifiScan, wifiPosture, lanTrustAssess, type LanReport, type LanHostResult, type LanTrustResult, type WifiPostureResult, type wifi } from '../lib/api';
import CopyButton from '../components/CopyButton';
import { useCaptureSession } from '../lib/session';
import { useI18n } from '../lib/i18n';
import { csvEscape } from '../lib/csv';

// Derives the network subnet (e.g. "192.168.1.0/24") from an interface
// address in "ip/prefix" form (what Go's net.Interface.Addrs() returns) —
// the scanner wants the network, not the host's own address.
function subnetOf(ipCidr: string): string | null {
  const [ip, bitsStr] = ipCidr.split('/');
  const bits = Number(bitsStr);
  const octets = (ip || '').split('.').map(Number);
  if (octets.length !== 4 || octets.some((o) => Number.isNaN(o) || o < 0 || o > 255)) return null;
  if (!Number.isFinite(bits) || bits < 0 || bits > 32) return null;
  const ipNum = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const netNum = (ipNum & mask) >>> 0;
  const netOctets = [(netNum >>> 24) & 255, (netNum >>> 16) & 255, (netNum >>> 8) & 255, netNum & 255];
  return `${netOctets.join('.')}/${bits}`;
}

// Advisory only (never blocks the scan) — surfaces the same kind of
// authorization reminder Live Capture already shows for promiscuous mode.
// A LAN scanner sending ICMP/TCP connect to a range you don't own or
// administer needs the same authorization any active probing does; this
// just makes that visible when the typed range isn't a private/loopback
// one, instead of assuming every range is "your LAN".
function looksPrivateRange(spec: string): boolean {
  const m = spec.match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
  if (!m) return true; // can't confidently parse — don't nag on ambiguous input
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local
  return false;
}

function hostsToCSV(hosts: LanHostResult[]): string {
  const header = 'ip,estado,hostname,mac,fabricante,rttMs,puertosAbiertos,soEstimado,interfaz';
  const rows = hosts.map((h) =>
    [
      h.ip,
      h.up ? 'activo' : 'sin respuesta',
      h.hostname || '',
      h.mac || '',
      h.vendor || '',
      h.rttMs != null ? String(h.rttMs) : '',
      (h.openPorts || []).map((p) => p.port + (p.service ? '/' + p.service : '')).join(' '),
      h.osGuess || '',
      h.iface || '',
    ]
      .map((v) => csvEscape(String(v)))
      .join(','),
  );
  return [header, ...rows].join('\n');
}

function normMac(mac: string): string {
  return mac.trim().toLowerCase();
}

function signalClass(pct: number): string {
  if (pct >= 60) return 'ok';
  if (pct >= 30) return 'warn';
  return 'bad';
}

// bandOf normalizes a network's band, falling back to a channel-number guess
// for entries without one (band ships with channel since the same scan, so
// this only matters for hidden/partial entries).
function bandOf(n: wifi.Network): string {
  if (n.band) return n.band;
  if (!n.channel) return '';
  return n.channel <= 14 ? '2.4 GHz' : '5 GHz';
}

interface ChannelAdvice {
  band: string;
  channel: number;
  reason: string;
}

// analyzeChannels recommends the least-congested channel per band using only
// what the scan actually saw (beacons + signal strength). 2.4 GHz channels
// overlap ±4, so a strong network on channel 8 also degrades 6 and 11 — the
// score weights each network by signal and by how much it overlaps the
// candidate. 5/6 GHz channels don't overlap that way, so there it's simply
// the least-occupied (weighted by signal) among common channels.
function analyzeChannels(networks: wifi.Network[]): ChannelAdvice[] {
  const advice: ChannelAdvice[] = [];

  const nets24 = networks
    .filter((n) => bandOf(n) === '2.4 GHz' && (n.channel ?? 0) > 0)
    .map((n) => ({ channel: n.channel ?? 0, signalPct: n.signalPct }));
  if (nets24.length > 0) {
    let best = 1;
    let bestScore = Infinity;
    for (const cand of [1, 6, 11]) {
      let score = 0;
      for (const n of nets24) {
        const diff = Math.abs(n.channel - cand);
        if (diff < 5) score += n.signalPct * (1 - diff / 5);
      }
      if (score < bestScore) {
        bestScore = score;
        best = cand;
      }
    }
    const onBest = nets24.filter((n) => Math.abs(n.channel - best) < 5).length;
    advice.push({
      band: '2.4 GHz',
      channel: best,
      reason: onBest === 0
        ? 'sin redes detectadas que lo interfieran'
        : `menor interferencia ponderada entre 1/6/11 (${onBest} red${onBest === 1 ? '' : 'es'} cercana${onBest === 1 ? '' : 's'} lo solapan)`,
    });
  }

  const common5 = [36, 40, 44, 48, 149, 153, 157, 161];
  const nets5 = networks
    .filter((n) => bandOf(n) === '5 GHz' && (n.channel ?? 0) > 0)
    .map((n) => ({ channel: n.channel ?? 0, signalPct: n.signalPct }));
  if (nets5.length > 0) {
    let best = common5[0];
    let bestScore = Infinity;
    for (const cand of common5) {
      const score = nets5.filter((n) => n.channel === cand).reduce((s, n) => s + n.signalPct, 0);
      if (score < bestScore) {
        bestScore = score;
        best = cand;
      }
    }
    advice.push({
      band: '5 GHz',
      channel: best,
      reason: bestScore === 0 ? 'libre entre las redes detectadas' : 'el menos ocupado entre los canales comunes detectables',
    });
  }

  return advice;
}

// WifiPanel scans nearby WiFi networks via Windows' own WLAN API (no
// monitor mode, no special hardware — see internal/wifi). It's a quick,
// on-demand lookup (not a long-running session), so state stays local to
// this component instead of living in CaptureSessionProvider.
function WifiPanel() {
  const { t } = useI18n();
  const [available, setAvailable] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(false);
  const [networks, setNetworks] = useState<wifi.Network[] | null>(null);
  const [error, setError] = useState<string | null>(null);
	const [posture, setPosture] = useState<WifiPostureResult | null>(null);

  useEffect(() => {
    if (!backendAvailable()) {
      setAvailable(false);
      return;
    }
    wifiAvailable().then(setAvailable);
  }, []);

  async function scan() {
    setLoading(true);
    setError(null);
    try {
      const found = await wifiScan();
			setNetworks(found);
			setPosture(await wifiPosture(found));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  if (available === false) return null; // non-Windows build or no runtime — nothing to show

  return (
    <div className="card pad-lg" style={{ marginTop: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
        <div>
          <h3 style={{ margin: 0 }}>{t('Redes WiFi cercanas')}</h3>
          <p className="dim" style={{ fontSize: 11.5, marginTop: 4 }}>
            {t('Lee el resultado de escaneo almacenado por Windows, el mismo que usa el selector WiFi del sistema. No requiere modo monitor ni hardware especial y se actualiza aproximadamente cada 60 segundos.')}
          </p>
        </div>
        <button className="btn ghost" onClick={scan} disabled={loading}>{loading ? <span className="spin" /> : '📶'} {t('Escanear')}</button>
      </div>
      {error && (
        <div className="note" style={{ marginTop: 10 }}>
          {error}
          {error.includes('Ubicación') && (
            <div style={{ marginTop: 6 }}>
              <span className="mono" style={{ fontSize: 11.5 }}>ms-settings:privacy-location</span>
            </div>
          )}
        </div>
      )}
      {networks && (
        networks.length === 0 ? (
          <p className="dim" style={{ marginTop: 10 }}>{t('No se detectaron redes.')}</p>
        ) : (
          <>
          {analyzeChannels(networks).length > 0 && (
            <div className="note" style={{ marginTop: 10 }}>
              <strong>{t('Canal recomendado para tu router')}:</strong>
              {analyzeChannels(networks).map((a) => (
                <div key={a.band} style={{ marginTop: 4, fontSize: 12.5 }}>
                  {a.band}: <strong>{t('canal')} {a.channel}</strong> — {a.reason}
                </div>
              ))}
              <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>
                {t('La recomendación se basa en las redes visibles desde este adaptador. La congestión puede variar en otras zonas de la casa u oficina.')}
              </div>
            </div>
          )}
          <div className="hop-list" style={{ marginTop: 10 }}>
            {networks.map((n, i) => (
              <div className="hop-row" key={n.ssid + i}>
                <span className={'pill ' + signalClass(n.signalPct)}><span className="dot" /> {n.signalPct}%</span>
                <span className="hop-host mono">{n.ssid || '(oculta)'}</span>
                <span className="dim" style={{ fontSize: 11 }}>
                  {n.security}{n.channel ? ` · canal ${n.channel}${bandOf(n) ? ` (${bandOf(n)})` : ''}` : ''}{n.rssiDbm ? ` · ${n.rssiDbm} dBm` : ''}{n.apCount > 1 ? ` · ${n.apCount} APs` : ''}
                </span>
                {n.bssid && <span className="dim mono" style={{ fontSize: 11, marginLeft: 'auto' }}>{n.bssid}</span>}
              </div>
            ))}
          </div>
          </>
        )
      )}
		{posture && (
			<div className="note" style={{marginTop:10,borderColor:posture.score>=85?'var(--ok)':posture.score>=60?'var(--warn)':'var(--danger)'}}>
				<strong>{t('Postura WiFi')}: {posture.score}/100</strong> · {t('{count} señales', { count: posture.findings.length })}
				{posture.baselineCreated&&<div className="dim" style={{fontSize:11}}>{t('Primera observación: se creó localmente la línea base de BSSID.')}</div>}
				{posture.findings.map((f,i)=><div key={i} style={{fontSize:12,marginTop:4}}><span className={'tag '+(f.level==='high'?'vpn':'reserved')}>{f.level}</span> <strong>{f.ssid||'(oculta)'}</strong> · {f.summary}{f.evidence?` · ${f.evidence}`:''}</div>)}
			</div>
		)}
    </div>
  );
}

export default function Lan() {
  const { t } = useI18n();
  // ---- Passive discovery (existing, unchanged behavior) ----
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<LanReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function discover() {
    if (!backendAvailable()) {
      setError(t('Necesita el runtime Wails (app de escritorio).'));
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const r = await lanDiscover();
      setReport(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  const activeIfaces = report?.interfaces.filter((i) => i.up && !i.loopback && i.addrs.length > 0) ?? [];

  // ---- Active scan — state lives in CaptureSessionProvider so leaving this
  // tab mid-scan no longer orphans the running backend scan, and the last
  // results stay visible from Overview too. ----
  const {
    lanScanRange: rangeSpec, lanScanIface: ifaceLabel, lanScanRunning: scanRunning,
    lanScanHosts: scanHosts, lanScanProgress: scanProgress, lanScanSummary: scanSummary,
    lanScanError, startLanScanSession, stopLanScanSession, clearLanScan,
    pendingLanRange, setPendingLanRange,
  } = useCaptureSession();
  const [rangeInput, setRangeInput] = useState(rangeSpec);
  const [ifaceInput, setIfaceInput] = useState(ifaceLabel);
  const [detecting, setDetecting] = useState(false);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [subnetCandidates, setSubnetCandidates] = useState<{ iface: string; subnet: string }[]>([]);
	const [trust, setTrust] = useState<LanTrustResult | null>(null);
  const scanError = dialogError ?? lanScanError;

  // ---- New-device detection: compare each finished scan's MACs against the
  // locally remembered set. First scan ever seeds the registry silently
  // (everything would be "new", which tells the user nothing). ----
  const prevScanRunning = useRef(scanRunning);
  useEffect(() => {
    const justFinished = prevScanRunning.current && !scanRunning;
    prevScanRunning.current = scanRunning;
    if (!justFinished || scanHosts.length === 0) return;
		lanTrustAssess(scanHosts).then(setTrust).catch((e)=>setDialogError(String(e)));
  }, [scanRunning, scanHosts]);
	const newMacs = new Set((trust?.findings??[]).filter((f)=>f.kind==='new_device'||f.kind==='identity_changed').map((f)=>f.mac&&normMac(f.mac)).filter(Boolean) as string[]);

  // Pick up a range handed over by the IP calculator ("Escanear →") and clear
  // it immediately so it applies once, not on every future visit to this tab.
  useEffect(() => {
    if (!pendingLanRange) return;
    setRangeInput(pendingLanRange);
    setPendingLanRange(null);
  }, [pendingLanRange, setPendingLanRange]);

  async function detectNetworks() {
    if (!backendAvailable()) return setDialogError(t('Necesita el runtime Wails (app de escritorio).'));
    setDetecting(true);
    try {
      let r = report;
      if (!r) {
        r = await lanDiscover();
        setReport(r);
      }
      const ifaces = r.interfaces.filter((i) => i.up && !i.loopback);
      const raw = ifaces.flatMap((i) => i.addrs.map((a) => ({ iface: i.name, subnet: subnetOf(a) })).filter((c): c is { iface: string; subnet: string } => !!c.subnet && c.subnet.includes('.')));
      // De-duplicate (an interface can report the same /24 twice under IPv4 aliases).
      const seen = new Set<string>();
      const candidates = raw.filter((c) => {
        const key = `${c.iface}|${c.subnet}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
      setSubnetCandidates(candidates);
      if (candidates[0]) {
        setRangeInput(candidates[0].subnet);
        setIfaceInput(candidates[0].iface);
      } else {
        setDialogError(t('No se detectó ninguna red IPv4 activa. Introduce el rango manualmente.'));
      }
    } catch (e) {
      setDialogError(String(e));
    } finally {
      setDetecting(false);
    }
  }

  function pickSubnet(c: { iface: string; subnet: string }) {
    setRangeInput(c.subnet);
    setIfaceInput(c.iface);
  }

  async function startActiveScan() {
    if (!backendAvailable()) return setDialogError(t('Necesita el runtime Wails (app de escritorio).'));
    if (!rangeInput.trim()) return;
    setDialogError(null);
    await startLanScanSession(rangeInput.trim(), ifaceInput);
  }

  function stopActiveScan() {
    stopLanScanSession();
  }

  const progressPct = scanProgress && scanProgress.total > 0 ? Math.round((scanProgress.scanned / scanProgress.total) * 100) : 0;

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('LAN Explorer')}</h2>
        <p className="body-text">
          {t('Escaneo activo por CIDR o rango: barrido ICMP, hostname, MAC/fabricante, puertos TCP comunes y sistema operativo estimado por TTL — o vista pasiva de interfaces y tabla ARP/NDP del sistema, sin enviar nada.')}
        </p>
      </div>

      <WifiPanel />

      <div className="card pad-lg" style={{ marginTop: 16 }}>
        <h3>{t('Escaneo activo')}</h3>
        <div className="field">
          <input
            className="input mono"
            placeholder="192.168.1.0/24 o 192.168.1.1-192.168.1.254"
            value={scanRunning ? rangeSpec : rangeInput}
            onChange={(e) => setRangeInput(e.target.value)}
            disabled={scanRunning}
          />
          <button className="btn ghost" onClick={detectNetworks} disabled={scanRunning || detecting}>
            {detecting ? <span className="spin" /> : '📡'} {t('Detectar redes')}
          </button>
          {scanRunning ? (
            <button className="btn ghost" onClick={stopActiveScan}>■ {t('Detener')}</button>
          ) : (
            <button className="btn" onClick={startActiveScan} disabled={!rangeInput.trim()}>▶ {t('Escanear')}</button>
          )}
          {!scanRunning && scanHosts.length > 0 && <button className="btn ghost" onClick={clearLanScan}>🗑 {t('Limpiar')}</button>}
        </div>
        {subnetCandidates.length > 1 && !scanRunning && (
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 8 }}>
            {subnetCandidates.map((c) => (
              <button
                key={`${c.iface}|${c.subnet}`}
                className={'tag' + (rangeInput === c.subnet && ifaceInput === c.iface ? ' active' : '')}
                onClick={() => pickSubnet(c)}
                title={t('Usar {subnet} ({interface})', { subnet: c.subnet, interface: c.iface })}
              >
                {c.iface} → {c.subnet}
              </button>
            ))}
          </div>
        )}
        {(scanRunning ? ifaceLabel : ifaceInput) && (
          <p className="dim" style={{ fontSize: 11.5, marginTop: 6 }}>{t('Interfaz sugerida: {interface}', { interface: scanRunning ? ifaceLabel : ifaceInput })}</p>
        )}
        <p className="dim" style={{ fontSize: 11.5, marginTop: 6 }}>
          {t('Máximo de 4096 direcciones por ejecución. El escaneo continúa en segundo plano y puedes detenerlo en cualquier momento.')}
        </p>
        {!scanRunning && rangeInput.trim() && !looksPrivateRange(rangeInput) && (
          <p className="note" style={{ fontSize: 11.5, marginTop: 8 }}>
            ⚠ {t('"{range}" no parece un rango privado/local (RFC 1918). El escaneo enviará ICMP y conexiones TCP a esas direcciones. Escanea únicamente redes que administres o para las que tengas autorización explícita.', { range: rangeInput.trim() })}
          </p>
        )}

        {(scanRunning || scanProgress) && (
          <div style={{ marginTop: 12 }}>
            <div style={{ height: 6, borderRadius: 4, background: 'var(--border)', overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${progressPct}%`, background: 'var(--accent)', transition: 'width 0.2s' }} />
            </div>
            <p className="dim" style={{ fontSize: 11.5, marginTop: 6 }}>
              {t('{scanned} / {total} direcciones probadas', { scanned: scanProgress?.scanned ?? 0, total: scanProgress?.total ?? 0 })}
              {scanRunning && <span className="spin" style={{ marginLeft: 8 }} />}
            </p>
          </div>
        )}
      </div>

      {scanError && <div className="note">{scanError}</div>}

      {(scanHosts.length > 0 || scanSummary) && (
        <div className="card" style={{ marginTop: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
            <h3 style={{ margin: 0 }}>
              {t('Dispositivos encontrados ({found} de {total} probadas)', { found: scanHosts.length, total: scanSummary?.totalIPs ?? scanHosts.length })}
            </h3>
            <div style={{ display: 'flex', gap: 8 }}>
              <CopyButton label={t('Copiar CSV')} disabled={scanHosts.length === 0} getText={() => hostsToCSV(scanHosts)} />
              <button
                className="btn ghost"
                disabled={scanHosts.length === 0}
                onClick={() => {
                  const blob = new Blob([hostsToCSV(scanHosts)], { type: 'text/csv' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `trazip-lan-scan-${Date.now()}.csv`;
                  a.click();
                  URL.revokeObjectURL(url);
                }}
              >
                ⬇ {t('Descargar CSV')}
              </button>
            </div>
          </div>
				{trust && (
					<div className="note" style={{marginTop:10,borderColor:trust.findings.some((f)=>f.level==='high')?'var(--danger)':'var(--border)'}}>
						<strong>{t('Monitor de confianza LAN')}:</strong> {t('{known} identidades conocidas · {changes} cambios', { known: trust.knownDevices, changes: trust.findings.length })}
						{trust.baselineCreated&&<div className="dim" style={{fontSize:11}}>{t('Se creó una línea base persistente en el almacenamiento local de TRAZIP.')}</div>}
						{trust.findings.map((f,i)=><div key={i} style={{fontSize:12,marginTop:4}}><span className={'tag '+(f.level==='high'?'vpn':'reserved')}>{f.kind}</span> <span className="mono">{f.ip||f.identity}</span> · {f.summary}{f.evidence?` · ${f.evidence}`:''}</div>)}
					</div>
				)}
          <div className="mtr-table-wrap" style={{ marginTop: 10 }}>
            <table className="mtr-table">
              <thead>
                <tr>
                  <th className="l">IP</th>
                  <th className="l">{t('Estado')}</th>
                  <th className="l">Hostname</th>
                  <th className="l">MAC</th>
                  <th className="l">{t('Fabricante')}</th>
                  <th>RTT</th>
                  <th className="l">{t('Puertos abiertos')}</th>
                  <th className="l">{t('SO estimado')}</th>
                  <th className="l">{t('Interfaz')}</th>
                </tr>
              </thead>
              <tbody>
                {scanHosts.map((h) => (
                  <tr key={h.ip}>
                    <td className="l mono">{h.ip}</td>
                    <td className="l"><span className="tag private">{t('activo')}</span></td>
                    <td className="l">{h.hostname || <span className="dim">—</span>}</td>
                    <td className="l mono dim">
                      {h.mac || '—'}
                      {h.mac && newMacs.has(normMac(h.mac)) && <span className="tag bogon" style={{ marginLeft: 6 }}>{t('NUEVO')}</span>}
                    </td>
                    <td className="l">{h.vendor || <span className="dim">{t('desconocido')}</span>}</td>
                    <td className="dim">{h.rttMs != null ? `${h.rttMs.toFixed(1)}ms` : '—'}</td>
                    <td className="l">
                      {(h.openPorts || []).length === 0
                        ? <span className="dim">{t('ninguno detectado')}</span>
                        : h.openPorts!.map((p) => (
                            <span key={p.port} className="tag" style={{ marginRight: 4 }} title={p.service || ''}>{p.port}</span>
                          ))}
                    </td>
                    <td className="l dim" style={{ fontSize: 11.5 }}>{h.osGuess || '—'}</td>
                    <td className="l dim">{h.iface || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="section-title" style={{ marginTop: 24 }}>{t('Vista pasiva (ARP/NDP del sistema)')}</div>
      <div className="card">
        <button className="btn ghost" onClick={discover} disabled={loading}>
          {loading ? <span className="spin" /> : '⟳'} {t('Leer tabla ARP/NDP')}
        </button>
      </div>

      {error && <div className="note">{error}</div>}
      {report?.note && <div className="note">{report.note}</div>}

      {report && (
        <>
          <div className="section-title">{t('Interfaces activas')}</div>
          <div className="grid cols-2">
            {activeIfaces.map((it) => (
              <div className="card" key={it.name}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong>{it.name}</strong>
                  <span className="tag public">up</span>
                </div>
                <div className="kv"><span className="k">MAC</span><span className="v">{it.mac || '—'}</span></div>
                {it.vendor && <div className="kv"><span className="k">{t('Fabricante')}</span><span className="v">{it.vendor}</span></div>}
                <div className="kv"><span className="k">MTU</span><span className="v">{it.mtu}</span></div>
                {it.addrs.map((a) => (
                  <div className="kv" key={a}><span className="k">IP</span><span className="v">{a}</span></div>
                ))}
              </div>
            ))}
          </div>

          <div className="section-title">{t('Vecinos (tabla ARP/NDP)')} — {report.neighbors.length}</div>
          <div className="card">
            {report.neighbors.length === 0 ? (
              <div className="empty"><div className="big">⌂</div>{t('No hay vecinos en la tabla del sistema.')}</div>
            ) : (
              <div className="mtr-table-wrap">
                <table className="mtr-table">
                  <thead>
                    <tr>
                      <th className="l">IP</th>
                      <th className="l">MAC</th>
                      <th className="l">{t('Fabricante')}</th>
                      <th className="l">{t('Tipo')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.neighbors.map((n) => (
                      <tr key={n.ip + n.mac}>
                        <td className="l mono">{n.ip}</td>
                        <td className="l mono dim">{n.mac}</td>
                        <td className="l">{n.vendor || <span className="dim">{t('desconocido')}</span>}</td>
                        <td className="l dim">{n.type}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
