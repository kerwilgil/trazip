import { useEffect, useState } from 'react';
import {
  backendAvailable,
  voipQualityAddTarget,
  voipQualityListTargets,
  voipQualityRemoveTarget,
  voipQualityHistory,
  voipQualityCompareWindows,
  investigationAddVoIPCall,
  type voip,
  type quality,
} from '../lib/api';
import { useCaptureSession } from '../lib/session';
import CallFlowDiagram from '../components/CallFlowDiagram';
import VoipCallSummary from '../components/VoipCallSummary';
import VoipDiagnosis from '../components/VoipDiagnosis';
import RtpQualityPanel from '../components/RtpQualityPanel';
import CallAudioPanel from '../components/CallAudioPanel';
import RtcpQualityPanel from '../components/RtcpQualityPanel';
import SdpNegotiation from '../components/SdpNegotiation';
import VoipAdvanced from '../components/VoipAdvanced';
import AddToInvestigation from '../components/AddToInvestigation';
import { useI18n } from '../lib/i18n';

const NO_BACKEND = 'Necesita el runtime Wails (app de escritorio). En el preview del navegador no hay backend.';

// Mirrors internal/voip/thresholds.go's mosLowScore/mosPoorScore — see
// RtpQualityPanel's mosClass for why these stay hardcoded rather than a
// shared config, and why the VALUES must still match Diagnose's own.
function mosClass(score?: number): string {
  if (score === undefined) return '';
  if (score < 2.5) return 'bad'; // mosPoorScore
  if (score < 3.5) return 'warn'; // mosLowScore
  return 'ok';
}

function callState(call: voip.Call): { label: string; cls: string } {
  if (call.established) return { label: 'Establecida', cls: 'ok' };
  if (call.failureCode || call.failureReason) return { label: 'Fallida', cls: 'danger' };
  return { label: 'Incompleta', cls: 'warn' };
}

function CallTimeline({ timeline }: { timeline: voip.TimelineEvent[] }) {
  const { t } = useI18n();
  if (!timeline || timeline.length === 0) return null;
  return (
    <div className="hop-list">
      {timeline.map((ev, i) => (
        <div className="hop-row" key={i}>
          <span className="hop-ttl">{i + 1}</span>
          <span className="hop-host">
            <span className="mono">{ev.src} → {ev.dst}</span>
            <span className="hop-ip">{ev.summary}</span>
          </span>
          {ev.retransmission && <span className="tag vpn">{t('retransmisión')}</span>}
        </div>
      ))}
    </div>
  );
}

function CallCard({ pcapPath, call }: { pcapPath: string; call: voip.Call }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const state = callState(call);

  return (
    <div className="card" style={{ marginTop: 10 }}>
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 14, cursor: 'pointer' }}
        onClick={() => setOpen((v) => !v)}
      >
        <span className={'pill ' + (state.cls === 'ok' ? 'ok' : state.cls === 'danger' ? 'danger' : 'warn')}>
          <span className="dot" /> {t(state.label)}
        </span>
        <span className="mono" style={{ fontWeight: 700 }}>
          {call.from || '?'} → {call.to || '?'}
        </span>
        <span className="dim" style={{ fontSize: 12, marginLeft: 'auto' }}>
          {call.setupMs !== undefined && `setup ${call.setupMs} ms`}
          {call.durationSec !== undefined && ` · dur ${call.durationSec.toFixed(1)}s`}
          {call.retransmissions > 0 && ` · ${call.retransmissions} retx`}
          {call.natIssue && ` · ${t('posible NAT')}`}
          {call.unidirectional && ` · ${t('audio unidireccional')}`}
        </span>
        <span className="dim">{open ? '▲' : '▼'}</span>
      </div>

      {/* Visible whether or not the card is expanded: the one-line conclusion
          is the fast-scan answer to "how did this call go", and it comes
          straight from the backend Diagnosis so it never disagrees with the
          full evidence panel below (§10/§16 — one judgement, one source). */}
      {call.diagnosis && (
        <div className="note" style={{ marginTop: 10 }}>
          <strong>{t('Diagnóstico')}:</strong> {t(call.diagnosis.conclusion)}
        </div>
      )}

      {open && (
        <div style={{ marginTop: 14 }}>
          <VoipCallSummary call={call} />
          <VoipDiagnosis diagnosis={call.diagnosis} />

          {call.diagnosis && (
            <div style={{ marginTop: 8 }}>
              <AddToInvestigation onAdd={(id) => investigationAddVoIPCall(id, call)} />
            </div>
          )}

          {call.streams && call.streams.length > 0 && (
            <>
              <h3 style={{ marginTop: 16 }}>{t('Calidad RTP')}</h3>
              <div className="grid cols-2">
                {call.streams.map((s, i) => (
                  <RtpQualityPanel key={i} stream={s} pcapPath={pcapPath} label={`${s.src} → ${s.dst}`} />
                ))}
              </div>
              <CallAudioPanel pcapPath={pcapPath} call={call} />
              {call.streams.some((s) => s.mos) && (
                <p className="dim" style={{ fontSize: 11, marginTop: 8 }}>
                  {t('MOS estimado mediante un modelo E simplificado con constantes G.711 de ITU-T G.113, apéndice I. No incluye el retardo unidireccional medido; consulta las limitaciones en el informe técnico.')}
                </p>
              )}

              <h3 style={{ marginTop: 16 }}>{t('Calidad reportada por RTCP')}</h3>
              <div className="grid cols-2">
                {call.streams.map((s, i) => (
                  <RtcpQualityPanel key={i} stream={s} label={`${s.src} → ${s.dst}`} />
                ))}
              </div>
            </>
          )}

          <h3 style={{ marginTop: 16 }}>{t('Señalización SIP')}</h3>
          <CallFlowDiagram call={call} />
          <h4 style={{ marginTop: 14, fontSize: 12.5 }}>{t('Registro')}</h4>
          <CallTimeline timeline={call.timeline} />

          {(call.sdpOffer || call.sdpAnswer) && (
            <>
              <h3 style={{ marginTop: 16 }}>{t('Negociación SDP')}</h3>
              <SdpNegotiation call={call} />
            </>
          )}

          <VoipAdvanced call={call} />
        </div>
      )}
    </div>
  );
}

// QualityChart plots MOS across a línea's call samples — a simple index-based
// SVG line chart (not time-based: calls land irregularly, so a real time axis
// would leave most of the width empty). Same hand-built-SVG convention as
// PingMTR.tsx's LatencyChart, scaled down for this narrower use.
function QualityChart({ samples }: { samples: quality.Sample[] }) {
  const { t } = useI18n();
  const withMos = samples
    .filter((s) => s.mos !== undefined && s.mos > 0)
    .map((s) => ({ ...s, mos: s.mos as number }));
  if (withMos.length < 2) return null;
  const width = 760;
  const height = 140;
  const plot = { left: 34, right: 748, top: 12, bottom: 118 };
  const xFor = (i: number) => plot.left + (i / (withMos.length - 1)) * (plot.right - plot.left);
  const yFor = (mos: number) => plot.bottom - (Math.min(Math.max(mos, 1), 5) - 1) / 4 * (plot.bottom - plot.top);
  const line = withMos.map((s, i) => `${i === 0 ? 'M' : 'L'} ${xFor(i).toFixed(1)} ${yFor(s.mos).toFixed(1)}`).join(' ');

  return (
    <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={t('MOS a través del tiempo')} style={{ width: '100%', height: 'auto' }}>
      {[1, 2, 3, 4, 5].map((v) => (
        <g key={v}>
          <line x1={plot.left} y1={yFor(v)} x2={plot.right} y2={yFor(v)} stroke="var(--border)" strokeWidth={1} />
          <text x={plot.left - 8} y={yFor(v) + 4} textAnchor="end" fontSize={10} fill="var(--text-dim)">{v}</text>
        </g>
      ))}
      <path d={line} fill="none" stroke="var(--accent)" strokeWidth={2} />
      {withMos.map((s, i) => (
        <circle key={i} cx={xFor(i)} cy={yFor(s.mos)} r={9} fill="transparent" style={{ cursor: 'crosshair' }}>
          <title>{`${s.time.slice(0, 19).replace('T', ' ')}\nMOS: ${s.mos.toFixed(2)}\nJitter: ${s.avgJitterMs.toFixed(1)} ms\nPérdida: ${s.avgLossPct.toFixed(1)}%\nLlamada: ${s.callId}`}</title>
        </circle>
      ))}
      {withMos.map((s, i) => (
        <circle key={'dot-' + i} cx={xFor(i)} cy={yFor(s.mos)} r={3} fill="var(--accent)" />
      ))}
    </svg>
  );
}

function QualityHistoryPanel() {
  const { t } = useI18n();
  // A finished analysis ingests new samples backend-side; watching the shared
  // voipResult means the selected línea's chart refreshes itself instead of
  // requiring the user to reopen the panel.
  const { voipResult } = useCaptureSession();
  const [targets, setTargets] = useState<quality.Target[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [samples, setSamples] = useState<quality.Sample[]>([]);
  const [comparison, setComparison] = useState<quality.WindowComparison | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [label, setLabel] = useState('');
  const [match, setMatch] = useState('');

  const refreshTargets = async () => {
    if (!backendAvailable()) return;
    try {
      setTargets(await voipQualityListTargets());
    } catch (e) {
      setError(String(e));
    }
  };

  useEffect(() => {
    refreshTargets();
  }, []);

  useEffect(() => {
    if (!voipResult || !selected) return;
    void select(selected);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [voipResult]);

  async function addTarget() {
    if (!backendAvailable()) return setError(NO_BACKEND);
    if (!label.trim() || !match.trim()) return;
    setError(null);
    try {
      await voipQualityAddTarget({ label: label.trim(), match: match.trim() });
      setLabel('');
      setMatch('');
      await refreshTargets();
    } catch (e) {
      setError(String(e));
    }
  }

  async function removeTarget(id: string) {
    try {
      await voipQualityRemoveTarget(id);
      if (selected === id) {
        setSelected(null);
        setSamples([]);
        setComparison(null);
      }
      await refreshTargets();
    } catch (e) {
      setError(String(e));
    }
  }

  async function select(id: string) {
    setSelected(id);
    setComparison(null);
    setError(null);
    try {
      const h = await voipQualityHistory(id, 0);
      setSamples(h.samples ?? []);
    } catch (e) {
      setError(String(e));
    }
  }

  async function compare(id: string) {
    try {
      setComparison(await voipQualityCompareWindows(id, 60 * 60 * 1000));
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div style={{ marginTop: 24 }}>
      <h3>{t('Histórico de calidad')}</h3>
      <p className="dim" style={{ fontSize: 12, marginBottom: 10 }}>
        {t('Cada línea agrupa llamadas mediante un patrón de texto aplicado a los campos From/To. Cada captura VoIP analizada actualiza el historial de las líneas coincidentes, aunque esta pestaña no esté abierta.')}
      </p>

      <div className="card">
        <div className="field">
          <input className="input" placeholder={t('Etiqueta (por ejemplo, Oficina Panamá)')} value={label} onChange={(e) => setLabel(e.target.value)} style={{ maxWidth: 200 }} />
          <input className="input" placeholder={t('Patrón (por ejemplo, sip.miclientes.com)')} value={match} onChange={(e) => setMatch(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && addTarget()} />
          <button className="btn" onClick={addTarget} disabled={!label.trim() || !match.trim()}>+ {t('Agregar línea')}</button>
        </div>
      </div>

      {error && <div className="note">{error}</div>}

      <div className="card" style={{ marginTop: 12 }}>
        {targets.length === 0 ? (
          <p className="dim">{t('Todavía no hay líneas registradas.')}</p>
        ) : (
          <div className="hop-list">
            {targets.map((target) => (
              <div className={'hop-row' + (selected === target.id ? ' reached' : '')} key={target.id} style={{ cursor: 'pointer' }} onClick={() => select(target.id)}>
                <span className="hop-host mono">{target.label}</span>
                <span className="dim" style={{ fontSize: 11 }}>{t('coincide')}: {target.match}</span>
                <span style={{ marginLeft: 'auto' }} onClick={(e) => e.stopPropagation()}>
                  <button className="btn ghost" style={{ padding: '3px 10px', fontSize: 12 }} onClick={() => removeTarget(target.id)}>🗑</button>
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {selected && (
        <>
          <div className="grid cols-3" style={{ marginTop: 12 }}>
            <div className="card stat">
              <span className="label">{t('Llamadas')}</span>
              <span className="value accent">{samples.length}</span>
              <span className="sub">{t('en esta línea')}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('MOS promedio')}</span>
              <span className="value">
                {samples.filter((s) => s.mos).length
                  ? (samples.reduce((sum, s) => sum + (s.mos || 0), 0) / samples.filter((s) => s.mos).length).toFixed(2)
                  : '—'}
              </span>
              <span className="sub">{t('de las llamadas con estimación')}</span>
            </div>
            <div className="card stat">
              <span className="sub" style={{ marginTop: 0 }}>
                <button className="btn ghost" onClick={() => compare(selected)}>{t('Comparar última hora')}</button>
              </span>
            </div>
          </div>

          {samples.length >= 2 && (
            <div className="card" style={{ marginTop: 12 }}>
              <h3 style={{ marginTop: 0 }}>{t('MOS a través del tiempo')}</h3>
              <QualityChart samples={samples} />
              {samples.filter((s) => s.mos).length < 2 && (
                <p className="dim" style={{ fontSize: 11 }}>{t('Se necesitan al menos dos llamadas con MOS estimado y 20 paquetes RTP o más para crear la gráfica.')}</p>
              )}
            </div>
          )}

          {comparison && (
            <div className="card" style={{ marginTop: 12 }}>
              <h3>{t('Comparación de ventanas (última hora frente a la anterior)')}</h3>
              <div className="grid cols-2">
                <div>
                  <p className="dim" style={{ fontSize: 12 }}>{t('Reciente')} ({comparison.recent.samples} {t('llamadas')})</p>
                  <p>Jitter: <strong>{comparison.recent.avgJitterMs.toFixed(1)} ms</strong> · {t('Pérdida')}: {comparison.recent.avgLossPct.toFixed(1)}% · MOS: {comparison.recent.avgMos.toFixed(2) || '—'}</p>
                </div>
                <div>
                  <p className="dim" style={{ fontSize: 12 }}>{t('Anterior')} ({comparison.previous.samples} {t('llamadas')})</p>
                  <p>Jitter: <strong>{comparison.previous.avgJitterMs.toFixed(1)} ms</strong> · {t('Pérdida')}: {comparison.previous.avgLossPct.toFixed(1)}% · MOS: {comparison.previous.avgMos.toFixed(2) || '—'}</p>
                </div>
              </div>
              <p className={comparison.deltaMos < 0 ? 'err' : 'dim'} style={{ marginTop: 8 }}>
                {t('Diferencia de jitter')}: {comparison.deltaJitterMs >= 0 ? '+' : ''}{comparison.deltaJitterMs.toFixed(1)} ms · {t('Diferencia de pérdida')}: {comparison.deltaLossPct >= 0 ? '+' : ''}{comparison.deltaLossPct.toFixed(1)}% · {t('Diferencia de MOS')}: {comparison.deltaMos >= 0 ? '+' : ''}{comparison.deltaMos.toFixed(2)}
              </p>
            </div>
          )}

          <div className="card" style={{ marginTop: 12 }}>
            <h3>{t('Llamadas registradas')}</h3>
            <div className="mtr-table-wrap pkt-scroll">
              <table className="mtr-table pkt-table">
                <thead><tr><th className="l">{t('Hora')}</th><th className="l">{t('Extremos')}</th><th>Jitter</th><th>{t('Pérdida')}</th><th>MOS</th></tr></thead>
                <tbody>
                  {samples.slice().reverse().slice(0, 200).map((s, i) => (
                    <tr key={i}>
                      <td className="l dim mono">{s.time.slice(0, 19).replace('T', ' ')}</td>
                      <td className="l mono" style={{ fontSize: 11.5 }}>{s.from || '?'} → {s.to || '?'}</td>
                      <td className="dim">{s.avgJitterMs.toFixed(1)} ms</td>
                      <td className={s.avgLossPct > 2 ? 'bad' : s.avgLossPct > 0 ? 'warn' : 'dim'}>{s.avgLossPct.toFixed(1)}%</td>
                      <td className={mosClass(s.mos)}>{s.mos ? s.mos.toFixed(2) : '—'}</td>
                    </tr>
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

export default function VoipCalls() {
  const { t } = useI18n();
  const { voipPath: path, voipResult: result, voipRunning: running, voipError, openVoip, stopVoip, clearVoip } = useCaptureSession();
  const [dialogError, setDialogError] = useState<string | null>(null);
  const error = dialogError ?? voipError;

  async function open() {
    if (!backendAvailable()) return setDialogError(NO_BACKEND);
    setDialogError(null);
    await openVoip();
  }

  function stop() {
    stopVoip();
  }

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('VoIP Calls')}</h2>
        <p className="body-text">
          {t('Correlaciona SIP/SDP/RTP/RTCP de una captura pasiva en llamadas: señalización, streams de audio, pérdida/jitter, MOS estimado y exportación de audio bajo demanda.')}
        </p>
      </div>

      <div className="card">
        <div className="field">
          <input className="input" placeholder={t('Ningún archivo abierto')} value={path} readOnly />
          {running ? (
            <button className="btn ghost" onClick={stop}>■ {t('Detener')}</button>
          ) : (
            <button className="btn" onClick={open}>📂 {t('Abrir captura')}</button>
          )}
          {path && !running && <button className="btn ghost" onClick={clearVoip}>🗑 {t('Cerrar')}</button>}
        </div>
      </div>

      {running && (
        <div className="card" style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="spin" /> {t('Correlacionando llamadas…')}
        </div>
      )}

      {error && <div className="note">{error}</div>}

      {result && (
        <>
          <div className="grid cols-4" style={{ marginTop: 16 }}>
            <div className="card stat">
              <span className="label">{t('Llamadas')}</span>
              <span className="value">{result.totalCalls}</span>
              <span className="sub">{t('detectadas')}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Establecidas')}</span>
              <span className="value accent">{result.established}</span>
              <span className="sub">{t('con RTP negociado')}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Fallidas')}</span>
              <span className={'value ' + (result.failed > 0 ? '' : 'accent')}>{result.failed}</span>
              <span className="sub">{t('sin completar')}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Éxito')}</span>
              <span className="value">
                {result.totalCalls > 0 ? Math.round((result.established / result.totalCalls) * 100) : 0}%
              </span>
              <span className="sub">{t('del total')}</span>
            </div>
          </div>

			{result.audit && (
				<div className="card" style={{marginTop:16}}>
					<h3 style={{marginTop:0}}>{t('Auditoría defensiva VoIP')}</h3>
					<p className="dim" style={{fontSize:12}}>{t('Evaluación pasiva del cifrado indicado por SDP, el transporte SIP observado, NAT, audio unidireccional, pérdida, MOS, retransmisiones y exposición DTMF. No realiza registros ni pruebas de credenciales.')}</p>
					<div style={{display:'flex',gap:8,flexWrap:'wrap',marginBottom:8}}><span className="pill danger"><span className="dot"/>{t('Alta')} {result.audit.high}</span><span className="pill warn"><span className="dot"/>{t('Media')} {result.audit.medium}</span><span className="pill"><span className="dot"/>{t('Baja')} {result.audit.low}</span></div>
					{result.audit.findings.map((f,i)=><div className="hop-row" key={i}>
						<span className={'tag '+(f.level==='high'?'vpn':f.level==='medium'?'reserved':'')}>{f.level}</span>
						<span className="mono">{f.callId||t('captura')}</span><span>{f.summary}</span><span className="dim" style={{fontSize:11}}>{f.evidence} · {t('confianza')} {f.confidence}%</span>
					</div>)}
				</div>
			)}

          {result.calls.length === 0 ? (
            <div className="note" style={{ marginTop: 16 }}>{t('No se encontró tráfico SIP en esta captura.')}</div>
          ) : (
            <div style={{ marginTop: 8 }}>
              {result.calls.map((c) => (
                <CallCard key={c.callId} pcapPath={path} call={c} />
              ))}
            </div>
          )}
        </>
      )}

      <QualityHistoryPanel />
    </div>
  );
}
