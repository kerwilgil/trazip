import { useState } from 'react';
import { exportVoipCallAudio, previewVoipCallAudio, type voip } from '../lib/api';
import RtpStreamPlayer from './RtpStreamPlayer';
import { useI18n } from '../lib/i18n';

type Mode = 'caller' | 'callee' | 'mono' | 'stereo';
const labels: Record<Mode, string> = { caller: 'Caller', callee: 'Callee', mono: 'Conversación mono', stereo: 'Conversación estéreo' };

function blocked(call: voip.Call) {
  return call.streams?.some((s) => ['srtp_detected', 'encrypted_audio_unavailable', 'missing_sdp', 'unsupported_codec', 'unsupported_g729_annex_b', 'resource_limit_exceeded'].includes(s.audioStatus || '')) ?? false;
}

export default function CallAudioPanel({ pcapPath, call }: { pcapPath: string; call: voip.Call }) {
  const { t } = useI18n();
  const [playing, setPlaying] = useState<Mode | null>(null);
  const [source, setSource] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState<Mode | null>(null);
  const encrypted = blocked(call);
	const mediaState = call.streams?.find((s) => s.audioStatus && s.audioStatus !== 'reconstructable')?.audioStatus || 'reconstructable';
  const codecs = Array.from(new Set((call.streams ?? []).filter((s) => s.mediaType === 'audio' || !s.mediaType).map((s) => s.codecName || `PT ${s.payloadType}`))).join(', ');

  async function play(mode: Mode) {
    setBusy(mode); setStatus(null);
    try { setSource(await previewVoipCallAudio(pcapPath, call, mode)); setPlaying(mode); }
    catch (e) { setStatus(t('No se pudo reproducir el audio: {detail}', { detail: String(e) })); }
    finally { setBusy(null); }
  }
  async function exportWav(mode: Mode) {
    setBusy(mode); setStatus(null);
    try { const out = await exportVoipCallAudio(pcapPath, call, mode); setStatus(out ? t('Guardado: {path}', { path: out.replace('|', ' — ') }) : t('Cancelado')); }
    catch (e) { setStatus(t('No se pudo exportar el audio: {detail}', { detail: String(e) })); }
    finally { setBusy(null); }
  }
  const action = (mode: Mode, exportLabel = 'Export WAV') => (
    <div key={mode} style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
      <strong style={{ minWidth: 150, fontSize: 12 }}>{labels[mode]}</strong>
      <button className="btn ghost" disabled={(encrypted || (mediaState === 'unknown_direction' && (mode === 'caller' || mode === 'callee')) || busy !== null)} onClick={() => play(mode)}>{busy === mode ? <span className="spin" /> : '▶'} Play</button>
      <button className="btn ghost" disabled={(encrypted || (mediaState === 'unknown_direction' && (mode === 'caller' || mode === 'callee')) || busy !== null)} onClick={() => exportWav(mode)}>{exportLabel}</button>
    </div>
  );
  return <section className="card" aria-label="Audio VoIP" style={{ marginTop: 16 }}>
    <h3 style={{ marginTop: 0 }}>Audio</h3>
    <div className="kv"><span className="k">Codec</span><span className="v">{codecs || 'No detectado'}</span></div>
    <div className="kv"><span className="k">Estado</span><span className={encrypted ? 'bad' : mediaState === 'degraded_reconstruction' ? 'warn' : 'ok'}>{mediaState}</span></div>
    {action('caller', 'Export Caller WAV')}
    {action('callee', 'Export Callee WAV')}
    {action('mono', 'Export Mono WAV')}
    {action('stereo', 'Export Stereo WAV')}
    {status && <p className="dim" role="status">{status}</p>}
    <RtpStreamPlayer source={source} label={playing ? `Audio ${labels[playing]}` : 'Audio VoIP'} />
  </section>;
}
