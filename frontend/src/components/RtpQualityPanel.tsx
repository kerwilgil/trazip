import { useState, type ReactNode } from 'react';
import { exportCallAudio, type voip } from '../lib/api';
import { useI18n } from '../lib/i18n';

// One compact quality block per RTP direction (§5 "Calidad RTP avanzada").
// Deliberately not a table: a table invites piling on columns until it's
// unreadable, and rtp.Snapshot already has 10+ fields worth showing.

// Mirrors internal/voip/thresholds.go's lossWarnPct/lossHighPct and
// mosLowScore/mosPoorScore — kept as plain numbers (not a shared config
// layer), but the VALUES must not drift from Diagnose's own boundaries: a
// stream painted red here while Diagnose still calls it merely "degraded"
// (or vice versa) is a visible contradiction between the two judgements.
const lossWarn = 5;
const lossBad = 10;

function mosClass(score?: number): string {
  if (score === undefined) return '';
  if (score < 2.5) return 'bad'; // mosPoorScore
  if (score < 3.5) return 'warn'; // mosLowScore
  return 'ok';
}

function Row({ label, value, cls }: { label: string; value: ReactNode; cls?: string }) {
  return (
    <div className="kv">
      <span className="k">{label}</span>
      <span className={'v ' + (cls || '')}>{value}</span>
    </div>
  );
}

export default function RtpQualityPanel({
  stream,
  label,
  pcapPath,
}: {
  stream: voip.StreamInfo;
  label: string;
  pcapPath: string;
}) {
  const { t } = useI18n();
  const s = stream.stats;
  const lossCls = s.lossPct >= lossBad ? 'bad' : s.lossPct >= lossWarn ? 'warn' : '';
  const canExport = stream.codecName === 'PCMU';
  const [exporting, setExporting] = useState(false);
  const [exportStatus, setExportStatus] = useState<string | null>(null);

  async function doExport() {
    setExporting(true);
    setExportStatus(null);
    try {
      const result = await exportCallAudio(pcapPath, stream.ssrc, stream.src);
      if (!result) {
        setExportStatus(t('Cancelado'));
      } else {
        const [path, warning] = result.split('|');
        setExportStatus(warning ? t('Guardado: {path} ({warning})', { path, warning }) : t('Guardado: {path}', { path }));
      }
    } catch (e) {
      setExportStatus(t('Error: {message}', { message: String(e) }));
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="card">
      <h4 style={{ margin: '0 0 8px', fontSize: 13, display: 'flex', alignItems: 'center', gap: 8 }}>
        {label}
        <span className="dim mono" style={{ fontSize: 11, fontWeight: 400 }}>
          {stream.mediaType ? `${stream.mediaType.toUpperCase()} · ` : ''}{stream.codecName || `PT ${stream.payloadType}`}
        </span>
      </h4>

      {/* MOS is a voice-quality model (E-model/G.107/G.113 baseline for
          G.711) — the backend already never computes it outside audio
          (stream.mos is undefined for video/other media), so this check is
          belt-and-suspenders: it stays correct even if that contract ever
          drifts, and makes the "audio-only" rule visible here too, not just
          in internal/voip. */}
      {stream.mos && (stream.mediaType === '' || stream.mediaType === undefined || stream.mediaType === 'audio') && (
        <Row label="MOS" value={stream.mos.score.toFixed(2)} cls={mosClass(stream.mos.score)} />
      )}
      <Row label={t('Pérdida')} value={`${s.lossPct.toFixed(1)}%`} cls={lossCls} />
      <Row label="Jitter" value={`${s.jitterMs.toFixed(1)} ms`} />
      <Row label={t('Paquetes recibidos')} value={s.received} />
      <Row label={t('Paquetes esperados')} value={s.expected} />
      <Row label={t('Paquetes perdidos')} value={s.lost} />
      {s.duplicates > 0 && <Row label={t('Duplicados')} value={s.duplicates} cls="warn" />}
      {s.reordered > 0 && <Row label={t('Reordenados')} value={s.reordered} cls="warn" />}
      {/* 50ms mirrors clockSkewWarnMs in internal/voip/thresholds.go — this is
          display-only color coding, not a judgement Diagnose makes, so it's
          not pulled from the Go constant; if that constant ever changes,
          check here too. */}
      <Row label={t('Clock skew')} value={`${s.clockSkewMs.toFixed(1)} ms`} cls={Math.abs(s.clockSkewMs) >= 50 ? 'warn' : undefined} />
      <Row label={t('Duración RTP')} value={`${(s.rtpDurationMs / 1000).toFixed(1)} s`} />
      <Row label={t('Duración observada')} value={`${(s.arrivalDurationMs / 1000).toFixed(1)} s`} />
      <Row label={t('Clock rate')} value={`${s.clockRate} Hz`} />
      {stream.audioStatus && <Row label="Audio" value={stream.audioStatusDetail || stream.audioStatus} cls={stream.audioStatus === 'reconstructable' ? 'ok' : 'warn'} />}

      <div style={{ marginTop: 8, fontSize: 11.5 }} className={s.clockAssumed ? 'warn' : 'dim'}>
        {s.clockAssumed
          ? t('⚠ Clock rate asumido; jitter y clock skew tienen menor confianza')
          : t('✓ Clock rate confirmado por SDP')}
      </div>

      <div style={{ marginTop: 10 }}>
        {canExport ? (
          <button className="btn ghost" style={{ padding: '4px 10px', fontSize: 12 }} onClick={doExport} disabled={exporting}>
            {exporting ? <span className="spin" /> : '🔊'} {t('Exportar audio')}
          </button>
        ) : (
          <span className="dim" style={{ fontSize: 12 }}>{t('Exportar audio: solo PCMU')}</span>
        )}
        {exportStatus && <div className="dim" style={{ fontSize: 11, marginTop: 4 }}>{exportStatus}</div>}
      </div>
    </div>
  );
}
