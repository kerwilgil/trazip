import type { voip } from '../lib/api';
import { useI18n } from '../lib/i18n';

// What RTCP adds beyond RTP's own packet counting: the same stream's
// destination reporting how IT received it (§6 RTCP completo). Same stream,
// same direction — never "the opposite direction" or "sentido contrario" —
// just a second vantage point on it. The rule this exists to enforce
// visually: "pérdida observada localmente" (a running total this capture
// counted itself) and "pérdida RTCP del último intervalo" (the receiver's
// own report, covering only the time since ITS previous report) describe
// different WINDOWS of the same signal, never treated or displayed as if
// they measured the same thing.
//
// lossWarnPct/lossHighPct mirror internal/voip/thresholds.go's constants of
// the same name — kept as plain numbers here (not a shared config) per the
// same reasoning as RtpQualityPanel's clock-skew comment, but the VALUES
// must not drift from Diagnose's own boundaries: a stream painted red here
// while Diagnose still calls it merely "degraded" is a visible contradiction.
const lossWarnPct = 5;
const lossHighPct = 10;

function lossClass(pct: number): string {
  if (pct >= lossHighPct) return 'bad';
  if (pct >= lossWarnPct) return 'warn';
  return '';
}

export default function RtcpQualityPanel({ stream, label }: { stream: voip.StreamInfo; label: string }) {
  const { t } = useI18n();
  if (!stream.rtcpSeen) {
    return (
      <div className="card">
        <h4 style={{ margin: '0 0 6px', fontSize: 13 }}>{label}</h4>
        <p className="dim" style={{ fontSize: 12 }}>{t('No se observó RTCP para este stream.')}</p>
      </div>
    );
  }
  const receiver = stream.rtcp?.receiver; // the DESTINATION of this same stream reporting its own reception
  const sender = stream.rtcp?.sender; // this stream's own ORIGIN self-reporting via its own Sender Report

  return (
    <div className="card">
      <h4 style={{ margin: '0 0 8px', fontSize: 13 }}>{label}</h4>

      <div className="kv">
        <span className="k">{t('Pérdida observada localmente')}</span>
        <span className={'v ' + lossClass(stream.stats.lossPct)}>
          {stream.stats.lossPct.toFixed(1)}%
        </span>
      </div>

      {receiver ? (
        <>
          <div className="kv">
            <span className="k" title={t('Porcentaje de pérdida desde el informe RTCP anterior del receptor — no el acumulado de toda la llamada')}>
              {t('Pérdida RTCP último intervalo')}
            </span>
            <span className={'v ' + lossClass(receiver.fractionLostPct)}>
              {receiver.fractionLostPct.toFixed(1)}%
            </span>
          </div>
          <div className="kv">
            <span className="k">{t('Pérdida acumulada (reportada por RTCP)')}</span>
            <span className="v">{receiver.cumulativeLost}</span>
          </div>
          <div className="kv">
            <span className="k">{t('Jitter reportado por RTCP')}</span>
            <span className="v">
              {receiver.jitterMs !== undefined
                ? `${receiver.jitterMs.toFixed(1)} ms`
                : t('{ticks} ticks (crudo — sin clock rate confirmado)', { ticks: receiver.jitterTicks })}
            </span>
          </div>
        </>
      ) : (
        <p className="dim" style={{ fontSize: 11.5, marginTop: 6 }}>
          {sender
            ? t('Se observó el Sender Report del origen, pero no se observó un Receiver Report del receptor para este stream en la captura.')
            : t('Se observó RTCP en la captura, pero ningún informe nombró el SSRC de este stream.')}
        </p>
      )}

      <div className="kv">
        {/* "Estimado" in the label itself, not just a tooltip: RFC 3550's
            formula needs the RR's arrival time at the ORIGINAL SR's
            sender, which a passive capture cannot observe — only its own
            capture-point timestamp, used here as a stand-in. The gap
            between the two grows with how far the capture sits from the
            endpoint, so this can never be shown as an exact figure. */}
        <span className="k" title={t('Estimado desde el punto de captura; la precisión depende de la ubicación de la captura respecto al endpoint')}>
          {t('RTT RTCP estimado')}
        </span>
        <span className="v">
          {stream.rtcp?.estimatedRttMs !== undefined
            ? <span title={t('Estimado desde el punto de captura; la precisión depende de la ubicación de la captura respecto al endpoint')}>
                {`~${stream.rtcp.estimatedRttMs.toFixed(0)} ms`}
              </span>
            : <span className="dim" title={stream.rtcp?.estimatedRttUnavailableReason ? t(stream.rtcp.estimatedRttUnavailableReason) : undefined}>{t('no disponible')}</span>}
        </span>
      </div>
    </div>
  );
}
