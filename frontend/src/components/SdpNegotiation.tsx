import type { voip, sdp } from '../lib/api';
import { useI18n } from '../lib/i18n';

// A readable rendering of SDP offer/answer (§8 SDP avanzado) — never a raw
// JSON dump. §9's SDP-vs-RTP findings render alongside it since they're
// exactly what this data is for: knowing whether what was negotiated is what
// actually happened on the wire.

function MediaBlock({ m }: { m: sdp.Media }) {
  const { t } = useI18n();
  const codecs = Object.values(m.codecs || {});
  return (
    <div style={{ marginTop: 8, fontSize: 12.5 }}>
      <div className="kv"><span className="k">{t('Dirección de media')}</span><span className="v mono">{m.connAddr || '—'}{m.connFamily ? ` (${m.connFamily})` : ''}</span></div>
      <div className="kv"><span className="k">{t('Puerto')}</span><span className="v mono">{m.port}</span></div>
      {m.ptimeMs !== undefined && <div className="kv"><span className="k">ptime</span><span className="v">{m.ptimeMs} ms</span></div>}
      <div className="kv"><span className="k">{t('Payload types')}</span><span className="v mono">{(m.payloadTypes || []).join(', ') || '—'}</span></div>
      <div className="kv">
        <span className="k">{t('Códecs ofrecidos')}</span>
        <span className="v" style={{ textAlign: 'right' }}>
          {codecs.length > 0
            ? codecs.map((c) => `${c.name}${c.clockRate ? '/' + c.clockRate : ''}${c.channels ? '/' + c.channels : ''}`).join(', ')
            : '—'}
        </span>
      </div>
      {m.candidates && m.candidates.length > 0 && (
        <div className="kv">
          <span className="k">{t('Candidatos ICE')}</span>
          <span className="v mono" style={{ fontSize: 10.5, textAlign: 'right' }}>{m.candidates.length}</span>
        </div>
      )}
    </div>
  );
}

export default function SdpNegotiation({ call }: { call: voip.Call }) {
  const { t } = useI18n();
  if (!call.sdpOffer && !call.sdpAnswer) return null;

  return (
    <>
      <div className="grid cols-2">
        {call.sdpOffer && (
          <div className="card">
            <span className="label dim">{t('Oferta')}</span>
            {call.sdpOffer.media.map((m, i) => <MediaBlock key={i} m={m} />)}
          </div>
        )}
        {call.sdpAnswer && (
          <div className="card">
            <span className="label dim">{t('Respuesta')}</span>
            {call.sdpAnswer.media.map((m, i) => <MediaBlock key={i} m={m} />)}
          </div>
        )}
      </div>

      {call.streams && call.streams.length > 0 && (
        <div className="card" style={{ marginTop: 10 }}>
          <span className="label dim">{t('Códec finalmente observado')}</span>
          {call.streams.map((s, i) => (
            <div className="kv" key={i}>
              <span className="k mono" style={{ fontSize: 11 }}>{s.src} → {s.dst}</span>
              <span className="v">{s.codecName || `PT ${s.payloadType}`}</span>
            </div>
          ))}
        </div>
      )}

      {call.mediaFindings && call.mediaFindings.length > 0 && (
        <div style={{ marginTop: 10 }}>
          {call.mediaFindings.map((f, i) =>
            f.level === 'warn' ? (
              <div key={i} className="note">{t(f.summary)}</div>
            ) : (
              <p key={i} className="dim" style={{ fontSize: 11.5, margin: '4px 0' }}>{t(f.summary)}</p>
            ),
          )}
        </div>
      )}
    </>
  );
}
