import { useState } from 'react';
import type { voip } from '../lib/api';
import { useI18n } from '../lib/i18n';

// Protocol-level detail, folded away by default (§12 "Panel avanzado") —
// SSRC, timestamps, LSR/DLSR, packet/octet counts, the RTCP reports relevant
// to this stream. Not a JSON dump: still one field per row with a label,
// just everything that didn't earn a spot in the quality panels above.

function ssrcHex(ssrc: number): string {
  return '0x' + ssrc.toString(16).padStart(8, '0');
}

function StreamAdvanced({ s }: { s: voip.StreamInfo }) {
  const { t } = useI18n();
  const receiver = s.rtcp?.receiver; // the OTHER party's report about receiving THIS stream
  const sender = s.rtcp?.sender; // THIS stream's own origin (s.src) self-reporting via its own Sender Report
  return (
    <div className="card" style={{ marginTop: 8 }}>
      <div className="kv"><span className="k">{t('Extremos')}</span><span className="v mono" style={{ fontSize: 11 }}>{s.src} → {s.dst}</span></div>
      <div className="kv"><span className="k">SSRC</span><span className="v mono">{ssrcHex(s.ssrc)}</span></div>
      <div className="kv"><span className="k">{t('Payload type')}</span><span className="v mono">{s.payloadType}</span></div>
      {receiver && (
        <>
          <div className="kv"><span className="k">{t('Highest sequence (receptor)')}</span><span className="v mono">{receiver.highestSeq}</span></div>
          {receiver.lsr !== undefined && <div className="kv"><span className="k">LSR</span><span className="v mono">{receiver.lsr.toString(16)}</span></div>}
          {receiver.dlsr !== undefined && <div className="kv"><span className="k">DLSR</span><span className="v mono">{receiver.dlsr.toString(16)}</span></div>}
        </>
      )}
      {sender && (
        <>
          <div className="kv"><span className="k">{t('Packet count (Sender Report del origen)')}</span><span className="v mono">{sender.packetCount}</span></div>
          <div className="kv"><span className="k">{t('Octet count (Sender Report del origen)')}</span><span className="v mono">{sender.octetCount}</span></div>
          <div className="kv"><span className="k">NTP</span><span className="v mono" style={{ fontSize: 10.5 }}>{sender.ntpSeconds}.{sender.ntpFraction}</span></div>
          <div className="kv"><span className="k">RTP timestamp</span><span className="v mono">{sender.rtpTimestamp}</span></div>
        </>
      )}
      {s.dtmfDigits && <div className="kv"><span className="k">DTMF</span><span className="v mono">{s.dtmfDigits}</span></div>}
      {s.rtcpReports && s.rtcpReports.length > 0 && (
        <div className="kv"><span className="k">{t('Informes RTCP de este stream')}</span><span className="v">{s.rtcpReports.length}</span></div>
      )}
    </div>
  );
}

export default function VoipAdvanced({ call }: { call: voip.Call }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  if (!call.streams || call.streams.length === 0) return null;

  return (
    <div style={{ marginTop: 12 }}>
      <button
        type="button"
        className="btn ghost"
        style={{ fontSize: 12, padding: '5px 12px' }}
        onClick={() => setOpen((v) => !v)}
      >
        {open ? '▲' : '▼'} {t('Avanzado')}
      </button>
      {open && (
        <div style={{ marginTop: 8 }}>
          {call.streams.map((s, i) => <StreamAdvanced key={i} s={s} />)}
        </div>
      )}
    </div>
  );
}
