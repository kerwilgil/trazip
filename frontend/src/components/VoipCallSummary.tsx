import type { voip } from '../lib/api';
import { useI18n } from '../lib/i18n';
import { countryFlag } from '../lib/flags';

// The call's headline: who called whom, with what device/software, and from
// where (§3 "Resumen de llamada"). State/From→To/setup/duration/retransmisiones
// already live in CallCard's always-visible toggle row just above this — this
// panel exists for what that compact row has no room for, not to repeat it.

// PartyShape covers both voip.CallParty (the dialog-initiating INVITE's two
// endpoints) and voip.SignalingHop (every address TRAZIP actually saw
// carrying the call's signaling) — structurally identical aside from Role,
// which this component never needs.
interface PartyShape {
  address?: string;
  userAgent?: string;
  server?: string;
  country?: string;
  countryCode?: string;
  asn?: number;
  organization?: string;
}

function PartyLine({ role, party }: { role: string; party?: PartyShape }) {
  const { t } = useI18n();
  if (!party || !party.address) return null;
  // City and ASN are separate MaxMind datasets — an address can resolve one
  // without the other (e.g. 1.1.1.1 commonly has ASN 13335/Cloudflare but no
  // City match). Gating the whole line on countryCode alone silently hid a
  // resolved ASN whenever that happened — caught by looking at a real
  // Cloudflare/Google capture, not by a unit test with synthetic geo data.
  const hasGeo = !!party.countryCode || !!party.asn;
  const geo = hasGeo ? (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
      {party.countryCode && <>{countryFlag(party.countryCode)} {party.country}</>}
      {party.asn ? `${party.countryCode ? ' · ' : ''}AS${party.asn}${party.organization ? ' ' + party.organization : ''}` : ''}
    </span>
  ) : null;
  return (
    <div className="kv">
      <span className="k">{role}</span>
      <span className="v" style={{ textAlign: 'right', fontWeight: 400 }}>
        <div className="mono" style={{ fontWeight: 700 }}>{party.address}</div>
        {party.userAgent && <div className="dim" style={{ fontSize: 11.5 }}>{t('User-Agent')}: {party.userAgent}</div>}
        {party.server && <div className="dim" style={{ fontSize: 11.5 }}>{t('Server')}: {party.server}</div>}
        {geo && <div className="dim" style={{ fontSize: 11.5 }}>{geo}</div>}
      </span>
    </div>
  );
}

// summaryParties turns whatever topology evidence is available into an
// ordered (label, party) list to render: the full SignalingPath (origin,
// zero or more numbered intermediaries, destination) when TRAZIP built one
// from real INVITE evidence, or the Caller/Callee fallback — unchanged from
// before this feature — for older captures/exports or a mid-dialog capture
// with no SignalingPath at all.
function summaryParties(call: voip.Call, t: (s: string) => string): { role: string; party?: PartyShape }[] {
  const path = call.signalingPath;
  if (path && path.length >= 2) {
    const intermediaries = path.filter((h) => h.role === 'intermediary').length;
    let seen = 0;
    return path.map((hop) => {
      let role: string;
      if (hop.role === 'origin') role = t('Origen');
      else if (hop.role === 'destination') role = t('Destino');
      else {
        seen += 1;
        role = intermediaries > 1 ? `${t('Intermediario')} ${seen}` : t('Intermediario');
      }
      return { role, party: hop };
    });
  }
  return [
    { role: t('Origen'), party: call.caller },
    { role: t('Destino'), party: call.callee },
  ];
}

export default function VoipCallSummary({ call }: { call: voip.Call }) {
  const { t } = useI18n();
  const codec = call.streams && call.streams.length > 0 ? (call.streams[0].codecName || `PT ${call.streams[0].payloadType}`) : undefined;
  const parties = summaryParties(call, t);

  return (
    <div className="card" style={{ marginTop: 10 }}>
      <div className="kv">
        <span className="k">Call-ID</span>
        <span className="v mono" style={{ fontWeight: 400, fontSize: 11 }}>{call.callId}</span>
      </div>
      {codec && (
        <div className="kv"><span className="k">{t('Códec principal')}</span><span className="v">{codec}</span></div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 20, marginTop: 6 }}>
        {parties.map((p, i) => (
          <PartyLine key={i} role={p.role} party={p.party} />
        ))}
      </div>
    </div>
  );
}
