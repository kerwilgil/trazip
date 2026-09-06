import { useMemo, useRef, type ReactElement } from 'react';
import type { voip } from '../lib/api';
import { useI18n } from '../lib/i18n';
import CopyButton from './CopyButton';

// sngrep-style SIP call-flow swimlane, built entirely from the real packets
// TRAZIP already decoded (voip.Call.Timeline/Streams from internal/voip's
// SIP+RTP correlator) — no synthetic/generic artwork.

const MARGIN_X = 90;
const LANE_MIN_SPACING = 190;
const ROW_HEIGHT = 46;
const HEADER_HEIGHT = 40;
const RTP_BAND_HEIGHT = 70;
const FOOTER_HEIGHT = 50;

interface Lane {
  key: string; // "ip:port" as it appears in the timeline
  ip: string;
  x: number;
}

function ipOf(hostport: string): string {
  const i = hostport.lastIndexOf(':');
  return i < 0 ? hostport : hostport.slice(0, i);
}

function buildLanes(call: voip.Call): Lane[] {
  const seen: string[] = [];
  for (const ev of call.timeline || []) {
    if (ev.src && !seen.includes(ev.src)) seen.push(ev.src);
    if (ev.dst && !seen.includes(ev.dst)) seen.push(ev.dst);
  }
  return seen.map((key, i) => ({ key, ip: ipOf(key), x: MARGIN_X + i * LANE_MIN_SPACING }));
}

function laneX(lanes: Lane[], key: string): number {
  const exact = lanes.find((l) => l.key === key);
  if (exact) return exact.x;
  // RTP endpoints often use a different port than the SIP signaling leg on
  // the same host — fall back to matching by IP only.
  const byIP = lanes.find((l) => l.ip === ipOf(key));
  return byIP ? byIP.x : MARGIN_X;
}

// failureSenderIP finds which endpoint actually sent the call's final SIP
// failure response (e.g. "486 Busy Here"). TRAZIP's backend now identifies
// this directly (Call.failureOrigin — see internal/voip's FailureOrigin,
// the true responder even when a proxy/SBC/carrier relays that response
// onward) and that's used whenever present; the old timeline scan remains
// as a fallback only for older exported/cached calls captured before that
// field existed. Exported so VoipCalls.tsx's own failure summary (outside
// this diagram) can show the same attribution.
export function failureSenderIP(call: voip.Call): string {
  if (!call.failureCode) return '';
  if (call.failureOrigin) return ipOf(call.failureOrigin);
  const prefix = `${call.failureCode} `;
  const ev = (call.timeline || []).find((e) => e.summary.startsWith(prefix));
  return ev ? ipOf(ev.src) : '';
}

// diagnoseCall used to recompute a one-line summary from raw call signals
// with its own threshold checks (loss>=5%, MOS<3.5, retx>=3...), duplicating
// exactly what internal/voip's Diagnose() now decides server-side. It just
// reads that decision: call.diagnosis.conclusion IS the one-line answer,
// computed once, in one place, shared by every consumer of a Call (the GUI
// today, a future CLI tomorrow). Kept as a named function (not an inline
// `call.diagnosis?.conclusion`) purely so its two call sites don't need to
// know that detail, and so a future backend field rename has one place to fix.
export function diagnoseCall(call: voip.Call): string {
  return call.diagnosis?.conclusion ?? '';
}

function relMs(iso: string, baseMs: number): number {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t - baseMs : 0;
}

function fmtElapsed(ms: number): string {
  if (ms < 1000) return `+${Math.round(ms)}ms`;
  return `+${(ms / 1000).toFixed(2)}s`;
}

export function formatCallFlowText(call: voip.Call): string {
  const lanes = buildLanes(call);
  if (lanes.length === 0) return 'Sin señalización SIP decodificada para esta llamada.';
  const colWidth = 22;
  const pad = (s: string) => s.padEnd(colWidth).slice(0, colWidth);
  const lines: string[] = [];
  lines.push(`Call-ID: ${call.callId}`);
  lines.push(`${call.from || '?'} -> ${call.to || '?'}`);
  lines.push('');
  lines.push(lanes.map((l) => pad(l.ip)).join(''));
  lines.push(lanes.map(() => pad('|')).join(''));

  const base = call.timeline?.[0] ? Date.parse(call.timeline[0].time) : 0;
  for (const ev of call.timeline || []) {
    const from = lanes.findIndex((l) => l.key === ev.src);
    const to = lanes.findIndex((l) => l.key === ev.dst);
    const row = lanes.map(() => '|'.padEnd(colWidth));
    if (from >= 0 && to >= 0 && from !== to) {
      const lo = Math.min(from, to);
      const hi = Math.max(from, to);
      const arrow = to > from ? '-->' : '<--';
      const label = ev.summary + (ev.retransmission ? ' (retx)' : '');
      const dashLen = colWidth * (hi - lo) - label.length - arrow.length;
      const dashes = '-'.repeat(Math.max(dashLen, 1));
      const segment = to > from ? `${label}${dashes}${arrow}` : `${arrow}${dashes}${label}`;
      row[lo] = segment.padEnd(colWidth * (hi - lo)).slice(0, colWidth * (hi - lo));
      for (let i = lo + 1; i < hi; i++) row[i] = '';
    }
    lines.push(`[${fmtElapsed(relMs(ev.time, base)).padStart(9)}] ` + row.join(''));
  }

  if (call.streams && call.streams.length > 0) {
    lines.push('');
    lines.push('=== RTP ===');
    for (const s of call.streams) {
      lines.push(
        `${s.src} <-> ${s.dst}  ${s.codecName || 'PT ' + s.payloadType}  ` +
          `pérdida ${s.stats.lossPct.toFixed(1)}%  jitter ${s.stats.jitterMs.toFixed(1)}ms` +
          (s.mos ? `  MOS ${s.mos.score.toFixed(1)}` : ''),
      );
    }
  }

  lines.push('');
  lines.push(
    call.established
      ? `Resultado: establecida${call.durationSec ? ` · duración ${call.durationSec.toFixed(1)}s` : ''}`
      : `Resultado: fallida${call.failureCode ? ` · SIP ${call.failureCode} ${call.failureReason || ''}${failureSenderIP(call) ? ` (respondido por ${failureSenderIP(call)})` : ''}` : ''}`,
  );
  const diagnosis = diagnoseCall(call);
  if (diagnosis) lines.push(`Diagnóstico: ${diagnosis}`);
  return lines.join('\n');
}

export default function CallFlowDiagram({ call }: { call: voip.Call }) {
  const { t } = useI18n();
  const svgRef = useRef<SVGSVGElement>(null);

  const { lanes, width, height, base } = useMemo((): { lanes: Lane[]; width: number; height: number; base: number } => {
    const l = buildLanes(call);
    const w = l.length > 0 ? l[l.length - 1].x + MARGIN_X : MARGIN_X * 2;
    const rows = (call.timeline || []).length;
    const h = HEADER_HEIGHT + rows * ROW_HEIGHT + (call.streams?.length ? RTP_BAND_HEIGHT : 0) + FOOTER_HEIGHT + 30;
    const b = call.timeline?.[0] ? Date.parse(call.timeline[0].time) : 0;
    return { lanes: l, width: w, height: h, base: b };
  }, [call]);

  async function exportPNG() {
    const svg = svgRef.current;
    if (!svg) return;
    const xml = new XMLSerializer().serializeToString(svg);
    const svgBlob = new Blob([xml], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(svgBlob);
    const img = new Image();
    img.onload = () => {
      const scale = 2; // crisper export than the on-screen SVG size
      const canvas = document.createElement('canvas');
      canvas.width = width * scale;
      canvas.height = height * scale;
      const ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.fillStyle = '#0a1220';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.scale(scale, scale);
        ctx.drawImage(img, 0, 0);
        const a = document.createElement('a');
        a.download = `trazip-llamada-${call.callId.slice(0, 12)}.png`;
        a.href = canvas.toDataURL('image/png');
        a.click();
      }
      URL.revokeObjectURL(url);
    };
    img.src = url;
  }

  if (lanes.length === 0) {
    return <p className="dim" style={{ fontSize: 12.5 }}>{t('No hay señalización SIP decodificada para esta llamada.')}</p>;
  }

  let y = HEADER_HEIGHT;
  const rowEls: ReactElement[] = [];
  for (const [i, ev] of (call.timeline || []).entries()) {
    const x1 = laneX(lanes, ev.src);
    const x2 = laneX(lanes, ev.dst);
    const label = ev.summary + (ev.retransmission ? ' (retx)' : '');
    rowEls.push(
      <g key={i}>
        <text x={MARGIN_X - 14} y={y - 6} textAnchor="end" fontSize={10} fill="var(--text-faint, #7a8aa8)">
          {fmtElapsed(relMs(ev.time, base))}
        </text>
        {x1 === x2 ? (
          <text x={x1} y={y - 4} textAnchor="middle" fontSize={11} fill="var(--text-dim,#a9b7d0)">{label}</text>
        ) : (
          <>
            <text x={(x1 + x2) / 2} y={y - 6} textAnchor="middle" fontSize={11} fill={ev.retransmission ? 'var(--warn,#e0a030)' : 'var(--text,#e8edf7)'}>
              {label}
            </text>
            <line
              x1={x1} y1={y} x2={x2} y2={y}
              stroke={ev.retransmission ? 'var(--warn,#e0a030)' : 'var(--accent,#3ea6ff)'}
              strokeWidth={1.5}
              strokeDasharray={ev.retransmission ? '4 3' : undefined}
              markerEnd="url(#arrowHead)"
            />
          </>
        )}
      </g>,
    );
    y += ROW_HEIGHT;
  }

  let rtpEls: ReactElement[] = [];
  if (call.streams && call.streams.length > 0) {
    const bandY = y + 14;
    rtpEls = call.streams.map((s, i) => {
      const x1 = laneX(lanes, s.src);
      const x2 = laneX(lanes, s.dst);
      const ry = bandY + i * 22;
      return (
        <g key={i}>
          <line x1={x1} y1={ry} x2={x2} y2={ry} stroke="var(--ok,#3fbf6f)" strokeWidth={3} opacity={0.6} />
          <text x={(x1 + x2) / 2} y={ry - 6} textAnchor="middle" fontSize={10.5} fill="var(--ok,#3fbf6f)">
            RTP {s.codecName || 'PT ' + s.payloadType} · {t('pérdida')} {s.stats.lossPct.toFixed(1)}% · jitter {s.stats.jitterMs.toFixed(1)}ms
            {s.mos ? ` · MOS ${s.mos.score.toFixed(1)}` : ''}
          </text>
        </g>
      );
    });
    y = bandY + call.streams.length * 22;
  }

  const failureFrom = failureSenderIP(call);
  const footerText = call.established
    ? t('Establecida{duration}', { duration: call.durationSec ? ` · ${t('duración')} ${call.durationSec.toFixed(1)} s` : '' })
    : t('Fallida{detail}', { detail: call.failureCode ? ` · SIP ${call.failureCode} ${call.failureReason || ''}${failureFrom ? ` (${t('respondido por')} ${failureFrom})` : ''}` : '' });

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
        <CopyButton label={t('Copiar como texto')} getText={() => formatCallFlowText(call)} />
        <button className="btn ghost" onClick={exportPNG} type="button">🖼️ {t('Exportar PNG')}</button>
      </div>
      <div className="mtr-table-wrap" style={{ overflowX: 'auto' }}>
        <svg ref={svgRef} viewBox={`0 0 ${width} ${height}`} width={width} height={height} style={{ background: 'var(--bg,#0a1220)' }}>
          <defs>
            {/* orient="auto" already rotates this marker to match each line's
                actual direction (src->dst, whichever way that points) — a
                single rightward-pointing arrowhead is correct for every line.
                A second pre-mirrored "arrowLeft" marker used to exist and be
                swapped in for right-to-left lines, but orient="auto" was
                already rotating it too, so leftward (response) arrows ended
                up double-flipped and pointed the wrong way. */}
            <marker id="arrowHead" markerWidth={8} markerHeight={8} refX={7} refY={4} orient="auto">
              <path d="M0,0 L8,4 L0,8 Z" fill="var(--accent,#3ea6ff)" />
            </marker>
          </defs>
          {lanes.map((l, i) => {
            // Role: prefer TRAZIP's own SignalingPath — built from real
            // INVITE/re-INVITE evidence (internal/voip's buildSignalingPath),
            // so it can tell a genuine proxy/SBC intermediary apart from an
            // address that just happens to appear between others in the
            // timeline's raw event order. Falls back to that order-of-
            // appearance heuristic only when SignalingPath doesn't cover
            // this lane (no INVITE evidence at all, or a lane that only
            // ever appears in a response, not the forward signaling chain).
            const hop = call.signalingPath?.find((h) => h.address === l.key);
            let role = '';
            if (hop) {
              role = hop.role === 'origin' ? 'emisor' : hop.role === 'destination' ? 'destino' : 'intermediario';
            } else if (lanes.length >= 2) {
              role = i === 0 ? 'emisor' : i === lanes.length - 1 ? 'destino' : 'intermediario';
            }
            const roleColor = role === 'emisor' ? 'var(--accent,#3ea6ff)' : role === 'destino' ? 'var(--ok,#3fbf6f)' : 'var(--text-faint,#7a8aa8)';
            return (
              <g key={l.key}>
                <text x={l.x} y={14} textAnchor="middle" fontSize={11.5} fontWeight={700} fill="var(--text,#e8edf7)">
                  {l.ip}
                </text>
                {role && (
                  <text x={l.x} y={26} textAnchor="middle" fontSize={9} fill={roleColor}>
                    {t(role)}
                  </text>
                )}
                <line x1={l.x} y1={HEADER_HEIGHT - 6} x2={l.x} y2={y} stroke="var(--border,#2a3654)" strokeWidth={1} strokeDasharray="2 3" />
              </g>
            );
          })}
          {rowEls}
          {rtpEls}
          <text x={MARGIN_X - 14} y={y + FOOTER_HEIGHT / 2} fontSize={12} fontWeight={700} fill={call.established ? 'var(--ok,#3fbf6f)' : 'var(--danger,#e5484d)'}>
            {footerText}
          </text>
        </svg>
      </div>
    </div>
  );
}
