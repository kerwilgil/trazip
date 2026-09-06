// Real country flags, hand-drawn as small inline SVGs — no npm dependency,
// no external assets, no font. This exists because Windows' Segoe UI Emoji
// font ships without glyphs for the Unicode regional-indicator flag
// sequences (shows blank boxes or bare letters), so emoji flags never
// render inside TRAZIP's WebView2 window regardless of browser engine.
//
// Coverage is the ~55 countries TRAZIP is realistically going to see
// (Panama/LatAm first, then the rest of the Americas, Europe, and a handful
// of others) — deliberately simplified (flat color blocks, no coats of
// arms/fine detail) for quick visual recognition rather than heraldic
// accuracy. Countries outside this list fall back to a plain "[XX]" text
// chip, which always renders regardless of font support.
import type { ReactNode } from 'react';

const VB = '0 0 30 20';

function Svg({ children }: { children: ReactNode }) {
  return (
    <svg viewBox={VB} width="20" height="13.3" style={{ verticalAlign: 'middle', borderRadius: 2, flexShrink: 0 }} aria-hidden="true">
      {children}
    </svg>
  );
}

function stripesH(colors: string[]) {
  const h = 20 / colors.length;
  return colors.map((c, i) => <rect key={i} x={0} y={i * h} width={30} height={h + 0.5} fill={c} />);
}

function stripesV(colors: string[]) {
  const w = 30 / colors.length;
  return colors.map((c, i) => <rect key={i} x={i * w} y={0} width={w + 0.5} height={20} fill={c} />);
}

// Simple horizontal/vertical stripe flags — the majority of world flags.
// A repeated color widens that band (e.g. 4 entries where one repeats
// approximates a non-equal ratio like Colombia's 2:1:1 without extra code).
const STRIPES: Record<string, { dir: 'h' | 'v'; colors: string[] }> = {
  // España: 1:2:1, de ahí el amarillo repetido (sin escudo, como el resto).
  ES: { dir: 'h', colors: ['#AA151B', '#F1BF00', '#F1BF00', '#AA151B'] },
  DE: { dir: 'h', colors: ['#000000', '#DD0000', '#FFCE00'] },
  IT: { dir: 'v', colors: ['#009246', '#FFFFFF', '#CE2B37'] },
  FR: { dir: 'v', colors: ['#0055A4', '#FFFFFF', '#EF4135'] },
  NL: { dir: 'h', colors: ['#AE1C28', '#FFFFFF', '#21468B'] },
  BE: { dir: 'v', colors: ['#000000', '#FAE042', '#ED2939'] },
  IE: { dir: 'v', colors: ['#169B62', '#FFFFFF', '#FF883E'] },
  MX: { dir: 'v', colors: ['#006847', '#FFFFFF', '#CE1126'] },
  CO: { dir: 'h', colors: ['#FCD116', '#FCD116', '#003893', '#CE1126'] },
  EC: { dir: 'h', colors: ['#FFDD00', '#FFDD00', '#034EA2', '#ED1C24'] },
  VE: { dir: 'h', colors: ['#FCD116', '#00247D', '#CE1126'] },
  PE: { dir: 'v', colors: ['#D91023', '#FFFFFF', '#D91023'] },
  BO: { dir: 'h', colors: ['#D52B1E', '#F9E300', '#007934'] },
  AR: { dir: 'h', colors: ['#74ACDF', '#FFFFFF', '#74ACDF'] },
  UY: { dir: 'h', colors: ['#0038A8', '#FFFFFF', '#0038A8', '#FFFFFF', '#0038A8'] },
  PY: { dir: 'h', colors: ['#D52B1E', '#FFFFFF', '#0038A8'] },
  GT: { dir: 'v', colors: ['#4997D0', '#FFFFFF', '#4997D0'] },
  HN: { dir: 'h', colors: ['#0073CF', '#FFFFFF', '#0073CF'] },
  SV: { dir: 'h', colors: ['#0047AB', '#FFFFFF', '#0047AB'] },
  NI: { dir: 'h', colors: ['#0067C6', '#FFFFFF', '#0067C6'] },
  CR: { dir: 'h', colors: ['#002B7F', '#FFFFFF', '#CE1126', '#CE1126', '#FFFFFF', '#002B7F'] },
  PL: { dir: 'h', colors: ['#FFFFFF', '#DC143C'] },
  AT: { dir: 'h', colors: ['#ED2939', '#FFFFFF', '#ED2939'] },
  RU: { dir: 'h', colors: ['#FFFFFF', '#0039A6', '#D52B1E'] },
  ID: { dir: 'h', colors: ['#CE1126', '#FFFFFF'] },
  TH: { dir: 'h', colors: ['#A51931', '#F4F5F8', '#2D2A4A', '#2D2A4A', '#F4F5F8', '#A51931'] },
};

// Nordic offset-cross flags (Sweden/Norway/Denmark/Finland).
const NORDIC: Record<string, { bg: string; cross: string; crossOutline?: string }> = {
  SE: { bg: '#006AA7', cross: '#FECC02' },
  FI: { bg: '#FFFFFF', cross: '#003580' },
  DK: { bg: '#C60C30', cross: '#FFFFFF' },
  NO: { bg: '#EF2B2D', cross: '#FFFFFF', crossOutline: '#002868' },
};

function NordicFlag({ bg, cross, crossOutline }: { bg: string; cross: string; crossOutline?: string }) {
  const barX = 11; // offset toward the hoist, like every real Nordic flag
  const barY = 8;
  return (
    <>
      <rect x={0} y={0} width={30} height={20} fill={bg} />
      {crossOutline && (
        <>
          <rect x={barX - 1.5} y={0} width={5} height={20} fill={crossOutline} />
          <rect x={0} y={barY - 1.5} width={30} height={5} fill={crossOutline} />
        </>
      )}
      <rect x={barX} y={0} width={2.5} height={20} fill={cross} />
      <rect x={0} y={barY} width={30} height={2.5} fill={cross} />
    </>
  );
}

function StarDot({ x, y, r = 1.1, fill = '#FFFFFF' }: { x: number; y: number; r?: number; fill?: string }) {
  return <circle cx={x} cy={y} r={r} fill={fill} />;
}

// Countries whose flag isn't a plain stripe/cross pattern get a small
// bespoke render — still simplified (no coats of arms), but shaped enough
// to be recognizable at a glance.
const CUSTOM: Record<string, () => ReactNode> = {
  // Panama: quartered field with a star in the white quarters — priority #1
  // since Kerwil is based there.
  PA: () => (
    <>
      <rect x={0} y={0} width={15} height={10} fill="#FFFFFF" />
      <rect x={15} y={0} width={15} height={10} fill="#DA121A" />
      <rect x={0} y={10} width={15} height={10} fill="#072357" />
      <rect x={15} y={10} width={15} height={10} fill="#FFFFFF" />
      <StarDot x={7.5} y={5} r={1.4} fill="#072357" />
      <StarDot x={22.5} y={15} r={1.4} fill="#DA121A" />
    </>
  ),
  US: () => (
    <>
      {stripesH(['#B22234', '#FFFFFF', '#B22234', '#FFFFFF', '#B22234', '#FFFFFF', '#B22234'])}
      <rect x={0} y={0} width={13} height={11} fill="#3C3B6E" />
    </>
  ),
  PT: () => (
    <>
      <rect x={0} y={0} width={12} height={20} fill="#006600" />
      <rect x={12} y={0} width={18} height={20} fill="#FF0000" />
      <circle cx={12} cy={10} r={4} fill="#FFFF00" />
      <circle cx={12} cy={10} r={2.4} fill="#FF0000" />
    </>
  ),
  CA: () => (
    <>
      <rect x={0} y={0} width={30} height={20} fill="#FFFFFF" />
      <rect x={0} y={0} width={7.5} height={20} fill="#FF0000" />
      <rect x={22.5} y={0} width={7.5} height={20} fill="#FF0000" />
      <polygon points="15,4 16.6,8.4 20,7 18,11 21,12 16.6,13 15,16 13.4,13 9,12 12,11 10,7 13.4,8.4" fill="#FF0000" />
    </>
  ),
  CL: () => (
    <>
      <rect x={0} y={0} width={30} height={10} fill="#FFFFFF" />
      <rect x={0} y={10} width={30} height={10} fill="#D52B1E" />
      <rect x={0} y={0} width={10} height={10} fill="#0039A6" />
      <StarDot x={5} y={5} r={2} />
    </>
  ),
  CU: () => (
    <>
      {stripesH(['#002A8F', '#FFFFFF', '#002A8F', '#FFFFFF', '#002A8F'])}
      <polygon points="0,0 12,10 0,20" fill="#CF142B" />
      <StarDot x={4} y={10} r={1.8} />
    </>
  ),
  PR: () => (
    <>
      {stripesH(['#EF3340', '#FFFFFF', '#EF3340', '#FFFFFF', '#EF3340'])}
      <polygon points="0,0 12,10 0,20" fill="#0050F0" />
      <StarDot x={4} y={10} r={1.8} />
    </>
  ),
  GB: () => (
    <>
      <rect x={0} y={0} width={30} height={20} fill="#00247D" />
      <path d="M0,0 L30,20 M30,0 L0,20" stroke="#FFFFFF" strokeWidth={3.2} />
      <path d="M0,0 L30,20 M30,0 L0,20" stroke="#CF142B" strokeWidth={1.4} />
      <rect x={12.5} y={0} width={5} height={20} fill="#FFFFFF" />
      <rect x={0} y={7.5} width={30} height={5} fill="#FFFFFF" />
      <rect x={13.3} y={0} width={3.4} height={20} fill="#CF142B" />
      <rect x={0} y={8.3} width={30} height={3.4} fill="#CF142B" />
    </>
  ),
  CH: () => (
    <>
      <rect x={0} y={0} width={30} height={20} fill="#D52B1E" />
      <rect x={12.5} y={5} width={5} height={10} fill="#FFFFFF" />
      <rect x={9} y={8.5} width={12} height={3} fill="#FFFFFF" />
    </>
  ),
  JP: () => (
    <>
      <rect x={0} y={0} width={30} height={20} fill="#FFFFFF" />
      <circle cx={15} cy={10} r={5.5} fill="#BC002D" />
    </>
  ),
  CN: () => (
    <>
      <rect x={0} y={0} width={30} height={20} fill="#DE2910" />
      <StarDot x={6} y={6} r={2.2} fill="#FFDE00" />
      <StarDot x={11} y={3} r={0.8} fill="#FFDE00" />
      <StarDot x={13} y={6} r={0.8} fill="#FFDE00" />
      <StarDot x={13} y={9} r={0.8} fill="#FFDE00" />
      <StarDot x={11} y={11} r={0.8} fill="#FFDE00" />
    </>
  ),
  BR: () => (
    <>
      <rect x={0} y={0} width={30} height={20} fill="#009C3B" />
      <polygon points="15,2.5 27.5,10 15,17.5 2.5,10" fill="#FFDF00" />
      <circle cx={15} cy={10} r={4} fill="#002776" />
    </>
  ),
  DO: () => (
    <>
      <rect x={0} y={0} width={13.5} height={9} fill="#002D62" />
      <rect x={16.5} y={0} width={13.5} height={9} fill="#CE1126" />
      <rect x={0} y={11} width={13.5} height={9} fill="#CE1126" />
      <rect x={16.5} y={11} width={13.5} height={9} fill="#002D62" />
      <rect x={13.5} y={0} width={3} height={20} fill="#FFFFFF" />
      <rect x={0} y={9} width={30} height={2} fill="#FFFFFF" />
    </>
  ),
  TR: () => (
    <>
      <rect x={0} y={0} width={30} height={20} fill="#E30A17" />
      <circle cx={12} cy={10} r={4.2} fill="#FFFFFF" />
      <circle cx={13.3} cy={10} r={3.4} fill="#E30A17" />
      <StarDot x={18} y={10} r={1.1} fill="#FFFFFF" />
    </>
  ),
  IL: () => (
    <>
      <rect x={0} y={0} width={30} height={20} fill="#FFFFFF" />
      <rect x={0} y={2.5} width={30} height={2.2} fill="#0038B8" />
      <rect x={0} y={15.3} width={30} height={2.2} fill="#0038B8" />
      <polygon points="15,7 17.5,11.3 12.5,11.3" fill="none" stroke="#0038B8" strokeWidth={0.9} />
      <polygon points="15,13 12.5,8.7 17.5,8.7" fill="none" stroke="#0038B8" strokeWidth={0.9} />
    </>
  ),
  AE: () => (
    <>
      <rect x={0} y={0} width={30} height={6.7} fill="#00732F" />
      <rect x={0} y={6.7} width={30} height={6.6} fill="#FFFFFF" />
      <rect x={0} y={13.3} width={30} height={6.7} fill="#000000" />
      <rect x={0} y={0} width={8} height={20} fill="#FF0000" />
    </>
  ),
  PH: () => (
    <>
      <rect x={0} y={0} width={30} height={10} fill="#0038A8" />
      <rect x={0} y={10} width={30} height={10} fill="#CE1126" />
      <polygon points="0,0 12,10 0,20" fill="#FFFFFF" />
      <StarDot x={4} y={10} r={1.6} fill="#FCD116" />
    </>
  ),
  KR: () => (
    <>
      <rect x={0} y={0} width={30} height={20} fill="#FFFFFF" />
      <path d="M15,4.5 A5.5,5.5 0 0 1 15,15.5 A2.75,2.75 0 0 1 15,10 A2.75,2.75 0 0 0 15,4.5 Z" fill="#CD2E3A" />
      <path d="M15,15.5 A5.5,5.5 0 0 1 15,4.5 A2.75,2.75 0 0 1 15,10 A2.75,2.75 0 0 0 15,15.5 Z" fill="#0047A0" />
    </>
  ),
  VN: () => (
    <>
      <rect x={0} y={0} width={30} height={20} fill="#DA251D" />
      <StarDot x={15} y={10} r={3.6} fill="#FFFF00" />
    </>
  ),
  SG: () => (
    <>
      <rect x={0} y={0} width={30} height={10} fill="#ED2939" />
      <rect x={0} y={10} width={30} height={10} fill="#FFFFFF" />
      <circle cx={7} cy={5} r={3} fill="#FFFFFF" />
      <circle cx={8.2} cy={5} r={2.5} fill="#ED2939" />
    </>
  ),
  MY: () => (
    <>
      {stripesH(['#CC0001', '#FFFFFF', '#CC0001', '#FFFFFF', '#CC0001', '#FFFFFF', '#CC0001', '#FFFFFF'])}
      <rect x={0} y={0} width={14} height={11.4} fill="#010066" />
      <circle cx={5.5} cy={5.7} r={2.6} fill="#FFCC00" />
      <circle cx={6.6} cy={5.7} r={2.1} fill="#010066" />
      <StarDot x={9.5} y={5.7} r={1.1} fill="#FFCC00" />
    </>
  ),
  AU: () => (
    <>
      <rect x={0} y={0} width={30} height={20} fill="#00247D" />
      <rect x={0} y={0} width={13} height={9} fill="#00247D" />
      <path d="M0,0 L13,9 M13,0 L0,9" stroke="#FFFFFF" strokeWidth={1.4} />
      <rect x={5.6} y={0} width={1.8} height={9} fill="#FFFFFF" />
      <rect x={0} y={3.6} width={13} height={1.8} fill="#FFFFFF" />
      <StarDot x={21} y={13} r={2.2} fill="#FFFFFF" />
      <StarDot x={24} y={5} r={1} fill="#FFFFFF" />
      <StarDot x={27} y={9} r={1} fill="#FFFFFF" />
      <StarDot x={24} y={15} r={1} fill="#FFFFFF" />
      <StarDot x={19} y={7} r={1} fill="#FFFFFF" />
    </>
  ),
  NZ: () => (
    <>
      <rect x={0} y={0} width={30} height={20} fill="#00247D" />
      <rect x={0} y={0} width={13} height={9} fill="#00247D" />
      <path d="M0,0 L13,9 M13,0 L0,9" stroke="#FFFFFF" strokeWidth={1.4} />
      <rect x={5.6} y={0} width={1.8} height={9} fill="#FFFFFF" />
      <rect x={0} y={3.6} width={13} height={1.8} fill="#FFFFFF" />
      <StarDot x={22} y={5} r={1.3} fill="#CC142B" />
      <StarDot x={26} y={9} r={1.6} fill="#CC142B" />
      <StarDot x={22} y={14} r={1.3} fill="#CC142B" />
      <StarDot x={18} y={11} r={1} fill="#CC142B" />
    </>
  ),
  ZA: () => (
    <>
      <rect x={0} y={0} width={30} height={20} fill="#FFFFFF" />
      <polygon points="0,0 0,20 9,10" fill="#000000" />
      <polygon points="0,3 0,17 13,10" fill="#DE3831" />
      <polygon points="0,6 0,14 17,10" fill="#FFB612" />
      <rect x={9} y={0} width={21} height={4} fill="#002395" />
      <rect x={9} y={16} width={21} height={4} fill="#007A4D" />
      <polygon points="9,4 21,10 9,16" fill="#FFFFFF" />
      <polygon points="9,6 18,10 9,14" fill="#007A4D" />
    </>
  ),
  IN: () => (
    <>
      {stripesH(['#FF9933', '#FFFFFF', '#138808'])}
      <circle cx={15} cy={10} r={2.4} fill="none" stroke="#000080" strokeWidth={0.5} />
      <StarDot x={15} y={10} r={0.5} fill="#000080" />
    </>
  ),
};

// Windows' Segoe UI Emoji font intentionally ships without flag glyphs for
// the Unicode regional-indicator flag sequences, so plain emoji never
// render inside TRAZIP's WebView2 window. Real flags above are used when
// available; anything else falls back to a bracketed ISO code, which
// renders identically everywhere.
export function countryFlag(countryCode?: string): ReactNode {
  if (!countryCode || countryCode.length !== 2) return '';
  const code = countryCode.toUpperCase();
  if (code < 'AA' || code > 'ZZ') return '';

  if (CUSTOM[code]) {
    return <Svg>{CUSTOM[code]()}</Svg>;
  }
  if (NORDIC[code]) {
    const n = NORDIC[code];
    return <Svg><NordicFlag bg={n.bg} cross={n.cross} crossOutline={n.crossOutline} /></Svg>;
  }
  if (STRIPES[code]) {
    const s = STRIPES[code];
    return <Svg>{s.dir === 'h' ? stripesH(s.colors) : stripesV(s.colors)}</Svg>;
  }
  return `[${code}]`;
}
