// Navigation model mirrors the dashboard sections in prompt maestro §11.
// `phase` marks which build phase delivers the feature; `ready` flags the views
// already wired to the backend so the UI never fakes capability. Icons are
// rendered from a consistent SVG set keyed by `id` (see components/icons.tsx).

export type ViewId =
  | 'overview'
  | 'diagnose'
  | 'investigations'
  | 'capture'
  | 'pcap'
  | 'flows'
  | 'endpoints'
  | 'geomap'
  | 'connections'
  | 'pingmtr'
  | 'throughput'
  | 'httpload'
  | 'scanner'
  | 'lan'
  | 'maclookup'
  | 'ipcalc'
  | 'webintel'
  | 'bgp'
  | 'osint'
  | 'phone'
  | 'voip'
  | 'monitor'
  | 'lab'
  | 'selftest'
  | 'manual'
  | 'settings';

export interface NavItem {
  id: ViewId;
  label: string;
  phase: number;
  ready?: boolean;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV: NavGroup[] = [
  {
    label: 'General',
    items: [
      { id: 'overview', label: 'Resumen', phase: 0, ready: true },
      { id: 'diagnose', label: 'Diagnóstico rápido', phase: 1, ready: true },
      { id: 'investigations', label: 'Investigaciones', phase: 6, ready: true },
    ],
  },
  {
    label: 'Tráfico',
    items: [
      { id: 'capture', label: 'Captura en vivo', phase: 2, ready: true },
      { id: 'pcap', label: 'Analizador PCAP', phase: 1, ready: true },
      { id: 'flows', label: 'Flujos', phase: 1, ready: true },
      { id: 'endpoints', label: 'Endpoints', phase: 1, ready: true },
      { id: 'geomap', label: 'Mapa GeoIP', phase: 1, ready: true },
      { id: 'connections', label: 'Conexiones', phase: 0, ready: true },
    ],
  },
  {
    label: 'Diagnóstico',
    items: [
      { id: 'pingmtr', label: 'Ping / MTR', phase: 1, ready: true },
      { id: 'throughput', label: 'Rendimiento', phase: 5, ready: true },
      { id: 'httpload', label: 'Prueba de carga HTTP', phase: 5, ready: true },
      { id: 'scanner', label: 'Escáner', phase: 2, ready: true },
      { id: 'lan', label: 'Explorador LAN', phase: 2, ready: true },
      { id: 'maclookup', label: 'Consulta MAC', phase: 0, ready: true },
      { id: 'ipcalc', label: 'Calculadora IP', phase: 0, ready: true },
    ],
  },
  {
    label: 'Inteligencia',
    items: [
      { id: 'webintel', label: 'Inteligencia web', phase: 4, ready: true },
      { id: 'bgp', label: 'Inteligencia BGP', phase: 8, ready: true },
      { id: 'osint', label: 'Inteligencia OSINT', phase: 9, ready: true },
      { id: 'phone', label: 'Teléfono', phase: 4, ready: true },
      { id: 'voip', label: 'Llamadas VoIP', phase: 3, ready: true },
    ],
  },
  {
    label: 'Laboratorio',
    items: [
      { id: 'monitor', label: 'Monitor histórico', phase: 5, ready: true },
      { id: 'lab', label: 'Modo laboratorio', phase: 5, ready: true },
    ],
  },
  {
    label: 'Sistema',
    items: [
      { id: 'selftest', label: 'Estado del producto', phase: 7, ready: true },
      { id: 'manual', label: 'Manual', phase: 0, ready: true },
      { id: 'settings', label: 'Configuración / Datasets', phase: 0, ready: true },
    ],
  },
];

export function findItem(id: ViewId): NavItem | undefined {
  for (const g of NAV) {
    const it = g.items.find((i) => i.id === id);
    if (it) return it;
  }
  return undefined;
}
