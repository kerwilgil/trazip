import type { PcapResult, LanHostResult, LanScanSummary, voip, report } from './api';
import { diagnoseCall, failureSenderIP } from '../components/CallFlowDiagram';

// buildSessionReport composes a módulo-26 report.Report from whatever the
// current UI session actually has loaded (PCAP, VoIP, LAN scan) — sections
// only exist for data that exists, and the backend (ExportSessionReport)
// fills provenance metadata before rendering. The wording here follows the
// report package's own rule: never smooth over uncertainty.

export interface SessionReportInput {
  pcapPath: string;
  pcapResult: PcapResult | null;
  voipPath: string;
  voipResult: voip.Result | null;
  lanScanRange: string;
  lanScanHosts: LanHostResult[];
  lanScanSummary: LanScanSummary | null;
}

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

export function hasSessionData(input: SessionReportInput): boolean {
  return Boolean(input.pcapResult || input.voipResult || input.lanScanHosts.length > 0);
}

export function buildSessionReport(input: SessionReportInput): report.Report {
  const sections: report.Section[] = [];
  const loaded: string[] = [];

  if (input.pcapResult) {
    const r = input.pcapResult;
    loaded.push('captura PCAP');
    const top = [...(r.endpoints ?? [])]
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 15);
    const pcapTables: report.Table[] = [];
    if (top.length > 0) {
      pcapTables.push({
        title: 'Top endpoints por volumen',
        columns: ['IP', 'Clases', 'País', 'Organización', 'Paquetes', 'Bytes'],
        rows: top.map((e) => [
          e.addr,
          (e.classes || []).join(' '),
          e.country || '',
          e.org || '',
          String(e.packets),
          humanBytes(e.bytes),
        ]),
      } as report.Table);
    }
    if ((r.scanDetection?.findings ?? []).length > 0) {
      pcapTables.push({
        title: 'Detecciones pasivas de reconocimiento',
        columns: ['Tipo', 'Origen', 'Objetivo / puerto', 'Distintos', 'Intentos', 'Confianza', 'Resumen'],
        rows: r.scanDetection.findings.map((f) => [
          f.kind === 'vertical' ? 'vertical' : 'horizontal',
          f.source,
          f.kind === 'vertical' ? (f.target || '') : `TCP/${f.port || ''}`,
          String(f.distinct),
          String(f.attempts),
          `${f.confidence}%`,
          f.summary,
        ]),
      } as report.Table);
    }
    sections.push({
      title: 'Captura PCAP',
      summary: `Archivo: ${input.pcapPath}`,
      keyValues: [
        { key: 'Paquetes analizados', value: String(r.totalPackets) },
        { key: 'Flujos', value: String(r.totalFlows) },
        { key: 'Endpoints únicos', value: String(r.totalEndpoints) },
        { key: 'Patrones de reconocimiento', value: String(r.scanDetection?.findings?.length ?? 0) },
        { key: 'GeoIP/ASN offline', value: r.geoAvailable ? 'disponible' : 'no instalado' },
      ],
      tables: pcapTables,
      notes: [
        'GeoIP/ASN es enriquecimiento offline (GeoLite2) — precisión a nivel país/ciudad, no ubicación exacta.',
        'Una detección de reconocimiento describe un patrón observable y requiere validar el alcance; no afirma por sí sola intención maliciosa.',
      ],
    } as report.Section);
  }

  if (input.voipResult) {
    const v = input.voipResult;
    loaded.push('análisis VoIP');
		const voipTables: report.Table[] = [];
		if ((v.calls ?? []).length > 0) {
			voipTables.push({title:'Detalle por llamada',columns:['De','A','Resultado','Duración','Diagnóstico'],rows:(v.calls??[]).map((c)=>[
				c.from||'?',c.to||'?',c.established?'establecida':`fallida${c.failureCode?` (SIP ${c.failureCode}${failureSenderIP(c)?`, respondido por ${failureSenderIP(c)}`:''})`:''}`,c.durationSec?`${c.durationSec.toFixed(1)}s`:'—',diagnoseCall(c)||'sin anomalías observadas',
			])} as report.Table);
		}
		if ((v.audit?.findings ?? []).length > 0) {
			voipTables.push({title:'Auditoría defensiva VoIP',columns:['Nivel','Categoría','Call-ID','Resumen','Evidencia','Confianza'],rows:v.audit.findings.map((f)=>[f.level,f.category,f.callId||'',f.summary,f.evidence||'',`${f.confidence}%`])} as report.Table);
		}
    sections.push({
      title: 'Llamadas VoIP',
      summary: `Archivo: ${input.voipPath}`,
      keyValues: [
        { key: 'Llamadas correlacionadas', value: String(v.totalCalls) },
        { key: 'Establecidas', value: String(v.established) },
        { key: 'Fallidas', value: String(v.failed) },
				{ key: 'Hallazgos defensivos', value: String(v.audit?.findings?.length ?? 0) },
      ],
      tables: voipTables,
      notes: [
        'Diagnóstico desde una captura pasiva de un solo punto: la atribución es sólida cuando el extremo respondió explícitamente; un timeout no permite distinguir emisor/destino/red intermedia.',
      ],
    } as report.Section);
  }

  if (input.lanScanHosts.length > 0) {
    loaded.push('escaneo LAN');
    const s = input.lanScanSummary;
    sections.push({
      title: 'Escaneo LAN activo',
      summary: `Rango: ${input.lanScanRange || (s?.range ?? '')}`,
      keyValues: s
        ? [
            { key: 'IPs probadas', value: String(s.totalIPs) },
            { key: 'Hosts activos', value: String(s.upCount) },
            { key: 'Duración', value: `${s.durationSec.toFixed(1)}s` },
          ]
        : [],
      tables: [
        {
          title: 'Dispositivos encontrados',
          columns: ['IP', 'Hostname', 'MAC', 'Fabricante', 'Puertos abiertos', 'SO estimado'],
          rows: input.lanScanHosts.map((h) => [
            h.ip,
            h.hostname || '',
            h.mac || '',
            h.vendor || '',
            (h.openPorts || []).map((p) => String(p.port)).join(' '),
            h.osGuess || '',
          ]),
        },
      ],
      notes: ['Escaneo autorizado por el operador sobre su propia red. El SO estimado es una heurística (TTL/puertos), no una identificación definitiva.'],
    } as report.Section);
  }

  return {
    title: 'Informe de sesión TRAZIP',
    // Backend fills generatedAt/trazipVersion (provenance lives server-side).
    meta: { generatedAt: '', trazipVersion: '' },
    summary:
      loaded.length > 0
        ? `Resultados cargados en esta sesión: ${loaded.join(', ')}. Cada sección refleja exactamente lo que el operador tenía abierto al exportar.`
        : 'Sesión sin resultados cargados.',
    sections,
  } as report.Report;
}
