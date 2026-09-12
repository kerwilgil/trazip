// Thin wrapper over the generated Wails bindings. Centralizes access so views
// never import binding paths directly, and so calls degrade gracefully when the
// app runs in a plain browser (no Wails runtime) during `npm run dev`.
import {
  Capabilities as goCapabilities,
  PublicIP as goPublicIP,
  ClassifyIP as goClassifyIP,
  QuickDiagnose as goQuickDiagnose,
  StartSession as goStartSession,
  ListSessions as goListSessions,
  CancelSession as goCancelSession,
  AnalyzePcap as goAnalyzePcap,
  LanDiscover as goLanDiscover,
  GeoStatus as goGeoStatus,
  GeoUpdateStatus as goGeoUpdateStatus,
  SaveGeoUpdateSettings as goSaveGeoUpdateSettings,
  CheckGeoUpdates as goCheckGeoUpdates,
  CaptureAvailable as goCaptureAvailable,
  CaptureDevices as goCaptureDevices,
  WifiAvailable as goWifiAvailable,
  WifiScan as goWifiScan,
  WifiStatus as goWifiStatus,
  WifiPosture as goWifiPosture,
  LanTrustAssess as goLanTrustAssess,
  ExposureCompare as goExposureCompare,
  PassiveOSINT as goPassiveOSINT,
  DNSResolvers as goDNSResolvers,
  DNSRecordTypes as goDNSRecordTypes,
  DNSQuery as goDNSQuery,
  DNSCompare as goDNSCompare,
  DNSReversePTR as goDNSReversePTR,
  DNSResolveSRVTargets as goDNSResolveSRVTargets,
  DNSDiscoverSRVSIP as goDNSDiscoverSRVSIP,
  TLSInspect as goTLSInspect,
  HTTPInspect as goHTTPInspect,
  WebIntelAnalyze as goWebIntelAnalyze,
  RDAPLookupIP as goRDAPLookupIP,
  RDAPLookupASN as goRDAPLookupASN,
  RDAPLookupDomain as goRDAPLookupDomain,
  BGPRoutingStatus as goBGPRoutingStatus,
  BGPRPKIValidate as goBGPRPKIValidate,
  BGPOverview as goBGPOverview,
  BGPPrefixes as goBGPPrefixes,
  BGPSecurity as goBGPSecurity,
  BGPNeighbours as goBGPNeighbours,
  BGPTopology as goBGPTopology,
  BGPRealtimeInfo as goBGPRealtimeInfo,
  BGPHistory as goBGPHistory,
  BGPlay as goBGPlay,
  BGPCountryObservatory as goBGPCountryObservatory,
  BGPGlobalObservatory as goBGPGlobalObservatory,
  BGPASNObservatory as goBGPASNObservatory,
  BGPRPKIObservatory as goBGPRPKIObservatory,
  BGPBogonLookup as goBGPBogonLookup,
  ReputationAssess as goReputationAssess,
  MonitorAddTarget as goMonitorAddTarget,
  MonitorListTargets as goMonitorListTargets,
  MonitorRemoveTarget as goMonitorRemoveTarget,
  MonitorHistory as goMonitorHistory,
  MonitorCompareWindows as goMonitorCompareWindows,
  MonitorReport as goMonitorReport,
  MonitorPinBaseline as goMonitorPinBaseline,
  MonitorClearBaseline as goMonitorClearBaseline,
  MonitorCompareToBaseline as goMonitorCompareToBaseline,
  VoipQualityAddTarget as goVoipQualityAddTarget,
  VoipQualityListTargets as goVoipQualityListTargets,
  VoipQualityRemoveTarget as goVoipQualityRemoveTarget,
  VoipQualityHistory as goVoipQualityHistory,
  VoipQualityCompareWindows as goVoipQualityCompareWindows,
  LabScenarios as goLabScenarios,
  LabRunScenario as goLabRunScenario,
  LabReport as goLabReport,
  NetClassSources as goNetClassSources,
  NetClassUpdate as goNetClassUpdate,
  NetClassRemove as goNetClassRemove,
  MACLookup as goMACLookup,
  ThreatFeedSources as goThreatFeedSources,
  ThreatFeedUpdate as goThreatFeedUpdate,
  ThreatFeedRemove as goThreatFeedRemove,
  PhoneAnalyze as goPhoneAnalyze,
  OUIInfo as goOUIInfo,
  OUIUpdate as goOUIUpdate,
  OUIRemove as goOUIRemove,
  IPCalcAnalyze as goIPCalcAnalyze,
  IPCalcSplit as goIPCalcSplit,
  IPCalcVLSM as goIPCalcVLSM,
  IPCalcAggregate as goIPCalcAggregate,
  IPCalcContains as goIPCalcContains,
  IPCalcCustomerPlan as goIPCalcCustomerPlan,
  UpdateStatus as goUpdateStatus,
  CheckForUpdates as goCheckForUpdates,
  UpdateAutoCheckEnabled as goUpdateAutoCheckEnabled,
  SetUpdateAutoCheck as goSetUpdateAutoCheck,
  DownloadUpdate as goDownloadUpdate,
  CancelUpdateDownload as goCancelUpdateDownload,
  InvestigationCreate as goInvestigationCreate,
  InvestigationList as goInvestigationList,
  InvestigationGet as goInvestigationGet,
  InvestigationUpdateMetadata as goInvestigationUpdateMetadata,
  InvestigationDelete as goInvestigationDelete,
  InvestigationRemoveEntry as goInvestigationRemoveEntry,
  InvestigationUpdateEntryNote as goInvestigationUpdateEntryNote,
  InvestigationReport as goInvestigationReport,
  InvestigationAddDiagnose as goInvestigationAddDiagnose,
  InvestigationAddPcap as goInvestigationAddPcap,
  InvestigationAddMonitorEvent as goInvestigationAddMonitorEvent,
  InvestigationAddVoIPCall as goInvestigationAddVoIPCall,
  SelfTestLocal as goSelfTestLocal,
  ListOSINTProviders as goListOSINTProviders,
} from '../../wailsjs/go/api/Service';
import {
  PickPcapFile as goPickPcapFile,
  StartVoIPAnalysis as goStartVoIPAnalysis,
  StopVoIPAnalysis as goStopVoIPAnalysis,
  StartDiagnose as goStartDiagnose,
  StopDiagnose as goStopDiagnose,
  ExportCallAudio as goExportCallAudio,
	ExportVoIPCallAudio as goExportVoIPCallAudio,
	PreviewVoIPCallAudio as goPreviewVoIPCallAudio,
  StartThroughput as goStartThroughput,
  StopThroughput as goStopThroughput,
  StartThroughputServer as goStartThroughputServer,
  StopThroughputServer as goStopThroughputServer,
  ThroughputServerAddr as goThroughputServerAddr,
  ThroughputAccessCode as goThroughputAccessCode,
  StartHTTPLoad as goStartHTTPLoad,
  StopHTTPLoad as goStopHTTPLoad,
  MonitorStart as goMonitorStart,
  MonitorStop as goMonitorStop,
  MonitorExportReport as goMonitorExportReport,
  LabExportReport as goLabExportReport,
  ExportSessionReport as goExportSessionReport,
  ServiceAudit as goServiceAudit,
  InstallUpdate as goInstallUpdate,
  InvestigationExportReport as goInvestigationExportReport,
  BGPRealtimeStart as goBGPRealtimeStart,
  BGPRealtimeStop as goBGPRealtimeStop,
} from '../../wailsjs/go/main/App';
import {
  StartPing as goStartPing,
  StopPing as goStopPing,
  StartTrace as goStartTrace,
  StopTrace as goStopTrace,
  StartMTR as goStartMTR,
  StopMTR as goStopMTR,
  StartScanAdvanced as goStartScanAdvanced,
  StopScan as goStopScan,
  StartLanScan as goStartLanScan,
  StopLanScan as goStopLanScan,
  StartCapture as goStartCapture,
  StartTZSPCapture as goStartTZSPCapture,
  StopCapture as goStopCapture,
  StartConnMon as goStartConnMon,
  StopConnMon as goStopConnMon,
  SetWindowBackground as goSetWindowBackground,
} from '../../wailsjs/go/main/App';
import { EventsOn, BrowserOpenURL } from '../../wailsjs/runtime';
import { api, voip, dnsintel, tlsintel, httpintel, webintel, rdap, bgp, reputation, throughput, monitor, quality, report, lab, wifi, ipcalc, sdp, model, investigation, correlation } from '../../wailsjs/go/models';

function hasRuntime(): boolean {
  return typeof window !== 'undefined' && Boolean((window as any).go);
}

interface BridgedEvent {
  sessionId: string;
  topic: string;
  kind: string;
  payload: unknown;
}

const bridgedHandlers = new Map<string, Set<(payload: any) => void>>();
const bridgedBacklog = new Map<string, BridgedEvent[]>();
let bridgeStarted = false;

function bridgedKey(topic: string, sessionId: string): string {
  return topic + ':' + sessionId;
}

function cleanupBridgedSession(sessionId: string): void {
  const suffix = ':' + sessionId;
  for (const key of bridgedHandlers.keys()) if (key.endsWith(suffix)) bridgedHandlers.delete(key);
  for (const key of bridgedBacklog.keys()) if (key.endsWith(suffix)) bridgedBacklog.delete(key);
}

function deliverBridgedEvent(event: BridgedEvent): boolean {
  const handlers = bridgedHandlers.get(bridgedKey(event.topic, event.sessionId));
  if (!handlers?.size) return false;
  for (const handler of [...handlers]) handler(event.payload);
  if (event.kind === 'done') cleanupBridgedSession(event.sessionId);
  return true;
}

function ensureEventBridge(): void {
  if (bridgeStarted || !hasRuntime()) return;
  bridgeStarted = true;
  EventsOn('trazip:event', (event: BridgedEvent) => {
    if (deliverBridgedEvent(event)) return;
    const key = bridgedKey(event.topic, event.sessionId);
    const queue = bridgedBacklog.get(key) ?? [];
    if (queue.length >= 256) queue.shift();
    queue.push(event);
    bridgedBacklog.set(key, queue);
    if (bridgedBacklog.size > 128) bridgedBacklog.delete(bridgedBacklog.keys().next().value!);
  });
}

function onSessionEvent<T>(topic: string, id: string, handler: (payload: T) => void): () => void {
  ensureEventBridge();
  const key = bridgedKey(topic, id);
  const handlers = bridgedHandlers.get(key) ?? new Set<(payload: any) => void>();
  handlers.add(handler);
  bridgedHandlers.set(key, handlers);
  const queued = bridgedBacklog.get(key);
  if (queued?.length) {
    bridgedBacklog.delete(key);
    queueMicrotask(() => queued.forEach((event) => deliverBridgedEvent(event)));
  }
  return () => {
    handlers.delete(handler);
    if (!handlers.size) bridgedHandlers.delete(key);
  };
}

ensureEventBridge();

export const backendAvailable = hasRuntime;

// Keeps the native window's background colour matched to the UI theme — see
// App.SetWindowBackground for why a static startup colour causes an
// intermittent flash. No-op in the browser preview.
export function setWindowBackground(theme: 'dark' | 'light'): void {
  if (!hasRuntime()) return;
  void goSetWindowBackground(theme);
}

export async function getCapabilities(): Promise<api.Capabilities> {
  if (!hasRuntime()) {
    return api.Capabilities.createFrom({
      platform: 'browser',
      arch: '-',
      elevated: false,
      liveCapture: false,
      captureNote: 'Sin runtime Wails (modo navegador). Ejecuta `wails dev`.',
      rawSockets: false,
      version: 'dev',
    });
  }
  return goCapabilities();
}

export async function publicIP(): Promise<api.PublicIPResult> {
  if (!hasRuntime()) return api.PublicIPResult.createFrom({ source: 'api64.ipify.org', err: 'Sin runtime Wails.' });
  return goPublicIP();
}

export async function quickDiagnose(input: string): Promise<api.DiagnoseResult> {
  return goQuickDiagnose(input);
}

// ---- Diagnose 2.0 (correlated diagnosis, TRAZIP V1) ----
//
// DiagnosticReport/DiagnosticStage/NetworkAction are defined by hand here
// rather than imported from wailsjs/go/models: Wails only generates a
// model's TS class when it appears in some bound method's own signature,
// and diagnosis.DiagnosticReport deliberately does NOT (Phase B.1 fix #6 —
// App.StartDiagnose returns just a session id; the report itself only ever
// arrives as this event's payload, never as a direct return value, so nothing
// bypasses session/scope authorization to fetch one). Same pattern already
// used below for PingReply/PingStats/TraceHop, which arrive the same way.

export type DiagnoseMode = 'offline' | 'standard' | 'full';

export interface NetworkAction {
  stageId: string;
  kind: string;
  subject: string;
  destinationClass: string;
  dataSent: string;
  queriedAt: string;
}

export interface DiagnosticStage {
  id: string;
  label: string;
  status: string;
  summary: string;
  subjects?: string[];
  evidence?: model.Evidence[];
  limitations?: string[];
  networkOut: boolean;
  networkActions?: NetworkAction[];
  durationMs: number;
}

export interface DiagnosticReport {
  target: string;
  kind: string;
  mode: string;
  resolvedAddresses?: string[];
  primaryAddress?: string;
  summary: string;
  level: string;
  confidence: number;
  evidence?: model.Evidence[];
  counterEvidence?: model.Evidence[];
  limitations?: string[];
  stages: DiagnosticStage[];
  networkOut: boolean;
  networkActions?: NetworkAction[];
  startedAt: string;
  completedAt: string;
  durationMs: number;
}

/**
 * Starts a cancellable Diagnose 2.0 run. `authorized` is only enforced for
 * standard/full (active probes leave the host); offline never needs it.
 * Returns the run id used to subscribe/stop.
 */
export async function startDiagnose(input: string, mode: DiagnoseMode, authorized: boolean): Promise<string> {
  return goStartDiagnose(input, mode, authorized);
}

export async function stopDiagnose(id: string): Promise<void> {
  return goStopDiagnose(id);
}

/** Subscribes to a Diagnose 2.0 run's completion. Returns an unsubscribe function. */
export function subscribeDiagnose(id: string, onDone: (report: DiagnosticReport, err: string) => void): () => void {
  if (!hasRuntime()) return () => {};
  return onSessionEvent('diagnose:done', id, (data: { report: DiagnosticReport; err: string }) => {
    onDone(data.report, data.err || '');
  });
}

export async function classifyIP(ip: string): Promise<api.AddrReport> {
  return goClassifyIP(ip);
}

export async function startSession(label: string): Promise<api.SessionInfo> {
  return goStartSession(label);
}

export async function listSessions(): Promise<api.SessionInfo[]> {
  return goListSessions();
}

export async function cancelSession(id: string): Promise<void> {
  return goCancelSession(id);
}

// ---- Ping streaming (Fase 1) ----

export interface PingReply {
  seq: number;
  from: string;
  rttMs: number;
  ttl: number;
  size: number;
  ok: boolean;
  err?: string;
}

export interface PingStats {
  sent: number;
  recv: number;
  lost: number;
  lossPct: number;
  minMs: number;
  avgMs: number;
  maxMs: number;
  stdDevMs: number;
  jitterMs: number;
  lastMs: number;
}

export interface PingConfig {
  target: string;
  count: number; // 0 = continuous
  intervalMs: number;
  timeoutMs: number;
  payload: number;
}

/** Starts a streaming ping. Returns the run id used to subscribe/stop. */
export async function startPing(cfg: PingConfig): Promise<string> {
  return goStartPing(cfg.target, cfg.count, cfg.intervalMs, cfg.timeoutMs, cfg.payload, true);
}

export async function stopPing(id: string): Promise<void> {
  return goStopPing(id);
}

/** Subscribes to a ping run. Returns an unsubscribe function. */
export function subscribePing(
  id: string,
  onReply: (reply: PingReply, stats: PingStats) => void,
  onDone: (addr: string, err: string) => void,
  onResolved?: (addr: string, err: string) => void,
): () => void {
  if (!hasRuntime()) return () => {};
  // Llega antes de la primera sonda, para poder mostrar la IP de destino
  // aunque después nada responda.
  const offResolved = onSessionEvent('ping:resolved', id, (data: { addr?: string; err?: string }) => {
    onResolved?.(data.addr || '', data.err || '');
  });
  const offReply = onSessionEvent('ping:reply', id, (data: { reply: PingReply; stats: PingStats }) => {
    onReply(data.reply, data.stats);
  });
  const offDone = onSessionEvent('ping:done', id, (data: { addr: string; err: string }) => {
    onDone(data.addr, data.err);
  });
  return () => {
    offResolved();
    offReply();
    offDone();
  };
}

// ---- Traceroute streaming (Fase 1) ----

export interface TraceProbe {
  rttMs: number;
  ok: boolean;
}

export interface TraceHop {
  ttl: number;
  addr: string;
  hostname?: string;
  probes: TraceProbe[];
  bestMs: number;
  avgMs: number;
  timeout: boolean;
  reached: boolean;
  classes?: string[];
  country?: string;
  countryCode?: string;
  city?: string;
  region?: string;
  asn?: number;
  org?: string;
  lat?: number;
  lon?: number;
}

export async function startTrace(
  target: string,
  maxHops: number,
  probes: number,
  timeoutMs: number,
  resolveDNS: boolean,
): Promise<string> {
  return goStartTrace(target, maxHops, probes, timeoutMs, resolveDNS, true);
}

export async function stopTrace(id: string): Promise<void> {
  return goStopTrace(id);
}

/** Subscribes to a traceroute run. Returns an unsubscribe function. */
export function subscribeTrace(
  id: string,
  onHop: (hop: TraceHop) => void,
  onDone: (addr: string, err: string) => void,
  onResolved?: (addr: string, err: string) => void,
): () => void {
  if (!hasRuntime()) return () => {};
  const offResolved = onSessionEvent('trace:resolved', id, (data: { addr?: string; err?: string }) => {
    onResolved?.(data.addr || '', data.err || '');
  });
  const offHop = onSessionEvent('trace:hop', id, (hop: TraceHop) => onHop(hop));
  const offDone = onSessionEvent('trace:done', id, (data: { addr: string; err: string }) => {
    onDone(data.addr, data.err);
  });
  return () => {
    offResolved();
    offHop();
    offDone();
  };
}

// ---- MTR streaming (Fase 1) ----

export interface MtrHop {
  ttl: number;
  addr: string;
  hostname?: string;
  sent: number;
  recv: number;
  lossPct: number;
  lastMs: number;
  bestMs: number;
  avgMs: number;
  worstMs: number;
  stdDevMs: number;
  jitterMs: number;
  classes?: string[];
  reached: boolean;
  country?: string;
  countryCode?: string;
  city?: string;
  region?: string;
  asn?: number;
  org?: string;
  lat?: number;
  lon?: number;
}

export async function startMTR(
  target: string,
  maxHops: number,
  timeoutMs: number,
  roundMs: number,
  resolveDNS: boolean,
): Promise<string> {
  return goStartMTR(target, maxHops, timeoutMs, roundMs, resolveDNS, true);
}

export async function stopMTR(id: string): Promise<void> {
  return goStopMTR(id);
}

/** Subscribes to an MTR run; each round delivers the full hop table. */
export function subscribeMTR(
  id: string,
  onUpdate: (hops: MtrHop[]) => void,
  onDone: (addr: string, err: string) => void,
  onResolved?: (addr: string, err: string) => void,
): () => void {
  if (!hasRuntime()) return () => {};
  const offResolved = onSessionEvent('mtr:resolved', id, (data: { addr?: string; err?: string }) => {
    onResolved?.(data.addr || '', data.err || '');
  });
  const offUpdate = onSessionEvent('mtr:update', id, (hops: MtrHop[]) => onUpdate(hops));
  const offDone = onSessionEvent('mtr:done', id, (data: { addr: string; err: string }) => {
    onDone(data.addr, data.err);
  });
  return () => {
    offResolved();
    offUpdate();
    offDone();
  };
}

// ---- PCAP analysis (Fase 1) ----

export interface PktSummary {
  index: number;
  time: string;
  timeUnix: number;
  length: number;
  src: string;
  dst: string;
  srcMAC?: string;
  dstMAC?: string;
  etherType?: string;
  srcPort?: number;
  dstPort?: number;
  proto: string;
  transport?: string;
  ttl?: number;
  tcpFlags?: string[];
  payloadLen?: number;
  payloadHex?: string;
  info: string;
  app?: string;
  layers: string[];
  err?: string;
  /** Campos 802.11: solo presentes en capturas WiFi (modo monitor, radiotap o PPI). */
  ssid?: string;
  bssid?: string;
  channel?: number;
  wifiType?: string;
}

/** Posición GPS que acompañaba a una trama en una captura PPI. */
export interface GPSFix {
  latitude?: number;
  longitude?: number;
  altitudeM?: number;
}

export interface FlowRow {
  proto: string;
  aAddr: string;
  aPort?: number;
  bAddr: string;
  bPort?: number;
  pktsAB: number;
  pktsBA: number;
  bytesAB: number;
  bytesBA: number;
  packets: number;
  bytes: number;
  start?: string;
  end?: string;
  durationSec: number;
  apps?: string[];
  resets?: number;
}

export interface PcapInfo {
  format: string;
  linkType: string;
  packets: number;
  bytes: number;
  firstTime?: string;
  lastTime?: string;
  durationSec: number;
  truncated: boolean;
  /** Número crudo del link type: cuando no hay decodificador, `linkType` es "UnknownLinkType". */
  linkTypeNum: number;
  /** Paquetes cuya capa de enlace no se pudo parsear. Si iguala a `packets`, el medio no es legible. */
  undecodable: number;
  /** Sobres TZSP abiertos: lo analizado es el tráfico transportado, no el transporte. */
  tzspDecapsulated: number;
  /** Tramas que llegaron con posición GPS (capturas PPI de reconocimiento WiFi). */
  gpsFixes: number;
  firstFix?: GPSFix;
  lastFix?: GPSFix;
}

export interface TalkerRow {
  key: string;
  label: string;
  packets: number;
  bytes: number;
  country?: string;
  asn?: number;
  org?: string;
}

export interface PcapResult {
  info: PcapInfo;
  packets: PktSummary[];
  flows: FlowRow[];
  totalPackets: number;
  shownPackets: number;
  totalFlows: number;
  topHosts: TalkerRow[];
  topCountries: TalkerRow[];
  topASN: TalkerRow[];
  geoAvailable: boolean;
  endpoints: EndpointInfo[];
  totalEndpoints: number;
  scanDetection: ScanDetectionResult;
  netDiag: NetDiagResult;
  summary: PcapIncidentSummary;
}

// ---- Resumen de captura (Phase C: correlated incident summary) ----

export interface PcapFinding {
  id: string;
  category: string;
  summary: string;
  level: string;
  confidence: number;
  evidence?: model.Evidence[];
  limitations?: string[];
  // Domain-neutral — which kind of evidence backs this finding, not which
  // UI tab shows it. The frontend maps this to a tab itself (see
  // PcapAnalyzer's SOURCE_AREA_TAB); the backend has no opinion on tabs.
  sourceArea: 'netdiag' | 'scan_detection' | 'flows' | 'packets';
}

export interface PcapSummaryStats {
  packets: number;
  flows: number;
  endpoints: number;
  publicEndpoints: number;
  privateEndpoints: number;
  otherEndpoints: number;
  geoAvailable: boolean;
  sipDetected: boolean;
  topTalker?: string;
  topASN?: string;
  tcpResets: number;
}

export interface PcapIncidentSummary {
  summary: string;
  level: string;
  confidence: number;
  findings: PcapFinding[];
  evidence?: model.Evidence[];
  limitations?: string[];
  stats: PcapSummaryStats;
}

// ---- Salud de red (internal/detection/netdiag) ----
// El backend garantiza que findings y neighbors son siempre arreglos, nunca
// null: un slice nil de Go marshalea a null y un .map() sobre null tumba la
// vista. Ver TestEmptyResultMarshalsArraysNotNull.

export interface NetDiagFinding {
  id: string;
  kind: 'loop' | 'broadcast_storm' | 'duplicate_ip' | 'rogue_dhcp';
  severity: 'high' | 'medium' | 'low';
  confidence: number;
  subject: string;
  count: number;
  ratePerSec?: number;
  evidence: string[];
  summary: string;
  explain: string;
  caveat?: string;
}

export interface NetDiagNeighbor {
  mac: string;
  ip?: string;
  protocol: string;
  vendor?: string;
  count: number;
}

export interface NetDiagResult {
  frames: number;
  broadcasts: number;
  loopedFrames: number;
  findings: NetDiagFinding[];
  neighbors: NetDiagNeighbor[];
  truncated: boolean;
}

export const emptyNetDiag: NetDiagResult = {
  frames: 0, broadcasts: 0, loopedFrames: 0, findings: [], neighbors: [], truncated: false,
};

export interface ScanDetectionFinding {
  id: string;
  kind: 'vertical' | 'horizontal';
  severity: 'low' | 'medium' | 'high';
  confidence: number;
  source: string;
  target?: string;
  port?: number;
  distinct: number;
  attempts: number;
  firstSeen?: string;
  lastSeen?: string;
  durationSec: number;
  ports?: number[];
  targets?: string[];
  summary: string;
  explain: string;
  mitre: string;
}

export interface ScanDetectionResult {
  initialSyn: number;
  vertical: number;
  horizontal: number;
  findings: ScanDetectionFinding[];
  truncated: boolean;
}

export interface EvidenceInfo {
  type: string;
  value: string;
  source: string;
  provenance: string;
  timestamp: string;
  confidence: number;
  explain?: string;
}

export interface EndpointInfo {
  addr: string;
  classes?: string[];
  firstSeen?: string;
  lastSeen?: string;
  packets: number;
  bytes: number;
  country?: string;
  countryCode?: string;
  city?: string;
  asn?: number;
  org?: string;
  evidence: EvidenceInfo[];
}

export interface GeoDataset {
  name: string;
  path: string;
  type?: string;
  buildEpoch?: number;
  present: boolean;
}

export async function geoStatus(): Promise<GeoDataset[]> {
  if (!hasRuntime()) return [];
  return goGeoStatus() as unknown as Promise<GeoDataset[]>;
}

export interface GeoUpdateStatus {
  accountId: string;
  hasLicenseKey: boolean;
  autoUpdate: boolean;
  busy: boolean;
  lastCheck?: string;
  lastSuccess?: string;
  lastError?: string;
  dataDir: string;
  datasets: GeoDataset[];
}

export interface GeoUpdateResult {
  checkedAt: string;
  updated: string[];
  current: string[];
}

export async function geoUpdateStatus(): Promise<GeoUpdateStatus> {
  return goGeoUpdateStatus() as unknown as Promise<GeoUpdateStatus>;
}

export async function saveGeoUpdateSettings(
  accountID: string,
  licenseKey: string,
  autoUpdate: boolean,
): Promise<GeoUpdateStatus> {
  return goSaveGeoUpdateSettings(accountID, licenseKey, autoUpdate) as unknown as Promise<GeoUpdateStatus>;
}

export async function checkGeoUpdates(force: boolean): Promise<GeoUpdateResult> {
  return goCheckGeoUpdates(force) as unknown as Promise<GeoUpdateResult>;
}

// TRAZIP self-update — checks only kerwilgil/trazip-releases (a public,
// binaries-only distribution repo, separate from the private source repo).
// See internal/update's own package doc for the full design: Ed25519-signed
// manifest, SHA-256 asset hash, no telemetry of any kind in the request.
export type UpdateLifecycleStatus =
  | 'idle' | 'checking' | 'available' | 'downloading' | 'verifying' | 'ready' | 'installing' | 'error';

export interface UpdateAsset {
  name: string;
  url: string;
  size: number;
  sha256: string;
}

export interface UpdateReleaseInfo {
  currentVersion: string;
  latestVersion: string;
  available: boolean;
  publishedAt: string;
  notesUrl: string;
  asset: UpdateAsset;
}

export interface UpdateStatusSnapshot {
  status: UpdateLifecycleStatus;
  info?: UpdateReleaseInfo;
  downloaded?: number;
  total?: number;
  error?: string;
  installPath?: string;
  lastCheck?: string;
}

export async function updateStatus(): Promise<UpdateStatusSnapshot> {
  if (!hasRuntime()) return { status: 'idle' };
  return goUpdateStatus() as unknown as Promise<UpdateStatusSnapshot>;
}

/** "Buscar ahora" (force=true) always hits the network; the startup auto-check does not call this directly. */
export async function checkForUpdates(force: boolean): Promise<UpdateReleaseInfo> {
  return goCheckForUpdates(force) as unknown as Promise<UpdateReleaseInfo>;
}

export async function updateAutoCheckEnabled(): Promise<boolean> {
  if (!hasRuntime()) return false;
  return goUpdateAutoCheckEnabled();
}

export async function setUpdateAutoCheck(enabled: boolean): Promise<void> {
  return goSetUpdateAutoCheck(enabled);
}

/** Starts the verified download in the background — poll updateStatus() for progress. */
export async function downloadUpdate(): Promise<void> {
  return goDownloadUpdate();
}

export async function cancelUpdateDownload(): Promise<void> {
  return goCancelUpdateDownload();
}

/** Launches trazip-updater and exits TRAZIP. Only valid once status is 'ready'. */
export async function installUpdate(): Promise<void> {
  return goInstallUpdate();
}

/** Opens a URL in the user's default browser — never called automatically, only from an explicit click ("Ver novedades"). */
export function openExternal(url: string): void {
  if (hasRuntime()) {
    BrowserOpenURL(url);
    return;
  }
  window.open(url, '_blank', 'noopener,noreferrer');
}

/** Opens a native file dialog and returns the chosen capture path ('' if cancelled). */
export async function pickPcapFile(): Promise<string> {
  if (!hasRuntime()) return '';
  return goPickPcapFile();
}

export async function analyzePcap(path: string): Promise<PcapResult> {
  return goAnalyzePcap(path) as unknown as Promise<PcapResult>;
}

// ---- Port scan (Fase 2) ----

export interface ScanResult {
  port: number;
  state: string; // open | closed | filtered
  service?: string;
  rttMs?: number;
}

export interface ScanSummary {
  target: string;
  scanned: number;
  open: number;
  closed: number;
  filtered: number;
  durationSec: number;
  ratePerSec: number;
  actualRate: number;
  concurrency: number;
  timeoutMs: number;
  cancelled: boolean;
}

export interface ScanOptions {
	ratePerSec: number;
	concurrency: number;
	timeoutMs: number;
}

export interface AuditFinding { level: string; category: string; title: string; detail: string; evidence?: string }
export interface ServiceAuditResult { target: string; port: number; protocol: string; reachable: boolean; metadata: Record<string,string>; findings: AuditFinding[]; durationMs: number; err?: string }
export interface ExposureResult { expected: number[]; observed: number[]; unexpected: number[]; missing: number[]; compliant: boolean }

export async function auditService(target: string, port: number): Promise<ServiceAuditResult> {
	const result = await goServiceAudit(target, port, true) as unknown as ServiceAuditResult;
	return {
		...result,
		metadata: result.metadata ?? {},
		findings: result.findings ?? [],
	};
}

export async function compareExposure(observed: number[], expected: number[]): Promise<ExposureResult> {
	return goExposureCompare(observed, expected) as unknown as Promise<ExposureResult>;
}

export async function startScan(target: string, preset: string, lo: number, hi: number, options: ScanOptions): Promise<string> {
  return goStartScanAdvanced(target, preset, lo, hi, options.ratePerSec, options.concurrency, options.timeoutMs, true);
}

export async function stopScan(id: string): Promise<void> {
  return goStopScan(id);
}

export function subscribeScan(
  id: string,
  onResult: (r: ScanResult, scanned: number, total: number) => void,
  onDone: (sum: ScanSummary, err: string) => void,
): () => void {
  if (!hasRuntime()) return () => {};
  const offResult = onSessionEvent('scan:result', id, (d: { result: ScanResult; scanned: number; total: number }) => {
    onResult(d.result, d.scanned, d.total);
  });
  const offDone = onSessionEvent('scan:done', id, (d: { summary: ScanSummary; err: string }) => {
    onDone(d.summary, d.err);
  });
  return () => {
    offResult();
    offDone();
  };
}

// ---- LAN Explorer (Fase 2) ----

export interface LanIface {
  name: string;
  mac?: string;
  vendor?: string;
  addrs: string[];
  up: boolean;
  loopback: boolean;
  mtu: number;
}

export interface LanNeighbor {
  ip: string;
  mac: string;
  vendor?: string;
  type?: string;
}

export interface LanReport {
  interfaces: LanIface[];
  neighbors: LanNeighbor[];
  note?: string;
}

export async function lanDiscover(): Promise<LanReport> {
  return goLanDiscover() as unknown as Promise<LanReport>;
}

// ---- WiFi network scan ----
// No monitor mode, no special hardware — reads Windows' own cached WLAN scan
// results (WifiAvailable() is false on non-Windows builds). Windows requires
// the system Location toggle on for SSID names to be visible to ANY app
// since 10 1803; WifiScan()'s error message explains that directly.

export async function wifiAvailable(): Promise<boolean> {
  if (!hasRuntime()) return false;
  return goWifiAvailable();
}

export async function wifiScan(): Promise<wifi.Network[]> {
  return goWifiScan() as unknown as Promise<wifi.Network[]>;
}

export interface WifiPostureFinding { level: string; category: string; ssid?: string; bssid?: string; summary: string; evidence?: string }
export interface WifiPostureResult { score: number; networks: number; baselineCreated: boolean; findings: WifiPostureFinding[]; assessedAt: string }

export async function wifiPosture(networks: wifi.Network[]): Promise<WifiPostureResult> {
  return goWifiPosture(networks) as unknown as Promise<WifiPostureResult>;
}

// wifiStatus reports each WLAN interface's connection state — used by Live
// Capture to warn when WiFi is on but not associated to any network.
export async function wifiStatus(): Promise<wifi.IfaceStatus[]> {
  if (!hasRuntime()) return [];
  return goWifiStatus() as unknown as Promise<wifi.IfaceStatus[]>;
}

// ---- LAN active scanner (Bloque 3) ----

export interface LanPortResult {
  port: number;
  state: string;
  service?: string;
  rttMs?: number;
}

export interface LanHostResult {
  ip: string;
  up: boolean;
  hostname?: string;
  mac?: string;
  vendor?: string;
  rttMs?: number;
  openPorts?: LanPortResult[];
  osGuess?: string;
  iface?: string;
}

export interface LanScanSummary {
  range: string;
  totalIPs: number;
  scanned: number;
  upCount: number;
  durationSec: number;
}

export interface TrustFinding { level: string; kind: string; identity: string; ip?: string; mac?: string; summary: string; evidence?: string }
export interface LanTrustResult { baselineCreated: boolean; knownDevices: number; observedDevices: number; findings: TrustFinding[]; updatedAt: string }

export async function lanTrustAssess(hosts: LanHostResult[]): Promise<LanTrustResult> {
	return goLanTrustAssess(hosts as any) as unknown as Promise<LanTrustResult>;
}

export async function startLanScan(rangeSpec: string, iface: string): Promise<string> {
  return goStartLanScan(rangeSpec, iface, true);
}

export async function stopLanScan(id: string): Promise<void> {
  return goStopLanScan(id);
}

export function subscribeLanScan(
  id: string,
  onHost: (h: LanHostResult) => void,
  onProgress: (scanned: number, total: number) => void,
  onDone: (sum: LanScanSummary, err: string) => void,
): () => void {
  if (!hasRuntime()) return () => {};
  const offHost = onSessionEvent('lanscan:host', id, (h: LanHostResult) => onHost(h));
  const offProgress = onSessionEvent('lanscan:progress', id, (d: { scanned: number; total: number }) => onProgress(d.scanned, d.total));
  const offDone = onSessionEvent('lanscan:done', id, (d: { summary: LanScanSummary; err: string }) => onDone(d.summary, d.err));
  return () => {
    offHost();
    offProgress();
    offDone();
  };
}

// ---- Connection monitor ("Conexiones") ----
// Purely passive (reads OS socket tables, sends nothing) — see StartConnMon
// in app.go for why it still goes through the same session ceremony as
// Scanner/LAN Scan/Capture with a fixed "local" target.

export interface ConnRow {
  proto: string;
  localAddr: string;
  localPort: number;
  remoteAddr: string;
  remotePort: number;
  state?: string;
  pid?: number;
  process?: string;
  remote?: api.AddrReport;
}

export interface ConnMonSnapshot {
  connections: ConnRow[];
  total: number;
}

export async function startConnMon(intervalMs: number): Promise<string> {
  return goStartConnMon(intervalMs, true);
}

export async function stopConnMon(id: string): Promise<void> {
  return goStopConnMon(id);
}

export function subscribeConnMon(
  id: string,
  onSnapshot: (snap: ConnMonSnapshot) => void,
  onDone: (err: string) => void,
): () => void {
  if (!hasRuntime()) return () => {};
  const offSnapshot = onSessionEvent('connmon:snapshot', id, (d: ConnMonSnapshot | { err: string }) => {
    if ('connections' in d) onSnapshot(d);
  });
  const offDone = onSessionEvent('connmon:done', id, (d: { err: string }) => onDone(d.err));
  return () => {
    offSnapshot();
    offDone();
  };
}

// ---- Live capture (Fase 2) ----

export interface CaptureDevice {
  name: string;
  description: string;
}

export async function captureAvailable(): Promise<boolean> {
  if (!hasRuntime()) return false;
  return goCaptureAvailable();
}

export async function captureDevices(): Promise<CaptureDevice[]> {
  if (!hasRuntime()) return [];
  return goCaptureDevices() as unknown as Promise<CaptureDevice[]>;
}

export async function startCapture(device: string, promisc: boolean, monitorMode = false): Promise<string> {
  return goStartCapture(device, promisc, monitorMode, true);
}

// startTZSPCapture listens for TZSP-encapsulated traffic a router (e.g.
// MikroTik "/tool sniffer") exports to this machine — same events as
// startCapture ("capture:batch:<id>" / "capture:done:<id>"), same
// subscribeCapture() below works for both sources unchanged.
export async function startTZSPCapture(bindAddr: string): Promise<string> {
  return goStartTZSPCapture(bindAddr, true);
}

export async function stopCapture(id: string): Promise<void> {
  return goStopCapture(id);
}

export function subscribeCapture(
  id: string,
  onBatch: (packets: PktSummary[], total: number, protos: Record<string, number>, scanDetection: ScanDetectionResult, netDiag: NetDiagResult) => void,
  onDone: (err: string) => void,
): () => void {
  if (!hasRuntime()) return () => {};
  const offBatch = onSessionEvent('capture:batch', id, (d: { packets: PktSummary[]; total: number; protos: Record<string, number>; scanDetection: ScanDetectionResult; netDiag: NetDiagResult }) => {
    onBatch(d.packets || [], d.total, d.protos || {}, d.scanDetection || { initialSyn: 0, vertical: 0, horizontal: 0, findings: [], truncated: false }, d.netDiag || emptyNetDiag);
  });
  const offDone = onSessionEvent('capture:done', id, (d: { err: string }) => onDone(d.err));
  return () => {
    offBatch();
    offDone();
  };
}

// ---- VoIP analysis (Fase 3 backend; GUI uses this cancellable contract) ----

export async function startVoIPAnalysis(path: string): Promise<string> {
  return goStartVoIPAnalysis(path);
}

export async function stopVoIPAnalysis(id: string): Promise<void> {
  return goStopVoIPAnalysis(id);
}

export function subscribeVoIPAnalysis(
  id: string,
  onDone: (result: voip.Result, err: string) => void,
): () => void {
  if (!hasRuntime()) return () => {};
  return onSessionEvent('voip:done', id, (d: { result: voip.Result; err: string }) => onDone(d.result, d.err));
}

export async function exportCallAudio(pcapPath: string, ssrc: number, srcHostPort: string): Promise<string> {
  return goExportCallAudio(pcapPath, ssrc, srcHostPort);
}

export async function previewVoipCallAudio(pcapPath: string, call: voip.Call, mode: string): Promise<string> {
	return goPreviewVoIPCallAudio(pcapPath, call, mode);
}

export async function exportVoipCallAudio(pcapPath: string, call: voip.Call, mode: string): Promise<string> {
	return goExportVoIPCallAudio(pcapPath, call, mode);
}

// ---- Throughput (Fase 5) ----

export interface ThroughputParams {
  sessionId?: string;
  proto: 'tcp' | 'udp';
  direction: 'download' | 'upload' | 'bidir';
  durationMs: number;
  streams: number;
  bufferKB: number;
  udpPacket: number;
  targetMbps: number;
  accessCode?: string;
}

export interface ThroughputDirectionResult {
  bytes: number;
  durationSec: number;
  mbps: number;
  packetsSent?: number;
  packetsRecv?: number;
  lossPct?: number;
  jitterMs?: number;
}

export interface ThroughputResult {
  params: ThroughputParams;
  serverAddr: string;
  startedAt: string;
  downStream?: ThroughputDirectionResult;
  upStream?: ThroughputDirectionResult;
  streams: number;
  err?: string;
}

export async function startThroughput(addr: string, params: ThroughputParams): Promise<string> {
  return goStartThroughput(addr, params as unknown as throughput.Params);
}

export async function stopThroughput(id: string): Promise<void> {
  return goStopThroughput(id);
}

export function subscribeThroughput(
  id: string,
  onDone: (result: ThroughputResult, err: string) => void,
): () => void {
  if (!hasRuntime()) return () => {};
  return onSessionEvent('throughput:done', id, (d: { result: ThroughputResult; err: string }) => onDone(d.result, d.err));
}

export async function startThroughputServer(bindAddr: string): Promise<string> {
  return goStartThroughputServer(bindAddr);
}

export async function stopThroughputServer(): Promise<void> {
  return goStopThroughputServer();
}

export async function throughputServerAddr(): Promise<string> {
  return goThroughputServerAddr();
}

export async function throughputAccessCode(): Promise<string> {
  return goThroughputAccessCode();
}

// ---- Prueba de carga HTTP ----
// Types hand-declared (not generated): httpload.ProgressTick/Result only ever
// travel inside Wails event payloads, never as a method return value, so
// `wails generate module` has nothing to build a TS class from — same
// situation as PktSummary/LanHostResult elsewhere in this file.

export interface HTTPLoadParams {
  url: string;
  method?: string;
  concurrency: number;
  durationMs: number;
  headers?: Record<string, string>;
  body?: string;
  targetRps?: number;
}

export interface HTTPLoadProgressTick {
  elapsedMs: number;
  requests: number;
  rps: number;
  avgLatencyMs: number;
  p95LatencyMs: number;
  errorRatePct: number;
  throughputMbps: number;
  statusCounts?: Record<number, number>;
}

export interface HTTPLoadResult {
  params: HTTPLoadParams;
  totalRequests: number;
  durationSec: number;
  avgRps: number;
  p50LatencyMs: number;
  p90LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  errorRatePct: number;
  totalBytes: number;
  avgBytesPerReq: number;
  throughputMbps: number;
  statusCounts?: Record<number, number>;
  err?: string;
}

export async function startHTTPLoad(params: HTTPLoadParams): Promise<string> {
  // authorized is always true here — same convention as startScan/startLanScan/
  // startPing: the operator's own click in the GUI IS the authorization event,
  // there is no separate consent step to gate.
  return goStartHTTPLoad(
    params.url,
    params.method || 'GET',
    params.concurrency,
    params.durationMs,
    params.headers || {},
    params.body || '',
    params.targetRps || 0,
    true,
  );
}

export async function stopHTTPLoad(id: string): Promise<void> {
  return goStopHTTPLoad(id);
}

export function subscribeHTTPLoad(
  id: string,
  onProgress: (tick: HTTPLoadProgressTick) => void,
  onDone: (result: HTTPLoadResult, err: string) => void,
): () => void {
  if (!hasRuntime()) return () => {};
  const offProgress = onSessionEvent('httpload:progress', id, (t: HTTPLoadProgressTick) => onProgress(t));
  const offDone = onSessionEvent('httpload:done', id, (d: { result: HTTPLoadResult; err: string }) => onDone(d.result, d.err));
  return () => {
    offProgress();
    offDone();
  };
}

// ---- Web Intelligence (Fase 4) ----

export async function dnsResolvers(): Promise<dnsintel.Resolver[]> {
  if (!hasRuntime()) return [];
  return goDNSResolvers() as unknown as Promise<dnsintel.Resolver[]>;
}

export async function dnsRecordTypes(): Promise<string[]> {
  if (!hasRuntime()) return [];
  return goDNSRecordTypes();
}

// A Go nil slice (e.g. zero DNS records found) serializes to JSON `null`, and
// the generated Wails model constructor leaves that as `null` rather than
// `[]` — any `.length`/`.map` on it throws, and with no ErrorBoundary that
// silently blanks the whole window. Normalize once here instead of guarding
// every render call site.
function withRecords(r: dnsintel.QueryResult): dnsintel.QueryResult {
  r.records = r.records ?? [];
  return r;
}

export async function dnsQuery(domain: string, recordType: string, resolverAddr: string, dnssec: boolean): Promise<dnsintel.QueryResult> {
  const r = (await goDNSQuery(domain, recordType, resolverAddr, dnssec)) as unknown as dnsintel.QueryResult;
  return withRecords(r);
}

export async function dnsCompare(domain: string, recordType: string, dnssec: boolean): Promise<dnsintel.Comparison> {
  const c = (await goDNSCompare(domain, recordType, dnssec)) as unknown as dnsintel.Comparison;
  c.results = (c.results ?? []).map(withRecords);
  return c;
}

export async function dnsReversePTR(ip: string, resolverAddr: string, dnssec: boolean): Promise<dnsintel.QueryResult> {
  const r = (await goDNSReversePTR(ip, resolverAddr, dnssec)) as unknown as dnsintel.QueryResult;
  return withRecords(r);
}

export async function dnsResolveSRVTargets(targets: string[], resolverAddr: string): Promise<dnsintel.TargetResolution[]> {
  const r = (await goDNSResolveSRVTargets(targets, resolverAddr)) as unknown as dnsintel.TargetResolution[];
  return (r ?? []).map((t) => ({ ...t, ips: t.ips ?? [] }));
}

export async function dnsDiscoverSRVSIP(name: string, resolverAddr: string, dnssec: boolean): Promise<dnsintel.SRVDiscoveryCandidate[]> {
  const r = (await goDNSDiscoverSRVSIP(name, resolverAddr, dnssec)) as unknown as dnsintel.SRVDiscoveryCandidate[];
  const candidates = r ?? [];
  candidates.forEach((c) => { c.result = withRecords(c.result); });
  return candidates;
}

export async function tlsInspect(host: string, port: number, sni: string): Promise<tlsintel.Result> {
  return goTLSInspect(host, port, sni) as unknown as Promise<tlsintel.Result>;
}

export async function httpInspect(url: string, method: string, maxRedirects: number): Promise<httpintel.Result> {
  return goHTTPInspect(url, method, maxRedirects) as unknown as Promise<httpintel.Result>;
}

export async function webIntelAnalyze(input: string, resolverAddr: string): Promise<webintel.Result> {
  return goWebIntelAnalyze(input, resolverAddr) as unknown as Promise<webintel.Result>;
}

export interface PassiveOSINTResult {
  input: string;
  host: string;
  external: boolean;
  addresses: api.AddrReport[];
  rdap?: rdap.Result;
  notes?: string[];
  queriedAt?: string;
  dataSent?: string;
}

export async function passiveOSINT(input: string, external: boolean): Promise<PassiveOSINTResult> {
  return goPassiveOSINT(input, external) as unknown as Promise<PassiveOSINTResult>;
}

// ---- OSINT Intelligence — read-only provider metadata (V1.5-2 foundation,
// V1.5-3 UI). Hand-declared like PassiveOSINTResult above. This is the ONLY
// OSINT backend call in V1.5-3: metadata only, no execution. An empty array
// is a valid "no sources registered yet" state, and is what the browser
// preview (no Wails runtime) returns.
export interface OsintProviderInfo {
  id: string;
  name: string;
  capabilities: string[];
  activityClass: string; // "passive" | "active"
  disclosureClass: string; // "local" | "passive" | "active"
  requiresScope: boolean;
  rateLimit?: string;
}

export async function listOsintProviders(): Promise<OsintProviderInfo[]> {
  if (!hasRuntime()) return [];
  return goListOSINTProviders() as unknown as Promise<OsintProviderInfo[]>;
}

export async function rdapLookupIP(ip: string): Promise<rdap.Result> {
  return goRDAPLookupIP(ip) as unknown as Promise<rdap.Result>;
}

export async function rdapLookupASN(asn: number): Promise<rdap.Result> {
  return goRDAPLookupASN(asn) as unknown as Promise<rdap.Result>;
}

export async function rdapLookupDomain(name: string): Promise<rdap.DomainResult> {
  return goRDAPLookupDomain(name) as unknown as Promise<rdap.DomainResult>;
}

export async function bgpRoutingStatus(resource: string): Promise<bgp.RouteStatus> {
  return goBGPRoutingStatus(resource) as unknown as Promise<bgp.RouteStatus>;
}

export async function bgpRPKIValidate(asn: number, prefix: string): Promise<bgp.RPKIStatus> {
  return goBGPRPKIValidate(asn, prefix) as unknown as Promise<bgp.RPKIStatus>;
}

export async function bgpOverview(resource: string): Promise<bgp.Overview> {
  return goBGPOverview(resource) as unknown as Promise<bgp.Overview>;
}

export async function bgpPrefixes(req: bgp.PrefixPageRequest): Promise<bgp.PrefixPage> {
  return goBGPPrefixes(req) as unknown as Promise<bgp.PrefixPage>;
}

export async function bgpSecurity(resource: string): Promise<bgp.SecurityResult> {
  return goBGPSecurity(resource) as unknown as Promise<bgp.SecurityResult>;
}

export async function bgpNeighbours(asn: number): Promise<bgp.ASNNeighboursResult> {
  return goBGPNeighbours(asn) as unknown as Promise<bgp.ASNNeighboursResult>;
}

export async function bgpTopology(resource: string): Promise<bgp.Graph> {
  return goBGPTopology(resource) as unknown as Promise<bgp.Graph>;
}

// ---- BGP Realtime (v1.2 Gate 6) ----
//
// BGPRealtimeEvent (and the types it nests — BGPPathElement/
// BGPOriginResolution/BGPRealtimeChangeSnapshot/BGPRealtimeEvidence) are
// hand-declared here, never imported from wailsjs/go/models: like
// PktSummary/MtrHop/HTTPLoadResult elsewhere in this file,
// bgp.BGPRealtimeEvent only ever travels as a "bgp:realtime" event
// payload, never as a bound method's own return value, so `wails
// generate module` has no signature to build a TS class from.
//
// Casing is NOT uniform — it mirrors exactly what internal/bgp/
// realtime_event.go's Go structs marshal to, field by field:
// BGPRealtimeEvent/BGPPathElement.Kind/BGPOriginResolution/
// BGPRealtimeChangeSnapshot carry no `json:"..."` tags at all, so
// encoding/json uses their Go field names verbatim (capitalized);
// BGPPathElement.asn/set and BGPRealtimeEvidence's fields DO carry
// explicit lowercase tags (shared with bgp.ComponentEvidence, already
// generated elsewhere in this file). Never assume — this was checked
// directly against the Go source, not inferred.

export type BGPPathElementKind = 'asn' | 'as_set';

export interface BGPPathElement {
  Kind: BGPPathElementKind;
  asn?: number;
  set?: number[];
}

export type BGPPath = BGPPathElement[];

export interface BGPOriginResolution {
  Determinate: boolean;
  ASN: number;
  Reason: string;
}

export interface BGPRealtimeChangeSnapshot {
  Path: BGPPath;
  Origin: BGPOriginResolution;
  RPKIState: string;
  SourceEventID: string;
}

// BGPRealtimeEvidence mirrors bgp.ComponentEvidence's real JSON shape —
// not reused as `bgp.ComponentEvidence` (the generated class) because that
// class also carries a `convertValues` method a plain event payload never
// has; see this section's own comment above.
export interface BGPRealtimeEvidence {
  component: string;
  status: string;
  disclosure: { source: string; queriedAt: string; dataSent: string; cachePolicy: string; confidence: string; rateLimit: string };
  fromCache: boolean;
  err?: string;
  sourceEventIds?: string[];
}

export type BGPRealtimeEventType =
  | 'announcement' | 'withdrawal' | 'path_changed' | 'origin_changed'
  | 'moas_appeared' | 'moas_disappeared' | 'rpki_transition';

export interface BGPRealtimeEvent {
  ID: string;
  SourceMessageID: string;
  Timestamp: string;
  Type: BGPRealtimeEventType;
  Resource: string;
  Prefix: string;
  PeerASN: number;
  Peer: string;
  Path: BGPPath;
  Origin: BGPOriginResolution;
  Previous?: BGPRealtimeChangeSnapshot | null;
  Current?: BGPRealtimeChangeSnapshot | null;
  Source: string;
  Evidence?: BGPRealtimeEvidence[];
}

/** Explicit, user-initiated start — never called on mount/tab-open/automatically. IP or IPv4/IPv6 prefix only; ASN is rejected by the backend. */
export async function startBGPRealtime(resource: string): Promise<bgp.RealtimeSessionInfo> {
  return goBGPRealtimeStart(resource) as unknown as Promise<bgp.RealtimeSessionInfo>;
}

/** Deterministic stop — resolves only once the backend session has fully joined. */
export async function stopBGPRealtime(sessionID: string): Promise<void> {
  return goBGPRealtimeStop(sessionID);
}

/** Read-only local snapshot — zero RIPEstat HTTP, zero RIS Live WS, never reconnects, never mutates the session (see Service.BGPRealtimeInfo's own Go doc comment). */
export async function bgpRealtimeInfo(sessionID: string): Promise<bgp.RealtimeSessionInfo> {
  return goBGPRealtimeInfo(sessionID) as unknown as Promise<bgp.RealtimeSessionInfo>;
}

/**
 * Subscribes to one realtime session's events — reuses the existing
 * generic "trazip:event" bridge (onSessionEvent) exactly like every other
 * streaming feature in this file, never a second EventsOn/event
 * mechanism. One subscriber receives every BGPRealtimeEvent.Type the
 * backend ever publishes on this session (source and derived alike, all
 * on the single "bgp:realtime" logical topic — see realtime.go's own
 * bgpRealtimeTopic comment); the caller distinguishes them via
 * event.Type. Returns an unsubscribe function — callers must invoke it
 * before starting another session and on unmount (see BgpIntelligence's
 * RealtimePanel).
 */
export function subscribeBGPRealtime(sessionID: string, onEvent: (ev: BGPRealtimeEvent) => void): () => void {
  if (!hasRuntime()) return () => {};
  return onSessionEvent<BGPRealtimeEvent>('bgp:realtime', sessionID, onEvent);
}

export async function bgpHistory(req: bgp.BGPHistoryRequest): Promise<bgp.BGPHistoryResult> {
  return goBGPHistory(req) as unknown as Promise<bgp.BGPHistoryResult>;
}

export async function bgPlay(req: bgp.BGPlayRequest): Promise<bgp.BGPlayResult> {
  return goBGPlay(req) as unknown as Promise<bgp.BGPlayResult>;
}

// ---- BGP Observatory (v1.3 Gate 5/6) ----
// Thin wrappers, same pattern as bgpOverview/bgpHistory/bgPlay above — no
// logic here beyond the delegation itself, no auto-invocation on any view.

export async function bgpCountryObservatory(req: bgp.CountryObservatoryRequest): Promise<bgp.CountryObservatoryResult> {
  return goBGPCountryObservatory(req) as unknown as Promise<bgp.CountryObservatoryResult>;
}

export async function bgpGlobalObservatory(): Promise<bgp.GlobalRISObservatoryResult> {
  return goBGPGlobalObservatory() as unknown as Promise<bgp.GlobalRISObservatoryResult>;
}

export async function bgpASNObservatory(req: bgp.ASNObservatoryRequest): Promise<bgp.ASNObservatoryResult> {
  return goBGPASNObservatory(req) as unknown as Promise<bgp.ASNObservatoryResult>;
}

export async function bgpRPKIObservatory(req: bgp.RPKIObservatoryRequest): Promise<bgp.RPKIObservatoryResult> {
  return goBGPRPKIObservatory(req) as unknown as Promise<bgp.RPKIObservatoryResult>;
}

export async function bgpBogonLookup(req: bgp.BogonLookupRequest): Promise<bgp.BogonLookupResult> {
  return goBGPBogonLookup(req) as unknown as Promise<bgp.BogonLookupResult>;
}

export async function reputationAssess(ip: string): Promise<reputation.Score> {
  return goReputationAssess(ip) as unknown as Promise<reputation.Score>;
}

// ---- Monitor histórico (Fase 5, módulo 25) ----

export async function monitorAddTarget(t: Partial<monitor.Target>): Promise<monitor.Target> {
  return goMonitorAddTarget(t as monitor.Target) as unknown as Promise<monitor.Target>;
}

export async function monitorListTargets(): Promise<api.MonitorTargetInfo[]> {
  if (!hasRuntime()) return [];
  return goMonitorListTargets() as unknown as Promise<api.MonitorTargetInfo[]>;
}

export async function monitorRemoveTarget(id: string): Promise<void> {
  return goMonitorRemoveTarget(id);
}

export async function monitorHistory(id: string, sinceMs: number): Promise<monitor.History> {
  return goMonitorHistory(id, sinceMs) as unknown as Promise<monitor.History>;
}

export async function monitorCompareWindows(id: string, windowMs: number): Promise<monitor.WindowComparison> {
  return goMonitorCompareWindows(id, windowMs) as unknown as Promise<monitor.WindowComparison>;
}

export async function monitorReport(id: string, sinceMs: number, windowMs: number): Promise<report.Report> {
  return goMonitorReport(id, sinceMs, windowMs) as unknown as Promise<report.Report>;
}

export async function monitorPinBaseline(id: string, sinceMs: number, windowMs: number): Promise<monitor.BaselineProfile> {
  return goMonitorPinBaseline(id, sinceMs, windowMs) as unknown as Promise<monitor.BaselineProfile>;
}

export async function monitorClearBaseline(id: string): Promise<void> {
  return goMonitorClearBaseline(id);
}

export async function monitorCompareToBaseline(id: string): Promise<monitor.BaselineComparison> {
  return goMonitorCompareToBaseline(id) as unknown as Promise<monitor.BaselineComparison>;
}

export async function monitorStart(id: string): Promise<void> {
  return goMonitorStart(id);
}

export async function monitorStop(id: string): Promise<void> {
  return goMonitorStop(id);
}

export async function monitorExportReport(id: string, format: string, sinceMs: number, windowMs: number): Promise<string> {
  return goMonitorExportReport(id, format, sinceMs, windowMs);
}

// exportSessionReport saves a report the UI composed from the current
// session's results (see lib/sessionReport.ts) — backend fills provenance
// metadata, renders json/csv/html/pdf and shows the native save dialog.
export async function exportSessionReport(rep: report.Report, format: string): Promise<string> {
  return goExportSessionReport(rep, format);
}

// MonitorStart emits directly on "monitor:sample:<id>" / "monitor:event:<id>"
// (app.go's MonitorStart) rather than through the generic trazip:event
// session bridge used by one-shot operations — a monitor target isn't a
// short-lived session, so it never fits the bridge's "done" cleanup model.
// Subscribe to those raw Wails events directly instead of onSessionEvent,
// which only ever fires from the trazip:event listener and would silently
// never receive these.
export function subscribeMonitor(
  id: string,
  onSample: (s: monitor.Sample) => void,
  onEvent: (e: monitor.DegradationEvent) => void,
): () => void {
  if (!hasRuntime()) return () => {};
  const offSample = EventsOn(`monitor:sample:${id}`, (s: monitor.Sample) => onSample(s));
  const offEvent = EventsOn(`monitor:event:${id}`, (e: monitor.DegradationEvent) => onEvent(e));
  return () => {
    offSample();
    offEvent();
  };
}

// ---- Histórico de calidad VoIP ----

export async function voipQualityAddTarget(t: Partial<quality.Target>): Promise<quality.Target> {
  return goVoipQualityAddTarget(t as quality.Target) as unknown as Promise<quality.Target>;
}

export async function voipQualityListTargets(): Promise<quality.Target[]> {
  if (!hasRuntime()) return [];
  return goVoipQualityListTargets() as unknown as Promise<quality.Target[]>;
}

export async function voipQualityRemoveTarget(id: string): Promise<void> {
  return goVoipQualityRemoveTarget(id);
}

export async function voipQualityHistory(id: string, sinceMs: number): Promise<quality.History> {
  return goVoipQualityHistory(id, sinceMs) as unknown as Promise<quality.History>;
}

export async function voipQualityCompareWindows(id: string, windowMs: number): Promise<quality.WindowComparison> {
  return goVoipQualityCompareWindows(id, windowMs) as unknown as Promise<quality.WindowComparison>;
}

// ---- Investigaciones (Fase E: workspace local de evidencia) ----
// Nunca construye correlation.Snapshot en TypeScript — cada Add* solo
// reenvía un resultado ya terminado del módulo correspondiente; el backend
// es quien llama al adapter (diagnosis.ToSnapshot/summary.ToSnapshot/
// monitor.ToSnapshot/voip.ToSnapshot) y valida el Snapshot resultante.

export async function investigationCreate(name: string, objective: string): Promise<investigation.Investigation> {
  return goInvestigationCreate(name, objective) as unknown as Promise<investigation.Investigation>;
}

export async function investigationList(): Promise<investigation.ListResult> {
  if (!hasRuntime()) return new investigation.ListResult({ investigations: [] });
  return goInvestigationList() as unknown as Promise<investigation.ListResult>;
}

export async function investigationGet(id: string): Promise<investigation.Investigation> {
  return goInvestigationGet(id) as unknown as Promise<investigation.Investigation>;
}

export async function investigationUpdateMetadata(id: string, name: string, objective: string): Promise<investigation.Investigation> {
  return goInvestigationUpdateMetadata(id, name, objective) as unknown as Promise<investigation.Investigation>;
}

export async function investigationDelete(id: string): Promise<void> {
  return goInvestigationDelete(id);
}

export async function investigationRemoveEntry(investigationID: string, entryID: string): Promise<void> {
  return goInvestigationRemoveEntry(investigationID, entryID);
}

export async function investigationUpdateEntryNote(investigationID: string, entryID: string, note: string): Promise<investigation.Entry> {
  return goInvestigationUpdateEntryNote(investigationID, entryID, note) as unknown as Promise<investigation.Entry>;
}

export async function investigationReport(id: string): Promise<report.Report> {
  return goInvestigationReport(id) as unknown as Promise<report.Report>;
}

export async function investigationExportReport(id: string, format: string): Promise<string> {
  return goInvestigationExportReport(id, format);
}

// reportJSON is the exact DiagnosticReport JSON the caller already holds
// from the diagnose:done event — see InvestigationAddDiagnose's own Go doc
// comment for why this is a JSON string, not a typed DiagnosticReport
// parameter.
export async function investigationAddDiagnose(investigationID: string, reportJSON: string): Promise<api.InvestigationAddResult> {
  return goInvestigationAddDiagnose(investigationID, reportJSON) as unknown as Promise<api.InvestigationAddResult>;
}

// summary takes this file's own hand-maintained PcapIncidentSummary shape
// (what PcapResult.summary is already typed as here — see that type's own
// comment) rather than the generated correlation.PcapIncidentSummary class:
// both describe the exact same JSON, so the cast is safe, and this avoids
// forcing every caller to convert between the two.
export async function investigationAddPcap(
  investigationID: string,
  summary: PcapIncidentSummary,
  subject: string,
  sourceID: string,
  occurredAt: string,
): Promise<api.InvestigationAddResult> {
  return goInvestigationAddPcap(investigationID, summary as unknown as correlation.PcapIncidentSummary, subject, sourceID, occurredAt) as unknown as Promise<api.InvestigationAddResult>;
}

export async function investigationAddMonitorEvent(investigationID: string, event: monitor.DegradationEvent): Promise<api.InvestigationAddResult> {
  return goInvestigationAddMonitorEvent(investigationID, event as monitor.DegradationEvent) as unknown as Promise<api.InvestigationAddResult>;
}

export async function investigationAddVoIPCall(investigationID: string, call: voip.Call): Promise<api.InvestigationAddResult> {
  return goInvestigationAddVoIPCall(investigationID, call as voip.Call) as unknown as Promise<api.InvestigationAddResult>;
}

// ---- Investigation Enrichment (V1.5-5) ----
// Hand-declared because they are type aliases in Go and Wails doesn't
// generate them automatically. They mirror internal/osint enrichment types.

export interface Finding {
  id: string;
  subject: string;
  kind: string;
  evidenceClass: string;
  provenanceRef: string;
  sourceRefs: string[];
  attributes: Record<string, string>;
  summary: string;
  createdAt: string;
  updatedAt: string;
}

export interface FindingEvidence {
  id: string;
  findingId: string;
  type: string;
  value: string;
  source: string;
  provenanceRef: string;
  evidenceClass: string;
  confidence: string;
  explain: string;
  timestamp: string;
}

export interface FindingCorrelation {
  id: string;
  from: string;
  to: string;
  kind: string;
  directed: boolean;
  evidenceClass: string;
  provenanceRef: string;
  label: string;
  createdAt: string;
}

export interface EnrichmentStats {
  totalFindings: number;
  totalCorrelations: number;
  totalEvidence: number;
  bySourceKind: Record<string, number>;
}

export interface InvestigationEnrichResult {
  investigationId: string;
  investigationName: string;
  findings: Finding[];
  correlations: FindingCorrelation[];
  evidence: Record<string, FindingEvidence[]>;
  entryMapping: Record<string, string>;
  stats: EnrichmentStats;
}

export async function investigationEnrich(id: string): Promise<InvestigationEnrichResult> {
  if (!hasRuntime()) {
    return {
      investigationId: '',
      investigationName: '',
      findings: [],
      correlations: [],
      evidence: {},
      entryMapping: {},
      stats: { totalFindings: 0, totalCorrelations: 0, totalEvidence: 0, bySourceKind: {} },
    };
  }
  // goInvestigationEnrich is generated by `walls generate module` after adding
  // the Go method. If not yet generated, fall back to a safe empty result.
  const svc = (window as any).go?.api?.Service;
  if (svc && typeof svc.InvestigationEnrich === 'function') {
    const result = await svc.InvestigationEnrich(id) as unknown as {
      investigationId: string;
      investigationName: string;
      findings: Finding[];
      correlations: FindingCorrelation[];
      evidence: Record<string, FindingEvidence[]>;
      entryMapping: Record<string, string>;
      stats: EnrichmentStats;
    };
    return result as InvestigationEnrichResult;
  }
  // Binding not yet generated — return empty result to avoid TS error
  return {
    investigationId: '',
    investigationName: '',
    findings: [],
    correlations: [],
    evidence: {},
    entryMapping: {},
    stats: { totalFindings: 0, totalCorrelations: 0, totalEvidence: 0, bySourceKind: {} },
  };
}

// ---- Modo laboratorio (Fase 5, módulo 27) ----

export async function labScenarios(): Promise<lab.Scenario[]> {
  if (!hasRuntime()) return [];
  return goLabScenarios() as unknown as Promise<lab.Scenario[]>;
}

export async function labRunScenario(id: string): Promise<lab.RunResult> {
  return goLabRunScenario(id) as unknown as Promise<lab.RunResult>;
}

export async function labReport(id: string): Promise<report.Report> {
  return goLabReport(id) as unknown as Promise<report.Report>;
}

export async function labExportReport(id: string, format: string): Promise<string> {
  return goLabExportReport(id, format);
}

// ---- Estado del producto / Product Health Check (Fase F.1) ----
// Comprobación local, offline y determinística de los componentes internos
// de TRAZIP — nunca analiza la red del usuario ni envía tráfico externo.

export async function selfTestLocal(): Promise<api.SelfTestResult> {
  return goSelfTestLocal() as unknown as Promise<api.SelfTestResult>;
}

export type { api, voip, dnsintel, tlsintel, httpintel, webintel, rdap, bgp, reputation, throughput, monitor, quality, report, lab, wifi, ipcalc, sdp, model, investigation, correlation };

// ---- Categoría de red (netclass) ----
// Las descargas son la única salida a internet de este módulo y solo ocurren
// cuando el operador la pide explícitamente desde Settings.

export interface NetClassMatch {
  category: string;
  provider?: string;
  service?: string;
  region?: string;
  prefix?: string;
  source: string;
  confidence: string;
  evidence: string;
  inferred: boolean;
}

export interface NetClassSource {
  id: string;
  name: string;
  url: string;
  fetchedAt?: string;
  sha256?: string;
  prefixCount?: number;
  present: boolean;
}

export async function netClassSources(): Promise<NetClassSource[]> {
  if (!hasRuntime()) return [];
  return goNetClassSources() as unknown as Promise<NetClassSource[]>;
}

export async function netClassUpdate(id: string): Promise<NetClassSource> {
  return goNetClassUpdate(id) as unknown as Promise<NetClassSource>;
}

export async function netClassRemove(id: string): Promise<void> {
  return goNetClassRemove(id);
}

// ---- Listas de amenazas (Spamhaus DROP, nodos de salida Tor) ----

export interface ThreatFeedSource {
  id: string;
  name: string;
  url: string;
  fetchedAt?: string;
  sha256?: string;
  prefixCount: number;
  present: boolean;
  /** Días desde la descarga: una lista vieja es evidencia más débil. */
  ageDays: number;
}

export async function threatFeedSources(): Promise<ThreatFeedSource[]> {
  if (!hasRuntime()) return [];
  return goThreatFeedSources() as unknown as Promise<ThreatFeedSource[]>;
}

export async function threatFeedUpdate(id: string): Promise<ThreatFeedSource> {
  return goThreatFeedUpdate(id) as unknown as Promise<ThreatFeedSource>;
}

export async function threatFeedRemove(id: string): Promise<void> {
  return goThreatFeedRemove(id);
}

// ---- Teléfono (libphonenumber, cálculo local) ----

export interface PhoneResult {
  input: string;
  valid: boolean;
  e164?: string;
  international?: string;
  national?: string;
  /** URI tel: — la forma que viaja en las cabeceras SIP. */
  rfc3966?: string;
  countryCode?: number;
  /** ISO 3166-1 alpha-2; el nombre lo resuelve la vista con Intl.DisplayNames. */
  region?: string;
  area?: string;
  kind: string;
  kindNote?: string;
  carrier?: string;
  /** Advertencia de portabilidad: viaja con el operador porque aplica siempre. */
  carrierNote?: string;
  timezones: string[];
  notes: string[];
  err?: string;
}

export async function phoneAnalyze(input: string, region: string): Promise<PhoneResult> {
  return goPhoneAnalyze(input, region) as unknown as Promise<PhoneResult>;
}

// ---- Fabricante por MAC (registros IEEE) ----

export interface OUIInfo {
  present: boolean;
  fetchedAt?: string;
  prefixCount: number;
  registries?: string;
  source: string;
}

export interface MACDetail {
  input: string;
  mac?: string;
  valid: boolean;
  vendor?: string;
  prefix?: string;
  registry?: string;
  local: boolean;
  multicast: boolean;
  broadcast: boolean;
  note?: string;
}

export async function macLookup(mac: string): Promise<MACDetail> {
  return goMACLookup(mac) as unknown as Promise<MACDetail>;
}

export async function ouiInfo(): Promise<OUIInfo> {
  if (!hasRuntime()) return { present: false, prefixCount: 0, source: '' };
  return goOUIInfo() as unknown as Promise<OUIInfo>;
}

export async function ouiUpdate(): Promise<OUIInfo> {
  return goOUIUpdate() as unknown as Promise<OUIInfo>;
}

export async function ouiRemove(): Promise<void> {
  return goOUIRemove();
}

// ---- Calculadora IP ----
// Cálculo puro offline (internal/ipcalc): llamadas síncronas, sin sesión ni
// eventos porque no hay nada que transmitir ni que cancelar.

export async function ipcalcAnalyze(input: string): Promise<ipcalc.Info> {
  return goIPCalcAnalyze(input) as unknown as Promise<ipcalc.Info>;
}

export async function ipcalcSplit(input: string, newBits: number): Promise<ipcalc.SplitResult> {
  return goIPCalcSplit(input, newBits) as unknown as Promise<ipcalc.SplitResult>;
}

export async function ipcalcVLSM(input: string, reqs: ipcalc.VLSMRequest[]): Promise<ipcalc.VLSMResult> {
  return goIPCalcVLSM(input, reqs as any) as unknown as Promise<ipcalc.VLSMResult>;
}

export async function ipcalcAggregate(inputs: string[]): Promise<string[]> {
  return goIPCalcAggregate(inputs);
}

export async function ipcalcContains(prefix: string, addr: string): Promise<boolean> {
  return goIPCalcContains(prefix, addr);
}

export async function ipcalcCustomerPlan(requested: number, reserveGateway: boolean): Promise<ipcalc.CustomerPlan> {
  return goIPCalcCustomerPlan(requested, reserveGateway) as unknown as Promise<ipcalc.CustomerPlan>;
}
