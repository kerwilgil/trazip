import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';
import {
  analyzePcap,
  pickPcapFile,
  startVoIPAnalysis,
  stopVoIPAnalysis,
  subscribeVoIPAnalysis,
  startCapture,
  startTZSPCapture as startTZSPCaptureApi,
  stopCapture,
  subscribeCapture,
  startLanScan,
  stopLanScan,
  subscribeLanScan,
  startConnMon,
  stopConnMon,
  subscribeConnMon,
  type PcapResult,
  type PktSummary,
  type voip,
  type LanHostResult,
  type LanScanSummary,
  type ScanDetectionResult,
  type NetDiagResult,
  emptyNetDiag,
  type ConnMonSnapshot,
} from './api';
import type { ViewId } from './nav';

// One "last query" entry pushed by any view (currently Web Intelligence) so
// Overview can show a cross-module "últimas consultas" feed without every
// view needing its own history plumbing — same shape WebIntelligence.tsx
// already used locally, just promoted to a shared, capped ring buffer.
export interface ActivityEntry {
  tool: string;
  query: string;
  summary: string;
  at: string; // ISO timestamp
}
const ACTIVITY_MAX = 30;

// Mounted once at the App root, above the top-level view switch — unlike a
// context scoped inside a view, this Provider never unmounts when the user
// changes tabs, so the loaded capture/analysis/live-capture state (and, for
// Live Capture, the actual event subscription) survives navigation. It is
// cleared only by explicit user action (Limpiar / cargar otra captura /
// detener) or by closing the app, per the user's own requirement.
interface CaptureSessionValue {
  // PCAP Analyzer, Flows and GeoMap's "Captura" tab all analyze the exact
  // same file through the exact same analyzePcap() call — one shared result
  // means opening a capture once feeds all three instead of asking again.
  pcapPath: string;
  pcapResult: PcapResult | null;
  pcapLoading: boolean;
  pcapError: string | null;
  openPcap: () => Promise<void>;
  loadPcap: (path: string) => Promise<void>;
  clearPcap: () => void;

  // VoIP Calls — its own file (a call PCAP is often a different, smaller
  // extract than the general capture), preserved across tab switches.
  voipPath: string;
  voipResult: voip.Result | null;
  voipRunning: boolean;
  voipError: string | null;
  openVoip: () => Promise<void>;
  loadVoip: (path: string) => Promise<void>;
  stopVoip: () => void;
  clearVoip: () => void;

  // Live Capture — the subscription lives in this Provider (which never
  // unmounts), so leaving the tab no longer kills a running capture; it
  // keeps accumulating in the background exactly like a real capture tool.
  captureDevice: string;
  setCaptureDevice: (d: string) => void;
  capturePromisc: boolean;
  setCapturePromisc: (b: boolean) => void;
  captureRunning: boolean;
  capturePackets: PktSummary[];
  captureTotal: number;
  captureProtos: Record<string, number>;
  captureScanDetection: ScanDetectionResult;
  captureNetDiag: NetDiagResult;
  captureError: string | null;
  captureRunningSinceMs: number | null;
  startLiveCapture: (device: string, promisc: boolean, monitorMode?: boolean) => Promise<void>;
  startTZSPCapture: (bindAddr: string) => Promise<void>;
  stopLiveCapture: () => void;
  clearLiveCapture: () => void;

  // LAN Scanner — same "subscription lives in the Provider" treatment as
  // Live Capture: before this, leaving the LAN Explorer tab mid-scan orphaned
  // the running backend scan (nothing stopped it, but the component's local
  // state/refs were destroyed on unmount, so there was no way back to it).
  lanScanRange: string;
  lanScanIface: string;
  lanScanRunning: boolean;
  lanScanHosts: LanHostResult[];
  lanScanProgress: { scanned: number; total: number } | null;
  lanScanSummary: LanScanSummary | null;
  lanScanError: string | null;
  startLanScanSession: (rangeSpec: string, iface: string) => Promise<void>;
  stopLanScanSession: () => void;
  clearLanScan: () => void;

  // Connection monitor ("Conexiones") — same "subscription lives in the
  // Provider" treatment as Live Capture/LAN Scan, so leaving the tab doesn't
  // stop the poll or blank the list on return. Each tick replaces the
  // snapshot (it's a live "right now" view, not an accumulating log).
  connMonRunning: boolean;
  connMonSnapshot: ConnMonSnapshot | null;
  connMonError: string | null;
  startConnMonSession: (intervalMs: number) => Promise<void>;
  stopConnMonSession: () => void;
  clearConnMon: () => void;

  // Hand-off slot: the IP calculator drops a CIDR here and jumps to LAN
  // Explorer, which picks it up on mount and clears it. A one-shot value
  // rather than a permanent setting — re-entering the tab later must not
  // silently re-populate a range the operator never asked for again.
  pendingLanRange: string | null;
  setPendingLanRange: (cidr: string | null) => void;

  // Cross-module "últimas consultas" feed for Overview.
  activity: ActivityEntry[];
  pushActivity: (tool: string, query: string, summary: string) => void;
  clearActivity: () => void;

  // Lets a view (e.g. "this capture has SIP traffic, see it as calls")
  // switch the top-level nav tab without App.tsx needing to know about it.
  navigateTo: (view: ViewId) => void;
}

const CaptureSessionContext = createContext<CaptureSessionValue | null>(null);

export function useCaptureSession(): CaptureSessionValue {
  const ctx = useContext(CaptureSessionContext);
  if (!ctx) throw new Error('useCaptureSession must be used within CaptureSessionProvider');
  return ctx;
}

export function CaptureSessionProvider({ children, onNavigate }: { children: ReactNode; onNavigate: (view: ViewId) => void }) {
  const [pcapPath, setPcapPath] = useState('');
  const [pcapResult, setPcapResult] = useState<PcapResult | null>(null);
  const [pcapLoading, setPcapLoading] = useState(false);
  const [pcapError, setPcapError] = useState<string | null>(null);

  const loadPcap = useCallback(async (path: string) => {
    setPcapPath(path);
    setPcapLoading(true);
    setPcapError(null);
    setPcapResult(null);
    try {
      setPcapResult(await analyzePcap(path));
    } catch (e) {
      setPcapError(String(e));
    } finally {
      setPcapLoading(false);
    }
  }, []);

  const openPcap = useCallback(async () => {
    const p = await pickPcapFile();
    if (!p) return;
    await loadPcap(p);
  }, [loadPcap]);

  const clearPcap = useCallback(() => {
    setPcapPath('');
    setPcapResult(null);
    setPcapError(null);
  }, []);

  const [voipPath, setVoipPath] = useState('');
  const [voipResult, setVoipResult] = useState<voip.Result | null>(null);
  const [voipRunning, setVoipRunning] = useState(false);
  const [voipError, setVoipError] = useState<string | null>(null);
  const voipRunIdRef = useRef<string | null>(null);
  const voipUnsubRef = useRef<(() => void) | null>(null);

  const loadVoip = useCallback(async (path: string) => {
    if (voipRunIdRef.current) return; // already analyzing
    setVoipPath(path);
    setVoipError(null);
    setVoipResult(null);
    setVoipRunning(true);
    try {
      const id = await startVoIPAnalysis(path);
      voipRunIdRef.current = id;
      voipUnsubRef.current = subscribeVoIPAnalysis(id, (res, err) => {
        setVoipRunning(false);
        voipRunIdRef.current = null;
        if (err) setVoipError(err);
        else setVoipResult(res);
      });
    } catch (e) {
      setVoipError(String(e));
      setVoipRunning(false);
    }
  }, []);

  const openVoip = useCallback(async () => {
    const p = await pickPcapFile();
    if (!p) return;
    await loadVoip(p);
  }, [loadVoip]);

  const stopVoip = useCallback(() => {
    if (voipUnsubRef.current) voipUnsubRef.current();
    if (voipRunIdRef.current) stopVoIPAnalysis(voipRunIdRef.current);
    voipUnsubRef.current = null;
    voipRunIdRef.current = null;
    setVoipRunning(false);
  }, []);

  const clearVoip = useCallback(() => {
    stopVoip();
    setVoipPath('');
    setVoipResult(null);
    setVoipError(null);
  }, [stopVoip]);

  const [captureDevice, setCaptureDevice] = useState('');
  const [capturePromisc, setCapturePromisc] = useState(false);
  const [captureRunning, setCaptureRunning] = useState(false);
  const [capturePackets, setCapturePackets] = useState<PktSummary[]>([]);
  const [captureTotal, setCaptureTotal] = useState(0);
  const [captureProtos, setCaptureProtos] = useState<Record<string, number>>({});
  const [captureScanDetection, setCaptureScanDetection] = useState<ScanDetectionResult>({
    initialSyn: 0, vertical: 0, horizontal: 0, findings: [], truncated: false,
  });
  const [captureNetDiag, setCaptureNetDiag] = useState<NetDiagResult>(emptyNetDiag);
  const [captureError, setCaptureError] = useState<string | null>(null);
  const [captureRunningSinceMs, setCaptureRunningSinceMs] = useState<number | null>(null);
  const captureRunIdRef = useRef<string | null>(null);
  const captureUnsubRef = useRef<(() => void) | null>(null);
  const CAPTURE_MAX_ROWS = 2000;

  // beginCapture is shared by startLiveCapture and startTZSPCapture — both
  // sources stream the identical capture:batch/capture:done event contract
  // (see app.go's runBatchedCapture), so only the Start call itself differs.
  const beginCapture = useCallback(async (start: () => Promise<string>) => {
    if (captureRunIdRef.current) return;
    setCaptureError(null);
    setCapturePackets([]);
    setCaptureTotal(0);
    setCaptureProtos({});
    setCaptureScanDetection({ initialSyn: 0, vertical: 0, horizontal: 0, findings: [], truncated: false });
    setCaptureNetDiag(emptyNetDiag);
    try {
      const id = await start();
      captureRunIdRef.current = id;
      setCaptureRunning(true);
      setCaptureRunningSinceMs(Date.now());
      captureUnsubRef.current = subscribeCapture(
        id,
        (pkts, tot, pr, detection, l2) => {
          setCaptureTotal(tot);
          setCaptureProtos(pr);
          setCaptureScanDetection(detection);
          setCaptureNetDiag(l2);
          if (pkts.length) {
            setCapturePackets((prev) => {
              const next = [...pkts.slice().reverse(), ...prev];
              return next.length > CAPTURE_MAX_ROWS ? next.slice(0, CAPTURE_MAX_ROWS) : next;
            });
          }
        },
        (err) => {
          setCaptureRunning(false);
          setCaptureRunningSinceMs(null);
          captureRunIdRef.current = null;
          if (err) setCaptureError(err);
        },
      );
    } catch (e) {
      setCaptureError(String(e));
      setCaptureRunning(false);
      setCaptureRunningSinceMs(null);
    }
  }, []);

  const startLiveCapture = useCallback(
    (device: string, promisc: boolean, monitorMode?: boolean) => beginCapture(() => startCapture(device, promisc, monitorMode)),
    [beginCapture],
  );

  const startTZSPCapture = useCallback(
    (bindAddr: string) => beginCapture(() => startTZSPCaptureApi(bindAddr)),
    [beginCapture],
  );

  const stopLiveCapture = useCallback(() => {
    if (captureUnsubRef.current) captureUnsubRef.current();
    if (captureRunIdRef.current) stopCapture(captureRunIdRef.current);
    captureUnsubRef.current = null;
    captureRunIdRef.current = null;
    setCaptureRunning(false);
    setCaptureRunningSinceMs(null);
  }, []);

  const clearLiveCapture = useCallback(() => {
    stopLiveCapture();
    setCapturePackets([]);
    setCaptureTotal(0);
    setCaptureProtos({});
    setCaptureScanDetection({ initialSyn: 0, vertical: 0, horizontal: 0, findings: [], truncated: false });
    setCaptureNetDiag(emptyNetDiag);
    setCaptureError(null);
  }, [stopLiveCapture]);

  const [lanScanRange, setLanScanRange] = useState('');
  const [lanScanIface, setLanScanIface] = useState('');
  const [lanScanRunning, setLanScanRunning] = useState(false);
  const [lanScanHosts, setLanScanHosts] = useState<LanHostResult[]>([]);
  const [lanScanProgress, setLanScanProgress] = useState<{ scanned: number; total: number } | null>(null);
  const [lanScanSummary, setLanScanSummary] = useState<LanScanSummary | null>(null);
  const [lanScanError, setLanScanError] = useState<string | null>(null);
  const lanScanRunIdRef = useRef<string | null>(null);
  const lanScanUnsubRef = useRef<(() => void) | null>(null);

  const startLanScanSession = useCallback(async (rangeSpec: string, iface: string) => {
    if (lanScanRunIdRef.current) return;
    setLanScanRange(rangeSpec);
    setLanScanIface(iface);
    setLanScanError(null);
    setLanScanHosts([]);
    setLanScanSummary(null);
    setLanScanProgress(null);
    try {
      const id = await startLanScan(rangeSpec, iface);
      lanScanRunIdRef.current = id;
      setLanScanRunning(true);
      lanScanUnsubRef.current = subscribeLanScan(
        id,
        (h) => setLanScanHosts((prev) => [...prev, h].sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }))),
        (scanned, total) => setLanScanProgress({ scanned, total }),
        (sum, err) => {
          setLanScanRunning(false);
          lanScanRunIdRef.current = null;
          setLanScanSummary(sum);
          if (err) setLanScanError(err);
        },
      );
    } catch (e) {
      setLanScanError(String(e));
      setLanScanRunning(false);
    }
  }, []);

  const stopLanScanSession = useCallback(() => {
    if (lanScanUnsubRef.current) lanScanUnsubRef.current();
    if (lanScanRunIdRef.current) stopLanScan(lanScanRunIdRef.current);
    lanScanUnsubRef.current = null;
    lanScanRunIdRef.current = null;
    setLanScanRunning(false);
  }, []);

  const clearLanScan = useCallback(() => {
    stopLanScanSession();
    setLanScanHosts([]);
    setLanScanSummary(null);
    setLanScanProgress(null);
    setLanScanError(null);
  }, [stopLanScanSession]);

  const [connMonRunning, setConnMonRunning] = useState(false);
  const [connMonSnapshot, setConnMonSnapshot] = useState<ConnMonSnapshot | null>(null);
  const [connMonError, setConnMonError] = useState<string | null>(null);
  const connMonRunIdRef = useRef<string | null>(null);
  const connMonUnsubRef = useRef<(() => void) | null>(null);

  const startConnMonSession = useCallback(async (intervalMs: number) => {
    if (connMonRunIdRef.current) return;
    setConnMonError(null);
    try {
      const id = await startConnMon(intervalMs);
      connMonRunIdRef.current = id;
      setConnMonRunning(true);
      connMonUnsubRef.current = subscribeConnMon(
        id,
        (snap) => setConnMonSnapshot(snap),
        (err) => {
          setConnMonRunning(false);
          connMonRunIdRef.current = null;
          if (err) setConnMonError(err);
        },
      );
    } catch (e) {
      setConnMonError(String(e));
      setConnMonRunning(false);
    }
  }, []);

  const stopConnMonSession = useCallback(() => {
    if (connMonUnsubRef.current) connMonUnsubRef.current();
    if (connMonRunIdRef.current) stopConnMon(connMonRunIdRef.current);
    connMonUnsubRef.current = null;
    connMonRunIdRef.current = null;
    setConnMonRunning(false);
  }, []);

  const clearConnMon = useCallback(() => {
    stopConnMonSession();
    setConnMonSnapshot(null);
    setConnMonError(null);
  }, [stopConnMonSession]);

  const [pendingLanRange, setPendingLanRange] = useState<string | null>(null);

  const [activity, setActivity] = useState<ActivityEntry[]>([]);

  const pushActivity = useCallback((tool: string, query: string, summary: string) => {
    setActivity((prev) => [{ tool, query, summary, at: new Date().toISOString() }, ...prev].slice(0, ACTIVITY_MAX));
  }, []);

  const clearActivity = useCallback(() => setActivity([]), []);

  const value: CaptureSessionValue = {
    pcapPath, pcapResult, pcapLoading, pcapError, openPcap, loadPcap, clearPcap,
    voipPath, voipResult, voipRunning, voipError, openVoip, loadVoip, stopVoip, clearVoip,
    captureDevice, setCaptureDevice, capturePromisc, setCapturePromisc,
    captureRunning, capturePackets, captureTotal, captureProtos, captureScanDetection, captureNetDiag, captureError, captureRunningSinceMs,
    startLiveCapture, startTZSPCapture, stopLiveCapture, clearLiveCapture,
    lanScanRange, lanScanIface, lanScanRunning, lanScanHosts, lanScanProgress, lanScanSummary, lanScanError,
    startLanScanSession, stopLanScanSession, clearLanScan,
    connMonRunning, connMonSnapshot, connMonError, startConnMonSession, stopConnMonSession, clearConnMon,
    pendingLanRange, setPendingLanRange,
    activity, pushActivity, clearActivity,
    navigateTo: onNavigate,
  };

  return <CaptureSessionContext.Provider value={value}>{children}</CaptureSessionContext.Provider>;
}
