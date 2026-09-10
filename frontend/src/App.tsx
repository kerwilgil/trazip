import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Overview from './views/Overview';
import Diagnose from './views/Diagnose';
import Investigations from './views/Investigations';
import PingMTR from './views/PingMTR';
import Throughput from './views/Throughput';
import HttpLoad from './views/HttpLoad';
import PcapAnalyzer from './views/PcapAnalyzer';
import Endpoints from './views/Endpoints';
import Connections from './views/Connections';
import IPCalc from './views/IPCalc';
import MacLookup from './views/MacLookup';
import Phone from './views/Phone';
import Scanner from './views/Scanner';
import Lan from './views/Lan';
import GeoMap from './views/GeoMap';
import LiveCapture from './views/LiveCapture';
import VoipCalls from './views/VoipCalls';
import WebIntelligence from './views/WebIntelligence';
import BgpIntelligence from './views/BgpIntelligence';
import OsintIntelligence from './views/OsintIntelligence';
import Monitor from './views/Monitor';
import Lab from './views/Lab';
import SelfTest from './views/SelfTest';
import Manual from './views/Manual';
import Settings from './views/Settings';
import Placeholder from './views/Placeholder';
import { LocalizedErrorBoundary } from './components/ErrorBoundary';
import { findItem, type ViewId } from './lib/nav';
import { useTheme } from './lib/theme';
import { getCapabilities, publicIP, type api } from './lib/api';
import { CaptureSessionProvider } from './lib/session';
import { useI18n } from './lib/i18n';

function viewComponent(view: ViewId, caps: api.Capabilities | null, active: boolean): ReactNode {
  switch (view) {
    case 'overview': return <Overview caps={caps} active={active} />;
    case 'diagnose': return <Diagnose />;
    case 'investigations': return <Investigations />;
    case 'pingmtr': return <PingMTR />;
    case 'throughput': return <Throughput />;
    case 'httpload': return <HttpLoad />;
    case 'pcap': return <PcapAnalyzer initialTab="summary" />;
    case 'flows': return <PcapAnalyzer initialTab="flows" />;
    case 'endpoints': return <Endpoints />;
    case 'scanner': return <Scanner />;
    case 'lan': return <Lan />;
    case 'geomap': return <GeoMap />;
    case 'connections': return <Connections />;
    case 'maclookup': return <MacLookup />;
    case 'phone': return <Phone />;
    case 'ipcalc': return <IPCalc />;
    case 'capture': return <LiveCapture />;
    case 'voip': return <VoipCalls />;
    case 'webintel': return <WebIntelligence />;
    case 'bgp': return <BgpIntelligence />;
    case 'osint': return <OsintIntelligence />;
    case 'monitor': return <Monitor />;
    case 'lab': return <Lab />;
    case 'selftest': return <SelfTest />;
    case 'manual': return <Manual />;
    case 'settings': return <Settings />;
    default: return <Placeholder id={view} />;
  }
}

interface WorkspaceProps {
  view: ViewId;
  visited: ViewId[];
  theme: ReturnType<typeof useTheme>[0];
  toggleTheme: () => void;
  caps: api.Capabilities | null;
  observedPublicIP: api.PublicIPResult | null;
  publicIPLoading: boolean;
  onRetryPublicIP: () => void;
}

function Workspace({ view, visited, theme, toggleTheme, caps, observedPublicIP, publicIPLoading, onRetryPublicIP }: WorkspaceProps) {
  const { t } = useI18n();
  const title = t(findItem(view)?.label ?? 'TRAZIP');

  return (
    <div className="main">
      <Topbar
        title={title}
        theme={theme}
        onToggleTheme={toggleTheme}
        caps={caps}
        observedPublicIP={observedPublicIP}
        publicIPLoading={publicIPLoading}
        onRetryPublicIP={onRetryPublicIP}
      />
      <div className="content">
        {visited.map((cachedView) => (
          <div className="cached-view" hidden={cachedView !== view} key={cachedView}>
            <LocalizedErrorBoundary>
              {viewComponent(cachedView, caps, cachedView === view)}
            </LocalizedErrorBoundary>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const [view, setView] = useState<ViewId>('overview');
  const [visited, setVisited] = useState<ViewId[]>(['overview']);
  const [theme, toggleTheme] = useTheme();
  const [caps, setCaps] = useState<api.Capabilities | null>(null);
  const [observedPublicIP, setObservedPublicIP] = useState<api.PublicIPResult | null>(null);
  const [publicIPLoading, setPublicIPLoading] = useState(false);
  const publicIPInFlight = useRef(false);

  useEffect(() => {
    getCapabilities().then(setCaps).catch(() => setCaps(null));
  }, []);

  // One transparent observation per shell startup. Any later request is only
  // initiated by the user after a failure; no target or capture is sent.
  const refreshPublicIP = useCallback(async () => {
    if (publicIPInFlight.current) return;
    publicIPInFlight.current = true;
    setPublicIPLoading(true);
    setObservedPublicIP(null);
    try {
      setObservedPublicIP(await publicIP());
    } catch {
      setObservedPublicIP({ ip: '', family: 0, source: 'api64.ipify.org', err: 'Public IP unavailable.' });
    } finally {
      publicIPInFlight.current = false;
      setPublicIPLoading(false);
    }
  }, []);

  useEffect(() => { void refreshPublicIP(); }, [refreshPublicIP]);

  const navigate = useCallback((next: ViewId) => {
    setVisited((prev) => prev.includes(next) ? prev : [...prev, next]);
    setView(next);
  }, []);

  return (
    <div className="app">
      <Sidebar active={view} onSelect={navigate} caps={caps} />
      <CaptureSessionProvider onNavigate={navigate}>
        <Workspace view={view} visited={visited} theme={theme} toggleTheme={toggleTheme} caps={caps} observedPublicIP={observedPublicIP} publicIPLoading={publicIPLoading} onRetryPublicIP={refreshPublicIP} />
      </CaptureSessionProvider>
    </div>
  );
}
