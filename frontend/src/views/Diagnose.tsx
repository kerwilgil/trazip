import { useEffect, useRef, useState } from 'react';
import { startDiagnose, stopDiagnose, subscribeDiagnose, investigationAddDiagnose, type DiagnoseMode, type DiagnosticReport, type DiagnosticStage } from '../lib/api';
import { model } from '../../wailsjs/go/models';
import VoipDiagnosis from '../components/VoipDiagnosis';
import AddToInvestigation from '../components/AddToInvestigation';
import { useI18n } from '../lib/i18n';

const MODE_NOTE: Record<DiagnoseMode, string> = {
  offline: 'Modo offline: solo datos locales (clasificación, GeoIP/ASN, NetClass, listas de reputación ya descargadas). Sin salida de red.',
  standard:
    'Modo Diagnóstico: se enviarán consultas hacia el objetivo y servicios públicos necesarios — DNS del sistema, ping y traceroute cortos, RDAP, BGP/RPKI, TLS y HTTP.',
  full: 'Modo Completo: además compara DNS entre varios resolvers públicos y hace un traceroute más detallado. Sigue siendo diagnóstico, no un pentest.',
};

const STAGE_ORDER = ['resolution', 'reachability', 'route', 'ownership', 'routing_security', 'tls', 'http', 'reputation'];
const STAGE_LABEL: Record<string, string> = {
  resolution: 'Resolución DNS',
  reachability: 'Alcance',
  route: 'Ruta',
  ownership: 'Propiedad',
  routing_security: 'Routing',
  tls: 'TLS',
  http: 'HTTP',
  reputation: 'Reputación',
};
const STAGE_ICON: Record<string, string> = {
  ok: '✓',
  warning: '⚠',
  problem: '✗',
  unknown: '?',
  skipped: '∅',
  error: '✗',
};
const STAGE_CLASS: Record<string, string> = {
  ok: 'ok',
  warning: 'warn',
  problem: 'danger',
  unknown: 'warn',
  skipped: '',
  error: 'danger',
};

function StageRow({ stage }: { stage: DiagnosticStage }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const hasDetail = (stage.evidence && stage.evidence.length > 0) || (stage.limitations && stage.limitations.length > 0);
  return (
    <div className="hop-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: hasDetail ? 'pointer' : 'default' }}
        onClick={() => hasDetail && setOpen((o) => !o)}
      >
        <span className={'pill ' + (STAGE_CLASS[stage.status] || '')} style={{ minWidth: 22, justifyContent: 'center' }}>
          {STAGE_ICON[stage.status] || '?'}
        </span>
        <strong style={{ fontSize: 12.5 }}>{STAGE_LABEL[stage.id] || stage.id}</strong>
        <span className="dim" style={{ fontSize: 11.5 }}>{t(stage.summary)}</span>
        {hasDetail && <span className="dim" style={{ marginLeft: 'auto', fontSize: 11 }}>{open ? '▲' : '▼'}</span>}
      </div>
      {open && (
        <div style={{ margin: '6px 0 4px 30px' }}>
          {stage.subjects && stage.subjects.length > 0 && (
            <div style={{ fontSize: 10.5, color: 'var(--text-faint)', marginBottom: 4 }}>
              {t('Examinó')}: <span className="mono">{stage.subjects.join(', ')}</span>
            </div>
          )}
          {stage.evidence?.map((e, i) => (
            <div key={i} style={{ fontSize: 11.5, marginBottom: 2 }}>
              <span className="dim">{t(e.explain || e.value)}</span>
            </div>
          ))}
          {stage.limitations?.map((l, i) => (
            <div key={i} style={{ fontSize: 11, color: 'var(--text-faint)', marginBottom: 2 }}>
              ⚠ {t(l)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function Diagnose() {
  const { t } = useI18n();
  const [input, setInput] = useState('');
  const [mode, setMode] = useState<DiagnoseMode>('standard');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<DiagnosticReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const runIdRef = useRef<string | null>(null);
  const unsubRef = useRef<(() => void) | null>(null);

  useEffect(() => () => unsubRef.current?.(), []);

  async function run() {
    const target = input.trim();
    if (!target || loading) return;
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const id = await startDiagnose(target, mode, true);
      runIdRef.current = id;
      unsubRef.current = subscribeDiagnose(id, (rep, err) => {
        setLoading(false);
        runIdRef.current = null;
        if (err) setError(err);
        else setReport(rep);
      });
    } catch (e) {
      setError(String(e));
      setLoading(false);
    }
  }

  async function cancel() {
    if (runIdRef.current) {
      await stopDiagnose(runIdRef.current);
      runIdRef.current = null;
    }
    setLoading(false);
  }

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Quick Diagnose')}</h2>
        <p className="body-text">
          {t('Pega una IP, dominio o URL. TRAZIP correlaciona DNS, alcance, ruta, propiedad, seguridad de ruta, TLS, HTTP y reputación en una sola conclusión con evidencia.')}
        </p>
      </div>

      <div className="card">
        <div className="field">
          <input
            className="input"
            placeholder="8.8.8.8 · example.com · https://sitio.com"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && run()}
            autoFocus
          />
          {loading ? (
            <button className="btn" onClick={cancel}>
              <span className="spin" /> {t('Cancelar')}
            </button>
          ) : (
            <button className="btn" onClick={run} disabled={!input.trim()}>
              ⚡ {t('Diagnosticar')}
            </button>
          )}
        </div>
        <div className="tabs" style={{ marginTop: 10 }}>
          {(['offline', 'standard', 'full'] as DiagnoseMode[]).map((m) => (
            <button
              key={m}
              className={'tab' + (mode === m ? ' active' : '')}
              onClick={() => setMode(m)}
              disabled={loading}
            >
              {m === 'offline' ? t('Offline') : m === 'standard' ? t('Diagnóstico') : t('Completo')}
            </button>
          ))}
        </div>
        <p className="dim" style={{ fontSize: 11, marginTop: 8 }}>{t(MODE_NOTE[mode])}</p>
      </div>

      {error && <div className="note">{error}</div>}

      {report && (
        <>
          <VoipDiagnosis
            diagnosis={model.Assessment.createFrom({
              conclusion: report.summary,
              level: report.level,
              confidence: report.confidence,
              evidence: report.evidence,
              counterEvidence: report.counterEvidence,
              limitations: report.limitations,
            })}
          />

          {report.completedAt && (
            <div style={{ marginTop: 8 }}>
              <AddToInvestigation onAdd={(id) => investigationAddDiagnose(id, JSON.stringify(report))} />
            </div>
          )}

          <div className="card" style={{ marginTop: 10 }}>
            <span className="label dim" style={{ fontSize: 11 }}>{t('Cadena de diagnóstico')}</span>
            <div className="hop-list" style={{ marginTop: 6 }}>
              {STAGE_ORDER.map((id) => {
                const stage = report.stages.find((s) => s.id === id);
                return stage ? <StageRow key={id} stage={stage} /> : null;
              })}
            </div>
          </div>

          {report.resolvedAddresses && report.resolvedAddresses.length > 1 && (
            <p className="dim" style={{ fontSize: 11, marginTop: 8 }}>
              {t('Direcciones resueltas')}: <span className="mono">{report.resolvedAddresses.join(', ')}</span> — {t('se evaluó')} <span className="mono">{report.primaryAddress}</span>.
            </p>
          )}
          <p className="dim" style={{ fontSize: 11, marginTop: 8 }}>
            {report.networkOut ? t('Esta ejecución envió tráfico fuera del equipo (ver etapas arriba).') : t('Esta ejecución no envió tráfico fuera del equipo.')}
            {' · '}
            {report.durationMs} ms
          </p>
        </>
      )}
    </div>
  );
}
