import { Finding, FindingEvidence, FindingCorrelation, EnrichmentStats } from '../lib/api';
import { sourceLabel } from '../lib/investigationHelpers';
import { useI18n } from '../lib/i18n';

interface EnrichmentPanelProps {
  result: {
    stats: EnrichmentStats;
    findings: Finding[];
    correlations: FindingCorrelation[];
    evidence: Record<string, FindingEvidence[]>;
  };
  t: (s: string) => string;
}

export default function EnrichmentPanel({ result, t }: EnrichmentPanelProps) {
  const { stats, findings, correlations, evidence } = result;

  return (
    <div style={{ marginTop: 14 }}>
      <h3 style={{ marginTop: 0 }}>{t('Resultado del enriquecimiento')}</h3>
      <div className="card" style={{ marginTop: 10 }}>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 10 }}>
          <span className="pill ok">{t('Hallazgos')}: {stats.totalFindings}</span>
          <span className="pill ok">{t('Correlaciones')}: {stats.totalCorrelations}</span>
          <span className="pill ok">{t('Evidencias')}: {stats.totalEvidence}</span>
        </div>

        {findings.length > 0 && (
          <div>
            <h4 style={{ marginBottom: 6 }}>{t('Hallazgos')}</h4>
            <div className="hop-list" style={{ maxHeight: 300, overflow: 'auto' }}>
              {findings.map((f) => (
                <div key={f.id} className="hop-row">
                  <span className="hop-host" style={{ minWidth: 0 }}>
                    <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {f.subject || f.id}
                    </span>
                    <span className="hop-ip">
                      {t(sourceLabel(f.kind))} · {f.evidenceClass} · {f.provenanceRef}
                    </span>
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {correlations.length > 0 && (
          <div style={{ marginTop: 14 }}>
            <h4 style={{ marginBottom: 6 }}>{t('Correlaciones')}</h4>
            <div className="hop-list" style={{ maxHeight: 200, overflow: 'auto' }}>
              {correlations.map((c) => (
                <div key={c.id} className="hop-row">
                  <span className="hop-host">
                    <span className="mono">{c.from} → {c.to}</span>
                    <span className="hop-ip">{c.kind} · {c.evidenceClass} · {c.label}</span>
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {Object.keys(evidence).length > 0 && (
          <div style={{ marginTop: 14 }}>
            <h4 style={{ marginBottom: 6 }}>{t('Evidencias')}</h4>
            <div className="hop-list" style={{ maxHeight: 200, overflow: 'auto' }}>
              {Object.entries(evidence).flatMap(([findingId, evs]) =>
                evs.map((e) => (
                  <div key={`${findingId}-${e.id}`} className="hop-row">
                    <span className="hop-host">
                      <span className="mono">{e.type}: {e.value}</span>
                      <span className="hop-ip">{e.source} · {e.provenanceRef} · {e.evidenceClass} · {e.confidence}%{e.explain ? ' · ' + e.explain : ''}</span>
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}