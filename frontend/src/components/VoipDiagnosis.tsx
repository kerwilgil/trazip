import type { model } from '../lib/api';
import { useI18n } from '../lib/i18n';

// Renders a model.Assessment — the central "reasoned conclusion" shape every
// TRAZIP judgement is supposed to use (prompt maestro §8/§10: conclusion,
// level, confidence, evidence, counter-evidence, limitations). This is the
// first place in the frontend that actually renders one; written generically
// enough that any future Assessment-producing feature can reuse it as-is.

const LEVEL_CLASS: Record<string, string> = {
  informativo: 'ok',
  bajo: 'warn',
  medio: 'warn',
  alto: 'danger',
  critico: 'danger',
};

function EvidenceList({ items, title, muted }: { items?: model.Evidence[]; title: string; muted?: boolean }) {
  const { t } = useI18n();
  if (!items || items.length === 0) return null;
  return (
    <div style={{ marginTop: 10 }}>
      <span className="label dim" style={{ fontSize: 11 }}>{title}</span>
      <div className="hop-list">
        {items.map((e, i) => (
          <div className="hop-row" key={i}>
            <span className={muted ? 'dim' : ''} style={{ fontSize: 12.5 }}>{t(e.explain || e.value)}</span>
            <span className="dim" style={{ fontSize: 11, marginLeft: 'auto' }}>{t('confianza')} {e.confidence}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function VoipDiagnosis({ diagnosis }: { diagnosis?: model.Assessment }) {
  const { t } = useI18n();
  if (!diagnosis) return null;
  const cls = LEVEL_CLASS[diagnosis.level] || '';

  return (
    <div className="card" style={{ marginTop: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <span className={'pill ' + cls}>
          <span className="dot" /> {t(diagnosis.level)}
        </span>
        <strong style={{ fontSize: 13.5 }}>{t(diagnosis.conclusion)}</strong>
        <span className="dim" style={{ fontSize: 11, marginLeft: 'auto' }}>
          {t('Confianza')}: {diagnosis.confidence}%
        </span>
      </div>

      <EvidenceList items={diagnosis.evidence} title={t('Evidencia')} />
      <EvidenceList items={diagnosis.counterEvidence} title={t('Contraevidencia')} muted />

      {diagnosis.limitations && diagnosis.limitations.length > 0 && (
        <ul style={{ margin: '10px 0 0 18px', fontSize: 11.5, color: 'var(--text-faint)' }}>
          {diagnosis.limitations.map((l, i) => <li key={i}>{t(l)}</li>)}
        </ul>
      )}
    </div>
  );
}
