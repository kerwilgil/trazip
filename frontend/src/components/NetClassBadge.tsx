import type { NetClassMatch } from '../lib/api';
import { useI18n } from '../lib/i18n';

// Human labels + the tag colour class each category borrows. Categories reuse
// the existing .tag variants rather than introducing new colours, so the
// legend reads as part of the same system as the RFC class chips next to it.
const CATEGORY: Record<string, { label: string; cls: string }> = {
  cloud: { label: 'Cloud', cls: 'public' },
  cdn: { label: 'CDN', cls: 'public' },
  isp: { label: 'ISP', cls: 'private' },
  mobile: { label: 'Móvil', cls: 'private' },
  hosting: { label: 'Hosting', cls: 'hosting' },
  education: { label: 'Educación', cls: '' },
  enterprise: { label: 'Empresa', cls: '' },
};

/**
 * NetClassBadge renders the network-category legend for one address.
 *
 * The distinction it exists to preserve: a hit in a list the provider itself
 * publishes is a fact, while a match on the org name is a guess. Those must
 * never look the same, so inferred matches are visibly marked and always show
 * the evidence that produced them.
 */
export default function NetClassBadge({ m, compact = false }: { m?: NetClassMatch | null; compact?: boolean }) {
  const { t } = useI18n();
  if (!m) return null;
  const cat = CATEGORY[m.category] ?? { label: m.category, cls: '' };
  const title = [
    m.evidence,
    t('Fuente: {source}', { source: m.source }),
    t('Confianza: {confidence}', { confidence: m.confidence }),
    m.prefix ? t('Prefijo: {prefix}', { prefix: m.prefix }) : '',
  ]
    .filter(Boolean)
    .join('\n');

  if (compact) {
    return (
      <span className={'tag ' + cat.cls} title={title}>
        {t(cat.label)}
        {m.inferred && <span style={{ opacity: 0.7 }}>?</span>}
      </span>
    );
  }

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
      <span className={'tag ' + cat.cls} title={title}>{t(cat.label)}</span>
      {m.provider && <span style={{ fontSize: 12.5, fontWeight: 600 }}>{m.provider}</span>}
      {m.service && <span className="dim mono" style={{ fontSize: 11.5 }}>{m.service}</span>}
      {m.region && <span className="dim" style={{ fontSize: 11.5 }}>{m.region}</span>}
      <span className="dim" style={{ fontSize: 11 }} title={title}>
        {m.inferred ? t('inferido · confianza {confidence}', { confidence: m.confidence }) : t('dato publicado por el proveedor')}
      </span>
    </span>
  );
}
