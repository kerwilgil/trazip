import { NAV } from '../lib/nav';
import { MODULE_INFO } from '../lib/moduleInfo';
import { Icon } from '../components/icons';
import { useI18n } from '../lib/i18n';

export default function Manual() {
  const { t } = useI18n();
  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Manual')}</h2>
        <p className="body-text">{t('Referencia rápida de qué hace cada módulo de TRAZIP, agrupados igual que en el menú lateral.')}</p>
      </div>

      {NAV.map((group) => (
        <div key={group.label}>
          <div className="section-title">{t(group.label)}</div>
          <div className="grid cols-2">
            {group.items
              .filter((it) => it.id !== 'manual')
              .map((it) => (
                <div className="card" key={it.id}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ display: 'inline-flex', color: 'var(--accent)' }}>
                      <Icon name={it.id} size={20} />
                    </span>
                    <strong>{t(it.label)}</strong>
                    {!it.ready && <span className="tag warn" style={{ marginLeft: 'auto' }}>{t('pendiente')}</span>}
                  </div>
                  <p className="dim" style={{ fontSize: 13, marginTop: 8, marginBottom: 0 }}>
                    {t(MODULE_INFO[it.id] ?? 'Módulo planificado según el prompt maestro.')}
                  </p>
                </div>
              ))}
          </div>
        </div>
      ))}
    </div>
  );
}
