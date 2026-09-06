import { useState, type FocusEvent, type MouseEvent } from 'react';
import banner from '../assets/images/trazip-banner.png';
import logo from '../assets/images/trazip-logo.png';
import { NAV, type ViewId } from '../lib/nav';
import { Icon } from './icons';
import { MODULE_INFO } from '../lib/moduleInfo';
import type { api } from '../lib/api';
import { useI18n } from '../lib/i18n';

interface Props {
  active: ViewId;
  onSelect: (id: ViewId) => void;
  caps: api.Capabilities | null;
}

// position: fixed (not absolute) so the tooltip bubble isn't clipped by
// .nav's overflow-y: auto — a container with an overflow value other than
// visible on one axis forces the other axis to auto too, which would slice
// off any absolutely-positioned bubble poking out to the right.
export default function Sidebar({ active, onSelect, caps }: Props) {
  const { t } = useI18n();
  const [hover, setHover] = useState<{ id: ViewId; top: number; left: number } | null>(null);

  function showTooltip(e: MouseEvent<HTMLButtonElement> | FocusEvent<HTMLButtonElement>, id: ViewId) {
    const r = e.currentTarget.getBoundingClientRect();
    setHover({ id, top: r.top + r.height / 2, left: r.right + 10 });
  }

  return (
    <aside className="sidebar">
      <div className="brand">
        <img className="brand-lockup" src={banner} alt="TRAZIP" />
        <img className="brand-icon" src={logo} alt="TRAZIP" />
      </div>
      <nav className="nav" aria-label={t('Navegación principal')}>
        {NAV.map((group) => (
          <div key={group.label}>
            <div className="nav-group-label">{t(group.label)}</div>
            {group.items.map((it) => (
              <button
                key={it.id}
                className={'nav-item' + (active === it.id ? ' active' : '')}
                onClick={() => onSelect(it.id)}
                aria-current={active === it.id ? 'page' : undefined}
                onMouseEnter={(e) => showTooltip(e, it.id)}
                onMouseLeave={() => setHover(null)}
                onFocus={(e) => showTooltip(e, it.id)}
                onBlur={() => setHover(null)}
              >
                <span className="ico">
                  <Icon name={it.id} />
                </span>
                <span className="txt">{t(it.label)}</span>
              </button>
            ))}
          </div>
        ))}
      </nav>

      {hover && MODULE_INFO[hover.id] && (
        <div className="tooltip-bubble" role="tooltip" style={{ top: hover.top, left: hover.left }}>
          <strong>{t(NAV.flatMap((g) => g.items).find((i) => i.id === hover.id)?.label ?? '')}</strong>
          <p>{t(MODULE_INFO[hover.id] ?? '')}</p>
        </div>
      )}

      {caps && (
        <div className="sidebar-version" title={caps.dataDir}>
          <span className="ver">v{caps.version}</span>
          {caps.portable && <span className="mode">portable</span>}
        </div>
      )}
    </aside>
  );
}
