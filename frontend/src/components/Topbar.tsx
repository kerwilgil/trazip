import { useState } from 'react';
import type { Theme } from '../lib/theme';
import type { api } from '../lib/api';
import { useI18n } from '../lib/i18n';

// Sun / Moon icons from Reicon (MIT © 2026 Dev Chauhan), currentColor.
const SUN =
  '<path fill-rule="evenodd" clip-rule="evenodd" d="M12 1.25C12.4142 1.25 12.75 1.58579 12.75 2V3C12.75 3.41421 12.4142 3.75 12 3.75C11.5858 3.75 11.25 3.41421 11.25 3V2C11.25 1.58579 11.5858 1.25 12 1.25ZM4.39861 4.39861C4.6915 4.10572 5.16638 4.10572 5.45927 4.39861L5.85211 4.79145C6.145 5.08434 6.145 5.55921 5.85211 5.85211C5.55921 6.145 5.08434 6.145 4.79145 5.85211L4.39861 5.45927C4.10572 5.16638 4.10572 4.6915 4.39861 4.39861ZM19.6011 4.39887C19.894 4.69176 19.894 5.16664 19.6011 5.45953L19.2083 5.85237C18.9154 6.14526 18.4405 6.14526 18.1476 5.85237C17.8547 5.55947 17.8547 5.0846 18.1476 4.79171L18.5405 4.39887C18.8334 4.10598 19.3082 4.10598 19.6011 4.39887ZM12 6.75C9.1005 6.75 6.75 9.1005 6.75 12C6.75 14.8995 9.1005 17.25 12 17.25C14.8995 17.25 17.25 14.8995 17.25 12C17.25 9.1005 14.8995 6.75 12 6.75ZM5.25 12C5.25 8.27208 8.27208 5.25 12 5.25C15.7279 5.25 18.75 8.27208 18.75 12C18.75 15.7279 15.7279 18.75 12 18.75C8.27208 18.75 5.25 15.7279 5.25 12ZM1.25 12C1.25 11.5858 1.58579 11.25 2 11.25H3C3.41421 11.25 3.75 11.5858 3.75 12C3.75 12.4142 3.41421 12.75 3 12.75H2C1.58579 12.75 1.25 12.4142 1.25 12ZM20.25 12C20.25 11.5858 20.5858 11.25 21 11.25H22C22.4142 11.25 22.75 11.5858 22.75 12C22.75 12.4142 22.4142 12.75 22 12.75H21C20.5858 12.75 20.25 12.4142 20.25 12ZM18.1476 18.1476C18.4405 17.8547 18.9154 17.8547 19.2083 18.1476L19.6011 18.5405C19.894 18.8334 19.894 19.3082 19.6011 19.6011C19.3082 19.894 18.8334 19.894 18.5405 19.6011L18.1476 19.2083C17.8547 18.9154 17.8547 18.4405 18.1476 18.1476ZM5.85211 18.1479C6.145 18.4408 6.145 18.9157 5.85211 19.2086L5.45927 19.6014C5.16638 19.8943 4.6915 19.8943 4.39861 19.6014C4.10572 19.3085 4.10572 18.8336 4.39861 18.5407L4.79145 18.1479C5.08434 17.855 5.55921 17.855 5.85211 18.1479ZM12 20.25C12.4142 20.25 12.75 20.5858 12.75 21V22C12.75 22.4142 12.4142 22.75 12 22.75C11.5858 22.75 11.25 22.4142 11.25 22V21C11.25 20.5858 11.5858 20.25 12 20.25Z" fill="currentColor"/>';
const MOON =
  '<path fill-rule="evenodd" clip-rule="evenodd" d="M11.0174 2.80157C6.37072 3.29221 2.75 7.22328 2.75 12C2.75 17.1086 6.89137 21.25 12 21.25C16.7767 21.25 20.7078 17.6293 21.1984 12.9826C19.8717 14.6669 17.8126 15.75 15.5 15.75C11.4959 15.75 8.25 12.5041 8.25 8.5C8.25 6.18738 9.33315 4.1283 11.0174 2.80157ZM1.25 12C1.25 6.06294 6.06294 1.25 12 1.25C12.7166 1.25 13.0754 1.82126 13.1368 2.27627C13.196 2.71398 13.0342 3.27065 12.531 3.57467C10.8627 4.5828 9.75 6.41182 9.75 8.5C9.75 11.6756 12.3244 14.25 15.5 14.25C17.5882 14.25 19.4172 13.1373 20.4253 11.469C20.7293 10.9658 21.286 10.804 21.7237 10.8632C22.1787 10.9246 22.75 11.2834 22.75 12C22.75 17.9371 17.9371 22.75 12 22.75C6.06294 22.75 1.25 17.9371 1.25 12Z" fill="currentColor"/>';
// A simple monitor glyph for "usar el tema del sistema" — stroked rather than
// filled (unlike SUN/MOON above) because a solid rectangle reads as an app
// icon, not a display; built from a rect + two straight lines rather than
// hand-authored bezier paths.
const SYSTEM =
  '<rect x="3" y="4.5" width="18" height="12" rx="1.5" stroke="currentColor" stroke-width="1.6" fill="none"/><path d="M8.5 19.5h7M12 16.5v3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>';

function SpainFlag() {
  return (
    <svg className="language-flag" viewBox="0 0 24 16" aria-hidden="true">
      <rect width="24" height="16" fill="#aa151b" />
      <rect y="4" width="24" height="8" fill="#f1bf00" />
    </svg>
  );
}

function UnitedStatesFlag() {
  return (
    <svg className="language-flag" viewBox="0 0 24 16" aria-hidden="true">
      <rect width="24" height="16" fill="#fff" />
      <path fill="#b22234" d="M0 0h24v2H0zm0 4h24v2H0zm0 4h24v2H0zm0 4h24v2H0z" />
      <rect width="10.5" height="8.6" fill="#3c3b6e" />
      <g fill="#fff">
        <circle cx="1.5" cy="1.4" r=".45" /><circle cx="3.8" cy="1.4" r=".45" />
        <circle cx="6.1" cy="1.4" r=".45" /><circle cx="8.4" cy="1.4" r=".45" />
        <circle cx="2.65" cy="3.3" r=".45" /><circle cx="4.95" cy="3.3" r=".45" />
        <circle cx="7.25" cy="3.3" r=".45" /><circle cx="1.5" cy="5.2" r=".45" />
        <circle cx="3.8" cy="5.2" r=".45" /><circle cx="6.1" cy="5.2" r=".45" />
        <circle cx="8.4" cy="5.2" r=".45" /><circle cx="2.65" cy="7.1" r=".45" />
        <circle cx="4.95" cy="7.1" r=".45" /><circle cx="7.25" cy="7.1" r=".45" />
      </g>
    </svg>
  );
}

interface Props {
  title: string;
  theme: Theme;
  onToggleTheme: () => void;
  caps: api.Capabilities | null;
  observedPublicIP: api.PublicIPResult | null;
  publicIPLoading: boolean;
  onRetryPublicIP: () => void;
}

export default function Topbar({ title, theme, onToggleTheme, caps, observedPublicIP, publicIPLoading, onRetryPublicIP }: Props) {
  const { locale, setLocale, t } = useI18n();
  const [copied, setCopied] = useState(false);
  const online = caps && caps.platform !== 'browser';
  const ip = observedPublicIP?.ip;
  const publicIPLabel = publicIPLoading || observedPublicIP === null ? 'IP …' : ip ? `IP ${ip}` : 'IP — ↻';
  const publicIPTitle = ip
    ? t('IP pública: {ip} · Clic para copiar', { ip })
    : observedPublicIP?.err
      ? `${t('IP pública no disponible. Clic para reintentar.')}\n${observedPublicIP.err.slice(0, 180)}`
      : t('IP pública observada externamente. TRAZIP consulta api64.ipify.org una vez al iniciar; no envía direcciones analizadas ni capturas.');
  const displayIP = ip && ip.length > 22 ? `${ip.slice(0, 18)}…` : ip;

  function copyPublicIP() {
    if (!ip || !navigator.clipboard) return;
    navigator.clipboard.writeText(ip).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    }).catch(() => undefined);
  }
  return (
    <header className="topbar">
      <h1>{title}</h1>
      <div className="spacer" />

      <span className={'pill ' + (online ? 'ok' : 'warn')} title={t('Estado del backend')}>
        <span className="dot" />
        {online ? `${caps?.platform} · ${caps?.arch}` : t('sin backend')}
      </span>

      {caps?.elevated && (
        <span className="pill ok" title={t('TRAZIP se está ejecutando como administrador')}>
          <span className="dot" />
          {t('Administrador')}
        </span>
      )}

      {ip ? (
        <button type="button" className="pill public-ip" title={publicIPTitle} onClick={copyPublicIP}>
          {copied ? t('Copiado') : `IP ${displayIP}`}
        </button>
      ) : observedPublicIP && !publicIPLoading ? (
        <button type="button" className="pill public-ip" title={publicIPTitle} aria-label={publicIPTitle} onClick={onRetryPublicIP}>
          {publicIPLabel}
        </button>
      ) : (
        <span className="pill" title={publicIPTitle}>{publicIPLabel}</span>
      )}

      <div className="language-switch" role="group" aria-label={t('Idioma')}>
        <button
          type="button"
          className={locale === 'es' ? 'active' : ''}
          onClick={() => setLocale('es')}
          title={t('Español (España)')}
          aria-pressed={locale === 'es'}
        >
          <SpainFlag /><span>ES</span>
        </button>
        <button
          type="button"
          className={locale === 'en-US' ? 'active' : ''}
          onClick={() => setLocale('en-US')}
          title={t('Inglés (Estados Unidos)')}
          aria-pressed={locale === 'en-US'}
        >
          <UnitedStatesFlag /><span>US</span>
        </button>
      </div>

      <button
        className="icon-btn"
        onClick={onToggleTheme}
        title={
          theme === 'dark' ? t('Cambiar a modo claro')
          : theme === 'light' ? t('Usar el tema del sistema')
          : t('Cambiar a modo oscuro')
        }
        aria-label={t('Cambiar tema')}
      >
        <svg
          width={18}
          height={18}
          viewBox="0 0 24 24"
          fill="none"
          aria-hidden="true"
          dangerouslySetInnerHTML={{ __html: theme === 'dark' ? MOON : theme === 'light' ? SUN : SYSTEM }}
        />
      </button>
    </header>
  );
}
