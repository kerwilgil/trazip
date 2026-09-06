import { useCallback, useEffect, useState } from 'react';
import { backendAvailable, setWindowBackground } from './api';
import { SystemThemePreference as goSystemThemePreference } from '../../wailsjs/go/main/App';

// Theme is the user's own choice, which may be 'system' — "keep following
// whatever the OS says", not just "start from the OS once". Applied is what
// actually lands on <html data-theme> and the native window background: the
// resolved value, always 'dark' or 'light', never 'system' itself.
export type Theme = 'dark' | 'light' | 'system';
export type Applied = 'dark' | 'light';
const KEY = 'trazip-theme';

// index.html's inline pre-paint script already resolves 'system' (or no
// stored choice at all) against prefers-color-scheme before first paint, so
// there's no flash to avoid here — this only needs to agree with what that
// script already decided. That pre-paint script can only use the media
// query (it runs before the Wails bridge exists), so the very first paint
// may briefly disagree with Windows before the effect below corrects it —
// see systemPrefersDark for why the media query alone isn't trustworthy.
function storedTheme(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    if (v === 'light' || v === 'dark' || v === 'system') return v;
  } catch {
    /* storage may be unavailable */
  }
  return 'system';
}

function systemPrefersDarkMedia(): boolean {
  return typeof window !== 'undefined' && !!window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
}

// WebView2's own prefers-color-scheme media query does not reliably track
// Windows' "Choose your default app mode" setting, so a user in dark mode
// can see TRAZIP resolve "system" to light. app.go's SystemThemePreference
// reads the same registry value Windows' own Settings page does, so it's
// authoritative when it answers "dark" or "light". It answers "" (unknown)
// on platforms with no equivalent integration yet (or if the registry read
// failed) — that case, like running with no Wails runtime at all, falls
// back to the media query rather than asserting a preference nobody
// actually confirmed.
async function systemPrefersDark(): Promise<boolean> {
  if (backendAvailable()) {
    try {
      const pref = await goSystemThemePreference();
      if (pref === 'dark') return true;
      if (pref === 'light') return false;
      // pref === '' (unknown): fall through to the media query below.
    } catch {
      /* fall through to the media query below */
    }
  }
  return systemPrefersDarkMedia();
}

async function resolve(theme: Theme): Promise<Applied> {
  if (theme !== 'system') return theme;
  return (await systemPrefersDark()) ? 'dark' : 'light';
}

function apply(applied: Applied): void {
  document.documentElement.setAttribute('data-theme', applied);
  // The native window paints its own background before the page content, so
  // it has to follow the theme too or repaints flash the other theme's colour.
  setWindowBackground(applied);
}

export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(storedTheme);

  useEffect(() => {
    let cancelled = false;
    resolve(theme).then((applied) => {
      if (!cancelled) apply(applied);
    });
    try {
      localStorage.setItem(KEY, theme);
    } catch {
      /* storage may be unavailable */
    }

    if (theme !== 'system') return () => { cancelled = true; };
    // While the user has explicitly chosen "system", keep following it live —
    // otherwise the OS switching at sunset (or the user changing it manually)
    // would leave TRAZIP stuck on whatever it happened to resolve to at mount.
    // The media query's 'change' event is a best-effort trigger (it may not
    // fire at all if WebView2 never updates it); 'focus' catches the common
    // case of the user changing Windows' theme and switching back to TRAZIP.
    const recheck = () => {
      resolve('system').then((applied) => {
        if (!cancelled) apply(applied);
      });
    };
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    mq.addEventListener('change', recheck);
    window.addEventListener('focus', recheck);
    return () => {
      cancelled = true;
      mq.removeEventListener('change', recheck);
      window.removeEventListener('focus', recheck);
    };
  }, [theme]);

  const toggle = useCallback(() => {
    setTheme((t) => (t === 'dark' ? 'light' : t === 'light' ? 'system' : 'dark'));
  }, []);

  return [theme, toggle];
}
