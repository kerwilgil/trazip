import { useState } from 'react';
import { useI18n } from '../lib/i18n';

// Copies the text produced by getText() to the clipboard and shows brief,
// explicit feedback for both success and failure — a bare onClick with a
// swallowed .catch() gives zero visible signal either way, which reads as
// "the button doesn't work" even when the copy actually succeeded.
export default function CopyButton({
  getText,
  label = 'Copiar',
  className = 'btn ghost',
  disabled = false,
}: {
  getText: () => string;
  label?: string;
  className?: string;
  disabled?: boolean;
}) {
  const { t } = useI18n();
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');

  async function copy() {
    try {
      await navigator.clipboard.writeText(getText());
      setState('copied');
    } catch {
      setState('failed');
    } finally {
      setTimeout(() => setState('idle'), 1500);
    }
  }

  const text = state === 'copied' ? t('✅ Copiado') : state === 'failed' ? t('⚠️ No se pudo copiar') : `📋 ${t(label)}`;
  return (
    <button className={className} onClick={copy} type="button" disabled={disabled}>
      {text}
    </button>
  );
}
