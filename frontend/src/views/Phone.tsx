import { useCallback, useEffect, useState } from 'react';
import { backendAvailable, phoneAnalyze, type PhoneResult } from '../lib/api';
import { useI18n } from '../lib/i18n';
import { countryFlag } from '../lib/flags';
import CopyButton from '../components/CopyButton';

// Phone identifica un número contra los metadatos de libphonenumber, que van
// compilados dentro del binario. Vive en Inteligencia junto a Web Intelligence
// porque responde el mismo tipo de pregunta —qué es esto que aparece en un
// registro— y no toca la red en ningún momento: un número es dato personal, y
// los que se consultan aquí suelen ser de un cliente o de quien llamó.

// regionName traduce el código ISO al idioma activo con lo que ya trae el
// navegador, en vez de arrastrar una tabla de ~250 países en el backend.
function regionName(code: string, locale: string): string {
  if (!code) return '';
  try {
    return new Intl.DisplayNames([locale], { type: 'region' }).of(code) ?? code;
  } catch {
    return code;
  }
}

// kindTone colorea el tipo de línea solo cuando decir algo aporta: VoIP y
// premium cambian decisiones (enrutado, coste), el resto es informativo.
function kindTone(kind: string): string | undefined {
  switch (kind) {
    case 'tarifa premium':
      return 'var(--danger)';
    case 'VoIP':
      return 'var(--accent)';
    default:
      return undefined;
  }
}

function Row({ k, children, mono }: { k: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div className="kv">
      <span className="k">{k}</span>
      <span className={'v' + (mono ? ' mono' : '')} style={mono ? undefined : { fontFamily: 'inherit', fontWeight: 400, textAlign: 'right' }}>
        {children}
      </span>
    </div>
  );
}

export default function Phone() {
  const { locale, t } = useI18n();
  const [input, setInput] = useState('');
  const [res, setRes] = useState<PhoneResult | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const analyze = useCallback(async (value: string) => {
    if (!value.trim()) {
      setRes(null);
      setErr(null);
      return;
    }
    if (!backendAvailable()) {
      setErr(t('Necesita el runtime Wails (app de escritorio).'));
      return;
    }
    try {
      setRes(await phoneAnalyze(value, ''));
      setErr(null);
    } catch (e) {
      setRes(null);
      setErr(String(e).replace(/^Error:\s*/, ''));
    }
  }, [t]);

  // Cálculo local puro: se resuelve al escribir, igual que MAC Lookup.
  useEffect(() => {
    const id = setTimeout(() => void analyze(input), 150);
    return () => clearTimeout(id);
  }, [input, analyze]);

  const country = regionName(res?.region ?? '', locale);

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Teléfono')}</h2>
        <p className="body-text">
          {t('Identificá cualquier número: si es válido, de qué país, qué operador tenía asignado el rango y si la línea es móvil, fija o VoIP. Cálculo local con los metadatos de libphonenumber incluidos en la app — el número no sale de esta máquina.')}
        </p>
      </div>

      <div className="card">
        <div className="field">
          <input
            className="input mono"
            placeholder="+507 6123 4567 · +1 800 555 0199 · 61234567"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            autoFocus
          />
          {input && <button className="btn ghost" onClick={() => setInput('')}>{t('Limpiar')}</button>}
        </div>
        <p className="dim" style={{ fontSize: 11.5, marginTop: 10 }}>
          {t('Sin el prefijo internacional se asume Panamá (+507). Escribí el número con "+" y su código de país para consultar otro.')}
        </p>
      </div>

      {err && <div className="note">{err}</div>}
      {res?.err && <div className="note">{res.err}</div>}
      {res && res.notes.length > 0 && <div className="note">{res.notes.join(' · ')}</div>}

      {res && !res.err && (
        <>
          <div className="grid cols-3" style={{ marginTop: 16 }}>
            <div className="card stat">
              <span className="label">{t('Tipo de línea')}</span>
              <span className="value accent" style={{ fontSize: 22, lineHeight: 1.3, color: kindTone(res.kind) }}>
                {res.kind}
              </span>
              {res.kindNote && <span className="sub">{res.kindNote}</span>}
            </div>
            <div className="card stat">
              <span className="label">{t('País')}</span>
              <span className="value" style={{ fontSize: 20, lineHeight: 1.3, display: 'flex', alignItems: 'center', gap: 8 }}>
                {res.region && countryFlag(res.region)} {country || '—'}
              </span>
              <span className="sub">{res.countryCode ? `+${res.countryCode}` : ''}{res.area ? ` · ${res.area}` : ''}</span>
            </div>
            <div className="card stat">
              <span className="label">{t('Validez')}</span>
              <span className="value" style={{ fontSize: 20, lineHeight: 1.3, color: res.valid ? undefined : 'var(--warn)' }}>
                {res.valid ? t('válido') : t('no asignado')}
              </span>
              <span className="sub">{res.valid ? t('cae en un rango asignado del país') : t('revisá la transcripción')}</span>
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0 }}>{t('Detalle')}</h3>
              <CopyButton
                label={t('Copiar')}
                getText={() => [
                  `${t('Entrada')}: ${res.input}`,
                  res.e164 ? `E.164: ${res.e164}` : '',
                  res.international ? `${t('Internacional')}: ${res.international}` : '',
                  res.national ? `${t('Nacional')}: ${res.national}` : '',
                  res.rfc3966 ? `${t('URI tel:')}: ${res.rfc3966}` : '',
                  `${t('Tipo de línea')}: ${res.kind}`,
                  country ? `${t('País')}: ${country} (+${res.countryCode})` : '',
                  res.carrier ? `${t('Operador')}: ${res.carrier}` : '',
                  res.timezones.length ? `${t('Zona horaria')}: ${res.timezones.join(', ')}` : '',
                ].filter(Boolean).join('\n')}
              />
            </div>
            <div className="list-reset" style={{ marginTop: 10 }}>
              {res.e164 && <Row k="E.164" mono>{res.e164}</Row>}
              {res.international && <Row k={t('Internacional')} mono>{res.international}</Row>}
              {res.national && <Row k={t('Nacional')} mono>{res.national}</Row>}
              {/* La forma que viaja en las cabeceras SIP: lista para pegar. */}
              {res.rfc3966 && <Row k={t('URI tel:')} mono>{res.rfc3966}</Row>}
              {res.carrier && (
                <Row k={t('Operador')}>
                  {res.carrier}
                  {res.carrierNote && (
                    <div className="dim" style={{ fontSize: 11, marginTop: 2 }}>{res.carrierNote}</div>
                  )}
                </Row>
              )}
              {res.timezones.length > 0 && <Row k={t('Zona horaria')}>{res.timezones.join(', ')}</Row>}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
