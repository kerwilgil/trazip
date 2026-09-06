import { useEffect, useRef, useState } from 'react';
import { rdapLookupDomain, backendAvailable, type rdap } from '../lib/api';
import { useI18n } from '../lib/i18n';

// Consulta bajo demanda del registro de un dominio (RDAP, el sucesor de whois).
//
// Existe porque resolver un nombre y consultarlo en el registro son dos cosas
// distintas y la app solo sabía hacer la primera: un dominio puede estar
// registrado y no resolver —sin registro A, vencido, o retenido por el
// registro— y "no resuelve" es el síntoma, no la causa.
//
// Nunca se dispara sola: es una salida a internet hacia el registro del TLD y
// se rige por la misma regla de "bajo demanda" que el RDAP de IP.

function fmtDate(s?: string): string {
  return s ? s.slice(0, 10) : '';
}

function Row({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <li className="kv">
      <span className="k">{k}</span>
      <span className="v" style={{ textAlign: 'right', fontFamily: 'inherit', fontWeight: 400 }}>{children}</span>
    </li>
  );
}

type Props = {
  name: string;
  /** Consulta al montar. Solo para quien ya pulsó un botón que pide esto. */
  auto?: boolean;
  /** El nombre no resolvió: explica por qué vale la pena mirar el registro. */
  autoOpen?: boolean;
};

export default function DomainRegistration({ name, auto, autoOpen }: Props) {
  const { t } = useI18n();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<rdap.DomainResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fired = useRef(false);

  async function lookup() {
    if (!backendAvailable()) return setError(t('Necesita el runtime Wails (app de escritorio).'));
    setError(null);
    setLoading(true);
    try {
      setResult(await rdapLookupDomain(name));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  // El ref evita que StrictMode dispare dos veces la misma consulta externa en
  // desarrollo: es tráfico real hacia el registro, no una llamada idempotente
  // que dé igual repetir.
  useEffect(() => {
    if (!auto || fired.current) return;
    fired.current = true;
    lookup();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto, name]);

  if (!result) {
    return (
      <div className="card" style={{ marginTop: 16 }}>
        <h3>{t('Registro del dominio')}</h3>
        <p className="body-text dim">
          {autoOpen
            ? t('El nombre no resolvió a ninguna dirección. Eso no dice si el dominio existe: consultá su registro para saber si está registrado, quién es el registrador y cuándo vence.')
            : t('Consulta el registro del TLD (RDAP, el sucesor de whois): registrador, fechas de alta y vencimiento, estado y servidores de nombres.')}
        </p>
        {error && <div className="note">{error}</div>}
        <button className="btn" onClick={lookup} disabled={loading}>
          {loading ? <span className="spin" /> : '📋'} {t('Consultar registro de {name}', { name })}
        </button>
      </div>
    );
  }

  // Un dominio vencido o por vencer explica caídas que parecen de red, así que
  // el estado del plazo se destaca en vez de quedar como una fecha más.
  const days = result.daysToExpiry;
  const expiryColor = days === undefined ? undefined
    : days < 0 ? 'var(--danger)'
    : days <= 30 ? 'var(--warn)'
    : undefined;

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <h3>{t('Registro del dominio')}</h3>

      {result.err ? (
        <>
          <p className="body-text">
            {t('El registro no devolvió datos para {name}: {err}', { name: result.asked, err: result.err })}
          </p>
          {result.notes.length > 0 && <div className="note">{result.notes.join(' · ')}</div>}
        </>
      ) : (
        <>
          {!result.isExact && (
            <div className="note">{result.notes.join(' · ')}</div>
          )}

          <div className="mono" style={{ fontWeight: 700, fontSize: 15, marginTop: 12 }}>{result.registered}</div>

          <ul className="list-reset" style={{ marginTop: 10 }}>
            {result.registrar && <Row k={t('Registrador')}>{result.registrar}</Row>}
            {result.created && <Row k={t('Registrado')}>{fmtDate(result.created)}</Row>}
            {result.updated && <Row k={t('Último cambio')}>{fmtDate(result.updated)}</Row>}
            {result.expires && (
              <Row k={t('Vence')}>
                <span style={{ color: expiryColor, fontWeight: expiryColor ? 700 : undefined }}>
                  {fmtDate(result.expires)}
                  {days !== undefined && (
                    days < 0
                      ? ` · ${t('vencido hace {n} días', { n: String(-days) })}`
                      : ` · ${t('en {n} días', { n: String(days) })}`
                  )}
                </span>
              </Row>
            )}
            {result.tld && <Row k={t('TLD')}>.{result.tld}</Row>}
            {result.handle && <Row k={t('Identificador')}>{result.handle}</Row>}
            {result.abuseEmail && <Row k={t('Abuso')}>{result.abuseEmail}</Row>}
          </ul>

          {result.nameservers && result.nameservers.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div className="settings-label">{t('Servidores de nombres')}</div>
              <div className="mono" style={{ fontSize: 12 }}>{result.nameservers.join(', ')}</div>
            </div>
          )}

          {result.status && result.status.length > 0 && (
            <div style={{ marginTop: 10, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {result.status.map((s) => <span key={s} className="tag" style={{ fontSize: 10 }}>{s}</span>)}
            </div>
          )}

          {result.isExact && result.notes.length > 0 && (
            <div className="note">{result.notes.join(' · ')}</div>
          )}

          {result.remarks && result.remarks.length > 0 && (
            <p className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>{result.remarks.join(' · ')}</p>
          )}

          <div className="dim" style={{ fontSize: 10.5, marginTop: 10 }}>
            {result.disclosure.source} · {t('consultado')} {result.disclosure.queriedAt}
          </div>
        </>
      )}
    </div>
  );
}
