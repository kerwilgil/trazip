import { useState } from 'react';
import { backendAvailable, selfTestLocal, type api } from '../lib/api';
import { useI18n } from '../lib/i18n';

const NO_BACKEND = 'Necesita el runtime Wails (app de escritorio). En el preview del navegador no hay backend.';

function statusPillClass(status: string): string {
  switch (status) {
    case 'pass': return 'pill ok';
    case 'fail': return 'pill danger';
    default: return 'pill'; // skipped, unavailable — neutral, never alarming
  }
}

function statusLabel(status: string, t: (s: string) => string): string {
  switch (status) {
    case 'pass': return t('PASS');
    case 'fail': return t('FAIL');
    case 'skipped': return t('SKIPPED');
    case 'unavailable': return t('UNAVAILABLE');
    default: return status;
  }
}

function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export default function SelfTest() {
  const { t } = useI18n();
  const [result, setResult] = useState<api.SelfTestResult | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    if (running) return;
    if (!backendAvailable()) {
      setError(t(NO_BACKEND));
      return;
    }
    setError(null);
    setRunning(true);
    try {
      const res = await selfTestLocal();
      setResult(res);
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Estado del producto')}</h2>
        <p className="body-text">
          {t('Comprueba los componentes internos de TRAZIP mediante pruebas locales, offline y determinísticas. No analiza la conexión a Internet ni la calidad de tu red, no envía tráfico externo y no utiliza capturas personales — usa fixtures sintéticos y almacenamiento temporal que se elimina al terminar.')}
        </p>
      </div>

      {error && <div className="note">{error}</div>}

      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <p className="dim" style={{ margin: 0 }}>
            {running
              ? t('Comprobando TRAZIP…')
              : result
              ? t('Última ejecución: {time}', { time: formatTimestamp(result.completedAt) })
              : t('Aún no se ha ejecutado la comprobación.')}
          </p>
          <button className="btn" onClick={run} disabled={running}>
            {running && <span className="spin" />} {t('Ejecutar comprobación')}
          </button>
        </div>
      </div>

      {result && (
        <>
          <div className="card" style={{ marginTop: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <span className={statusPillClass(result.overallStatus)}>
                <span className="dot" />
                {result.overallStatus === 'fail' ? t('Se detectaron problemas') : t('TRAZIP funciona correctamente')}
              </span>
              <span className="dim mono" style={{ fontSize: 12 }}>{t('Modo:')} {t('Local')}</span>
              <span className={result.networkOut ? 'pill danger' : 'dim'} style={{ fontSize: 12 }}>
                {result.networkOut ? (
                  <>
                    <span className="dot" /> {t('Red externa: se detectó tráfico (inesperado)')}
                  </>
                ) : (
                  t('Red externa: no utilizada')
                )}
              </span>
            </div>

            <div className="grid cols-4" style={{ marginTop: 16 }}>
              <div className="stat">
                <span className="label">{t('PASS')}</span>
                <span className="value accent">{result.passed}</span>
              </div>
              <div className="stat">
                <span className="label">{t('FAIL')}</span>
                <span className="value">{result.failed}</span>
              </div>
              <div className="stat">
                <span className="label">{t('SKIPPED')}</span>
                <span className="value">{result.skipped}</span>
              </div>
              <div className="stat">
                <span className="label">{t('UNAVAILABLE')}</span>
                <span className="value">{result.unavailable}</span>
              </div>
            </div>

            <p className="dim" style={{ fontSize: 12, marginTop: 14 }}>
              {t('Iniciada: {start} · Finalizada: {end}', {
                start: formatTimestamp(result.startedAt),
                end: formatTimestamp(result.completedAt),
              })}
            </p>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <h3>{t('Detalle de comprobaciones')}</h3>
            <p className="dim" style={{ fontSize: 12, marginBottom: 12 }}>
              {t('UNAVAILABLE significa que una capacidad opcional local no está disponible; no implica que TRAZIP esté dañado. SKIPPED indica que una comprobación dependía de otra que no produjo el resultado requerido.')}
            </p>
            <div className="mtr-table-wrap">
              <table className="mtr-table">
                <thead>
                  <tr>
                    <th className="l">{t('Resultado')}</th>
                    <th className="l">{t('Componente')}</th>
                    <th className="l">{t('Detalle')}</th>
                    <th>{t('Duración')}</th>
                  </tr>
                </thead>
                <tbody>
                  {result.checks.map((c) => (
                    <tr key={c.id}>
                      <td className="l">
                        <span className={statusPillClass(c.status)}>
                          <span className="dot" />
                          {statusLabel(c.status, t)}
                        </span>
                      </td>
                      <td className="l">
                        {c.label}
                        <div className="dim mono" style={{ fontSize: 10.5 }}>{c.id}</div>
                      </td>
                      <td className="l">{c.detail}</td>
                      <td className="mono">{c.durationMs} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
