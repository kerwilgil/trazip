import { useEffect, useState } from 'react';
import { backendAvailable, labScenarios, labRunScenario, labExportReport, type lab } from '../lib/api';
import { useI18n } from '../lib/i18n';

const NO_BACKEND = 'Necesita el runtime Wails (app de escritorio). En el preview del navegador no hay backend.';

export default function Lab() {
  const { t } = useI18n();
  const [scenarios, setScenarios] = useState<lab.Scenario[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, lab.RunResult>>({});
  const [exporting, setExporting] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!backendAvailable()) return;
    labScenarios().then(setScenarios).catch((e) => setError(String(e)));
  }, []);

  async function run(id: string) {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    setError(null);
    setRunning(id);
    try {
      const res = await labRunScenario(id);
      setResults((prev) => ({ ...prev, [id]: res }));
      if (res.err) setError(res.err);
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning(null);
    }
  }

  async function exportReport(id: string, format: string) {
    if (!backendAvailable()) return setError(t(NO_BACKEND));
    setExporting(id + format);
    try {
      await labExportReport(id, format);
    } catch (e) {
      setError(String(e));
    } finally {
      setExporting(null);
    }
  }

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Modo laboratorio')}</h2>
        <p className="body-text">
          {t('Escenarios reproducibles con capturas 100% sintéticas, sin datos personales y con generación determinística. Cada ejecución vuelve a generar la captura, la analiza con los motores reales de TRAZIP y compara el resultado con lo esperado. Está pensado para clases y autoevaluación.')}
        </p>
      </div>

      {error && <div className="note">{error}</div>}

      {scenarios.map((s) => {
        const res = results[s.id];
        return (
          <div className="card" key={s.id} style={{ marginTop: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
              <div>
                <h3 style={{ margin: 0 }}>{t(s.title)}</h3>
                <p className="body-text" style={{ marginTop: 6 }}>{t(s.description)}</p>
						{s.technique && <p className="dim" style={{fontSize:12}}><strong>{t('Técnica:')}</strong> {t(s.technique)} · <strong>{t('Señal:')}</strong> {t(s.signal ?? '')}</p>}
              </div>
              <button className="btn" onClick={() => run(s.id)} disabled={running === s.id}>
                {running === s.id ? <span className="spin" /> : '▶'} {t('Ejecutar')}
              </button>
            </div>

            <h4 style={{ marginTop: 14, marginBottom: 6, fontSize: 13 }}>{t('Objetivos')}</h4>
            <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13 }}>
              {s.objectives.map((o, i) => (
                <li key={i} style={{ marginBottom: 4 }}>
                  {t(o.question)}
                  {o.hint && <span className="dim"> — {t(o.hint)}</span>}
                </li>
              ))}
            </ul>

            {res && (
              <>
						<div style={{display:'flex',gap:8,alignItems:'center',marginTop:10}}><span className={'pill '+(res.status==='pass'?'ok':res.status==='partial'?'warn':'danger')}><span className="dot"/>{res.score}% · {res.passed}/{res.total}</span><span className="dim" style={{fontSize:12}}>scorecard Purple Team</span></div>
                <p className="dim mono" style={{ fontSize: 11.5, marginTop: 12 }}>{t('Captura: {path}', { path: res.pcapPath })}</p>
                {res.err ? (
                  <div className="note">{res.err}</div>
                ) : (
                  <div className="mtr-table-wrap" style={{ marginTop: 8 }}>
                    <table className="mtr-table">
                      <thead><tr><th className="l">{t('Hallazgo')}</th><th className="l">{t('Esperado')}</th><th className="l">{t('Obtenido')}</th><th>{t('¿Coincide?')}</th></tr></thead>
                      <tbody>
                        {res.expected.map((exp) => {
                          const got = res.actual.find((a) => a.key === exp.key);
                          const match = res.matches?.[exp.key];
                          return (
                            <tr key={exp.key}>
                              <td className="l">{t(exp.label)}</td>
                              <td className="l mono">{exp.value}</td>
                              <td className="l mono">{got ? got.value : t('(no encontrado)')}</td>
                              <td className={match ? 'accent-t' : 'err'}>{match ? '✅' : '❌'}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
                <div style={{ display: 'flex', gap: 6, marginTop: 10, flexWrap: 'wrap' }}>
                  <span className="dim" style={{ fontSize: 12, alignSelf: 'center' }}>{t('Exportar evidencia:')}</span>
                  {['json', 'csv', 'html', 'pdf'].map((f) => (
                    <button key={f} className="btn ghost" style={{ padding: '3px 10px', fontSize: 11.5 }} disabled={exporting === s.id + f} onClick={() => exportReport(s.id, f)}>
                      {f.toUpperCase()}
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}
