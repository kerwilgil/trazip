import { useCallback, useEffect, useState } from 'react';
import { backendAvailable, macLookup, ouiInfo, type MACDetail, type OUIInfo } from '../lib/api';
import { useI18n } from '../lib/i18n';
import CopyButton from '../components/CopyButton';

// MacLookup resuelve cualquier MAC contra los registros del IEEE. Vive aparte
// de LAN Explorer porque responde otra pregunta: aquel inventaría *tu* red,
// este consulta una dirección cualquiera —la de un equipo que todavía no
// llegó, la de un log, la de una etiqueta— sin necesidad de tenerla delante.
export default function MacLookup() {
  const { locale, t } = useI18n();
  const [mac, setMac] = useState('');
  const [detail, setDetail] = useState<MACDetail | null>(null);
  const [info, setInfo] = useState<OUIInfo | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    ouiInfo().then(setInfo).catch(() => setInfo(null));
  }, []);

  const lookup = useCallback(async (value: string) => {
    if (!value.trim()) {
      setDetail(null);
      setErr(null);
      return;
    }
    if (!backendAvailable()) {
      setErr(t('Necesita el runtime Wails (app de escritorio).'));
      return;
    }
    try {
      setDetail(await macLookup(value));
      setErr(null);
    } catch (e) {
      setDetail(null);
      setErr(String(e).replace(/^Error:\s*/, ''));
    }
  }, [t]);

  // Cálculo local puro: se resuelve al escribir, sin exigir Enter.
  useEffect(() => {
    const id = setTimeout(() => void lookup(mac), 150);
    return () => clearTimeout(id);
  }, [mac, lookup]);

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('MAC Lookup')}</h2>
        <p className="body-text">
          {t('Consultá el fabricante de cualquier dirección MAC contra los registros oficiales del IEEE, esté o no en tu red. Cálculo local: no consulta ningún servicio externo. Acepta los formatos con dos puntos, con guiones o sin separadores.')}
        </p>
      </div>

      <div className="card">
        <div className="field">
          <input
            className="input mono"
            placeholder="74:4d:28:88:d9:a3 · 744D2888D9A3 · 74-4D-28-88-D9-A3"
            value={mac}
            onChange={(e) => setMac(e.target.value)}
            autoFocus
          />
          {mac && <button className="btn ghost" onClick={() => setMac('')}>{t('Limpiar')}</button>}
        </div>
        {info && !info.present && (
          <p className="note" style={{ fontSize: 11.5, marginTop: 10 }}>
            {t('Los registros del IEEE no están instalados: solo se reconocen fabricantes comunes. Descargalos en Settings / Datasets → Fabricante por MAC.')}
          </p>
        )}
      </div>

      {err && <div className="note">{err}</div>}

      {detail && (
        <>
          {detail.vendor && (
            <div className="card stat" style={{ marginTop: 16 }}>
              <span className="label">{t('Fabricante')}</span>
              <span className="value accent" style={{ fontSize: 22, lineHeight: 1.3 }}>{detail.vendor}</span>
              {detail.prefix && (
                <span className="sub">
                  {t('prefijo {prefix} · {registry}', { prefix: detail.prefix, registry: detail.registry ?? '' })}
                </span>
              )}
            </div>
          )}

          <div className="card" style={{ marginTop: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0 }}>{t('Detalle')}</h3>
              <CopyButton
                label={t('Copiar')}
                getText={() => [
                  `${t('Entrada')}: ${detail.input}`,
                  detail.mac ? `${t('Dirección')}: ${detail.mac}` : '',
                  detail.vendor ? `${t('Fabricante')}: ${detail.vendor}` : '',
                  detail.prefix ? `${t('Prefijo')}: ${detail.prefix} (${detail.registry})` : '',
                  detail.note ? `${t('Nota')}: ${detail.note}` : '',
                ].filter(Boolean).join('\n')}
              />
            </div>
            <div className="list-reset" style={{ marginTop: 10 }}>
              {detail.mac && <div className="kv"><span className="k">{t('Dirección')}</span><span className="v mono">{detail.mac}</span></div>}
              {detail.prefix && (
                <div className="kv">
                  <span className="k">{t('Prefijo asignado')}</span>
                  <span className="v mono">{detail.prefix}</span>
                </div>
              )}
              {detail.registry && (
                <div className="kv">
                  <span className="k">{t('Registro')}</span>
                  <span className="v" style={{ fontFamily: 'inherit' }}>{detail.registry}</span>
                </div>
              )}
              <div className="kv">
                <span className="k">{t('Tipo de dirección')}</span>
                <span className="v" style={{ fontFamily: 'inherit' }}>
                  {detail.broadcast && <span className="tag bogon" style={{ marginRight: 4 }}>{t('difusión')}</span>}
                  {detail.multicast && !detail.broadcast && <span className="tag reserved" style={{ marginRight: 4 }}>{t('multicast')}</span>}
                  {detail.local && <span className="tag reserved" style={{ marginRight: 4 }}>{t('local / aleatoria')}</span>}
                  {!detail.broadcast && !detail.multicast && !detail.local && (
                    <span className="tag private">{t('unicast, asignada por IEEE')}</span>
                  )}
                </span>
              </div>
            </div>
            {detail.note && (
              <p className="dim" style={{ fontSize: 12, marginTop: 12, lineHeight: 1.5 }}>{detail.note}</p>
            )}
          </div>
        </>
      )}

      {info?.present && (
        <p className="dim" style={{ fontSize: 11.5, marginTop: 16 }}>
          {t('{count} prefijos instalados · {registries} · fuente: IEEE Registration Authority', {
            count: info.prefixCount.toLocaleString(locale),
            registries: info.registries ?? '',
          })}
        </p>
      )}
    </div>
  );
}
