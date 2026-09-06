import { useCallback, useEffect, useState } from 'react';
import {
  backendAvailable,
  ipcalcAnalyze,
  ipcalcSplit,
  ipcalcVLSM,
  ipcalcAggregate,
  ipcalcContains,
  ipcalcCustomerPlan,
  type ipcalc,
} from '../lib/api';
import { useCaptureSession } from '../lib/session';
import CopyButton from '../components/CopyButton';
import { useI18n } from '../lib/i18n';

type Tab = 'analizar' | 'cantidad' | 'dividir' | 'vlsm' | 'agregar';

function formatInteger(value: string | number): string {
  try {
    return BigInt(value).toLocaleString();
  } catch {
    return String(value);
  }
}

function csvEscape(v: string): string {
  if (/[",\n]/.test(v)) return '"' + v.replace(/"/g, '""') + '"';
  return v;
}

function subnetsToCSV(rows: ipcalc.Subnet[]): string {
  const header = 'n,prefijo,red,broadcast,primerHost,ultimoHost,hostsUtiles';
  const lines = rows.map((r) =>
    [r.index + 1, r.prefix, r.network, r.broadcast || '', r.firstHost, r.lastHost, r.usableCount]
      .map((v) => csvEscape(String(v)))
      .join(','),
  );
  return [header, ...lines].join('\n');
}

function downloadText(filename: string, text: string, mime: string) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// Kv is the label/value row used all over the breakdown — same .kv class the
// rest of the app uses, with the value in mono since these are all addresses.
function Kv({ k, v, mono = true }: { k: string; v?: string; mono?: boolean }) {
  const { t } = useI18n();
  if (!v) return null;
  return (
    <div className="kv">
      <span className="k">{t(k)}</span>
      <span className={'v' + (mono ? '' : ' plain')} style={mono ? undefined : { fontFamily: 'inherit', fontWeight: 600 }}>{v}</span>
    </div>
  );
}

function classChips(classes?: string[]) {
  if (!classes || classes.length === 0) return null;
  const known = ['public', 'private', 'bogon', 'reserved', 'documentation', 'vpn', 'proxy', 'tor', 'hosting'];
  return (
    <>
      {classes.map((c) => (
        <span key={c} className={'tag ' + (known.includes(c) ? c : '')} style={{ marginRight: 4 }}>{c}</span>
      ))}
    </>
  );
}

export default function IPCalc() {
  const { locale, t } = useI18n();
  const { navigateTo, setPendingLanRange } = useCaptureSession();
  const [tab, setTab] = useState<Tab>('analizar');

  // --- Cantidad de IP ---
  const [customerCount, setCustomerCount] = useState('4');
  const [reserveGateway, setReserveGateway] = useState(true);
  const [customerReference, setCustomerReference] = useState('');
  const [customerPlan, setCustomerPlan] = useState<ipcalc.CustomerPlan | null>(null);
  const [customerBlock, setCustomerBlock] = useState<ipcalc.Info | null>(null);
  const [customerPlanError, setCustomerPlanError] = useState<string | null>(null);
  const [customerReferenceError, setCustomerReferenceError] = useState<string | null>(null);

  async function calculateCustomerPlan() {
    const requested = Number(customerCount);
    if (!Number.isSafeInteger(requested) || requested < 1) {
      setCustomerPlan(null);
      setCustomerBlock(null);
      setCustomerPlanError(t('Introduce una cantidad entera de al menos una IP.'));
      setCustomerReferenceError(null);
      return;
    }
    try {
      const plan = await ipcalcCustomerPlan(requested, reserveGateway);
      setCustomerPlan(plan);
      setCustomerPlanError(null);
      setCustomerBlock(null);
      setCustomerReferenceError(null);

      const reference = customerReference.trim();
      if (reference) {
        try {
          const address = reference.split('/', 1)[0].trim();
          const block = await ipcalcAnalyze(`${address}/${plan.prefixLen}`);
          if (block.family !== 'IPv4') {
            throw new Error(t('La referencia debe ser una dirección IPv4.'));
          }
          setCustomerBlock(block);
        } catch (e) {
          setCustomerReferenceError(
            t('El bloque por cantidad se calculó correctamente. Revisa la IPv4 opcional: {error}', { error: String(e).replace(/^Error:\s*/, '') }),
          );
        }
      }
    } catch (e) {
      setCustomerPlan(null);
      setCustomerBlock(null);
      setCustomerPlanError(String(e).replace(/^Error:\s*/, ''));
      setCustomerReferenceError(null);
    }
  }

  // --- Analizar ---
  const [input, setInput] = useState('192.168.10.77/26');
  const [info, setInfo] = useState<ipcalc.Info | null>(null);
  const [error, setError] = useState<string | null>(null);

  const analyze = useCallback(async (value: string) => {
    if (!backendAvailable()) {
      setError(t('Necesita el runtime Wails (app de escritorio).'));
      return;
    }
    if (!value.trim()) {
      setInfo(null);
      setError(null);
      return;
    }
    try {
      setInfo(await ipcalcAnalyze(value));
      setError(null);
    } catch (e) {
      setInfo(null);
      setError(String(e).replace(/^Error:\s*/, ''));
    }
  }, [t]);

  // Recalcula al escribir: es cálculo local puro, no hay razón para exigir Enter.
  useEffect(() => {
    const t = setTimeout(() => void analyze(input), 150);
    return () => clearTimeout(t);
  }, [input, analyze]);

  // --- Dividir ---
  const [splitBits, setSplitBits] = useState(28);
  const [split, setSplit] = useState<ipcalc.SplitResult | null>(null);
  const [splitError, setSplitError] = useState<string | null>(null);

  async function doSplit() {
    setSplitError(null);
    try {
      setSplit(await ipcalcSplit(input, splitBits));
    } catch (e) {
      setSplit(null);
      setSplitError(String(e).replace(/^Error:\s*/, ''));
    }
  }

  // --- VLSM ---
  const [reqs, setReqs] = useState<{ label: string; hosts: string }[]>([
    { label: 'Oficina', hosts: '100' },
    { label: 'WiFi invitados', hosts: '50' },
    { label: 'Enlace router', hosts: '2' },
  ]);
  const [vlsm, setVlsm] = useState<ipcalc.VLSMResult | null>(null);
  const [vlsmError, setVlsmError] = useState<string | null>(null);

  async function doVLSM() {
    setVlsmError(null);
    const parsed = reqs
      .filter((r) => r.label.trim() || r.hosts.trim())
      .map((r) => ({ label: r.label.trim() || t('sin nombre'), hosts: Number(r.hosts) || 0 }));
    try {
      setVlsm(await ipcalcVLSM(input, parsed as ipcalc.VLSMRequest[]));
    } catch (e) {
      setVlsm(null);
      setVlsmError(String(e).replace(/^Error:\s*/, ''));
    }
  }

  // --- Agregar / contiene ---
  const [aggInput, setAggInput] = useState('192.168.1.0/25\n192.168.1.128/25\n10.0.0.0/8\n10.1.2.0/24');
  const [agg, setAgg] = useState<string[] | null>(null);
  const [aggError, setAggError] = useState<string | null>(null);
  const [containsAddr, setContainsAddr] = useState('192.168.10.90');
  const [contains, setContains] = useState<boolean | null>(null);

  async function doAggregate() {
    setAggError(null);
    try {
      setAgg(await ipcalcAggregate(aggInput.split('\n').filter((l) => l.trim())));
    } catch (e) {
      setAgg(null);
      setAggError(String(e).replace(/^Error:\s*/, ''));
    }
  }

  async function doContains() {
    try {
      setContains(await ipcalcContains(input, containsAddr));
      setAggError(null);
    } catch (e) {
      setContains(null);
      setAggError(String(e).replace(/^Error:\s*/, ''));
    }
  }

  function clearActiveTab() {
    switch (tab) {
      case 'analizar':
        setInput('');
        setInfo(null);
        setError(null);
        break;
      case 'cantidad':
        setCustomerCount('');
        setReserveGateway(true);
        setCustomerReference('');
        setCustomerPlan(null);
        setCustomerBlock(null);
        setCustomerPlanError(null);
        setCustomerReferenceError(null);
        break;
      case 'dividir':
        setSplit(null);
        setSplitError(null);
        break;
      case 'vlsm':
        setVlsm(null);
        setVlsmError(null);
        break;
      case 'agregar':
        setAgg(null);
        setContains(null);
        setAggError(null);
        break;
    }
  }

  // Manda el prefijo calculado al LAN Explorer y salta a esa pestaña — el
  // motivo por el que la calculadora vive en Diagnóstico y no suelta.
  function scanThis(prefix: string) {
    setPendingLanRange(prefix);
    navigateTo('lan');
  }

  const canScan = info?.family === 'IPv4' && info.prefixLen <= 32 && info.prefixLen >= 16;
  const customerBlockLabel = customerBlock
    ? `${customerBlock.network}/${customerBlock.prefixLen}`
    : customerPlan?.block;

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Calculadora IP')}</h2>
        <p className="body-text">
          {t('Subnetting, planificación VLSM y agregación de prefijos para IPv4 e IPv6. Cálculo local puro: no consulta nada, no envía nada. Acepta prefijo, máscara o wildcard.')}
        </p>
      </div>

      <div className="card">
        <div className="field">
          <input
            className="input mono"
            placeholder="192.168.10.77/26 · 10.0.0.1 255.255.255.0 · 2001:db8::1/64"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            autoFocus
          />
          {canScan && (
            <button className="btn ghost" onClick={() => scanThis(info!.prefix.replace(/\/\d+$/, '/' + info!.prefixLen))} title={t('Cargar esta red en el LAN Explorer')}>
              {t('Escanear →')}
            </button>
          )}
        </div>
        {error && <div className="note" style={{ marginTop: 10 }}>{error}</div>}
      </div>

      <div className="tabs" style={{ marginTop: 16 }}>
        <button className={'tab' + (tab === 'analizar' ? ' active' : '')} onClick={() => setTab('analizar')}>{t('Desglose')}</button>
        <button className={'tab' + (tab === 'cantidad' ? ' active' : '')} onClick={() => setTab('cantidad')}>{t('Cantidad de IP')}</button>
        <button className={'tab' + (tab === 'dividir' ? ' active' : '')} onClick={() => setTab('dividir')}>{t('Dividir en subredes')}</button>
        <button className={'tab' + (tab === 'vlsm' ? ' active' : '')} onClick={() => setTab('vlsm')}>VLSM</button>
        <button className={'tab' + (tab === 'agregar' ? ' active' : '')} onClick={() => setTab('agregar')}>{t('Agregar / contiene')}</button>
        <button className="btn ghost tab-clear" onClick={clearActiveTab}>🗑 {t('Limpiar pestaña')}</button>
      </div>

      {/* Los paneles se montan siempre y se ocultan: conserva el estado al
          cambiar de pestaña, mismo patrón que Web Intelligence y Ping/MTR. */}
      {info && (
        <div style={{ display: tab === 'analizar' ? 'block' : 'none' }}>
            <div className="grid cols-4">
              <div className="card stat">
                <span className="label">{t('Red')}</span>
                <span className="value accent mono" style={{ fontSize: 19 }}>{info.network}</span>
                <span className="sub">/{info.prefixLen} · {info.family}</span>
              </div>
              <div className="card stat">
                <span className="label">{t('Hosts utilizables')}</span>
                <span className="value">{formatInteger(info.usableCount)}</span>
                <span className="sub">{t('de {total} direcciones', { total: formatInteger(info.totalCount) })}</span>
              </div>
              <div className="card stat">
                <span className="label">{t('Primer host')}</span>
                <span className="value mono" style={{ fontSize: 17 }}>{info.firstHost}</span>
                <span className="sub">{t('inicio del rango')}</span>
              </div>
              <div className="card stat">
                <span className="label">{info.broadcast ? 'Broadcast' : t('Última dirección')}</span>
                <span className="value mono" style={{ fontSize: 17 }}>{info.broadcast || info.lastHost}</span>
                <span className="sub">{info.broadcast ? t('último host {host}', { host: info.lastHost }) : t('fin del rango')}</span>
              </div>
            </div>

            <div className="grid cols-2" style={{ marginTop: 16 }}>
              <div className="card">
                <h3>{t('Direccionamiento')}</h3>
                <div className="list-reset">
                  <Kv k="Prefijo" v={info.prefix} />
                  <Kv k="Máscara" v={info.netmask} />
                  <Kv k="Wildcard (ACL)" v={info.wildcard} />
                  <Kv k="Rango útil" v={`${info.firstHost} – ${info.lastHost}`} />
                  <Kv k="Total direcciones" v={formatInteger(info.totalCount)} />
                  {info.class && <Kv k="Clase histórica" v={info.class} mono={false} />}
                  <div className="kv">
                    <span className="k">{t('Clasificación RFC')}</span>
                    <span className="v" style={{ fontFamily: 'inherit' }}>{classChips(info.classes)}</span>
                  </div>
                </div>
              </div>

              <div className="card">
                <h3>{t('Representaciones')}</h3>
                <div className="list-reset">
                  <Kv k="Binario (dirección)" v={info.addrBinary} />
                  <Kv k="Binario (red)" v={info.networkBinary} />
                  <Kv k="Binario (máscara)" v={info.maskBinary} />
                  <Kv k="Hexadecimal" v={info.hex} />
                  <Kv k="Decimal" v={info.decimal ? formatInteger(info.decimal) : undefined} />
                  <Kv k="Expandida" v={info.expanded} />
                  <Kv k="Comprimida" v={info.compressed} />
                </div>
              </div>
            </div>

            <div className="card" style={{ marginTop: 16 }}>
              <h3>{t('DNS inverso')}</h3>
              <div className="list-reset">
                <Kv k="PTR de esta dirección" v={info.ptr} />
                <Kv k="Zona de delegación" v={info.reverseZone} />
              </div>
              <div style={{ marginTop: 10 }}>
                <CopyButton label={t('Copiar desglose')} getText={() => [
                  `Entrada: ${info.input}`,
                  `Prefijo: ${info.prefix}`,
                  `Red: ${info.network}`,
                  info.broadcast ? `Broadcast: ${info.broadcast}` : '',
                  `Rango útil: ${info.firstHost} - ${info.lastHost}`,
                  `Hosts utilizables: ${info.usableCount} (de ${info.totalCount})`,
                  info.netmask ? `Máscara: ${info.netmask}` : '',
                  info.wildcard ? `Wildcard: ${info.wildcard}` : '',
                  `Clases: ${(info.classes || []).join(', ')}`,
                  `PTR: ${info.ptr}`,
                  `Zona inversa: ${info.reverseZone}`,
                ].filter(Boolean).join('\n')} />
              </div>
            </div>

            {info.notes && info.notes.length > 0 && (
              <div className="note" style={{ marginTop: 12 }}>
                {info.notes.map((n, i) => <div key={i} style={{ marginTop: i ? 6 : 0 }}>{n}</div>)}
              </div>
            )}
        </div>
      )}

      <div style={{ display: tab === 'cantidad' ? 'block' : 'none' }}>
            <div className="card">
              <h3>{t('Cantidad de IP')}</h3>
              <p className="dim" style={{ fontSize: 11.5, marginTop: 0, marginBottom: 12 }}>
                {t('Calcula el bloque IPv4 convencional mínimo. La dirección de red y el broadcast se reservan siempre; el gateway puede reservarse dentro del mismo bloque.')}
              </p>
              <div className="field-grid cols-2">
                <label>
                  {t('IP utilizables requeridas')}
                  <input
                    className="input mono"
                    type="number"
                    min={1}
                    max={4294967294}
                    step={1}
                    value={customerCount}
                    onChange={(e) => setCustomerCount(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') void calculateCustomerPlan();
                    }}
                    placeholder={t('Ej. 4, 20, 50')}
                  />
                </label>
                <div>
                  <label className="check-inline" style={{ marginTop: 23 }}>
                    <input
                      type="checkbox"
                      checked={reserveGateway}
                      onChange={(e) => setReserveGateway(e.target.checked)}
                    />
                    {t('Reservar 1 IP para gateway/router')}
                  </label>
                </div>
              </div>
              <div className="field-grid cols-2" style={{ marginTop: 10 }}>
                <label>
                  {t('IPv4 de referencia (opcional)')}
                  <input
                    className="input mono"
                    value={customerReference}
                    onChange={(e) => setCustomerReference(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') void calculateCustomerPlan();
                    }}
                    placeholder={t('Ingresa la IP pública')}
                    spellCheck={false}
                  />
                  <span className="dim" style={{ fontSize: 10.5, fontWeight: 400 }}>
                    {t('Déjala vacía para calcular solo el tamaño. Si la completas, se mostrará la subred concreta que contiene esa IP.')}
                  </span>
                </label>
              </div>
              <button className="btn" style={{ marginTop: 12 }} onClick={calculateCustomerPlan}>
                {t('Calcular bloque requerido')}
              </button>
              {customerPlanError && <div className="note" style={{ marginTop: 10 }}>{customerPlanError}</div>}
              {customerReferenceError && <div className="note" style={{ marginTop: 10 }}>{customerReferenceError}</div>}
            </div>

            {customerPlan && (
              <>
                <div className="grid cols-4" style={{ marginTop: 16 }}>
                  <div className="card stat">
                    <span className="label">{t('Bloque requerido')}</span>
                    <span className="value accent mono" style={customerBlock ? { fontSize: 18 } : undefined}>{customerBlockLabel}</span>
                    <span className="sub">{customerBlock ? t('subred concreta · {block}', { block: customerPlan.block }) : t('IPv4 convencional mínimo')}</span>
                  </div>
                  <div className="card stat">
                    <span className="label">{t('Total del bloque')}</span>
                    <span className="value">{formatInteger(customerPlan.total)}</span>
                    <span className="sub">{t('direcciones en total')}</span>
                  </div>
                  <div className="card stat">
                    <span className="label">{t('IP solicitadas')}</span>
                    <span className="value">{formatInteger(customerPlan.requested)}</span>
                    <span className="sub">{t('IP solicitadas')}</span>
                  </div>
                  <div className="card stat">
                    <span className="label">{t('Reservadas o libres')}</span>
                    <span className="value">{formatInteger(customerPlan.notAssignedToCustomer)}</span>
                    <span className="sub">{t('reservadas + libres')}</span>
                  </div>
                </div>

                <div className="card" style={{ marginTop: 16 }}>
                  <div className="result-card-head">
                    <div>
                      <h3>{t('Desglose del bloque {block}', { block: customerBlockLabel ?? '' })}</h3>
                      <p className="dim">
                        {t('No son IP “perdidas”: algunas son obligatorias para la subred y las demás quedan disponibles dentro del bloque asignado.')}
                      </p>
                    </div>
                    <CopyButton
                      label={t('Copiar desglose')}
                      getText={() => [
                        `IP utilizables solicitadas: ${customerPlan.requested}`,
                        `Bloque requerido: ${customerBlockLabel} (${customerPlan.total} direcciones)`,
                        customerBlock ? `IPv4 de referencia: ${customerBlock.addr}` : '',
                        customerBlock ? `Dirección de red: ${customerBlock.network}` : '',
                        customerBlock ? `Rango utilizable: ${customerBlock.firstHost} - ${customerBlock.lastHost}` : '',
                        customerBlock ? `Broadcast: ${customerBlock.broadcast}` : '',
                        customerBlock && customerPlan.gatewayReserved ? `Gateway sugerido (opcional): ${customerBlock.firstHost}` : '',
                        `Red: ${customerPlan.networkReserved}`,
                        `Broadcast: ${customerPlan.broadcastReserved}`,
                        `Gateway: ${customerPlan.gatewayReserved}`,
                        `Libres en el bloque: ${customerPlan.spare}`,
                        `Reservadas o libres: ${customerPlan.notAssignedToCustomer}`,
                      ].filter(Boolean).join('\n')}
                    />
                  </div>
                  <div className="list-reset" style={{ marginTop: 12 }}>
                    {customerBlock && (
                      <>
                        <Kv k="IPv4 de referencia" v={customerBlock.addr} />
                        <Kv k="Subred concreta" v={customerBlockLabel} />
                        <Kv k="Dirección de red" v={customerBlock.network} />
                        <Kv k="Rango utilizable total" v={`${customerBlock.firstHost} – ${customerBlock.lastHost}`} />
                        <Kv k="Broadcast" v={customerBlock.broadcast} />
                        {customerPlan.gatewayReserved > 0 && (
                          <Kv k="Gateway sugerido (opcional)" v={customerBlock.firstHost} />
                        )}
                      </>
                    )}
                    <Kv k="IP utilizables solicitadas" v={formatInteger(customerPlan.requested)} mono={false} />
                    <Kv k="Gateway / router" v={formatInteger(customerPlan.gatewayReserved)} mono={false} />
                    <Kv k="Dirección de red" v={formatInteger(customerPlan.networkReserved)} mono={false} />
                    <Kv k="Dirección de broadcast" v={formatInteger(customerPlan.broadcastReserved)} mono={false} />
                    <Kv k="Libres dentro del bloque" v={formatInteger(customerPlan.spare)} mono={false} />
                    <Kv k="Capacidad utilizable de la subred" v={formatInteger(customerPlan.usableInSubnet)} mono={false} />
                  </div>
                  <div className="note" style={{ marginTop: 12 }}>
                    {t(customerPlan.gatewayReserved
                      ? 'Se requieren {total} direcciones ({block}) para cubrir {requested} IP utilizables, reservar 1 para el gateway y dejar {spare} libres en el bloque.'
                      : 'Se requieren {total} direcciones ({block}) para cubrir {requested} IP utilizables y dejar {spare} libres en el bloque.',
                    { total: formatInteger(customerPlan.total), block: customerPlan.block, requested: formatInteger(customerPlan.requested), spare: formatInteger(customerPlan.spare) })}
                  </div>
                </div>
              </>
            )}
      </div>

      {info && (
        <div style={{ display: tab === 'dividir' ? 'block' : 'none' }}>
            <div className="card">
              <div className="field-grid cols-2">
                <label>
                  {t('Dividir {prefix} en subredes de', { prefix: info.prefix })}
                  <select className="input" value={splitBits} onChange={(e) => setSplitBits(+e.target.value)}>
                    {Array.from({ length: (info.family === 'IPv4' ? 32 : 128) - info.prefixLen + 1 }, (_, i) => info.prefixLen + i)
                      .filter((b) => b - info.prefixLen <= 16)
                      .map((b) => <option key={b} value={b}>/{b}</option>)}
                  </select>
                </label>
                <label>
                  &nbsp;
                  <button className="btn" onClick={doSplit}>{t('Calcular división')}</button>
                </label>
              </div>
              {splitError && <div className="note" style={{ marginTop: 10 }}>{splitError}</div>}
            </div>

            {split && (
              <div className="card" style={{ marginTop: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                  <h3 style={{ margin: 0 }}>
                    {t('{count} subredes', { count: formatInteger(split.total) })}
                    {split.truncated && <span className="dim" style={{ fontWeight: 400, fontSize: 12 }}> · {t('mostrando las primeras {count}', { count: split.rows.length.toLocaleString(locale) })}</span>}
                  </h3>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <CopyButton label={t('Copiar CSV')} disabled={split.rows.length === 0} getText={() => subnetsToCSV(split.rows)} />
                    <button className="btn ghost" onClick={() => downloadText(`trazip-subredes-${Date.now()}.csv`, subnetsToCSV(split.rows), 'text/csv')}>⬇ {t('Descargar CSV')}</button>
                  </div>
                </div>
                <div className="mtr-table-wrap" style={{ marginTop: 10 }}>
                  <table className="mtr-table">
                    <thead>
                      <tr>
                        <th className="l">#</th>
                        <th className="l">{t('Prefijo')}</th>
                        <th className="l">{t('Red')}</th>
                        <th className="l">{t('Rango útil')}</th>
                        <th className="l">Broadcast</th>
                        <th>{t('Hosts')}</th>
                        <th className="l"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {split.rows.map((r) => (
                        <tr key={r.prefix}>
                          <td className="l dim">{r.index + 1}</td>
                          <td className="l mono">{r.prefix}</td>
                          <td className="l mono dim">{r.network}</td>
                          <td className="l mono" style={{ fontSize: 12 }}>{r.firstHost} – {r.lastHost}</td>
                          <td className="l mono dim">{r.broadcast || '—'}</td>
                          <td className="accent-t">{formatInteger(r.usableCount)}</td>
                          <td className="l">
                            <button className="tag" style={{ cursor: 'pointer' }} onClick={() => scanThis(r.prefix)}>{t('Escanear →')}</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
        </div>
      )}

      {info && (
        <div style={{ display: tab === 'vlsm' ? 'block' : 'none' }}>
            <div className="card">
              <h3>{t('Subredes requeridas dentro de {prefix}', { prefix: info.prefix })}</h3>
              <p className="dim" style={{ fontSize: 11.5, marginTop: 0, marginBottom: 10 }}>
                {t('Se asignan de mayor a menor, que es el único orden que evita fragmentar el espacio.')}
              </p>
              {reqs.map((r, i) => (
                <div className="field" key={i} style={{ marginTop: 8 }}>
                  <input
                    className="input"
                    placeholder={t('Nombre (ej. Ventas)')}
                    value={r.label}
                    onChange={(e) => setReqs((p) => p.map((x, j) => (j === i ? { ...x, label: e.target.value } : x)))}
                  />
                  <input
                    className="input"
                    type="number"
                    min={1}
                    style={{ maxWidth: 130 }}
                    placeholder={t('Hosts')}
                    value={r.hosts}
                    onChange={(e) => setReqs((p) => p.map((x, j) => (j === i ? { ...x, hosts: e.target.value } : x)))}
                  />
                  <button className="btn ghost" onClick={() => setReqs((p) => p.filter((_, j) => j !== i))} disabled={reqs.length <= 1}>🗑</button>
                </div>
              ))}
              <div style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
                <button className="btn ghost" onClick={() => setReqs((p) => [...p, { label: '', hosts: '' }])}>+ {t('Agregar subred')}</button>
                <button className="btn" onClick={doVLSM}>{t('Planificar')}</button>
              </div>
              {vlsmError && <div className="note" style={{ marginTop: 10 }}>{vlsmError}</div>}
            </div>

            {vlsm && (
              <div className="card" style={{ marginTop: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                  <h3 style={{ margin: 0 }}>{t('Plan · {percent}% del espacio asignado', { percent: vlsm.usedPct.toFixed(1) })}</h3>
                  <CopyButton
                    label={t('Copiar plan')}
                    getText={() => vlsm.allocations.map((a) => `${a.label}\t${a.prefix}\t${a.firstHost} - ${a.lastHost}\t${a.usableCount} hosts (pidió ${a.hostsAsked}, sobran ${a.waste})`).join('\n')}
                  />
                </div>
                <div className="mtr-table-wrap" style={{ marginTop: 10 }}>
                  <table className="mtr-table">
                    <thead>
                      <tr>
                        <th className="l">{t('Subred')}</th>
                        <th className="l">{t('Prefijo')}</th>
                        <th className="l">{t('Rango útil')}</th>
                        <th className="l">Broadcast</th>
                        <th>{t('Pedidos')}</th>
                        <th>{t('Útiles')}</th>
                        <th>{t('Sobran')}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vlsm.allocations.map((a) => (
                        <tr key={a.prefix}>
                          <td className="l">{a.label}</td>
                          <td className="l mono">{a.prefix}</td>
                          <td className="l mono" style={{ fontSize: 12 }}>{a.firstHost} – {a.lastHost}</td>
                          <td className="l mono dim">{a.broadcast || '—'}</td>
                          <td className="dim">{a.hostsAsked}</td>
                          <td className="accent-t">{a.usableCount}</td>
                          <td className={a.waste > a.usableCount / 2 ? 'warn' : 'dim'}>{a.waste}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {vlsm.allocations.some((a) => a.note) && (
                  <p className="dim" style={{ fontSize: 11.5, marginTop: 10 }}>
                    {vlsm.allocations.find((a) => a.note)?.note}
                  </p>
                )}
                {vlsm.remaining && vlsm.remaining.length > 0 && (
                  <div style={{ marginTop: 12 }}>
                    <span className="dim" style={{ fontSize: 12, fontWeight: 700 }}>{t('Espacio libre restante:')} </span>
                    {vlsm.remaining.map((p) => <span key={p} className="tag" style={{ marginRight: 4 }}>{p}</span>)}
                  </div>
                )}
              </div>
            )}
        </div>
      )}

      {info && (
        <div style={{ display: tab === 'agregar' ? 'block' : 'none' }}>
            <div className="grid cols-2">
              <div className="card">
                <h3>{t('Agregar prefijos (supernetting)')}</h3>
                <p className="dim" style={{ fontSize: 11.5, marginTop: 0, marginBottom: 8 }}>{t('Uno por línea. Fusiona hermanos adyacentes y descarta los contenidos en otro.')}</p>
                <textarea
                  className="input mono"
                  style={{ width: '100%', minHeight: 120, resize: 'vertical' }}
                  value={aggInput}
                  onChange={(e) => setAggInput(e.target.value)}
                />
                <button className="btn" style={{ marginTop: 10 }} onClick={doAggregate}>{t('Agregar')}</button>
                {agg && (
                  <div style={{ marginTop: 12 }}>
                    <span className="dim" style={{ fontSize: 12, fontWeight: 700 }}>{t('Resultado ({count}):', { count: agg.length })}</span>
                    <div className="list-reset" style={{ marginTop: 6 }}>
                      {agg.map((p) => (
                        <div className="kv" key={p}>
                          <span className="k mono">{p}</span>
                          <span className="v">
                            <button className="tag" style={{ cursor: 'pointer' }} onClick={() => setInput(p)}>{t('Analizar')}</button>
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div className="card">
                <h3>{t('¿Esta IP está dentro de la red?')}</h3>
                <p className="dim" style={{ fontSize: 11.5, marginTop: 0, marginBottom: 8 }}>{t('Comprueba contra {prefix}, la red del campo de arriba.', { prefix: info.prefix })}</p>
                <div className="field">
                  <input className="input mono" value={containsAddr} onChange={(e) => setContainsAddr(e.target.value)} placeholder="192.168.10.90" />
                  <button className="btn" onClick={doContains}>{t('Comprobar')}</button>
                </div>
                {contains !== null && (
                  <p style={{ marginTop: 12 }}>
                    <span className={'pill ' + (contains ? 'ok' : 'warn')}>
                      <span className="dot" />
                      {contains ? t('{address} está dentro de {prefix}', { address: containsAddr, prefix: info.prefix }) : t('{address} está fuera de {prefix}', { address: containsAddr, prefix: info.prefix })}
                    </span>
                  </p>
                )}
              </div>
            </div>
            {aggError && <div className="note">{aggError}</div>}
        </div>
      )}
    </div>
  );
}
