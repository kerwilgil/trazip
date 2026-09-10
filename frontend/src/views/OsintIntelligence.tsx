import { useEffect, useMemo, useState } from 'react';
import { listOsintProviders } from '../lib/api';
import { useI18n } from '../lib/i18n';
import {
  ACTIVITY_DESCRIPTORS,
  DISCLOSURE_DESCRIPTORS,
  OSINT_ERROR_KINDS,
  PROVENANCE_FIELDS,
  RESULT_STATES,
  capabilityOptionsFor,
  normalizeProviders,
  requiresAuthorizedScope,
  type MetadataState,
  type OsintProvider,
} from '../lib/osint';

// OSINT Intelligence workspace (V1.5-3).
//
// This surface exposes the V1.5-2 OSINT foundation: it lists the providers in
// the backend Registry with their real metadata, and lays out — but does not
// run — the query, results and provenance areas. There are no real external
// providers and no execution API yet; the empty Registry is the expected
// state. Passive/active separation, capability gating and scope authorization
// are enforced by the Go Executor + ScopeGuard, never by this view.
export default function OsintIntelligence() {
  const { t } = useI18n();
  const [state, setState] = useState<MetadataState>('idle');
  const [providers, setProviders] = useState<OsintProvider[]>([]);
  const [target, setTarget] = useState('');
  const [providerId, setProviderId] = useState('');
  const [capability, setCapability] = useState('');

  useEffect(() => {
    let alive = true;
    setState('loading');
    listOsintProviders()
      .then((raw) => {
        if (!alive) return;
        setProviders(normalizeProviders(raw));
        setState('ready');
      })
      .catch((e) => {
        if (!alive) return;
        setState('error');
      });
    return () => {
      alive = false;
    };
  }, []);

  const capabilityOptions = useMemo(
    () => capabilityOptionsFor(providerId, providers),
    [providerId, providers],
  );

  // Keep the capability selection coherent with the chosen provider: a
  // provider only ever offers the capabilities its own metadata declares.
  useEffect(() => {
    if (capability && !capabilityOptions.includes(capability)) setCapability('');
  }, [capability, capabilityOptions]);

  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t('Inteligencia OSINT')}</h2>
        <p className="body-text">
          {t(
            'Fundación de inteligencia OSINT: los proveedores registrados en el backend y su metadata real. Esta versión no integra proveedores externos ni ejecuta consultas — el registro vacío es el estado esperado. La separación pasivo/activo, el control de capacidades y la autorización de alcance los aplica el backend (Executor y ScopeGuard), no esta pantalla.',
          )}
        </p>
      </div>

      {/* ---- Query workspace (laid out, not executable in this version) ---- */}
      <section className="card" aria-labelledby="osint-query-h">
        <h3 id="osint-query-h">{t('Consulta')}</h3>
        <div className="field-grid cols-2" style={{ marginTop: 4 }}>
          <label>
            {t('Objetivo / consulta')}
            <input
              className="input mono"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={t('IP, dominio, ASN, CVE…')}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <label>
            {t('Fuente')}
            <select
              value={providerId}
              onChange={(e) => {
                setProviderId(e.target.value);
                setCapability('');
              }}
              disabled={providers.length === 0}
            >
              <option value="">
                {providers.length === 0 ? t('Sin fuentes disponibles') : t('Selecciona una fuente')}
              </option>
              {providers.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            {t('Capacidad')}
            <select
              value={capability}
              onChange={(e) => setCapability(e.target.value)}
              disabled={capabilityOptions.length === 0}
            >
              <option value="">
                {capabilityOptions.length === 0
                  ? t('Elige primero una fuente')
                  : t('Selecciona una capacidad')}
              </option>
              {capabilityOptions.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </label>
          <label>
            {' '}
            <button className="btn" type="button" disabled aria-disabled="true">
              {t('Ejecutar consulta')}
            </button>
          </label>
        </div>
        <p className="note" style={{ marginTop: 12 }}>
          {t(
            'La ejecución de proveedores OSINT llega en una fase posterior. Aquí solo se muestra la metadata registrada.',
          )}
        </p>
      </section>

      {/* ---- Registered providers (real metadata) ---- */}
      <section className="card" aria-labelledby="osint-sources-h" style={{ marginTop: 16 }}>
        <h3 id="osint-sources-h">{t('Fuentes registradas')}</h3>

        {state === 'loading' && (
          <p className="dim" role="status" aria-live="polite" style={{ marginTop: 8 }}>
            {t('Cargando metadata de fuentes OSINT…')}
          </p>
        )}

        {state === 'error' && (
          <div className="note" role="alert" style={{ marginTop: 8 }}>
            {t('No se pudo cargar la metadata de fuentes OSINT.')}
          </div>
        )}

        {state === 'ready' && providers.length === 0 && (
          <div className="empty" style={{ marginTop: 8 }}>
            <div className="big" aria-hidden="true">
              ∅
            </div>
            <p>{t('No hay fuentes OSINT registradas todavía.')}</p>
          </div>
        )}

        {state === 'ready' && providers.length > 0 && (
          <div className="grid cols-2" style={{ marginTop: 12 }}>
            {providers.map((p) => (
              <ProviderCard key={p.id} provider={p} />
            ))}
          </div>
        )}
      </section>

      {/* ---- Results area (prepared, not executed) ---- */}
      <section className="card" aria-labelledby="osint-results-h" style={{ marginTop: 16 }}>
        <h3 id="osint-results-h">{t('Resultados')}</h3>
        <p className="dim" style={{ marginTop: 4 }}>
          {t(
            'Área preparada para presentar el resultado de una consulta y sus estados. No se simula ningún resultado en esta versión.',
          )}
        </p>
        <div className="list-reset" style={{ marginTop: 10 }}>
          {RESULT_STATES.map((s) => (
            <div className="kv" key={s}>
              <span className="k">{t(resultStateLabel(s))}</span>
              <span className="v" style={{ fontFamily: 'inherit', color: 'var(--text-faint)' }}>
                {t('preparado')}
              </span>
            </div>
          ))}
        </div>
      </section>

      {/* ---- Provenance area (prepared) ---- */}
      <section className="card" aria-labelledby="osint-prov-h" style={{ marginTop: 16 }}>
        <h3 id="osint-prov-h">{t('Procedencia')}</h3>
        <p className="dim" style={{ marginTop: 4 }}>
          {t(
            'Cada resultado exitoso llevará su procedencia. El endpoint se mostrará saneado y nunca se muestran tokens ni credenciales.',
          )}
        </p>
        <div className="list-reset" style={{ marginTop: 10 }}>
          {PROVENANCE_FIELDS.map((f) => (
            <div className="kv" key={f.id}>
              <span className="k">{t(f.labelKey)}</span>
              <span className="v" style={{ fontFamily: 'inherit', color: 'var(--text-faint)' }}>
                {t('preparado')}
              </span>
            </div>
          ))}
        </div>
      </section>

      {/* ---- Error presentation reference (prepared) ---- */}
      <section className="card" aria-labelledby="osint-errors-h" style={{ marginTop: 16 }}>
        <h3 id="osint-errors-h">{t('Errores contemplados')}</h3>
        <p className="dim" style={{ marginTop: 4 }}>
          {t(
            'Estados de error que la interfaz mostrará de forma legible cuando exista ejecución. No se provocan en esta versión.',
          )}
        </p>
        <div className="list-reset" style={{ marginTop: 10 }}>
          {OSINT_ERROR_KINDS.map((k) => (
            <div className="kv" key={k.id}>
              <span className="k">{t(k.titleKey)}</span>
              <span className="v" style={{ fontFamily: 'inherit', color: 'var(--text-dim)' }}>
                {t(k.bodyKey)}
              </span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function ProviderCard({ provider }: { provider: OsintProvider }) {
  const { t } = useI18n();
  const act = ACTIVITY_DESCRIPTORS[provider.activityClass];
  const disc = DISCLOSURE_DESCRIPTORS[provider.disclosureClass];
  const needsScope = requiresAuthorizedScope(provider);

  return (
    <div className="card" style={{ background: 'var(--surface-2)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 10, flexWrap: 'wrap' }}>
        <strong style={{ fontSize: 14 }}>{provider.name}</strong>
        <span className="mono dim" style={{ fontSize: 11.5 }}>
          {provider.id}
        </span>
      </div>

      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10 }}>
        <span className={`tag ${act.tagClass}`} title={t(act.summaryKey)} aria-label={`${t('Actividad')}: ${t(act.labelKey)} — ${t(act.summaryKey)}`}>
          {t(act.labelKey)}
        </span>
        <span className={`tag ${disc.tagClass}`} title={t(disc.summaryKey)} aria-label={`${t('Divulgación')}: ${t(disc.labelKey)} — ${t(disc.summaryKey)}`}>
          {t(disc.labelKey)}
        </span>
        {needsScope && (
          <span className="tag warn" aria-label={t('Requiere alcance autorizado')}>
            {t('Requiere alcance autorizado')}
          </span>
        )}
      </div>

      <div className="list-reset" style={{ marginTop: 12 }}>
        <div className="kv">
          <span className="k">{t('Capacidades')}</span>
          <span className="v mono" style={{ overflowWrap: 'anywhere' }}>
            {provider.capabilities.length > 0 ? provider.capabilities.join(', ') : '—'}
          </span>
        </div>
        <div className="kv">
          <span className="k">{t('Actividad')}</span>
          <span className="v" style={{ fontFamily: 'inherit' }}>
            {t(act.labelKey)} · {t(act.summaryKey)}
          </span>
        </div>
        <div className="kv">
          <span className="k">{t('Divulgación')}</span>
          <span className="v" style={{ fontFamily: 'inherit' }}>
            {t(disc.labelKey)} · {t(disc.summaryKey)}
          </span>
        </div>
        <div className="kv">
          <span className="k">{t('Requiere alcance')}</span>
          <span className="v" style={{ fontFamily: 'inherit' }}>
            {needsScope ? t('Sí') : t('No')}
          </span>
        </div>
        {provider.rateLimit && (
          <div className="kv">
            <span className="k">{t('Límite de frecuencia')}</span>
            <span className="v" style={{ fontFamily: 'inherit' }}>
              {provider.rateLimit}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

function resultStateLabel(s: (typeof RESULT_STATES)[number]): string {
  switch (s) {
    case 'idle':
      return 'En espera';
    case 'loading':
      return 'Cargando';
    case 'success':
      return 'Correcto';
    case 'empty':
      return 'Sin datos';
    case 'error':
      return 'Error';
    case 'canceled':
      return 'Cancelado';
    case 'rate_limited':
      return 'Límite de frecuencia';
    case 'unavailable':
      return 'No disponible';
    case 'scope_denied':
      return 'Fuera de alcance';
  }
}
