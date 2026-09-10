// OSINT Intelligence — pure view-model logic (V1.5-3).
//
// The React view (views/OsintIntelligence.tsx) is deliberately thin: every
// rule that decides *what* to show lives here so it can be unit-tested the
// same way nav.ts / tabs.ts / topologyGraph.ts are. This module holds NO
// runtime data — no providers, no results, no intelligence. It only shapes
// the read-only metadata that Service.ListOSINTProviders returns and the
// fixed descriptors the UI renders around it.
//
// Security note: the UI is not the barrier. Passive/active separation,
// capability gating, scope authorization and provenance validation are all
// enforced by the Go Executor + ScopeGuard (internal/osint). What follows is
// presentation only.

import type { OsintProviderInfo } from './api';

export type OsintActivity = 'passive' | 'active' | 'unknown';
export type OsintDisclosure = 'local' | 'passive' | 'active' | 'unknown';

/** One OSINT provider as shown in the UI — a normalized OsintProviderInfo. */
export interface OsintProvider {
  id: string;
  name: string;
  capabilities: string[];
  activityClass: OsintActivity;
  disclosureClass: OsintDisclosure;
  requiresScope: boolean;
  rateLimit: string;
}

/** Fetch state for the provider-metadata bridge. Only these are reachable at
 *  runtime in V1.5-3 — there is no provider execution yet. */
export type MetadataState = 'idle' | 'loading' | 'ready' | 'error';

// ---- Activity / disclosure descriptors -------------------------------------
// labelKey / summaryKey are Spanish source strings passed through i18n's t()
// in the component (see lib/i18n.tsx — Spanish is the source locale).

export interface ClassDescriptor {
  labelKey: string;
  summaryKey: string;
  /** Existing .tag modifier from style.css — never the only signal (text +
   *  aria-label carry the meaning too). */
  tagClass: string;
}

export const ACTIVITY_DESCRIPTORS: Record<OsintActivity, ClassDescriptor> = {
  passive: {
    labelKey: 'Pasivo',
    summaryKey: 'Sin interacción activa directa con el objetivo.',
    tagClass: 'info',
  },
  active: {
    labelKey: 'Activo',
    summaryKey: 'Envía sondas directamente a la infraestructura del objetivo.',
    tagClass: 'warn',
  },
  unknown: {
    labelKey: 'Sin clasificar',
    summaryKey: 'El proveedor no declaró una clase de actividad válida.',
    tagClass: 'error',
  },
};

export const DISCLOSURE_DESCRIPTORS: Record<OsintDisclosure, ClassDescriptor> = {
  local: {
    labelKey: 'Local',
    summaryKey: 'Nada sale del equipo (cálculo puramente local).',
    tagClass: 'ok',
  },
  passive: {
    labelKey: 'Consulta externa',
    summaryKey: 'Consulta pasiva a un tercero (DNS, HTTP a un servicio externo).',
    tagClass: 'info',
  },
  active: {
    labelKey: 'Interacción activa',
    summaryKey: 'Interacción activa de red con la infraestructura del objetivo.',
    tagClass: 'warn',
  },
  unknown: {
    labelKey: 'Sin clasificar',
    summaryKey: 'El proveedor no declaró una clase de divulgación válida.',
    tagClass: 'error',
  },
};

function asActivity(raw: string): OsintActivity {
  return raw === 'passive' || raw === 'active' ? raw : 'unknown';
}

function asDisclosure(raw: string): OsintDisclosure {
  return raw === 'local' || raw === 'passive' || raw === 'active' ? raw : 'unknown';
}

/** Sorted, de-duplicated capability list. A provider offers exactly the
 *  capabilities in its own metadata — never more (coherence rule §9). */
export function providerCapabilities(caps: readonly string[] | null | undefined): string[] {
  return Array.from(new Set((caps ?? []).filter((c) => typeof c === 'string' && c.length > 0))).sort();
}

/** Normalizes one raw OsintProviderInfo from the backend into an OsintProvider,
 *  guarding against a null array, an unknown class string or a missing field. */
export function normalizeProvider(raw: OsintProviderInfo): OsintProvider {
  return {
    id: raw.id ?? '',
    name: raw.name || raw.id || '',
    capabilities: providerCapabilities(raw.capabilities),
    activityClass: asActivity(raw.activityClass),
    disclosureClass: asDisclosure(raw.disclosureClass),
    requiresScope: Boolean(raw.requiresScope),
    rateLimit: raw.rateLimit ?? '',
  };
}

/** Deterministic display order: by name (locale-aware), then id as tiebreak.
 *  The backend already sorts by id; this keeps the UI stable if that changes. */
export function sortProviders(list: OsintProvider[]): OsintProvider[] {
  return [...list].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
}

export function normalizeProviders(raw: OsintProviderInfo[] | null | undefined): OsintProvider[] {
  return sortProviders((raw ?? []).map(normalizeProvider));
}

/** Whether an authorized scope is required before this provider could ever run.
 *  Active providers always require it; a passive provider must not. The flag is
 *  authoritative but active class is a hard floor. */
export function requiresAuthorizedScope(p: OsintProvider): boolean {
  return p.requiresScope || p.activityClass === 'active';
}

/** The capabilities a provider selector may offer for `providerId` — exactly
 *  that provider's declared set, nothing inferred. Unknown id → []. */
export function capabilityOptionsFor(providerId: string, providers: OsintProvider[]): string[] {
  const match = providers.find((p) => p.id === providerId);
  return match ? match.capabilities : [];
}

// ---- Results area (prepared, not executed in V1.5-3) ----------------------
// The workspace shows a Results panel that is *ready* for these outcomes, but
// V1.5-3 performs no provider execution, so none of these are produced at
// runtime. Listed here so the panel and the docs stay in sync, and so a test
// pins the set.

export type OsintResultState =
  | 'idle'
  | 'loading'
  | 'success'
  | 'empty'
  | 'error'
  | 'canceled'
  | 'rate_limited'
  | 'unavailable'
  | 'scope_denied';

export const RESULT_STATES: readonly OsintResultState[] = [
  'idle',
  'loading',
  'success',
  'empty',
  'error',
  'canceled',
  'rate_limited',
  'unavailable',
  'scope_denied',
] as const;

// ---- Error presentation --------------------------------------------------
// One entry per typed error the Go layer can raise (internal/osint/errors.go).
// Presentation only: V1.5-3 never triggers these at runtime. `id` mirrors the
// Go predicate/sentinel so a future execution phase can map errors 1:1.

export interface OsintErrorKind {
  id: string;
  titleKey: string;
  bodyKey: string;
}

export const OSINT_ERROR_KINDS: readonly OsintErrorKind[] = [
  { id: 'invalid_config', titleKey: 'Configuración inválida', bodyKey: 'La solicitud u origen no está bien formado.' },
  { id: 'unsupported_capability', titleKey: 'Capacidad no soportada', bodyKey: 'El proveedor no declara la capacidad solicitada.' },
  { id: 'scope_denied', titleKey: 'Fuera de alcance', bodyKey: 'No hay alcance autorizado o el objetivo queda fuera de él.' },
  { id: 'rate_limited', titleKey: 'Límite de frecuencia', bodyKey: 'Se alcanzó el límite de peticiones del proveedor.' },
  { id: 'provider_unavailable', titleKey: 'Proveedor no disponible', bodyKey: 'El proveedor no puede atender la consulta ahora mismo.' },
  { id: 'external_lookup_failed', titleKey: 'Fallo en consulta externa', bodyKey: 'La consulta al servicio externo no se completó.' },
  { id: 'canceled', titleKey: 'Cancelado', bodyKey: 'La operación se canceló antes de terminar.' },
  { id: 'deadline_exceeded', titleKey: 'Tiempo agotado', bodyKey: 'La operación superó el tiempo máximo permitido.' },
  { id: 'provider_not_found', titleKey: 'Proveedor no encontrado', bodyKey: 'No hay ningún proveedor registrado con ese identificador.' },
  { id: 'activity_violation', titleKey: 'Violación de clase de actividad', bodyKey: 'Un proveedor pasivo entró en un flujo activo, o al revés.' },
  { id: 'invalid_provenance', titleKey: 'Procedencia inválida', bodyKey: 'El resultado no trae una procedencia coherente; se descarta el dato.' },
] as const;

// ---- Provenance area (prepared) -----------------------------------------
// Fields of osint.Provenance the UI is ready to render for a successful
// result. Order is the display order. Endpoint is shown sanitized; secrets /
// tokens are never displayed.

export interface ProvenanceField {
  id: string;
  labelKey: string;
}

export const PROVENANCE_FIELDS: readonly ProvenanceField[] = [
  { id: 'source', labelKey: 'Fuente' },
  { id: 'provider', labelKey: 'Proveedor' },
  { id: 'capability', labelKey: 'Capacidad' },
  { id: 'activity', labelKey: 'Actividad' },
  { id: 'disclosure', labelKey: 'Divulgación' },
  { id: 'retrievedAt', labelKey: 'Momento de obtención' },
  { id: 'endpoint', labelKey: 'Endpoint (saneado)' },
  { id: 'confidence', labelKey: 'Confianza' },
] as const;
