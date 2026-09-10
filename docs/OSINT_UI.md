# TRAZIP OSINT Intelligence UI (V1.5-3)

## Purpose

V1.5-3 turns the [OSINT Intelligence Foundation](OSINT_FOUNDATION.md) (V1.5-2)
into a real surface inside TRAZIP. It is **UI + read-only metadata only**.

It provides:

- An **OSINT Intelligence** entry in the primary navigation.
- A workspace view (`frontend/src/views/OsintIntelligence.tsx`) that lists the
  providers registered in the backend OSINT Registry with their real metadata.
- A read-only backend bridge (`Service.ListOSINTProviders`) that serializes
  `osint.ProviderMeta` into a small DTO.
- Laid-out (not executed) areas for the query, results and provenance, plus a
  reference list of the typed errors the interface will present once execution
  exists.
- Full ES/EN strings and Light/Dark/System theming, reusing existing components
  and tokens.

It deliberately does **NOT** include:

- Any real external provider (crt.sh, NVD/CVE, PeeringDB, Shodan, Censys,
  VirusTotal, SecurityTrails, AbuseIPDB, GreyNoise, OTX, TeleGeography, …).
- Any new outbound HTTP, API key or secret.
- Any execution API (`ExecuteOSINT` / `RunOSINT` / `Probe` / `Scan` / …).
- Entity Graph / node-edge canvas / force-directed graph.
- Active scanners or submarine-cable inference.
- Dynamic scope revocation (still not implemented — see OSINT_FOUNDATION.md).

The empty Registry is the **expected** state in V1.5-3 and is shown as a plain
empty state, never as an error.

---

## Navigation

`frontend/src/lib/nav.ts` adds one `ViewId`, `'osint'`, in the **Inteligencia**
group (`label: 'Inteligencia OSINT'`, `phase: 9`). It reuses the existing
sidebar button, active state, keyboard handling and tooltip
(`MODULE_INFO.osint`), and a dedicated 24×24 `currentColor` icon in
`components/icons.tsx`. `App.tsx` routes `'osint'` to `<OsintIntelligence />`.

---

## Backend bridge

`Service.ListOSINTProviders() []OSINTProviderInfo` (`internal/api/service.go`)
is the only OSINT call in V1.5-3.

- Reads `s.osintRegistry` (an `osint.NewRegistry()` owned by the Service).
- Iterates `Registry.AllMetas()` (metadata copies only — the registry never
  hands out a runnable provider) and maps each to `OSINTProviderInfo`.
- `ActivityClass` / `DisclosureClass` are the string forms of the domain enums
  (`"passive"`/`"active"`, `"local"`/`"passive"`/`"active"`).
- Output is sorted by `ID` for a deterministic UI (`AllMetas` iterates a map).
- Always returns a non-nil slice; an empty Registry serializes as `[]`.

`OSINTProviderInfo` (`internal/api/dto.go`) carries exactly: `id`, `name`,
`capabilities` (`[]string`), `activityClass`, `disclosureClass`,
`requiresScope`, `rateLimit`. There is no field that exposes a provider object,
a Go interface, or anything secret-shaped; `internal/api/osint_test.go` pins
that key set.

The frontend wrapper `listOsintProviders()` (`frontend/src/lib/api.ts`) returns
`[]` when the Wails runtime is absent (browser preview), which renders the same
real empty state.

---

## View model

All display logic lives in `frontend/src/lib/osint.ts` (pure, unit-tested in
`osint.test.ts`), so the React view stays thin:

- `normalizeProvider` / `normalizeProviders` — guard a null capabilities array,
  map an unknown class string to `'unknown'`, fall back to `id` for a missing
  name, sort providers by name then id.
- `providerCapabilities` — de-duplicated, sorted capability list.
- `requiresAuthorizedScope(p)` — `p.requiresScope || p.activityClass === 'active'`
  (active is a hard floor).
- `capabilityOptionsFor(providerId, providers)` — **coherence rule**: a provider
  selector offers exactly that provider's declared capabilities, nothing
  inferred; unknown id → `[]`.
- `ACTIVITY_DESCRIPTORS` / `DISCLOSURE_DESCRIPTORS` — label + summary + existing
  `.tag` modifier for each class. Meaning is carried by text and `aria-label`,
  never by color alone.
- `RESULT_STATES` — the nine outcomes the Results area is *prepared* for
  (`idle`, `loading`, `success`, `empty`, `error`, `canceled`, `rate_limited`,
  `unavailable`, `scope_denied`). Not produced at runtime in V1.5-3.
- `OSINT_ERROR_KINDS` — one entry per typed error in
  `internal/osint/errors.go`, presentation only.
- `PROVENANCE_FIELDS` — the provenance fields the UI will render for a
  successful result, in display order. Endpoint is shown sanitized; tokens and
  credentials are never displayed.

---

## Workspace layout

`OsintIntelligence.tsx`, top to bottom:

1. **Header** — title + a short description stating that there are no external
   providers and no execution, and that security is enforced by the backend
   Executor + ScopeGuard, not the UI.
2. **Query** — target/query input, source `<select>` (from metadata), capability
   `<select>` (coherent with the chosen source). The "Ejecutar consulta" button
   is permanently `disabled` / `aria-disabled` with an explanatory note — there
   is **no false execution**.
3. **Fuentes registradas** — `loading` / `error` / empty / populated states.
   Each provider is a card with name, id, activity + disclosure tags (with
   `aria-label`), an explicit "Requiere alcance autorizado" tag for providers
   that need scope, and a key/value list of capabilities, activity, disclosure,
   requires-scope and rate limit.
4. **Resultados** — a prepared panel listing the nine states; no simulated
   result.
5. **Procedencia** — a prepared panel listing the provenance schema.
6. **Errores contemplados** — the typed-error reference list.

---

## i18n / theme / accessibility

- Every visible string is a Spanish source string passed through `t()`, with an
  English entry in `EN` (`frontend/src/lib/i18n.tsx`). Spanish is the source
  locale.
- Theming is inherited: the view uses existing CSS custom properties and
  component classes (`card`, `tag`, `note`, `empty`, `kv`, `field-grid`,
  `grid cols-2`, `dim`), so Light / Dark / System all work with no view-specific
  rules.
- Each `<section>` has an `aria-labelledby` heading; the loading line is
  `role="status" aria-live="polite"`; the metadata error is `role="alert"`;
  activity/disclosure tags carry `aria-label` so the meaning does not depend on
  color. Layout uses `content-inner` and wrapping grids, reusing the existing
  responsive primitives. Visual QA was executed on desktop; narrow viewport
  remains pending in V1.5-3.

---

## Tests

- `internal/api/osint_test.go` — empty registry → `[]` (not `null`); metadata
  serialized faithfully (capabilities, activity, disclosure, requires-scope,
  rate limit); deterministic ordering by id; JSON key set is metadata-only; a
  provider with invalid metadata never registers and never surfaces.
- `frontend/src/lib/osint.test.ts` — the `'osint'` nav entry and its module
  description; `normalizeProvider` guards; capability de-dup/sort; deterministic
  provider ordering; `requiresAuthorizedScope` (active always true); the
  provider/capability coherence rule; completeness of the activity/disclosure
  descriptors, `RESULT_STATES`, `OSINT_ERROR_KINDS` and `PROVENANCE_FIELDS`
  (and that no provenance field is secret-shaped).

Component render tests are not part of this change: the repo's frontend test
harness is logic-only (`vitest`, node environment, no jsdom / testing-library),
matching the existing `nav` / `tabs` / `topologyGraph` tests.
