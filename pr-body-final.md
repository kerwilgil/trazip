Turns the V1.5-2 OSINT foundation into a real surface. UI + read-only metadata only — no external providers, no execution API, no outbound calls, no Entity Graph, no active scanner.

**Backend**
  * api.OSINTProviderInfo DTO + Service.ListOSINTProviders(): serializes osint.Registry.AllMetas() (metadata copies only), sorted by ID, always a non-nil slice. Service owns an empty osint.NewRegistry().
  * osint_test.go: empty registry -> []; faithful metadata / class / scope / rate-limit passthrough; deterministic ordering; JSON key set pinned to metadata-only; invalid metadata never registers or surfaces.

**Frontend**
  * nav: new 'osint' ViewId in the Inteligencia group + icon + module description; App routes it to views/OsintIntelligence.tsx.
  * lib/osint.ts: pure view-model — provider normalization, capability coherence (a source offers only its declared capabilities), requiresAuthorizedScope (active is a hard floor), activity/disclosure descriptors, and the prepared RESULT_STATES / OSINT_ERROR_KINDS / PROVENANCE_FIELDS sets. osint.test.ts covers all of it plus the nav entry.
  * OsintIntelligence.tsx: header, query workspace (laid out, execute button permanently disabled — no false execution), registered-sources list with loading/error/empty/populated states, and prepared results / provenance / error-reference areas. Meaning carried by text and aria-label, not color alone.
  * i18n: full ES + EN for every new string.

**Semantic remediation (P1/P2 from independent audit):**
  * P1-01: Passive activity descriptor fixed — "Sin interacción activa directa con el objetivo" / "No direct active interaction with the target" (was incorrectly claiming external-only).
  * P1-01 test: Added test confirming passive descriptor does NOT claim external lookup; passive+local+no-scope combination validated.
  * P2-01: Raw technical error removed from normal UI — only localized "No se pudo cargar la metadata de fuentes OSINT." shown.
  * P2-02: docs/OSINT_UI.md honest about narrow viewport — QA executed on desktop; narrow viewport pending in V1.5-3.
  * docs/OSINT_FOUNDATION.md: "Purely external lookups" definition corrected to align with ProviderMeta.Validate.

**Tests**
  * frontend tests: 49 PASS
  * OSINT: PASS
  * API: PASS
  * full Go: PASS
  * vet: PASS
  * build: PASS
  * govulncheck: PASS (0 vulnerabilities)
  * gitleaks: PASS
  * diff-check: PASS

**CI final run:** 34492367791
**7/7 required checks: SUCCESS**

Security is enforced by the Go Executor + ScopeGuard, never by this view.
docs/OSINT_UI.md documents exactly what shipped.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_019AgexFECZTKNqpRjrJPeNJ