# TRAZIP v1.4.0

## Trust Rotation (Breaking Change for Auto-Update)

Due to loss of the original v1.3.2 Ed25519 signing private key after a
system reinstallation, TRAZIP v1.4.0 introduces a new update signing identity.

**Impact:**
- Automatic signed updates from v1.3.2 -> v1.4.0 are NOT possible.
- Users on v1.3.2 or earlier must install v1.4.0 manually once.
- From v1.4.0 onward, automatic signed updates resume normally.

**Technical Details:**
- OLD signing key (v1.3.2 and earlier): ec8c7353f673a9d0b5a43e91a0c062f9444e6416b09cb51d1220805be6aedd16
- NEW signing key (v1.4.0 and later): a94f501667c8de95e7c056a1d6493f61cf10d6849e155f32837fcf543a9cc149
- The original private key was lost during a system reinstallation and could
  not be recovered from DPAPI backups (machine context changed).
- The update repository (kerwilgil/trazip-releases) remains the same.
- Legacy v1.3.2 installations cannot auto-update to v1.4.0 (key change).
  Manual installation required once. From v1.4.0 onward, auto-updates resume normally.

## BGP Intelligence Finalization

- Complete BGP Intelligence v1.4 finalization with all tabs:
  Resumen, Prefijos, Vecinos, Topología, Seguridad, Tiempo real, Histórico, BGPlay, Observatorio.
- Topology: stable pan/zoom/click-drag, export SVG/PNG, 100 nodes / 250 edges caps.
- Realtime: strict stale-session isolation, no orphan polls, capped timeline.
- History/BGPlay: closed datetime ranges, truncation notices, no epoch fabrication.
- Observatory: Country, Global/RIS, ASN, RPKI, Bogons — tri-state preserved, no fabricated data.
- BGP semantics preserved: no commercial inference, no HIJACK auto-label, MOAS=Attention not Risk, RPKI prefix-scoped.

## UI/UX Refinements

- ARIA tablist/tab/aria-selected semantics on all tab groups.
- Focus-visible styles, keyboard navigation (ArrowLeft/Right, Home/End) on all tab groups.
- Error handling: friendly primary message + technical details, role="alert" for errors.
- Overflow protection: .stat .sub overflow-wrap, tables with horizontal scroll.
- Reduced-motion support for animations.

## i18n Completion

- All BGP Intelligence strings now have English translations in i18n.tsx.
- No hardcoded Spanish strings remain in user-visible BGP UI.

## Accessibility

- Tabs: role="tablist"/"tab"/"tabpanel", aria-selected, aria-controls, aria-labelledby.
- Keyboard navigation: Tab/Arrow/Enter/Space across all interactive elements.
- Focus-visible global styles, reduced-motion support.

## Tests

- Frontend unit tests: 30 tests (realtime session logic, topology helpers, tabs navigation).
- Backend tests: all existing tests PASS including new trust_rotation_test.go.

## BGP Intelligence Physical Validation

- 1366x768: PASS
- 1920x1080: PASS
- Keyboard navigation: PASS
- Focus management: PASS
- Overflow: PASS
- Topology pan/zoom/click-drag: PASS
- Realtime stale-session isolation: PASS
- Result persistence across tabs: PASS
- Manual migration v1.3.2 -> v1.4.0: required; final release validation pending

## Signing Identity

- New Ed25519 signing identity generated and validated:
  - Public key: a94f501667c8de95e7c056a1d6493f61cf10d6849e155f32837fcf543a9cc149
  - Private key: generated, backed up (Google Drive + independent remote), restore-tested
  - Sign/Verify/Tamper tests: ALL PASS
  - Private key never in repo, logs, or reports

## Migration Note

**v1.3.2 -> v1.4.0 requires a one-time manual installation** because the update
signing key changed (the original v1.3.2 private key was lost).

- From v1.4.0 onward, automatic signed updates resume normally.
- The update repository (kerwilgil/trazip-releases) is unchanged.
- Final validation of the v1.3.2 -> v1.4.0 manual migration is still pending (post-release).