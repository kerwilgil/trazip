# TRAZIP Update Channel Migration

## v1.4 Current Behavior

**Repository:** `kerwilgil/trazip-releases`

**Manifest:** `update.json` + `update.json.sig`

**Channel:** `stable`

**Trust:** Ed25519 public verification key embedded in v1.4+

**Asset integrity:** SHA-256

**notesUrl accepted ONLY under:**

```
https://github.com/kerwilgil/trazip-releases/
```

## v1.5+ Channel

**Repository:** `kerwilgil/trazip`

**Channel:** `stable`

**Same trust root:** Same Ed25519 public key as v1.4+

**notesUrl accepted under:**

```
https://github.com/kerwilgil/trazip-releases/
and
https://github.com/kerwilgil/trazip/
```

## Bridge Model

```
v1.4
    ↓
consults trazip-releases/releases/latest
    ↓
finds a v1.5 release with a manifest compatible with the v1.4 parser
    ↓
update.json
    channel = "stable"
    ↓
update.json.sig
    signed with the v1.4+ trust root
    ↓
TRAZIP-1.5.0.exe
trazip-updater.exe
    ↓
signature PASS
checksum PASS
download PASS
install PASS
    ↓
TRAZIP v1.5 starts
    ↓
v1.5 queries the NEW official channel
kerwilgil/trazip
```

**The bridge is:** v1.4 continues to query `trazip-releases/releases/latest`, finds a v1.5 release with a manifest that uses `channel: "stable"` (which v1.4 accepts), verifies the Ed25519 signature and SHA-256 checksums, downloads the binaries, installs them, and restarts. v1.5 then uses the new channel (`kerwilgil/trazip`).

**The bridge does NOT use `migration.json`** — the v1.4 binary does not know about that format.

## Bridge Manifest Compatibility

The bridge release published in `trazip-releases` must use a manifest that v1.4 can parse:

- `channel: "stable"` (v1.4 only accepts "stable")
- `notesUrl` under `trazip-releases` (compatible with v1.4 validator)
- Same asset naming: `TRAZIP-<version>.exe` + `trazip-updater.exe`
- Same Ed25519 signature verification
- Same SHA-256 checksum verification

The v1.5 bridge release published in `trazip-releases` must contain an `update.json` that passes v1.4's validation:

```json
{
  "version": "1.5.0",
  "channel": "stable",
  "publishedAt": "2026-09-07T12:00:00Z",
  "notesUrl": "https://github.com/kerwilgil/trazip-releases/releases/tag/v1.5.0",
  "windows": {
    "amd64": {
      "app": {
        "asset": "TRAZIP-1.5.0.exe",
        "sha256": "...",
        "size": 12345678
      },
      "updater": {
        "asset": "trazip-updater.exe",
        "sha256": "...",
        "size": 876543
      }
    }
  }
}
```

**Notes URL constraint:** The v1.4 validator only accepts URLs under `https://github.com/kerwilgil/trazip-releases/`. The bridge manifest MUST use the legacy URL prefix.

## Trust Model

- **NO trust rotation** — same Ed25519 public key as v1.4+
- **NO migration.json** — v1.4 cannot parse it
- **NO unsigned migration metadata** — only the signed `update.json` + `update.json.sig` is trusted
- **NO private keys in repo** — private key stays offline

## Physical Release Validation

Future procedure for publishing v1.5:

1. Build v1.5 binary with new channel config (`kerwilgil/trazip`)
2. Generate bridge `update.json` compatible with v1.4 (channel=stable, notesUrl under trazip-releases)
3. Sign offline with the v1.4+ Ed25519 private key
4. Publish bridge release to `kerwilgil/trazip-releases` with `update.json`, `update.json.sig`, `TRAZIP-1.5.0.exe`, `trazip-updater.exe`
5. Test physically: install v1.4 → Check for Updates → Install v1.5 → restart → verify v1.5 queries `kerwilgil/trazip`
6. Verify signature, checksum, download, install all pass
7. Only after successful physical validation: consider archiving `trazip-releases`

## Retirement of trazip-releases

**DO NOT DELETE** `kerwilgil/trazip-releases`.

Only consider **ARCHIVE** (GitHub archive feature) after:
- Physical v1.4 → v1.5 bridge test PASS
- Evidence that v1.5 correctly queries `kerwilgil/trazip`

Maintain historical releases for audit trail.