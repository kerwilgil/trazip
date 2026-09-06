<div align="center">
  <img src="assets/branding/trazip-logo-horizontal.png"
       alt="TRAZIP"
       width="620">
  <h1>TRAZIP — Network Analyzer & Intelligence Toolkit</h1>
  <p>
    <strong>
      Packet Analysis · Network Diagnostics · BGP/RPKI · VoIP · PCAP · Monitoring · Security
    </strong>
  </p>
  <p>
    <img src="https://img.shields.io/github/v/release/kerwilgil/trazip-releases?label=Latest%20Release&color=1267F5"
         alt="Latest Release">
    <img src="https://img.shields.io/badge/Windows-10%20%7C%2011-0F172A?logo=windows&logoColor=white"
         alt="Windows 10/11">
    <img src="https://img.shields.io/badge/macOS-Apple%20Silicon%20(ARM64)-0F172A?logo=apple&logoColor=white"
         alt="macOS Apple Silicon">
    <img src="https://img.shields.io/badge/portable-no%20installer-18C7F4"
         alt="Portable mode available">
    <img src="https://img.shields.io/badge/checksums-SHA--256-071D49"
         alt="SHA-256 Checksums">
    <img src="https://img.shields.io/badge/updates-Ed25519%20signed-1267F5"
         alt="Ed25519 Signed Updates">
    <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-111827"
         alt="MIT License"></a>
    <img src="https://img.shields.io/badge/languages-ES%20%7C%20EN-0F766E"
         alt="Spanish and English">
  </p>
</div>

<div align="center" style="margin: 1.5rem 0;">
  <a href="https://github.com/kerwilgil/trazip-releases/releases/latest">
    <img src="https://img.shields.io/badge/⬇_Download_v1.4.0-1267F5?style=for-the-badge&logo=github"
         alt="Download TRAZIP v1.4.0">
  </a>
  <br>
  <em>Stable binaries and signed updates: <a href="https://github.com/kerwilgil/trazip-releases/releases">kerwilgil/trazip-releases</a></em>
</div>

> **TRAZIP is open source and local-first.**
> This repository contains the official source code, documentation, and community resources.
> Stable binaries and signed updates are available in
> [`kerwilgil/trazip-releases`](https://github.com/kerwilgil/trazip-releases).

---

## Screenshots

Screenshots are published as release assets. See the [v1.4.0 release](https://github.com/kerwilgil/trazip-releases/releases/tag/v1.4.0) for current captures of:

- BGP Intelligence tabs (Summary, Prefixes, Neighbors, Topology, Security, Realtime, History, BGPlay, Observatory)
- Live Capture (Summary / Chains / Hex)
- VoIP Calls (per-direction RTP, RTCP, SDP comparison)
- Network Diagnostics (Quick Diagnose, Ping, Traceroute, MTR)
- LAN Explorer & Network Health

*Real product screenshots will be embedded here when available.*

---

## What is TRAZIP?

TRAZIP is a **cross-platform desktop application** for network diagnostics, packet analysis, and network intelligence — built **local-first** on Windows and macOS (Apple Silicon). All analysis runs on your machine: no backend, no telemetry, no capture uploads.

**Core capabilities:**

- **Network Diagnostics** — Ping, Traceroute, MTR with custom engines; Quick Diagnose with offline IP classification (RFC) and DNS
- **Packet / PCAP Analysis** — Read PCAP/PCAPNG, live capture, flow engine, Live Capture with app/SNI/WebSocket identification
- **Network Monitoring** — Historical monitor, native TCP/UDP Throughput, lab mode, session reports (HTML/PDF/CSV/JSON)
- **Port Scanning (Authorized)** — LAN host discovery, passive switch-loop detection, broadcast storms, duplicate IPs, rogue DHCP
- **BGP Intelligence** — ASN/Prefix/Country/Global/RIS views, RPKI validation, MOAS detection, BGP Topology (pan/zoom/export SVG/PNG), RIS Live real-time, Historical BGP, BGPlay
- **RPKI** — Prefix-scoped validation, ROA/ASP tracking
- **ASN / GeoIP Intelligence** — Offline GeoLite2 datasets, cloud/CDN/ISP categorization from official provider lists
- **VoIP / SIP / RTP Troubleshooting** — Per-call and per-direction diagnostics: RTP loss/jitter/MOS, RTCP Sender/Receiver Reports, RTT estimation, multi-SSRC correlation, SDP↔RTP direction-aware comparison
- **DNS / TLS / RDAP Intelligence** — RDAP registrar/dates/status/nameservers, TLS certificate inspection, public abuse reputation (Spamhaus DROP, Tor exits)
- **Network Investigations** — Unified Investigations workspace with timeline, deduplication, persistence
- **Reports** — Session exports: HTML, PDF, CSV, JSON
- **TZSP** — Headless sender (`tzsp-sender`) to stream captures from remote machines into TRAZIP

---

## Supported Platforms

| Platform | Build | Auto-Update | Notes |
|----------|-------|-------------|-------|
| **Windows 10/11 (x64)** | Native (Wails/WebView2) | ✅ Yes (v0.7.4+) | Installer or Portable |
| **macOS Apple Silicon (M1+)** | Native (Wails/WKWebView) | ❌ Manual only | Ad-hoc signed, not notarized |

> **No Intel/amd64 macOS build is available at this time.**

---

## Key Features

### 📦 Packet & PCAP Analysis
- Read PCAP/PCAPNG files of any size
- Live capture via Npcap (Windows) / libpcap/BPF (macOS)
- Flow engine with 5-tuple + L7 app identification (SNI, HTTP, WebSocket, QUIC, etc.)
- Live Capture views: Summary · Chains · Hexadecimal
- TZSP receiver for remote capture ingestion

### 🔬 Network Diagnostics
- **Ping / Traceroute / MTR** — Custom Go implementations, no system dependencies
- **Quick Diagnose** — Offline IP classification (RFC 1918, 6598, bogons, etc.) + DNS resolution in one conclusion
- **LAN Explorer** — Host discovery, passive detection of switching loops, broadcast storms, duplicate IPs, multiple DHCP servers
- **Active Connections** — TCP/UDP sockets with owning process + remote IP country
- **IP Calculator** — Subnetting, VLSM, aggregation for IPv4/IPv6

### 📊 Network Monitoring
- Historical monitor with configurable intervals
- Native TCP/UDP Throughput (client/server, upload/download/bidirectional)
- Lab mode for controlled testing
- Native notifications
- Session reports: HTML / PDF / CSV / JSON

### 🌐 BGP / RPKI Intelligence
- **Observatory** — Country, Global/RIS, ASN, RPKI History, Bogon lookup
- **Topology** — Observed AS-path adjacencies, stable pan/zoom/drag, SVG/PNG export
- **Realtime** — RIS Live streams, strict stale-session isolation
- **Historical / BGPlay** — Closed datetime ranges, truncation notices, no epoch fabrication
- **RPKI** — Prefix-scoped ROA validation, ASP tracking, MOAS flagged as *Attention* (not auto-labeled Hijack)

### 📞 VoIP Intelligence
- **RTP** — Per-direction loss, jitter, MOS (audio), multi-SSRC correlation
- **RTCP** — Sender Reports & Receiver Reports correctly separated
- **SDP↔RTP** — Direction-aware, multi-media comparison
- **Call diagnostics** — Assessment model with actionable findings
- **Historical quality** — Fixed baseline profile, load testing

### 🛠️ Field Tools
- **Phone** — Offline E.164 validation, country, carrier, line type (mobile/landline/VoIP) — libphonenumber compiled in
- **MAC Lookup** — IEEE MA-L/MA-M/MA-S registry, explains matched prefix
- **RDAP** — Registrar, dates, status, nameservers; handles subdomains correctly
- **Reputation** — Spamhaus DROP, Tor exits — opt-in, local check, source cited

---

## Screenshots

Real product screenshots will be added here after physical capture from the current stable build.

---

## Downloads — v1.4.0 (Latest Stable)

<div align="center">

### [⬇ Download Latest Release](https://github.com/kerwilgil/trazip-releases/releases/latest)

</div>

### Windows (x64)

| Format | File | When to Use |
|--------|------|-------------|
| **Installer (Recommended)** | `trazip-amd64-installer.exe` | Fixed installation; may prompt UAC; creates shortcuts & uninstaller |
| **Portable** | `TRAZIP-portable-1.4.0.zip` | No install. All config, history, datasets in `.\data` folder. Ideal for USB / running on another machine without leaving traces |
| **Standalone EXE** | `TRAZIP-1.4.0.exe` | Single executable, double-click to run (part of update contract) |

> **Requirements:** Windows 10/11 64-bit + WebView2 (pre-installed on updated Windows).  
> **Npcap** (https://npcap.com) required **only for Live Capture**. Not bundled due to license. All other features work without it.

### macOS (Apple Silicon ARM64)

| Format | File | Notes |
|--------|------|-------|
| **Native App** | `TRAZIP-macos-1.4.0-arm64.zip` | Contains `TRAZIP.app`, `herramientas/tzsp-sender`, `LEEME.txt` |

**macOS Important Notes:**
- Native ARM64 build (M1/M2/M3/M4); **no Intel build**
- **Ad-hoc signed, NOT notarized** — First launch: *System Settings → Privacy & Security → "Open Anyway"*
- **Live Capture** requires `/dev/bpf*` access — install Wireshark's **ChmodBPF** helper or run with `sudo`
- PCAP, diagnostics, BGP, VoIP, reports work **without privileges**
- **No Auto-Update on macOS** — Manual download from Releases. Signed `update.json`/`update.json.sig` is Windows-only

---

## Installation

### Windows Installer
1. Download `trazip-amd64-installer.exe`
2. Run — may prompt UAC
3. Launch from Start Menu or Desktop shortcut

### Windows Portable
1. Download `TRAZIP-portable-1.4.0.zip`
2. Extract to any folder (e.g., USB drive)
3. Run `TRAZIP.exe` — `portable.txt` enables local data storage in `.\data`

### macOS
1. Download `TRAZIP-macos-1.4.0-arm64.zip`
2. Extract
3. Drag `TRAZIP.app` to `/Applications` (or run in place)
4. **First launch:** macOS blocks it → *System Settings → Privacy & Security → "Open Anyway"*
5. For Live Capture: install **ChmodBPF** (via Wireshark) or run `sudo /Applications/TRAZIP.app/Contents/MacOS/TRAZIP`

---

## Privacy & Local-First

- **100% local analysis** — Captures, traffic, diagnostics never leave your machine
- **No telemetry / no analytics** — Nothing sent to any server
- **Auto-Update check** (opt-out in Settings) queries only the GitHub Releases channel — reveals only your IP + `TRAZIP/<version>` User-Agent to GitHub (standard HTTP behavior, not TRAZIP telemetry)
- **Explicit external queries only** — BGP uses RIPEstat/RIS; public IP uses `api64.ipify.org`; reputation uses downloaded lists locally

---

## Security & Authorized Use

TRAZIP is a **defensive and authorized pentesting tool**. Active functions require an authorized scope before execution (scope guard). It does **not** implement exploitation, brute force, evasion, automated MITM, or DDoS.

- **SHA-256 checksums** published for every artifact
- **Ed25519-signed update manifest** (`update.json` + `update.json.sig`) — verified before any update is trusted
- **Private signing key never distributed** — Only public key embedded for verification
- **Independent re-verification** — Every downloaded update re-hashed against signed manifest before install
- **Automatic rollback** — If new executable fails to start, reverts to previous version

---

## Development

Requirements: Go 1.26+, Node 20+ and Wails CLI v2. On Windows also WebView2; on macOS, Xcode Command Line Tools (cgo). Live capture uses Npcap on Windows and system libpcap on macOS (access to `/dev/bpf*` via sudo or ChmodBPF from Wireshark).

```bash
wails dev            # live app with frontend hot-reload
wails build          # redistributable binary (.exe on Windows, .app on macOS)
wails build -nsis    # + Windows installer (requires NSIS: winget install NSIS.NSIS)
```

macOS packaging (ZIP with `trazip.app`, `tzsp-sender`, LEEME and hashes):

```bash
go build -o build/bin/tzsp-sender ./cmd/tzsp-sender
bash scripts/package_macos.sh    # → build/bin/TRAZIP-macos-<version>-<arch>.zip
```

Backend tests:

```bash
go test ./...  # test suite (IP classification, etc.)
go vet ./...
```

Regenerate TS bindings after changing the Go API:

```bash
wails generate module
```

---

## Architecture

```
cmd/trazip/            (pending) CLI sharing the core
cmd/tzsp-sender/       headless emitter: local capture → TZSP/UDP → remote TRAZIP
internal/model/        core entities: Endpoint, Flow, Evidence, Assessment
internal/events/       typed event bus with backpressure, consumed by Wails/CLI
internal/scope/        scope guard applied in backend to active operations
internal/session/      UUID orchestrator: context + bus + scope + cancellation
internal/api/          backend facade exposed to GUI (Wails) and CLI
internal/intel/classify/  IP Classification Engine offline
internal/intel/netclass/  network category (cloud/CDN/ISP) from official lists
internal/intel/oui/       vendor by MAC from IEEE registries
internal/intel/threatfeed/ public abuse range lists (opt-in)
internal/phoneintel/      phone number identification (offline)
internal/detection/       passive detectors: scans (scandetect) and layer 2 (netdiag)
internal/connmon/         active sockets of the machine with owning process
internal/ipcalc/          IP calculator: subnetting, VLSM, aggregation
internal/throughput/      TRAZIP TCP/UDP throughput tests (client and server)
frontend/              React + TS (dashboard)
docs/                  dependencies, architecture
```

---

## Releases & Changelog

Full version history and binaries: [Releases](https://github.com/kerwilgil/trazip-releases/releases)

### v1.4.0 Highlights
- **New signing identity** (one-time manual install from v1.3.2 or earlier) — Auto-Update resumes normally from v1.4.0 onward
- **BGP Intelligence complete** — All 9 tabs + Observatory (5 views), Topology with SVG/PNG export
- **Accessibility** — Full ARIA tablist/tab/tabpanel, keyboard navigation, focus-visible, reduced-motion
- **i18n** — Full English translation for BGP Intelligence

### v1.3.1
- BGP Observatory, RIS Live, Historical BGP, BGPlay with RPKI/MOAS evidence
- BGP Topology visual with zoom/fit/export
- Live Capture: Summary / Chains / Hex views

### v0.7.4
- First version with **Auto-Update** (signed manifest, SHA-256, HTTPS-only, anti-downgrade/replay, external updater with rollback)
- System theme fix for Windows dark/light mode

---

## Contributing

Issues and PRs are welcome. Please:

- Report bugs with steps to reproduce, expected vs actual behavior
- Propose features with clear use cases
- Run `go test ./...` and `go vet ./...` before submitting
- Frontend: `cd frontend && npm run build && npm test`
- No sensitive information in issues/PRs (captures, IPs, credentials)
- Tools are for authorized network analysis only

---

## Security

See [SECURITY.md](.github/SECURITY.md) for vulnerability reporting. Use GitHub Private Vulnerability Reporting when possible.

---

## Author & License

Developed by **Kerwil Gil** ([@kerwilgil](https://github.com/kerwilgil))

Distributed under the [MIT License](./LICENSE) — Copyright © 2026 Kerwil Gil