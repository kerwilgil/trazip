# TRAZIP v1.5-0 — DISCOVERY & ROADMAP REPORT

---

## A. BASELINE

| Campo | Valor |
|-------|-------|
| **HEAD** | `852c4bd5d21e62b08e3dd43d41d5e2d3f1023656` |
| **origin/main** | `852c4bd5d21e62b08e3dd43d41d5e2d3f1023656` |
| **ahead/behind** | 0 / 0 (sincronizado) |
| **working tree** | 2 archivos modificados, 7 sin trackear |
| **repo visibility** | Público (github.com/kerwilgil/trazip) |
| **branch protection** | No configurada (main permite force push) |
| **CI state** | No hay CI configurada en el repo público |

**Archivos modificados no committeados:**
- `frontend/package.json.md5`
- `frontend/wailsjs/go/models.ts`

**Archivos sin trackear (artefactos de desarrollo/auditoría):**
- `.claude/` — configuración local de Claude Code
- `.playwright-cli/` — binarios de Playwright
- `BGP_INTELLIGENCE_ROADMAP.md` — roadmap interno BGP v1.2
- `CONTEXT-trazip.md` — contexto maestro del proyecto
- `TRAZIP_prompt_maestro.md` — prompt maestro v1.4
- `docs/releases/` — carpeta vacía
- `gitleaks-report.json` — reporte de secrets scan

**Veredicto baseline:** ✅ HEAD = origin/main = baseline canónico esperado. Working tree limpio salvo artefactos de desarrollo esperados. No hay secretos reales en `gitleaks-report.json` (solo placeholders de testing).

---

## B. CURRENT CAPABILITY INVENTORY

Tabla exhaustiva de capacidades actuales clasificadas por estado real:

| Capacidad | Módulo(s) Interno(s) | Vista Frontend | Estado | Evidencia |
|-----------|---------------------|----------------|--------|-----------|
| **Web Intelligence** | `internal/webintel`, `internal/dnsintel`, `internal/tlsintel`, `internal/httpintel` | `WebIntelligence.tsx` (57KB) | **COMPLETE** | Pipeline completo: normalize → DNS/CNAME → redirects → TLS → headers → CDN/WAF → graph domain→DNS→IP→ASN→country→cert |
| **Passive DNS Intelligence** | `internal/dnsintel` | Integrado en WebIntel | **COMPLETE** | Query A/AAAA/CNAME con resolver configurable, RCODE handling, NXDOMAIN detection |
| **TLS Intelligence** | `internal/tlsintel` | Integrado en WebIntel | **COMPLETE** | Inspección cert chain, validación, SANs, fingerprint SHA256, OCSP stapling check |
| **RDAP/WHOIS** | `internal/rdap` | Bajo demanda (módulo 22) | **COMPLETE** | Cliente RDAP con bootstrap IANA, cache, rate limiting |
| **Reputation / Threat Feeds** | `internal/intel/threatfeed`, `internal/reputation` | Settings + Diagnose | **COMPLETE** | Multi-source (AbuseIPDB, AlienVault, Spamhaus, etc.), cache TTL, scoring |
| **ASN / GeoIP Offline** | `internal/intel/geoip`, `internal/intel/geoupdate` | Settings + todas las vistas | **COMPLETE** | MaxMind GeoLite2 + IP2Location, auto-update con DPAPI, datasets status |
| **BGP Intelligence** | `internal/bgp` (40+ archivos) | `BgpIntelligence.tsx` (113KB) | **COMPLETE** | Observatory (global/country/ASN), RPKI, Bogon, Realtime RIS Live, topology, security |
| **RPKI Validation** | `internal/bgp/rpki_*.go` | Integrado en BGP | **COMPLETE** | Prefix-scoped, ROA/ASPA, observatory |
| **Looking Glass / RIPEstat** | `internal/bgp` (client) | BGP Intelligence | **COMPLETE** | `bgp.Client` con cache, rate limiting, fallback |
| **Investigations Workspace** | `internal/investigation` | `Investigations.tsx` (16KB) | **COMPLETE** | Casos locales, snapshots correlación, export JSON/CSV/HTML/PDF, dedup fingerprint |
| **PCAP Analysis** | `internal/pcap`, `internal/packet`, `internal/flow`, `internal/wifi` | `PcapAnalyzer.tsx` (30KB) | **COMPLETE** | Reader pcap/pcapng, flow aggregation, endpoint extraction, WiFi, scan detection, netdiag |
| **Live Capture** | `internal/capture`, `internal/tzsp`, `internal/packet` | `LiveCapture.tsx` (36KB) | **COMPLETE** | Npcap/WinPcap, TZSP remote, batch events, protocol breakdown, scan detection, MAC vendor |
| **Diagnostics 2.0** | `internal/diagnosis`, `internal/api` | `Diagnose.tsx` (8KB) | **COMPLETE** | Pipeline correlacionado: Offline/Standard/Full, stages (resolution, route, TLS/HTTP, RPKI, reputation), evidence |
| **Ping / Traceroute / MTR** | `internal/probe/{ping,trace,mtr}` | `PingMTR.tsx` (33KB) | **COMPLETE** | Streaming, geo-enrichment por hop, cancellation, scope guard |
| **Port Scanner** | `internal/probe/portscan` | `Scanner.tsx` (13KB) | **COMPLETE** | TCP connect, rate/concurrency bounded, presets (quick/top100/extended/range), service detection |
| **LAN Discovery** | `internal/lan` | `Lan.tsx` (27KB) | **COMPLETE** | ARP/NDP pasivo + scan activo CIDR, MAC vendor (OUI), trust store |
| **Active Connections** | `internal/connmon` | `Connections.tsx` (9KB) | **COMPLETE** | Polling tablas sockets OS, geo/ASN enrichment |
| **HTTP Load Test** | `internal/httpload` | `HttpLoad.tsx` (13KB) | **COMPLETE** | Concurrent HTTP, RPS target, progress streaming |
| **Throughput Test** | `internal/throughput` | `Throughput.tsx` (12KB) | **COMPLETE** | TCP/UDP client/server, access codes |
| **Service Audit** | `internal/serviceaudit` | `Endpoints.tsx` (10KB) | **COMPLETE** | Protocol-safe validation, scope guard, sin credenciales |
| **VoIP Analysis** | `internal/voip` (20+ archivos) | `VoipCalls.tsx` (22KB) | **COMPLETE** | SIP/RTP correlación two-pass, audio reconstruct (G.711), MOS, RTCP RTT, ladder, media path |
| **Phone Intelligence** | `internal/phoneintel` | `Phone.tsx` (7KB) | **COMPLETE** | E.164 parse, carrier, tipo, geo, validación |
| **MAC Intelligence** | `internal/intel/oui` | Integrado LAN/Capture | **COMPLETE** | IEEE OUI database local, lookup vendor |
| **IP Calculator** | `internal/ipcalc` | `IPCalc.tsx` (35KB) | **COMPLETE** | CIDR, subnetting, VLSM, IPv6 |
| **Network Classification** | `internal/intel/netclass` | Diagnose | **COMPLETE** | RFC1918, bogon, multicast, link-local, carrier-grade NAT |
| **Scope Guard** | `internal/scope`, `internal/session` | Transversal (todas las active) | **COMPLETE** | Declaración explícita scope, authorized bool, cancellation, evidence log |
| **Event Bus / Correlation** | `internal/events`, `internal/correlation` | Transversal | **COMPLETE** | Session-scoped events, snapshot correlation, assessment model |
| **Self-Update (Windows)** | `internal/update`, `internal/selfupdate`, `cmd/trazip-updater` | `Settings.tsx` | **COMPLETE** | Signed manifest, SHA256 verification, external updater binary, kerwilgil/trazip-releases |
| **Reporting/Export** | `internal/report` | Transversal | **COMPLETE** | JSON/CSV/HTML/PDF, native save dialog, provenance metadata |
| **WiFi Posture** | `internal/wifi` | Integrado Capture | **PARTIAL** | Posture store, fingerprinting básico |
| **MAC Vendor (OUI)** | `internal/intel/oui` | LAN/Capture | **COMPLETE** | 24 prefijos integrados, offline |
| **DNSSEC** | — | — | **MISSING** | No implementado |
| **Certificate Transparency** | — | — | **MISSING** | No implementado (solo TLS inspection del endpoint final) |
| **Subdomain Discovery** | — | — | **MISSING** | Solo hostnames extraídos de body/headers HTTP |
| **CVE Intelligence** | — | — | **MISSING** | No hay matching producto/versión → CVE |
| **Entity Graph Unificado** | `webintel.Graph` (local) | WebIntel only | **FOUNDATION_ONLY** | Graph domain→DNS→IP→ASN→country→cert solo en WebIntel |
| **Internet Infrastructure (Cables/IXP)** | — | — | **MISSING** | No existe |
| **Sanctions Screening** | — | — | **MISSING** | No existe |
| **GitHub/Public Source OSINT** | — | — | **MISSING** | No existe |
| **Crypto Intelligence** | — | — | **MISSING** | No existe |
| **Telegram OSINT** | — | — | **MISSING** | No existe |
| **Aviation/Maritime/Satellite** | — | — | **REJECT** | Fuera de scope red |

---

## C. GAP ANALYSIS

### Qué falta realmente (gaps genuinos para v1.5)

| Gap | Impacto | Complejidad |
|-----|---------|-------------|
| **OSINT Intelligence Module** — módulo unificado que agregue WebIntel + Passive OSINT + Threat Intel + Infrastructure | Alto | HIGH |
| **Entity Graph Cross-Module** — grafo unificado navegable desde Investigations, Diagnose, PCAP, Live Capture, BGP | Alto | HIGH |
| **Certificate Transparency / Subdomain Discovery** — CT logs, crt.sh, passive DNS | Medio | MEDIUM |
| **CVE Intelligence** — NVD + CISA KEV + product/version matching con evidence | Alto | HIGH |
| **Internet Infrastructure Intelligence** — Submarine cables, landing stations, IXPs, facilities | Medio | MEDIUM |
| **Sanctions / Watchlist Screening** — OpenSanctions, OFAC, UN, EU | Bajo | LOW |
| **Investigation Enrichment** — "Enrich Investigation" button que correlacione todo automáticamente | Alto | MEDIUM |
| **Active Recon Expansion** — service fingerprinting dirigido, TLS probe, DNS probe bajo Scope Guard | Medio | MEDIUM |
| **Update Channel Migration** — v1.4 → v1.5 channel switch design | Obligatorio | MEDIUM |
| **CI / Main Protection / Secret Scanning** — GitHub Actions, branch protection, gitleaks en CI | Obligatorio | LOW |

### Qué NO es gap (ya existe, no reproponer)

- BGP Intelligence completo (observatory, realtime, RPKI, bogon, topology, security)
- Web Intelligence completo (pipeline + graph local)
- Investigations workspace completo (CRUD, export, dedup, integrity)
- PCAP + Live Capture completos (flows, endpoints, WiFi, scan detection, netdiag)
- Diagnose 2.0 correlacionado (stages, evidence, offline/standard/full)
- Active probes completos (ping, trace, mtr, scan, lan, httpload, throughput, service audit)
- Scope Guard transversal (session, authorized, cancellation, evidence)
- Threat feeds multi-source + reputation
- GeoIP/ASN offline + auto-update
- VoIP completo (SIP/RTP, audio, MOS, ladder, media path)
- Phone/MAC intelligence
- Reporting multi-formato
- Self-update Windows firmado

---

## D. OSIRIS AUDIT

**Referencias:**
- https://osirisai.live/docs#api
- https://github.com/simplifaisoul/osiris

**Corrección (post-discovery):** Repositorio `simplifaisoul/osiris` licencia actual: **MIT** (no AGPL-3.0). La decisión permanece: **DO NOT USE AS TRAZIP MIDDLEWARE**.

Motivo correcto:
- TRAZIP debe permanecer independiente
- Preferencia por fuentes primarias
- Evitar dependencia operacional externa innecesaria
- Evitar provider lock-in
- Reducir superficie de fallo
- Conservar provenance directo

Clasificación:
```
OSIRIS:
REFERENCE / FEATURE DISCOVERY
NOT CORE DEPENDENCY
NOT MIDDLEWARE
```

### Matriz de evaluación por capacidad

| Feature | OSIRIS Endpoint | Underlying Source | TRAZIP Already Has | Network Relevance | Passive/Active | Privacy Impact | License | Rate Limit | Auth | Reliability | Recommended Strategy | Reason |
|---------|----------------|-------------------|-------------------|-------------------|----------------|----------------|---------|------------|------|-------------|---------------------|--------|
| **Certificate Transparency** | `/ct` | crt.sh / Censys / CT logs | ❌ MISSING | Alto (cert tracking) | Passive | Bajo (público) | MIT (osiris) / Various | Sí | API Key | Media | **DIRECT_SOURCE** | crt.sh es público, sin auth, rate limit razonable. OSIRIS añade capa innecesaria. |
| **Subdomain Discovery** | `/subdomains` | crt.sh / DNSDB / VirusTotal / SecurityTrails | ❌ MISSING | Alto (attack surface) | Passive | Bajo | Mixed | Sí | API Key (algunos) | Media | **DIRECT_SOURCE + ADAPT** | crt.sh gratis sin key; DNSDB/VT requieren key. TRAZIP debe implementar multi-source con fallback. |
| **CVE Intelligence** | `/cve` | NVD / CISA KEV / GitHub Advisories | ❌ MISSING | Alto (vuln mgmt) | Passive | Bajo | NVD: público; CISA KEV: público | NVD: 5req/30s | No (NVD) / Key (GitHub) | Alta (NVD) | **DIRECT_SOURCE** | NVD API pública, CISA KEV CSV público. OSIRIS solo agrega. |
| **Threat Intelligence** | `/threat-intel` | AbuseIPDB / AlienVault / Spamhaus / URLhaus / etc. | ✅ COMPLETE (threatfeed) | Alto | Passive | Bajo | Mixed | Sí | Keys múltiples | Media | **REJECT OSIRIS / KEEP NATIVE** | TRAZIP ya tiene threatfeed multi-source propio con cache, TTL, scoring. No añadir capa. |
| **Sanctions Screening** | `/sanctions` | OpenSanctions / OFAC / UN / EU | ❌ MISSING | Medio (compliance) | Passive | Bajo | OpenSanctions: CC-BY-4.0 | Sí | Key (OpenSanctions) | Media | **DIRECT_SOURCE** | OpenSanctions dataset descargable (CSV/JSON), actualizable. Mejor cache local que API. |
| **Entity Expansion** | `/expand` | Múltiples (graph traversal) | 🟡 FOUNDATION (webintel.Graph) | Alto | Passive | Bajo | MIT | Sí | Key | Media | **REIMPLEMENT** | TRAZIP ya tiene graph foundation. Expandir a entity graph unificado nativo. |
| **IP Enrichment** | `/ip` | GeoIP / ASN / RDAP / Threat feeds | ✅ COMPLETE (geoip + threatfeed + rdap) | Alto | Passive | Bajo | Mixed | Sí | Key | Media | **REJECT OSIRIS / KEEP NATIVE** | TRAZIP ya tiene geoip offline, threatfeed, rdap client. |
| **DNS Enrichment** | `/dns` | DNSDB / Farsight / SecurityTrails / passive DNS | 🟡 PARTIAL (dnsintel solo A/AAAA/CNAME) | Alto | Passive | Bajo | Mixed | Sí | Key | Media | **ADAPT** | Añadir passive DNS histórico (DNSDB/Farsight) como source opcional con key. |
| **WHOIS/RDAP Enrichment** | `/whois` | RDAP bootstrap IANA / WHOIS legacy | ✅ COMPLETE (rdap) | Alto | Passive | Medio (PII en WHOIS legacy) | Público | Bootstrap IANA sin auth | No (RDAP) | Alta | **REJECT OSIRIS / KEEP NATIVE** | Cliente RDAP propio completo con bootstrap, cache, rate limit. |
| **Cyber Infrastructure Feeds** | `/infrastructure` | Censys / Shodan / BinaryEdge / ZoomEye | ❌ MISSING | Medio | Passive | Bajo | Comercial | Sí | Key | Media | **DIRECT_SOURCE (SELECTIVE)** | Solo si añade valor sobre threatfeed actual. Censys/Shodan caros. Evaluar costo/beneficio. |
| **GitHub/Public Source Intel** | `/github` | GitHub API / Gists / Repos | ❌ MISSING | Bajo-Medio | Passive | Bajo (público) | GitHub API terms | Sí | Token | Alta | **DEFER** | Valor marginal para network analyzer. Defer a v1.6+. |
| **Crypto Intelligence** | `/crypto` | Blockchain explorers / OFAC crypto | ❌ MISSING | Bajo | Passive | Bajo | Mixed | Sí | Key | Media | **REJECT** | Fuera de scope network analyzer. |
| **Telegram Public OSINT** | `/telegram` | Telegram public channels / TgStat | ❌ MISSING | Bajo | Passive | Medio (metadatos usuarios) | Telegram API terms | Sí | Bot token | Baja | **REJECT** | Fuera de scope, riesgo privacidad. |
| **Global Cyber Events** | `/events` | Aggregation feeds | ❌ MISSING | Medio | Passive | Bajo | Mixed | Sí | Key | Media | **DEFER** | Puede servirse via threatfeed existente. |
| **Aviation/Maritime/Earthquake/Weather/Satellite/CCTV/News** | Varios | APIs especializadas | ❌ MISSING | **NULO** | Passive/Active | Variable | Mixed | Sí | Key | Variable | **REJECT** | No responden "¿hace mejor a un analizador e investigador de redes?". |

### Conclusión OSIRIS

**NO usar OSIRIS API como capa intermedia general.**

- **3 capacidades**: REJECT OSIRIS / KEEP NATIVE (threat intel, IP enrichment, RDAP) — TRAZIP ya lo tiene mejor (offline, sin key, sin rate limit externo)
- **4 capacidades**: DIRECT_SOURCE (CT, CVE, Sanctions, Cyber Infra selective) — ir a fuente original
- **2 capacidades**: DIRECT_SOURCE + ADAPT (Subdomain, DNS Enrichment) — multi-source con fallback
- **1 capacidad**: REIMPLEMENT (Entity Expansion) — sobre foundation propia
- **6 capacidades**: REJECT / DEFER — fuera de scope o valor marginal

**Principio aplicado:** "No añadir una capa intermedia si no aporta valor." OSIRIS (MIT) agrega latencia, dependencia de backend, provider lock-in operacional, y rate limits sin mejorar la calidad de datos sobre las fuentes primarias.

---

## E. INTERNET INFRASTRUCTURE AUDIT

### Submarine Cables

| Fuente | Software License | Data License | API | Auth | Rate Limit | Redistribution | Freshness | Decisión |
|--------|-----------------|--------------|-----|------|------------|----------------|-----------|----------|
| **Submarine Cable Map (TeleGeography)** | Proprietary | Proprietary (© TeleGeography) | No público | N/A | N/A | **NO** (copyright estricto) | Anual | **RECHAZAR DATOS** |
| **Submarine Cable Map (Open Source Forks)** | MIT/Apache-2.0 | Derivada de TeleGeography | No | N/A | N/A | Gris (derivada) | Variable | **CAUTELOSO** — verificar procedencia |
| **Telegeography Data (oficial)** | N/A | Comercial (licencia $$) | Sí (partners) | Key | Contractual | Con licencia pagada | Anual | **NO** para open source |
| **CableMapData (GitHub: cablemapdata/cablemapdata)** | MIT | CC-BY-4.0 (claim) | No | N/A | N/A | Sí (CC-BY-4.0) | 2023-2024 | **EVALUAR** — verificar attribution real |
| **OpenCableMap / OpenInfraMap** | AGPL-3.0 | OSM-derived / CC-BY-SA | Overpass API | No | OSM limits | OSM license | Continuo | **VIABLE** — OSM tiene cables submarinos (man_made=submarine_cable) |

**Hallazgo clave:** TeleGeography (dueño de submarinecablemap.com) tiene copyright estricto sobre sus datos. No se pueden redistribuir sin licencia comercial. Los forks "open source" en GitHub a menudo redistribuyen datos de TeleGeography sin licencia — **riesgo legal P0**.

**Fuente viable:** OpenStreetMap (man_made=submarine_cable, landing_point, cable_system). Licencia ODbL/CC-BY-SA. Datos crowdsourced, menos completos que TeleGeography pero legalmente seguros. Requiere processing Overpass API → dataset local.

### Landing Stations

| Fuente | Licencia | Cobertura | API | Decisión |
|--------|----------|-----------|-----|----------|
| **OSM (landing_point, station=submarine_cable)** | ODbL/CC-BY-SA | Parcial (crowdsourced) | Overpass | **VIABLE** como base |
| **TeleGeography** | Propietaria | Completa | Comercial | **NO** |
| **PeeringDB (facilities)** | CC-BY-4.0 | Solo facilities con IXP/peering | API REST | **COMPLEMENTARIA** |

### IXPs y Network Facilities

| Fuente | Software License | Data License | API | Auth | Rate Limit | Redistribution | Decisión |
|--------|-----------------|--------------|-----|------|------------|----------------|----------|
| **PeeringDB** | BSD-3-Clause | CC-BY-4.0 | REST + GraphQL | OAuth (opcional) | 1000/hr sin auth | ✅ Con attribution | **ADOPTAR** |
| **PCH (Packet Clearing House) IXP Directory** | Propietario | Propietario | Limitado | Key | Contractual | Limitado | **EVITAR** |
| **Euro-IX / APIX / LAC-IX member lists** | Varias | Varias | Web/CSV | No | N/A | Mixta | **SELECTIVO** |
| **NetIX / DE-CIX / AMS-IX / LINX public lists** | N/A | Pública | Web | No | N/A | Pública | **VIABLE** (scraping ético + cache) |

**PeeringDB es la fuente canónica:** licencia clara (CC-BY-4.0), API documentada, datos de IXP + facilities + ASN presence + ubicaciones. Cubre >1300 IXPs y >3000 facilities globalmente.

### Correlación Infraestructura ↔ Red

| Correlación | Viabilidad | Evidencia Requerida |
|-------------|------------|---------------------|
| Traceroute ASN transition → nearby landing station | **POSIBLE** | GeoIP de hops + distancia a landing points OSM |
| BGP prefix → IXP peering | **POSIBLE** | PeeringDB: ASN presence at IXP + prefix origin ASN |
| ASN → facility / datacenter | **POSIBLE** | PeeringDB: facility → netfac → ASN |
| Cable system → prefix path | **NO PROVEN** | Solo "Infrastructure Context", nunca "Confirmed Physical Path" |

---

## F. EXTERNAL SOURCE & LICENSE MATRIX

| Source | Software License | Data License | Commercial Use | Redistribution | Attribution | API Terms | Bundling Allowed | Caching Allowed | Decision |
|--------|-----------------|--------------|----------------|----------------|-------------|-----------|------------------|-----------------|----------|
| **MaxMind GeoLite2** | Apache-2.0 | CC-BY-SA-4.0 | ✅ | ✅ (con attribution) | Requerida | EULA + license key | ✅ (MMDB) | ✅ | KEEP |
| **IP2Location Lite** | Proprietary | Proprietary (free tier) | ✅ | ❌ (no redistribute DB) | Requerida | License key | ❌ | ✅ (runtime) | KEEP (runtime only) |
| **PeeringDB** | BSD-3-Clause | CC-BY-4.0 | ✅ | ✅ | Requerida | REST API terms | ✅ (cached) | ✅ | ADOPT |
| **OpenStreetMap** | ODbL | ODbL/CC-BY-SA | ✅ | ✅ (share-alike) | Requerida | Overpass API usage policy | ✅ (derived) | ✅ | ADOPT (derived datasets) |

**Corrección (post-discovery):** OSM no es simplemente "safe/permissive". Datos bajo **ODbL** — el diseño futuro debe contemplar:
- Attribution obligatorio
- Provider provenance tracking
- Caching rules (share-alike para derivados)
- Derivative database obligations (ODbL §4)
- Separación entre código MIT de TRAZIP y datos ODbL

No implementar Infrastructure Intelligence todavía.
| **NVD (CVE)** | Public Domain | Public Domain | ✅ | ✅ | Ninguna | Rate limit 5/30s | ✅ | ✅ | ADOPT |
| **CISA KEV** | Public Domain | Public Domain | ✅ | ✅ | Ninguna | CSV/JSON público | ✅ | ✅ | ADOPT |
| **OpenSanctions** | MIT | CC-BY-4.0 | ✅ | ✅ | Requerida | API key (gratis) | ✅ | ✅ | ADOPT |
| **crt.sh (CT logs)** | PostgreSQL/Apache | Público (CT logs) | ✅ | ✅ | Ninguna | Rate limit suave | ✅ | ✅ | ADOPT |
| **AbuseIPDB** | Proprietary | Proprietary | ✅ (con plan) | ❌ | Requerida | API key, rate limit | ❌ | ✅ (cached) | KEEP (threatfeed) |
| **AlienVault OTX** | Proprietary | Proprietary | ✅ | ❌ | Requerida | API key | ❌ | ✅ (cached) | KEEP (threatfeed) |
| **Spamhaus DROP/EDROP** | Proprietary | Proprietary | ⚠️ (requiere licencia) | ❌ | Requerida | DNS zone / HTTP | ❌ | ✅ (cached) | KEEP (threatfeed) |
| **URLhaus** | Open | CC0 | ✅ | ✅ | Ninguna | API pública | ✅ | ✅ | KEEP (threatfeed) |
| **OSIRIS API** | MIT | MIT (derivada) | ✅ | ✅ (con source) | Requerida | API key | ❌ | ❌ | **REJECT** (operational dependency) |
| **TeleGeography Cable Data** | Proprietary | Proprietary | ❌ (sin pagar) | ❌ | Requerida | Comercial | ❌ | ❌ | **REJECT** |

**Nota crítica:** Software license ≠ Data license. TeleGeography: software del mapa puede ser open source, pero los **datos** son propietarios. PeeringDB: software BSD-3, datos CC-BY-4.0 — ambos compatibles. OSM: software (Overpass) AGPL, datos ODbL — requiere share-alike para derivados.

---

## G. PROPOSED ARCHITECTURE

### High-Level Module Structure (v1.5)

```
trazip/
├── internal/
│   ├── osint/                    # NEW: OSINT Intelligence core
│   │   ├── overview.go           # Dashboard aggregator
│   │   ├── passive/              # Passive intelligence engines
│   │   │   ├── ctlog.go          # Certificate Transparency (crt.sh)
│   │   │   ├── subdomain.go      # Subdomain discovery (multi-source)
│   │   │   ├── dns_historical.go # Passive DNS (DNSDB/Farsight optional)
│   │   │   ├── sanctions.go      # OpenSanctions screening
│   │   │   └── github_intel.go   # GitHub public source (DEFER)
│   │   ├── infrastructure/       # Internet Infrastructure Intelligence
│   │   │   ├── cables.go         # Submarine cables (OSM-derived)
│   │   │   ├── landings.go       # Landing stations (OSM + PeeringDB)
│   │   │   ├── ixps.go           # IXPs (PeeringDB)
│   │   │   ├── facilities.go     # Network facilities (PeeringDB)
│   │   │   └── correlation.go    # Infra ↔ ASN/Prefix/BGP correlation
│   │   ├── threat/               # Unified Threat Intelligence
│   │   │   ├── engine.go         # Unified indicator model
│   │   │   ├── providers.go      # Multi-source aggregator
│   │   │   └── cve.go            # CVE Intelligence (NVD + CISA KEV)
│   │   ├── entity/               # Entity Graph
│   │   │   ├── graph.go          # Unified graph model
│   │   │   ├── nodes.go          # Domain, IP, ASN, Cert, Cable, IXP, Facility, CVE, Sanction
│   │   │   ├── edges.go          # Relationship types with evidence
│   │   │   └── traversal.go      # Graph queries, expansion
│   │   ├── investigation/        # Investigation Enrichment
│   │   │   ├── enrich.go         # Enrich Investigation command
│   │   │   ├── correlator.go     # Cross-module correlation
│   │   │   └── evidence.go       # Evidence chain for enrichment
│   │   └── active/               # Active Recon (expansion)
│   │       ├── service_probe.go  # Targeted service identification
│   │       ├── tls_probe.go      # TLS config probe
│   │       └── dns_probe.go      # DNS zone/record probe
│   ├── webintel/                 # EXISTING - keep, integrate bidirectionally
│   ├── bgp/                      # EXISTING - enhance with entity graph
│   ├── investigation/            # EXISTING - add Enrich action
│   ├── intel/                    # EXISTING - geoip, threatfeed, classify, netclass, oui
│   └── ... (rest unchanged)
├── frontend/src/
│   ├── views/
│   │   ├── OsintIntelligence.tsx      # NEW: Main OSINT module
│   │   ├── OsintOverview.tsx          # NEW: Overview dashboard
│   │   ├── OsintPassive.tsx           # NEW: Passive Intelligence
│   │   ├── OsintInfrastructure.tsx    # NEW: Internet Infrastructure
│   │   ├── OsintThreat.tsx            # NEW: Threat Intelligence
│   │   ├── OsintEntityGraph.tsx       # NEW: Entity Graph
│   │   ├── OsintInvestigations.tsx    # NEW: Investigation integration
│   │   ├── OsintActiveRecon.tsx       # NEW: Active Recon
│   │   └── ... (existing views)
│   └── components/
│       ├── EntityGraph/               # NEW: Graph visualization (Cytoscape/Canvas)
│       ├── InfraMap/                  # NEW: Cable/IXP map (Leaflet/MapLibre)
│       └── ...
└── cmd/trazip/                    # EXISTING
```

### Integration Points

| Punto | Descripción |
|-------|-------------|
| **WebIntel ↔ OSINT** | Bidireccional: WebIntel "Open in OSINT" para entity expansion; OSINT "Analyze in WebIntel" para deep dive URL |
| **Investigations ↔ OSINT** | "Enrich Investigation" button en Investigations view → OSINT correlator |
| **BGP ↔ OSINT Infrastructure** | BGP Observatory → "Infrastructure Context" panel (cables/IXPs near ASN/prefix) |
| **PCAP/Live Capture ↔ OSINT** | Entity extraction → "Add to OSINT Graph" / "Enrich in OSINT" |
| **Diagnose ↔ OSINT** | Diagnose result → "Expand in OSINT Entity Graph" |
| **Threat Feed ↔ OSINT Threat** | Unified indicator model, shared cache, single UI |

### Data Flow Principles (Invariantes)

1. **Local-first**: OSM cable/IXP datasets cached locally (MMDB-style), updated via background job
2. **Passive ≠ Active**: OSINT Passive = solo consultas cacheadas/offline/públicas sin rate limit externo; Active Recon = Scope Guard explícito
3. **Evidence-first**: Cada edge en Entity Graph tiene `{source, timestamp, evidence, confidence, scope}`
4. **Bounded Runtime**: Colas acotadas, TTL, rate limiting, cancellation, offline mode para todas las fuentes externas
5. **No Vendor Lock-in**: Fuentes primarias directas, no APIs agregadoras con licencias virales

---

## H. PROPOSED OSINT INTELLIGENCE UX

### Opción Seleccionada: **C. Módulo principal con integración bidireccional a Web Intelligence**

**Justificación:**
- Web Intelligence es "deep dive" de un target HTTP/DNS/TLS específico
- OSINT Intelligence es "wide view" de entidad (dominio, IP, ASN, cert, cable, IXP) y sus relaciones
- Son complementarios, no redundantes: WebIntel → OSINT para expansión; OSINT → WebIntel para análisis profundo
- Investigation workspace necesita ambos como fuentes de evidencia

### Estructura de Navegación (Sidebar)

```
TRAZIP
├── Overview
├── Web Intelligence          ← EXISTING
├── OSINT Intelligence        ← NEW (v1.5)
│   ├── Overview              # Dashboard: threat summary, infra context, entity count
│   ├── Passive Intelligence  # CT logs, subdomains, passive DNS, sanctions
│   ├── Internet Infrastructure # Cables, landings, IXPs, facilities, map
│   ├── Threat Intelligence   # Unified indicators, CVE, threat feeds
│   ├── Entity Graph          # Interactive graph (Cytoscape/Canvas)
│   ├── Investigations        # Enrich + cross-ref existing cases
│   └── Active Recon          # Service/TLS/DNS probes (Scope Guard)
├── BGP Intelligence          ← EXISTING
├── Investigations            ← EXISTING (add "Enrich" button)
├── Diagnose                  ← EXISTING
├── PCAP Analyzer             ← EXISTING
├── Live Capture              ← EXISTING
├── ... (rest unchanged)
```

### OSINT Overview Dashboard

Widgets:
- **Threat Summary**: Indicadores activos por severidad (threatfeed + CVE KEV + sanctions)
- **Infrastructure Context**: Cables/IXPs cercanos a ASNs/top prefixes del caso actual
- **Entity Graph Mini**: Top 50 nodos del grafo actual, click → Entity Graph view
- **Passive Intelligence Queue**: CT logs nuevos, subdominios descubiertos, sanctions hits
- **Active Recon Status**: Scans/probes en curso con scope guard visible

---

## I. PASSIVE vs ACTIVE MODEL

### Separación Estricta (Invariante TRAZIP)

```
┌─────────────────────────────────────────────────────────────┐
│                     OSINT INTELLIGENCE                        │
├─────────────────────────────────────────────────────────────┤
│  PASSIVE EXTERNAL                          ACTIVE AUTHORIZED │
│  ─────────────────                          ──────────────── │
│  • CT Logs (crt.sh)                        • Service Probe    │
│  • Passive DNS (DNSDB opt-in)              • TLS Probe        │
│  • Subdomain (crt.sh + DNS)                • DNS Zone Probe   │
│  • Sanctions (OpenSanctions local cache)   • Host Sweep       │
│  • CVE (NVD/CISA KEV local cache)          • Targeted Port    │
│  • Threat Feeds (local cache)              • Fingerprinting   │
│  • Infrastructure (OSM/PeeringDB local)    │                   │
│  • GitHub Public (opt-in, rate limited)    │                   │
│                                             │                   │
│  ✅ Sin Scope Guard                         ⚠️ REQUIERE Scope Guard   │
│  ✅ Sin autorización explícita              ⚠️ Autorización explícita   │
│  ✅ Cancelable en cualquier momento         ⚠️ Timeout + bounds         │
│  ✅ Offline mode (cache only)               ⚠️ Concurrency limits       │
│  ✅ Provenance visible                      ⚠️ Evidence log obligatorio  │
└─────────────────────────────────────────────────────────────┘
```

### Reglas de Implementación

1. **Nunca mezclar visualmente**: Tabs separados, colores distintos, badges "PASSIVE" / "ACTIVE AUTHORIZED"
2. **Active Recon nunca auto-ejecutar**: Solo bajo acción explícita del usuario con checkbox "Autorizado" + scope declarado
3. **Passive siempre cancelable**: Botón "Stop" visible, context cancellation propagado
4. **Provenance obligatoria**: Cada resultado passive muestra `[fuente] [timestamp] [cache hit/miss]`
5. **Offline mode**: Toggle global "Solo datos locales" — desactiva todas las consultas externas

---

## J. ENTITY GRAPH DESIGN

### Modelo de Datos

```go
// Node kinds
const (
    NodeDomain     = "domain"
    NodeDNS        = "dns"          // CNAME, NS, MX, etc.
    NodeIP         = "ip"
    NodeASN        = "asn"
    NodePrefix     = "prefix"
    NodeBGP        = "bgp"          // BGP observation (MOAS, hijack suspect, RPKI)
    NodeRPKI       = "rpki"         // ROA, ASPA
    NodeCertificate = "cert"        // SHA256 fingerprint
    NodeSubdomain  = "subdomain"
    NodeCVE        = "cve"
    NodeThreat     = "threat"       // Indicator from threat feed
    NodeSanction   = "sanction"     // OpenSanctions entity
    NodeCable      = "cable"        // Submarine cable system
    NodeLanding    = "landing"      // Landing station
    NodeIXP        = "ixp"          // Internet Exchange Point
    NodeFacility   = "facility"     // Network facility / datacenter
    NodeService    = "service"      // Service audit result
)

// Edge kinds
const (
    EdgeResolvesTo      = "resolves_to"       // domain -> dns/ip
    EdgeRedirectsTo     = "redirects_to"      // domain -> domain
    EdgeInASN           = "in_asn"            // ip -> asn
    EdgeOriginates      = "originates"        // asn -> prefix
    EdgeBGPObserved     = "bgp_observed"      // asn/prefix -> bgp event
    EdgeRPKIValid       = "rpki_valid"        // prefix -> rpki (valid/invalid/unknown)
    EdgeServesCert      = "serves_cert"       // domain/ip -> cert
    EdgeCertSAN         = "cert_san"          // cert -> domain (SAN)
    EdgeSubdomainOf     = "subdomain_of"      // subdomain -> domain
    EdgeThreatIndicator = "threat_indicator"  // ip/domain -> threat
    EdgeCVEAffects      = "cve_affects"       // cve -> service/product
    EdgeSanctioned      = "sanctioned"        // entity -> sanction
    EdgeLandingOnCable  = "landing_on_cable"  // landing -> cable
    EdgeCableCountry    = "cable_country"     // cable -> country
    EdgeIXPAtFacility   = "ixp_at_facility"   // ixp -> facility
    EdgeASNAtIXP        = "asn_at_ixp"        // asn -> ixp (peering)
    EdgeASNAtFacility   = "asn_at_facility"   // asn -> facility
    EdgeInfraContext    = "infra_context"     // ASN/prefix -> cable/landing/ixp (PROXIMITY, not proven)
)

// Edge metadata (REQUIRED)
type EdgeMeta struct {
    Source       string    `json:"source"`        // "crt.sh", "peeringdb", "bgp:ris", "nvd", "osint:ct", etc.
    Timestamp    string    `json:"timestamp"`     // RFC3339
    Evidence     string    `json:"evidence"`      // JSON serializable proof (record, response, etc.)
    Confidence   float64   `json:"confidence"`    // 0.0 - 1.0
    Scope        string    `json:"scope"`         // "observed" | "inferred" | "proximity"
    Limitations  string    `json:"limitations"`   // e.g. "geographic proximity only, not path proof"
}
```

### Reglas de Grafo

| Regla | Descripción |
|-------|-------------|
| **No edges sin evidence** | Cada edge requiere `Evidence` no vacío |
| **Confidence calibrada** | observed=0.9-1.0, inferred=0.5-0.8, proximity=0.1-0.4 |
| **Scope honesto** | "proximity" para cable/IXP cerca de ASN; nunca "confirmed path" |
| **Dedup por fingerprint** | Mismo node+edge+evidence = mismo fingerprint, no duplicar |
| **Temporalidad** | Nodes/edges tienen `first_seen`, `last_seen`; expiry configurable |
| **Investigation binding** | Graph puede filtrarse por investigation ID (solo evidencia del caso) |

### Visualización

- **Backend**: Cytoscape.js o Canvas custom (rendimiento >10k nodos)
- **Layouts**: Force-directed, Hierarchical (domain→DNS→IP→ASN), Geographic (MapLibre)
- **Filtros**: Por node kind, edge kind, confidence threshold, time range, investigation
- **Acciones**: Click nodo → panel detalle; Click edge → evidence viewer; "Add to Investigation"; "Open in WebIntel/BGP"

---

## K. INVESTIGATION INTEGRATION

### Enrich Investigation Workflow

```
Investigations View
    │
    ├── Case List
    │   └── [Case Row] → "Enrich" button (nuevo)
    │
    └── Case Detail
        ├── Timeline (entries)
        │   └── [Entry] → "Expand in Entity Graph" (existente)
        │
        └── Toolbar
            ├── Export (JSON/CSV/HTML/PDF) ← EXISTING
            ├── Enrich Investigation ← NEW
            │   ├── Paso 1: Seleccionar fuentes
            │   │   ☑ Certificate Transparency
            │   │   ☑ Subdomain Discovery
            │   │   ☑ Passive DNS (opt-in)
            │   │   ☑ CVE Intelligence
            │   │   ☑ Threat Intelligence
            │   │   ☑ Sanctions Screening
            │   │   ☑ Infrastructure Context
            │   │   ☐ Active Recon (requiere Scope Guard)
            │   │
            │   ├── Paso 2: Confirmar consultas externas (lista visible)
            │   │   📋 crt.sh (CT logs) — Passive, sin auth, ~2s
            │   │   📋 NVD API (CVE) — Passive, rate limited, ~1s
            │   │   📋 OpenSanctions (local cache) — Passive, instant
            │   │   📋 PeeringDB (IXP/Facility) — Passive, cached
            │   │
            │   └── Paso 3: Ejecutar → Entity Graph se popula → Review → Save entries
            │
            └── Active Recon ← NEW (separado, Scope Guard)
                ├── Service Probe
                ├── TLS Probe
                └── DNS Probe
```

### Correlation Engine (internal/osint/investigation/correlator.go)

Input: `Investigation` (entries con snapshots de Diagnose, PCAP, VoIP, Monitor, BGP, etc.)

Output: `EnrichmentResult` con:
- `NewNodes` — entidades descubiertas (subdominios, IPs, ASNs, certificados, CVEs, sanciones, cables, IXPs)
- `NewEdges` — relaciones con evidence
- `Conflicts` — datos contradictorios entre fuentes
- `Gaps` — entidades sin enriquecer (ej. IP sin ASN en geoip local)

Cada `NewEdge` incluye `EdgeMeta` completo para trazabilidad.

---

## L. EXISTING TRAZIP IMPROVEMENT PLAN (v1.5)

| Módulo | Mejora | Justificación | Complejidad |
|--------|--------|---------------|-------------|
| **Diagnostics** | Correlación con Entity Graph; evidencia RPKI/BGP/OSINT opcional en reporte | Unificar vista; evitar saltar entre módulos | MEDIUM |
| **PCAP Analyzer** | Extracción entidades (dominios, certs, IPs) → "Add to OSINT Graph"; Threat enrichment en flows | PCAP como fuente OSINT | MEDIUM |
| **Live Capture** | Entity extraction en tiempo real; ASN/RPKI/TLS context en flows; Handoff a Investigation | Live capture como sensor OSINT | MEDIUM |
| **BGP Intelligence** | Investigation integration (add BGP event to case); Evidence improvements (ROA dump); Historical comparison; Entity Graph sync | BGP como fuente de grafo | MEDIUM |
| **VoIP** | Call timeline unificado; SIP ladder export; Media path visualization; RTP trends; Export improvements | Usabilidad investigación VoIP | LOW |
| **Threat Intel** | Unified indicator model (source, classification, evidence, first/last seen, TTL, confidence); Deprecate magic score | Evitar "magic score" sin provenance | LOW |
| **Web Intelligence** | CT log integration button; Subdomain discovery button; "Open in OSINT Entity Graph" | Puente a OSINT | LOW |
| **Scope Guard** | Audit log persistente (JSONL) de todas las active operations con scope/target/authorized/timestamp | Compliance, forensics | LOW |
| **Update Subsystem** | Migration design v1.4→v1.5 channel (ver sección M) | Obligatorio para release | MEDIUM |

---

## M. UPDATE MIGRATION PLAN

### Estado Actual (v1.4)

- Canal: `kerwilgil/trazip-releases` (GitHub Releases)
- Formato: `update.json` + `update.json.sig` (Ed25519)
- Cliente: `internal/update` + `cmd/trazip-updater` (Windows only)
- Auto-check: 24h, solo Windows, user-controlled

### Diseño Migración v1.4 → v1.5

```
Fase 1 (v1.4.x patch): "Bridge Release"
├── Publicar v1.4.1 en trazip-releases CON:
│   ├── update.json v1.4.1 (normal)
│   └── migration_manifest.json (NUEVO)
│       ├── v1_5_channel: "kerwilgil/trazip-releases-v15" (nuevo repo)
│       ├── v1_5_manifest_url: "https://.../v1.5.0/update.json"
│       ├── v1_5_pubkey: "ed25519:NUEVA_CLAVE_BASE64"
│       └── min_version: "1.4.1"
│
Fase 2 (v1.5.0): "New Channel"
├── Nuevo repo: `kerwilgil/trazip-releases-v15` (o tag v1.5 en mismo repo con prefix)
├── Nueva clave Ed25519 (key rotation)
├── update.json v1.5.0 firmado con NUEVA clave
├── Cliente v1.5:
│   ├── Lee migration_manifest de v1.4.1
│   ├── Valida firma v1.4.1 (clave vieja)
│   ├── Descarga v1.5.0 manifest con NUEVA clave
│   ├── Instala v1.5.0
│   └── v1.5.0 conoce SOLO nuevo canal y NUEVA clave
│
Fase 3 (post-v1.5): "Cleanup"
├── v1.5.1+ ya no consulta canal v1.4
├── trazip-releases puede archivarse
└── Clave vieja revocada/rotada
```

### Requisitos de Seguridad

- **Key rotation**: Nueva Ed25519 keypair para v1.5; v1.4.1 bridge manifest firmado con clave vieja
- **TOFU**: v1.4.1 valida bridge manifest con clave vieja; v1.5 valida con clave nueva
- **No downgrade**: v1.5 rechaza manifests firmados con clave vieja
- **Channel isolation**: v1.5 nunca escribe en trazip-releases (solo lee bridge una vez)

### Archivos a Modificar (solo diseño, NO implementar ahora)

- `internal/update/manager.go` — lógica migración
- `internal/update/types.go` — `MigrationManifest` struct
- `cmd/trazip-updater/` — sin cambios (binario genérico)
- `wails.json` — `productVersion` = "1.5.0"
- `frontend/package.json` — `version` = "1.5.0"
- GitHub Actions (NEW) — build + sign + publish to v1.5 channel

---

## N. FINAL v1.5 ROADMAP

### Bloques Propuestos (ordenados por dependencias y valor)

| Bloque | Nombre | Contenido Principal | Dependencias | Prioridad | Complejidad |
|--------|--------|---------------------|--------------|-----------|-------------|
| **V1.5-0** | Baseline / CI / Security Foundation | GitHub Actions CI (build, test, gitleaks, govulncheck); Branch protection main; Dependabot; SBOM | Ninguna | **MUST HAVE** | LOW |
| **V1.5-1** | Update Channel Migration | Bridge release v1.4.1 + nuevo canal v1.5 + key rotation | V1.5-0 | **MUST HAVE** | MEDIUM |
| **V1.5-2** | OSINT Foundation | `internal/osint` package; Passive engines (CT, Subdomain, Sanctions, CVE); Local caches; Unified threat model | V1.5-0 | **MUST HAVE** | HIGH |
| **V1.5-3** | OSINT Intelligence UI | `OsintIntelligence.tsx` + sub-vistas (Overview, Passive, Threat); Navigation integration | V1.5-2 | **MUST HAVE** | HIGH |
| **V1.5-4** | Entity Graph Core | Graph model, nodes/edges, traversal, persistence, Cytoscape/Canvas renderer | V1.5-2 | **MUST HAVE** | HIGH |
| **V1.5-5** | Investigation Enrichment | "Enrich Investigation" workflow; Correlator; Evidence chain; Bidirectional WebIntel/BGP/PCAP | V1.5-2, V1.5-4 | **MUST HAVE** | MEDIUM |
| **V1.5-6** | Internet Infrastructure Intelligence | Submarine cables (OSM), Landing stations, IXPs (PeeringDB), Facilities; InfraMap view; Correlation engine | V1.5-2 | **SHOULD HAVE** | MEDIUM |
| **V1.5-7** | CVE Intelligence | NVD API + CISA KEV local cache; Product/version matching con evidence; CVE nodes en Entity Graph | V1.5-2 | **SHOULD HAVE** | MEDIUM |
| **V1.5-8** | Active Recon Expansion | Service probe, TLS probe, DNS probe bajo Scope Guard; Integration en OSINT Active Recon tab | V1.5-0 (Scope Guard) | **SHOULD HAVE** | MEDIUM |
| **V1.5-9** | Diagnostics / PCAP / Live Correlation | Entity extraction → OSINT Graph; Threat enrichment; Investigation handoff improvements | V1.5-2, V1.5-4 | **SHOULD HAVE** | MEDIUM |
| **V1.5-10** | BGP / VoIP Enhancements | BGP investigation integration; VoIP timeline/ladder/media path exports | V1.5-5 | **NICE TO HAVE** | LOW |
| **V1.5-11** | Release Hardening | SBOM (CycloneDX), SLSA provenance, signed artifacts, reproducible builds, notarization (macOS) | V1.5-0 | **MUST HAVE** | MEDIUM |

### Bloques Fusionados/Reordenados vs Propuesta Inicial

| Cambio | Justificación |
|--------|---------------|
| **Fusionado V1.5-2+3+4** | OSINT Foundation + UI + Entity Graph son inseparables: el grafo es el modelo de datos del módulo OSINT |
| **V1.5-6 (Infrastructure) antes de CVE** | Infrastructure data (PeeringDB/OSM) es más estable y fundamental; CVE depende de NVD API reliability |
| **Active Recon (V1.5-8) separado** | Requiere Scope Guard auditado (V1.5-0); riesgo mayor, aislar |
| **Release Hardening (V1.5-11) al final** | Depende de CI (V1.5-0) y canal nuevo (V1.5-1) |
| **Eliminado V1.5-12/13 originales** | Cubiertos por V1.5-9/10/11 |

---

## O. PRIORITY MATRIX

| Clasificación | Bloques | Rationale |
|---------------|---------|-----------|
| **MUST HAVE** | V1.5-0, V1.5-1, V1.5-2, V1.5-3, V1.5-4, V1.5-5, V1.5-11 | Fundación CI/Seguridad/Update + OSINT core + Entity Graph + Investigation integration + Release hardening. Sin estos, no hay v1.5 coherente. |
| **SHOULD HAVE** | V1.5-6, V1.5-7, V1.5-8, V1.5-9 | Infrastructure, CVE, Active Recon, Correlation — alto valor, completan la visión OSINT + Network Intelligence. |
| **NICE TO HAVE** | V1.5-10 | BGP/VoIP UX polish — importante pero no bloqueante. |
| **DEFER** | GitHub OSINT, Crypto Intel, Telegram OSINT, Global Cyber Events, Aviation/Maritime/Weather/Satellite/CCTV/News | Fuera de scope "Network Analyzer + Intelligence + Investigation". Revisar en v1.6+. |
| **REJECT** | OSIRIS API as middleware, TeleGeography cable data, PCH IXP data, Shodan/Censys como dependencia hard | Licencias incompatibles, vendor lock-in, fuera de scope, duplican capacidades nativas. |

---

## P. RISKS / STOP CONDITIONS

### Riesgos Identificados

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|------------|
| **Licencia datos cables submarinos** | ALTA | P0 (legal) | Usar SOLO OSM/PeeringDB; NO usar TeleGeography ni forks que redistribuyan sus datos |
| **OSIRIS AGPL-3.0 viral** | MEDIA | P0 (legal) | NO depender de OSIRIS API; usar direct sources únicamente |
| **NVD API rate limit / downtime** | MEDIA | MEDIO | Cache local agresivo (24h+); fallback a CISA KEV CSV; offline mode |
| **PeeringDB API changes** | BAJA | MEDIO | Versionar client; cache local; fallback a export CSV mensual |
| **MaxMind license key rotation** | BAJA | ALTO (geoip offline) | Ya manejado en geoupdate (DPAPI, auto-check) |
| **Scope Guard bypass** | BAJA | CRÍTICO | Tests de integración obligatorios; audit log persistente |
| **Entity Graph performance (>10k nodes)** | MEDIA | MEDIO | Canvas/WebGL renderer; virtualización; lazy loading |
| **Update channel migration failure** | BAJA | CRÍTICO | Bridge release v1.4.1 obligatorio; testing en staging; rollback plan |

### STOP CONDITIONS (detener discovery e informar)

Se detectó durante discovery:
- ❌ Secreto real / credencial / nueva key → **NO** (gitleaks-report.json solo placeholders)
- ❌ License conflict P0 → **SÍ POTENCIAL** — TeleGeography cable data es P0 si se usara; reportado arriba como RECHAZAR
- ❌ Código público que no debería estarlo → **NO**
- ❌ Dependencia crítica no documentada → **NO** (go.mod revisado, todo documentado)
- ❌ Baseline divergente → **NO** (HEAD = origin/main = canónico)
- ❌ Corrupción Git → **NO**
- ❌ Updater v1.4 alterado → **NO** (selfupdate.go intacto)

**Veredicto STOP:** No hay condiciones de parada bloqueantes. Discovery puede completarse.

---

## Q. RECOMMENDED FIRST IMPLEMENTATION BLOCK

### **V1.5-0: Baseline / CI / Security Foundation** (2-3 días)

**Objetivo:** Establecer guardrails antes de escribir código v1.5.

**Entregables:**
1. **GitHub Actions Workflow** (`.github/workflows/ci.yml`):
   - `go build ./...` (Windows, Linux, macOS)
   - `go test ./... -race -count=1`
   - `govulncheck ./...`
   - `gitleaks detect --source=. --verbose`
   - `cyclonedx-gomod` → SBOM
   - `wails build` (matrix: windows-latest, ubuntu-latest, macos-latest)
2. **Branch Protection Rules** (via GitHub API o manual):
   - Require PR review (1+)
   - Require status checks (CI pass)
   - No force push to main
   - No delete main
   - Require linear history
3. **Dependabot** (`.github/dependabot.yml`): weekly, Go + npm + GitHub Actions
4. **CODEOWNERS** para main protection
5. **Security Policy** (`SECURITY.md`): responsible disclosure, supported versions

**Criterio de Done:** CI verde en main, branch protection activa, sin findings gitleaks/govulncheck críticos.

---

### Segundo Bloque: **V1.5-1: Update Channel Migration** (1-2 semanas)

Puede desarrollarse en paralelo con V1.5-2 una vez CI está verde.

---

## VEREDICTO FINAL

```
TRAZIP_V1_5_DISCOVERY_COMPLETE
READY_FOR_ROADMAP_APPROVAL
```

---

**Discovery completado.** No se ha implementado ninguna funcionalidad. No se ha modificado código productivo. No se han hecho commits. No se han creado tags. No se han publicado releases.

El reporte está listo para revisión y aprobación del roadmap antes de iniciar implementación.