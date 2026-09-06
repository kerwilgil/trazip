# TRAZIP — Inventario de dependencias

> Gate obligatorio (prompt maestro §4.3). Toda dependencia de runtime nueva se
> registra aquí **antes** de usarse, con licencia verificada. Solo se permiten
> licencias permisivas: MIT, BSD-2/3, Apache-2.0, ISC, Zlib, CC0.

Estado: `approved` · `experimental` · `rejected` · `replace`

## Runtime — Backend (Go)

| Dependencia | Versión | Licencia | Función | Estado |
|---|---|---|---|---|
| `github.com/wailsapp/wails/v2` | v2.13.0 | MIT | GUI desktop (WebView2/WebKit) + bindings Go↔TS | approved |
| `github.com/google/uuid` | v1.6.0 | BSD-3-Clause | IDs de sesión | approved |
| `golang.org/x/sys` | v0.46.0 | BSD-3-Clause | Detección de privilegios por plataforma (token Windows) | approved |
| `golang.org/x/net` (icmp/ipv4/ipv6) | v0.55.0 | BSD-3-Clause | Ping/Traceroute/MTR en macOS/Linux (ICMP + TTL) | approved |
| `github.com/gopacket/gopacket` (+pcapgo/layers) | v1.7.0 | BSD-3-Clause | Decodificación de paquetes y lectura PCAP/PCAPNG sin driver (§5.3) | approved |
| `github.com/oschwald/maxminddb-golang/v2` | v2.4.1 | ISC | Lookup MMDB GeoIP/ASN offline (§5.3) | approved |
| `codeberg.org/miekg/dns` | v0.6.84 | BSD-3-Clause | Consultas DNS crudas (SOA/CAA/EDNS0/DNSSEC) del DNS Toolkit (Fase 4, §5.3 — línea histórica en GitHub marcada `replace`) | approved |
| `github.com/nyaruka/phonenumbers` | v1.8.1 | MIT | Identificación de números telefónicos (país, tipo de línea, operador) — puerto Go de libphonenumber, con los metadatos compilados en el binario: el módulo Teléfono no hace ninguna petición de red | approved |
| `google.golang.org/protobuf` | v1.36.11 | BSD-3-Clause | Transitiva de `phonenumbers`: decodifica los metadatos de libphonenumber embebidos | approved |
| stdlib `net`, `net/netip`, `net/url`, `net/http`, `crypto/tls`, `crypto/x509`, `runtime`, `context` | go1.26 | BSD-3-Clause | Sockets, clasificación IP, resolución DNS básica, TLS/HTTP activos, cancelación | approved |

Las demás entradas en `go.mod` son transitivas de Wails (indirect) y no se
consumen directamente desde el código de TRAZIP.

## Runtime — Frontend

| Dependencia | Versión | Licencia | Función | Estado |
|---|---|---|---|---|
| `react` / `react-dom` | ^19.1 | MIT | UI | approved |
| `@fontsource-variable/inter` | ^5 | MIT (fuente SIL OFL 1.1) | Tipografía Inter self-hosted (woff2 variable, sin CDN) | approved |

Sin dependencias de routing, estado global ni UI kit: la navegación y el tema se
resuelven con estado local de React y CSS con tokens, para minimizar superficie
y tamaño (§4.2 "necesidad real frente a implementación pequeña propia").

### Assets vendored (no dependencia de runtime)

| Asset | Licencia | Uso | Nota |
|---|---|---|---|
| Iconos Reicon (14 SVG outline) | MIT © 2026 Dev Chauhan | Iconos del menú lateral | Solo se copiaron los 14 SVG usados en `frontend/src/components/icons.tsx`; NO se importa el paquete npm de 2700 iconos. Reicon se apoya en Solar Icons (CC BY 4.0) y Zappicon. |
| Marca TRAZIP (logo/banner) | Propiedad de Kerwil Gil | Branding | `frontend/src/assets/images/` (versiones con fondo transparente); originales en `imagen/` |

## Fuentes de datos descargables (opt-in, no van en el binario)

Listas que el operador descarga desde Settings / Datasets y que después se
consultan **en local**. Ninguna se baja sola, y cada URL fue verificada sirviendo
lo que declara antes de entrar al catálogo — el mismo criterio que dejó fuera a
Azure en `netclass` por rotar su enlace semanalmente.

| Fuente | URL | Uso | Nota |
|---|---|---|---|
| Spamhaus DROP | `https://www.spamhaus.org/drop/drop_v4.json` | Rangos que Spamhaus considera controlados por operaciones delictivas | JSON Lines con `cidr` y el identificador `SBL` de cada registro |
| Nodos de salida Tor | `https://check.torproject.org/torbulkexitlist` | Origen deliberadamente inatribuible | Lista publicada por el propio Tor Project |

**Evaluada y descartada:** `feodotracker.abuse.ch/downloads/ipblocklist.txt`
servía 5 entradas y llevaba cinco meses sin actualizarse. Una fuente así no
añade cobertura, añade la falsa sensación de haber comprobado algo.

## Aprobadas para fases siguientes (aún no importadas)

Se agregarán a la tabla de runtime cuando el módulo que las use entre en
construcción, no antes:

| Dependencia | Licencia | Fase | Uso |
|---|---|---|---|
| `golang.org/x/net/icmp`, `ipv4`, `ipv6` | BSD-3 | 1 | Motores propios de Ping/Traceroute/MTR |
| `github.com/gopacket/gopacket` | BSD-3 | 1–2 | Decodificación de paquetes y PCAP/PCAPNG |
| `github.com/oschwald/maxminddb-golang/v2` | ISC | 1 | Lookup MMDB GeoIP/ASN en camino crítico |

## Herramientas de dev (no van al binario)

| Herramienta | Uso |
|---|---|
| Go 1.26.5 | Compilador |
| Wails CLI v2.13.0 | `wails dev` / `wails build` / `wails generate` |
| Node 24 + npm 11, Vite 7, TypeScript 5.6 | Build del frontend |

## Prohibidas / descartadas

Ninguna importada. Referencias GPL/AGPL (p.ej. `traviscross/mtr`) quedan como
inspiración funcional, nunca como código enlazado (§5.3).
