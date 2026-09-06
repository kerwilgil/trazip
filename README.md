<div align="center">
  <img src="imagen/trazip_logo_horizontal_transparent.png" alt="TRAZIP" width="620">
  <h1>TRAZIP</h1>
  <p>
    Diagnóstico, observabilidad, análisis de tráfico e inteligencia IP/web para redes y VoIP.<br>
    Escritorio <strong>local-first</strong> sobre Go, Wails y React, sin telemetría ni analytics.
  </p>

  <p>
    <img src="https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&amp;logoColor=white" alt="Go 1.26+">
    <img src="https://img.shields.io/badge/Wails-2.13-DF0000" alt="Wails 2.13">
    <img src="https://img.shields.io/badge/React-19-61DAFB?logo=react&amp;logoColor=0B2239" alt="React 19">
    <img src="https://img.shields.io/badge/idiomas-ES%20%7C%20US-0F766E" alt="Español e inglés de Estados Unidos">
    <a href="./LICENSE"><img src="https://img.shields.io/badge/licencia-MIT-111827" alt="Licencia MIT"></a>
  </p>

  <p>
    <a href="https://github.com/kerwilgil/trazip-releases/releases/tag/v1.4.0"><strong>Descargar TRAZIP v1.4.0</strong></a>
  </p>
</div>

Fuente de verdad de arquitectura y alcance: [`TRAZIP_prompt_maestro.md`](./TRAZIP_prompt_maestro.md).

## Descargar

Este repositorio es privado (código fuente). Las descargas oficiales viven en
el canal público de distribución [kerwilgil/trazip-releases](https://github.com/kerwilgil/trazip-releases), separado a partir de v0.7.4 — ver
[Auto-Update seguro para Windows](#novedades-de-v074):

- **Windows Installer (recomendado):** [`trazip-amd64-installer.exe`](https://github.com/kerwilgil/trazip-releases/releases/download/v1.4.0/trazip-amd64-installer.exe), para instalación fija; puede solicitar UAC de Windows durante la instalación.
- **Portable:** [`TRAZIP-portable-1.4.0.zip`](https://github.com/kerwilgil/trazip-releases/releases/download/v1.4.0/TRAZIP-portable-1.4.0.zip), con `portable.txt` y datos junto a la aplicación; no requiere el directorio de datasets instalado.
- **Distribución técnica / actualizaciones:** `TRAZIP-1.4.0.exe` forma parte del contrato de actualización, pero no es la descarga principal para usuarios.
- **Verificación:** la [publicación v1.4.0](https://github.com/kerwilgil/trazip-releases/releases/tag/v1.4.0) incluye `update.json` + `update.json.sig` (manifiesto firmado Ed25519) y los SHA-256 de la app y el updater en las notas de la versión.
- **Npcap:** se instala por separado y no se incluye por sus restricciones de distribución/licencia.
- **macOS:** compilación nativa con `scripts/package_macos.sh` (sin Auto-Update todavía).

## Novedades de v1.4.0

- **Rotación de identidad de firma (cambio incompatible para el auto-update):** tras perderse la clave privada Ed25519 original de v1.3.2, v1.4.0 estrena una nueva identidad de firma (`a94f5016…`). Quien venga de **v1.3.2 o anterior instala v1.4.0 manualmente una vez**; desde v1.4.0 en adelante, Settings → Actualizaciones vuelve a funcionar con normalidad. El repositorio de distribución (`kerwilgil/trazip-releases`) no cambia.
- **BGP Intelligence, finalizado:** todas las pestañas completas — Resumen, Prefijos, Vecinos, Topología, Seguridad, Tiempo real, Histórico, BGPlay y Observatorio (país, Global/RIS, ASN, RPKI, Bogons). Topología con pan/zoom/arrastre estable y exportación SVG/PNG; tiempo real con aislamiento estricto de sesiones obsoletas.
- **UI/UX y accesibilidad:** patrón ARIA completo en todos los grupos de pestañas (`tablist`/`tab`/`tabpanel`), navegación por teclado (Tab/Flechas/Inicio/Fin), estilos `focus-visible` globales y soporte de `reduced-motion`.
- **i18n:** traducción al inglés completa de las cadenas de BGP Intelligence; sin español fijo en la UI visible.

Detalle completo en [`RELEASE_NOTES_v1.4.0.md`](./RELEASE_NOTES_v1.4.0.md).

## Novedades de v1.3.1

- **BGP Intelligence / Observatory:** observabilidad de ASN, prefijos y contexto por país/global cuando aplica; RIS Live en tiempo real para los flujos de prefijo/IP compatibles, histórico BGP y BGPlay. La evidencia de RPKI, MOAS y salud se presenta con su alcance: no declara automáticamente un “hijack” sin evidencia suficiente.
- **Topología BGP visual:** topología observada y determinista, con relaciones de camino AS como adyacencias observadas — no como inferencia comercial. Incluye hover/focus interactivo, zoom de 50–200 %, **Ajustar vista** y exportación SVG/PNG.
- **Live Capture:** captura Npcap/TZSP e interpretación por **Resumen**, **Cadenas** y **Hexadecimal**, con lectura L2/L3/L4, identificación segura de broadcast/multicast y metadata TLS visible sin presentar la carga cifrada como texto plano. Cuando falta evidencia, el protocolo de aplicación permanece sin identificar. La vista de datos densos aprovecha mejor el ancho disponible.
- **IP pública:** indicador de IP pública observada externamente mediante `api64.ipify.org`, con solicitud acotada y reintento explícito. No envía objetivos analizados ni datos de captura.
- **Datasets y almacenamiento:** en modo instalado, los datasets van a `%APPDATA%\TRAZIP\geolite`; en portable permanecen en `<portable>\data\geolite`. El uso normal e instalación de datasets no debería requerir abrir TRAZIP como administrador; el instalador sí puede solicitar UAC.
- **Experiencia:** mejoras de interfaz en español/inglés, descripciones y tooltips de módulos, y ajustes de layout.

## Novedades de v1.0.0

Primera versión mayor con diagnóstico correlacionado: Quick Diagnose 2.0
(DNS/alcance/ruta/propiedad/RPKI/TLS/HTTP/reputación en una sola conclusión,
modos Offline/Standard/Full), resumen de incidente en PCAP sobre la captura
completa, atribución correcta de encabezados SIP en llamadas VoIP con
intermediarios, confirmación de cambios de ruta persistentes en Monitor, un
espacio de Investigaciones que reúne resultados de todos esos módulos con
línea de tiempo, deduplicación, persistencia y reportes JSON/CSV/HTML/PDF, y
un Estado del producto (Product Health Check) local y offline para verificar
que TRAZIP mismo funciona antes de confiar en sus diagnósticos. Detalle
completo en [`RELEASE_NOTES_v1.0.0.md`](./RELEASE_NOTES_v1.0.0.md).

## Novedades de v0.7.4

Auto-Update seguro para Windows (primera versión que lo incluye — quien venga
de v0.7.3 instala esta una vez manualmente; desde acá en adelante,
Settings → Actualizaciones lo hace en la app): canal público de distribución
separado del código fuente, manifiesto firmado Ed25519, SHA-256 de app y
updater, HTTPS-only (incluida la URL inicial, no solo redirects), protección
anti-downgrade y anti-replay, descarga con límites y cancelación, updater
externo con rollback automático si el nuevo ejecutable no arranca, soporte
portable y standalone, errores de descarga visibles y reintentables, chequeo
automático configurable (activado por defecto, desactivable), y el fix del
tema "Sistema" en Windows/WebView2 detectado durante la propia auditoría de
esta feature.

## Novedades de v0.7.3

- **VoIP Calls**, reestructurado como herramienta diagnóstica: RTP por dirección (loss/jitter/MOS y métricas avanzadas), RTCP con Sender Report y Receiver Report correctamente separados, RTT RTCP estimado desde el punto de captura, correlación multi-SSRC, User-Agent/Server, GeoIP/ASN, comparación SDP↔RTP direction-aware y multi-media, diagnóstico basado en `model.Assessment`, y audio separado de video para que MOS e Histórico de calidad nunca mezclen ambos.
- **Interfaz:** modo de tema Light / Dark / System.

## Novedades de v0.7.2

- **WiFi/PPI:** lectura de canal desde Radiotap/HT, BSSID correcto según la dirección DS y validación estricta de coordenadas GPS.
- **PCAP Prism:** conserva correctamente las tramas 802.11 que ya incluyen un FCS válido.
- **Seguridad:** exportaciones CSV neutralizadas, historiales privados y protocolo de throughput endurecido para uso controlado en LAN.

- **Teléfono** (nuevo módulo): identifica cualquier número sin salir a internet — validez, país, operador y, lo que más pesa al enrutar, si la línea es **móvil, fija o VoIP**. Devuelve el E.164 canónico y el URI `tel:` que viaja en las cabeceras SIP. Los metadatos de libphonenumber van compilados en la app: un número es dato personal y no sale de la máquina.
- **Listas de amenazas**: Reputación ya no se limita a rangos bogon. Con las listas que descargues en Settings puede decir si una IP está en **Spamhaus DROP** o es un **nodo de salida de Tor**, citando siempre qué afirma cada fuente y cuánto restó a la puntuación. Se consultan en local: comprobar una dirección nunca revela cuál estás mirando. Y si no hay ninguna descargada, lo dice, en vez de dar un "limpio" que solo significaba que no se comprobó nada.
- **PCAP Analyzer** abre los sobres **TZSP**: una captura tomada en la máquina que recibe el stream de un router mostraba un único flujo UDP hacia el colector. Ahora se analiza el tráfico transportado, igual que si hubiera llegado en vivo — sobre un archivo real, 866 flujos donde antes había 1.
- **PCAP Analyzer** avisa cuando el archivo es de un medio que no sabe leer, con el número de link type para poder buscarlo, en vez de mostrar una lista de fallos por paquete sin explicación.
- **Registro de dominios (RDAP)**: consulta registrador, fechas de alta y vencimiento, estado y servidores de nombres contra el registro del TLD. Responde lo que "no resuelve" nunca dijo: un dominio puede estar registrado y no tener registro A, o haber vencido. Si preguntás por un subdominio, informa cuál es el dominio registrado del que cuelga en vez de hacer pasar sus datos por propios. En GeoIP Map bajo la consulta y en Web Intelligence → RDAP/BGP.
- **Corregido**: consultar un dominio que no resuelve en GeoIP Map detenía la vista en vez de informarlo. Ahora muestra la nota de resolución fallida, que es la respuesta útil.
- **Salud de red**: detección pasiva de fallos que afectan a todo el segmento — bucles de conmutación, tormentas de broadcast, IP duplicadas y servidores DHCP múltiples — más un inventario de equipos que se anuncian por MNDP, LLDP o CDP. Disponible sobre archivo en PCAP Analyzer y en tiempo real en Live Capture, con la fuente que prefieras: interfaz local o TZSP desde un router.
- **MAC Lookup**: consulta el fabricante de cualquier dirección MAC contra los registros oficiales del IEEE (MA-L, MA-M y MA-S), sin salir a internet. Explica qué prefijo coincidió y de qué registro, y distingue las direcciones que no pueden tener fabricante: difusión, multicast y las administradas localmente.
- **Calculadora IP**: subnetting, planificación VLSM, agregación de prefijos y desglose completo para IPv4 e IPv6, con entrega directa del rango al LAN Explorer.
- **Conexiones**: sockets TCP/UDP activos de la propia máquina con el proceso dueño de cada uno y el país de cada IP remota, leyendo tablas del sistema operativo sin enviar nada ni requerir privilegios.
- **Categorías de red**: identifica si una IP pertenece a un cloud, una CDN o un ISP usando las listas que los propios proveedores publican, en lugar de deducirlo del nombre de la organización.
- Ping, Traceroute y MTR muestran la dirección de destino antes de la primera sonda, de modo que sigue siendo visible aunque el host no responda.

Historial completo por versión en [`CONTEXT-trazip.md`](./CONTEXT-trazip.md).

## Stack

- **Backend:** Go 1.26, paquetes internos con contratos pequeños, `context.Context` para cancelación, event bus tipado.
- **Desktop:** Wails v2 + React 19 + TypeScript + Vite. Dashboard sin servidor HTTP público.
- **Sin dependencias de runtime fuera del allowlist permisivo** (MIT/BSD/Apache/ISC). Ver [`docs/dependencies.md`](./docs/dependencies.md).

## Estado actual

| Fase | Módulo | Estado |
|---|---|---|
| 0 | Base técnica: modelo de datos, event bus, scope guard, sesiones | ✅ |
| 1 | Clasificación IP offline (RFC) + Quick Diagnose (DNS) | ✅ |
| 1 | Ping · Traceroute · MTR (motores propios) | ✅ |
| 1 | PCAP reader · Flow engine · Raw Traffic GeoIP · Endpoints observados | ✅ |
| 2 | Captura live · Scanner · LAN · metadata DNS/TLS/HTTP | ✅ |
| 3 | VoIP SIP/SDP/RTP/RTCP · MOS · audio PCMU | ✅ |
| 4 | Web Intelligence · RDAP/BGP/RPKI · Reputación | ✅ |
| 5 | Throughput nativo TCP/UDP (cliente/servidor, carga/descarga/bidireccional) | ✅ |
| 5 | Monitor histórico · Reportes · Modo laboratorio | ✅ |
| 5+ | Histórico de calidad VoIP · perfil base fijo · Prueba de carga HTTP | ✅ |
| 5+ | Recepción TZSP · Top Talkers · escaneo WiFi + canal recomendado | ✅ |
| 5+ | Informe de sesión (HTML/PDF/CSV/JSON) · notificaciones nativas del Monitor | ✅ |
| 5+ | Detección de dispositivos nuevos en LAN · emisor TZSP headless (`cmd/tzsp-sender`) | ✅ |
| 6 | BGP Intelligence / Observatory (ASN, prefijos, evidencia RPKI/MOAS/salud) | ✅ |
| 6 | RIS Live en tiempo real · histórico BGP · BGPlay | ✅ |
| 6 | Topología BGP observada, zoom y exportación SVG/PNG | ✅ |
| 6 | Live Capture: interpretación Resumen · Cadenas · Hexadecimal | ✅ |
| Purple Team | Reconocimiento controlado · detección pasiva · validación segura de servicios | ✅ |
| Purple Team | Confianza LAN · postura WiFi · auditoría VoIP · política de exposición | ✅ |
| Purple Team | Scorecard de laboratorio · OSINT local/opt-in | ✅ |

Interfaz: dashboard con navegación completa (§11), tema oscuro/claro adaptable y
paleta de marca (navy `#071D49` · azul eléctrico `#1267F5` · cyan `#18C7F4`).

Distribución: **portable** (`TRAZIP-portable-1.4.0.zip`, ZIP autocontenido con
`portable.txt` → todos los datos en `.\data`) o **instalador NSIS**
(`trazip-amd64-installer.exe`) para instalación fija. En modo instalado, los datasets
residen por usuario en `%APPDATA%\TRAZIP\geolite`; en portable, bajo
`<portable>\data\geolite`. Npcap se instala aparte (su licencia no permite redistribuirlo).
En macOS: **`trazip.app`** nativo (Wails/WKWebView) empaquetado en ZIP con
`scripts/package_macos.sh`.

## Desarrollo

Requisitos: Go 1.26+, Node 20+ y Wails CLI v2. En Windows además WebView2; en
macOS, Xcode Command Line Tools (cgo). La captura live usa Npcap en Windows y el
libpcap del sistema en macOS (acceso a `/dev/bpf*` vía sudo o ChmodBPF de Wireshark).

```bash
    wails dev            # app en vivo con hot-reload del frontend
    wails build          # binario redistribuible (.exe en Windows, .app en macOS)
    wails build -nsis    # + instalador Windows (requiere NSIS: winget install NSIS.NSIS)
```

Empaquetado macOS (ZIP con `trazip.app`, `tzsp-sender`, LEEME y hashes):

```bash
go build -o build/bin/tzsp-sender ./cmd/tzsp-sender
bash scripts/package_macos.sh    # → build/bin/TRAZIP-macos-<version>-<arch>.zip
```

Notas macOS: mismo codebase vía build tags (`_windows.go` / `_darwin.go`); los
SSID del escaneo WiFi aparecen redactados hasta otorgar permiso de Ubicación a
la app; las notificaciones usan el Centro de notificaciones y el almacén seguro
usa el Keychain del usuario.

El instalador (`build/bin/trazip-amd64-installer.exe`) **no incluye Npcap** —
su licencia gratuita no permite redistribuirlo. Para captura en vivo, instalarlo
aparte desde npcap.com (la app lo detecta y avisa si falta; todo lo demás
funciona sin él).

Emisor headless para ver tráfico de otra máquina desde TRAZIP:

```bash
go build -o build/bin/tzsp-sender.exe ./cmd/tzsp-sender
tzsp-sender -listar
tzsp-sender -interfaz "\Device\NPF_{...}" -destino <ip-trazip>:37008 -autorizado
```

Backend:

```bash
go test ./...  # suite de tests (clasificación IP, etc.)
go vet ./...
```

Regenerar bindings TS tras cambiar la API Go:

```bash
wails generate module
```

## Estructura

```
cmd/trazip/            (pendiente) CLI que comparte el core
cmd/tzsp-sender/       emisor headless: captura local → TZSP/UDP → TRAZIP remoto
internal/model/        entidades centrales: Endpoint, Flow, Evidence, Assessment
internal/events/       event bus tipado con backpressure, consumido por Wails/CLI
internal/scope/        scope guard aplicado en backend a operaciones activas
internal/session/      orquestador UUID: context + bus + scope + cancelación
internal/api/          fachada backend expuesta a GUI (Wails) y CLI
internal/intel/classify/  IP Classification Engine offline
internal/intel/netclass/  categoría de red (cloud/CDN/ISP) desde listas oficiales
internal/intel/oui/       fabricante por MAC desde los registros IEEE
internal/intel/threatfeed/ listas publicas de rangos con abuso conocido (opt-in)
internal/phoneintel/      identificacion de numeros telefonicos (offline)
internal/detection/       detectores pasivos: barridos (scandetect) y capa 2 (netdiag)
internal/connmon/         sockets activos de la máquina con su proceso dueño
internal/ipcalc/          calculadora IP: subnetting, VLSM, agregación
internal/throughput/      pruebas de throughput TRAZIP TCP/UDP (cliente y servidor)
frontend/              React + TS (dashboard)
docs/                  dependencias, arquitectura
```

## Seguridad y privacidad

Herramienta **defensiva y de pentesting autorizado**. Las funciones activas exigen
un alcance autorizado antes de ejecutarse (scope guard). No implementa explotación,
fuerza bruta, evasión, MITM automático ni DDoS. Detalle en el prompt maestro §3, §12.

TRAZIP es local-first, pero no todo funciona offline: solo las funciones que requieren
datos externos hacen consultas explícitas. El indicador de IP pública consulta
`api64.ipify.org`; las funciones BGP usan RIPEstat/RIS cuando corresponde. Las capturas
de paquetes no se envían a esos servicios. La evidencia se muestra con sus límites y no
convierte puertos en atribución de malware ni datos cifrados en contenido descifrado.

## Autor y licencia

Creado y mantenido por [Kerwil Gil](https://github.com/kerwilgil).

TRAZIP se distribuye bajo la [Licencia MIT](./LICENSE). Copyright © 2026 Kerwil Gil.
