# TRAZIP v0.7.2

Versión de mantenimiento y seguridad posterior a v0.7.1. Conserva compatibilidad de uso y formatos, y corrige problemas encontrados durante una auditoría integral del repositorio.

## Seguridad

- Se eliminó del estado actual del repositorio un archivo de credenciales y se añadieron reglas para impedir que vuelva a versionarse. La credencial afectada debe rotarse y el historial antiguo debe purgarse por separado.
- Las exportaciones CSV neutralizan celdas que una hoja de cálculo podría interpretar como fórmulas.
- Los historiales de Monitor y calidad VoIP validan sus identificadores y usan permisos privados en sistemas POSIX.
- Npcap se carga mediante una ruta absoluta obtenida desde la API de Windows; macOS ejecuta `lsof` mediante ruta absoluta y con timeout.
- Las dependencias de build `nanoid` y `postcss` se actualizaron a versiones corregidas. `npm audit` informa cero vulnerabilidades.

## Red y estabilidad

- Throughput limita conexiones simultáneas, autentica los streams TCP con tokens aleatorios y valida token/origen en UDP para impedir secuestro o reflexión ciega.
- El código de acceso de Throughput falla cerrado si el sistema no puede generar entropía y nunca vuelve a la UI en los resultados.
- TZSP fija la captura al primer emisor válido y limita el trabajo de decodificación por segundo.
- HTTP Load mantiene una muestra estadística acotada en lugar de conservar y ordenar todas las latencias.
- La exportación de audio VoIP limita la duración reconstruida y deja de retener paquetes completos en memoria.

## Correcciones funcionales

- Las operaciones asíncronas usan un puente de eventos estable con backlog acotado, evitando estados de UI bloqueados y listeners acumulados.
- PCAP Prism conserva correctamente tramas 802.11 que ya incluyen FCS.
- BSSID respeta los indicadores ToDS/FromDS.
- El canal WiFi se obtiene también desde HT Operation y Radiotap para redes de 5/6 GHz.
- PPI rechaza latitudes fuera de ±90° sin descartar longitudes válidas.
- Metadata, enlaces y empaquetado quedan sincronizados con v0.7.2; Wails usa `npm ci`.

## Validación

- Suite Go completa, `go vet`, `go mod verify` y `govulncheck`.
- `npm audit` y build TypeScript/Vite.
- Build Wails Windows/amd64 y compilación cruzada Linux/amd64.
- Pruebas de regresión para CSV, traversal, límites de memoria, throughput TCP/UDP, TZSP, Prism/FCS, BSSID, canales y GPS.

## Riesgos externos pendientes

- Rotar la credencial eliminada y coordinar la purga del historial Git remoto.
- Los artefactos se publican con SHA-256, pero siguen sin firma Authenticode/notarización porque el proyecto no dispone todavía de certificados de firma.
