# TRAZIP v0.7.4

Auto-Update seguro para Windows, integrado a la aplicación por primera vez. El diseño y la implementación pasaron dos rondas de auditoría independiente antes de este cierre; los hallazgos de cada una quedan documentados en `CONTEXT-trazip.md`.

**Los usuarios de v0.7.3 deben instalar v0.7.4 manualmente una vez. A partir de v0.7.4, las versiones futuras pueden instalarse desde Settings → Actualizaciones.**

## Auto-Update

- Canal de distribución público separado del código fuente (`kerwilgil/trazip-releases`): solo binarios, checksums y manifiesto firmado — nunca código, configuración ni datos privados.
- Manifiesto `update.json` firmado con Ed25519 (`crypto/ed25519` de la librería estándar, sin dependencia nueva); la app verifica la firma antes de confiar en cualquier campo del manifiesto.
- SHA-256 verificado de forma independiente tanto para el ejecutable de la app como para el helper `trazip-updater.exe` — cada descarga se re-verifica contra el hash firmado, nunca se confía solo en que la petición HTTP haya devuelto 200.
- HTTPS obligatorio de punta a punta: la URL inicial de cada asset (manifiesto, firma, app, updater) debe ser HTTPS, y cualquier redirect que intente degradar a HTTP se rechaza — no solo los redirects, la URL de partida también.
- Protección anti-downgrade (nunca se ofrece como actualización una versión igual o más vieja que la instalada) y anti-replay (una release firmada pero más vieja que la última observada por esa misma instalación se rechaza, aunque siga siendo más nueva que la versión actual).
- Descarga a archivo `.partial` con límite de tamaño, verificación de tamaño exacto contra el manifiesto firmado, y cancelación limpia sin dejar archivos huérfanos.
- Helper externo `trazip-updater.exe` (Windows no permite que un `.exe` en ejecución se reemplace a sí mismo) con rollback automático: si el nuevo ejecutable no llega a arrancar, se restaura el anterior.
- Soporte tanto para instalación portable (reemplazo in-place) como standalone (`.exe` suelto descargado directamente) — un standalone nunca depende de tener el updater preinstalado, siempre usa el que se descargó y verificó junto con la actualización.
- Errores de descarga reales (hash incorrecto, fallo de red, disco) quedan visibles y son reintentables; una cancelación deliberada del usuario nunca se muestra como una falla.
- Comprobación automática configurable desde Settings → Actualizaciones (activada por defecto, con aviso claro de qué se envía y qué no — nunca capturas, direcciones analizadas, IPs, hostname ni ID de máquina).

## Interfaz

- Corregido: el tema "Sistema" en Windows no seguía correctamente el modo oscuro/claro configurado en Windows — WebView2 no sincroniza de forma confiable su `prefers-color-scheme` con ese ajuste. TRAZIP ahora lee el mismo valor de registro que usa la propia barra de título de Windows como fuente autoritativa, con `matchMedia` solo como respaldo cuando no hay forma de saberlo (por ejemplo, otras plataformas).

## Privacidad

- Documentación de privacidad corregida para reflejar con precisión el comportamiento real: el chequeo de actualizaciones es una llamada de red visible y desactivable, no algo oculto — se documenta explícitamente qué envía (nada del análisis del usuario) y qué revela naturalmente cualquier petición HTTP (IP de origen, User-Agent).

## Limitaciones conocidas

- Auto-Update integrado está disponible actualmente solo en Windows. macOS sigue requiriendo descarga manual.
- Sin soporte para instalaciones elevadas (Program Files sin permisos de escritura) todavía — TRAZIP detecta el caso y ofrece la descarga manual en vez de fallar a mitad de un reemplazo.
