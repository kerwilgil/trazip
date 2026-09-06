#!/bin/bash
# Empaqueta el build de Wails para macOS en un ZIP listo para distribuir.
#
# Estructura generada:
#   TRAZIP-macos-<version>-<arch>/
#     TRAZIP.app            la app (arrastrar a /Applications, o correr en sitio)
#     LEEME.txt             guía rápida (permisos BPF, Ubicación para SSIDs)
#     herramientas/
#       tzsp-sender         emisor headless para capturar desde otra máquina
#     capturas/             carpeta sugerida para guardar .pcap del sitio
#     SHA256SUMS.txt        hash de cada binario (verificación de integridad)
#
# Uso:
#   wails build -clean
#   go build -o build/bin/tzsp-sender ./cmd/tzsp-sender
#   bash scripts/package_macos.sh [version]
#
# Si no se pasa versión, se toma del último tag de git (sin la 'v'), o la
# fecha si no hay tags.
#
# Firma/notarización (opcional, requiere Apple Developer Program, 99 USD/año):
#   codesign --deep --force --options runtime -s "Developer ID Application: ..." build/bin/trazip.app
#   xcrun notarytool submit <zip> --keychain-profile <perfil> --wait
#   xcrun stapler staple build/bin/trazip.app
# Hoy el .app va firmado ad-hoc (Signature=adhoc, sin TeamIdentifier), así que
# `spctl -a -t exec` lo rechaza y el usuario tiene que autorizarlo a mano una
# vez — ver LEEME.txt. Decisión pendiente: se notariza cuando la demanda de
# usuarios macOS lo justifique. Si se hace, revalidar con hardened runtime la
# captura BPF y las llamadas a security(1) y osascript(1).

set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:-}"
if [[ -z "$version" ]]; then
    version="$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')" || true
    [[ -z "$version" ]] && version="$(date +%Y.%m.%d)"
fi
arch="$(uname -m)"

app="build/bin/trazip.app"
[[ -d "$app" ]] || { echo "No se encontró $app — corre 'wails build -clean' primero." >&2; exit 1; }

pkg="TRAZIP-macos-${version}-${arch}"
out="build/bin/$pkg"
appout="$out/TRAZIP.app"
rm -rf "$out" "build/bin/$pkg.zip"
mkdir -p "$out/herramientas" "$out/capturas"

# El bundle de Wails se genera como build/bin/trazip.app (minúscula, del
# "name" de wails.json). Dentro del paquete se distribuye como TRAZIP.app,
# que ya coincide con CFBundleName y CFBundleExecutable del propio bundle.
cp -R "$app" "$appout"

if [[ -f build/bin/tzsp-sender ]]; then
    cp build/bin/tzsp-sender "$out/herramientas/"
fi

cat > "$out/LEEME.txt" <<EOF
TRAZIP $version — macOS ($arch)
================================

Inicio rápido
  1. Arrastra TRAZIP.app a /Applications (o ábrela desde esta carpeta).
  2. TRAZIP no está notarizada por Apple, así que la primera apertura hay que
     autorizarla a mano. Una sola vez; después abre con doble clic normal.

     macOS 15 Sequoia o posterior:
       a) Doble clic en TRAZIP.app. macOS la bloquea — es lo esperado.
       b) Ajustes del Sistema → Privacidad y seguridad → bajar hasta
          "Seguridad" → "Abrir de todos modos" → confirmar con Abrir.
       (El truco de clic derecho → Abrir ya NO funciona: Apple lo quitó
        en Sequoia.)

     macOS 14 Sonoma o anterior:
       Clic derecho sobre TRAZIP.app → Abrir → Abrir.

Captura en vivo (permisos BPF)
  macOS restringe /dev/bpf* a root. Opciones:
    a) Instalar el helper ChmodBPF (incluido con Wireshark) — captura sin sudo.
    b) sudo /Applications/TRAZIP.app/Contents/MacOS/TRAZIP
  Todo lo demás (PCAP, ping, traceroute, MTR, LAN, VoIP, reportes) funciona
  sin privilegios.

Nombres de redes WiFi (SSID)
  macOS redacta los SSID ajenos hasta que otorgues permiso de Ubicación a
  TRAZIP (Ajustes del Sistema → Privacidad y seguridad → Ubicación). Canal,
  banda, seguridad y señal se muestran igual sin el permiso.

herramientas/tzsp-sender
  Emisor headless: captura en otra máquina y envía el tráfico a TRAZIP.
    ./tzsp-sender -listar
    sudo ./tzsp-sender -interfaz en0 -destino <ip-trazip>:37008 -autorizado

Verificación de integridad
  shasum -a 256 -c SHA256SUMS.txt
EOF

(
    cd "$out"
    shasum -a 256 TRAZIP.app/Contents/MacOS/TRAZIP > SHA256SUMS.txt
    [[ -f herramientas/tzsp-sender ]] && shasum -a 256 herramientas/tzsp-sender >> SHA256SUMS.txt
)

# Sin esto el ZIP arrastra archivos AppleDouble (._TRAZIP, .__CodeSignature):
# macOS guarda los xattr de cada archivo en un fichero hermano al comprimir.
# Aqui el unico xattr es com.apple.provenance, que macOS pone al copiar y no
# forma parte de la firma — la del .app vive en Contents/_CodeSignature y
# embebida en el Mach-O, asi que limpiar no la invalida.
xattr -cr "$out"

# --sequesterRsrc: si aun quedara algun resource fork, va a __MACOSX/ en vez
# de mezclarse con los archivos reales del bundle.
ditto -c -k --sequesterRsrc --keepParent "$out" "build/bin/$pkg.zip"

codesign --verify --deep --strict "$appout" 2>/dev/null \
    || echo "Aviso: la firma de $appout no verifica." >&2

echo "Listo: build/bin/$pkg.zip"
