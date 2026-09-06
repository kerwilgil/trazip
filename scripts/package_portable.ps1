# Empaqueta el build de Wails en una carpeta portable limpia y estructurada,
# lista para copiar a un pendrive o pasar a un colega en la LAN.
#
# Estructura generada:
#   TRAZIP-<version>.exe
#   TRAZIP-<version>.exe.sha256
#   TRAZIP-portable-<version>/
#     TRAZIP.exe            la app
#     portable.txt          marcador: hace que TRAZIP guarde TODO en .\data
#     LEEME.txt             guia rapida
#     herramientas/
#       tzsp-sender.exe     emisor headless para capturar desde otra maquina
#       trazip-updater.exe  helper de auto-actualizacion (reemplaza el exe)
#     capturas/             carpeta sugerida para guardar .pcap del sitio
#     SHA256SUMS.txt        hash de cada ejecutable (verificacion de integridad)
#
# Uso:
#   wails build -clean
#   go build -o build\bin\tzsp-sender.exe .\cmd\tzsp-sender
#   go build -o build\bin\trazip-updater.exe .\cmd\trazip-updater
#   .\scripts\package_portable.ps1 [-Version 0.5.0]
#
# Si no se pasa -Version, se toma del ultimo tag de git (sin la 'v'), o la
# fecha si no hay tags.

param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not $Version) {
    $tag = (git describe --tags --abbrev=0 2>$null)
    if ($tag) { $Version = $tag -replace '^v', '' }
    else { $Version = (Get-Date -Format "yyyy.MM.dd") }
}

$exePath = Join-Path $root "build\bin\TRAZIP.exe"
if (-not (Test-Path $exePath)) {
    throw "No se encontro $exePath - corre 'wails build -clean' primero."
}
$senderPath = Join-Path $root "build\bin\tzsp-sender.exe"
$haveSender = Test-Path $senderPath
$updaterPath = Join-Path $root "build\bin\trazip-updater.exe"
if (-not (Test-Path $updaterPath)) {
    # Fail closed, not just a warning: LEEME.txt and la propia estructura
    # documentada de este paquete prometen herramientas\trazip-updater.exe.
    # Publicar un ZIP que no lo trae es publicar contenido distinto del que
    # el paquete dice tener.
    throw "No se encontro $updaterPath - corre 'go build -o build\bin\trazip-updater.exe .\cmd\trazip-updater' antes de empaquetar."
}

$distRoot = Join-Path $root "dist"
$pkgName = "TRAZIP-portable-$Version"
$pkgDir = Join-Path $distRoot $pkgName

# Copia standalone con nombre versionado, tal como se publica en GitHub.
$releaseExeName = "TRAZIP-$Version.exe"
$releaseExePath = Join-Path $distRoot $releaseExeName
Copy-Item $exePath -Destination $releaseExePath -Force
$releaseExeHash = (Get-FileHash -Algorithm SHA256 $releaseExePath).Hash
Set-Content -Path "$releaseExePath.sha256" -Value "$releaseExeHash  $releaseExeName" -Encoding utf8

if (Test-Path $pkgDir) { Remove-Item -Recurse -Force $pkgDir }
New-Item -ItemType Directory -Force -Path $pkgDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $pkgDir "herramientas") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $pkgDir "capturas") | Out-Null

Copy-Item $exePath -Destination (Join-Path $pkgDir "TRAZIP.exe")
if ($haveSender) {
    Copy-Item $senderPath -Destination (Join-Path $pkgDir "herramientas\tzsp-sender.exe")
}

# herramientas\trazip-updater.exe viaja como utilidad offline/de respaldo —
# el mecanismo de auto-actualizacion en si mismo NO depende de esta copia:
# App.InstallUpdate (app.go) siempre usa el trazip-updater.exe recien
# descargado y verificado por SHA-256 junto con la actualizacion, nunca
# uno que ya estuviera en disco.
Copy-Item $updaterPath -Destination (Join-Path $pkgDir "herramientas\trazip-updater.exe")

# El marcador portable.txt hace que TRAZIP guarde config/monitores/historico/
# GeoLite2 en .\data junto al exe, en vez de %AppData%. Asi el USB no deja
# rastro en la maquina ajena y los datos viajan con la app.
Set-Content -Path (Join-Path $pkgDir "portable.txt") `
    -Value "No borrar. Este archivo activa el modo portable: TRAZIP guarda todos sus datos en la carpeta .\data junto al ejecutable." `
    -Encoding utf8

# Placeholder para que la carpeta capturas viaje aunque este vacia.
Set-Content -Path (Join-Path $pkgDir "capturas\.gitkeep") -Value "" -Encoding utf8

$senderDoc = if ($haveSender) {
@"

herramientas\tzsp-sender.exe - ver trafico de OTRA maquina:
  Copia tzsp-sender.exe a la maquina remota (Windows con Npcap) y corre:
    tzsp-sender.exe -listar
    tzsp-sender.exe -interfaz "<NPF de -listar>" -destino <IP-de-esta-PC>:37008 -autorizado
  En TRAZIP (esta PC): Live Capture -> Recibir TZSP en 0.0.0.0:37008.
  El trafico remoto llega con el mismo analisis (apps, SNI, WebSocket).
"@
} else { "" }

$readme = @"
TRAZIP - portable ($Version)

Ejecutable unico, sin instalador. Doble clic en TRAZIP.exe para arrancar.

MODO PORTABLE ACTIVO:
  Este paquete incluye 'portable.txt', que hace que TRAZIP guarde TODA su
  configuracion, historial de monitores, historico VoIP y datasets GeoLite2 en
  la subcarpeta .\data junto al ejecutable - NO en %AppData%. Podes llevar toda
  la carpeta en un USB: los datos viajan con la app y no queda rastro en la
  maquina donde la corras. Si borras portable.txt, TRAZIP vuelve al modo normal
  (datos por usuario de Windows en %AppData%\TRAZIP).

Requisitos:
  - Windows 10/11 64-bit + WebView2 (preinstalado en Windows 10/11 actualizado).
  - Npcap (https://npcap.com) SOLO para Captura en vivo. Sin Npcap el resto
    funciona igual (lectura PCAP, Ping, Traceroute, MTR, Throughput, VoIP, etc.).
    Npcap no se incluye por su licencia (no permite redistribucion).
$senderDoc
GeoLite2 (pais/ciudad/ASN): se instala desde Settings dentro de la app.

Actualizaciones: Settings -> Actualizaciones comprueba kerwilgil/trazip-releases
(un repositorio publico solo de binarios, separado del codigo fuente). Por
defecto TRAZIP hace esta comprobacion automaticamente al iniciar (maximo una
vez cada 24 horas); podes desactivarla desde Settings. Descargar e instalar
siempre requieren un clic explicito, nunca ocurren solos. La descarga se
verifica con SHA-256 y firma Ed25519 antes de instalarse.

Alternativa: existe tambien un instalador (trazip-amd64-installer.exe) para
quien prefiera instalarla fija en su maquina con acceso directo y desinstalador.

Privacidad: el analisis de capturas y diagnosticos es 100% local y TRAZIP no
envia telemetria. La comprobacion de actualizaciones (activada por defecto,
desactivable en Settings) consulta unicamente el canal oficial de releases
para saber que version esta disponible - nunca envia capturas, direcciones
analizadas, hostname ni ningun identificador de la maquina. Como cualquier
peticion HTTP, esa consulta revela naturalmente la IP de origen y un
User-Agent "TRAZIP/<version>" al servidor, igual que visitar cualquier
pagina web; eso no es telemetria de TRAZIP.
"@
Set-Content -Path (Join-Path $pkgDir "LEEME.txt") -Value $readme -Encoding utf8

# SHA256 de cada ejecutable, para verificar integridad si se comparte suelto.
$sumsLines = @()
Get-ChildItem -Path $pkgDir -Recurse -Filter *.exe | ForEach-Object {
    $rel = $_.FullName.Substring($pkgDir.Length + 1)
    $hash = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash
    $sumsLines += "$hash  $rel"
}
Set-Content -Path (Join-Path $pkgDir "SHA256SUMS.txt") -Value $sumsLines -Encoding utf8

$zipPath = Join-Path $distRoot "$pkgName.zip"
if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
# Se comprime la carpeta, no su contenido: al extraer queda
# TRAZIP-portable-<version>\ y no un puñado de archivos sueltos. Con dos
# versiones descargadas, el contenido extraido era indistinguible porque el
# ejecutable se llama igual en todas.
Compress-Archive -Path $pkgDir -DestinationPath $zipPath

# SHA256 del ZIP completo (lo que se sube al release).
$zipHash = (Get-FileHash -Algorithm SHA256 $zipPath).Hash
Set-Content -Path "$zipPath.sha256" -Value "$zipHash  $pkgName.zip" -Encoding utf8

Write-Host "Version: $Version"
Write-Host "EXE:     $releaseExePath"
Write-Host "SHA256:  $releaseExePath.sha256"
Write-Host "Carpeta: $pkgDir"
Write-Host "Zip:     $zipPath"
Write-Host "SHA256:  $zipPath.sha256"
if (-not $haveSender) {
    Write-Host "AVISO: tzsp-sender.exe no encontrado - corre 'go build -o build\bin\tzsp-sender.exe .\cmd\tzsp-sender' antes para incluirlo."
}
