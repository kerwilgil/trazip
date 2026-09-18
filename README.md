# TRAZIP

**Network Analyzer & Intelligence Toolkit**

TRAZIP es una herramienta de análisis e inteligencia de red con enfoque local
(local-first): diagnóstico de red, análisis de capturas PCAP, GeoIP/ASN,
diagnóstico VoIP y observabilidad BGP — sin enviar tus capturas a ningún
servidor.

---

This repository is the official **distribution** channel for TRAZIP.
It publishes releases with signed update manifests and verified binaries.
It is not a source development repository.

## Releases

Las releases oficiales de distribución publicadas en este repositorio están
disponibles bajo **GitHub Releases**:

- https://github.com/kerwilgil/trazip/releases

Las releases puente de compatibilidad **v1.4.0** y **v1.4.1** permanecen
disponibles a través de `kerwilgil/trazip-releases` durante el período de
compatibilidad (los clientes v1.4.0 actualizan desde ese canal).

## Verificación / Verification

El material de integridad varía por release y puede incluir `SHA256SUMS.txt`,
archivos `.sha256` por asset, y/o el manifiesto de actualización firmado
(`update.json` + `update.json.sig`).

- **SHA-256**: compara el hash publicado con tu descarga:
  - Windows PowerShell: `Get-FileHash .\TRAZIP-x.y.z.exe -Algorithm SHA256`
  - macOS/Linux: `shasum -a 256 TRAZIP-x.y.z`
- **Manifiesto firmado**: las actualizaciones automáticas se validan con
  firma Ed25519 (`update.json` + `update.json.sig`) y SHA-256 por asset antes
  de instalarse.
- Clave pública de verificación de actualizaciones (Ed25519):
  `a94f501667c8de95e7c056a1d6493f61cf10d6849e155f32837fcf543a9cc149`

## Plataformas

- Windows 10/11 x64 (binario principal; la captura en vivo requiere Npcap
  instalado por separado)
- macOS ARM64 (paquete `.app`)

## Documentos

- [LICENSE](LICENSE) — términos de uso del software.
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — avisos y licencias de
  componentes de terceros incluidos en los binarios (textos completos en
  `THIRD_PARTY_LICENSES/`).
- [SECURITY.md](SECURITY.md) — cómo reportar vulnerabilidades de forma
  responsable (divulgación coordinada; **no** abras un issue público para
  vulnerabilidades).
- [CHANGELOG.md](CHANGELOG.md) — historial de versiones publicadas.
- [docs/legal/HISTORICAL_LICENSING.md](docs/legal/HISTORICAL_LICENSING.md) —
  política de licencias históricas.

> Las versiones antiguas distribuidas bajo licencia MIT conservan plenamente
> los derechos concedidos bajo MIT para esas copias.
