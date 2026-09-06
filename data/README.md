# data/ — Datasets externos

TRAZIP consume datasets locales versionados. **No se incluyen en el repo** (licencia
MaxMind y tamaño). Se pueden instalar desde **Settings / Datasets** o colocar aquí manualmente.

## GeoIP / ASN (MaxMind GeoLite2)

1. Cuenta gratuita: https://www.maxmind.com/en/geolite2/signup
2. Descarga en formato **MMDB**: *GeoLite2 City* y *GeoLite2 ASN*.
3. Copia aquí con estos nombres exactos:
   - `GeoLite2-City.mmdb`
   - `GeoLite2-ASN.mmdb`

TRAZIP los detecta al iniciar. Sin ellos, GeoIP/ASN degrada silenciosamente
(el resto de la app funciona igual).

### Actualización automática

La vista **Settings / Datasets** permite guardar el Account ID y una License
Key de MaxMind, comprobar versiones e instalar actualizaciones sin descargar
archivos manualmente. En Windows la License Key se cifra con DPAPI para el
usuario actual y se guarda fuera del repositorio. La opción automática realiza
como máximo una comprobación cada 24 horas y solo descarga cuando hay una
versión más reciente. Cada archivo se verifica con SHA256 y se valida como MMDB
antes de reemplazar la copia activa.

> Licencia: GeoLite2 es de MaxMind bajo su EULA; se trata como dato externo
> versionado, no como código (prompt maestro §5.7).

## Futuro
- `oui.csv` (IEEE) para fabricantes MAC completos en LAN Explorer.
- Listas VPN/Tor/bogon para clasificación de IP.
