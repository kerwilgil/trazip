# TRAZIP v1.0.0

Primera versión mayor con diagnóstico correlacionado: TRAZIP ya no muestra
diez señales sueltas por separado — las cruza en una sola conclusión con
evidencia, tanto en un diagnóstico puntual como en una investigación que
junta resultados de varios módulos a lo largo del tiempo.

## Quick Diagnose 2.0

- Diagnóstico correlacionado por etapas (DNS, alcance, ruta, propiedad,
  seguridad de ruta/RPKI, TLS, HTTP, reputación) en una sola conclusión con
  nivel, confianza y evidencia — no diez resultados sueltos para interpretar
  a mano.
- Tres modos explícitos: **Offline** (sin tocar la red), **Standard**
  (sondas acotadas) y **Full** (comparación cruzada de resolutores DNS y
  traceroute más profundo).
- Divulgación explícita de qué salió de la máquina en cada corrida — nunca
  una sonda activa oculta detrás de un modo "diagnóstico".

## Resumen de incidente en PCAP

- Un resumen orientado a "qué mirar primero" en vez de una lista plana de
  paquetes: hallazgos priorizados por severidad, con contexto de flujos,
  endpoints y protocolos detectados.
- Las estadísticas del resumen reflejan siempre la captura completa, incluso
  cuando la vista solo puede mostrar una porción por tamaño.
- Integración directa con Investigaciones, sin exponer nunca la ruta local
  del archivo capturado.

## Diagnóstico VoIP

- Atribución correcta de quién originó realmente una respuesta SIP cuando
  hay un proxy/SBC intermedio de por medio — el intermediario ya no aparece
  como si fuera la fuente cuando solo relayó un mensaje que le llegó de otro
  lado, tanto para el origen del fallo como para los encabezados
  User-Agent/Server de cada salto.
- Integración con Investigaciones vía snapshot correlacionado.

## Monitor de cambios de ruta

- Diferencia un cambio de ruta real y persistente de una fluctuación
  transitoria (ECMP, timeout puntual) antes de confirmarlo.
- Integración con Investigaciones vía snapshot correlacionado.

## Investigaciones

- Un espacio de trabajo único para reunir resultados que ya obtuviste en
  Diagnose, PCAP, Monitor y VoIP — nunca vuelve a ejecutar nada por su
  cuenta, solo organiza lo que el operador eligió guardar.
- Línea de tiempo ordenada, con supresión de duplicados exactos y
  persistencia real en disco.
- Exportación a reporte en JSON, CSV, HTML y PDF.
- Ninguna ruta de archivo local ni identificador interno del sistema queda
  expuesto en lo que se guarda o se exporta.

## Estado del producto (Product Health Check)

- Una comprobación local, offline y determinística de que TRAZIP mismo
  funciona correctamente — 13 verificaciones sobre fixtures sintéticos y
  almacenamiento temporal, sin tocar capturas reales del usuario ni la red.
- Estados PASS / FAIL / SKIPPED / UNAVAILABLE claramente diferenciados:
  que una capacidad opcional (como los datasets de GeoIP) no esté instalada
  se reporta como UNAVAILABLE, nunca como una falla de la aplicación.
- Siempre `networkOut = false`.

## Confiabilidad y hallazgos cerrados en esta versión

- Una URL con credenciales embebidas (`usuario:contraseña@` en Quick
  Diagnose) se rechaza antes de tocar la red, sin dejar la credencial en
  ningún error ni en ninguna Investigación guardada.
- Corregida la atribución de encabezados SIP (User-Agent/Server) en
  llamadas con intermediarios — ver "Diagnóstico VoIP" arriba.
- El resumen de un análisis PCAP ahora se calcula sobre los datos
  completos de la captura, antes de aplicar cualquier límite de la vista.
- La comparación entre resolutores DNS ahora también detecta divergencias
  de RCODE (por ejemplo NXDOMAIN contra NOERROR), no solo diferencias de
  registros.
- La validación RPKI evalúa TODOS los ASN de origen anunciados cuando hay
  más de uno (MOAS), no solo el primero — y cuando RIPEstat no resuelve un
  prefijo real, el resultado se reporta como inconcluso (Unknown), nunca
  como validado.

## Actualización

Los usuarios en v0.7.4 podrán actualizar desde **Settings → Actualizaciones**
una vez que se publique el manifiesto firmado de v1.0.0. Hasta esa
publicación, la actualización automática a esta versión todavía no está
disponible.
