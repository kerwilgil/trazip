# TRAZIP v0.7.3

VoIP Calls reestructurado de punta a punta como herramienta diagnóstica, más modo de tema Light/Dark/System. Cuatro auditorías independientes revisaron la reestructuración antes de este cierre; los hallazgos de cada una quedan documentados en `CONTEXT-trazip.md`.

## VoIP Calls

- Nuevo resumen diagnóstico por llamada: User-Agent / Server observados por parte, GeoIP / ASN (IPv4 e IPv6).
- Calidad RTP por stream y por dirección: pérdida, jitter, duplicados, paquetes reordenados, clock skew.
- MOS calculado únicamente para audio — nunca fabricado para video u otro tipo de media.
- RTCP con Receiver Report y Sender Report tratados como lo que son — dos partes distintas, nunca fundidos en una sola bolsa "remota": Receiver Report es la misma dirección observada desde el otro extremo; Sender Report es el propio origen del stream autorreportándose.
- Pérdida RTCP etiquetada explícitamente como el último intervalo del receptor, nunca comparada como si fuera el acumulado local.
- RTT RTCP estimado desde el punto de captura, con el caveat explícito de que la precisión depende de dónde se sitúa la captura respecto al endpoint real.
- Correlación multi-SSRC: dos streams RTP con SSRC distintos entre el mismo par de IPs ya no mezclan su RTCP.
- Negociación SDP offer/answer consciente de dirección y de multi-media: cada stream se compara contra la sección `m=` correcta (nunca "la primera audio"), destino como evidencia primaria y origen solo como heurística de clasificación, codecs validados por identidad (nombre/clockRate/channels) entre offer y answer, y atributos `sendonly`/`recvonly`/`inactive` respetados.
- Diagnóstico de calidad de voz (`model.Assessment`: evidencia, confianza, limitaciones) basado exclusivamente en streams de audio — un video degradado nunca contamina la conclusión de calidad de la llamada.
- Histórico de calidad (Quality History) también restringido a audio: una llamada solo-video ya no genera una muestra falsa de "0% pérdida, voz perfecta".

## Interfaz

- Modo de tema Light / Dark / System, con seguimiento en vivo de `prefers-color-scheme` mientras el modo System está activo.

## Correcciones de robustez

- Asociación de reportes RTCP por SSRC, no solo por par de IPs.
- Un Sender Report ya no fabrica un falso 0% de pérdida/jitter cuando nunca existió un Receiver Report real.
- Aritmética de RTT resistente al rollover de 16 bits de NTP-short (~18.2h).
- Un Report Block que referencia una Sender Report anterior (no la más reciente vista) sigue correlacionando correctamente.
- `DLSR=0` tratado como valor válido, no como sentinel de "ausente" inventado.
- GeoIP/ASN funciona correctamente sobre direcciones IPv6.
- Asociación RTCP por IP compartida ya no duplica el conteo cuando origen y destino comparten la misma IP.
- Detección de llamada unidireccional consciente del tipo de media (un stream de video en el sentido faltante ya no hace pasar por bidireccional una llamada cuyo audio sigue siendo de un solo sentido) y a prueba de direcciones same-IP (loopback).
- Un video degradado ya no contamina el MOS ni el histórico de calidad de la voz.
- Una llamada solo-video ya no crea una muestra falsa en el histórico de calidad.

## Limitaciones conocidas

- El RTT RTCP es una estimación desde el punto de captura, nunca una medición exacta — RFC 3550 exige el instante de llegada en el propio emisor de la SR, algo que una captura pasiva de tercero no puede observar directamente.
- El correlador SIP actual no soporta transporte TCP/TLS, solo UDP.
- User-Agent/Server reflejan el primer valor observado por cada parte de la llamada, no valores posteriores contradictorios.
- Caller/Callee se fijan desde la primera INVITE observada; una transferencia de llamada (re-INVITE cambiando de extremo) no se refleja.
- El texto dinámico generado por el backend (Conclusion/Evidence/MediaFindings del diagnóstico) puede seguir apareciendo en español en la UI en inglés — limitación deliberada y ya documentada, no nueva de esta versión.
- Sin firma Authenticode ni notarización nueva en esta versión — el proyecto no dispone todavía de certificados de firma; los artefactos se publican con SHA-256 únicamente.

## Validación

- `go test ./...`, `go test ./internal/voip/... -count=5`, `go test ./internal/voip/quality/... -count=5`, `go vet ./...`, `go mod verify`, `govulncheck ./...`.
- `npm ci`, `npm audit`, `npx tsc --noEmit`, `npm run build`.
- `wails generate module` × 2 sin drift; confirmado que `AnalyzeVoIPWithContext` no está expuesto como binding de Wails.
- Compilación cruzada `GOOS=linux GOARCH=amd64`; `wails build` para Windows/amd64.
