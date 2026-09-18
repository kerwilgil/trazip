# TRAZIP — Política de seguridad

## Divulgación responsable

Si descubres una vulnerabilidad de seguridad que afecta a TRAZIP (binarios
distribuidos, mecanismo de actualización firmada, manejo de capturas, web o
paquetes publicados), por favor sigue una divulgación coordinada:

- **No abras un issue público con los detalles de la vulnerabilidad.** Los
  issues de este repositorio son públicos.
- Reporta el hallazgo de forma privada mediante la pestaña **Security** →
  **Report a vulnerability** (ver la sección "Cómo reportar").

## Cómo reportar

Los reportes se envían de forma **privada** a través de GitHub:

1. En este repositorio, abre la pestaña **Security**.
2. Selecciona **Report a vulnerability** (Private vulnerability reporting).
3. Completa el formulario con los detalles mínimos indicados abajo.

GitHub mantiene el reporte privado entre el reporter y el equipo del proyecto;
no se publica. Es el canal oficial — no uses issues públicos para seguridad.

## Divulgación coordinada

- No publiques exploits, PoC funcionales ni detalles del hallazgo hasta que el
  problema esté resuelto o se haya acordado una divulgación con el mantenedor.
- Cuando exista un fix o mitigación, las notas de la vulnerabilidad se
  publicarán de forma coordinada en la pestaña Security Advisories.

## Qué incluir en un reporte

- Versión de TRAZIP afectada (p. ej. `1.4.1`) y cómo la obtuviste.
- Plataforma (Windows versión/arquitectura, macOS versión, etc.).
- Pasos concretos para reproducir el comportamiento.
- Impacto observado (qué puede hacer un atacante, qué datos se ven afectados).
- Logs relevantes **sanitizados** (sin IPs personales, nombres de host,
  credenciales ni capturas reales de tráfico usuario).
- No incluyas claves de firma ni credenciales.

## Alcance

En alcance: los binarios publicados, los manifests de actualización y su
cadena de verificación, el instalador/paquetes, y esta página de distribución.
Fuera de alcance: investigaciones sin impacto de seguridad verificable,
denegaciones de servicio genéricas de red, y problemas de terceros fuera del
control de TRAZIP (los componentes de terceros se mantienen bajo su propia
licencia y política; ver THIRD_PARTY_NOTICES.md).
