import type { ViewId } from './nav';

// Single source of truth for sidebar and Manual descriptions. Keeping this a
// complete Record makes a missing module description a TypeScript error.
export const MODULE_INFO: Record<ViewId, string> = {
  overview: 'Estado general de TRAZIP: capacidades del equipo, actividad en curso y alertas (datasets desactualizados, Npcap faltante, degradaciones de monitores).',
  diagnose: 'Clasifica una IP o dominio en un solo paso: alcance (pública/privada/bogon), GeoIP/ASN offline y notas de contexto.',
  investigations: 'Agrupa evidencias y notas de distintos módulos de TRAZIP en una investigación local con timeline y exportación.',
  capture: 'Captura de paquetes en tiempo real usando Npcap (con modo monitor 802.11 opcional, si el adaptador lo soporta) o recibiendo TZSP de un router (por ejemplo, MikroTik), con la misma decodificación por capas que el analizador de PCAP y un panel de principales emisores. Continúa en segundo plano si cambias de pestaña.',
  pcap: 'Lee archivos .pcap/.pcapng (incluso comprimidos en gzip) sin necesitar ningún driver instalado, decodificando cada paquete por capas.',
  flows: 'Agrupa el tráfico de una captura en conversaciones bidireccionales por IP/puerto/protocolo — misma captura que PCAP Analyzer, sin volver a abrirla.',
  endpoints: 'Cada dirección de una captura como una sola entidad correlacionada: clases de red, GeoIP/ASN, primera/última vez vista, volumen y la evidencia detrás de cada dato.',
  geomap: 'Ubicación geográfica y WHOIS/RDAP completo de una IP o dominio (estilo whois de Linux), o análisis geográfico del tráfico de una captura.',
  connections: 'Muestra conexiones de red activas del sistema con dirección local/remota, protocolo, estado y proceso cuando está disponible.',
  pingmtr: 'Ping, Traceroute y MTR con motores propios sobre ICMP/UDP/TCP — latencia, pérdida, jitter y ruta geográfica en vivo.',
  throughput: 'Mide el ancho de banda real (TCP/UDP) entre dos equipos, ambos con TRAZIP — servidor y cliente en la misma app.',
  httpload: 'Prueba de carga HTTP propia de TRAZIP: N conexiones concurrentes contra una URL tuya, con RPS/latencia/errores en vivo mientras corre.',
  scanner: 'Escaneo de puertos TCP por connect scan, sin privilegios especiales, sobre un host puntual.',
  lan: 'Descubrimiento activo de dispositivos en tu red local (barrido ICMP por CIDR/rango, puertos, fabricante, SO estimado) y escaneo de redes WiFi cercanas (SSID, señal, canal, seguridad — vía la API nativa de Windows).',
  maclookup: 'Identifica el fabricante asociado a una dirección MAC usando la base OUI local.',
  ipcalc: 'Calcula redes, hosts, máscaras, prefijos y rangos IPv4/IPv6 sin realizar consultas externas.',
  webintel: 'Analiza un dominio o URL: DNS, TLS/certificados, cabeceras HTTP, RDAP, reputación — con historial de consultas de la sesión.',
  bgp: 'Analiza routing BGP mediante RIPEstat/RIS: prefijos, vecinos observados, topología, RPKI, histórico, BGPlay, tiempo real y observatorio.',
  phone: 'Identifica un número de teléfono sin salir a internet: validez, país, operador y si la línea es móvil, fija o VoIP. Devuelve además el E.164 canónico y el URI tel: que viaja en las cabeceras SIP.',
  voip: 'Reconstruye llamadas SIP/RTP de una captura: diagrama de señalización estilo sngrep, calidad de audio estimada (MOS), exportación de audio e histórico de calidad por línea a través del tiempo.',
  monitor: 'Ping/MTR continuo en segundo plano por objetivo, con detección de degradación respecto a una línea base móvil, perfil base fijo opcional y comparación entre ventanas de tiempo.',
  lab: 'Escenarios de captura sintéticos y reproducibles (llamada VoIP con pérdida, DNS+HTTP básico) para practicar sin datos reales.',
  selftest: 'Comprueba las capacidades esenciales de TRAZIP y distingue fallos reales de funciones opcionales no disponibles.',
  manual: 'Referencia rápida de qué hace cada módulo de TRAZIP.',
  settings: 'Gestión de datasets GeoIP/ASN (instalación y actualización automática), tema de la interfaz y preferencias de privacidad.',
};
