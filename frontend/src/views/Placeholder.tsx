import { findItem, type ViewId } from '../lib/nav';
import { Icon } from '../components/icons';
import { useI18n } from '../lib/i18n';

const DETAIL: Partial<Record<ViewId, string>> = {
  capture: 'Enumeración de interfaces, modo promiscuo señalado, filtros BPF, ring buffer acotado y guardado PCAP/PCAPNG con rotación.',
  pcap: 'Apertura por streaming de archivos grandes, tabla de paquetes virtualizada, filtros, hex/ASCII viewer y decodificación por capas.',
  flows: 'Agregación bidireccional por 5-tupla, estado TCP, bytes/paquetes por sentido, correlación DNS/SNI y exportación.',
  endpoints: 'Cada IP se convierte en una entidad correlacionada: MAC, hostnames, ASN, prefijo, GeoIP, clases de red, riesgos y confianza.',
  geomap: 'Enriquecimiento GeoIP/ASN offline por paquete y flujo, top talkers y grafo de conexiones — sin afirmar ubicación exacta.',
  pingmtr: 'Motores propios de Ping, Traceroute y MTR sobre ICMP/UDP/TCP con estadísticas, jitter RFC 3550 y estado por hop.',
  scanner: 'TCP connect sin privilegios, SYN/UDP con elevación, rate limit configurable y banner grabbing seguro.',
  lan: 'Descubrimiento ARP/NDP, IP/MAC/vendor/hostname, Wake-on-LAN y detección de cambios — sin ataques ni suplantación.',
  webintel: 'Grafo dominio → DNS → IP → ASN → país → certificado, con headers HTTP, TLS/SANs y detección de CDN/WAF por evidencia.',
  voip: 'Reconstrucción de diálogos SIP por Call-ID, negociación SDP, streams RTP por SSRC, jitter/pérdida y MOS estimado con limitaciones.',
  settings: 'Gestor de datasets (GeoIP/ASN/VPN/Tor), preferencias de privacidad, tema, caché local y política de consultas externas (desactivadas por defecto).',
};

export default function Placeholder({ id }: { id: ViewId }) {
  const { t } = useI18n();
  const item = findItem(id);
  if (!item) return null;
  return (
    <div className="content-inner">
      <div className="page-head">
        <h2>{t(item.label)}</h2>
        <p className="body-text">{t(DETAIL[id] ?? 'Módulo planificado según el prompt maestro.')}</p>
      </div>
      <div className="card pad-lg">
        <span className="phase-badge">{t('Fase {phase}', { phase: item.phase })}</span>
        <div className="empty">
          <div className="big"><Icon name={id} size={40} /></div>
          <p style={{ margin: '0 auto', maxWidth: '46ch', color: 'var(--text-dim)' }}>
            {t('Contrato de datos y backend en construcción. Esta vista se activará cuando el motor correspondiente pase su suite de tests y validación por CLI, según la forma de trabajo del §17.')}
          </p>
        </div>
      </div>
    </div>
  );
}
