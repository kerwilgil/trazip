export type PayloadKind = 'empty' | 'text' | 'binary';
export type LinkDestination = 'broadcast' | 'multicast' | null;
export type NetworkScope = 'ipv4-broadcast' | 'ipv4-multicast' | 'ipv6-multicast' | null;

export interface PacketEvidence {
  src?: string;
  dst?: string;
  srcMAC?: string;
  dstMAC?: string;
  etherType?: string;
  srcPort?: number;
  dstPort?: number;
  proto?: string;
  transport?: string;
  ttl?: number;
  tcpFlags?: string[];
  payloadLen?: number;
  payloadHex?: string;
  info?: string;
  app?: string;
  layers?: string[];
}

export interface PayloadPreview {
  bytes: number[];
  availableBytes: number;
  totalBytes: number;
  truncated: boolean;
  printablePercent: number;
  utf8Valid: boolean;
  kind: PayloadKind;
  strings: string[];
  invalidHex: boolean;
}

export interface PacketInterpretation {
  link: { protocol: string; sourceMAC: string; destinationMAC: string; etherType: string; destination: LinkDestination };
  network: { source: string; destination: string; ttl: number | null; protocol: string; scope: NetworkScope };
  transport: { protocol: string; sourcePort: number | null; destinationPort: number | null; tcpFlags: string[]; payloadBytes: number };
  application: { protocol: string | null; app: string; info: string; encrypted: boolean };
  payload: PayloadPreview;
}

const MAX_STRINGS = 30;

export function decodePayloadHex(hex: string | undefined): { bytes: number[]; invalid: boolean } {
  if (!hex) return { bytes: [], invalid: false };
  const compact = hex.replace(/\s/g, '');
  const bytes: number[] = [];
  for (let index = 0; index + 1 < compact.length; index += 2) {
    const pair = compact.slice(index, index + 2);
    if (!/^[0-9a-f]{2}$/i.test(pair)) return { bytes, invalid: true };
    bytes.push(Number.parseInt(pair, 16));
  }
  return { bytes, invalid: compact.length % 2 !== 0 };
}

export function extractASCIIStrings(bytes: number[], maximum = MAX_STRINGS): string[] {
  const strings: string[] = [];
  const seen = new Set<string>();
  let current = '';
  const push = () => {
    if (current.length >= 4 && !seen.has(current) && strings.length < maximum) {
      seen.add(current);
      strings.push(current);
    }
    current = '';
  };
  for (const byte of bytes) {
    if (byte >= 32 && byte <= 126) current += String.fromCharCode(byte);
    else push();
  }
  push();
  return strings;
}

function validMAC(value: string | undefined): number[] | null {
  if (!value || !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(value)) return null;
  return value.split(':').map((part) => Number.parseInt(part, 16));
}

export function classifyLinkDestination(mac: string | undefined): LinkDestination {
  const bytes = validMAC(mac);
  if (!bytes) return null;
  if (bytes.every((byte) => byte === 0xff)) return 'broadcast';
  return (bytes[0] & 1) === 1 ? 'multicast' : null;
}

function ipv4Octets(value: string | undefined): number[] | null {
  if (!value) return null;
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => Number(part));
  return octets.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) ? octets : null;
}

export function classifyNetworkScope(destination: string | undefined): NetworkScope {
  const ipv4 = ipv4Octets(destination);
  if (ipv4) {
    if (ipv4.every((part) => part === 255)) return 'ipv4-broadcast';
    return ipv4[0] >= 224 && ipv4[0] <= 239 ? 'ipv4-multicast' : null;
  }
  return /^ff[0-9a-f]{2}:/i.test(destination ?? '') ? 'ipv6-multicast' : null;
}

function isUTF8(bytes: number[]): boolean {
  if (bytes.length === 0) return false;
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
    return true;
  } catch {
    return false;
  }
}

export function inspectPayload(hex: string | undefined, totalLength?: number): PayloadPreview {
  const decoded = decodePayloadHex(hex);
  const availableBytes = decoded.bytes.length;
  const declared = Number.isFinite(totalLength) && (totalLength ?? 0) > 0 ? Math.floor(totalLength ?? 0) : 0;
  const totalBytes = Math.max(declared, availableBytes);
  const printable = decoded.bytes.filter((byte) => byte >= 32 && byte <= 126).length;
  const printablePercent = availableBytes === 0 ? 0 : Math.round((printable / availableBytes) * 100);
  const utf8Valid = isUTF8(decoded.bytes);
  const kind: PayloadKind = totalBytes === 0 ? 'empty' : availableBytes >= 4 && printablePercent >= 85 && utf8Valid ? 'text' : 'binary';
  return {
    bytes: decoded.bytes,
    availableBytes,
    totalBytes,
    truncated: totalBytes > availableBytes,
    printablePercent,
    utf8Valid,
    kind,
    strings: extractASCIIStrings(decoded.bytes),
    invalidHex: decoded.invalid,
  };
}

function transportLabel(value: string | undefined, proto: string | undefined): string {
  const normalized = (value || '').toLowerCase();
  if (normalized === 'tcp' || normalized === 'udp') return normalized.toUpperCase();
  if (normalized === 'icmp') return 'ICMP';
  if (normalized === 'icmp6') return 'ICMPv6';
  if (!/^(TCP|UDP|ICMP|ICMPv6)$/i.test(proto ?? '')) return '';
  if (/^icmpv?6$/i.test(proto ?? '')) return 'ICMPv6';
  return (proto ?? '').toUpperCase();
}

function observedApplication(proto: string | undefined, transport: string): string | null {
  const value = (proto ?? '').trim();
  if (!value || value.toUpperCase() === transport.toUpperCase()) return null;
  return value;
}

export function interpretPacket(packet: PacketEvidence): PacketInterpretation {
  const transport = transportLabel(packet.transport, packet.proto);
  const applicationProtocol = observedApplication(packet.proto, transport);
  const payload = inspectPayload(packet.payloadHex, packet.payloadLen);
  const layers = packet.layers ?? [];
  const protocol = layers.includes('IPv6') ? 'IPv6' : layers.includes('IPv4') ? 'IPv4' : layers.includes('ARP') ? 'ARP' : '';
  const ttl = Number.isFinite(packet.ttl) && (packet.ttl ?? 0) >= 0 ? Math.floor(packet.ttl ?? 0) : null;
  const port = (value: number | undefined) => Number.isFinite(value) && (value ?? 0) > 0 ? Math.floor(value ?? 0) : null;
  return {
    link: {
      protocol: packet.etherType || layers.includes('Ethernet') ? 'Ethernet' : layers.some((layer) => /Dot11|802\.11/i.test(layer)) ? '802.11' : '',
      sourceMAC: packet.srcMAC ?? '',
      destinationMAC: packet.dstMAC ?? '',
      etherType: packet.etherType ?? '',
      destination: classifyLinkDestination(packet.dstMAC),
    },
    network: {
      source: packet.src ?? '',
      destination: packet.dst ?? '',
      ttl,
      protocol,
      scope: classifyNetworkScope(packet.dst),
    },
    transport: {
      protocol: transport,
      sourcePort: port(packet.srcPort),
      destinationPort: port(packet.dstPort),
      tcpFlags: packet.tcpFlags ?? [],
      payloadBytes: payload.totalBytes,
    },
    application: {
      protocol: applicationProtocol,
      app: packet.app ?? '',
      info: packet.info ?? '',
      encrypted: applicationProtocol === 'TLS',
    },
    payload,
  };
}
