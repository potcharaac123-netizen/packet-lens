import type { ProtocolName, Severity } from '../types/packet';

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function formatMs(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(1)} ms`;
  return `${(ms / 1000).toFixed(3)} s`;
}

export function getHostDisplayName(
  ip: string,
  ipToDomains: Record<string, string[]>
): { primary: string; secondary?: string } {
  const domains = ipToDomains[ip];
  if (domains && domains.length > 0) {
    return { primary: domains[0], secondary: ip };
  }
  return { primary: ip };
}

export function getProtocolBadgeClass(protocol: ProtocolName): string {
  switch (protocol) {
    case 'DNS':
      return 'bg-sky-50 text-sky-700 ring-sky-200';
    case 'HTTP':
      return 'bg-emerald-50 text-emerald-700 ring-emerald-200';
    case 'TLS':
    case 'QUIC':
      return 'bg-teal-50 text-teal-700 ring-teal-200';
    case 'ICMP':
    case 'ICMPv6':
      return 'bg-amber-50 text-amber-700 ring-amber-200';
    case 'ARP':
      return 'bg-orange-50 text-orange-700 ring-orange-200';
    case 'TCP':
      return 'bg-slate-100 text-slate-700 ring-slate-200';
    case 'UDP':
      return 'bg-indigo-50 text-indigo-700 ring-indigo-200';
    case 'SSH':
    case 'DHCP':
    case 'NTP':
      return 'bg-cyan-50 text-cyan-700 ring-cyan-200';
    default:
      return 'bg-slate-100 text-slate-600 ring-slate-200';
  }
}

export function getProtocolStrokeColor(
  protocol: ProtocolName,
  severity: Severity
): string {
  if (severity === 'error') return '#e11d48'; // rose-600
  if (severity === 'warning') return '#d97706'; // amber-600
  switch (protocol) {
    case 'DNS':
      return '#0284c7'; // sky-600
    case 'HTTP':
      return '#059669'; // emerald-600
    case 'TLS':
    case 'QUIC':
      return '#0d9488'; // teal-600
    case 'ICMP':
    case 'ICMPv6':
      return '#d97706'; // amber-600
    case 'ARP':
      return '#ea580c'; // orange-600
    default:
      return '#475569'; // slate-600
  }
}
