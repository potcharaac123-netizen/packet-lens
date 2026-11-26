import type {
  CaptureAnalysis,
  DomainVisit,
  ParsedPacket,
  ProtocolName,
  StoryInsight,
  TopologyEdge,
  TopologyNode,
} from '../types/packet';
import { dissectPacket } from './dissectors';
import { parseCaptureFile } from './pcapParser';

function isPrivateIp(ip: string): boolean {
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip === '127.0.0.1') {
    return true;
  }
  if (ip.startsWith('172.')) {
    const second = Number(ip.split('.')[1]);
    if (second >= 16 && second <= 31) return true;
  }
  if (ip.startsWith('fe80:') || ip === '::1') return true;
  return false;
}

function isBroadcastOrMulticast(ip: string): boolean {
  return (
    ip === '255.255.255.255' ||
    ip.startsWith('224.') ||
    ip.startsWith('239.') ||
    ip.startsWith('ff0') ||
    ip.endsWith('.255')
  );
}

export function analyzeCaptureBuffer(
  fileName: string,
  buffer: ArrayBuffer
): CaptureAnalysis {
  const parsed = parseCaptureFile(buffer);
  const records = parsed.records;

  if (records.length === 0) {
    throw new Error('ไม่พบแพ็กเก็ตข้อมูลในไฟล์นี้ (No packets found in capture)');
  }

  const firstTs = records[0].timestampMs;
  const packets: ParsedPacket[] = records.map((rec, idx) =>
    dissectPacket(rec, idx + 1, firstTs)
  );

  const ipToDomains: Record<string, Set<string>> = {};
  for (const [ip, names] of Object.entries(parsed.nameResolution)) {
    ipToDomains[ip] = new Set(names);
  }

  const addDomainMapping = (ip: string, domain: string) => {
    if (!ip || !domain || ip === 'Unknown') return;
    if (!ipToDomains[ip]) ipToDomains[ip] = new Set();
    ipToDomains[ip].add(domain);
  };

  const domainMap = new Map<string, DomainVisit>();
  const recordDomainVisit = (
    domain: string,
    ip: string | undefined,
    via: 'DNS' | 'HTTP' | 'TLS',
    tsMs: number,
    hasError: boolean
  ) => {
    const clean = domain.replace(/\.$/, '').toLowerCase();
    if (!clean || clean === '<root>') return;
    const existing = domainMap.get(clean);
    if (existing) {
      existing.packetCount += 1;
      if (ip && !existing.ips.includes(ip)) existing.ips.push(ip);
      if (hasError) existing.hasError = true;
    } else {
      domainMap.set(clean, {
        domain: clean,
        ips: ip ? [ip] : [],
        via,
        packetCount: 1,
        firstSeenMs: tsMs,
        hasError,
      });
    }
  };

  const protocolCounts: Record<string, number> = {};
  let totalBytes = 0;
  let warningCount = 0;
  let errorCount = 0;

  const dnsServers = new Set<string>();
  const rstPackets: number[] = [];
  const nxDomainPackets: number[] = [];
  const httpErrorPackets: number[] = [];
  const unencryptedHttpPackets: number[] = [];

  for (const pkt of packets) {
    totalBytes += pkt.originalLen;
    protocolCounts[pkt.protocol] = (protocolCounts[pkt.protocol] ?? 0) + 1;
    if (pkt.severity === 'warning') warningCount++;
    if (pkt.severity === 'error') errorCount++;

    if (pkt.protocol === 'DNS') {
      if (pkt.dstPort === 53) dnsServers.add(pkt.dstIp);
      if (pkt.srcPort === 53) dnsServers.add(pkt.srcIp);

      if (pkt.dnsQuery) {
        const isErr = pkt.dnsRcode !== undefined && pkt.dnsRcode !== 0;
        if (pkt.dnsRcode === 3) nxDomainPackets.push(pkt.id);
        const resolvedIp = pkt.dnsAnswers?.find((a) => a.ip)?.ip;
        recordDomainVisit(pkt.dnsQuery, resolvedIp, 'DNS', pkt.relativeTimeMs, isErr);
      }
      if (pkt.dnsAnswers) {
        for (const ans of pkt.dnsAnswers) {
          if (ans.ip) addDomainMapping(ans.ip, ans.name);
        }
      }
    }

    if (pkt.protocol === 'HTTP') {
      if (pkt.httpHost) {
        addDomainMapping(pkt.dstIp, pkt.httpHost);
        recordDomainVisit(pkt.httpHost, pkt.dstIp, 'HTTP', pkt.relativeTimeMs, false);
      }
      if (pkt.httpMethod) {
        unencryptedHttpPackets.push(pkt.id);
      }
      if (pkt.httpStatus && pkt.httpStatus >= 400) {
        httpErrorPackets.push(pkt.id);
      }
    }

    if (pkt.protocol === 'TLS' && pkt.tlsSni) {
      addDomainMapping(pkt.dstIp, pkt.tlsSni);
      recordDomainVisit(pkt.tlsSni, pkt.dstIp, 'TLS', pkt.relativeTimeMs, false);
    }

    if (pkt.tcpFlags?.includes('RST')) {
      rstPackets.push(pkt.id);
    }
  }

  // Convert ipToDomains sets to arrays
  const ipToDomainsFinal: Record<string, string[]> = {};
  for (const [ip, set] of Object.entries(ipToDomains)) {
    ipToDomainsFinal[ip] = Array.from(set);
  }

  // Build Topology Nodes & Edges
  const nodeMap = new Map<string, TopologyNode>();
  const ensureNode = (ip: string): TopologyNode => {
    const existing = nodeMap.get(ip);
    if (existing) return existing;

    const domains = ipToDomainsFinal[ip] ?? [];
    let role: TopologyNode['role'] = 'external';
    if (isBroadcastOrMulticast(ip)) {
      role = 'broadcast';
    } else if (dnsServers.has(ip)) {
      role = 'dns';
    } else if (isPrivateIp(ip)) {
      role = ip.endsWith('.1') || ip.endsWith('.254') ? 'gateway' : 'local';
    }

    const label = domains[0] ? domains[0] : ip;
    const node: TopologyNode = {
      id: ip,
      label,
      ip,
      domains,
      role,
      packetsSent: 0,
      packetsReceived: 0,
      bytesSent: 0,
      bytesReceived: 0,
      protocols: [],
    };
    nodeMap.set(ip, node);
    return node;
  };

  const edgeMap = new Map<
    string,
    {
      source: string;
      target: string;
      packets: number;
      bytes: number;
      protocols: Set<ProtocolName>;
      hasError: boolean;
      hasWarning: boolean;
    }
  >();

  for (const pkt of packets) {
    const src = ensureNode(pkt.srcIp);
    const dst = ensureNode(pkt.dstIp);
    src.packetsSent += 1;
    src.bytesSent += pkt.originalLen;
    dst.packetsReceived += 1;
    dst.bytesReceived += pkt.originalLen;

    if (!src.protocols.includes(pkt.protocol)) src.protocols.push(pkt.protocol);
    if (!dst.protocols.includes(pkt.protocol)) dst.protocols.push(pkt.protocol);

    const pair = [pkt.srcIp, pkt.dstIp].sort();
    const edgeId = `${pair[0]}<->${pair[1]}`;
    let edge = edgeMap.get(edgeId);
    if (!edge) {
      edge = {
        source: pair[0],
        target: pair[1],
        packets: 0,
        bytes: 0,
        protocols: new Set(),
        hasError: false,
        hasWarning: false,
      };
      edgeMap.set(edgeId, edge);
    }
    edge.packets += 1;
    edge.bytes += pkt.originalLen;
    edge.protocols.add(pkt.protocol);
    if (pkt.severity === 'error') edge.hasError = true;
    if (pkt.severity === 'warning') edge.hasWarning = true;
  }

  const edges: TopologyEdge[] = Array.from(edgeMap.entries()).map(([id, e]) => ({
    id,
    source: e.source,
    target: e.target,
    packets: e.packets,
    bytes: e.bytes,
    protocols: Array.from(e.protocols),
    hasError: e.hasError,
    hasWarning: e.hasWarning,
    label: `${e.packets} pkts`,
  }));

  // Build Storytelling Insights
  const insights: StoryInsight[] = [];
  const domains = Array.from(domainMap.values());

  if (domains.length > 0) {
    const names = domains.slice(0, 4).map((d) => d.domain).join(', ');
    const more = domains.length > 4 ? ` และอีก ${domains.length - 4} แห่ง` : '';
    const moreEn = domains.length > 4 ? ` and ${domains.length - 4} more` : '';
    insights.push({
      id: 'domains',
      severity: 'info',
      titleTh: `มีการเชื่อมต่อกับเว็บไซต์ / โดเมน ${domains.length} แห่ง`,
      titleEn: `Accessed ${domains.length} domain(s) / services`,
      descriptionTh: `พบการเรียกใช้งาน: ${names}${more}`,
      descriptionEn: `Observed traffic to: ${names}${moreEn}`,
      relatedPacketIds: [],
    });
  }

  if (nxDomainPackets.length > 0) {
    insights.push({
      id: 'nxdomain',
      severity: 'error',
      titleTh: `พบชื่อโดเมนที่หาไม่เจอ (DNS NXDOMAIN) ${nxDomainPackets.length} ครั้ง`,
      titleEn: `DNS lookup failed (NXDOMAIN) ${nxDomainPackets.length} time(s)`,
      descriptionTh:
        'มีคำขอค้นหาชื่อเว็บไซต์ที่ไม่มีอยู่จริงหรือพิมพ์ผิด ทำให้ไม่สามารถเชื่อมต่อไปยังปลายทางได้',
      descriptionEn:
        'One or more domain names could not be resolved because they do not exist.',
      relatedPacketIds: nxDomainPackets,
    });
  }

  if (rstPackets.length > 0) {
    insights.push({
      id: 'tcp-rst',
      severity: 'error',
      titleTh: `พบการตัดการเชื่อมต่อกะทันหัน (TCP Reset) ${rstPackets.length} ครั้ง`,
      titleEn: `Abrupt connection reset (TCP RST) detected ${rstPackets.length} time(s)`,
      descriptionTh:
        'เซิร์ฟเวอร์ปฏิเสธการเชื่อมต่อหรือพอร์ตปลายทางไม่ได้เปิดให้บริการ (อาจถูก Firewall บล็อกหรือเซอร์วิสปิดอยู่)',
      descriptionEn:
        'A host abruptly closed or refused the connection (port closed or blocked).',
      relatedPacketIds: rstPackets,
    });
  }

  if (httpErrorPackets.length > 0) {
    insights.push({
      id: 'http-err',
      severity: 'error',
      titleTh: `เว็บเซิร์ฟเวอร์ตอบกลับ Error (HTTP 4xx/5xx) ${httpErrorPackets.length} ครั้ง`,
      titleEn: `HTTP Error responses (4xx/5xx) ${httpErrorPackets.length} time(s)`,
      descriptionTh: 'คำขอไปยังเว็บไซต์บางรายการไม่สำเร็จ เช่น ไม่พบหน้าเว็บ (404) หรือเซิร์ฟเวอร์ขัดข้อง (500)',
      descriptionEn: 'Web server returned client or server error status codes.',
      relatedPacketIds: httpErrorPackets,
    });
  }

  if (unencryptedHttpPackets.length > 0) {
    insights.push({
      id: 'http-plain',
      severity: 'warning',
      titleTh: `พบการใช้งาน HTTP แบบไม่ได้เข้ารหัส ${unencryptedHttpPackets.length} คำขอ`,
      titleEn: `Unencrypted HTTP traffic detected (${unencryptedHttpPackets.length} requests)`,
      descriptionTh:
        'ข้อมูลที่ส่งผ่าน HTTP ธรรมดา (ไม่ใช่ HTTPS) สามารถถูกดักอ่านเนื้อหาได้ระหว่างทาง ควรหลีกเลี่ยงการส่งรหัสผ่าน',
      descriptionEn:
        'Plain HTTP traffic is not encrypted and can be read in transit.',
      relatedPacketIds: unencryptedHttpPackets,
    });
  }

  if (insights.length === 1 && errorCount === 0 && warningCount === 0) {
    insights.push({
      id: 'healthy',
      severity: 'success',
      titleTh: 'ไม่พบความผิดปกติในการเชื่อมต่อ',
      titleEn: 'No connection anomalies detected',
      descriptionTh: 'แพ็กเก็ตทั้งหมดสื่อสารกันได้ตามปกติ ไม่พบการตัดการเชื่อมต่อหรือ DNS ล้มเหลว',
      descriptionEn: 'All observed traffic completed without resets or DNS failures.',
      relatedPacketIds: [],
    });
  }

  const lastTs = records[records.length - 1].timestampMs;
  const durationMs = Math.max(0, lastTs - firstTs);

  return {
    fileName,
    fileSize: buffer.byteLength,
    fileFormat: parsed.format,
    totalPackets: packets.length,
    totalBytes,
    durationMs,
    startTimeMs: firstTs,
    packets,
    ipToDomains: ipToDomainsFinal,
    protocolCounts,
    nodes: Array.from(nodeMap.values()),
    edges,
    domains,
    insights,
    warningCount,
    errorCount,
  };
}
