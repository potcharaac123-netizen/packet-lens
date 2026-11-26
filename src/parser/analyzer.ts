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
      titleTh: `หาชื่อเว็บไซต์ไม่เจอ ${nxDomainPackets.length} ครั้ง (DNS NXDOMAIN)`,
      titleEn: `Website name not found ${nxDomainPackets.length} time(s) (DNS NXDOMAIN)`,
      descriptionTh:
        'ระบบค้นหาชื่อเว็บ (DNS เหมือนสมุดหน้าเหลือง) ตอบกลับมาว่าไม่มีชื่อเว็บไซต์นี้อยู่ในระบบ ทำให้เปิดเว็บไม่ได้',
      descriptionEn:
        'DNS (the internet phonebook) reported that this domain name does not exist.',
      tipTh: 'วิธีเช็คเบื้องต้น: ตรวจดูว่าพิมพ์ชื่อเว็บผิดไหม, เว็บภายในองค์กรต้องต่อ VPN หรือเปล่า, หรือลองเปลี่ยน DNS เป็น 8.8.8.8 / 1.1.1.1',
      tipEn: 'Tip: Check for typos in the URL, verify if a VPN is required, or test with DNS 8.8.8.8 / 1.1.1.1.',
      relatedPacketIds: nxDomainPackets,
    });
  }

  if (rstPackets.length > 0) {
    insights.push({
      id: 'tcp-rst',
      severity: 'error',
      titleTh: `ปลายทางปฏิเสธการเชื่อมต่อ ${rstPackets.length} ครั้ง (TCP Reset)`,
      titleEn: `Connection refused / cut off ${rstPackets.length} time(s) (TCP RST)`,
      descriptionTh:
        'เหมือนไปเคาะประตูบ้านปลายทางแล้วไม่มีใครเปิดรับ หรือถูกปิดประตูใส่ทันที',
      descriptionEn:
        'The destination host immediately refused or terminated the connection.',
      tipTh: 'วิธีเช็คเบื้องต้น: โปรแกรมหรือเซิร์ฟเวอร์ปลายทางอาจยังไม่เปิดทำงาน, พอร์ตนั้นปิดอยู่, หรือมี Firewall บล็อกไว้',
      tipEn: 'Tip: The target service may be down, the port is closed, or a firewall is blocking it.',
      relatedPacketIds: rstPackets,
    });
  }

  if (httpErrorPackets.length > 0) {
    insights.push({
      id: 'http-err',
      severity: 'error',
      titleTh: `เว็บไซต์แจ้ง Error กลับมา ${httpErrorPackets.length} ครั้ง (HTTP 4xx/5xx)`,
      titleEn: `Web server returned Error ${httpErrorPackets.length} time(s) (HTTP 4xx/5xx)`,
      descriptionTh: 'เชื่อมต่อกับเว็บได้แล้ว แต่หน้าเว็บนั้นมีปัญหา เช่น ไม่พบหน้าเว็บ (404) หรือระบบหลังบ้านล่ม (500)',
      descriptionEn: 'Connected to the server, but it returned a client or server error code.',
      tipTh: 'วิธีเช็คเบื้องต้น: ถ้าเป็นเลข 404 แปลว่าลิงก์ผิด/ไม่มีหน้านี้ ถ้าเป็นเลข 500–503 แปลว่าเซิร์ฟเวอร์ฝั่งเว็บมีปัญหา',
      tipEn: 'Tip: 404 means page not found; 500–503 indicates a server-side issue.',
      relatedPacketIds: httpErrorPackets,
    });
  }

  if (unencryptedHttpPackets.length > 0) {
    insights.push({
      id: 'http-plain',
      severity: 'warning',
      titleTh: `มีการส่งข้อมูลแบบไม่ได้เข้ารหัส ${unencryptedHttpPackets.length} ครั้ง (HTTP ธรรมดา)`,
      titleEn: `Unencrypted HTTP traffic detected (${unencryptedHttpPackets.length} requests)`,
      descriptionTh:
        'เหมือนส่งจดหมายแบบไม่ใส่ซองปิดผนึก คนที่อยู่บนเครือข่ายเดียวกันอาจแอบอ่านข้อความข้างในได้',
      descriptionEn:
        'Plain HTTP traffic is not encrypted and can be read in transit.',
      tipTh: 'คำแนะนำ: ควรใช้ HTTPS แทน HTTP และหลีกเลี่ยงการกรอกรหัสผ่านหรือข้อมูลส่วนตัวบนเว็บนี้',
      tipEn: 'Tip: Prefer HTTPS and avoid sending passwords or sensitive data over plain HTTP.',
      relatedPacketIds: unencryptedHttpPackets,
    });
  }

  if (insights.length === 1 && errorCount === 0 && warningCount === 0) {
    insights.push({
      id: 'healthy',
      severity: 'success',
      titleTh: 'การเชื่อมต่อทั้งหมดดูปกติดี',
      titleEn: 'Everything looks healthy',
      descriptionTh: 'ไม่พบอาการเข้าเว็บไม่ได้, ไม่พบการตัดการเชื่อมต่อกะทันหัน หรือ DNS ล้มเหลว',
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
