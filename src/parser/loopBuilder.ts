import type {
  CommunicationLoop,
  LoopStatus,
  ParsedPacket,
  ProtocolName,
} from '../types/packet';

function hostLabel(ip: string, ipToDomains: Record<string, string[]>): string {
  const dom = ipToDomains[ip]?.[0];
  return dom ? `${dom} (${ip})` : ip;
}

function normalizedPairKey(a: string, pA: number | undefined, b: string, pB: number | undefined): string {
  const left = `${a}:${pA ?? 0}`;
  const right = `${b}:${pB ?? 0}`;
  return left < right ? `${left}<->${right}` : `${right}<->${left}`;
}

export function buildCommunicationLoops(
  packets: ParsedPacket[],
  ipToDomains: Record<string, string[]>
): CommunicationLoop[] {
  interface RawGroup {
    id: number;
    packets: ParsedPacket[];
    closed: boolean;
    seenSeqLen: Set<string>;
    retransmissions: number;
  }

  const activeByKey = new Map<string, RawGroup>();
  const allGroups: RawGroup[] = [];
  let nextId = 1;

  for (const pkt of packets) {
    let key: string;
    if (pkt.transportProtocol === 'TCP') {
      key = `TCP|${normalizedPairKey(pkt.srcIp, pkt.srcPort, pkt.dstIp, pkt.dstPort)}`;
    } else if (pkt.protocol === 'DNS') {
      const txField = pkt.layers
        .find((l) => l.name === 'DNS')
        ?.fields.find((f) => f.key === 'txId')?.value;
      key = `DNS|${normalizedPairKey(pkt.srcIp, undefined, pkt.dstIp, undefined)}|${txField ?? pkt.dnsQuery ?? pkt.id}`;
    } else if (pkt.transportProtocol === 'ICMP' || pkt.transportProtocol === 'ICMPv6') {
      key = `${pkt.transportProtocol}|${normalizedPairKey(pkt.srcIp, undefined, pkt.dstIp, undefined)}`;
    } else if (pkt.protocol === 'ARP') {
      key = `ARP|${normalizedPairKey(pkt.srcIp, undefined, pkt.dstIp, undefined)}`;
    } else {
      key = `${pkt.protocol}|${normalizedPairKey(pkt.srcIp, pkt.srcPort, pkt.dstIp, pkt.dstPort)}`;
    }

    let group = activeByKey.get(key);
    const isFreshTcpSyn =
      pkt.transportProtocol === 'TCP' &&
      pkt.tcpFlags?.includes('SYN') &&
      !pkt.tcpFlags?.includes('ACK');

    // Start a new loop if previous TCP session closed or a fresh SYN arrives
    if (!group || (group.closed && pkt.transportProtocol === 'TCP') || (isFreshTcpSyn && group.packets.length > 0)) {
      group = {
        id: nextId++,
        packets: [],
        closed: false,
        seenSeqLen: new Set(),
        retransmissions: 0,
      };
      activeByKey.set(key, group);
      allGroups.push(group);
    }

    // Retransmission heuristic for TCP packets with payload or SYN/FIN
    if (pkt.transportProtocol === 'TCP') {
      const tcpLayer = pkt.layers.find((l) => l.name === 'TCP');
      const seqVal = tcpLayer?.fields.find((f) => f.key === 'seq')?.value;
      const isPureAck =
        pkt.tcpFlags?.length === 1 &&
        pkt.tcpFlags[0] === 'ACK' &&
        pkt.layers.every((l) => l.name !== 'HTTP' && l.name !== 'TLS');

      if (seqVal && !isPureAck) {
        const dirKey = `${pkt.srcIp}:${pkt.srcPort}->${seqVal}:${pkt.originalLen}`;
        if (group.seenSeqLen.has(dirKey)) {
          pkt.isRetransmission = true;
          group.retransmissions += 1;
        } else {
          group.seenSeqLen.add(dirKey);
        }
      }

      if (pkt.tcpFlags?.includes('FIN') || pkt.tcpFlags?.includes('RST')) {
        group.closed = true;
      }
    }

    const prevPkt = group.packets[group.packets.length - 1];
    if (prevPkt) {
      pkt.deltaFromPrevInLoopMs = Math.max(0, pkt.relativeTimeMs - prevPkt.relativeTimeMs);
    } else {
      pkt.deltaFromPrevInLoopMs = 0;
    }

    pkt.loopId = group.id;
    group.packets.push(pkt);
  }

  return allGroups.map((g) => {
    const first = g.packets[0];
    const last = g.packets[g.packets.length - 1];
    const initiatorIp = first.srcIp;
    const responderIp = first.dstIp;
    const hasReply = g.packets.some((p) => p.srcIp !== initiatorIp);

    // Pick highest-level protocol in the loop
    const appPriority: ProtocolName[] = [
      'HTTP',
      'TLS',
      'DNS',
      'QUIC',
      'SSH',
      'DHCP',
      'NTP',
      'ARP',
      'ICMP',
      'ICMPv6',
      'TCP',
      'UDP',
    ];
    let mainProto: ProtocolName = first.protocol;
    for (const candidate of appPriority) {
      if (g.packets.some((p) => p.protocol === candidate)) {
        mainProto = candidate;
        break;
      }
    }

    // Domain hint
    const domainHint =
      g.packets.find((p) => p.dnsQuery)?.dnsQuery ??
      g.packets.find((p) => p.httpHost)?.httpHost ??
      g.packets.find((p) => p.tlsSni)?.tlsSni ??
      ipToDomains[responderIp]?.[0];

    const targetLabel = domainHint ?? hostLabel(responderIp, ipToDomains);

    let titleTh = `${mainProto}: ${hostLabel(initiatorIp, ipToDomains)} ↔ ${targetLabel}`;
    let titleEn = `${mainProto}: ${hostLabel(initiatorIp, ipToDomains)} ↔ ${targetLabel}`;
    if (mainProto === 'DNS' && domainHint) {
      titleTh = `ค้นหาโดเมน ${domainHint} (DNS)`;
      titleEn = `DNS Lookup: ${domainHint}`;
    } else if (mainProto === 'HTTP') {
      titleTh = `เปิดเว็บ ${targetLabel} (HTTP)`;
      titleEn = `HTTP Request to ${targetLabel}`;
    } else if (mainProto === 'TLS') {
      titleTh = `เชื่อมต่อปลอดภัย ${targetLabel} (HTTPS/TLS)`;
      titleEn = `HTTPS/TLS Session with ${targetLabel}`;
    } else if (mainProto === 'ICMP' || mainProto === 'ICMPv6') {
      titleTh = `ทดสอบ Ping ไปยัง ${targetLabel}`;
      titleEn = `Ping to ${targetLabel}`;
    } else if (mainProto === 'ARP') {
      titleTh = `ค้นหา MAC ในวงแลน (${responderIp})`;
      titleEn = `ARP Discovery (${responderIp})`;
    }

    // Max gap inside loop
    let maxGapMs = 0;
    let maxGapAfterPacketId: number | undefined;
    for (let i = 1; i < g.packets.length; i++) {
      const gap = g.packets[i].deltaFromPrevInLoopMs ?? 0;
      if (gap > maxGapMs) {
        maxGapMs = gap;
        maxGapAfterPacketId = g.packets[i - 1].id;
      }
    }

    const totalBytes = g.packets.reduce((acc, p) => acc + p.originalLen, 0);
    const hasRst = g.packets.some((p) => p.tcpFlags?.includes('RST'));
    const hasFin = g.packets.some((p) => p.tcpFlags?.includes('FIN'));
    const hasSynOnly = first.transportProtocol === 'TCP' && first.tcpFlags?.includes('SYN') && !first.tcpFlags?.includes('ACK');
    const dnsErrPkt = g.packets.find((p) => p.protocol === 'DNS' && p.dnsRcode !== undefined && p.dnsRcode !== 0);
    const httpErrPkt = g.packets.find((p) => p.protocol === 'HTTP' && (p.httpStatus ?? 0) >= 400);
    const icmpErrPkt = g.packets.find((p) => p.protocol === 'ICMP' && p.severity === 'error');

    const startDescTh = `#${first.id} • ${first.summaryTh}`;
    const startDescEn = `#${first.id} • ${first.summaryEn}`;
    const endDescTh =
      g.packets.length === 1
        ? `#${last.id} • ยังไม่มีการตอบกลับต่อ`
        : `#${last.id} • ${last.summaryTh}`;
    const endDescEn =
      g.packets.length === 1
        ? `#${last.id} • No further packets`
        : `#${last.id} • ${last.summaryEn}`;

    let status: LoopStatus = 'completed';
    let stuckReasonTh: string | undefined;
    let stuckReasonEn: string | undefined;

    if (hasRst) {
      const rstPkt = g.packets.find((p) => p.tcpFlags?.includes('RST'))!;
      status = 'error';
      stuckReasonTh = `ติดที่ #${rstPkt.id}: การเชื่อมต่อถูกตัด/ปฏิเสธกะทันหัน (TCP RST)`;
      stuckReasonEn = `Stopped at #${rstPkt.id}: Connection reset/refused (TCP RST)`;
    } else if (dnsErrPkt) {
      status = 'error';
      stuckReasonTh = `ติดที่ #${dnsErrPkt.id}: ${dnsErrPkt.summaryTh}`;
      stuckReasonEn = `Failed at #${dnsErrPkt.id}: ${dnsErrPkt.summaryEn}`;
    } else if (httpErrPkt) {
      status = 'error';
      stuckReasonTh = `ติดที่ #${httpErrPkt.id}: เว็บตอบกลับ HTTP ${httpErrPkt.httpStatus}`;
      stuckReasonEn = `Error at #${httpErrPkt.id}: HTTP ${httpErrPkt.httpStatus}`;
    } else if (icmpErrPkt) {
      status = 'error';
      stuckReasonTh = `ติดที่ #${icmpErrPkt.id}: ${icmpErrPkt.summaryTh}`;
      stuckReasonEn = `Failed at #${icmpErrPkt.id}: ${icmpErrPkt.summaryEn}`;
    } else if (!hasReply && first.dstIp !== '255.255.255.255' && !first.dstIp.startsWith('224.')) {
      status = 'stuck';
      if (hasSynOnly) {
        stuckReasonTh = `ค้างหลัง #${first.id}: ส่งคำขอเปิดเชื่อมต่อ (SYN) แล้ว แต่ปลายทางไม่ตอบกลับ`;
        stuckReasonEn = `Stuck after #${first.id}: Sent SYN but received no reply`;
      } else {
        stuckReasonTh = `ค้างหลัง #${last.id}: ส่งข้อมูลไปแล้ว แต่ไม่ได้รับคำตอบจากปลายทาง`;
        stuckReasonEn = `Stuck after #${last.id}: Sent request with no response`;
      }
    } else if (g.retransmissions > 0) {
      status = 'warning';
      stuckReasonTh = `พบการส่งข้อมูลซ้ำ (Retransmission) ${g.retransmissions} ครั้ง`;
      stuckReasonEn = `Detected ${g.retransmissions} TCP retransmission(s)`;
    } else if (maxGapMs >= 300) {
      status = 'warning';
      stuckReasonTh = `รอการตอบกลับนาน ${maxGapMs.toFixed(0)} ms หลังแพ็กเก็ต #${maxGapAfterPacketId}`;
      stuckReasonEn = `High latency gap of ${maxGapMs.toFixed(0)} ms after #${maxGapAfterPacketId}`;
    } else if (first.transportProtocol === 'TCP' && !hasFin && !hasRst) {
      status = 'active';
    }

    return {
      id: g.id,
      titleTh,
      titleEn,
      protocol: mainProto,
      initiatorIp,
      responderIp,
      initiatorPort: first.srcPort,
      responderPort: first.dstPort,
      startTimeMs: first.relativeTimeMs,
      endTimeMs: last.relativeTimeMs,
      durationMs: Math.max(0, last.relativeTimeMs - first.relativeTimeMs),
      maxGapMs,
      maxGapAfterPacketId,
      packetIds: g.packets.map((p) => p.id),
      totalBytes,
      status,
      startDescTh,
      startDescEn,
      endDescTh,
      endDescEn,
      stuckReasonTh,
      stuckReasonEn,
      retransmissionCount: g.retransmissions,
      hasReply,
    };
  });
}
