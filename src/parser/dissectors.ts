import type {
  ParsedPacket,
  ProtocolField,
  ProtocolLayer,
  ProtocolName,
  Severity,
} from '../types/packet';
import type { RawPacketRecord } from './pcapParser';

function formatMac(bytes: Uint8Array, offset: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 6; i++) {
    parts.push(bytes[offset + i].toString(16).padStart(2, '0'));
  }
  return parts.join(':');
}

function formatIpv4(bytes: Uint8Array, offset: number): string {
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

function formatIpv6(bytes: Uint8Array, offset: number): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    const val = (bytes[offset + i] << 8) | bytes[offset + i + 1];
    groups.push(val.toString(16));
  }
  return groups.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
}

function readDnsName(
  bytes: Uint8Array,
  startOffset: number,
  dnsBase: number
): { name: string; nextOffset: number } {
  const labels: string[] = [];
  let offset = startOffset;
  let jumped = false;
  let nextOffset = startOffset;
  let guard = 0;

  while (offset < bytes.length && guard++ < 64) {
    const len = bytes[offset];
    if (len === 0) {
      if (!jumped) nextOffset = offset + 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (offset + 1 >= bytes.length) break;
      const ptr = ((len & 0x3f) << 8) | bytes[offset + 1];
      if (!jumped) nextOffset = offset + 2;
      offset = dnsBase + ptr;
      jumped = true;
      continue;
    }
    offset += 1;
    if (offset + len > bytes.length) break;
    let label = '';
    for (let i = 0; i < len; i++) {
      label += String.fromCharCode(bytes[offset + i]);
    }
    labels.push(label);
    offset += len;
    if (!jumped) nextOffset = offset;
  }

  return { name: labels.join('.') || '<root>', nextOffset };
}

function dnsTypeName(t: number): string {
  switch (t) {
    case 1:
      return 'A';
    case 2:
      return 'NS';
    case 5:
      return 'CNAME';
    case 6:
      return 'SOA';
    case 12:
      return 'PTR';
    case 15:
      return 'MX';
    case 16:
      return 'TXT';
    case 28:
      return 'AAAA';
    case 33:
      return 'SRV';
    case 65:
      return 'HTTPS';
    default:
      return `TYPE${t}`;
  }
}

function parseDns(
  bytes: Uint8Array,
  offset: number
): {
  isResponse: boolean;
  rcode: number;
  txId: number;
  queryName?: string;
  queryType?: string;
  answers: { name: string; ip?: string; type: string }[];
} | null {
  if (offset + 12 > bytes.length) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const txId = view.getUint16(offset, false);
  const flags = view.getUint16(offset + 2, false);
  const isResponse = (flags & 0x8000) !== 0;
  const rcode = flags & 0x000f;
  const qdCount = view.getUint16(offset + 4, false);
  const anCount = view.getUint16(offset + 6, false);

  let cursor = offset + 12;
  let queryName: string | undefined;
  let queryType: string | undefined;

  for (let i = 0; i < qdCount && cursor < bytes.length; i++) {
    const res = readDnsName(bytes, cursor, offset);
    cursor = res.nextOffset;
    if (cursor + 4 > bytes.length) break;
    const qtype = view.getUint16(cursor, false);
    cursor += 4;
    if (i === 0) {
      queryName = res.name;
      queryType = dnsTypeName(qtype);
    }
  }

  const answers: { name: string; ip?: string; type: string }[] = [];
  for (let i = 0; i < anCount && cursor < bytes.length; i++) {
    const res = readDnsName(bytes, cursor, offset);
    cursor = res.nextOffset;
    if (cursor + 10 > bytes.length) break;
    const rtype = view.getUint16(cursor, false);
    const rdLength = view.getUint16(cursor + 8, false);
    cursor += 10;
    if (cursor + rdLength > bytes.length) break;

    const typeStr = dnsTypeName(rtype);
    let ip: string | undefined;
    if (rtype === 1 && rdLength === 4) {
      ip = formatIpv4(bytes, cursor);
    } else if (rtype === 28 && rdLength === 16) {
      ip = formatIpv6(bytes, cursor);
    }
    answers.push({ name: res.name, ip, type: typeStr });
    cursor += rdLength;
  }

  return { isResponse, rcode, txId, queryName, queryType, answers };
}

function parseTlsSni(
  bytes: Uint8Array,
  offset: number
): {
  contentType: number;
  version: string;
  handshakeType?: number;
  sni?: string;
} | null {
  if (offset + 5 > bytes.length) return null;
  const contentType = bytes[offset];
  if (contentType < 20 || contentType > 23) return null;
  const verMajor = bytes[offset + 1];
  const verMinor = bytes[offset + 2];
  if (verMajor !== 3) return null;

  const versionMap: Record<number, string> = {
    0: 'SSL 3.0',
    1: 'TLS 1.0',
    2: 'TLS 1.1',
    3: 'TLS 1.2/1.3',
    4: 'TLS 1.3',
  };
  const version = versionMap[verMinor] ?? `TLS 3.${verMinor}`;

  if (contentType !== 22 || offset + 9 > bytes.length) {
    return { contentType, version };
  }

  const handshakeType = bytes[offset + 5];
  if (handshakeType !== 1) {
    return { contentType, version, handshakeType };
  }

  // ClientHello: record(5) + handshake header(4) + client_version(2) + random(32) = +43
  let cursor = offset + 43;
  if (cursor >= bytes.length) return { contentType, version, handshakeType };

  const sessionIdLen = bytes[cursor];
  cursor += 1 + sessionIdLen;
  if (cursor + 2 > bytes.length) return { contentType, version, handshakeType };

  const cipherSuitesLen = (bytes[cursor] << 8) | bytes[cursor + 1];
  cursor += 2 + cipherSuitesLen;
  if (cursor + 1 > bytes.length) return { contentType, version, handshakeType };

  const compMethodsLen = bytes[cursor];
  cursor += 1 + compMethodsLen;
  if (cursor + 2 > bytes.length) return { contentType, version, handshakeType };

  const extTotalLen = (bytes[cursor] << 8) | bytes[cursor + 1];
  cursor += 2;
  const extEnd = Math.min(bytes.length, cursor + extTotalLen);

  while (cursor + 4 <= extEnd) {
    const extType = (bytes[cursor] << 8) | bytes[cursor + 1];
    const extLen = (bytes[cursor + 2] << 8) | bytes[cursor + 3];
    cursor += 4;
    if (cursor + extLen > extEnd) break;

    if (extType === 0 && extLen >= 5) {
      // Server Name Indication
      const nameType = bytes[cursor + 2];
      const nameLen = (bytes[cursor + 3] << 8) | bytes[cursor + 4];
      if (nameType === 0 && cursor + 5 + nameLen <= extEnd) {
        let sni = '';
        for (let i = 0; i < nameLen; i++) {
          sni += String.fromCharCode(bytes[cursor + 5 + i]);
        }
        return { contentType, version, handshakeType, sni };
      }
    }
    cursor += extLen;
  }

  return { contentType, version, handshakeType };
}

function parseHttp(
  bytes: Uint8Array,
  offset: number
): {
  isRequest: boolean;
  method?: string;
  path?: string;
  host?: string;
  status?: number;
  statusText?: string;
  firstLine: string;
} | null {
  if (offset >= bytes.length) return null;
  const sliceLen = Math.min(bytes.length - offset, 512);
  let text = '';
  for (let i = 0; i < sliceLen; i++) {
    const c = bytes[offset + i];
    if (c === 0) return null;
    text += String.fromCharCode(c);
  }

  const lines = text.split(/\r?\n/);
  const firstLine = lines[0]?.trim() ?? '';
  const reqMatch = firstLine.match(
    /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP\/\d\.\d/
  );
  if (reqMatch) {
    let host: string | undefined;
    for (const line of lines.slice(1)) {
      const m = line.match(/^Host:\s*(.+)$/i);
      if (m) {
        host = m[1].trim();
        break;
      }
    }
    return {
      isRequest: true,
      method: reqMatch[1],
      path: reqMatch[2],
      host,
      firstLine,
    };
  }

  const resMatch = firstLine.match(/^HTTP\/\d\.\d\s+(\d{3})\s*(.*)$/);
  if (resMatch) {
    return {
      isRequest: false,
      status: Number(resMatch[1]),
      statusText: resMatch[2]?.trim(),
      firstLine,
    };
  }

  return null;
}

export function dissectPacket(
  record: RawPacketRecord,
  id: number,
  firstTimestampMs: number
): ParsedPacket {
  const bytes = record.data;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const layers: ProtocolLayer[] = [];

  let offset = 0;
  let etherType = 0;
  let srcMac: string | undefined;
  let dstMac: string | undefined;

  // 1. Link Layer
  if (record.linkType === 1 && bytes.length >= 14) {
    dstMac = formatMac(bytes, 0);
    srcMac = formatMac(bytes, 6);
    etherType = view.getUint16(12, false);
    offset = 14;
    if (etherType === 0x8100 && bytes.length >= 18) {
      etherType = view.getUint16(16, false);
      offset = 18;
    }
    layers.push({
      name: 'Ethernet II',
      titleTh: 'ชั้นเชื่อมต่อฮาร์ดแวร์ (Ethernet)',
      titleEn: 'Link Layer (Ethernet II)',
      summaryTh: `ส่งจาก MAC ${srcMac} ไปยัง ${dstMac}`,
      summaryEn: `From MAC ${srcMac} to ${dstMac}`,
      fields: [
        { key: 'srcMac', labelTh: 'MAC ต้นทาง', labelEn: 'Source MAC', value: srcMac },
        { key: 'dstMac', labelTh: 'MAC ปลายทาง', labelEn: 'Destination MAC', value: dstMac },
        {
          key: 'etherType',
          labelTh: 'ชนิดข้อมูลถัดไป',
          labelEn: 'EtherType',
          value: `0x${etherType.toString(16).padStart(4, '0')}`,
        },
      ],
    });
  } else if (record.linkType === 113 && bytes.length >= 16) {
    etherType = view.getUint16(14, false);
    offset = 16;
  } else if (record.linkType === 0 && bytes.length >= 4) {
    const family = view.getUint32(0, true);
    etherType = family === 2 ? 0x0800 : 0x86dd;
    offset = 4;
  } else if (record.linkType === 101 && bytes.length >= 1) {
    const ver = bytes[0] >> 4;
    etherType = ver === 6 ? 0x86dd : 0x0800;
    offset = 0;
  }

  let srcIp = srcMac ?? 'Unknown';
  let dstIp = dstMac ?? 'Unknown';
  let protocol: ProtocolName = 'UNKNOWN';
  let transportProtocol: ParsedPacket['transportProtocol'];
  let srcPort: number | undefined;
  let dstPort: number | undefined;
  let tcpFlags: string[] | undefined;
  let dnsQuery: string | undefined;
  let dnsAnswers: ParsedPacket['dnsAnswers'];
  let dnsRcode: number | undefined;
  let httpMethod: string | undefined;
  let httpPath: string | undefined;
  let httpHost: string | undefined;
  let httpStatus: number | undefined;
  let tlsSni: string | undefined;
  let tlsVersion: string | undefined;

  let summaryTh = 'แพ็กเก็ตข้อมูลเครือข่าย';
  let summaryEn = 'Network data packet';
  let detailTh = 'ข้อมูลการสื่อสารระดับเครือข่าย';
  let detailEn = 'General network communication packet';
  let severity: Severity = 'info';
  let warningTagTh: string | undefined;
  let warningTagEn: string | undefined;

  // 2. Network Layer
  if (etherType === 0x0806 && offset + 28 <= bytes.length) {
    // ARP
    protocol = 'ARP';
    transportProtocol = 'ARP';
    const op = view.getUint16(offset + 6, false);
    const senderIp = formatIpv4(bytes, offset + 14);
    const targetIp = formatIpv4(bytes, offset + 24);
    srcIp = senderIp;
    dstIp = targetIp;

    const isReq = op === 1;
    summaryTh = isReq
      ? `ถามหาเครื่องที่ใช้ IP ${targetIp}`
      : `ตอบกลับว่า IP ${senderIp} อยู่ที่เครื่องนี้`;
    summaryEn = isReq
      ? `Who has ${targetIp}? Tell ${senderIp}`
      : `${senderIp} is at ${formatMac(bytes, offset + 8)}`;
    detailTh = isReq
      ? 'ARP Request: อุปกรณ์กำลังประกาศถามในวงแลนว่าใครเป็นเจ้าของ IP นี้ เพื่อจะได้ส่งข้อมูลถูกเครื่อง'
      : 'ARP Reply: อุปกรณ์ตอบกลับเพื่อแจ้งหมายเลขฮาร์ดแวร์ (MAC Address) ของตัวเอง';
    detailEn = detailTh;

    layers.push({
      name: 'ARP',
      titleTh: 'ค้นหาอุปกรณ์ในวงแลน (ARP)',
      titleEn: 'Address Resolution Protocol (ARP)',
      summaryTh,
      summaryEn,
      fields: [
        { key: 'op', labelTh: 'คำสั่ง', labelEn: 'Operation', value: isReq ? 'Request (1)' : 'Reply (2)' },
        { key: 'senderIp', labelTh: 'IP ผู้ส่ง', labelEn: 'Sender IP', value: senderIp },
        { key: 'targetIp', labelTh: 'IP เป้าหมาย', labelEn: 'Target IP', value: targetIp },
      ],
    });
  } else if (etherType === 0x0800 && offset + 20 <= bytes.length) {
    // IPv4
    const ihl = (bytes[offset] & 0x0f) * 4;
    const totalLen = view.getUint16(offset + 2, false);
    const ttl = bytes[offset + 8];
    const ipProto = bytes[offset + 9];
    srcIp = formatIpv4(bytes, offset + 12);
    dstIp = formatIpv4(bytes, offset + 16);

    layers.push({
      name: 'IPv4',
      titleTh: 'ที่อยู่เครือข่าย (IPv4)',
      titleEn: 'Internet Protocol Version 4 (IPv4)',
      summaryTh: `${srcIp} → ${dstIp} (TTL: ${ttl})`,
      summaryEn: `${srcIp} → ${dstIp} (TTL: ${ttl})`,
      fields: [
        { key: 'srcIp', labelTh: 'IP ต้นทาง', labelEn: 'Source IP', value: srcIp },
        { key: 'dstIp', labelTh: 'IP ปลายทาง', labelEn: 'Destination IP', value: dstIp },
        { key: 'ttl', labelTh: 'อายุแพ็กเก็ต (TTL)', labelEn: 'Time to Live', value: `${ttl}` },
        { key: 'len', labelTh: 'ขนาดข้อมูล', labelEn: 'Total Length', value: `${totalLen} bytes` },
      ],
    });

    offset += Math.max(20, ihl);
    const payloadEnd = Math.min(bytes.length, offset + Math.max(0, totalLen - Math.max(20, ihl)));
    parseTransport(ipProto, payloadEnd);
  } else if (etherType === 0x86dd && offset + 40 <= bytes.length) {
    // IPv6
    const payloadLen = view.getUint16(offset + 4, false);
    const nextHeader = bytes[offset + 6];
    const hopLimit = bytes[offset + 7];
    srcIp = formatIpv6(bytes, offset + 8);
    dstIp = formatIpv6(bytes, offset + 24);

    layers.push({
      name: 'IPv6',
      titleTh: 'ที่อยู่เครือข่าย (IPv6)',
      titleEn: 'Internet Protocol Version 6 (IPv6)',
      summaryTh: `${srcIp} → ${dstIp}`,
      summaryEn: `${srcIp} → ${dstIp}`,
      fields: [
        { key: 'srcIp', labelTh: 'IP ต้นทาง', labelEn: 'Source IP', value: srcIp },
        { key: 'dstIp', labelTh: 'IP ปลายทาง', labelEn: 'Destination IP', value: dstIp },
        { key: 'hop', labelTh: 'Hop Limit', labelEn: 'Hop Limit', value: `${hopLimit}` },
      ],
    });

    offset += 40;
    const payloadEnd = Math.min(bytes.length, offset + payloadLen);
    parseTransport(nextHeader, payloadEnd);
  }

  function parseTransport(ipProto: number, payloadEnd: number) {
    if (ipProto === 1 && offset + 4 <= payloadEnd) {
      // ICMP
      protocol = 'ICMP';
      transportProtocol = 'ICMP';
      const type = bytes[offset];
      const code = bytes[offset + 1];
      if (type === 8) {
        summaryTh = `ทดสอบการเชื่อมต่อ (Ping Request) ไปยัง ${dstIp}`;
        summaryEn = `Ping (Echo Request) to ${dstIp}`;
        detailTh = 'ส่งสัญญาณ Ping เพื่อตรวจสอบว่าเครื่องปลายทางเปิดอยู่และตอบสนองหรือไม่';
        detailEn = 'ICMP Echo Request checking reachability of destination host.';
      } else if (type === 0) {
        summaryTh = `ตอบรับ Ping (Ping Reply) จาก ${srcIp}`;
        summaryEn = `Ping (Echo Reply) from ${srcIp}`;
        detailTh = 'เครื่องปลายทางตอบกลับมาแล้ว แสดงว่าการเชื่อมต่อใช้งานได้ปกติ';
        detailEn = 'ICMP Echo Reply confirming destination host is reachable.';
        severity = 'success';
      } else if (type === 3) {
        summaryTh = `ส่งข้อมูลไปไม่ถึงปลายทาง (Destination Unreachable)`;
        summaryEn = `Destination Unreachable (code ${code})`;
        detailTh = 'เครือข่ายหรือพอร์ตปลายทางไม่สามารถเข้าถึงได้';
        detailEn = 'The destination network, host, or port could not be reached.';
        severity = 'error';
        warningTagTh = 'เข้าถึงปลายทางไม่ได้';
        warningTagEn = 'Unreachable';
      } else {
        summaryTh = `ข้อความควบคุมเครือข่าย ICMP (Type ${type})`;
        summaryEn = `ICMP Type ${type}, Code ${code}`;
      }
      layers.push({
        name: 'ICMP',
        titleTh: 'ตรวจสอบสถานะเครือข่าย (ICMP)',
        titleEn: 'Internet Control Message Protocol (ICMP)',
        summaryTh,
        summaryEn,
        fields: [
          { key: 'type', labelTh: 'ประเภท (Type)', labelEn: 'Type', value: `${type}` },
          { key: 'code', labelTh: 'รหัส (Code)', labelEn: 'Code', value: `${code}` },
        ],
      });
    } else if (ipProto === 58 && offset + 4 <= payloadEnd) {
      // ICMPv6
      protocol = 'ICMPv6';
      transportProtocol = 'ICMPv6';
      const type = bytes[offset];
      summaryTh =
        type === 128
          ? `Ping Request (IPv6) ไปยัง ${dstIp}`
          : type === 129
            ? `Ping Reply (IPv6) จาก ${srcIp}`
            : `ข้อความควบคุม ICMPv6 (Type ${type})`;
      summaryEn = `ICMPv6 Type ${type}`;
      layers.push({
        name: 'ICMPv6',
        titleTh: 'ตรวจสอบสถานะเครือข่าย (ICMPv6)',
        titleEn: 'ICMPv6',
        summaryTh,
        summaryEn,
        fields: [{ key: 'type', labelTh: 'Type', labelEn: 'Type', value: `${type}` }],
      });
    } else if (ipProto === 6 && offset + 20 <= payloadEnd) {
      // TCP
      protocol = 'TCP';
      transportProtocol = 'TCP';
      srcPort = view.getUint16(offset, false);
      dstPort = view.getUint16(offset + 2, false);
      const seq = view.getUint32(offset + 4, false);
      const ack = view.getUint32(offset + 8, false);
      const dataOffset = ((bytes[offset + 12] >> 4) & 0x0f) * 4;
      const flagsByte = bytes[offset + 13];
      const win = view.getUint16(offset + 14, false);

      const flags: string[] = [];
      if (flagsByte & 0x02) flags.push('SYN');
      if (flagsByte & 0x10) flags.push('ACK');
      if (flagsByte & 0x01) flags.push('FIN');
      if (flagsByte & 0x04) flags.push('RST');
      if (flagsByte & 0x08) flags.push('PSH');
      tcpFlags = flags;

      const appOffset = offset + Math.max(20, dataOffset);
      const appLen = Math.max(0, payloadEnd - appOffset);

      if (flags.includes('RST')) {
        summaryTh = `การเชื่อมต่อถูกตัดกะทันหัน (TCP Reset) พอร์ต ${dstPort}`;
        summaryEn = `Connection reset (TCP RST) on port ${srcPort} → ${dstPort}`;
        detailTh =
          'เครื่องปลายทางปฏิเสธหรือตัดการเชื่อมต่อทันที (RST) อาจเกิดจากพอร์ตไม่ได้เปิดให้บริการ หรือ Firewall บล็อก';
        detailEn = 'TCP Reset indicates an abrupt connection refusal or termination.';
        severity = 'error';
        warningTagTh = 'ตัดการเชื่อมต่อ (RST)';
        warningTagEn = 'TCP Reset';
      } else if (flags.includes('SYN') && !flags.includes('ACK')) {
        summaryTh = `ขอเริ่มการเชื่อมต่อ (SYN) ไปยังพอร์ต ${dstPort}`;
        summaryEn = `Initiate connection (SYN) to port ${dstPort}`;
        detailTh = 'ขั้นตอนที่ 1 ของ TCP Handshake: ขอเปิดช่องทางสื่อสารกับเครื่องปลายทาง';
        detailEn = 'Step 1 of TCP 3-way handshake: requesting a new connection.';
      } else if (flags.includes('SYN') && flags.includes('ACK')) {
        summaryTh = `ตอบรับการเปิดเชื่อมต่อ (SYN-ACK) จากพอร์ต ${srcPort}`;
        summaryEn = `Accept connection (SYN-ACK) from port ${srcPort}`;
        detailTh = 'ขั้นตอนที่ 2 ของ TCP Handshake: ปลายทางพร้อมรับการเชื่อมต่อแล้ว';
        detailEn = 'Step 2 of TCP 3-way handshake: server acknowledges and agrees.';
        severity = 'success';
      } else if (flags.includes('FIN')) {
        summaryTh = `ขอปิดการเชื่อมต่ออย่างสมบูรณ์ (FIN) พอร์ต ${dstPort}`;
        summaryEn = `Close connection gracefully (FIN) port ${srcPort} → ${dstPort}`;
        detailTh = 'รับ-ส่งข้อมูลเสร็จสิ้น และกำลังปิดการเชื่อมต่อตามปกติ';
        detailEn = 'Graceful TCP connection teardown.';
      } else {
        summaryTh = `ส่งข้อมูล TCP (${srcPort} → ${dstPort}) [${flags.join(', ') || 'DATA'}]`;
        summaryEn = `TCP ${srcPort} → ${dstPort} [${flags.join(', ')}] (${appLen} bytes)`;
        detailTh = 'การรับ-ส่งข้อมูลหรือยืนยันการได้รับแพ็กเก็ตผ่าน TCP';
        detailEn = 'TCP data transfer or acknowledgment.';
      }

      const tcpFields: ProtocolField[] = [
        { key: 'srcPort', labelTh: 'พอร์ตต้นทาง', labelEn: 'Source Port', value: `${srcPort}` },
        { key: 'dstPort', labelTh: 'พอร์ตปลายทาง', labelEn: 'Destination Port', value: `${dstPort}` },
        { key: 'flags', labelTh: 'สถานะ (Flags)', labelEn: 'Flags', value: flags.join(', ') || 'None' },
        { key: 'seq', labelTh: 'ลำดับข้อมูล (Seq)', labelEn: 'Sequence', value: `${seq}` },
        { key: 'ack', labelTh: 'ยืนยันรับ (Ack)', labelEn: 'Acknowledgment', value: `${ack}` },
        { key: 'win', labelTh: 'ขนาดบัฟเฟอร์ (Window)', labelEn: 'Window Size', value: `${win}` },
      ];

      layers.push({
        name: 'TCP',
        titleTh: 'การส่งข้อมูลที่เชื่อถือได้ (TCP)',
        titleEn: 'Transmission Control Protocol (TCP)',
        summaryTh: `พอร์ต ${srcPort} → ${dstPort} (${flags.join(', ')})`,
        summaryEn: `Port ${srcPort} → ${dstPort} (${flags.join(', ')})`,
        fields: tcpFields,
      });

      // Application Layer over TCP
      if (appLen > 0) {
        const http = parseHttp(bytes, appOffset);
        if (http) {
          protocol = 'HTTP';
          if (http.isRequest) {
            httpMethod = http.method;
            httpPath = http.path;
            httpHost = http.host;
            summaryTh = `เปิดเว็บ/เรียก API (HTTP ${http.method}) ${http.host ? http.host : ''}${http.path}`;
            summaryEn = `HTTP ${http.method} ${http.host ? http.host : ''}${http.path}`;
            detailTh =
              'ส่งคำขอแบบ HTTP (ไม่ได้เข้ารหัส) เพื่อดึงข้อมูลหรือส่งข้อมูลไปยังเว็บเซิร์ฟเวอร์';
            detailEn = 'Unencrypted HTTP request sent to web server.';
            severity = 'warning';
            warningTagTh = 'HTTP ไม่เข้ารหัส';
            warningTagEn = 'Unencrypted HTTP';
          } else {
            httpStatus = http.status;
            const isErr = (http.status ?? 0) >= 400;
            summaryTh = `เว็บตอบกลับ HTTP ${http.status} ${http.statusText ?? ''}`;
            summaryEn = `HTTP Response ${http.status} ${http.statusText ?? ''}`;
            detailTh = isErr
              ? `เซิร์ฟเวอร์ตอบกลับด้วยรหัสผิดพลาด (${http.status})`
              : `เซิร์ฟเวอร์ส่งข้อมูลกลับมาสำเร็จ (${http.status})`;
            detailEn = isErr
              ? `Server returned an HTTP error status (${http.status}).`
              : `Server responded successfully (${http.status}).`;
            severity = isErr ? 'error' : 'success';
            if (isErr) {
              warningTagTh = `HTTP ${http.status}`;
              warningTagEn = `HTTP ${http.status}`;
            }
          }
          layers.push({
            name: 'HTTP',
            titleTh: 'ข้อมูลเว็บ (HTTP)',
            titleEn: 'Hypertext Transfer Protocol (HTTP)',
            summaryTh,
            summaryEn,
            fields: [
              { key: 'firstLine', labelTh: 'บรรทัดคำสั่ง', labelEn: 'Start Line', value: http.firstLine },
              ...(http.host
                ? [{ key: 'host', labelTh: 'เว็บไซต์ (Host)', labelEn: 'Host', value: http.host }]
                : []),
            ],
          });
        } else {
          const tls = parseTlsSni(bytes, appOffset);
          if (tls) {
            protocol = 'TLS';
            tlsVersion = tls.version;
            tlsSni = tls.sni;
            if (tls.sni) {
              summaryTh = `เชื่อมต่อแบบเข้ารหัส (HTTPS/TLS) ไปยัง ${tls.sni}`;
              summaryEn = `TLS ClientHello to ${tls.sni} (${tls.version})`;
              detailTh = `เริ่มเชื่อมต่อเว็บแบบปลอดภัย (HTTPS) โดยระบุชื่อโดเมนปลายทางว่า ${tls.sni}`;
              detailEn = `Encrypted HTTPS handshake initiating connection to ${tls.sni}.`;
              severity = 'success';
            } else if (tls.contentType === 21) {
              summaryTh = `แจ้งเตือนความปลอดภัย TLS (TLS Alert)`;
              summaryEn = `TLS Alert (${tls.version})`;
              severity = 'warning';
              warningTagTh = 'TLS Alert';
              warningTagEn = 'TLS Alert';
            } else {
              summaryTh = `รับ-ส่งข้อมูลแบบเข้ารหัส (${tls.version})`;
              summaryEn = `Encrypted TLS Application Data (${tls.version})`;
              detailTh = 'ข้อมูลถูกเข้ารหัสด้วย TLS เพื่อความปลอดภัย (ไม่สามารถอ่านเนื้อหาภายในได้)';
              detailEn = 'Payload is encrypted using TLS.';
            }
            layers.push({
              name: 'TLS',
              titleTh: 'การเข้ารหัสความปลอดภัย (TLS/HTTPS)',
              titleEn: 'Transport Layer Security (TLS)',
              summaryTh,
              summaryEn,
              fields: [
                { key: 'version', labelTh: 'เวอร์ชัน', labelEn: 'Version', value: tls.version },
                ...(tls.sni
                  ? [{ key: 'sni', labelTh: 'ชื่อโดเมน (SNI)', labelEn: 'Server Name (SNI)', value: tls.sni }]
                  : []),
              ],
            });
          } else if (srcPort === 22 || dstPort === 22) {
            protocol = 'SSH';
            summaryTh = `เชื่อมต่อรีโมตเซิร์ฟเวอร์แบบเข้ารหัส (SSH)`;
            summaryEn = `SSH encrypted traffic (${srcPort} → ${dstPort})`;
          }
        }
      }
    } else if (ipProto === 17 && offset + 8 <= payloadEnd) {
      // UDP
      protocol = 'UDP';
      transportProtocol = 'UDP';
      srcPort = view.getUint16(offset, false);
      dstPort = view.getUint16(offset + 2, false);
      const udpLen = view.getUint16(offset + 4, false);
      const appOffset = offset + 8;

      layers.push({
        name: 'UDP',
        titleTh: 'ส่งข้อมูลแบบรวดเร็ว (UDP)',
        titleEn: 'User Datagram Protocol (UDP)',
        summaryTh: `พอร์ต ${srcPort} → ${dstPort} (${udpLen} bytes)`,
        summaryEn: `Port ${srcPort} → ${dstPort} (${udpLen} bytes)`,
        fields: [
          { key: 'srcPort', labelTh: 'พอร์ตต้นทาง', labelEn: 'Source Port', value: `${srcPort}` },
          { key: 'dstPort', labelTh: 'พอร์ตปลายทาง', labelEn: 'Destination Port', value: `${dstPort}` },
          { key: 'len', labelTh: 'ความยาว', labelEn: 'Length', value: `${udpLen} bytes` },
        ],
      });

      if (srcPort === 53 || dstPort === 53 || srcPort === 5353 || dstPort === 5353) {
        const dns = parseDns(bytes, appOffset);
        if (dns) {
          protocol = 'DNS';
          dnsQuery = dns.queryName;
          dnsAnswers = dns.answers;
          dnsRcode = dns.rcode;

          if (!dns.isResponse) {
            summaryTh = `ค้นหา IP ของโดเมน ${dns.queryName ?? '?'} (DNS Query)`;
            summaryEn = `DNS Query: ${dns.queryName ?? '?'} (${dns.queryType ?? 'A'})`;
            detailTh = `เครื่องกำลังถาม DNS Server ว่าเว็บไซต์ "${dns.queryName}" อยู่ที่ IP Address อะไร`;
            detailEn = `Asking DNS server to resolve domain "${dns.queryName}".`;
          } else if (dns.rcode === 3) {
            summaryTh = `ไม่พบชื่อโดเมน ${dns.queryName ?? '?'} (NXDOMAIN)`;
            summaryEn = `DNS Error: Domain not found (${dns.queryName ?? '?'})`;
            detailTh = `DNS ตอบกลับว่าไม่มีโดเมน "${dns.queryName}" อยู่ในระบบ (NXDOMAIN)`;
            detailEn = `DNS server reported that "${dns.queryName}" does not exist (NXDOMAIN).`;
            severity = 'error';
            warningTagTh = 'ไม่พบโดเมน';
            warningTagEn = 'NXDOMAIN';
          } else if (dns.rcode !== 0) {
            summaryTh = `DNS ตอบกลับผิดพลาด (Code ${dns.rcode}) สำหรับ ${dns.queryName ?? '?'}`;
            summaryEn = `DNS Error (RCODE ${dns.rcode}) for ${dns.queryName ?? '?'}`;
            severity = 'error';
            warningTagTh = 'DNS ผิดพลาด';
            warningTagEn = 'DNS Error';
          } else {
            const ips = dns.answers.map((a) => a.ip).filter(Boolean);
            summaryTh =
              ips.length > 0
                ? `DNS ตอบกลับ: ${dns.queryName ?? '?'} → ${ips.join(', ')}`
                : `DNS ตอบกลับสำหรับ ${dns.queryName ?? '?'} (${dns.answers.length} รายการ)`;
            summaryEn =
              ips.length > 0
                ? `DNS Response: ${dns.queryName ?? '?'} → ${ips.join(', ')}`
                : `DNS Response for ${dns.queryName ?? '?'}`;
            detailTh = `DNS Server แจ้งที่อยู่ IP ของ "${dns.queryName}" กลับมาเรียบร้อย`;
            detailEn = `DNS server returned the resolved IP address(es) for "${dns.queryName}".`;
            severity = 'success';
          }

          layers.push({
            name: 'DNS',
            titleTh: 'ระบบแปลงชื่อเว็บไซต์เป็น IP (DNS)',
            titleEn: 'Domain Name System (DNS)',
            summaryTh,
            summaryEn,
            fields: [
              { key: 'txId', labelTh: 'รหัสอ้างอิง', labelEn: 'Transaction ID', value: `0x${dns.txId.toString(16)}` },
              { key: 'qname', labelTh: 'ชื่อโดเมน', labelEn: 'Query Name', value: dns.queryName ?? '-' },
              ...(dns.answers.length > 0
                ? [
                    {
                      key: 'answers',
                      labelTh: 'คำตอบ (Answers)',
                      labelEn: 'Answers',
                      value: dns.answers.map((a) => (a.ip ? `${a.ip} (${a.type})` : a.type)).join(', '),
                    },
                  ]
                : []),
            ],
          });
        }
      } else if (srcPort === 67 || dstPort === 67 || srcPort === 68 || dstPort === 68) {
        protocol = 'DHCP';
        summaryTh = `ขอรับหรือต่ออายุ IP Address อัตโนมัติ (DHCP)`;
        summaryEn = `DHCP automatic IP configuration (${srcPort} → ${dstPort})`;
      } else if (srcPort === 123 || dstPort === 123) {
        protocol = 'NTP';
        summaryTh = `เทียบเวลามาตรฐานกับเซิร์ฟเวอร์ (NTP)`;
        summaryEn = `Network Time Protocol sync (${srcPort} → ${dstPort})`;
      } else if (srcPort === 443 || dstPort === 443) {
        protocol = 'QUIC';
        summaryTh = `เชื่อมต่อเว็บความเร็วสูงแบบเข้ารหัส (QUIC / HTTP3)`;
        summaryEn = `QUIC / HTTP3 encrypted traffic (${srcPort} → ${dstPort})`;
      } else {
        summaryTh = `ส่งข้อมูล UDP (${srcPort} → ${dstPort})`;
        summaryEn = `UDP ${srcPort} → ${dstPort} (${udpLen} bytes)`;
      }
    }
  }

  return {
    id,
    timestampMs: record.timestampMs,
    relativeTimeMs: Math.max(0, record.timestampMs - firstTimestampMs),
    capturedLen: record.capturedLen,
    originalLen: record.originalLen,
    srcMac,
    dstMac,
    srcIp,
    dstIp,
    srcPort,
    dstPort,
    protocol,
    transportProtocol,
    tcpFlags,
    dnsQuery,
    dnsAnswers,
    dnsRcode,
    httpMethod,
    httpPath,
    httpHost,
    httpStatus,
    tlsSni,
    tlsVersion,
    summaryTh,
    summaryEn,
    detailTh,
    detailEn,
    severity,
    warningTagTh,
    warningTagEn,
    layers,
    rawBytes: bytes,
  };
}
