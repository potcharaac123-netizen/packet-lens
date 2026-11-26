// Generates a valid little-endian libpcap (.pcap) binary buffer with realistic packets
// so users can explore PacketLens immediately without needing their own capture file.

function writeUint16BE(arr: number[], val: number) {
  arr.push((val >> 8) & 0xff, val & 0xff);
}

function writeUint32BE(arr: number[], val: number) {
  arr.push((val >>> 24) & 0xff, (val >>> 16) & 0xff, (val >>> 8) & 0xff, val & 0xff);
}

function ipBytes(ip: string): number[] {
  return ip.split('.').map((n) => Number(n) & 0xff);
}

function macBytes(mac: string): number[] {
  return mac.split(':').map((h) => parseInt(h, 16) & 0xff);
}

function asciiBytes(str: string): number[] {
  return Array.from(str).map((c) => c.charCodeAt(0) & 0xff);
}

function encodeDnsName(domain: string): number[] {
  const out: number[] = [];
  for (const part of domain.split('.')) {
    out.push(part.length);
    out.push(...asciiBytes(part));
  }
  out.push(0);
  return out;
}

function buildEthIpv4(
  srcMac: string,
  dstMac: string,
  srcIp: string,
  dstIp: string,
  proto: number,
  payload: number[]
): number[] {
  const totalLen = 20 + payload.length;
  const pkt: number[] = [
    ...macBytes(dstMac),
    ...macBytes(srcMac),
    0x08,
    0x00, // IPv4
    0x45,
    0x00,
  ];
  writeUint16BE(pkt, totalLen);
  writeUint16BE(pkt, 0x1234); // ID
  writeUint16BE(pkt, 0x4000); // DF
  pkt.push(64, proto, 0x00, 0x00); // TTL, Proto, Checksum
  pkt.push(...ipBytes(srcIp), ...ipBytes(dstIp), ...payload);
  return pkt;
}

function buildUdp(srcPort: number, dstPort: number, payload: number[]): number[] {
  const pkt: number[] = [];
  writeUint16BE(pkt, srcPort);
  writeUint16BE(pkt, dstPort);
  writeUint16BE(pkt, 8 + payload.length);
  writeUint16BE(pkt, 0);
  pkt.push(...payload);
  return pkt;
}

function buildTcp(
  srcPort: number,
  dstPort: number,
  seq: number,
  ack: number,
  flags: number,
  payload: number[] = []
): number[] {
  const pkt: number[] = [];
  writeUint16BE(pkt, srcPort);
  writeUint16BE(pkt, dstPort);
  writeUint32BE(pkt, seq);
  writeUint32BE(pkt, ack);
  pkt.push(0x50, flags); // 20-byte header
  writeUint16BE(pkt, 65535);
  writeUint16BE(pkt, 0);
  writeUint16BE(pkt, 0);
  pkt.push(...payload);
  return pkt;
}

function buildDnsQuery(txId: number, domain: string): number[] {
  const pkt: number[] = [];
  writeUint16BE(pkt, txId);
  writeUint16BE(pkt, 0x0100); // Standard query
  writeUint16BE(pkt, 1); // QDCOUNT
  writeUint16BE(pkt, 0);
  writeUint16BE(pkt, 0);
  writeUint16BE(pkt, 0);
  pkt.push(...encodeDnsName(domain));
  writeUint16BE(pkt, 1); // A
  writeUint16BE(pkt, 1); // IN
  return pkt;
}

function buildDnsResponse(
  txId: number,
  domain: string,
  answerIp: string | null,
  rcode = 0
): number[] {
  const pkt: number[] = [];
  writeUint16BE(pkt, txId);
  writeUint16BE(pkt, 0x8180 | (rcode & 0x0f));
  writeUint16BE(pkt, 1);
  writeUint16BE(pkt, answerIp ? 1 : 0);
  writeUint16BE(pkt, 0);
  writeUint16BE(pkt, 0);
  pkt.push(...encodeDnsName(domain));
  writeUint16BE(pkt, 1);
  writeUint16BE(pkt, 1);
  if (answerIp) {
    pkt.push(0xc0, 0x0c); // pointer to question name
    writeUint16BE(pkt, 1); // A
    writeUint16BE(pkt, 1); // IN
    writeUint32BE(pkt, 300); // TTL
    writeUint16BE(pkt, 4);
    pkt.push(...ipBytes(answerIp));
  }
  return pkt;
}

function buildTlsClientHello(sni: string): number[] {
  const sniBytes = asciiBytes(sni);
  const sniExt: number[] = [];
  writeUint16BE(sniExt, 0x0000); // SNI ext type
  writeUint16BE(sniExt, sniBytes.length + 5);
  writeUint16BE(sniExt, sniBytes.length + 3);
  sniExt.push(0x00); // host_name
  writeUint16BE(sniExt, sniBytes.length);
  sniExt.push(...sniBytes);

  const body: number[] = [];
  body.push(0x03, 0x03); // TLS 1.2
  for (let i = 0; i < 32; i++) body.push(i + 1); // Random
  body.push(0x00); // Session ID len 0
  writeUint16BE(body, 2);
  writeUint16BE(body, 0x1301); // Cipher suite
  body.push(0x01, 0x00); // Compression null
  writeUint16BE(body, sniExt.length);
  body.push(...sniExt);

  const handshake: number[] = [
    0x01, // ClientHello
    (body.length >> 16) & 0xff,
    (body.length >> 8) & 0xff,
    body.length & 0xff,
    ...body,
  ];

  const record: number[] = [0x16, 0x03, 0x01];
  writeUint16BE(record, handshake.length);
  record.push(...handshake);
  return record;
}

export function generateSamplePcap(): ArrayBuffer {
  const clientMac = 'aa:bb:cc:11:22:33';
  const routerMac = '00:11:22:33:44:55';
  const clientIp = '192.168.1.50';
  const routerIp = '192.168.1.1';
  const dnsIp = '8.8.8.8';
  const webIp = '93.184.216.34';
  const apiIp = '104.21.48.120';
  const blockedIp = '192.168.1.99';

  const packets: { offsetMs: number; data: number[] }[] = [];

  // 1. ARP Request & Reply
  packets.push({
    offsetMs: 0,
    data: [
      ...macBytes('ff:ff:ff:ff:ff:ff'),
      ...macBytes(clientMac),
      0x08,
      0x06,
      0x00,
      0x01,
      0x08,
      0x00,
      0x06,
      0x04,
      0x00,
      0x01,
      ...macBytes(clientMac),
      ...ipBytes(clientIp),
      0,
      0,
      0,
      0,
      0,
      0,
      ...ipBytes(routerIp),
    ],
  });
  packets.push({
    offsetMs: 4,
    data: [
      ...macBytes(clientMac),
      ...macBytes(routerMac),
      0x08,
      0x06,
      0x00,
      0x01,
      0x08,
      0x00,
      0x06,
      0x04,
      0x00,
      0x02,
      ...macBytes(routerMac),
      ...ipBytes(routerIp),
      ...macBytes(clientMac),
      ...ipBytes(clientIp),
    ],
  });

  // 2. DNS Query & Response for shop.example.com
  packets.push({
    offsetMs: 18,
    data: buildEthIpv4(
      clientMac,
      routerMac,
      clientIp,
      dnsIp,
      17,
      buildUdp(54321, 53, buildDnsQuery(0x1a2b, 'shop.example.com'))
    ),
  });
  packets.push({
    offsetMs: 36,
    data: buildEthIpv4(
      routerMac,
      clientMac,
      dnsIp,
      clientIp,
      17,
      buildUdp(53, 54321, buildDnsResponse(0x1a2b, 'shop.example.com', webIp, 0))
    ),
  });

  // 3. TCP Handshake + HTTP GET + 200 OK
  packets.push({
    offsetMs: 42,
    data: buildEthIpv4(
      clientMac,
      routerMac,
      clientIp,
      webIp,
      6,
      buildTcp(51000, 80, 1000, 0, 0x02)
    ),
  });
  packets.push({
    offsetMs: 65,
    data: buildEthIpv4(
      routerMac,
      clientMac,
      webIp,
      clientIp,
      6,
      buildTcp(80, 51000, 5000, 1001, 0x12)
    ),
  });
  packets.push({
    offsetMs: 67,
    data: buildEthIpv4(
      clientMac,
      routerMac,
      clientIp,
      webIp,
      6,
      buildTcp(51000, 80, 1001, 5001, 0x10)
    ),
  });
  const httpReq = asciiBytes(
    'GET /products?category=electronics HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: PacketLens-Demo\r\n\r\n'
  );
  packets.push({
    offsetMs: 70,
    data: buildEthIpv4(
      clientMac,
      routerMac,
      clientIp,
      webIp,
      6,
      buildTcp(51000, 80, 1001, 5001, 0x18, httpReq)
    ),
  });
  const httpRes = asciiBytes(
    'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{"status":"ok","items":12}'
  );
  packets.push({
    offsetMs: 112,
    data: buildEthIpv4(
      routerMac,
      clientMac,
      webIp,
      clientIp,
      6,
      buildTcp(80, 51000, 5001, 1001 + httpReq.length, 0x18, httpRes)
    ),
  });

  // 4. DNS Query for api.payment-gateway.io + TLS ClientHello (HTTPS)
  packets.push({
    offsetMs: 145,
    data: buildEthIpv4(
      clientMac,
      routerMac,
      clientIp,
      dnsIp,
      17,
      buildUdp(54322, 53, buildDnsQuery(0x3c4d, 'api.payment-gateway.io'))
    ),
  });
  packets.push({
    offsetMs: 162,
    data: buildEthIpv4(
      routerMac,
      clientMac,
      dnsIp,
      clientIp,
      17,
      buildUdp(
        53,
        54322,
        buildDnsResponse(0x3c4d, 'api.payment-gateway.io', apiIp, 0)
      )
    ),
  });
  packets.push({
    offsetMs: 168,
    data: buildEthIpv4(
      clientMac,
      routerMac,
      clientIp,
      apiIp,
      6,
      buildTcp(51002, 443, 2000, 0, 0x02)
    ),
  });
  packets.push({
    offsetMs: 190,
    data: buildEthIpv4(
      routerMac,
      clientMac,
      apiIp,
      clientIp,
      6,
      buildTcp(443, 51002, 8000, 2001, 0x12)
    ),
  });
  packets.push({
    offsetMs: 194,
    data: buildEthIpv4(
      clientMac,
      routerMac,
      clientIp,
      apiIp,
      6,
      buildTcp(51002, 443, 2001, 8001, 0x18, buildTlsClientHello('api.payment-gateway.io'))
    ),
  });

  // 5. DNS NXDOMAIN error (typo domain)
  packets.push({
    offsetMs: 240,
    data: buildEthIpv4(
      clientMac,
      routerMac,
      clientIp,
      dnsIp,
      17,
      buildUdp(54325, 53, buildDnsQuery(0x55aa, 'missing-server.local'))
    ),
  });
  packets.push({
    offsetMs: 258,
    data: buildEthIpv4(
      routerMac,
      clientMac,
      dnsIp,
      clientIp,
      17,
      buildUdp(53, 54325, buildDnsResponse(0x55aa, 'missing-server.local', null, 3))
    ),
  });

  // 6. ICMP Ping to 8.8.8.8
  packets.push({
    offsetMs: 300,
    data: buildEthIpv4(clientMac, routerMac, clientIp, dnsIp, 1, [
      8, 0, 0, 0, 0, 1, 0, 1, 0x61, 0x62, 0x63, 0x64,
    ]),
  });
  packets.push({
    offsetMs: 315,
    data: buildEthIpv4(routerMac, clientMac, dnsIp, clientIp, 1, [
      0, 0, 0, 0, 0, 1, 0, 1, 0x61, 0x62, 0x63, 0x64,
    ]),
  });

  // 7. TCP Connection Refused (RST) to local port 8080
  packets.push({
    offsetMs: 360,
    data: buildEthIpv4(
      clientMac,
      routerMac,
      clientIp,
      blockedIp,
      6,
      buildTcp(51010, 8080, 9000, 0, 0x02)
    ),
  });
  packets.push({
    offsetMs: 362,
    data: buildEthIpv4(
      routerMac,
      clientMac,
      blockedIp,
      clientIp,
      6,
      buildTcp(8080, 51010, 0, 9001, 0x14) // RST + ACK
    ),
  });

  // Serialize to libpcap binary
  const totalPayloadSize = packets.reduce((acc, p) => acc + 16 + p.data.length, 0);
  const buffer = new ArrayBuffer(24 + totalPayloadSize);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  // Global Header (Little Endian)
  view.setUint32(0, 0xa1b2c3d4, true);
  view.setUint16(4, 2, true);
  view.setUint16(6, 4, true);
  view.setInt32(8, 0, true);
  view.setUint32(12, 0, true);
  view.setUint32(16, 65535, true);
  view.setUint32(20, 1, true); // Ethernet

  const baseSec = Math.floor(Date.now() / 1000);
  let offset = 24;
  for (const p of packets) {
    const sec = baseSec + Math.floor(p.offsetMs / 1000);
    const usec = (p.offsetMs % 1000) * 1000;
    view.setUint32(offset, sec, true);
    view.setUint32(offset + 4, usec, true);
    view.setUint32(offset + 8, p.data.length, true);
    view.setUint32(offset + 12, p.data.length, true);
    bytes.set(p.data, offset + 16);
    offset += 16 + p.data.length;
  }

  return buffer;
}
