export interface RawPacketRecord {
  timestampMs: number;
  capturedLen: number;
  originalLen: number;
  linkType: number;
  data: Uint8Array;
}

export interface PcapParseResult {
  format: 'pcap' | 'pcapng';
  records: RawPacketRecord[];
  nameResolution: Record<string, string[]>;
}

const PCAP_MAGIC_BE_US = 0xa1b2c3d4;
const PCAP_MAGIC_LE_US = 0xd4c3b2a1;
const PCAP_MAGIC_BE_NS = 0xa1b23c4d;
const PCAP_MAGIC_LE_NS = 0x4d3cb2a1;
const PCAPNG_SHB_TYPE = 0x0a0d0d0a;

export function parseCaptureFile(buffer: ArrayBuffer): PcapParseResult {
  if (buffer.byteLength < 24) {
    throw new Error('ไฟล์มีขนาดเล็กเกินไปหรือไม่ใช่ไฟล์ .pcap / .pcapng (File too small)');
  }

  const view = new DataView(buffer);
  const magicBE = view.getUint32(0, false);

  if (magicBE === PCAPNG_SHB_TYPE) {
    return parsePcapNg(buffer, view);
  }

  if (
    magicBE === PCAP_MAGIC_BE_US ||
    magicBE === PCAP_MAGIC_LE_US ||
    magicBE === PCAP_MAGIC_BE_NS ||
    magicBE === PCAP_MAGIC_LE_NS
  ) {
    return parsePcap(buffer, view, magicBE);
  }

  throw new Error(
    `ไม่รู้จักรูปแบบไฟล์นี้ (Magic: 0x${magicBE.toString(16).padStart(8, '0')}) — รองรับเฉพาะ .pcap และ .pcapng`
  );
}

function parsePcap(
  buffer: ArrayBuffer,
  view: DataView,
  magicBE: number
): PcapParseResult {
  const littleEndian =
    magicBE === PCAP_MAGIC_LE_US || magicBE === PCAP_MAGIC_LE_NS;
  const isNano = magicBE === PCAP_MAGIC_BE_NS || magicBE === PCAP_MAGIC_LE_NS;

  const linkType = view.getUint32(20, littleEndian);
  const records: RawPacketRecord[] = [];
  let offset = 24;

  while (offset + 16 <= buffer.byteLength) {
    const tsSec = view.getUint32(offset, littleEndian);
    const tsSub = view.getUint32(offset + 4, littleEndian);
    const inclLen = view.getUint32(offset + 8, littleEndian);
    const origLen = view.getUint32(offset + 12, littleEndian);
    offset += 16;

    if (inclLen > 262144 || offset + inclLen > buffer.byteLength) {
      // Truncated trailing packet — stop gracefully
      break;
    }

    const timestampMs =
      tsSec * 1000 + (isNano ? tsSub / 1_000_000 : tsSub / 1000);
    const data = new Uint8Array(buffer, offset, inclLen);

    records.push({
      timestampMs,
      capturedLen: inclLen,
      originalLen: origLen,
      linkType,
      data,
    });

    offset += inclLen;
  }

  return {
    format: 'pcap',
    records,
    nameResolution: {},
  };
}

function parsePcapNg(buffer: ArrayBuffer, view: DataView): PcapParseResult {
  const records: RawPacketRecord[] = [];
  const nameResolution: Record<string, string[]> = {};
  let interfaces: { linkType: number; tsResPow: number }[] = [];
  let littleEndian = true;
  let offset = 0;

  while (offset + 12 <= buffer.byteLength) {
    const blockType = view.getUint32(offset, littleEndian);

    // Section Header Block (SHB) — always 0x0a0d0d0a in both endiannesses
    if (blockType === PCAPNG_SHB_TYPE) {
      if (offset + 28 > buffer.byteLength) break;
      const byteOrderMagicLE = view.getUint32(offset + 8, true);
      littleEndian = byteOrderMagicLE === 0x1a2b3c4d;
      const blockLen = view.getUint32(offset + 4, littleEndian);
      if (blockLen < 28 || offset + blockLen > buffer.byteLength) break;
      interfaces = [];
      offset += blockLen;
      continue;
    }

    const blockLen = view.getUint32(offset + 4, littleEndian);
    if (blockLen < 12 || offset + blockLen > buffer.byteLength) {
      break;
    }

    if (blockType === 0x00000001) {
      // Interface Description Block (IDB)
      const linkType = view.getUint16(offset + 8, littleEndian);
      let tsResPow = 1e-6; // default microseconds
      // Parse options starting at offset + 16 up to blockLen - 4
      let optOffset = offset + 16;
      const optEnd = offset + blockLen - 4;
      while (optOffset + 4 <= optEnd) {
        const optCode = view.getUint16(optOffset, littleEndian);
        const optLen = view.getUint16(optOffset + 2, littleEndian);
        optOffset += 4;
        if (optCode === 0) break;
        if (optCode === 9 && optLen >= 1 && optOffset < optEnd) {
          const tsresol = view.getUint8(optOffset);
          const isBinary = (tsresol & 0x80) !== 0;
          const exp = tsresol & 0x7f;
          tsResPow = isBinary ? Math.pow(2, -exp) : Math.pow(10, -exp);
        }
        const paddedLen = (optLen + 3) & ~3;
        optOffset += paddedLen;
      }
      interfaces.push({ linkType, tsResPow });
    } else if (blockType === 0x00000006) {
      // Enhanced Packet Block (EPB)
      if (blockLen >= 32) {
        const interfaceId = view.getUint32(offset + 8, littleEndian);
        const tsHigh = view.getUint32(offset + 12, littleEndian);
        const tsLow = view.getUint32(offset + 16, littleEndian);
        const capturedLen = view.getUint32(offset + 20, littleEndian);
        const originalLen = view.getUint32(offset + 24, littleEndian);

        const iface = interfaces[interfaceId] ?? { linkType: 1, tsResPow: 1e-6 };
        const ts64 = tsHigh * 4294967296 + tsLow;
        const timestampMs = ts64 * iface.tsResPow * 1000;

        if (offset + 28 + capturedLen <= offset + blockLen) {
          const data = new Uint8Array(buffer, offset + 28, capturedLen);
          records.push({
            timestampMs,
            capturedLen,
            originalLen,
            linkType: iface.linkType,
            data,
          });
        }
      }
    } else if (blockType === 0x00000003) {
      // Simple Packet Block (SPB)
      if (blockLen >= 16) {
        const originalLen = view.getUint32(offset + 8, littleEndian);
        const capturedLen = Math.min(originalLen, blockLen - 16);
        const iface = interfaces[0] ?? { linkType: 1, tsResPow: 1e-6 };
        const data = new Uint8Array(buffer, offset + 12, capturedLen);
        records.push({
          timestampMs: 0,
          capturedLen,
          originalLen,
          linkType: iface.linkType,
          data,
        });
      }
    } else if (blockType === 0x00000004) {
      // Name Resolution Block (NRB)
      let recOffset = offset + 8;
      const recEnd = offset + blockLen - 4;
      while (recOffset + 4 <= recEnd) {
        const recType = view.getUint16(recOffset, littleEndian);
        const recLen = view.getUint16(recOffset + 2, littleEndian);
        recOffset += 4;
        if (recType === 0) break;
        if (recType === 1 && recLen > 4 && recOffset + recLen <= recEnd) {
          // IPv4 record: 4 bytes IP + null-terminated strings
          const ip = `${view.getUint8(recOffset)}.${view.getUint8(recOffset + 1)}.${view.getUint8(recOffset + 2)}.${view.getUint8(recOffset + 3)}`;
          const nameBytes = new Uint8Array(buffer, recOffset + 4, recLen - 4);
          const names = new TextDecoder()
            .decode(nameBytes)
            .split('\0')
            .filter(Boolean);
          if (names.length > 0) {
            nameResolution[ip] = Array.from(
              new Set([...(nameResolution[ip] ?? []), ...names])
            );
          }
        }
        recOffset += (recLen + 3) & ~3;
      }
    }

    offset += blockLen;
  }

  return {
    format: 'pcapng',
    records,
    nameResolution,
  };
}
