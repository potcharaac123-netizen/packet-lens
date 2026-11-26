import React, { useState } from 'react';
import { X, ChevronDown, ChevronRight, Code2, ArrowRight } from 'lucide-react';
import type { Lang, ParsedPacket } from '../types/packet';
import {
  formatBytes,
  formatMs,
  getHostDisplayName,
  getProtocolBadgeClass,
} from '../utils/format';

interface PacketInspectorProps {
  packet: ParsedPacket | null;
  ipToDomains: Record<string, string[]>;
  lang: Lang;
  onClose: () => void;
}

function formatHexDump(bytes: Uint8Array): string[] {
  const lines: string[] = [];
  const maxBytes = Math.min(bytes.length, 512);
  for (let i = 0; i < maxBytes; i += 16) {
    const offset = i.toString(16).padStart(4, '0');
    const hexParts: string[] = [];
    let ascii = '';
    for (let j = 0; j < 16; j++) {
      if (i + j < maxBytes) {
        const b = bytes[i + j];
        hexParts.push(b.toString(16).padStart(2, '0'));
        ascii += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
      } else {
        hexParts.push('  ');
      }
    }
    lines.push(`${offset}   ${hexParts.slice(0, 8).join(' ')}  ${hexParts.slice(8).join(' ')}   |${ascii}|`);
  }
  if (bytes.length > maxBytes) {
    lines.push(`... (${bytes.length - maxBytes} more bytes)`);
  }
  return lines;
}

export const PacketInspector: React.FC<PacketInspectorProps> = ({
  packet,
  ipToDomains,
  lang,
  onClose,
}) => {
  const [showHex, setShowHex] = useState(false);

  if (!packet) return null;

  const src = getHostDisplayName(packet.srcIp, ipToDomains);
  const dst = getHostDisplayName(packet.dstIp, ipToDomains);

  const bannerClass =
    packet.severity === 'error'
      ? 'bg-rose-50 border-rose-200 text-rose-900'
      : packet.severity === 'warning'
        ? 'bg-amber-50 border-amber-200 text-amber-900'
        : packet.severity === 'success'
          ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
          : 'bg-sky-50 border-sky-200 text-sky-900';

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-slate-900/25 backdrop-blur-[1px]">
      <div className="fixed inset-0" onClick={onClose} />
      <aside className="relative z-10 w-full max-w-xl bg-white h-full shadow-2xl border-l border-slate-200 flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4">
          <div className="flex items-center gap-2.5">
            <span className="font-mono text-sm font-bold text-slate-900">
              Packet #{packet.id}
            </span>
            <span
              className={`rounded-md px-2 py-0.5 text-xs font-medium ring-1 ${getProtocolBadgeClass(packet.protocol)}`}
            >
              {packet.protocol}
            </span>
            <span className="text-xs text-slate-500 font-mono">
              {formatMs(packet.relativeTimeMs)} • {formatBytes(packet.originalLen)}
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
            aria-label="Close"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* Plain-language card */}
          <div className={`rounded-xl border p-4 ${bannerClass}`}>
            <div className="text-xs font-semibold uppercase tracking-wide opacity-75">
              {lang === 'th' ? 'แพ็กเก็ตนี้กำลังทำอะไร?' : 'What is this packet doing?'}
            </div>
            <div className="mt-1 text-sm font-bold">
              {lang === 'th' ? packet.summaryTh : packet.summaryEn}
            </div>
            <p className="mt-1.5 text-xs leading-relaxed opacity-90">
              {lang === 'th' ? packet.detailTh : packet.detailEn}
            </p>
          </div>

          {/* Endpoints */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-3">
              <div className="text-[11px] font-medium text-slate-500">
                {lang === 'th' ? 'ผู้ส่ง (Source)' : 'Source'}
              </div>
              <div className="mt-0.5 text-sm font-semibold text-slate-900 truncate">
                {src.primary}
              </div>
              <div className="text-xs font-mono text-slate-500">
                {packet.srcIp}
                {packet.srcPort !== undefined ? `:${packet.srcPort}` : ''}
              </div>
            </div>

            <div className="rounded-xl border border-slate-200 bg-slate-50/70 p-3">
              <div className="text-[11px] font-medium text-slate-500 flex items-center gap-1">
                <ArrowRight className="h-3 w-3" />
                {lang === 'th' ? 'ผู้รับ (Destination)' : 'Destination'}
              </div>
              <div className="mt-0.5 text-sm font-semibold text-slate-900 truncate">
                {dst.primary}
              </div>
              <div className="text-xs font-mono text-slate-500">
                {packet.dstIp}
                {packet.dstPort !== undefined ? `:${packet.dstPort}` : ''}
              </div>
            </div>
          </div>

          {/* Protocol Layers */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              {lang === 'th' ? 'รายละเอียดแต่ละชั้น (Protocol Layers)' : 'Protocol Layers'}
            </h3>
            {packet.layers.map((layer, idx) => (
              <div
                key={`${layer.name}-${idx}`}
                className="rounded-xl border border-slate-200 bg-white overflow-hidden"
              >
                <div className="bg-slate-50/80 border-b border-slate-100 px-4 py-2.5 flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-900">
                    {lang === 'th' ? layer.titleTh : layer.titleEn}
                  </span>
                  <span className="text-[11px] font-mono text-slate-500">
                    {layer.name}
                  </span>
                </div>
                <div className="p-3.5 space-y-2">
                  {layer.fields.map((f) => (
                    <div
                      key={f.key}
                      className="flex items-start justify-between gap-4 text-xs"
                    >
                      <span className="text-slate-500 shrink-0">
                        {lang === 'th' ? f.labelTh : f.labelEn}
                      </span>
                      <span className="font-mono text-slate-900 text-right break-all">
                        {f.value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Optional Hex Dump */}
          <div className="rounded-xl border border-slate-200 overflow-hidden">
            <button
              type="button"
              onClick={() => setShowHex((v) => !v)}
              className="w-full px-4 py-2.5 bg-slate-50 flex items-center justify-between text-xs font-medium text-slate-700 hover:bg-slate-100 transition-colors"
            >
              <span className="inline-flex items-center gap-1.5">
                <Code2 className="h-4 w-4 text-slate-500" />
                {lang === 'th'
                  ? 'ดูข้อมูลดิบ (Raw Hex & ASCII)'
                  : 'Raw Hex & ASCII Dump'}
              </span>
              {showHex ? (
                <ChevronDown className="h-4 w-4 text-slate-500" />
              ) : (
                <ChevronRight className="h-4 w-4 text-slate-500" />
              )}
            </button>
            {showHex && (
              <pre className="p-3.5 bg-slate-900 text-slate-100 text-[11px] leading-relaxed overflow-x-auto font-mono">
                {formatHexDump(packet.rawBytes).join('\n')}
              </pre>
            )}
          </div>
        </div>
      </aside>
    </div>
  );
};
