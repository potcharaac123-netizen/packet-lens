import React, { useMemo, useState } from 'react';
import {
  ChevronLeft,
  ChevronRight,
  Search,
  EyeOff,
  Eye,
  Network,
  Layers,
  X,
} from 'lucide-react';
import type { CaptureAnalysis, CommunicationLoop, Lang, ParsedPacket } from '../types/packet';
import {
  formatMs,
  getHostDisplayName,
  getProtocolStrokeColor,
} from '../utils/format';

interface SequenceDiagramViewProps {
  analysis: CaptureAnalysis;
  lang: Lang;
  selectedPacketId: number | null;
  onSelectPacket: (packetId: number) => void;
  loopIdFilter: number | null;
  onClearLoopFilter: () => void;
}

const PAGE_SIZE = 50;

type DiagramRow =
  | { kind: 'loop-header'; loop: CommunicationLoop; y: number }
  | { kind: 'packet'; pkt: ParsedPacket; y: number };

export const SequenceDiagramView: React.FC<SequenceDiagramViewProps> = ({
  analysis,
  lang,
  selectedPacketId,
  onSelectPacket,
  loopIdFilter,
  onClearLoopFilter,
}) => {
  const [hidePureAck, setHidePureAck] = useState(true);
  const [groupByLoop, setGroupByLoop] = useState(true);
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [ipMacFilter, setIpMacFilter] = useState<string>('ALL');
  const [searchText, setSearchText] = useState('');
  const [page, setPage] = useState(0);

  const loopMap = useMemo(() => {
    const m = new Map<number, CommunicationLoop>();
    for (const l of analysis.loops) m.set(l.id, l);
    return m;
  }, [analysis.loops]);

  const { uniqueIps, uniqueMacs } = useMemo(() => {
    const ips = new Set<string>();
    const macs = new Set<string>();
    for (const p of analysis.packets) {
      if (p.srcIp && p.srcIp !== 'Unknown') ips.add(p.srcIp);
      if (p.dstIp && p.dstIp !== 'Unknown') ips.add(p.dstIp);
      if (p.srcMac) macs.add(p.srcMac);
      if (p.dstMac) macs.add(p.dstMac);
    }
    return { uniqueIps: Array.from(ips), uniqueMacs: Array.from(macs) };
  }, [analysis.packets]);

  const filteredPackets = useMemo(() => {
    const q = searchText.trim().toLowerCase();
    return analysis.packets.filter((p) => {
      if (loopIdFilter !== null && p.loopId !== loopIdFilter) {
        return false;
      }
      if (hidePureAck && p.protocol === 'TCP' && loopIdFilter === null) {
        const isPureAck =
          p.tcpFlags?.length === 1 &&
          p.tcpFlags[0] === 'ACK' &&
          p.layers.every((l) => l.name !== 'HTTP' && l.name !== 'TLS');
        if (isPureAck) return false;
      }
      if (protocolFilter !== 'ALL' && p.protocol !== protocolFilter) {
        return false;
      }
      if (ipMacFilter !== 'ALL') {
        const matches =
          p.srcIp === ipMacFilter ||
          p.dstIp === ipMacFilter ||
          p.srcMac === ipMacFilter ||
          p.dstMac === ipMacFilter;
        if (!matches) return false;
      }
      if (q) {
        const srcHost = getHostDisplayName(p.srcIp, analysis.ipToDomains).primary;
        const dstHost = getHostDisplayName(p.dstIp, analysis.ipToDomains).primary;
        const hay =
          `${p.id} ${p.srcIp} ${p.dstIp} ${p.srcMac ?? ''} ${p.dstMac ?? ''} ${srcHost} ${dstHost} ${p.protocol} ${p.summaryTh} ${p.summaryEn}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [
    analysis,
    loopIdFilter,
    hidePureAck,
    protocolFilter,
    ipMacFilter,
    searchText,
  ]);

  const totalPages = Math.max(1, Math.ceil(filteredPackets.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages - 1);
  const pagePackets = filteredPackets.slice(
    safePage * PAGE_SIZE,
    (safePage + 1) * PAGE_SIZE
  );

  // Determine ordered participants (hosts) in this page
  const hosts = useMemo(() => {
    const list: string[] = [];
    for (const p of pagePackets) {
      if (!list.includes(p.srcIp)) list.push(p.srcIp);
      if (!list.includes(p.dstIp)) list.push(p.dstIp);
    }
    return list;
  }, [pagePackets]);

  const colWidth = 190;
  const leftMargin = 84;
  const topHeaderHeight = 72;
  const loopBannerHeight = 32;
  const rowHeight = 52;

  const { rows, svgHeight } = useMemo(() => {
    const out: DiagramRow[] = [];
    let cursorY = topHeaderHeight + 8;
    let lastLoopId: number | undefined;

    for (const pkt of pagePackets) {
      if (groupByLoop && pkt.loopId !== undefined && pkt.loopId !== lastLoopId) {
        const loop = loopMap.get(pkt.loopId);
        if (loop) {
          out.push({ kind: 'loop-header', loop, y: cursorY });
          cursorY += loopBannerHeight;
        }
        lastLoopId = pkt.loopId;
      }
      out.push({ kind: 'packet', pkt, y: cursorY + 24 });
      cursorY += rowHeight;
    }

    return { rows: out, svgHeight: cursorY + 24 };
  }, [pagePackets, groupByLoop, loopMap]);

  const svgWidth = Math.max(680, leftMargin + hosts.length * colWidth + 40);
  const protocols = ['ALL', ...Object.keys(analysis.protocolCounts)];

  const loopBannerColors = (loop: CommunicationLoop) => {
    if (loop.status === 'error' || loop.status === 'stuck') {
      return { bg: '#fff1f2', border: '#fecdd3', text: '#be123c' };
    }
    if (loop.status === 'warning') {
      return { bg: '#fffbeb', border: '#fde68a', text: '#b45309' };
    }
    return { bg: '#f1f5f9', border: '#cbd5e1', text: '#334155' };
  };

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="rounded-xl border border-slate-200 bg-white p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchText}
              onChange={(e) => {
                setSearchText(e.target.value);
                setPage(0);
              }}
              placeholder={
                lang === 'th'
                  ? 'ค้นหา IP, MAC, โดเมน...'
                  : 'Search IP, MAC, domain...'
              }
              className="pl-9 pr-3 py-1.5 text-sm rounded-lg border border-slate-200 focus:outline-none focus:ring-2 focus:ring-sky-500 w-52"
            />
          </div>

          <div className="relative flex items-center">
            <Network className="h-3.5 w-3.5 text-slate-400 absolute left-2.5 pointer-events-none" />
            <select
              value={ipMacFilter}
              onChange={(e) => {
                setIpMacFilter(e.target.value);
                setPage(0);
              }}
              className="pl-8 pr-3 py-1.5 text-sm rounded-lg border border-slate-200 bg-white text-slate-700 focus:outline-none focus:ring-2 focus:ring-sky-500 max-w-[210px]"
            >
              <option value="ALL">
                {lang === 'th' ? 'ทุก IP / MAC' : 'All IP / MAC'}
              </option>
              {uniqueIps.length > 0 && (
                <optgroup label="IP Address">
                  {uniqueIps.map((ip) => {
                    const d = analysis.ipToDomains[ip]?.[0];
                    return (
                      <option key={`ip-${ip}`} value={ip}>
                        {d ? `${ip} (${d})` : ip}
                      </option>
                    );
                  })}
                </optgroup>
              )}
              {uniqueMacs.length > 0 && (
                <optgroup label="MAC Address">
                  {uniqueMacs.map((mac) => (
                    <option key={`mac-${mac}`} value={mac}>
                      {mac}
                    </option>
                  ))}
                </optgroup>
              )}
            </select>
          </div>

          <select
            value={protocolFilter}
            onChange={(e) => {
              setProtocolFilter(e.target.value);
              setPage(0);
            }}
            className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-sky-500"
          >
            {protocols.map((pr) => (
              <option key={pr} value={pr}>
                {pr === 'ALL'
                  ? lang === 'th'
                    ? 'ทุกโปรโตคอล'
                    : 'All Protocols'
                  : pr}
              </option>
            ))}
          </select>

          <button
            type="button"
            onClick={() => setGroupByLoop((v) => !v)}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium border transition-colors ${
              groupByLoop
                ? 'bg-sky-50 text-sky-700 border-sky-200'
                : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
            }`}
          >
            <Layers className="h-3.5 w-3.5" />
            {lang === 'th' ? 'แบ่งแถบตาม Loop' : 'Group by Loop'}
          </button>

          <button
            type="button"
            onClick={() => {
              setHidePureAck((v) => !v);
              setPage(0);
            }}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium border transition-colors ${
              hidePureAck
                ? 'bg-sky-50 text-sky-700 border-sky-200'
                : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
            }`}
          >
            {hidePureAck ? (
              <EyeOff className="h-3.5 w-3.5" />
            ) : (
              <Eye className="h-3.5 w-3.5" />
            )}
            {lang === 'th' ? 'ซ่อน TCP ACK เปล่า' : 'Hide empty TCP ACKs'}
          </button>

          {loopIdFilter !== null && (
            <button
              type="button"
              onClick={onClearLoopFilter}
              className="inline-flex items-center gap-1 rounded-lg bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-white hover:bg-slate-800"
            >
              Loop #{loopIdFilter}
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        {/* Pagination */}
        <div className="flex items-center gap-2 text-xs text-slate-600">
          <span>
            {filteredPackets.length}{' '}
            {lang === 'th' ? 'เหตุการณ์' : 'events'}
          </span>
          <div className="flex items-center gap-1">
            <button
              type="button"
              disabled={safePage === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              className="p-1.5 rounded-md border border-slate-200 disabled:opacity-40 hover:bg-slate-50"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <span className="px-2 font-medium">
              {safePage + 1} / {totalPages}
            </span>
            <button
              type="button"
              disabled={safePage >= totalPages - 1}
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              className="p-1.5 rounded-md border border-slate-200 disabled:opacity-40 hover:bg-slate-50"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Sequence Diagram SVG Canvas */}
      <div className="rounded-xl border border-slate-200 bg-white overflow-x-auto shadow-sm">
        {pagePackets.length === 0 ? (
          <div className="py-16 text-center text-sm text-slate-500">
            {lang === 'th'
              ? 'ไม่พบเหตุการณ์ที่ตรงกับเงื่อนไขการกรอง'
              : 'No matching packet events found.'}
          </div>
        ) : (
          <svg
            width={svgWidth}
            height={svgHeight}
            className="block select-none"
          >
            <defs>
              <marker
                id="arrow-end"
                markerWidth="8"
                markerHeight="8"
                refX="7"
                refY="4"
                orient="auto"
              >
                <path d="M0,1 L7,4 L0,7 Z" fill="context-stroke" />
              </marker>
            </defs>

            {/* Lifelines & Host Headers */}
            {hosts.map((ip, idx) => {
              const x = leftMargin + idx * colWidth + colWidth / 2;
              const display = getHostDisplayName(ip, analysis.ipToDomains);
              const shortPrimary =
                display.primary.length > 22
                  ? display.primary.slice(0, 20) + '…'
                  : display.primary;

              return (
                <g key={ip}>
                  <line
                    x1={x}
                    y1={topHeaderHeight - 10}
                    x2={x}
                    y2={svgHeight - 16}
                    stroke="#e2e8f0"
                    strokeWidth={1.5}
                    strokeDasharray="4 4"
                  />
                  <rect
                    x={x - 82}
                    y={12}
                    width={164}
                    height={46}
                    rx={10}
                    fill="#f8fafc"
                    stroke="#cbd5e1"
                    strokeWidth={1}
                  />
                  <text
                    x={x}
                    y={32}
                    textAnchor="middle"
                    className="fill-slate-900 text-[12px] font-semibold"
                  >
                    {shortPrimary}
                  </text>
                  <text
                    x={x}
                    y={48}
                    textAnchor="middle"
                    className="fill-slate-500 text-[10px] font-mono"
                  >
                    {display.secondary ?? 'Host'}
                  </text>
                </g>
              );
            })}

            {/* Loop Headers & Packet Arrows */}
            {rows.map((row) => {
              if (row.kind === 'loop-header') {
                const { loop, y } = row;
                const colors = loopBannerColors(loop);
                const title = lang === 'th' ? loop.titleTh : loop.titleEn;
                const statusTxt =
                  loop.stuckReasonTh
                    ? lang === 'th'
                      ? loop.stuckReasonTh
                      : loop.stuckReasonEn
                    : lang === 'th'
                      ? `จบรอบ (${formatMs(loop.durationMs)})`
                      : `Completed (${formatMs(loop.durationMs)})`;

                return (
                  <g key={`loop-hdr-${loop.id}-${y}`}>
                    <rect
                      x={10}
                      y={y + 4}
                      width={svgWidth - 20}
                      height={24}
                      rx={6}
                      fill={colors.bg}
                      stroke={colors.border}
                      strokeWidth={1}
                    />
                    <text
                      x={20}
                      y={y + 20}
                      fill={colors.text}
                      className="text-[11px] font-semibold"
                    >
                      Loop #{loop.id}: {title}
                    </text>
                    <text
                      x={svgWidth - 22}
                      y={y + 20}
                      textAnchor="end"
                      fill={colors.text}
                      className="text-[10px] font-medium"
                    >
                      {statusTxt}
                    </text>
                  </g>
                );
              }

              const { pkt, y } = row;
              const srcIdx = hosts.indexOf(pkt.srcIp);
              const dstIdx = hosts.indexOf(pkt.dstIp);
              const x1 = leftMargin + srcIdx * colWidth + colWidth / 2;
              const x2 = leftMargin + dstIdx * colWidth + colWidth / 2;
              const color = getProtocolStrokeColor(pkt.protocol, pkt.severity);
              const isSelected = selectedPacketId === pkt.id;
              const labelText =
                lang === 'th' ? pkt.summaryTh : pkt.summaryEn;
              const gapSuffix =
                (pkt.deltaFromPrevInLoopMs ?? 0) >= 50
                  ? ` (+${formatMs(pkt.deltaFromPrevInLoopMs!)})`
                  : '';
              const fullLabel = `[${pkt.protocol}] ${labelText}${gapSuffix}`;
              const truncatedLabel =
                fullLabel.length > 56
                  ? fullLabel.slice(0, 54) + '…'
                  : fullLabel;

              const midX = x1 === x2 ? x1 + 45 : (x1 + x2) / 2;

              return (
                <g
                  key={pkt.id}
                  onClick={() => onSelectPacket(pkt.id)}
                  className="cursor-pointer group"
                >
                  <rect
                    x={4}
                    y={y - 22}
                    width={svgWidth - 8}
                    height={44}
                    rx={6}
                    fill={isSelected ? '#e0f2fe' : 'transparent'}
                    className="group-hover:fill-slate-50/90 transition-colors"
                  />

                  <text
                    x={14}
                    y={y - 2}
                    className="fill-slate-400 text-[10px] font-mono"
                  >
                    #{pkt.id}
                  </text>
                  <text
                    x={14}
                    y={y + 11}
                    className="fill-slate-400 text-[10px] font-mono"
                  >
                    {formatMs(pkt.relativeTimeMs)}
                  </text>

                  {x1 === x2 ? (
                    <path
                      d={`M ${x1} ${y - 6} C ${x1 + 42} ${y - 6}, ${x1 + 42} ${y + 10}, ${x1 + 4} ${y + 10}`}
                      fill="none"
                      stroke={color}
                      strokeWidth={isSelected ? 2.5 : 1.75}
                      markerEnd="url(#arrow-end)"
                    />
                  ) : (
                    <line
                      x1={x1}
                      y1={y + 6}
                      x2={x2 > x1 ? x2 - 4 : x2 + 4}
                      y2={y + 6}
                      stroke={color}
                      strokeWidth={isSelected ? 2.5 : 1.75}
                      markerEnd="url(#arrow-end)"
                    />
                  )}

                  <text
                    x={midX}
                    y={y - 3}
                    textAnchor="middle"
                    fill={color}
                    className="text-[11px] font-medium"
                  >
                    {truncatedLabel}
                  </text>
                </g>
              );
            })}
          </svg>
        )}
      </div>
    </div>
  );
};
