import React, { useMemo } from 'react';
import { AlertTriangle, Search, X } from 'lucide-react';
import type { CaptureAnalysis, Lang } from '../types/packet';
import {
  formatBytes,
  formatMs,
  getHostDisplayName,
  getProtocolBadgeClass,
} from '../utils/format';

interface PacketTableViewProps {
  analysis: CaptureAnalysis;
  lang: Lang;
  searchText: string;
  onSearchChange: (val: string) => void;
  protocolFilter: string;
  onProtocolFilterChange: (val: string) => void;
  onlyWarnings: boolean;
  onOnlyWarningsChange: (val: boolean) => void;
  packetIdFilter: number[] | null;
  onClearPacketIdFilter: () => void;
  selectedPacketId: number | null;
  onSelectPacket: (packetId: number) => void;
}

export const PacketTableView: React.FC<PacketTableViewProps> = ({
  analysis,
  lang,
  searchText,
  onSearchChange,
  protocolFilter,
  onProtocolFilterChange,
  onlyWarnings,
  onOnlyWarningsChange,
  packetIdFilter,
  onClearPacketIdFilter,
  selectedPacketId,
  onSelectPacket,
}) => {
  const protocols = ['ALL', ...Object.keys(analysis.protocolCounts)];

  const filtered = useMemo(() => {
    const q = searchText.trim().toLowerCase();
    const idSet = packetIdFilter ? new Set(packetIdFilter) : null;
    return analysis.packets.filter((p) => {
      if (idSet && !idSet.has(p.id)) return false;
      if (onlyWarnings && p.severity !== 'warning' && p.severity !== 'error') {
        return false;
      }
      if (protocolFilter !== 'ALL' && p.protocol !== protocolFilter) {
        return false;
      }
      if (q) {
        const srcHost = getHostDisplayName(p.srcIp, analysis.ipToDomains).primary;
        const dstHost = getHostDisplayName(p.dstIp, analysis.ipToDomains).primary;
        const hay =
          `${p.id} ${p.srcIp} ${p.dstIp} ${srcHost} ${dstHost} ${p.protocol} ${p.summaryTh} ${p.summaryEn} ${p.srcPort ?? ''} ${p.dstPort ?? ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [analysis, searchText, protocolFilter, onlyWarnings, packetIdFilter]);

  return (
    <div className="space-y-4">
      {/* Filter Bar */}
      <div className="rounded-xl border border-slate-200 bg-white p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchText}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder={
                lang === 'th'
                  ? 'ค้นหา IP, โดเมน, พอร์ต, ข้อความ...'
                  : 'Search IP, domain, port, summary...'
              }
              className="pl-9 pr-8 py-1.5 text-sm rounded-lg border border-slate-200 focus:outline-none focus:ring-2 focus:ring-sky-500 w-64"
            />
            {searchText && (
              <button
                type="button"
                onClick={() => onSearchChange('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          <select
            value={protocolFilter}
            onChange={(e) => onProtocolFilterChange(e.target.value)}
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
            onClick={() => onOnlyWarningsChange(!onlyWarnings)}
            className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium border transition-colors ${
              onlyWarnings
                ? 'bg-amber-50 text-amber-800 border-amber-200'
                : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
            }`}
          >
            <AlertTriangle className="h-3.5 w-3.5" />
            {lang === 'th' ? 'เฉพาะที่มีปัญหา / คำเตือน' : 'Warnings & Errors only'}
          </button>

          {packetIdFilter && (
            <button
              type="button"
              onClick={onClearPacketIdFilter}
              className="inline-flex items-center gap-1 rounded-lg bg-sky-50 px-2.5 py-1.5 text-xs font-medium text-sky-700 ring-1 ring-sky-200 hover:bg-sky-100"
            >
              {lang === 'th'
                ? `กรองเฉพาะ ${packetIdFilter.length} แพ็กเก็ต`
                : `Filtered to ${packetIdFilter.length} packets`}
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        <div className="text-xs text-slate-500">
          {lang === 'th'
            ? `แสดง ${filtered.length} จาก ${analysis.totalPackets} แพ็กเก็ต`
            : `Showing ${filtered.length} of ${analysis.totalPackets} packets`}
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-slate-200 bg-white overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/80 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                <th className="py-3 pl-4 pr-2 w-14">#</th>
                <th className="py-3 px-2 w-24">
                  {lang === 'th' ? 'เวลา' : 'Time'}
                </th>
                <th className="py-3 px-2">
                  {lang === 'th' ? 'ต้นทาง → ปลายทาง' : 'Source → Destination'}
                </th>
                <th className="py-3 px-2 w-24">
                  {lang === 'th' ? 'โปรโตคอล' : 'Protocol'}
                </th>
                <th className="py-3 px-2">
                  {lang === 'th' ? 'คำอธิบาย' : 'Plain Summary'}
                </th>
                <th className="py-3 pl-2 pr-4 text-right w-20">
                  {lang === 'th' ? 'ขนาด' : 'Size'}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-sm">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    {lang === 'th'
                      ? 'ไม่พบแพ็กเก็ตที่ตรงกับการค้นหา'
                      : 'No packets match your filters.'}
                  </td>
                </tr>
              ) : (
                filtered.slice(0, 500).map((pkt) => {
                  const src = getHostDisplayName(pkt.srcIp, analysis.ipToDomains);
                  const dst = getHostDisplayName(pkt.dstIp, analysis.ipToDomains);
                  const isSel = selectedPacketId === pkt.id;
                  const rowBg = isSel
                    ? 'bg-sky-50/90'
                    : pkt.severity === 'error'
                      ? 'bg-rose-50/40 hover:bg-rose-50/70'
                      : pkt.severity === 'warning'
                        ? 'bg-amber-50/30 hover:bg-amber-50/60'
                        : 'hover:bg-slate-50';

                  return (
                    <tr
                      key={pkt.id}
                      onClick={() => onSelectPacket(pkt.id)}
                      className={`cursor-pointer transition-colors ${rowBg}`}
                    >
                      <td className="py-2.5 pl-4 pr-2 font-mono text-xs text-slate-500">
                        {pkt.id}
                      </td>
                      <td className="py-2.5 px-2 font-mono text-xs text-slate-500 whitespace-nowrap">
                        {formatMs(pkt.relativeTimeMs)}
                      </td>
                      <td className="py-2.5 px-2">
                        <div className="flex items-center gap-1.5 flex-wrap text-xs">
                          <span className="font-medium text-slate-800" title={pkt.srcIp}>
                            {src.primary}
                          </span>
                          <span className="text-slate-400">→</span>
                          <span className="font-medium text-slate-800" title={pkt.dstIp}>
                            {dst.primary}
                          </span>
                        </div>
                      </td>
                      <td className="py-2.5 px-2">
                        <span
                          className={`inline-block rounded-md px-2 py-0.5 text-xs font-medium ring-1 ${getProtocolBadgeClass(pkt.protocol)}`}
                        >
                          {pkt.protocol}
                        </span>
                      </td>
                      <td className="py-2.5 px-2 text-xs text-slate-700">
                        <div className="flex items-center gap-2">
                          <span>
                            {lang === 'th' ? pkt.summaryTh : pkt.summaryEn}
                          </span>
                          {(pkt.warningTagTh || pkt.warningTagEn) && (
                            <span
                              className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold ${
                                pkt.severity === 'error'
                                  ? 'bg-rose-100 text-rose-800'
                                  : 'bg-amber-100 text-amber-800'
                              }`}
                            >
                              {lang === 'th' ? pkt.warningTagTh : pkt.warningTagEn}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-2.5 pl-2 pr-4 text-right font-mono text-xs text-slate-500 whitespace-nowrap">
                        {formatBytes(pkt.originalLen)}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        {filtered.length > 500 && (
          <div className="border-t border-slate-200 bg-slate-50 px-4 py-2 text-xs text-slate-500 text-center">
            {lang === 'th'
              ? `แสดง 500 แพ็กเก็ตแรกเพื่อความลื่นไหล (ใช้ช่องค้นหาเพื่อเจาะจงแพ็กเก็ตที่ต้องการ)`
              : `Showing first 500 matching packets for performance. Use search/filters to narrow down.`}
          </div>
        )}
      </div>
    </div>
  );
};
