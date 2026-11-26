import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  GitCommitHorizontal,
  PauseCircle,
  PlayCircle,
  Search,
  XCircle,
} from 'lucide-react';
import type {
  CaptureAnalysis,
  CommunicationLoop,
  Lang,
  LoopStatus,
} from '../types/packet';
import {
  formatBytes,
  formatMs,
  getHostDisplayName,
  getProtocolBadgeClass,
} from '../utils/format';

interface LoopsViewProps {
  analysis: CaptureAnalysis;
  lang: Lang;
  onInspectPacket: (packetId: number) => void;
  onOpenInSequence: (loop: CommunicationLoop) => void;
}

export const LoopsView: React.FC<LoopsViewProps> = ({
  analysis,
  lang,
  onInspectPacket,
  onOpenInSequence,
}) => {
  const [statusFilter, setStatusFilter] = useState<'all' | 'issues' | 'completed'>('all');
  const [searchText, setSearchText] = useState('');
  const [expandedLoopId, setExpandedLoopId] = useState<number | null>(
    analysis.loops[0]?.id ?? null
  );

  const counts = useMemo(() => {
    let completed = 0;
    let issues = 0;
    for (const l of analysis.loops) {
      if (l.status === 'error' || l.status === 'stuck' || l.status === 'warning') {
        issues++;
      } else {
        completed++;
      }
    }
    return { total: analysis.loops.length, completed, issues };
  }, [analysis.loops]);

  const filteredLoops = useMemo(() => {
    const q = searchText.trim().toLowerCase();
    return analysis.loops.filter((l) => {
      if (
        statusFilter === 'issues' &&
        l.status !== 'error' &&
        l.status !== 'stuck' &&
        l.status !== 'warning'
      ) {
        return false;
      }
      if (
        statusFilter === 'completed' &&
        (l.status === 'error' || l.status === 'stuck' || l.status === 'warning')
      ) {
        return false;
      }
      if (q) {
        const hay =
          `${l.id} ${l.titleTh} ${l.titleEn} ${l.initiatorIp} ${l.responderIp} ${l.protocol} ${l.stuckReasonTh ?? ''} ${l.stuckReasonEn ?? ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [analysis.loops, statusFilter, searchText]);

  const statusMeta = (status: LoopStatus) => {
    switch (status) {
      case 'error':
        return {
          labelTh: 'เกิดข้อผิดพลาด / ถูกตัด',
          labelEn: 'Error / Reset',
          badgeClass: 'bg-rose-50 text-rose-700 ring-rose-200',
          borderClass: 'border-rose-200',
          icon: <XCircle className="h-4 w-4 text-rose-600" />,
        };
      case 'stuck':
        return {
          labelTh: 'ค้าง / ไม่ตอบกลับ',
          labelEn: 'Stuck / No Reply',
          badgeClass: 'bg-rose-50 text-rose-700 ring-rose-200',
          borderClass: 'border-rose-200',
          icon: <PauseCircle className="h-4 w-4 text-rose-600" />,
        };
      case 'warning':
        return {
          labelTh: 'ส่งซ้ำ / ตอบช้า',
          labelEn: 'Slow / Retransmit',
          badgeClass: 'bg-amber-50 text-amber-800 ring-amber-200',
          borderClass: 'border-amber-200',
          icon: <AlertTriangle className="h-4 w-4 text-amber-600" />,
        };
      case 'active':
        return {
          labelTh: 'กำลังสื่อสาร (ยังไม่ปิด)',
          labelEn: 'Active / Open',
          badgeClass: 'bg-sky-50 text-sky-700 ring-sky-200',
          borderClass: 'border-slate-200',
          icon: <PlayCircle className="h-4 w-4 text-sky-600" />,
        };
      default:
        return {
          labelTh: 'จบรอบสมบูรณ์',
          labelEn: 'Completed',
          badgeClass: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
          borderClass: 'border-slate-200',
          icon: <CheckCircle2 className="h-4 w-4 text-emerald-600" />,
        };
    }
  };

  return (
    <div className="space-y-5">
      {/* Summary Strip */}
      <div className="grid grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <div className="text-xs font-medium text-slate-500">
            {lang === 'th' ? 'รอบการสื่อสารทั้งหมด' : 'Total Loops'}
          </div>
          <div className="mt-1 text-2xl font-bold text-slate-900">
            {counts.total}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <div className="text-xs font-medium text-slate-500">
            {lang === 'th' ? 'ปกติ / สมบูรณ์' : 'Normal / Completed'}
          </div>
          <div className="mt-1 text-2xl font-bold text-emerald-600">
            {counts.completed}
          </div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <div className="text-xs font-medium text-slate-500">
            {lang === 'th' ? 'ติดขัด / มีปัญหา' : 'Stuck / Issues'}
          </div>
          <div className="mt-1 text-2xl font-bold text-rose-600">
            {counts.issues}
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="rounded-xl border border-slate-200 bg-white p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setStatusFilter('all')}
            className={`rounded-lg px-3 py-1.5 text-xs font-medium border transition-colors ${
              statusFilter === 'all'
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
            }`}
          >
            {lang === 'th' ? `ทั้งหมด (${counts.total})` : `All (${counts.total})`}
          </button>
          <button
            type="button"
            onClick={() => setStatusFilter('issues')}
            className={`rounded-lg px-3 py-1.5 text-xs font-medium border transition-colors ${
              statusFilter === 'issues'
                ? 'bg-rose-600 text-white border-rose-600'
                : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
            }`}
          >
            {lang === 'th'
              ? `ติดขัด / มีปัญหา (${counts.issues})`
              : `Stuck & Issues (${counts.issues})`}
          </button>
          <button
            type="button"
            onClick={() => setStatusFilter('completed')}
            className={`rounded-lg px-3 py-1.5 text-xs font-medium border transition-colors ${
              statusFilter === 'completed'
                ? 'bg-emerald-600 text-white border-emerald-600'
                : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
            }`}
          >
            {lang === 'th'
              ? `ปกติ / สมบูรณ์ (${counts.completed})`
              : `Normal (${counts.completed})`}
          </button>
        </div>

        <div className="relative">
          <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            placeholder={
              lang === 'th' ? 'ค้นหา Loop, IP, โดเมน...' : 'Search loop, IP, domain...'
            }
            className="pl-9 pr-3 py-1.5 text-sm rounded-lg border border-slate-200 focus:outline-none focus:ring-2 focus:ring-sky-500 w-60"
          />
        </div>
      </div>

      {/* Loop Cards */}
      <div className="space-y-3.5">
        {filteredLoops.length === 0 ? (
          <div className="rounded-xl border border-slate-200 bg-white py-12 text-center text-sm text-slate-500">
            {lang === 'th'
              ? 'ไม่พบรอบการสื่อสารที่ตรงกับเงื่อนไข'
              : 'No communication loops match the filter.'}
          </div>
        ) : (
          filteredLoops.map((loop) => {
            const meta = statusMeta(loop.status);
            const isExpanded = expandedLoopId === loop.id;
            const loopPackets = isExpanded
              ? analysis.packets.filter((p) => loop.packetIds.includes(p.id))
              : [];

            return (
              <div
                key={loop.id}
                className={`rounded-xl border bg-white overflow-hidden shadow-xs ${meta.borderClass}`}
              >
                {/* Card Header */}
                <div
                  onClick={() =>
                    setExpandedLoopId(isExpanded ? null : loop.id)
                  }
                  className="p-4 cursor-pointer hover:bg-slate-50/70 transition-colors"
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-2.5 min-w-0">
                      {isExpanded ? (
                        <ChevronDown className="h-4 w-4 text-slate-400 shrink-0" />
                      ) : (
                        <ChevronRight className="h-4 w-4 text-slate-400 shrink-0" />
                      )}
                      <span className="rounded-md bg-slate-900 px-2 py-0.5 text-xs font-bold text-white font-mono">
                        Loop #{loop.id}
                      </span>
                      <span
                        className={`rounded-md px-2 py-0.5 text-xs font-medium ring-1 ${getProtocolBadgeClass(loop.protocol)}`}
                      >
                        {loop.protocol}
                      </span>
                      <h3 className="text-sm font-semibold text-slate-900 truncate">
                        {lang === 'th' ? loop.titleTh : loop.titleEn}
                      </h3>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-xs text-slate-500 font-mono flex items-center gap-1">
                        <Clock className="h-3.5 w-3.5" />
                        {formatMs(loop.durationMs)} • {loop.packetIds.length} pkts •{' '}
                        {formatBytes(loop.totalBytes)}
                      </span>
                      <span
                        className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ${meta.badgeClass}`}
                      >
                        {meta.icon}
                        {lang === 'th' ? meta.labelTh : meta.labelEn}
                      </span>
                    </div>
                  </div>

                  {/* 3 Milestones: Start -> Issue/Bottleneck -> End */}
                  <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-2.5 text-xs">
                    <div className="rounded-lg bg-slate-50 border border-slate-100 px-3 py-2">
                      <div className="font-semibold text-slate-500 text-[11px]">
                        {lang === 'th' ? '1. เริ่มตรงไหน' : '1. Started at'}
                      </div>
                      <div className="mt-0.5 text-slate-800 truncate">
                        {lang === 'th' ? loop.startDescTh : loop.startDescEn}
                      </div>
                    </div>

                    <div
                      className={`rounded-lg border px-3 py-2 ${
                        loop.stuckReasonTh
                          ? loop.status === 'warning'
                            ? 'bg-amber-50/70 border-amber-200 text-amber-900'
                            : 'bg-rose-50/70 border-rose-200 text-rose-900'
                          : 'bg-emerald-50/50 border-emerald-100 text-emerald-900'
                      }`}
                    >
                      <div className="font-semibold text-[11px] opacity-75">
                        {lang === 'th' ? '2. ติดตรงไหน / สถานะ' : '2. Bottleneck / Status'}
                      </div>
                      <div className="mt-0.5 font-medium truncate">
                        {loop.stuckReasonTh
                          ? lang === 'th'
                            ? loop.stuckReasonTh
                            : loop.stuckReasonEn
                          : lang === 'th'
                            ? `ราบรื่น (รอสูงสุด ${formatMs(loop.maxGapMs)})`
                            : `Smooth (max wait ${formatMs(loop.maxGapMs)})`}
                      </div>
                    </div>

                    <div className="rounded-lg bg-slate-50 border border-slate-100 px-3 py-2">
                      <div className="font-semibold text-slate-500 text-[11px]">
                        {lang === 'th' ? '3. สุดตรงไหน' : '3. Ended at'}
                      </div>
                      <div className="mt-0.5 text-slate-800 truncate">
                        {lang === 'th' ? loop.endDescTh : loop.endDescEn}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Expanded Packet Steps inside this Loop */}
                {isExpanded && (
                  <div className="border-t border-slate-200 bg-slate-50/60 p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-slate-700">
                        {lang === 'th'
                          ? `ลำดับแพ็กเก็ตใน Loop #${loop.id} (คลิกเพื่อดูรายละเอียด)`
                          : `Packets in Loop #${loop.id} (click to inspect)`}
                      </span>
                      <button
                        type="button"
                        onClick={() => onOpenInSequence(loop)}
                        className="inline-flex items-center gap-1.5 rounded-lg bg-white px-2.5 py-1 text-xs font-medium text-sky-700 ring-1 ring-slate-200 hover:bg-sky-50"
                      >
                        <GitCommitHorizontal className="h-3.5 w-3.5" />
                        {lang === 'th'
                          ? 'ดูใน Sequence Diagram'
                          : 'View in Sequence Diagram'}
                      </button>
                    </div>

                    <div className="divide-y divide-slate-200/70 rounded-lg border border-slate-200 bg-white">
                      {loopPackets.map((pkt) => {
                        const src = getHostDisplayName(pkt.srcIp, analysis.ipToDomains);
                        const dst = getHostDisplayName(pkt.dstIp, analysis.ipToDomains);
                        const gap = pkt.deltaFromPrevInLoopMs ?? 0;

                        return (
                          <div
                            key={pkt.id}
                            onClick={() => onInspectPacket(pkt.id)}
                            className="px-3.5 py-2 flex flex-wrap items-center justify-between gap-2 text-xs hover:bg-sky-50/60 cursor-pointer transition-colors"
                          >
                            <div className="flex items-center gap-2 min-w-0">
                              <span className="font-mono text-slate-400 w-9 shrink-0">
                                #{pkt.id}
                              </span>
                              {gap > 0 && (
                                <span
                                  className={`font-mono text-[10px] px-1.5 py-0.5 rounded shrink-0 ${
                                    gap >= 200
                                      ? 'bg-amber-100 text-amber-800 font-semibold'
                                      : 'bg-slate-100 text-slate-500'
                                  }`}
                                >
                                  +{formatMs(gap)}
                                </span>
                              )}
                              <span className="font-medium text-slate-700 shrink-0">
                                {src.primary} → {dst.primary}
                              </span>
                              <span className="text-slate-600 truncate">
                                {lang === 'th' ? pkt.summaryTh : pkt.summaryEn}
                              </span>
                              {pkt.isRetransmission && (
                                <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-semibold text-amber-800 shrink-0">
                                  Retransmit
                                </span>
                              )}
                            </div>
                            <span className="font-mono text-[11px] text-slate-400 shrink-0">
                              {formatBytes(pkt.originalLen)}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
