import React from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Globe,
  Info,
  XCircle,
  ArrowRight,
  Lock,
  Unlock,
} from 'lucide-react';
import type { CaptureAnalysis, Lang } from '../types/packet';
import { formatBytes, formatMs, getProtocolBadgeClass } from '../utils/format';

interface OverviewViewProps {
  analysis: CaptureAnalysis;
  lang: Lang;
  onJumpToPackets: (packetIds?: number[], filterText?: string) => void;
  onInspectPacket: (packetId: number) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  analysis,
  lang,
  onJumpToPackets,
  onInspectPacket,
}) => {
  const sortedProtocols = Object.entries(analysis.protocolCounts).sort(
    (a, b) => b[1] - a[1]
  );

  const severityIcon = (sev: string) => {
    switch (sev) {
      case 'error':
        return <XCircle className="h-5 w-5 text-rose-600 shrink-0" />;
      case 'warning':
        return <AlertTriangle className="h-5 w-5 text-amber-600 shrink-0" />;
      case 'success':
        return <CheckCircle2 className="h-5 w-5 text-emerald-600 shrink-0" />;
      default:
        return <Info className="h-5 w-5 text-sky-600 shrink-0" />;
    }
  };

  const severityCardClass = (sev: string) => {
    switch (sev) {
      case 'error':
        return 'border-rose-200 bg-rose-50/60';
      case 'warning':
        return 'border-amber-200 bg-amber-50/60';
      case 'success':
        return 'border-emerald-200 bg-emerald-50/60';
      default:
        return 'border-slate-200 bg-white';
    }
  };

  return (
    <div className="space-y-6">
      {/* Summary Metrics Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <div className="text-xs font-medium text-slate-500">
            {lang === 'th' ? 'จำนวนแพ็กเก็ต' : 'Total Packets'}
          </div>
          <div className="mt-1 text-2xl font-bold text-slate-900">
            {analysis.totalPackets.toLocaleString()}
          </div>
          <div className="mt-0.5 text-xs text-slate-500">
            {formatBytes(analysis.totalBytes)}
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <div className="text-xs font-medium text-slate-500">
            {lang === 'th' ? 'ระยะเวลาที่ดักจับ' : 'Capture Duration'}
          </div>
          <div className="mt-1 text-2xl font-bold text-slate-900">
            {formatMs(analysis.durationMs)}
          </div>
          <div className="mt-0.5 text-xs text-slate-500 uppercase">
            {analysis.fileFormat}
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <div className="text-xs font-medium text-slate-500">
            {lang === 'th' ? 'อุปกรณ์ / โฮสต์' : 'Unique Hosts'}
          </div>
          <div className="mt-1 text-2xl font-bold text-slate-900">
            {analysis.nodes.length}
          </div>
          <div className="mt-0.5 text-xs text-slate-500">
            {analysis.domains.length}{' '}
            {lang === 'th' ? 'โดเมน' : 'domains'}
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <div className="text-xs font-medium text-slate-500">
            {lang === 'th' ? 'จุดที่น่าสังเกต' : 'Alerts & Warnings'}
          </div>
          <div className="mt-1 text-2xl font-bold text-slate-900">
            {analysis.errorCount + analysis.warningCount}
          </div>
          <div className="mt-0.5 text-xs text-slate-500">
            {analysis.errorCount} {lang === 'th' ? 'ข้อผิดพลาด' : 'errors'},{' '}
            {analysis.warningCount} {lang === 'th' ? 'คำเตือน' : 'warnings'}
          </div>
        </div>
      </div>

      {/* Story & Insights */}
      <section>
        <h2 className="text-base font-semibold text-slate-900 mb-3">
          {lang === 'th'
            ? 'สรุปเหตุการณ์สำคัญ (เกิดอะไรขึ้นบ้าง?)'
            : 'Key Findings & Story'}
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {analysis.insights.map((item) => (
            <div
              key={item.id}
              className={`rounded-xl border p-4 flex items-start gap-3 ${severityCardClass(item.severity)}`}
            >
              {severityIcon(item.severity)}
              <div className="flex-1 min-w-0">
                <h3 className="text-sm font-semibold text-slate-900">
                  {lang === 'th' ? item.titleTh : item.titleEn}
                </h3>
                <p className="mt-1 text-xs leading-relaxed text-slate-600">
                  {lang === 'th' ? item.descriptionTh : item.descriptionEn}
                </p>
                {item.relatedPacketIds.length > 0 && (
                  <div className="mt-2.5 flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => onInspectPacket(item.relatedPacketIds[0])}
                      className="inline-flex items-center gap-1 rounded-md bg-white px-2.5 py-1 text-xs font-medium text-slate-700 ring-1 ring-slate-200 hover:bg-slate-50 transition-colors"
                    >
                      {lang === 'th'
                        ? `ดูแพ็กเก็ต #${item.relatedPacketIds[0]}`
                        : `Inspect #${item.relatedPacketIds[0]}`}
                      <ArrowRight className="h-3 w-3" />
                    </button>
                    {item.relatedPacketIds.length > 1 && (
                      <button
                        type="button"
                        onClick={() => onJumpToPackets(item.relatedPacketIds)}
                        className="text-xs font-medium text-sky-700 hover:underline"
                      >
                        {lang === 'th'
                          ? `กรองดูทั้งหมด (${item.relatedPacketIds.length})`
                          : `Filter all (${item.relatedPacketIds.length})`}
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Websites / Domains Visited */}
        <section className="lg:col-span-2 rounded-xl border border-slate-200 bg-white p-5">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-base font-semibold text-slate-900 flex items-center gap-2">
              <Globe className="h-4 w-4 text-sky-600" />
              {lang === 'th'
                ? 'เว็บไซต์และบริการที่ถูกเรียกใช้งาน'
                : 'Websites & Services Accessed'}
            </h2>
            <span className="text-xs text-slate-500">
              {analysis.domains.length} {lang === 'th' ? 'รายการ' : 'total'}
            </span>
          </div>

          {analysis.domains.length === 0 ? (
            <p className="text-sm text-slate-500 py-6 text-center">
              {lang === 'th'
                ? 'ไม่พบชื่อโดเมนในไฟล์นี้ (อาจเป็นทราฟฟิกภายในหรือเชื่อมต่อผ่าน IP โดยตรง)'
                : 'No domain names found (direct IP or local-only traffic).'}
            </p>
          ) : (
            <div className="divide-y divide-slate-100">
              {analysis.domains.map((dom) => (
                <div
                  key={dom.domain}
                  className="py-2.5 flex items-center justify-between gap-3"
                >
                  <div className="min-w-0 flex items-center gap-2.5">
                    {dom.via === 'TLS' ? (
                      <Lock
                        className="h-4 w-4 text-teal-600 shrink-0"
                        aria-label="Encrypted"
                      />
                    ) : dom.via === 'HTTP' ? (
                      <Unlock
                        className="h-4 w-4 text-amber-600 shrink-0"
                        aria-label="Unencrypted"
                      />
                    ) : (
                      <Globe className="h-4 w-4 text-sky-600 shrink-0" />
                    )}
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-slate-900 truncate">
                          {dom.domain}
                        </span>
                        {dom.hasError && (
                          <span className="rounded bg-rose-50 px-1.5 py-0.5 text-[10px] font-semibold text-rose-700 ring-1 ring-rose-200">
                            {lang === 'th' ? 'ไม่พบ' : 'Error'}
                          </span>
                        )}
                      </div>
                      {dom.ips.length > 0 && (
                        <div className="text-xs text-slate-500 font-mono truncate">
                          {dom.ips.join(', ')}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <span
                      className={`rounded-md px-2 py-0.5 text-xs font-medium ring-1 ${getProtocolBadgeClass(dom.via)}`}
                    >
                      {dom.via}
                    </span>
                    <button
                      type="button"
                      onClick={() => onJumpToPackets(undefined, dom.domain)}
                      className="text-xs font-medium text-sky-700 hover:underline"
                    >
                      {lang === 'th' ? 'ดูแพ็กเก็ต' : 'Filter'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Protocol Breakdown */}
        <section className="rounded-xl border border-slate-200 bg-white p-5">
          <h2 className="text-base font-semibold text-slate-900 mb-3">
            {lang === 'th' ? 'สัดส่วนโปรโตคอล' : 'Protocol Breakdown'}
          </h2>
          <div className="space-y-2.5">
            {sortedProtocols.map(([proto, count]) => {
              const pct = Math.round((count / analysis.totalPackets) * 100);
              return (
                <div key={proto}>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <button
                      type="button"
                      onClick={() => onJumpToPackets(undefined, proto)}
                      className="font-medium text-slate-800 hover:text-sky-700"
                    >
                      {proto}
                    </button>
                    <span className="text-slate-500">
                      {count} ({pct}%)
                    </span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-slate-100 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-sky-500"
                      style={{ width: `${Math.max(pct, 2)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      </div>
    </div>
  );
};
