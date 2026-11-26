import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Globe,
  Info,
  XCircle,
  ArrowRight,
  Lock,
  Unlock,
  Lightbulb,
  BookOpen,
  ChevronDown,
  ChevronRight,
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
  const [showGlossary, setShowGlossary] = useState(false);

  const sortedProtocols = Object.entries(analysis.protocolCounts).sort(
    (a, b) => b[1] - a[1]
  );

  const hasIssues = analysis.errorCount > 0 || analysis.warningCount > 0;

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

  const glossaryItems = [
    {
      term: 'IP Address',
      th: 'เหมือน "บ้านเลขที่" ของเครื่องคอมพิวเตอร์หรือเซิร์ฟเวอร์บนอินเทอร์เน็ต เพื่อใช้ส่งข้อมูลให้ถูกที่',
      en: 'Like a street address for each device or server on the internet.',
    },
    {
      term: 'DNS',
      th: 'เหมือน "สมุดหน้าเหลือง" ที่คอยแปลชื่อเว็บ (เช่น google.com) ให้เป็นเลข IP ก่อนเชื่อมต่อ',
      en: 'The internet phonebook that translates domain names into IP addresses.',
    },
    {
      term: 'HTTPS / TLS',
      th: 'การส่งข้อมูลแบบ "ใส่ซองปิดผนึก" (เข้ารหัส) เพื่อไม่ให้คนอื่นแอบอ่านระหว่างทาง',
      en: 'Encrypted communication (like a sealed envelope) so nobody in the middle can read it.',
    },
    {
      term: 'HTTP',
      th: 'การเปิดเว็บแบบ "ไม่ใส่ซอง" (ไม่ได้เข้ารหัส) ใครที่ดักฟังบนเครือข่ายเดียวกันอาจอ่านข้อความได้',
      en: 'Unencrypted web traffic that can be read if intercepted on the same network.',
    },
    {
      term: 'TCP Reset (RST)',
      th: 'เหมือนไปเคาะประตูบ้านปลายทางแล้วถูก "ปิดประตูใส่ทันที" (มักเกิดจากพอร์ตปิด หรือ Firewall บล็อก)',
      en: 'Connection abruptly refused or closed by the other side (port closed or firewall blocked).',
    },
    {
      term: 'Ping (ICMP)',
      th: 'การตะโกนถามอีกเครื่องว่า "อยู่ไหม?" เพื่อเช็กว่าเชื่อมต่อถึงกันหรือเปล่า',
      en: 'A quick "Are you there?" check to see if a device is reachable.',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Plain-Human Health Banner */}
      <div
        className={`rounded-xl border p-4 sm:p-5 flex flex-wrap items-center justify-between gap-4 ${
          analysis.errorCount > 0
            ? 'border-rose-200 bg-rose-50/70'
            : hasIssues
              ? 'border-amber-200 bg-amber-50/70'
              : 'border-emerald-200 bg-emerald-50/70'
        }`}
      >
        <div className="flex items-start gap-3">
          {analysis.errorCount > 0 ? (
            <XCircle className="h-6 w-6 text-rose-600 shrink-0 mt-0.5" />
          ) : hasIssues ? (
            <AlertTriangle className="h-6 w-6 text-amber-600 shrink-0 mt-0.5" />
          ) : (
            <CheckCircle2 className="h-6 w-6 text-emerald-600 shrink-0 mt-0.5" />
          )}
          <div>
            <h2 className="text-base font-bold text-slate-900">
              {analysis.errorCount > 0
                ? lang === 'th'
                  ? `พบจุดที่เชื่อมต่อมีปัญหา ${analysis.errorCount} รายการ`
                  : `Found ${analysis.errorCount} connection error(s)`
                : hasIssues
                  ? lang === 'th'
                    ? `การเชื่อมต่อทำงานได้ แต่มีข้อควรระวัง ${analysis.warningCount} รายการ`
                    : `Traffic looks okay, with ${analysis.warningCount} warning(s)`
                  : lang === 'th'
                    ? 'การสื่อสารทั้งหมดปกติดี ไม่พบปัญหา'
                    : 'All network traffic looks healthy'}
            </h2>
            <p className="text-xs sm:text-sm text-slate-600 mt-0.5">
              {lang === 'th'
                ? `ไฟล์นี้บันทึกข้อมูลนาน ${formatMs(analysis.durationMs)} • มีการคุยกันทั้งหมด ${analysis.nodes.length} เครื่อง/เซิร์ฟเวอร์ (${analysis.domains.length} เว็บไซต์)`
                : `Captured over ${formatMs(analysis.durationMs)} • ${analysis.nodes.length} hosts (${analysis.domains.length} domains)`}
            </p>
          </div>
        </div>

        {hasIssues && (
          <button
            type="button"
            onClick={() => onJumpToPackets(undefined, '')}
            className="rounded-lg bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 ring-1 ring-slate-200 hover:bg-slate-50 transition-colors"
          >
            {lang === 'th' ? 'ดูรายการแพ็กเก็ตทั้งหมด' : 'View all packets'}
          </button>
        )}
      </div>

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
            {lang === 'th' ? 'อุปกรณ์ / เซิร์ฟเวอร์' : 'Unique Hosts'}
          </div>
          <div className="mt-1 text-2xl font-bold text-slate-900">
            {analysis.nodes.length}
          </div>
          <div className="mt-0.5 text-xs text-slate-500">
            {analysis.domains.length} {lang === 'th' ? 'โดเมน' : 'domains'}
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

      {/* Story & Insights + Troubleshooting Tips */}
      <section>
        <h2 className="text-base font-semibold text-slate-900 mb-3">
          {lang === 'th'
            ? 'สรุปแบบภาษาคน (เกิดอะไรขึ้นบ้าง & ควรเช็กอะไรต่อ)'
            : 'Plain-Language Findings & Tips'}
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
                {(item.tipTh || item.tipEn) && (
                  <div className="mt-2.5 rounded-lg bg-white/80 border border-slate-200/70 px-3 py-2 flex items-start gap-2 text-xs text-slate-700">
                    <Lightbulb className="h-3.5 w-3.5 text-amber-500 shrink-0 mt-0.5" />
                    <span>{lang === 'th' ? item.tipTh : item.tipEn}</span>
                  </div>
                )}
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
                      {dom.via === 'TLS'
                        ? 'HTTPS'
                        : dom.via}
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

      {/* Quick Beginner Glossary */}
      <section className="rounded-xl border border-slate-200 bg-white overflow-hidden">
        <button
          type="button"
          onClick={() => setShowGlossary((v) => !v)}
          className="w-full px-5 py-3.5 flex items-center justify-between text-left hover:bg-slate-50 transition-colors"
        >
          <span className="inline-flex items-center gap-2 text-sm font-semibold text-slate-900">
            <BookOpen className="h-4 w-4 text-sky-600" />
            {lang === 'th'
              ? 'คำศัพท์น่ารู้แบบเข้าใจง่าย (สำหรับมือใหม่)'
              : 'Quick Beginner Glossary'}
          </span>
          {showGlossary ? (
            <ChevronDown className="h-4 w-4 text-slate-400" />
          ) : (
            <ChevronRight className="h-4 w-4 text-slate-400" />
          )}
        </button>

        {showGlossary && (
          <div className="border-t border-slate-100 p-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5 bg-slate-50/50">
            {glossaryItems.map((g) => (
              <div
                key={g.term}
                className="rounded-lg border border-slate-200 bg-white p-3"
              >
                <div className="text-xs font-bold text-slate-900">{g.term}</div>
                <p className="mt-1 text-xs leading-relaxed text-slate-600">
                  {lang === 'th' ? g.th : g.en}
                </p>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};
