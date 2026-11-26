import React, { useRef, useState } from 'react';
import { FileUp, Play, ShieldCheck, Sparkles, Network, GitCommitHorizontal } from 'lucide-react';
import type { Lang } from '../types/packet';

interface DropZoneProps {
  lang: Lang;
  onFileSelected: (file: File) => void;
  onLoadSample: () => void;
  errorMsg?: string | null;
}

export const DropZone: React.FC<DropZoneProps> = ({
  lang,
  onFileSelected,
  onLoadSample,
  errorMsg,
}) => {
  const inputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) onFileSelected(file);
  };

  return (
    <div className="mx-auto max-w-4xl px-4 py-12 sm:py-16">
      <div className="text-center mb-10">
        <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-slate-900">
          {lang === 'th'
            ? 'อ่านไฟล์ .pcap แบบเข้าใจง่าย ไม่ต้องง้อ Wireshark'
            : 'Read .pcap files in plain language, no Wireshark needed'}
        </h1>
        <p className="mt-3 text-base sm:text-lg text-slate-600 max-w-2xl mx-auto">
          {lang === 'th'
            ? 'ลากไฟล์ .pcap หรือ .pcapng มาวางเพื่อดูสรุปว่าเครื่องคุยกับเว็บไหนบ้าง มีปัญหาตรงไหน พร้อมแผนภาพ Sequence และ Topology อัตโนมัติ'
            : 'Drop your .pcap or .pcapng capture to see plain-language summaries, websites visited, connection issues, and interactive diagrams.'}
        </p>
      </div>

      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={`relative cursor-pointer rounded-2xl border-2 border-dashed p-10 sm:p-14 text-center transition-all ${
          isDragging
            ? 'border-sky-500 bg-sky-50/70 scale-[1.01]'
            : 'border-slate-300 bg-white hover:border-sky-400 hover:bg-slate-50/60 shadow-sm'
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) onFileSelected(f);
          }}
        />
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-xl bg-sky-50 text-sky-600 mb-4">
          <FileUp className="h-7 w-7" />
        </div>
        <p className="text-lg font-semibold text-slate-900">
          {lang === 'th'
            ? 'คลิกเพื่อเลือกไฟล์ หรือลากไฟล์มาวางที่นี่'
            : 'Click to browse or drag & drop a capture file'}
        </p>
        <p className="mt-1.5 text-sm text-slate-500">
          {lang === 'th'
            ? 'รองรับ .pcap (libpcap), .pcapng, .cap'
            : 'Supports .pcap (libpcap), .pcapng, .cap'}
        </p>

        <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              inputRef.current?.click();
            }}
            className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-4 py-2.5 text-sm font-medium text-white hover:bg-slate-800 transition-colors"
          >
            <FileUp className="h-4 w-4" />
            {lang === 'th' ? 'เลือกไฟล์จากเครื่อง' : 'Choose File'}
          </button>

          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onLoadSample();
            }}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-4 py-2.5 text-sm font-medium text-slate-700 hover:bg-slate-50 transition-colors"
          >
            <Play className="h-4 w-4 text-sky-600" />
            {lang === 'th' ? 'ลองเปิดไฟล์ตัวอย่าง' : 'Try Sample Capture'}
          </button>
        </div>

        <div className="mt-6 inline-flex items-center gap-2 rounded-full bg-emerald-50 px-3.5 py-1 text-xs font-medium text-emerald-700">
          <ShieldCheck className="h-3.5 w-3.5" />
          {lang === 'th'
            ? 'ประมวลผลบน Browser 100% ข้อมูลไม่ถูกอัปโหลดขึ้น Server'
            : '100% client-side — your capture never leaves your browser'}
        </div>
      </div>

      {errorMsg && (
        <div className="mt-4 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {errorMsg}
        </div>
      )}

      <div className="mt-10 grid grid-cols-1 sm:grid-cols-3 gap-5">
        <div className="rounded-xl border border-slate-200 bg-white p-5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-50 text-sky-600 mb-3">
            <Sparkles className="h-5 w-5" />
          </div>
          <h3 className="font-semibold text-slate-900 text-sm">
            {lang === 'th' ? 'แปลเป็นภาษาคน' : 'Plain-Language Story'}
          </h3>
          <p className="mt-1 text-xs leading-relaxed text-slate-600">
            {lang === 'th'
              ? 'สรุปให้ทันทีว่าเข้าเว็บอะไรบ้าง มี DNS ล่ม หรือการเชื่อมต่อถูกตัด (RST) ตรงไหน'
              : 'Automatically highlights domains visited, DNS failures, and connection resets.'}
          </p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-teal-50 text-teal-600 mb-3">
            <GitCommitHorizontal className="h-5 w-5" />
          </div>
          <h3 className="font-semibold text-slate-900 text-sm">
            {lang === 'th' ? 'Sequence Diagram' : 'Sequence Diagram'}
          </h3>
          <p className="mt-1 text-xs leading-relaxed text-slate-600">
            {lang === 'th'
              ? 'เห็นลำดับการส่งข้อมูลระหว่างเครื่องและเซิร์ฟเวอร์ทีละขั้น คลิกดูไส้ในได้ทันที'
              : 'Follow chronological host-to-host flows step by step and click any arrow to inspect.'}
          </p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-amber-50 text-amber-600 mb-3">
            <Network className="h-5 w-5" />
          </div>
          <h3 className="font-semibold text-slate-900 text-sm">
            {lang === 'th' ? 'Network Topology' : 'Network Topology'}
          </h3>
          <p className="mt-1 text-xs leading-relaxed text-slate-600">
            {lang === 'th'
              ? 'แผนผังความสัมพันธ์แบบลากวางได้ แยกแยะเครื่องในวงแลน Router และเซิร์ฟเวอร์ภายนอก'
              : 'Interactive node-link map distinguishing local devices, gateways, DNS, and servers.'}
          </p>
        </div>
      </div>
    </div>
  );
};
