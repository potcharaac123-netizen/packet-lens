import React, { useMemo, useRef, useState } from 'react';
import {
  Activity,
  FileUp,
  GitCommitHorizontal,
  Languages,
  LayoutDashboard,
  List,
  Network,
  Repeat,
  RotateCcw,
} from 'lucide-react';
import { DropZone } from './components/DropZone';
import { LoopsView } from './components/LoopsView';
import { OverviewView } from './components/OverviewView';
import { PacketInspector } from './components/PacketInspector';
import { PacketTableView, type IpMacDirection } from './components/PacketTableView';
import { SequenceDiagramView } from './components/SequenceDiagramView';
import { TopologyView } from './components/TopologyView';
import { analyzeCaptureBuffer } from './parser/analyzer';
import { generateSamplePcap } from './parser/samplePcap';
import type { CaptureAnalysis, Lang } from './types/packet';
import { formatBytes } from './utils/format';

type TabKey = 'overview' | 'loops' | 'sequence' | 'topology' | 'packets';

export function App() {
  const [lang, setLang] = useState<Lang>('th');
  const [analysis, setAnalysis] = useState<CaptureAnalysis | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>('overview');
  const [selectedPacketId, setSelectedPacketId] = useState<number | null>(null);

  // PacketTable filter state
  const [searchText, setSearchText] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [ipMacFilter, setIpMacFilter] = useState('ALL');
  const [ipMacDirection, setIpMacDirection] = useState<IpMacDirection>('any');
  const [onlyWarnings, setOnlyWarnings] = useState(false);
  const [packetIdFilter, setPacketIdFilter] = useState<number[] | null>(null);
  const [sequenceLoopFilter, setSequenceLoopFilter] = useState<number | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleBuffer = (fileName: string, buffer: ArrayBuffer) => {
    try {
      setErrorMsg(null);
      const result = analyzeCaptureBuffer(fileName, buffer);
      setAnalysis(result);
      setActiveTab('overview');
      setSelectedPacketId(null);
      setSearchText('');
      setProtocolFilter('ALL');
      setIpMacFilter('ALL');
      setIpMacDirection('any');
      setOnlyWarnings(false);
      setPacketIdFilter(null);
      setSequenceLoopFilter(null);
    } catch (err) {
      setErrorMsg(
        err instanceof Error
          ? err.message
          : 'ไม่สามารถอ่านไฟล์ได้ กรุณาตรวจสอบว่าเป็นไฟล์ .pcap หรือ .pcapng'
      );
    }
  };

  const handleFileSelected = async (file: File) => {
    const buffer = await file.arrayBuffer();
    handleBuffer(file.name, buffer);
  };

  const handleLoadSample = () => {
    const buffer = generateSamplePcap();
    handleBuffer('sample-web-traffic.pcap', buffer);
  };

  const selectedPacket = useMemo(() => {
    if (!analysis || selectedPacketId === null) return null;
    return analysis.packets.find((p) => p.id === selectedPacketId) ?? null;
  }, [analysis, selectedPacketId]);

  const tabs: { key: TabKey; labelTh: string; labelEn: string; icon: React.ReactNode }[] = [
    {
      key: 'overview',
      labelTh: 'ภาพรวม & สรุปเรื่องราว',
      labelEn: 'Overview & Story',
      icon: <LayoutDashboard className="h-4 w-4" />,
    },
    {
      key: 'loops',
      labelTh: 'รอบการสื่อสาร (Loops)',
      labelEn: 'Communication Loops',
      icon: <Repeat className="h-4 w-4" />,
    },
    {
      key: 'sequence',
      labelTh: 'แผนภาพลำดับ (Sequence)',
      labelEn: 'Sequence Diagram',
      icon: <GitCommitHorizontal className="h-4 w-4" />,
    },
    {
      key: 'topology',
      labelTh: 'แผนผังเครือข่าย (Topology)',
      labelEn: 'Network Topology',
      icon: <Network className="h-4 w-4" />,
    },
    {
      key: 'packets',
      labelTh: 'รายการแพ็กเก็ต',
      labelEn: 'Packets',
      icon: <List className="h-4 w-4" />,
    },
  ];

  return (
    <div
      className="min-h-screen flex flex-col bg-slate-50 text-slate-900"
      onDragOver={(e) => e.preventDefault()}
      onDrop={(e) => {
        e.preventDefault();
        const f = e.dataTransfer.files?.[0];
        if (f) handleFileSelected(f);
      }}
    >
      {/* Top Navbar */}
      <header className="sticky top-0 z-30 border-b border-slate-200 bg-white/90 backdrop-blur-md">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 h-14 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-900 text-white shrink-0">
              <Activity className="h-4 w-4 text-sky-400" />
            </div>
            <span className="font-bold tracking-tight text-slate-900 text-base">
              PacketLens
            </span>
            {analysis && (
              <div className="hidden sm:flex items-center gap-2 rounded-full bg-slate-100 px-3 py-1 text-xs text-slate-700 truncate max-w-xs">
                <span className="font-medium truncate">{analysis.fileName}</span>
                <span className="text-slate-400">•</span>
                <span className="text-slate-500 shrink-0">
                  {formatBytes(analysis.fileSize)}
                </span>
              </div>
            )}
          </div>

          <div className="flex items-center gap-2">
            {analysis && (
              <>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".pcap,.pcapng,.cap"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) handleFileSelected(f);
                  }}
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50 transition-colors"
                >
                  <FileUp className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline">
                    {lang === 'th' ? 'เปิดไฟล์ใหม่' : 'Open File'}
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setAnalysis(null);
                    setSelectedPacketId(null);
                  }}
                  className="inline-flex items-center gap-1 rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-slate-800"
                  title={lang === 'th' ? 'กลับหน้าแรก' : 'Reset'}
                >
                  <RotateCcw className="h-4 w-4" />
                </button>
              </>
            )}

            <button
              type="button"
              onClick={() => setLang((l) => (l === 'th' ? 'en' : 'th'))}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors"
            >
              <Languages className="h-3.5 w-3.5 text-sky-600" />
              {lang === 'th' ? 'TH' : 'EN'}
            </button>
          </div>
        </div>

        {/* Tab Bar */}
        {analysis && (
          <div className="mx-auto max-w-7xl px-4 sm:px-6 flex items-center gap-1 overflow-x-auto border-t border-slate-100">
            {tabs.map((tab) => {
              const active = activeTab === tab.key;
              return (
                <button
                  key={tab.key}
                  type="button"
                  onClick={() => setActiveTab(tab.key)}
                  className={`inline-flex items-center gap-2 px-3.5 py-2.5 text-xs sm:text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
                    active
                      ? 'border-sky-600 text-sky-700'
                      : 'border-transparent text-slate-600 hover:text-slate-900 hover:border-slate-300'
                  }`}
                >
                  {tab.icon}
                  {lang === 'th' ? tab.labelTh : tab.labelEn}
                </button>
              );
            })}
          </div>
        )}
      </header>

      {/* Main Content */}
      <main className="flex-1">
        {!analysis ? (
          <DropZone
            lang={lang}
            onFileSelected={handleFileSelected}
            onLoadSample={handleLoadSample}
            errorMsg={errorMsg}
          />
        ) : (
          <div className="mx-auto max-w-7xl px-4 sm:px-6 py-6">
            {activeTab === 'overview' && (
              <OverviewView
                analysis={analysis}
                lang={lang}
                onInspectPacket={(id) => setSelectedPacketId(id)}
                onJumpToPackets={(ids, filterText) => {
                  setPacketIdFilter(ids ?? null);
                  setSearchText(filterText ?? '');
                  setProtocolFilter('ALL');
                  setOnlyWarnings(false);
                  setActiveTab('packets');
                }}
              />
            )}

            {activeTab === 'loops' && (
              <LoopsView
                analysis={analysis}
                lang={lang}
                onInspectPacket={(id) => setSelectedPacketId(id)}
                onOpenInSequence={(loop) => {
                  setSequenceLoopFilter(loop.id);
                  setActiveTab('sequence');
                }}
              />
            )}

            {activeTab === 'sequence' && (
              <SequenceDiagramView
                analysis={analysis}
                lang={lang}
                selectedPacketId={selectedPacketId}
                onSelectPacket={(id) => setSelectedPacketId(id)}
                loopIdFilter={sequenceLoopFilter}
                onClearLoopFilter={() => setSequenceLoopFilter(null)}
              />
            )}

            {activeTab === 'topology' && (
              <TopologyView
                analysis={analysis}
                lang={lang}
                onFilterHost={(ip) => {
                  setSearchText('');
                  setIpMacFilter(ip);
                  setIpMacDirection('any');
                  setPacketIdFilter(null);
                  setProtocolFilter('ALL');
                  setOnlyWarnings(false);
                  setActiveTab('packets');
                }}
              />
            )}

            {activeTab === 'packets' && (
              <PacketTableView
                analysis={analysis}
                lang={lang}
                searchText={searchText}
                onSearchChange={setSearchText}
                protocolFilter={protocolFilter}
                onProtocolFilterChange={setProtocolFilter}
                ipMacFilter={ipMacFilter}
                onIpMacFilterChange={setIpMacFilter}
                ipMacDirection={ipMacDirection}
                onIpMacDirectionChange={setIpMacDirection}
                onlyWarnings={onlyWarnings}
                onOnlyWarningsChange={setOnlyWarnings}
                packetIdFilter={packetIdFilter}
                onClearPacketIdFilter={() => setPacketIdFilter(null)}
                selectedPacketId={selectedPacketId}
                onSelectPacket={(id) => setSelectedPacketId(id)}
              />
            )}
          </div>
        )}
      </main>

      {/* Packet Inspector Drawer */}
      <PacketInspector
        packet={selectedPacket}
        ipToDomains={analysis?.ipToDomains ?? {}}
        lang={lang}
        onClose={() => setSelectedPacketId(null)}
      />
    </div>
  );
}

export default App;
