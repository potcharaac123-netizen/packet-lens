import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Monitor, Router, Globe, Server, Radio, ArrowRight } from 'lucide-react';
import type { CaptureAnalysis, Lang, TopologyEdge, TopologyNode } from '../types/packet';
import { formatBytes, getProtocolBadgeClass } from '../utils/format';

interface TopologyViewProps {
  analysis: CaptureAnalysis;
  lang: Lang;
  onFilterHost: (ip: string) => void;
}

interface NodePos {
  x: number;
  y: number;
}

export const TopologyView: React.FC<TopologyViewProps> = ({
  analysis,
  lang,
  onFilterHost,
}) => {
  const width = 880;
  const height = 500;

  // Limit to top 24 nodes if capture is huge so graph stays readable
  const displayNodes = useMemo(() => {
    return [...analysis.nodes]
      .sort(
        (a, b) =>
          b.packetsSent + b.packetsReceived - (a.packetsSent + a.packetsReceived)
      )
      .slice(0, 24);
  }, [analysis.nodes]);

  const displayNodeIds = useMemo(
    () => new Set(displayNodes.map((n) => n.id)),
    [displayNodes]
  );

  const displayEdges = useMemo(
    () =>
      analysis.edges.filter(
        (e) => displayNodeIds.has(e.source) && displayNodeIds.has(e.target)
      ),
    [analysis.edges, displayNodeIds]
  );

  const [positions, setPositions] = useState<Record<string, NodePos>>({});
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const draggingRef = useRef<{ id: string; offsetX: number; offsetY: number } | null>(
    null
  );
  const svgRef = useRef<SVGSVGElement>(null);

  // Compute initial clean layout by role
  useEffect(() => {
    const locals = displayNodes.filter((n) => n.role === 'local');
    const infra = displayNodes.filter(
      (n) => n.role === 'gateway' || n.role === 'dns' || n.role === 'broadcast'
    );
    const externals = displayNodes.filter((n) => n.role === 'external');

    const next: Record<string, NodePos> = {};
    const placeColumn = (list: TopologyNode[], x: number) => {
      const gap = height / (list.length + 1);
      list.forEach((n, i) => {
        next[n.id] = { x, y: gap * (i + 1) };
      });
    };

    if (locals.length > 0 && externals.length > 0) {
      placeColumn(locals, 160);
      placeColumn(infra, 430);
      placeColumn(externals, 710);
    } else {
      // Radial fallback
      const cx = width / 2;
      const cy = height / 2;
      const r = Math.min(width, height) * 0.35;
      displayNodes.forEach((n, i) => {
        const angle = (2 * Math.PI * i) / Math.max(1, displayNodes.length);
        next[n.id] = {
          x: cx + r * Math.cos(angle),
          y: cy + r * Math.sin(angle),
        };
      });
    }

    setPositions(next);
    setSelectedNodeId(displayNodes[0]?.id ?? null);
    setSelectedEdgeId(null);
  }, [displayNodes]);

  const handlePointerMove = (e: React.PointerEvent<SVGSVGElement>) => {
    if (!draggingRef.current || !svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const scaleX = width / rect.width;
    const scaleY = height / rect.height;
    const x = Math.max(
      50,
      Math.min(width - 50, (e.clientX - rect.left) * scaleX - draggingRef.current.offsetX)
    );
    const y = Math.max(
      40,
      Math.min(height - 40, (e.clientY - rect.top) * scaleY - draggingRef.current.offsetY)
    );
    const id = draggingRef.current.id;
    setPositions((prev) => ({ ...prev, [id]: { x, y } }));
  };

  const handlePointerUp = () => {
    draggingRef.current = null;
  };

  const roleStyle = (role: TopologyNode['role']) => {
    switch (role) {
      case 'local':
        return { fill: '#e0f2fe', stroke: '#0284c7', text: '#0369a1' };
      case 'gateway':
        return { fill: '#ffedd5', stroke: '#ea580c', text: '#c2410c' };
      case 'dns':
        return { fill: '#fef3c7', stroke: '#d97706', text: '#b45309' };
      case 'broadcast':
        return { fill: '#f1f5f9', stroke: '#64748b', text: '#475569' };
      default:
        return { fill: '#ccfbf1', stroke: '#0d9488', text: '#0f766e' };
    }
  };

  const roleLabel = (role: TopologyNode['role']) => {
    if (lang === 'th') {
      switch (role) {
        case 'local':
          return 'เครื่องในวงแลน (Local)';
        case 'gateway':
          return 'เราเตอร์ / Gateway';
        case 'dns':
          return 'DNS Server';
        case 'broadcast':
          return 'Broadcast / Multicast';
        default:
          return 'เซิร์ฟเวอร์ภายนอก (External)';
      }
    }
    switch (role) {
      case 'local':
        return 'Local Device';
      case 'gateway':
        return 'Router / Gateway';
      case 'dns':
        return 'DNS Server';
      case 'broadcast':
        return 'Broadcast / Multicast';
      default:
        return 'External Server';
    }
  };

  const selectedNode = displayNodes.find((n) => n.id === selectedNodeId);
  const selectedEdge: TopologyEdge | undefined = displayEdges.find(
    (e) => e.id === selectedEdgeId
  );

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-5">
      {/* Graph Canvas */}
      <div className="lg:col-span-3 rounded-xl border border-slate-200 bg-white overflow-hidden shadow-sm">
        <div className="border-b border-slate-100 px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
          <span>
            {lang === 'th'
              ? 'ลากโหนดเพื่อจัดระเบียบได้ • คลิกโหนดหรือเส้นเชื่อมเพื่อดูรายละเอียด'
              : 'Drag nodes to rearrange • Click any node or link to inspect'}
          </span>
          <div className="flex items-center gap-3">
            <span className="inline-flex items-center gap-1">
              <span className="h-2.5 w-2.5 rounded-full bg-sky-500" />
              Local
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="h-2.5 w-2.5 rounded-full bg-orange-500" />
              Gateway
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="h-2.5 w-2.5 rounded-full bg-amber-500" />
              DNS
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="h-2.5 w-2.5 rounded-full bg-teal-500" />
              External
            </span>
          </div>
        </div>

        <svg
          ref={svgRef}
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-auto block bg-slate-50/40 select-none touch-none"
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          onPointerLeave={handlePointerUp}
        >
          {/* Edges */}
          {displayEdges.map((edge) => {
            const p1 = positions[edge.source];
            const p2 = positions[edge.target];
            if (!p1 || !p2) return null;

            const isSel = selectedEdgeId === edge.id;
            const stroke = edge.hasError
              ? '#e11d48'
              : edge.hasWarning
                ? '#d97706'
                : isSel
                  ? '#0284c7'
                  : '#94a3b8';
            const strokeWidth = Math.min(6, Math.max(1.5, Math.log2(edge.packets + 1)));
            const mx = (p1.x + p2.x) / 2;
            const my = (p1.y + p2.y) / 2;

            return (
              <g
                key={edge.id}
                onClick={() => {
                  setSelectedEdgeId(edge.id);
                  setSelectedNodeId(null);
                }}
                className="cursor-pointer"
              >
                <line
                  x1={p1.x}
                  y1={p1.y}
                  x2={p2.x}
                  y2={p2.y}
                  stroke={stroke}
                  strokeWidth={strokeWidth}
                  strokeOpacity={isSel ? 1 : 0.7}
                />
                <rect
                  x={mx - 24}
                  y={my - 9}
                  width={48}
                  height={18}
                  rx={9}
                  fill="#ffffff"
                  stroke={stroke}
                  strokeWidth={1}
                />
                <text
                  x={mx}
                  y={my + 3}
                  textAnchor="middle"
                  className="fill-slate-700 text-[9px] font-medium"
                >
                  {edge.packets} pkts
                </text>
              </g>
            );
          })}

          {/* Nodes */}
          {displayNodes.map((node) => {
            const pos = positions[node.id];
            if (!pos) return null;
            const st = roleStyle(node.role);
            const isSel = selectedNodeId === node.id;
            const shortLabel =
              node.label.length > 22 ? node.label.slice(0, 20) + '…' : node.label;

            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                onPointerDown={(e) => {
                  if (!svgRef.current) return;
                  const rect = svgRef.current.getBoundingClientRect();
                  const scaleX = width / rect.width;
                  const scaleY = height / rect.height;
                  draggingRef.current = {
                    id: node.id,
                    offsetX: (e.clientX - rect.left) * scaleX - pos.x,
                    offsetY: (e.clientY - rect.top) * scaleY - pos.y,
                  };
                  setSelectedNodeId(node.id);
                  setSelectedEdgeId(null);
                }}
                className="cursor-grab active:cursor-grabbing"
              >
                <circle
                  r={isSel ? 27 : 23}
                  fill={st.fill}
                  stroke={st.stroke}
                  strokeWidth={isSel ? 3 : 2}
                />
                <text
                  y={4}
                  textAnchor="middle"
                  fill={st.text}
                  className="text-[10px] font-bold uppercase"
                >
                  {node.role === 'local'
                    ? 'PC'
                    : node.role === 'gateway'
                      ? 'GW'
                      : node.role === 'dns'
                        ? 'DNS'
                        : node.role === 'broadcast'
                          ? 'BC'
                          : 'WEB'}
                </text>
                <rect
                  x={-72}
                  y={28}
                  width={144}
                  height={node.domains.length > 0 ? 30 : 20}
                  rx={6}
                  fill="#ffffff"
                  fillOpacity={0.92}
                  stroke="#e2e8f0"
                />
                <text
                  y={41}
                  textAnchor="middle"
                  className="fill-slate-900 text-[10px] font-semibold"
                >
                  {shortLabel}
                </text>
                {node.domains.length > 0 && (
                  <text
                    y={53}
                    textAnchor="middle"
                    className="fill-slate-500 text-[9px] font-mono"
                  >
                    {node.ip}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      {/* Details Side Panel */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 flex flex-col justify-between">
        {selectedNode ? (
          <div className="space-y-4">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-slate-100 text-slate-700">
                {selectedNode.role === 'local' ? (
                  <Monitor className="h-5 w-5 text-sky-600" />
                ) : selectedNode.role === 'gateway' ? (
                  <Router className="h-5 w-5 text-orange-600" />
                ) : selectedNode.role === 'dns' ? (
                  <Server className="h-5 w-5 text-amber-600" />
                ) : selectedNode.role === 'broadcast' ? (
                  <Radio className="h-5 w-5 text-slate-600" />
                ) : (
                  <Globe className="h-5 w-5 text-teal-600" />
                )}
              </div>
              <div className="min-w-0">
                <div className="text-xs font-medium text-slate-500">
                  {roleLabel(selectedNode.role)}
                </div>
                <div className="text-sm font-bold text-slate-900 truncate">
                  {selectedNode.label}
                </div>
              </div>
            </div>

            <div className="rounded-lg bg-slate-50 p-3 space-y-1.5 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-500">IP Address</span>
                <span className="font-mono font-medium text-slate-900">
                  {selectedNode.ip}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">
                  {lang === 'th' ? 'ส่งออก' : 'Sent'}
                </span>
                <span className="font-medium text-slate-900">
                  {selectedNode.packetsSent} pkts ({formatBytes(selectedNode.bytesSent)})
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">
                  {lang === 'th' ? 'รับเข้า' : 'Received'}
                </span>
                <span className="font-medium text-slate-900">
                  {selectedNode.packetsReceived} pkts (
                  {formatBytes(selectedNode.bytesReceived)})
                </span>
              </div>
            </div>

            {selectedNode.domains.length > 0 && (
              <div>
                <div className="text-xs font-semibold text-slate-700 mb-1.5">
                  {lang === 'th' ? 'ชื่อโดเมนที่เกี่ยวข้อง' : 'Associated Domains'}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {selectedNode.domains.map((d) => (
                    <span
                      key={d}
                      className="rounded-md bg-slate-100 px-2 py-0.5 text-xs text-slate-700"
                    >
                      {d}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div>
              <div className="text-xs font-semibold text-slate-700 mb-1.5">
                {lang === 'th' ? 'โปรโตคอลที่ใช้' : 'Protocols'}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {selectedNode.protocols.map((p) => (
                  <span
                    key={p}
                    className={`rounded-md px-2 py-0.5 text-xs font-medium ring-1 ${getProtocolBadgeClass(p)}`}
                  >
                    {p}
                  </span>
                ))}
              </div>
            </div>

            <button
              type="button"
              onClick={() => onFilterHost(selectedNode.ip)}
              className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg bg-slate-900 px-3 py-2 text-xs font-medium text-white hover:bg-slate-800 transition-colors"
            >
              {lang === 'th'
                ? 'ดูแพ็กเก็ตทั้งหมดของเครื่องนี้'
                : 'Filter packets for this host'}
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        ) : selectedEdge ? (
          <div className="space-y-4">
            <div>
              <div className="text-xs font-medium text-slate-500">
                {lang === 'th' ? 'เส้นทางเชื่อมต่อ' : 'Connection Link'}
              </div>
              <div className="mt-1 text-sm font-bold text-slate-900 font-mono break-all">
                {selectedEdge.source} ↔ {selectedEdge.target}
              </div>
            </div>

            <div className="rounded-lg bg-slate-50 p-3 space-y-1.5 text-xs">
              <div className="flex justify-between">
                <span className="text-slate-500">
                  {lang === 'th' ? 'จำนวนแพ็กเก็ต' : 'Packets'}
                </span>
                <span className="font-medium text-slate-900">
                  {selectedEdge.packets}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">
                  {lang === 'th' ? 'ปริมาณข้อมูล' : 'Total Data'}
                </span>
                <span className="font-medium text-slate-900">
                  {formatBytes(selectedEdge.bytes)}
                </span>
              </div>
            </div>

            <div>
              <div className="text-xs font-semibold text-slate-700 mb-1.5">
                {lang === 'th' ? 'โปรโตคอล' : 'Protocols'}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {selectedEdge.protocols.map((p) => (
                  <span
                    key={p}
                    className={`rounded-md px-2 py-0.5 text-xs font-medium ring-1 ${getProtocolBadgeClass(p)}`}
                  >
                    {p}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="text-sm text-slate-500 text-center py-10">
            {lang === 'th'
              ? 'คลิกที่โหนดหรือเส้นเชื่อมบนแผนผังเพื่อดูรายละเอียด'
              : 'Click a node or edge on the map to view details.'}
          </div>
        )}
      </div>
    </div>
  );
};
