export type Lang = 'th' | 'en';

export type Severity = 'info' | 'success' | 'warning' | 'error';

export type ProtocolName =
  | 'DNS'
  | 'HTTP'
  | 'TLS'
  | 'QUIC'
  | 'TCP'
  | 'UDP'
  | 'ICMP'
  | 'ICMPv6'
  | 'ARP'
  | 'DHCP'
  | 'NTP'
  | 'SSH'
  | 'UNKNOWN';

export interface ProtocolField {
  key: string;
  labelTh: string;
  labelEn: string;
  value: string;
  hintTh?: string;
  hintEn?: string;
}

export interface ProtocolLayer {
  name: string;
  titleTh: string;
  titleEn: string;
  summaryTh: string;
  summaryEn: string;
  fields: ProtocolField[];
}

export interface ParsedPacket {
  id: number; // 1-indexed
  timestampMs: number;
  relativeTimeMs: number;
  capturedLen: number;
  originalLen: number;
  srcMac?: string;
  dstMac?: string;
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
  protocol: ProtocolName;
  transportProtocol?: 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6' | 'ARP';
  tcpFlags?: string[];
  dnsQuery?: string;
  dnsAnswers?: { name: string; ip?: string; type: string }[];
  dnsRcode?: number;
  httpMethod?: string;
  httpPath?: string;
  httpHost?: string;
  httpStatus?: number;
  tlsSni?: string;
  tlsVersion?: string;
  summaryTh: string;
  summaryEn: string;
  detailTh: string;
  detailEn: string;
  severity: Severity;
  warningTagTh?: string;
  warningTagEn?: string;
  loopId?: number;
  isRetransmission?: boolean;
  deltaFromPrevInLoopMs?: number;
  layers: ProtocolLayer[];
  rawBytes: Uint8Array;
}

export type LoopStatus = 'completed' | 'active' | 'stuck' | 'error' | 'warning';

export interface CommunicationLoop {
  id: number;
  titleTh: string;
  titleEn: string;
  protocol: ProtocolName;
  initiatorIp: string;
  responderIp: string;
  initiatorPort?: number;
  responderPort?: number;
  startTimeMs: number;
  endTimeMs: number;
  durationMs: number;
  maxGapMs: number;
  maxGapAfterPacketId?: number;
  packetIds: number[];
  totalBytes: number;
  status: LoopStatus;
  startDescTh: string;
  startDescEn: string;
  endDescTh: string;
  endDescEn: string;
  stuckReasonTh?: string;
  stuckReasonEn?: string;
  retransmissionCount: number;
  hasReply: boolean;
}

export interface TopologyNode {
  id: string; // IP or MAC
  label: string; // friendly name or domain
  ip: string;
  domains: string[];
  role: 'local' | 'gateway' | 'dns' | 'external' | 'broadcast';
  packetsSent: number;
  packetsReceived: number;
  bytesSent: number;
  bytesReceived: number;
  protocols: ProtocolName[];
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  packets: number;
  bytes: number;
  protocols: ProtocolName[];
  hasError: boolean;
  hasWarning: boolean;
  label: string;
}

export interface DomainVisit {
  domain: string;
  ips: string[];
  via: 'DNS' | 'HTTP' | 'TLS';
  packetCount: number;
  firstSeenMs: number;
  hasError: boolean;
}

export interface StoryInsight {
  id: string;
  severity: Severity;
  titleTh: string;
  titleEn: string;
  descriptionTh: string;
  descriptionEn: string;
  relatedPacketIds: number[];
}

export interface CaptureAnalysis {
  fileName: string;
  fileSize: number;
  fileFormat: 'pcap' | 'pcapng';
  totalPackets: number;
  totalBytes: number;
  durationMs: number;
  startTimeMs: number;
  packets: ParsedPacket[];
  ipToDomains: Record<string, string[]>;
  protocolCounts: Record<string, number>;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  domains: DomainVisit[];
  insights: StoryInsight[];
  loops: CommunicationLoop[];
  warningCount: number;
  errorCount: number;
}
