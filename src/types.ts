export type ProtocolStat = { name: string; packets: number; bytes: number; share: number };
export type Endpoint = { address: string; packets: number; bytes: number; role: string };
export type Conversation = { source: string; destination: string; protocol: string; packets: number; bytes: number };
export type Observation = { kind: "dns" | "http" | "tls" | "warning"; title: string; detail: string };
export type PacketSummary = {
  number: number;
  timestamp: number;
  source: string;
  destination: string;
  protocol: string;
  bytes: number;
  sourcePort: number | null;
  destinationPort: number | null;
  payloadPreview: string;
};
export type Analysis = {
  fileName: string; fileSize: number; packets: number; capturedBytes: number;
  durationMs: number; firstTimestamp: number | null; lastTimestamp: number | null;
  protocols: ProtocolStat[]; endpoints: Endpoint[]; conversations: Conversation[];
  observations: Observation[]; warnings: string[]; linkLayer: string; packetsPreview: PacketSummary[];
};
