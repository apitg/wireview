import { useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { readFile } from "@tauri-apps/plugin-fs";
import { Activity, AlertTriangle, ArrowDownToLine, BarChart3, Binary, ChevronRight, Clock3, FileUp, Globe2, HardDrive, LoaderCircle, Network, Radar, ShieldCheck, X } from "lucide-react";
import type { Analysis, Conversation, Endpoint, Observation, ProtocolStat } from "./types";

const formatBytes = (n: number) => n < 1024 ? `${n} B` : n < 1_048_576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1_048_576).toFixed(2)} MB`;
const formatDuration = (ms: number) => ms < 1000 ? `${ms} ms` : ms < 60000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.floor(ms / 60000)}m ${Math.round(ms % 60000 / 1000)}s`;
const formatTime = (stamp: number | null) => stamp === null ? "—" : new Date(stamp).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });

function Metric({ icon: Icon, label, value, detail }: { icon: typeof Activity; label: string; value: string; detail?: string }) {
  return <div className="metric"><div className="metric-icon"><Icon size={18} /></div><div><span>{label}</span><strong>{value}</strong>{detail && <small>{detail}</small>}</div></div>;
}
function ProtocolTable({ rows }: { rows: ProtocolStat[] }) {
  return <div className="table-wrap"><table><thead><tr><th>Protocol</th><th>Packets</th><th>Volume</th><th>Share</th></tr></thead><tbody>{rows.map(p => <tr key={p.name}><td><span className="protocol-dot" />{p.name}</td><td>{p.packets.toLocaleString()}</td><td>{formatBytes(p.bytes)}</td><td><div className="share"><i style={{ width: `${Math.max(p.share, 2)}%` }} /><span>{p.share.toFixed(1)}%</span></div></td></tr>)}</tbody></table></div>;
}
function EndpointTable({ rows }: { rows: Endpoint[] }) {
  return <div className="table-wrap"><table><thead><tr><th>Address</th><th>Role</th><th>Packets</th><th>Volume</th></tr></thead><tbody>{rows.map(e => <tr key={e.address}><td className="mono">{e.address}</td><td><span className={`tag ${e.role}`}>{e.role}</span></td><td>{e.packets.toLocaleString()}</td><td>{formatBytes(e.bytes)}</td></tr>)}</tbody></table></div>;
}
function ConversationTable({ rows }: { rows: Conversation[] }) {
  return <div className="table-wrap"><table><thead><tr><th>Source</th><th></th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Volume</th></tr></thead><tbody>{rows.map((c, i) => <tr key={`${c.source}-${c.destination}-${i}`}><td className="mono">{c.source}</td><td className="arrow">→</td><td className="mono">{c.destination}</td><td><span className="tag protocol">{c.protocol}</span></td><td>{c.packets.toLocaleString()}</td><td>{formatBytes(c.bytes)}</td></tr>)}</tbody></table></div>;
}
function ObservationCard({ item }: { item: Observation }) {
  const Icon = item.kind === "warning" ? AlertTriangle : item.kind === "dns" ? Globe2 : item.kind === "tls" ? ShieldCheck : Activity;
  return <div className={`observation ${item.kind}`}><Icon size={17} /><div><strong>{item.title}</strong><p>{item.detail}</p></div></div>;
}

export default function App() {
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const input = useRef<HTMLInputElement>(null);
  const analyze = async (file: File) => {
    setError(""); setLoading(true);
    try { setAnalysis(await invoke<Analysis>("analyze_capture", { data: Array.from(new Uint8Array(await file.arrayBuffer())), fileName: file.name, fileSize: file.size })); }
    catch (e) { setError(String(e)); } finally { setLoading(false); }
  };
  const chooseFile = async () => {
    try {
      const chosen = await open({ multiple: false, filters: [{ name: "Packet captures", extensions: ["pcap", "pcapng", "cap"] }] });
      if (chosen) { const bytes = await readFile(chosen); await analyze(new File([bytes], chosen.split(/[\\/]/).pop() || "capture.pcapng")); }
    } catch (e) { setError(String(e)); }
  };
  if (!analysis) return <main className="landing"><div className="brand"><span className="brand-mark"><Radar size={24} /></span><span>wire<span>view</span></span></div><div className="hero"><div className="eyebrow">OFFLINE NETWORK INTELLIGENCE</div><h1>See what’s really<br /><em>happening on your network.</em></h1><p>Drop a packet capture to turn raw traffic into a clear, actionable overview. Everything stays on this device.</p><button className="primary-button" onClick={chooseFile} disabled={loading}>{loading ? <><LoaderCircle className="spin" size={18} /> Analyzing capture…</> : <><FileUp size={18} /> Open a capture</>}</button><div className="drop-hint">Supports .pcap, .pcapng and .cap files</div><input ref={input} type="file" hidden accept=".pcap,.pcapng,.cap" onChange={e => e.target.files?.[0] && analyze(e.target.files[0])} /><div className="feature-row"><span><HardDrive size={15} /> No data leaves your device</span><span><Binary size={15} /> Deep packet inspection</span><span><BarChart3 size={15} /> Instant visual summary</span></div></div>{error && <div className="error-banner"><AlertTriangle size={16} />{error}</div>}<footer>WIREVIEW <span>•</span> PRIVATE BY DESIGN</footer></main>;
  return <main className="dashboard"><header><div className="brand"><span className="brand-mark"><Radar size={20} /></span><span>wire<span>view</span></span></div><div className="file-chip"><FileUp size={15} /><span>{analysis.fileName}</span><button onClick={() => setAnalysis(null)} aria-label="Close capture"><X size={15} /></button></div><div className="header-actions"><button className="icon-button" title="Open another capture" onClick={chooseFile}><ArrowDownToLine size={17} /></button><span className="offline"><i /> Offline analysis</span></div></header><div className="content"><div className="title-row"><div><div className="eyebrow">CAPTURE OVERVIEW</div><h1>Network activity</h1><p>Read-only analysis of <strong>{analysis.fileName}</strong></p></div><div className="capture-meta"><span><Clock3 size={14} /> {formatTime(analysis.firstTimestamp)}</span><span>Duration <strong>{formatDuration(analysis.durationMs)}</strong></span></div></div><section className="metrics"><Metric icon={Network} label="Packets" value={analysis.packets.toLocaleString()} detail={`${formatBytes(analysis.fileSize)} file`} /><Metric icon={HardDrive} label="Captured data" value={formatBytes(analysis.capturedBytes)} detail={analysis.linkLayer} /><Metric icon={Activity} label="Protocols" value={analysis.protocols.length.toString()} detail="detected" /><Metric icon={Globe2} label="Endpoints" value={analysis.endpoints.length.toString()} detail={`${analysis.conversations.length} conversations`} /></section><div className="grid two"><section className="panel"><div className="panel-head"><div><h2>Protocol distribution</h2><p>Traffic grouped by the highest-level protocol detected</p></div><ChevronRight size={17} /></div><ProtocolTable rows={analysis.protocols} /></section><section className="panel"><div className="panel-head"><div><h2>Network observations</h2><p>Signals found while inspecting packet contents</p></div><ChevronRight size={17} /></div><div className="observations">{analysis.observations.length ? analysis.observations.map((o, i) => <ObservationCard key={i} item={o} />) : <div className="empty">No notable observations found.</div>}</div></section></div><section className="panel"><div className="panel-head"><div><h2>Endpoints</h2><p>Most active addresses in this capture</p></div><span className="panel-count">{analysis.endpoints.length} hosts</span></div><EndpointTable rows={analysis.endpoints} /></section><section className="panel"><div className="panel-head"><div><h2>Conversations</h2><p>Bidirectional traffic pairs ranked by volume</p></div><span className="panel-count">{analysis.conversations.length} flows</span></div><ConversationTable rows={analysis.conversations} /></section>{analysis.warnings.length > 0 && <div className="warning-box"><AlertTriangle size={18} /><div><strong>Capture notes</strong>{analysis.warnings.map(w => <p key={w}>{w}</p>)}</div></div>}</div></main>;
}
