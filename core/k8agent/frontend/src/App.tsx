import { useState, useEffect, useRef } from "react";
import {
  LayoutDashboard,
  ScrollText,
  Radio,
  Link,
  FlaskConical,
  Activity,
  Shield,
  Cpu,
  Wifi,
  Database,
  Clock,
  ChevronRight,
  Hexagon,
  Zap,
  AlertTriangle,
  Globe,
  Server,
  Lock,
  BrainCircuit,
  Terminal,
} from "lucide-react";
import Dashboard from "./components/Dashboard";
import AuditLog from "./components/AuditLog";
import WarRoom from "./components/WarRoom";
import ChaosButton from "./components/ChaosButton";
import MTTRChart from "./components/MTTRChart";
import TracesView from "./components/TracesView";
import PodLogsView from "./components/PodLogsView";

type Tab = "dashboard" | "audit" | "warroom" | "chaos" | "blockchain" | "traces" | "logs";

const tabs: { id: Tab; label: string; icon: React.ReactNode; color: string }[] = [
  { id: "dashboard", label: "Dashboard", icon: <LayoutDashboard size={18} />, color: "cyan" },
  { id: "audit", label: "Audit Log", icon: <ScrollText size={18} />, color: "cyan" },
  { id: "warroom", label: "War Room", icon: <Radio size={18} />, color: "rose" },
  { id: "chaos", label: "Chaos Lab", icon: <FlaskConical size={18} />, color: "amber" },
  { id: "blockchain", label: "Blockchain", icon: <Link size={18} />, color: "purple" },
  { id: "traces", label: "Traces", icon: <BrainCircuit size={18} />, color: "cyan" },
  { id: "logs", label: "Logs", icon: <Terminal size={18} />, color: "emerald" },
];

function useCurrentTime() {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return time;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("dashboard");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const time = useCurrentTime();
  const tabRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const [underline, setUnderline] = useState({ left: 0, width: 0 });

  // Animate underline position
  useEffect(() => {
    const el = tabRefs.current[activeTab];
    if (el) {
      setUnderline({ left: el.offsetLeft, width: el.offsetWidth });
    }
  }, [activeTab]);

  const sidebarItems = [
    { icon: <Activity size={18} />, label: "Cluster Health", badge: "OK" },
    { icon: <Server size={18} />, label: "Nodes", badge: "3" },
    { icon: <Database size={18} />, label: "Workloads", badge: "12" },
    { icon: <Shield size={18} />, label: "Policies", badge: "5" },
    { icon: <AlertTriangle size={18} />, label: "Alerts", badge: "2" },
    { icon: <Globe size={18} />, label: "Ingress", badge: null },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 flex flex-col">
      {/* ─── HEADER ─── */}
      <header className="border-b border-slate-800/80 bg-slate-950/95 backdrop-blur-md sticky top-0 z-50">
        <div className="px-4 lg:px-6">
          <div className="flex items-center justify-between h-14">
            {/* Left: Logo + branding */}
            <div className="flex items-center gap-3">
              <button
                onClick={() => setSidebarCollapsed((c) => !c)}
                className="mr-1 p-1.5 rounded-md hover:bg-slate-800/60 transition-colors cursor-pointer"
              >
                <Hexagon size={20} className="text-cyan-400" />
              </button>
              <div className="relative w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500/30 to-emerald-500/20 border border-cyan-500/40 flex items-center justify-center shadow-lg shadow-cyan-500/10">
                <span className="text-cyan-300 font-bold text-xs font-mono tracking-tighter">K8</span>
                {/* Animated ring */}
                <span className="absolute inset-0 rounded-lg border border-cyan-400/40 animate-ping opacity-20" />
              </div>
              <div className="flex flex-col">
                <span className="text-sm font-mono font-bold text-slate-100 leading-none tracking-wide">
                  K8sWhisperer
                </span>
                <span className="text-[10px] text-cyan-500/80 font-mono uppercase tracking-[0.2em] leading-none mt-0.5">
                  Autonomous Incident Response
                </span>
              </div>
            </div>

            {/* Center: Tab navigation with animated underline */}
            <nav className="relative flex items-center gap-0.5 bg-slate-900/60 rounded-xl px-1.5 py-1 border border-slate-800/60">
              {/* Animated underline */}
              <div
                className="absolute bottom-0.5 h-0.5 bg-cyan-400 rounded-full transition-all duration-300 ease-out"
                style={{ left: underline.left, width: underline.width }}
              />
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  ref={(el) => { tabRefs.current[tab.id] = el; }}
                  onClick={() => setActiveTab(tab.id)}
                  className={`
                    relative flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono uppercase tracking-wider
                    transition-all duration-200 cursor-pointer
                    ${
                      activeTab === tab.id
                        ? "text-cyan-300 bg-cyan-500/10"
                        : "text-slate-500 hover:text-slate-300 hover:bg-slate-800/40"
                    }
                  `}
                >
                  <span className={activeTab === tab.id ? "text-cyan-400" : ""}>{tab.icon}</span>
                  <span className="hidden md:inline">{tab.label}</span>
                  {tab.id === "warroom" && (
                    <span className="flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-2 w-2 rounded-full bg-rose-400 opacity-75" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-500" />
                    </span>
                  )}
                </button>
              ))}
            </nav>

            {/* Right: Status + Time */}
            <div className="flex items-center gap-4">
              {/* Live indicator */}
              <div className="flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/20 rounded-full px-3 py-1">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                </span>
                <span className="text-[10px] font-mono font-bold text-emerald-400 uppercase tracking-widest">
                  Live
                </span>
              </div>
              {/* Clock */}
              <div className="hidden sm:flex items-center gap-1.5 text-slate-500">
                <Clock size={13} />
                <span className="text-xs font-mono tabular-nums">
                  {time.toLocaleTimeString("en-US", { hour12: false })}
                </span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* ─── BODY: Sidebar + Content ─── */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside
          className={`
            ${sidebarCollapsed ? "w-14" : "w-52"}
            transition-all duration-300 ease-out
            bg-slate-950 border-r border-slate-800/60 flex flex-col shrink-0
          `}
        >
          {/* Sidebar nav items */}
          <div className="flex-1 py-3 space-y-0.5 px-2">
            {sidebarItems.map((item, i) => (
              <div
                key={i}
                className="flex items-center gap-3 px-2 py-2 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-slate-800/50 transition-colors cursor-default group"
              >
                <span className="shrink-0 group-hover:text-cyan-400 transition-colors">{item.icon}</span>
                {!sidebarCollapsed && (
                  <>
                    <span className="text-xs font-mono truncate flex-1">{item.label}</span>
                    {item.badge && (
                      <span className="text-[10px] font-mono bg-slate-800 text-slate-400 rounded px-1.5 py-0.5">
                        {item.badge}
                      </span>
                    )}
                  </>
                )}
              </div>
            ))}
          </div>

          {/* Sidebar footer */}
          {!sidebarCollapsed && (
            <div className="p-3 border-t border-slate-800/60">
              <div className="bg-gradient-to-r from-cyan-500/10 to-emerald-500/10 border border-cyan-500/20 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1.5">
                  <Zap size={12} className="text-cyan-400" />
                  <span className="text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider">
                    Agent Status
                  </span>
                </div>
                <p className="text-[10px] font-mono text-slate-400 leading-relaxed">
                  Autonomous mode active. Monitoring 3 namespaces.
                </p>
              </div>
            </div>
          )}
        </aside>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto bg-slate-900/40">
          {/* Breadcrumb / context bar */}
          <div className="border-b border-slate-800/40 bg-slate-950/30 px-6 py-2 flex items-center gap-2 text-[11px] font-mono text-slate-600">
            <span>k8swhisperer</span>
            <ChevronRight size={10} />
            <span className="text-slate-400">
              {tabs.find((t) => t.id === activeTab)?.label}
            </span>
          </div>

          <div className="p-6">
            {/* Tab content with fade transition */}
            <div key={activeTab} className="animate-[fadeIn_0.25s_ease-out]">
              {activeTab === "dashboard" && <Dashboard />}
              {activeTab === "audit" && <AuditLog />}
              {activeTab === "warroom" && <WarRoom />}
              {activeTab === "chaos" && <ChaosLabView onSwitchToDashboard={() => setActiveTab("dashboard")} />}
              {activeTab === "blockchain" && <BlockchainView />}
              {activeTab === "traces" && <TracesView />}
              {activeTab === "logs" && <PodLogsView />}
            </div>
          </div>
        </main>
      </div>

      {/* ─── FOOTER ─── */}
      <footer className="border-t border-slate-800/60 bg-slate-950/95 backdrop-blur-sm px-6 py-2">
        <div className="flex items-center justify-between">
          {/* Left: system indicators */}
          <div className="flex items-center gap-5">
            <StatusPill icon={<Cpu size={11} />} label="API" status="ok" />
            <StatusPill icon={<Database size={11} />} label="Stellar" status="ok" />
            <StatusPill icon={<Wifi size={11} />} label="WebSocket" status="ok" />
            <StatusPill icon={<Lock size={11} />} label="RBAC" status="ok" />
          </div>
          {/* Right: version */}
          <div className="flex items-center gap-3 text-[10px] font-mono text-slate-600">
            <span>v0.1.0-hackathon</span>
            <span className="text-slate-800">|</span>
            <span>Tailwind v4</span>
            <span className="text-slate-800">|</span>
            <span>React 19</span>
          </div>
        </div>
      </footer>

      {/* Global CSS for fade-in animation */}
      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(6px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}

/* ─────────────── Sub-components ─────────────── */

function StatusPill({
  icon,
  label,
  status,
}: {
  icon: React.ReactNode;
  label: string;
  status: "ok" | "warn" | "error";
}) {
  const color =
    status === "ok"
      ? "text-emerald-500"
      : status === "warn"
        ? "text-amber-500"
        : "text-rose-500";
  const bg =
    status === "ok"
      ? "bg-emerald-500"
      : status === "warn"
        ? "bg-amber-500"
        : "bg-rose-500";

  return (
    <div className="flex items-center gap-1.5">
      <span className={color}>{icon}</span>
      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
        {label}
      </span>
      <span className={`h-1.5 w-1.5 rounded-full ${bg}`} />
    </div>
  );
}

function ChaosLabView({ onSwitchToDashboard }: { onSwitchToDashboard: () => void }) {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-2">
        <div className="w-9 h-9 rounded-lg bg-amber-500/20 border border-amber-500/30 flex items-center justify-center">
          <FlaskConical size={18} className="text-amber-400" />
        </div>
        <div>
          <h2 className="text-base font-mono font-bold text-slate-100">Chaos Engineering Lab</h2>
          <p className="text-xs font-mono text-slate-500">Inject faults and measure resilience</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chaos trigger panel */}
        <div className="bg-slate-800/40 rounded-xl border border-slate-700/40 p-6 space-y-4">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Zap size={13} className="text-amber-400" />
            Fault Injection
          </h3>
          <p className="text-xs font-mono text-slate-500 leading-relaxed">
            Trigger controlled chaos experiments against the target cluster. The agent will autonomously detect and remediate failures.
          </p>
          <ChaosButton onChaosComplete={onSwitchToDashboard} />
        </div>

        {/* MTTR Chart */}
        <div className="bg-slate-800/40 rounded-xl border border-slate-700/40 p-6">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2 mb-4">
            <Activity size={13} className="text-cyan-400" />
            Mean Time to Recovery
          </h3>
          <MTTRChart incidents={[]} />
        </div>
      </div>
    </div>
  );
}

function BlockchainView() {
  const [status, setStatus] = useState<{
    enabled: boolean; network: string; contract_id: string;
    incident_count: number; connection: string;
  } | null>(null);
  const [incidents, setIncidents] = useState<{
    incident_id: string; anomaly_type: string; action: string;
    timestamp: string; confidence: number; auto_executed: boolean;
    decision: string; explorer_url?: string;
  }[]>([]);
  const [loading, setLoading] = useState(true);
  const [stellarLoading, setStellarLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const API = import.meta.env.VITE_API_BASE || "http://localhost:8000";

  useEffect(() => {
    let cancelled = false;
    async function load() {
      // Only show full loading on first fetch
      if (!status) setStellarLoading(true);
      try {
        const [statusRes, incidentsRes] = await Promise.allSettled([
          fetch(`${API}/api/blockchain/status`).then(r => r.json()),
          fetch(`${API}/api/blockchain/incidents`).then(r => r.json()),
        ]);
        if (!cancelled) {
          if (statusRes.status === "fulfilled") setStatus(statusRes.value);
          if (incidentsRes.status === "fulfilled") setIncidents(Array.isArray(incidentsRes.value) ? incidentsRes.value : []);
          setError(null);
        }
      } catch (e: any) {
        // Keep stale data visible, just show error banner
        if (!cancelled) setError(e.message || "Failed to fetch blockchain data");
      } finally {
        if (!cancelled) { setLoading(false); setStellarLoading(false); }
      }
    }
    load();
    const interval = setInterval(load, 15000);
    return () => { cancelled = true; clearInterval(interval); };
  }, []);

  const timeAgo = (ts: string) => {
    try {
      const diff = Date.now() - new Date(ts).getTime();
      if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`;
      if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
      return `${Math.floor(diff / 3600000)}h ago`;
    } catch { return ts; }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-2">
        <div className="w-9 h-9 rounded-lg bg-purple-500/20 border border-purple-500/30 flex items-center justify-center">
          <Link size={18} className="text-purple-400" />
        </div>
        <div>
          <h2 className="text-base font-mono font-bold text-slate-100">Stellar Testnet Integration</h2>
          <p className="text-xs font-mono text-slate-500">Tamper-proof audit trail on-chain</p>
        </div>
        <span className={`ml-auto text-[10px] font-mono rounded-full px-3 py-1 uppercase tracking-wider flex items-center gap-1.5 ${
          stellarLoading
            ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
            : status?.connection === "active"
              ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
              : "bg-slate-500/15 text-slate-400 border border-slate-500/30"
        }`}>
          {stellarLoading && (
            <span className="h-3 w-3 border-2 border-amber-400/30 border-t-amber-400 rounded-full animate-spin" />
          )}
          {stellarLoading ? "Connecting..." : status?.connection === "active" ? "Connected" : loading ? "Loading..." : "Testnet"}
        </span>
      </div>

      {error && (
        <div className="bg-rose-500/10 border border-rose-500/30 rounded-lg p-3 text-xs font-mono text-rose-400">
          {error}
        </div>
      )}

      {/* Stats row — live data */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "On-Chain Records", value: loading ? "..." : String(status?.incident_count ?? 0), icon: <Database size={14} /> },
          { label: "Incidents Tracked", value: loading ? "..." : String(incidents.length), icon: <Activity size={14} /> },
          { label: "Contract", value: status?.contract_id ? `${status.contract_id.slice(0, 6)}...${status.contract_id.slice(-4)}` : "...", icon: <Lock size={14} /> },
          { label: "Network", value: status?.network ?? "Stellar", icon: <Globe size={14} /> },
        ].map((stat) => (
          <div key={stat.label} className="bg-slate-800/40 rounded-xl border border-slate-700/40 p-4 text-center">
            <div className="flex justify-center mb-2 text-purple-400">{stat.icon}</div>
            <div className="text-xl font-bold font-mono text-purple-300">{stat.value}</div>
            <div className="text-[10px] text-slate-500 font-mono mt-1 uppercase tracking-wider">{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Contract info */}
      {status?.contract_id && (
        <div className="bg-slate-800/40 rounded-xl border border-slate-700/40 p-4">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-2">
            <Shield size={13} className="text-purple-400" />
            Smart Contract
          </h3>
          <div className="flex items-center gap-2">
            <code className="text-[11px] font-mono text-purple-300 bg-slate-900/50 rounded px-2 py-1 flex-1 overflow-x-auto">
              {status.contract_id}
            </code>
            <a
              href={`https://stellar.expert/explorer/testnet/contract/${status.contract_id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[10px] font-mono text-purple-400 hover:text-purple-300 border border-purple-500/30 rounded px-2 py-1 hover:bg-purple-500/10 transition-colors"
            >
              Explorer
            </a>
          </div>
        </div>
      )}

      {/* On-chain incident records */}
      <div className="bg-slate-800/40 rounded-xl border border-slate-700/40 p-6">
        <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
          <Link size={13} className="text-purple-400" />
          On-Chain Incident Records
        </h3>
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-14 bg-slate-900/50 rounded-lg animate-pulse" />
            ))}
          </div>
        ) : incidents.length === 0 ? (
          <p className="text-xs font-mono text-slate-600 text-center py-8">
            No incidents recorded on-chain yet. Incidents are stored after remediation.
          </p>
        ) : (
          <div className="space-y-2">
            {incidents.map((inc, i) => (
              <div
                key={i}
                className="flex items-center gap-4 bg-slate-900/50 rounded-lg p-3 border border-slate-700/30 hover:border-purple-500/30 transition-colors"
              >
                <div className="w-8 h-8 rounded-md bg-purple-500/15 flex items-center justify-center shrink-0">
                  <Hexagon size={14} className="text-purple-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-mono text-slate-300">{inc.anomaly_type}</span>
                    <span className="text-[10px] font-mono text-slate-600">{inc.incident_id.slice(0, 12)}...</span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                      inc.auto_executed
                        ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30"
                        : "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                    }`}>
                      {inc.auto_executed ? "Auto" : "HITL"}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-[10px] font-mono text-slate-600">
                      {inc.action} | conf: {(inc.confidence * 100).toFixed(0)}%
                    </span>
                    <span className="text-[10px] font-mono text-slate-600">{timeAgo(inc.timestamp)}</span>
                  </div>
                </div>
                {inc.explorer_url ? (
                  <a
                    href={inc.explorer_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] font-mono text-purple-400 hover:text-purple-300 border border-purple-500/30 rounded px-2 py-1 hover:bg-purple-500/10 transition-colors shrink-0"
                  >
                    View Tx
                  </a>
                ) : (
                  <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                    Recorded
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
        <p className="text-[10px] font-mono text-slate-600 mt-4 text-center">
          Every incident remediation is hashed and stored on Stellar testnet via Soroban smart contract.
        </p>
      </div>
    </div>
  );
}
