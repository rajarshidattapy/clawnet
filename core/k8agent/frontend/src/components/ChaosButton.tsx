import { useState, useEffect, useRef } from "react";
import {
  Skull,
  Loader2,
  AlertTriangle,
  Zap,
  Server,
  Cpu,
  HardDrive,
  Network,
  Clock,
  FlaskConical,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Search,
  Wrench,
  Shield,
  Play,
  FileText,
  Bot,
} from "lucide-react";
import { fetchAuditLog, injectSpecificChaos, cleanupChaos, fetchChaosScenarios } from "../lib/api";
import type { AuditEntry } from "../types";

const SCENARIO_META: Record<string, { icon: typeof Skull; color: string }> = {
  "CrashLoopBackOff": { icon: Skull, color: "text-red-400" },
  "OOMKilled": { icon: HardDrive, color: "text-yellow-400" },
  "ImagePullBackOff": { icon: Network, color: "text-blue-400" },
  "Pending Pod": { icon: Clock, color: "text-orange-400" },
  "Stalled Deployment": { icon: Server, color: "text-purple-400" },
  "Evicted Pod": { icon: Zap, color: "text-cyan-400" },
  "Node Pressure": { icon: Cpu, color: "text-amber-400" },
};

export default function ChaosButton({ onChaosComplete: _unused }: { onChaosComplete?: () => void } = {}) {
  const [loading, setLoading] = useState(false);
  const [injected, setInjected] = useState<{ scenario: string; applied_at: string }[]>([]);
  const [countdown, setCountdown] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scenarios, setScenarios] = useState<{ name: string; available: boolean }[]>([]);
  const [selectedScenarios, setSelectedScenarios] = useState<Set<string>>(new Set());
  const [cleaning, setCleaning] = useState(false);
  // Live pipeline tracking
  const [tracking, setTracking] = useState(false);
  const [pipelineEvents, setPipelineEvents] = useState<AuditEntry[]>([]);
  const baselineCount = useRef(0);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Fetch available scenarios on mount
  useEffect(() => {
    fetchChaosScenarios().then((s) => {
      setScenarios(s);
      setSelectedScenarios(new Set(s.filter(x => x.available).map(x => x.name)));
    }).catch(() => {});
  }, []);

  const toggleScenario = (name: string) => {
    setSelectedScenarios((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const handleCleanup = async () => {
    setCleaning(true);
    try { await cleanupChaos(); } catch { /* silent */ }
    finally { setCleaning(false); }
  };

  // Start polling audit log for new entries after chaos
  const startTracking = async () => {
    // Capture current count as baseline
    try {
      const current = await fetchAuditLog();
      baselineCount.current = current.length;
    } catch { baselineCount.current = 0; }
    setPipelineEvents([]);
    setTracking(true);

    pollRef.current = setInterval(async () => {
      try {
        const entries = await fetchAuditLog();
        const newEntries = entries.slice(baselineCount.current);
        if (newEntries.length > 0) {
          setPipelineEvents(newEntries);
        }
      } catch { /* silent */ }
    }, 2000); // Poll every 2s
  };

  const stopTracking = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    setTracking(false);
  };

  // Auto-stop after 3 minutes
  useEffect(() => {
    if (tracking) {
      const timeout = setTimeout(stopTracking, 180000);
      return () => clearTimeout(timeout);
    }
  }, [tracking]);

  // Cleanup on unmount
  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const handleChaos = async () => {
    setLoading(true);
    setError(null);
    setInjected([]);
    setPipelineEvents([]);

    for (let i = 3; i > 0; i--) {
      setCountdown(i);
      await new Promise((r) => setTimeout(r, 1000));
    }
    setCountdown(null);

    try {
      // If specific scenarios selected, inject them individually
      const selected = Array.from(selectedScenarios);
      if (selected.length === 0) {
        setError("Select at least one scenario");
        setLoading(false);
        return;
      }

      // Clean up old pods first
      await cleanupChaos();

      const results: { scenario: string; applied_at: string }[] = [];
      for (const name of selected) {
        const r = await injectSpecificChaos(name);
        results.push({ scenario: r.scenario, applied_at: new Date().toISOString() });
      }
      setInjected(results);
      // Start live tracking of pipeline activity
      startTracking();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Chaos trigger failed");
    } finally {
      setLoading(false);
    }
  };

  const getScenarioIcon = (scenario: string) => {
    const lower = scenario.toLowerCase();
    if (lower.includes("cpu") || lower.includes("stress")) return Cpu;
    if (lower.includes("memory") || lower.includes("leak") || lower.includes("oom")) return HardDrive;
    if (lower.includes("network") || lower.includes("latency") || lower.includes("delay")) return Network;
    if (lower.includes("node") || lower.includes("drain")) return Server;
    if (lower.includes("kill") || lower.includes("crash") || lower.includes("delete")) return Skull;
    return Zap;
  };

  const getScenarioColor = (scenario: string) => {
    const lower = scenario.toLowerCase();
    if (lower.includes("cpu") || lower.includes("stress")) return "from-orange-500/20 to-orange-500/5 border-orange-500/30 text-orange-300";
    if (lower.includes("memory") || lower.includes("leak") || lower.includes("oom")) return "from-yellow-500/20 to-yellow-500/5 border-yellow-500/30 text-yellow-300";
    if (lower.includes("network") || lower.includes("latency") || lower.includes("delay")) return "from-blue-500/20 to-blue-500/5 border-blue-500/30 text-blue-300";
    if (lower.includes("node") || lower.includes("drain")) return "from-purple-500/20 to-purple-500/5 border-purple-500/30 text-purple-300";
    if (lower.includes("kill") || lower.includes("crash") || lower.includes("delete")) return "from-red-500/20 to-red-500/5 border-red-500/30 text-red-300";
    return "from-cyan-500/20 to-cyan-500/5 border-cyan-500/30 text-cyan-300";
  };

  return (
    <div className="min-h-full flex flex-col gap-6 p-6">
      {/* Warning Banner */}
      <div className="flex items-center gap-3 bg-amber-500/10 border border-amber-500/30 rounded-xl px-5 py-3">
        <AlertTriangle size={20} className="text-amber-400 shrink-0" />
        <p className="text-sm text-amber-200/90 font-medium">
          This will inject real failures into the live cluster. Ensure your incident response agent is running.
        </p>
      </div>

      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2.5 bg-red-500/15 rounded-xl border border-red-500/20">
          <FlaskConical size={22} className="text-red-400" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Chaos Engineering Lab</h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Trigger controlled failure scenarios to test K8sWhisperer's autonomous response
          </p>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1">
        {/* Left: Scenario Selector */}
        <div className="bg-slate-900/60 border border-slate-700/50 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <ShieldAlert size={16} className="text-slate-400" />
              <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                Pick Scenarios
              </h2>
              <span className="text-[10px] font-mono text-slate-600 bg-slate-800 px-1.5 py-0.5 rounded">
                {selectedScenarios.size} selected
              </span>
            </div>
            <button
              onClick={handleCleanup}
              disabled={cleaning}
              className="text-[10px] font-mono text-red-400/70 hover:text-red-400 border border-red-500/20 hover:border-red-500/40 px-2 py-1 rounded transition cursor-pointer"
            >
              {cleaning ? "Cleaning..." : "Clear All Pods"}
            </button>
          </div>
          <div className="grid grid-cols-1 gap-2 max-h-[320px] overflow-y-auto pr-1">
            {scenarios.map((scenario) => {
              const meta = SCENARIO_META[scenario.name] || { icon: Zap, color: "text-slate-400" };
              const Icon = meta.icon;
              const isSelected = selectedScenarios.has(scenario.name);
              return (
                <button
                  key={scenario.name}
                  onClick={() => toggleScenario(scenario.name)}
                  className={`
                    flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-left transition-all duration-200 cursor-pointer
                    border
                    ${
                      isSelected
                        ? "bg-slate-800/80 border-slate-600/60 text-white"
                        : "bg-slate-900/40 border-slate-800/40 text-slate-500"
                    }
                  `}
                >
                  <div
                    className={`w-8 h-8 rounded-lg flex items-center justify-center transition-colors ${
                      isSelected ? "bg-slate-700/60" : "bg-slate-800/40"
                    }`}
                  >
                    <Icon size={15} className={isSelected ? meta.color : "text-slate-600"} />
                  </div>
                  <span className="text-xs font-medium font-mono">{scenario.name}</span>
                  <div className="ml-auto">
                    <div
                      className={`w-4 h-4 rounded-full border-2 transition-all flex items-center justify-center ${
                        isSelected ? "border-emerald-400 bg-emerald-400/20" : "border-slate-600"
                      }`}
                    >
                      {isSelected && (
                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                      )}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
          <p className="text-xs text-slate-500 mt-3 leading-relaxed">
            Select scenarios to inject. Old pods are cleaned up automatically before injection.
          </p>
        </div>

        {/* Center: The Big Button */}
        <div className="flex flex-col items-center justify-center gap-6">
          <div className="relative">
            {/* Outer glow rings */}
            <div
              className={`absolute inset-0 rounded-full transition-all duration-1000 ${
                loading
                  ? "opacity-0"
                  : "animate-ping bg-red-500/10"
              }`}
              style={{ margin: "-20px" }}
            />
            <div
              className={`absolute inset-0 rounded-full transition-all duration-700 ${
                loading
                  ? "opacity-0"
                  : "animate-pulse bg-red-500/5"
              }`}
              style={{ margin: "-40px" }}
            />

            {/* Button ring */}
            <div
              className={`relative w-48 h-48 rounded-full p-1 transition-all duration-500 ${
                countdown !== null
                  ? "bg-gradient-to-br from-amber-500 via-red-500 to-orange-500"
                  : loading
                  ? "bg-gradient-to-br from-slate-600 to-slate-700"
                  : "bg-gradient-to-br from-red-500 via-red-600 to-red-700 hover:from-red-400 hover:via-red-500 hover:to-red-600"
              }`}
            >
              <button
                onClick={handleChaos}
                disabled={loading}
                className={`
                  w-full h-full rounded-full font-mono font-bold uppercase tracking-wider
                  transition-all duration-300 cursor-pointer flex flex-col items-center justify-center
                  ${
                    countdown !== null
                      ? "bg-slate-950 text-amber-400"
                      : loading
                      ? "bg-slate-900 text-slate-500 cursor-not-allowed"
                      : "bg-slate-950 text-red-400 hover:text-red-300 hover:bg-slate-900 active:scale-95"
                  }
                `}
              >
                {countdown !== null ? (
                  <span className="text-7xl font-black tabular-nums leading-none drop-shadow-[0_0_30px_rgba(251,191,36,0.5)]">
                    {countdown}
                  </span>
                ) : loading ? (
                  <Loader2 size={40} className="animate-spin text-slate-500" />
                ) : (
                  <>
                    <Skull size={36} className="mb-2" />
                    <span className="text-sm tracking-[0.2em]">INJECT</span>
                    <span className="text-sm tracking-[0.2em]">CHAOS</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {countdown !== null && (
            <p className="text-amber-400/80 text-sm font-mono animate-pulse">
              Initiating chaos sequence...
            </p>
          )}
          {!loading && !countdown && injected.length === 0 && (
            <p className="text-slate-500 text-sm text-center max-w-[220px]">
              Press the button to inject 3 random failure scenarios
            </p>
          )}
        </div>

        {/* Right: Results Timeline */}
        <div className="bg-slate-900/60 border border-slate-700/50 rounded-2xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Clock size={16} className="text-slate-400" />
            <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
              Injection Timeline
            </h2>
          </div>

          {injected.length === 0 && !error ? (
            <div className="flex flex-col items-center justify-center h-64 text-center">
              <div className="w-16 h-16 rounded-2xl bg-slate-800/60 border border-slate-700/30 flex items-center justify-center mb-3">
                <FlaskConical size={24} className="text-slate-600" />
              </div>
              <p className="text-sm text-slate-500">No scenarios injected yet</p>
              <p className="text-xs text-slate-600 mt-1">Results will appear here</p>
            </div>
          ) : (
            <div className="space-y-3">
              {injected.map((item, i) => {
                const Icon = getScenarioIcon(item.scenario);
                const colorClass = getScenarioColor(item.scenario);
                const time = item.applied_at
                  ? new Date(item.applied_at).toLocaleTimeString()
                  : "just now";
                return (
                  <div
                    key={i}
                    className={`
                      relative bg-gradient-to-r ${colorClass} border rounded-xl p-4
                      animate-[fadeIn_0.4s_ease-out_forwards]
                    `}
                    style={{ animationDelay: `${i * 150}ms`, opacity: 0 }}
                  >
                    <div className="flex items-start gap-3">
                      <div className="w-9 h-9 rounded-lg bg-black/20 flex items-center justify-center shrink-0 mt-0.5">
                        <Icon size={18} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-semibold truncate">{item.scenario}</p>
                        <p className="text-xs opacity-60 mt-0.5 font-mono">{time}</p>
                      </div>
                      <CheckCircle2 size={16} className="text-emerald-400/70 shrink-0 mt-1" />
                    </div>
                  </div>
                );
              })}

              {injected.length > 0 && (
                <div className="pt-2 border-t border-slate-700/30 mt-4">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-500">Total injected</span>
                    <span className="text-emerald-400 font-bold font-mono">{injected.length}</span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Error Alert */}
          {error && (
            <div className="mt-4 flex items-start gap-3 bg-red-500/10 border border-red-500/30 rounded-xl p-4">
              <AlertTriangle size={18} className="text-red-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-semibold text-red-300">Injection Failed</p>
                <p className="text-xs text-red-400/80 mt-0.5 font-mono">{error}</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ================================================================ */}
      {/*  LIVE PIPELINE ACTIVITY — shows agent working in real-time       */}
      {/* ================================================================ */}

      {(tracking || pipelineEvents.length > 0) && (
        <div className="relative overflow-hidden rounded-xl border border-slate-700/60 bg-slate-950/90 backdrop-blur-sm">
          <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-cyan-500/80 via-emerald-500/80 to-amber-500/80" />

          <div className="p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                {tracking && (
                  <div className="relative flex h-2.5 w-2.5">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500" />
                  </div>
                )}
                <Bot size={14} className="text-cyan-400" />
                <span className="text-xs font-mono font-bold uppercase tracking-widest text-slate-200">
                  Agent Pipeline — Live
                </span>
                <span className="rounded-full bg-slate-800 px-2 py-0.5 text-[10px] font-mono text-slate-500">
                  {pipelineEvents.length} steps
                </span>
              </div>
              {tracking && (
                <button onClick={stopTracking} className="text-[10px] font-mono text-slate-500 hover:text-slate-300 transition">
                  Stop tracking
                </button>
              )}
            </div>

            {pipelineEvents.length === 0 && tracking && (
              <div className="flex items-center gap-3 py-6 justify-center text-slate-500">
                <Loader2 size={16} className="animate-spin text-cyan-400" />
                <span className="text-xs font-mono">Waiting for agent to detect anomalies...</span>
              </div>
            )}

            <div className="space-y-1 max-h-[400px] overflow-y-auto pr-1">
              {pipelineEvents.map((entry, idx) => {
                const stageIcons: Record<string, React.ReactNode> = {
                  observe: <Search size={12} />,
                  detect: <AlertTriangle size={12} />,
                  diagnose: <Wrench size={12} />,
                  plan: <FileText size={12} />,
                  safety_gate: <Shield size={12} />,
                  execute: <Play size={12} />,
                  explain: <CheckCircle2 size={12} />,
                };
                const stageColors: Record<string, string> = {
                  observe: "text-blue-400 bg-blue-500/15 border-blue-500/30",
                  detect: "text-purple-400 bg-purple-500/15 border-purple-500/30",
                  diagnose: "text-cyan-400 bg-cyan-500/15 border-cyan-500/30",
                  plan: "text-amber-400 bg-amber-500/15 border-amber-500/30",
                  execute: "text-orange-400 bg-orange-500/15 border-orange-500/30",
                  explain: "text-emerald-400 bg-emerald-500/15 border-emerald-500/30",
                  safety_gate: "text-red-400 bg-red-500/15 border-red-500/30",
                };
                const stageClass = stageColors[entry.stage] || "text-slate-400 bg-slate-500/15 border-slate-500/30";
                const details = entry.details as Record<string, Record<string, string>> | undefined;
                const anomalyType = details?.anomaly?.type || "";
                const resource = details?.anomaly?.affected_resource || "";
                const action = details?.plan?.action || "";
                const confidence = details?.plan?.confidence || "";
                const blastRadius = details?.plan?.blast_radius || "";
                const isSuccess = entry.outcome?.includes("success");
                const isFailure = entry.outcome?.includes("failure");
                const decision = entry.decision || "";

                return (
                  <div
                    key={`${entry.incident_id}-${idx}`}
                    className="rounded-lg bg-slate-900/60 border border-slate-800/60 px-3 py-2 font-mono animate-[fadeIn_0.4s_ease]"
                  >
                    <div className="flex items-center gap-2 text-[11px]">
                      {/* Time */}
                      <span className="text-slate-600 w-14 shrink-0">
                        {entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : ""}
                      </span>

                      {/* Stage badge with icon */}
                      <span className={`flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase ${stageClass} shrink-0`}>
                        {stageIcons[entry.stage] || null}
                        {entry.stage}
                      </span>

                      {/* Incident ID */}
                      <span className="text-slate-600 shrink-0">{entry.incident_id.slice(0, 12)}</span>

                      {/* Anomaly type */}
                      {anomalyType && (
                        <span className="text-cyan-300 font-semibold shrink-0">{anomalyType}</span>
                      )}

                      {/* Outcome */}
                      <span className="ml-auto shrink-0">
                        {isSuccess && <span className="flex items-center gap-1 text-emerald-400"><CheckCircle2 size={11}/>resolved</span>}
                        {isFailure && <span className="flex items-center gap-1 text-red-400"><XCircle size={11}/>failed</span>}
                        {decision === "auto-executed" && !isSuccess && !isFailure && (
                          <span className="text-amber-400">auto-executing...</span>
                        )}
                      </span>
                    </div>

                    {/* Detail row — resource, action, confidence */}
                    {(resource || action) && (
                      <div className="flex items-center gap-2 mt-1 text-[10px] text-slate-500 pl-16">
                        {resource && (
                          <span>
                            <span className="text-slate-600">resource:</span>{" "}
                            <span className="text-slate-300">{resource.replace("pod/","").replace("deployment/","")}</span>
                          </span>
                        )}
                        {action && (
                          <span>
                            <span className="text-slate-600">action:</span>{" "}
                            <span className="text-amber-300">{action}</span>
                          </span>
                        )}
                        {confidence && (
                          <span>
                            <span className="text-slate-600">conf:</span>{" "}
                            <span className="text-cyan-300">{Number(confidence) > 1 ? confidence : (Number(confidence) * 100).toFixed(0) + "%"}</span>
                          </span>
                        )}
                        {blastRadius && (
                          <span>
                            <span className="text-slate-600">blast:</span>{" "}
                            <span className={blastRadius === "low" ? "text-emerald-400" : blastRadius === "high" ? "text-red-400" : "text-amber-400"}>
                              {blastRadius}
                            </span>
                          </span>
                        )}
                        {decision && (
                          <span>
                            <span className="text-slate-600">decision:</span>{" "}
                            <span className={decision === "auto-executed" ? "text-emerald-400" : decision === "rejected" ? "text-red-400" : "text-amber-400"}>
                              {decision}
                            </span>
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Inline keyframes for fadeIn animation */}
      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(8px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
