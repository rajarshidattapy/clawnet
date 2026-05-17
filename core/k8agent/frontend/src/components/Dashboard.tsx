import { useState, useEffect, useCallback, useRef } from "react";
import {
  Activity,
  CheckCircle2,
  UserCheck,
  Server,
  RefreshCw,
  Circle,
  ShieldAlert,
  Zap,
  Signal,
  TrendingDown,
  Clock,
} from "lucide-react";
import { fetchIncidents, fetchClusterState, fetchAuditLog } from "../lib/api";
import type { Incident, ClusterState, PodStatus, AuditEntry } from "../types";
import IncidentCard from "./IncidentCard";
import ChaosButton from "./ChaosButton";
import MTTRChart from "./MTTRChart";

/* ------------------------------------------------------------------ */
/*  Pod helpers                                                        */
/* ------------------------------------------------------------------ */

type PodPhase = "Running" | "Pending" | "Failed" | "Succeeded" | "Unknown";

const PHASE_META: Record<
  PodPhase,
  { color: string; ring: string; glow: string; label: string; text: string }
> = {
  Running: {
    color: "bg-emerald-500",
    ring: "ring-emerald-500/30",
    glow: "shadow-emerald-500/40",
    label: "Running",
    text: "text-emerald-400",
  },
  Pending: {
    color: "bg-yellow-500",
    ring: "ring-yellow-500/30",
    glow: "shadow-yellow-500/40",
    label: "Pending",
    text: "text-yellow-400",
  },
  Failed: {
    color: "bg-red-500",
    ring: "ring-red-500/30",
    glow: "shadow-red-500/40",
    label: "Failed",
    text: "text-red-400",
  },
  Succeeded: {
    color: "bg-blue-500",
    ring: "ring-blue-500/30",
    glow: "shadow-blue-500/40",
    label: "Succeeded",
    text: "text-blue-400",
  },
  Unknown: {
    color: "bg-slate-500",
    ring: "ring-slate-500/30",
    glow: "shadow-slate-500/40",
    label: "Unknown",
    text: "text-slate-400",
  },
};

function podPhase(pod: PodStatus): PodPhase {
  if (
    pod.phase === "Failed" ||
    pod.containers?.some(
      (c) => c.reason === "CrashLoopBackOff" || c.reason === "Error"
    )
  )
    return "Failed";
  if (pod.phase === "Running") return "Running";
  if (pod.phase === "Pending") return "Pending";
  if (pod.phase === "Succeeded") return "Succeeded";
  return "Unknown";
}

function podRestarts(pod: PodStatus): number {
  return pod.containers?.reduce((s, c) => s + (c.restart_count || 0), 0) || 0;
}

/* ------------------------------------------------------------------ */
/*  Skeleton / shimmer                                                 */
/* ------------------------------------------------------------------ */

function Skeleton({ className = "" }: { className?: string }) {
  return (
    <div
      className={`animate-pulse rounded-lg bg-gradient-to-r from-slate-800 via-slate-700 to-slate-800 bg-[length:200%_100%] ${className}`}
      style={{ animation: "shimmer 2s ease-in-out infinite" }}
    />
  );
}

function StatCardSkeleton() {
  return (
    <div className="relative overflow-hidden rounded-xl border border-slate-700/60 bg-slate-800/60 p-5 backdrop-blur-sm">
      <Skeleton className="mb-3 h-4 w-24" />
      <Skeleton className="h-9 w-16" />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Stat card                                                          */
/* ------------------------------------------------------------------ */

function StatCard({
  icon,
  label,
  value,
  gradient,
  accentColor,
  pulse,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  gradient: string;
  accentColor: string;
  pulse?: boolean;
}) {
  return (
    <div
      className={`group relative overflow-hidden rounded-xl border border-slate-700/60 bg-slate-900/80 backdrop-blur-sm
        transition-all duration-300 hover:border-slate-600 hover:shadow-lg hover:shadow-black/20 hover:-translate-y-0.5`}
    >
      {/* Gradient accent bar on top */}
      <div className={`absolute inset-x-0 top-0 h-[2px] ${gradient}`} />

      {/* Subtle background glow */}
      <div
        className={`absolute -right-4 -top-4 h-24 w-24 rounded-full opacity-[0.07] blur-2xl ${accentColor}`}
      />

      <div className="relative p-5">
        <div className="mb-3 flex items-center gap-2.5">
          <div className={`rounded-lg p-1.5 ${accentColor}/10`}>{icon}</div>
          <span className="text-xs font-medium uppercase tracking-widest text-slate-400">
            {label}
          </span>
        </div>
        <div
          className={`font-mono text-3xl font-bold text-white tabular-nums ${
            pulse ? "animate-pulse" : ""
          }`}
        >
          {value}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Pod dot with tooltip                                               */
/* ------------------------------------------------------------------ */

function PodDot({ pod }: { pod: PodStatus }) {
  const phase = podPhase(pod);
  const meta = PHASE_META[phase];
  const restarts = podRestarts(pod);
  const reason = pod.containers?.find((c) => c.reason)?.reason || pod.phase;
  const isCrashing = phase === "Failed";
  // Shorten name: remove hash suffixes for readability
  const shortName = pod.name.replace(/-[a-z0-9]{8,10}-[a-z0-9]{4,5}$/, "");

  return (
    <div className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-slate-800/50 border border-slate-700/40 transition-all hover:border-slate-600 ${isCrashing ? "animate-pulse" : ""}`}>
      <div className={`h-2.5 w-2.5 rounded-full shrink-0 ${meta.color} ${meta.glow}`} />
      <span className="text-[11px] font-mono text-slate-300 truncate max-w-[140px]" title={pod.name}>
        {shortName}
      </span>
      <span className={`text-[10px] font-mono ${meta.text} ml-auto shrink-0`}>{reason}</span>
      {restarts > 0 && (
        <span className="text-[10px] font-mono text-yellow-400 shrink-0">{restarts}x</span>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Pod legend                                                         */
/* ------------------------------------------------------------------ */

function PodLegend({ pods }: { pods: PodStatus[] }) {
  const counts: Record<PodPhase, number> = {
    Running: 0,
    Pending: 0,
    Failed: 0,
    Succeeded: 0,
    Unknown: 0,
  };
  pods.forEach((p) => counts[podPhase(p)]++);

  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-400">
      {(Object.entries(counts) as [PodPhase, number][])
        .filter(([, v]) => v > 0)
        .map(([phase, count]) => (
          <span key={phase} className="flex items-center gap-1.5">
            <span
              className={`inline-block h-2 w-2 rounded-full ${PHASE_META[phase].color}`}
            />
            {phase}{" "}
            <span className="font-mono text-slate-300">{count}</span>
          </span>
        ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Section header                                                     */
/* ------------------------------------------------------------------ */

function SectionHeader({
  icon,
  title,
  badge,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  badge?: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <div className="mb-4 flex items-center justify-between">
      <div className="flex items-center gap-2.5">
        {icon}
        <h2 className="text-sm font-semibold uppercase tracking-widest text-slate-300">
          {title}
        </h2>
        {badge}
      </div>
      {children}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Main Dashboard                                                     */
/* ------------------------------------------------------------------ */

export default function Dashboard() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [cluster, setCluster] = useState<ClusterState | null>(null);
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const mountedRef = useRef(true);
  const prevAuditCount = useRef(0);

  // Browser notification support
  useEffect(() => {
    if ("Notification" in window && Notification.permission === "default") {
      Notification.requestPermission();
    }
  }, []);

  const notifyIncident = useCallback((inc: Incident) => {
    if ("Notification" in window && Notification.permission === "granted") {
      new Notification(`K8sWhisperer: ${inc.anomaly_type || "Incident"}`, {
        body: `${inc.affected_resource || "Unknown resource"} — ${inc.action || "detecting"}`,
        icon: "/favicon.ico",
        tag: inc.incident_id,
      });
    }
  }, []);

  const load = useCallback(async (manual = false) => {
    if (manual) setRefreshing(true);
    try {
      const [inc, cs, al] = await Promise.allSettled([
        fetchIncidents(),
        fetchClusterState(),
        fetchAuditLog(),
      ]);
      if (!mountedRef.current) return;
      if (inc.status === "fulfilled") {
        // Notify on new incidents
        if (inc.value.length > incidents.length && incidents.length > 0) {
          const newOnes = inc.value.slice(incidents.length);
          newOnes.forEach(notifyIncident);
        }
        setIncidents(inc.value);
      }
      if (cs.status === "fulfilled") setCluster(cs.value);
      if (al.status === "fulfilled") {
        prevAuditCount.current = auditEntries.length;
        setAuditEntries(al.value);
      }
      setLastUpdate(new Date());
    } catch {
      // silent
    } finally {
      if (mountedRef.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    load();
    const interval = setInterval(() => load(), 5000);
    return () => {
      mountedRef.current = false;
      clearInterval(interval);
    };
  }, [load]);

  /* Derived stats */
  const totalIncidents = incidents.length;
  const resolved = incidents.filter((i) =>
    i.outcome?.startsWith("success") || i.outcome?.startsWith("rejected")
  ).length;
  const failed = incidents.filter((i) =>
    i.outcome?.startsWith("failure")
  ).length;
  const pending = totalIncidents - resolved - failed;
  // Count HITL-approved incidents from audit entries
  const hitlCount = auditEntries.filter((e) => e.decision === "human-approved").length;
  const activePods =
    cluster?.pods?.filter((p) => p.phase === "Running").length ?? 0;
  // Compute real avg resolution from stage_timings in audit entries
  const avgResolutionMs = (() => {
    const timings = auditEntries
      .filter((e) => e.stage === "explain" && (e.details as any)?.stage_timings)
      .map((e) => {
        const t = (e.details as any).stage_timings;
        return Object.values(t).reduce((a: number, b: any) => a + (Number(b) || 0), 0);
      });
    return timings.length > 0 ? timings.reduce((a, b) => a + b, 0) / timings.length : 0;
  })();

  const sortedIncidents = [...incidents].reverse();

  return (
    <div className="space-y-6">
      {/* -------- Inline CSS for shimmer keyframe -------- */}
      <style>{`
        @keyframes shimmer {
          0% { background-position: 200% 0; }
          100% { background-position: -200% 0; }
        }
      `}</style>

      {/* -------- Live indicator bar -------- */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="relative flex h-2.5 w-2.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500" />
          </div>
          <span className="text-xs font-medium tracking-wide text-slate-400">
            Live &middot; updated {lastUpdate.toLocaleTimeString()}
          </span>
        </div>
        <button
          onClick={() => load(true)}
          disabled={refreshing}
          className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5
            text-xs text-slate-400 transition hover:border-cyan-700 hover:text-cyan-400 disabled:opacity-50"
        >
          <RefreshCw
            className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`}
          />
          Refresh
        </button>
      </div>

      {/* ================================================================ */}
      {/*  TOP ROW: 4 Stat cards                                           */}
      {/* ================================================================ */}

      {loading ? (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <StatCardSkeleton key={i} />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard
            icon={<Activity className="h-5 w-5 text-cyan-400" />}
            label="Total Incidents"
            value={totalIncidents}
            gradient="bg-gradient-to-r from-cyan-500 to-blue-500"
            accentColor="bg-cyan-500"
          />
          <StatCard
            icon={<CheckCircle2 className="h-5 w-5 text-emerald-400" />}
            label="Auto-Resolved"
            value={resolved}
            gradient="bg-gradient-to-r from-emerald-500 to-teal-500"
            accentColor="bg-emerald-500"
          />
          <StatCard
            icon={<UserCheck className="h-5 w-5 text-amber-400" />}
            label={pending > 0 ? "HITL Pending" : "HITL Approved"}
            value={pending > 0 ? pending : hitlCount}
            gradient="bg-gradient-to-r from-amber-500 to-orange-500"
            accentColor="bg-amber-500"
            pulse={pending > 0}
          />
          <StatCard
            icon={<Server className="h-5 w-5 text-violet-400" />}
            label="Active Pods"
            value={activePods}
            gradient="bg-gradient-to-r from-violet-500 to-purple-500"
            accentColor="bg-violet-500"
          />
        </div>
      )}

      {/* ================================================================ */}
      {/*  COST SAVINGS ROW                                                 */}
      {/* ================================================================ */}

      {!loading && resolved > 0 && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard
            icon={<Clock className="h-5 w-5 text-emerald-400" />}
            label="Time Saved"
            value={`${((resolved * 40) / 60).toFixed(1)}h`}
            gradient="bg-gradient-to-r from-emerald-500 to-green-500"
            accentColor="bg-emerald-500"
          />
          <StatCard
            icon={<TrendingDown className="h-5 w-5 text-teal-400" />}
            label="Cost Saved"
            value={`$${(resolved * 40 * 0.75).toFixed(0)}`}
            gradient="bg-gradient-to-r from-teal-500 to-emerald-500"
            accentColor="bg-teal-500"
          />
          <StatCard
            icon={<Zap className="h-5 w-5 text-cyan-400" />}
            label="Avg MTTR"
            value={avgResolutionMs > 0 ? `${(avgResolutionMs / 1000).toFixed(0)}s` : "~30s"}
            gradient="bg-gradient-to-r from-cyan-500 to-sky-500"
            accentColor="bg-cyan-500"
          />
          <StatCard
            icon={<CheckCircle2 className="h-5 w-5 text-purple-400" />}
            label="Auto-Fix Rate"
            value={`${totalIncidents > 0 ? ((resolved / totalIncidents) * 100).toFixed(0) : 0}%`}
            gradient="bg-gradient-to-r from-purple-500 to-fuchsia-500"
            accentColor="bg-purple-500"
          />
        </div>
      )}

      {/* ================================================================ */}
      {/*  LIVE PIPELINE ACTIVITY FEED                                      */}
      {/* ================================================================ */}

      {auditEntries.length > 0 && (
        <div className="relative overflow-hidden rounded-xl border border-slate-700/60 bg-slate-900/80 backdrop-blur-sm">
          <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-amber-500/80 via-red-500/80 to-purple-500/80" />
          <div className="p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-75" />
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-amber-500" />
                </div>
                <span className="text-xs font-mono font-bold uppercase tracking-widest text-slate-300">
                  Live Pipeline Activity
                </span>
                <span className="rounded-full bg-slate-800 px-2 py-0.5 text-[10px] font-mono text-slate-500">
                  {auditEntries.length} events
                </span>
              </div>
            </div>
            <div className="space-y-1.5 max-h-[200px] overflow-y-auto pr-1">
              {[...auditEntries].reverse().slice(0, 15).map((entry, idx) => {
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
                const isNew = idx < (auditEntries.length - prevAuditCount.current) && prevAuditCount.current > 0;
                const anomalyType = (entry.details as Record<string, Record<string, string>>)?.anomaly?.type || "";
                const action = (entry.details as Record<string, Record<string, string>>)?.plan?.action || "";
                const isSuccess = entry.outcome?.includes("success");
                const isFailure = entry.outcome?.includes("failure");

                return (
                  <div
                    key={`${entry.incident_id}-${idx}`}
                    className={`flex items-center gap-2 rounded-lg px-3 py-1.5 font-mono text-[11px]
                      ${isNew ? "bg-amber-500/5 border border-amber-500/20 animate-[fadeIn_0.5s_ease]" : "bg-slate-800/40"}
                      transition-all duration-300`}
                  >
                    <span className="text-slate-600 w-16 shrink-0">
                      {entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : ""}
                    </span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] border font-bold uppercase ${stageClass} w-16 text-center shrink-0`}>
                      {entry.stage}
                    </span>
                    <span className="text-slate-500 w-24 shrink-0 truncate">{entry.incident_id}</span>
                    {anomalyType && (
                      <span className="text-cyan-300/80 shrink-0">{anomalyType}</span>
                    )}
                    {action && (
                      <span className="text-slate-500">→ <span className="text-amber-300/80">{action}</span></span>
                    )}
                    <span className="ml-auto shrink-0">
                      {isSuccess && <span className="text-emerald-400">resolved</span>}
                      {isFailure && <span className="text-red-400">failed</span>}
                      {entry.decision && !isSuccess && !isFailure && (
                        <span className="text-slate-500">{entry.decision}</span>
                      )}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ================================================================ */}
      {/*  MIDDLE: Cluster Health  |  Incident Analytics                    */}
      {/* ================================================================ */}

      <div className="grid gap-6 lg:grid-cols-2">
        {/* ---------- Cluster Health ---------- */}
        <div
          className="relative overflow-hidden rounded-xl border border-slate-700/60 bg-slate-900/80
            backdrop-blur-sm transition-all duration-300 hover:border-slate-600"
        >
          <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-emerald-500/80 via-cyan-500/80 to-blue-500/80" />

          <div className="p-5">
            <SectionHeader
              icon={<Signal className="h-4 w-4 text-emerald-400" />}
              title="Cluster Health"
              badge={
                cluster?.pods ? (
                  <span className="rounded-full bg-slate-800 px-2.5 py-0.5 text-xs font-mono text-slate-400">
                    {cluster.pods.length} pods
                  </span>
                ) : null
              }
            />

            {loading ? (
              <div className="space-y-3">
                <Skeleton className="h-4 w-32" />
                <div className="flex flex-wrap gap-2">
                  {Array.from({ length: 20 }).map((_, i) => (
                    <Skeleton key={i} className="h-3.5 w-3.5 rounded-full" />
                  ))}
                </div>
              </div>
            ) : cluster?.pods && cluster.pods.length > 0 ? (
              <>
                <PodLegend pods={cluster.pods} />
                <div className="mt-4 grid grid-cols-1 gap-1.5">
                  {cluster.pods.map((pod) => (
                    <PodDot
                      key={`${pod.namespace}/${pod.name}`}
                      pod={pod}
                    />
                  ))}
                </div>

                {/* Node list */}
                {cluster.nodes && cluster.nodes.length > 0 && (
                  <div className="mt-5 border-t border-slate-800 pt-3">
                    <div className="text-xs font-medium uppercase tracking-widest text-slate-500 mb-2">
                      Nodes
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {cluster.nodes.map((n) => {
                        const isReady = (n as unknown as Record<string, unknown>).ready === "True" ||
                          n.conditions?.find((c) => c.type === "Ready")?.status === "True";
                        return (
                          <span
                            key={n.name}
                            className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-mono
                              ${
                                isReady
                                  ? "border-emerald-800/50 bg-emerald-950/30 text-emerald-400"
                                  : "border-red-800/50 bg-red-950/30 text-red-400"
                              }`}
                          >
                            <Circle
                              className={`h-2 w-2 fill-current ${
                                isReady ? "text-emerald-500" : "text-red-500"
                              }`}
                            />
                            {n.name}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="flex flex-col items-center justify-center py-12 text-slate-500">
                <Server className="mb-2 h-8 w-8 opacity-40" />
                <span className="text-sm">No pods found</span>
              </div>
            )}
          </div>
        </div>

        {/* ---------- Incident Analytics ---------- */}
        <div
          className="relative overflow-hidden rounded-xl border border-slate-700/60 bg-slate-900/80
            backdrop-blur-sm transition-all duration-300 hover:border-slate-600"
        >
          <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-violet-500/80 via-fuchsia-500/80 to-pink-500/80" />

          <div className="p-5">
            <SectionHeader
              icon={<Zap className="h-4 w-4 text-violet-400" />}
              title="Incident Analytics"
            />

            {loading ? (
              <Skeleton className="h-[250px] w-full" />
            ) : (
              <MTTRChart incidents={incidents} />
            )}
          </div>
        </div>
      </div>

      {/* ================================================================ */}
      {/*  Chaos Button                                                     */}
      {/* ================================================================ */}

      <div className="flex justify-center">
        <ChaosButton />
      </div>

      {/* ================================================================ */}
      {/*  BOTTOM: Recent Incidents                                         */}
      {/* ================================================================ */}

      <div
        className="relative overflow-hidden rounded-xl border border-slate-700/60 bg-slate-900/80
          backdrop-blur-sm transition-all duration-300"
      >
        <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-cyan-500/80 via-blue-500/80 to-indigo-500/80" />

        <div className="p-5">
          <SectionHeader
            icon={<ShieldAlert className="h-4 w-4 text-cyan-400" />}
            title="Recent Incidents"
            badge={
              totalIncidents > 0 ? (
                <span className="rounded-full bg-cyan-500/10 px-2.5 py-0.5 text-xs font-mono text-cyan-400 border border-cyan-500/20">
                  {totalIncidents}
                </span>
              ) : null
            }
          />

          {loading ? (
            <div className="space-y-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <Skeleton key={i} className="h-28 w-full" />
              ))}
            </div>
          ) : sortedIncidents.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-slate-500">
              <div className="relative mb-4">
                <ShieldAlert className="h-12 w-12 opacity-20" />
                <div className="absolute -right-1 -top-1 flex h-3 w-3">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex h-3 w-3 rounded-full bg-emerald-500" />
                </div>
              </div>
              <span className="text-sm font-medium text-slate-400">
                No incidents detected
              </span>
              <span className="mt-1 text-xs text-slate-500">
                The agent is monitoring your cluster...
              </span>
            </div>
          ) : (
            <div className="relative max-h-[600px] space-y-3 overflow-y-auto pr-1">
              {/* Timeline line */}
              <div className="absolute left-[1.05rem] top-0 bottom-0 w-px bg-gradient-to-b from-cyan-500/30 via-slate-700/50 to-transparent" />

              {sortedIncidents.map((inc, idx) => (
                <div
                  key={inc.incident_id}
                  className="relative pl-10 transition-all duration-500"
                  style={{
                    animationDelay: `${idx * 60}ms`,
                    animation: "fadeSlideIn 0.4s ease-out both",
                  }}
                >
                  {/* Timeline dot */}
                  <div className="absolute left-[0.65rem] top-5 flex h-3 w-3 items-center justify-center">
                    <span
                      className={`inline-block h-2.5 w-2.5 rounded-full border-2 border-slate-900 ${
                        inc.outcome?.startsWith("success")
                          ? "bg-emerald-500"
                          : inc.outcome?.startsWith("failure")
                          ? "bg-red-500"
                          : "bg-amber-500"
                      }`}
                    />
                  </div>

                  <IncidentCard incident={inc} />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Keyframe for incident cards fade-in */}
      <style>{`
        @keyframes fadeSlideIn {
          from {
            opacity: 0;
            transform: translateY(8px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
      `}</style>
    </div>
  );
}
