import {
  CheckCircle2,
  XCircle,
  Clock,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Target,
  Radio,
  Box,
} from "lucide-react";
import type { Incident } from "../types";

/* ── severity palette ─────────────────────────────────────── */

const SEVERITY = {
  CRITICAL: {
    border: "border-l-red-500",
    badge: "bg-red-500/15 text-red-400 ring-red-500/30",
    glow: "hover:shadow-red-500/10",
    dot: "bg-red-500",
    bar: "bg-red-500",
  },
  HIGH: {
    border: "border-l-orange-500",
    badge: "bg-orange-500/15 text-orange-400 ring-orange-500/30",
    glow: "hover:shadow-orange-500/10",
    dot: "bg-orange-500",
    bar: "bg-orange-500",
  },
  MED: {
    border: "border-l-yellow-500",
    badge: "bg-yellow-500/15 text-yellow-400 ring-yellow-500/30",
    glow: "hover:shadow-yellow-500/10",
    dot: "bg-yellow-500",
    bar: "bg-yellow-500",
  },
  LOW: {
    border: "border-l-cyan-500",
    badge: "bg-cyan-500/15 text-cyan-400 ring-cyan-500/30",
    glow: "hover:shadow-cyan-500/10",
    dot: "bg-cyan-500",
    bar: "bg-cyan-500",
  },
} as const;

type SeverityKey = keyof typeof SEVERITY;

function sev(s?: string) {
  return SEVERITY[(s?.toUpperCase() as SeverityKey) ?? "MED"] ?? SEVERITY.MED;
}

/* ── anomaly type color (deterministic hash) ──────────────── */

const ANOMALY_COLORS = [
  "bg-violet-500/15 text-violet-400 ring-violet-500/25",
  "bg-fuchsia-500/15 text-fuchsia-400 ring-fuchsia-500/25",
  "bg-sky-500/15 text-sky-400 ring-sky-500/25",
  "bg-teal-500/15 text-teal-400 ring-teal-500/25",
  "bg-rose-500/15 text-rose-400 ring-rose-500/25",
  "bg-amber-500/15 text-amber-400 ring-amber-500/25",
  "bg-indigo-500/15 text-indigo-400 ring-indigo-500/25",
  "bg-lime-500/15 text-lime-400 ring-lime-500/25",
];

function anomalyColor(type: string) {
  let h = 0;
  for (let i = 0; i < type.length; i++) h = (h * 31 + type.charCodeAt(i)) | 0;
  return ANOMALY_COLORS[Math.abs(h) % ANOMALY_COLORS.length];
}

/* ── outcome config ───────────────────────────────────────── */

function outcomeStyle(outcome: string) {
  if (outcome?.startsWith("success"))
    return {
      bg: "bg-emerald-500/10 text-emerald-400 ring-emerald-500/25",
      Icon: CheckCircle2,
      label: "Resolved",
    };
  if (outcome?.startsWith("rejected"))
    return {
      bg: "bg-slate-500/10 text-slate-400 ring-slate-500/25",
      Icon: Shield,
      label: "Rejected",
    };
  if (outcome?.startsWith("failure"))
    return {
      bg: "bg-red-500/10 text-red-400 ring-red-500/25",
      Icon: XCircle,
      label: "Failed",
    };
  return {
    bg: "bg-yellow-500/10 text-yellow-400 ring-yellow-500/25",
    Icon: Clock,
    label: "Pending",
  };
}

/* ── blast radius config ──────────────────────────────────── */

function blastStyle(radius?: string) {
  switch (radius) {
    case "low":
      return { icon: ShieldCheck, cls: "text-emerald-400" };
    case "medium":
      return { icon: Shield, cls: "text-yellow-400" };
    case "high":
      return { icon: ShieldAlert, cls: "text-red-400" };
    default:
      return { icon: Shield, cls: "text-slate-500" };
  }
}

/* ── stage definitions (ordered) ──────────────────────────── */

const ALL_STAGES = ["detect", "diagnose", "plan", "execute", "explain"];

/* ── helpers ──────────────────────────────────────────────── */

function relativeTime(iso: string) {
  const d = new Date(iso);
  const diff = Date.now() - d.getTime();
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/* ── component ────────────────────────────────────────────── */

export default function IncidentCard({ incident }: { incident: Incident }) {
  const i = incident;
  const s = sev(i.severity);
  const oc = outcomeStyle(i.outcome);
  const bl = blastStyle(i.blast_radius);
  const BlastIcon = bl.icon;
  const OutcomeIcon = oc.Icon;
  const confPct = i.confidence != null ? Math.round(i.confidence * 100) : null;

  const summary =
    i.summary
      ?.replace(/^#.*\n/gm, "")
      ?.split("\n")
      ?.filter((l) => l.trim().length > 0)
      ?.[0]
      ?.slice(0, 220) || "Processing...";

  const completedStages = new Set(i.stages?.map((st) => st.toLowerCase()) ?? []);

  return (
    <div
      className={[
        "group relative rounded-lg border-l-[3px] bg-slate-900/80 backdrop-blur-sm",
        "border border-slate-700/60 p-4 transition-all duration-200 cursor-default",
        "hover:scale-[1.01] hover:shadow-lg",
        s.border,
        s.glow,
      ].join(" ")}
    >
      {/* ── top row ── */}
      <div className="flex items-center gap-2 flex-wrap">
        {i.anomaly_type && (
          <span
            className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ring-inset ${anomalyColor(i.anomaly_type)}`}
          >
            <Zap className="h-3 w-3" />
            {i.anomaly_type}
          </span>
        )}

        {i.severity && (
          <span
            className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ring-1 ring-inset ${s.badge}`}
          >
            {i.severity}
          </span>
        )}

        <span className="ml-auto text-[11px] text-slate-500 tabular-nums">
          {i.first_seen ? relativeTime(i.first_seen) : ""}
        </span>
      </div>

      {/* ── resource + namespace + confidence ── */}
      <div className="mt-2.5 flex items-center gap-2 flex-wrap">
        {i.affected_resource && (
          <span className="inline-flex items-center gap-1.5 text-sm font-mono font-medium text-slate-200">
            <Box className="h-3.5 w-3.5 text-slate-500" />
            {i.affected_resource}
          </span>
        )}
        {i.namespace && (
          <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-mono font-medium text-slate-400 ring-1 ring-slate-700">
            {i.namespace}
          </span>
        )}
        {confPct != null && (
          <div className="ml-auto flex items-center gap-1.5">
            <span className="text-[10px] text-slate-500 tabular-nums">{confPct}%</span>
            <div className="h-1 w-14 overflow-hidden rounded-full bg-slate-800">
              <div
                className={`h-full rounded-full transition-all duration-500 ${s.bar}`}
                style={{ width: `${confPct}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {/* ── summary ── */}
      <p className="mt-2 line-clamp-2 text-[13px] leading-relaxed text-slate-400">
        {summary}
      </p>

      {/* ── action + blast radius + outcome ── */}
      <div className="mt-3 flex items-center gap-3 flex-wrap text-xs">
        {i.action && (
          <span className="inline-flex items-center gap-1 rounded-md bg-slate-800/80 px-2 py-1 font-mono text-cyan-400 ring-1 ring-slate-700/80">
            <Target className="h-3 w-3" />
            {i.action}
          </span>
        )}

        {i.blast_radius && (
          <span className={`inline-flex items-center gap-1 font-medium ${bl.cls}`}>
            <BlastIcon className="h-3.5 w-3.5" />
            <span className="text-[11px] uppercase tracking-wide">{i.blast_radius}</span>
          </span>
        )}

        <span
          className={`ml-auto inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] font-semibold ring-1 ring-inset ${oc.bg}`}
        >
          <OutcomeIcon className="h-3 w-3" />
          {oc.label}
        </span>
      </div>

      {/* ── stage progress with timing ── */}
      <div className="mt-3 flex items-center gap-1">
        {ALL_STAGES.map((stage, idx) => {
          const done = completedStages.has(stage);
          return (
            <div key={stage} className="flex items-center">
              <div className="group/dot relative">
                <div
                  className={[
                    "h-1.5 w-1.5 rounded-full transition-all duration-300",
                    done
                      ? `${s.dot} shadow-[0_0_6px_1px] shadow-current`
                      : "bg-slate-700",
                  ].join(" ")}
                />
                <span className="pointer-events-none absolute -top-6 left-1/2 -translate-x-1/2 rounded bg-slate-800 px-1.5 py-0.5 text-[9px] text-slate-300 opacity-0 transition-opacity group-hover/dot:opacity-100 whitespace-nowrap ring-1 ring-slate-700">
                  {stage}
                </span>
              </div>
              {idx < ALL_STAGES.length - 1 && (
                <div
                  className={`mx-0.5 h-px w-3 ${
                    done && completedStages.has(ALL_STAGES[idx + 1])
                      ? s.bar + " opacity-60"
                      : "bg-slate-700"
                  }`}
                />
              )}
            </div>
          );
        })}
        <span className="ml-1.5 text-[9px] text-slate-600 uppercase tracking-widest">
          {completedStages.size}/{ALL_STAGES.length}
        </span>
      </div>

      {/* ── confidence breakdown ── */}
      {confPct != null && i.anomaly_type && (
        <div className="mt-2 text-[10px] font-mono text-slate-600 flex items-center gap-2 flex-wrap">
          <span className="text-slate-500">Confidence factors:</span>
          {i.anomaly_type === "CrashLoopBackOff" && <span className="text-cyan-500/70">restartCount &gt; 3</span>}
          {i.anomaly_type === "OOMKilled" && <span className="text-cyan-500/70">terminated.reason=OOMKilled</span>}
          {i.anomaly_type === "Pending" && <span className="text-cyan-500/70">pending &gt; 5min</span>}
          {i.anomaly_type === "ImagePullBackOff" && <span className="text-cyan-500/70">image pull failure</span>}
          {i.anomaly_type === "CPUThrottling" && <span className="text-cyan-500/70">CPU &gt; target*0.8</span>}
          {i.anomaly_type === "DeploymentStalled" && <span className="text-cyan-500/70">updatedReplicas &lt; desired</span>}
          {i.anomaly_type === "Evicted" && <span className="text-cyan-500/70">pod.status.reason=Evicted</span>}
          {i.anomaly_type === "NodeNotReady" && <span className="text-cyan-500/70">Ready=False</span>}
          {i.blast_radius && <span className="text-amber-500/70">blast:{i.blast_radius}</span>}
          {i.action && i.action !== "no_op" && <span className="text-emerald-500/70">action:{i.action}</span>}
        </div>
      )}

      {/* ── subtle animated pulse for active incidents ── */}
      {!i.outcome?.startsWith("success") && !i.outcome?.startsWith("failure") && (
        <div className="absolute right-3 top-3">
          <Radio className="h-3 w-3 text-yellow-500 animate-pulse" />
        </div>
      )}
    </div>
  );
}
