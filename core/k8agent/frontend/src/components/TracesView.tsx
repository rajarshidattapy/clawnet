import { useState, useEffect, useCallback } from "react";
import {
  Activity,
  ChevronDown,
  ChevronRight,
  Clock,
  Cpu,
  RefreshCw,
  Zap,
} from "lucide-react";
import { fetchTraces } from "../lib/api";
import type { Trace } from "../types";

const STAGE_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  detect:   { bg: "bg-purple-500/15", text: "text-purple-400", border: "border-purple-500/30" },
  diagnose: { bg: "bg-cyan-500/15",   text: "text-cyan-400",   border: "border-cyan-500/30" },
  plan:     { bg: "bg-amber-500/15",  text: "text-amber-400",  border: "border-amber-500/30" },
  explain:  { bg: "bg-emerald-500/15", text: "text-emerald-400", border: "border-emerald-500/30" },
};

function durationColor(ms: number) {
  if (ms < 2000) return "bg-emerald-500";
  if (ms < 5000) return "bg-amber-500";
  return "bg-rose-500";
}

function formatDuration(ms: number) {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function approxTokens(chars: number) {
  return Math.round(chars / 4);
}

/** Unescape literal \n and \t sequences so <pre> renders real whitespace. */
function unescapeText(s: string): string {
  return s.replace(/\\n/g, "\n").replace(/\\t/g, "\t");
}

export default function TracesView() {
  const [traces, setTraces] = useState<Trace[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedIncidents, setExpandedIncidents] = useState<Set<string>>(new Set());
  const [expandedPreviews, setExpandedPreviews] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    try {
      const data = await fetchTraces(200);
      setTraces(data);
    } catch {
      // silently fail
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, [load]);

  // Group by trace_id (incident)
  const grouped = traces.reduce<Record<string, Trace[]>>((acc, t) => {
    (acc[t.trace_id] ??= []).push(t);
    return acc;
  }, {});

  const incidentIds = Object.keys(grouped);
  const totalDuration = traces.reduce((s, t) => s + t.duration_ms, 0);
  const avgDuration = traces.length ? totalDuration / traces.length : 0;
  const totalTokens = traces.reduce((s, t) => s + approxTokens(t.input_chars + t.output_chars), 0);

  function toggleIncident(id: string) {
    setExpandedIncidents((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function togglePreview(key: string) {
    setExpandedPreviews((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center">
            <Activity size={18} className="text-cyan-400" />
          </div>
          <div>
            <h2 className="text-base font-mono font-bold text-slate-100">Pipeline Traces</h2>
            <p className="text-xs font-mono text-slate-500">
              {traces.length} traces &middot; {formatDuration(totalDuration)} total LLM time
            </p>
          </div>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-1.5 text-xs font-mono text-slate-500 hover:text-cyan-400 transition-colors cursor-pointer"
        >
          <RefreshCw size={13} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Traces", value: String(traces.length), icon: <Activity size={14} /> },
          { label: "Incidents", value: String(incidentIds.length), icon: <Zap size={14} /> },
          { label: "Avg Duration", value: formatDuration(avgDuration), icon: <Clock size={14} /> },
          { label: "Total Tokens", value: totalTokens.toLocaleString(), icon: <Cpu size={14} /> },
        ].map((stat) => (
          <div
            key={stat.label}
            className="bg-slate-800/40 rounded-xl border border-slate-700/40 p-4 text-center"
          >
            <div className="flex justify-center mb-2 text-cyan-400">{stat.icon}</div>
            <div className="text-xl font-bold font-mono text-cyan-300">{stat.value}</div>
            <div className="text-[10px] text-slate-500 font-mono mt-1 uppercase tracking-wider">
              {stat.label}
            </div>
          </div>
        ))}
      </div>

      {/* Timeline */}
      <div className="space-y-2">
        {incidentIds.length === 0 && !loading && (
          <div className="text-center py-16 text-slate-600 font-mono text-sm">
            No traces yet. Run an incident pipeline to see traces here.
          </div>
        )}

        {incidentIds.map((incidentId) => {
          const items = grouped[incidentId];
          const expanded = expandedIncidents.has(incidentId);
          const incidentDuration = items.reduce((s, t) => s + t.duration_ms, 0);
          const stageCount = items.length;

          return (
            <div
              key={incidentId}
              className="bg-slate-800/40 rounded-xl border border-slate-700/40 overflow-hidden"
            >
              {/* Incident header */}
              <button
                onClick={() => toggleIncident(incidentId)}
                className="w-full flex items-center gap-3 px-4 py-3 hover:bg-slate-800/60 transition-colors cursor-pointer"
              >
                {expanded ? (
                  <ChevronDown size={14} className="text-slate-500 shrink-0" />
                ) : (
                  <ChevronRight size={14} className="text-slate-500 shrink-0" />
                )}
                <span className="text-xs font-mono text-slate-300 truncate flex-1 text-left">
                  {incidentId}
                </span>
                <span className="text-[10px] font-mono text-slate-500">
                  {stageCount} stages
                </span>
                <span className="text-[10px] font-mono text-slate-500">
                  {formatDuration(incidentDuration)}
                </span>
                {/* Mini duration bar */}
                <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden shrink-0">
                  <div
                    className={`h-full rounded-full ${durationColor(incidentDuration)}`}
                    style={{ width: `${Math.min(100, (incidentDuration / 10000) * 100)}%` }}
                  />
                </div>
              </button>

              {/* Expanded stages */}
              {expanded && (
                <div className="border-t border-slate-700/40 px-4 py-3">
                  <div className="relative pl-6">
                    {/* Vertical timeline line */}
                    <div className="absolute left-2 top-2 bottom-2 w-px bg-slate-700" />

                    <div className="space-y-4">
                      {items.map((trace, idx) => {
                        const colors = STAGE_COLORS[trace.stage] ?? STAGE_COLORS.detect;
                        const inputKey = `${trace.trace_id}-${trace.stage}-input`;
                        const outputKey = `${trace.trace_id}-${trace.stage}-output`;
                        const inputExpanded = expandedPreviews.has(inputKey);
                        const outputExpanded = expandedPreviews.has(outputKey);

                        return (
                          <div key={idx} className="relative">
                            {/* Timeline dot */}
                            <div
                              className={`absolute -left-[18px] top-2 w-2.5 h-2.5 rounded-full border-2 ${colors.border} ${colors.bg}`}
                            />

                            <div className="bg-slate-900/50 rounded-lg border border-slate-700/30 p-4 space-y-3">
                              {/* Stage header */}
                              <div className="flex items-center gap-3 flex-wrap">
                                <span
                                  className={`text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded-full ${colors.bg} ${colors.text} border ${colors.border}`}
                                >
                                  {trace.stage}
                                </span>
                                <span className="text-[10px] font-mono text-slate-500">
                                  {trace.model}
                                </span>
                                <span className="text-[10px] font-mono text-slate-500">
                                  {formatDuration(trace.duration_ms)}
                                </span>
                                {/* Duration bar */}
                                <div className="w-20 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                                  <div
                                    className={`h-full rounded-full ${durationColor(trace.duration_ms)}`}
                                    style={{
                                      width: `${Math.min(100, (trace.duration_ms / 5000) * 100)}%`,
                                    }}
                                  />
                                </div>
                                <span className="ml-auto text-[10px] font-mono text-slate-600">
                                  ~{approxTokens(trace.input_chars + trace.output_chars)} tokens
                                </span>
                              </div>

                              {/* Input — what the LLM received */}
                              <div>
                                <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1 flex items-center gap-2">
                                  <span className="w-1.5 h-1.5 rounded-full bg-blue-400"></span>
                                  LLM Input — {trace.stage === "detect" ? "Raw cluster signals" : trace.stage === "diagnose" ? "kubectl logs + describe output" : trace.stage === "plan" ? "Diagnosis text" : "Full incident context"} ({trace.input_chars} chars)
                                </div>
                                <pre className="text-xs font-mono text-slate-400 bg-slate-950/60 rounded-md p-2.5 overflow-x-auto whitespace-pre-wrap break-words max-h-[300px] overflow-y-auto border border-slate-800/50">
                                  {inputExpanded
                                    ? unescapeText(trace.input_full || trace.input_preview)
                                    : unescapeText(trace.input_preview.slice(0, 200))}
                                  {trace.input_preview.length > 200 && (
                                    <button
                                      onClick={() => togglePreview(inputKey)}
                                      className="text-cyan-500 hover:text-cyan-400 ml-1 cursor-pointer"
                                    >
                                      {inputExpanded ? " ▲ collapse" : "... ▼ show full input"}
                                    </button>
                                  )}
                                </pre>
                              </div>

                              {/* Output — what the LLM responded */}
                              <div>
                                <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1 flex items-center gap-2">
                                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                                  LLM Output — {trace.stage === "detect" ? "Anomaly classification" : trace.stage === "diagnose" ? "Root cause analysis" : trace.stage === "plan" ? "Remediation plan" : "Incident summary"} ({trace.output_chars} chars)
                                </div>
                                <pre className="text-xs font-mono text-emerald-300/70 bg-slate-950/60 rounded-md p-2.5 overflow-x-auto whitespace-pre-wrap break-words max-h-[300px] overflow-y-auto border border-slate-800/50">
                                  {outputExpanded
                                    ? unescapeText(trace.output_full || trace.output_preview)
                                    : unescapeText(trace.output_preview.slice(0, 200))}
                                  {trace.output_preview.length > 200 && (
                                    <button
                                      onClick={() => togglePreview(outputKey)}
                                      className="text-emerald-500 hover:text-emerald-400 ml-1 cursor-pointer"
                                    >
                                      {outputExpanded ? " ▲ collapse" : "... ▼ show full output"}
                                    </button>
                                  )}
                                </pre>
                              </div>

                              {/* Timestamp */}
                              <div className="text-[10px] font-mono text-slate-600">
                                {new Date(trace.timestamp).toLocaleString()}
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
