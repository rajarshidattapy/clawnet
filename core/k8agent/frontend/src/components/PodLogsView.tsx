import { useState, useEffect, useRef, useCallback } from "react";
import {
  Terminal,
  RefreshCw,
  ChevronDown,
  ArrowDownToLine,
  ToggleLeft,
  ToggleRight,
} from "lucide-react";
import { fetchClusterState, fetchPodLogs } from "../lib/api";
import type { PodStatus } from "../types";

const TAIL_OPTIONS = [50, 100, 500];

function colorizeLogLine(line: string) {
  if (/\b(ERROR|FATAL|PANIC)\b/i.test(line)) {
    return "text-rose-400";
  }
  if (/\b(WARN|WARNING)\b/i.test(line)) {
    return "text-amber-400";
  }
  return "text-slate-300";
}

export default function PodLogsView() {
  const [pods, setPods] = useState<PodStatus[]>([]);
  const [selectedPod, setSelectedPod] = useState<PodStatus | null>(null);
  const [logs, setLogs] = useState<string>("");
  const [loadingLogs, setLoadingLogs] = useState(false);
  const [loadingPods, setLoadingPods] = useState(true);
  const [tailLines, setTailLines] = useState(100);
  const [previous, setPrevious] = useState(false);
  const logEndRef = useRef<HTMLDivElement>(null);

  // Load pods
  useEffect(() => {
    async function load() {
      try {
        const state = await fetchClusterState();
        setPods(state.pods ?? []);
      } catch {
        // silently fail
      } finally {
        setLoadingPods(false);
      }
    }
    load();
  }, []);

  // Load logs when pod or settings change
  const loadLogs = useCallback(async () => {
    if (!selectedPod) return;
    setLoadingLogs(true);
    try {
      const data = await fetchPodLogs(
        selectedPod.namespace,
        selectedPod.name,
        tailLines,
        previous
      );
      // API may return { logs: string } or just a string
      const text = typeof data === "string" ? data : data?.logs ?? JSON.stringify(data, null, 2);
      setLogs(text);
    } catch (err: any) {
      setLogs(`Error fetching logs: ${err.message}`);
    } finally {
      setLoadingLogs(false);
    }
  }, [selectedPod, tailLines, previous]);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  // Auto-scroll to bottom
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const logLines = logs ? logs.split("\n") : [];

  return (
    <div className="flex h-[calc(100vh-220px)] gap-4">
      {/* Left sidebar: pod list */}
      <div className="w-64 shrink-0 bg-slate-800/40 rounded-xl border border-slate-700/40 flex flex-col overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-700/40 flex items-center gap-2">
          <Terminal size={14} className="text-cyan-400" />
          <span className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
            Pods
          </span>
          <span className="ml-auto text-[10px] font-mono text-slate-500">{pods.length}</span>
        </div>
        <div className="flex-1 overflow-y-auto py-1">
          {loadingPods && (
            <div className="text-center py-8 text-slate-600 font-mono text-xs">Loading...</div>
          )}
          {!loadingPods && pods.length === 0 && (
            <div className="text-center py-8 text-slate-600 font-mono text-xs">No pods found</div>
          )}
          {pods.map((pod) => {
            const isSelected = selectedPod?.name === pod.name && selectedPod?.namespace === pod.namespace;
            const phaseColor =
              pod.phase === "Running"
                ? "bg-emerald-500"
                : pod.phase === "Pending"
                  ? "bg-amber-500"
                  : "bg-rose-500";

            return (
              <button
                key={`${pod.namespace}/${pod.name}`}
                onClick={() => setSelectedPod(pod)}
                className={`w-full text-left px-3 py-2 flex items-center gap-2 transition-colors cursor-pointer ${
                  isSelected
                    ? "bg-cyan-500/10 border-r-2 border-cyan-400"
                    : "hover:bg-slate-800/60"
                }`}
              >
                <span className={`w-2 h-2 rounded-full shrink-0 ${phaseColor}`} />
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-mono text-slate-300 truncate">{pod.name}</div>
                  <div className="text-[10px] font-mono text-slate-600 truncate">
                    {pod.namespace}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Right panel: logs */}
      <div className="flex-1 bg-slate-950 rounded-xl border border-slate-700/40 flex flex-col overflow-hidden">
        {/* Controls bar */}
        <div className="px-4 py-2 border-b border-slate-700/40 flex items-center gap-3 bg-slate-900/60">
          {selectedPod ? (
            <>
              <Terminal size={13} className="text-cyan-400 shrink-0" />
              <span className="text-xs font-mono text-slate-300 truncate">
                {selectedPod.namespace}/{selectedPod.name}
              </span>

              {/* Tail dropdown */}
              <div className="ml-auto flex items-center gap-3">
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-mono text-slate-500">Tail:</span>
                  <div className="relative">
                    <select
                      value={tailLines}
                      onChange={(e) => setTailLines(Number(e.target.value))}
                      className="appearance-none bg-slate-800 border border-slate-700/60 rounded px-2 py-0.5 text-[10px] font-mono text-slate-300 pr-5 cursor-pointer"
                    >
                      {TAIL_OPTIONS.map((n) => (
                        <option key={n} value={n}>
                          {n}
                        </option>
                      ))}
                    </select>
                    <ChevronDown
                      size={10}
                      className="absolute right-1 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none"
                    />
                  </div>
                </div>

                {/* Previous toggle */}
                <button
                  onClick={() => setPrevious((p) => !p)}
                  className="flex items-center gap-1 text-[10px] font-mono text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
                >
                  {previous ? (
                    <ToggleRight size={16} className="text-cyan-400" />
                  ) : (
                    <ToggleLeft size={16} />
                  )}
                  Previous
                </button>

                {/* Refresh */}
                <button
                  onClick={loadLogs}
                  className="flex items-center gap-1 text-[10px] font-mono text-slate-500 hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  <RefreshCw size={12} className={loadingLogs ? "animate-spin" : ""} />
                  Refresh
                </button>

                {/* Scroll to bottom */}
                <button
                  onClick={() => logEndRef.current?.scrollIntoView({ behavior: "smooth" })}
                  className="flex items-center gap-1 text-[10px] font-mono text-slate-500 hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  <ArrowDownToLine size={12} />
                </button>
              </div>
            </>
          ) : (
            <span className="text-xs font-mono text-slate-600">Select a pod to view logs</span>
          )}
        </div>

        {/* Log output */}
        <div className="flex-1 overflow-y-auto p-4 font-mono text-xs leading-relaxed">
          {!selectedPod && (
            <div className="flex flex-col items-center justify-center h-full text-slate-600">
              <Terminal size={40} className="mb-3 opacity-30" />
              <span className="text-sm font-mono">No pod selected</span>
              <span className="text-xs font-mono mt-1 text-slate-700">
                Choose a pod from the sidebar to view its logs
              </span>
            </div>
          )}

          {selectedPod && loadingLogs && (
            <div className="flex items-center justify-center h-full text-slate-600">
              <RefreshCw size={16} className="animate-spin mr-2" />
              <span className="font-mono text-xs">Loading logs...</span>
            </div>
          )}

          {selectedPod && !loadingLogs && logLines.length === 0 && (
            <div className="flex items-center justify-center h-full text-slate-600 font-mono text-xs">
              No log output
            </div>
          )}

          {selectedPod &&
            !loadingLogs &&
            logLines.map((line, i) => (
              <div key={i} className={`${colorizeLogLine(line)} whitespace-pre-wrap break-all`}>
                <span className="text-slate-700 select-none mr-3 inline-block w-8 text-right">
                  {i + 1}
                </span>
                {line}
              </div>
            ))}
          <div ref={logEndRef} />
        </div>
      </div>
    </div>
  );
}
