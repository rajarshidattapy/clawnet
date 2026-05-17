import { useState, useEffect, useRef, useCallback } from "react";
import {
  ArrowDownToLine,
  ChevronDown,
  ChevronRight,
  Filter,
  Loader2,
  RefreshCw,
  ScrollText,
  Search,
} from "lucide-react";
import { fetchAuditLog } from "../lib/api";
import type { AuditEntry } from "../types";

/* ── syntax highlight for JSON ── */
function syntaxHighlight(json: string): string {
  return json.replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
    (match) => {
      let cls = "text-amber-300";
      if (/^"/.test(match)) {
        cls = /:$/.test(match) ? "text-cyan-400" : "text-emerald-300";
      } else if (/true|false/.test(match)) {
        cls = "text-purple-400";
      } else if (/null/.test(match)) {
        cls = "text-slate-500";
      }
      return `<span class="${cls}">${match}</span>`;
    },
  );
}

/* ── stage color map ── */
const STAGE_COLORS: Record<string, { bg: string; text: string; dot: string }> = {
  observe:     { bg: "bg-blue-500/15",    text: "text-blue-400",    dot: "bg-blue-500" },
  detect:      { bg: "bg-purple-500/15",  text: "text-purple-400",  dot: "bg-purple-500" },
  diagnose:    { bg: "bg-cyan-500/15",    text: "text-cyan-400",    dot: "bg-cyan-500" },
  plan:        { bg: "bg-amber-500/15",   text: "text-amber-400",   dot: "bg-amber-500" },
  execute:     { bg: "bg-orange-500/15",  text: "text-orange-400",  dot: "bg-orange-500" },
  explain:     { bg: "bg-emerald-500/15", text: "text-emerald-400", dot: "bg-emerald-500" },
  safety_gate: { bg: "bg-red-500/15",     text: "text-red-400",     dot: "bg-red-500" },
};

const DEFAULT_STAGE = { bg: "bg-slate-500/15", text: "text-slate-400", dot: "bg-slate-500" };

function stageColor(stage: string) {
  return STAGE_COLORS[stage.toLowerCase()] ?? DEFAULT_STAGE;
}

/* ── outcome helpers ── */
function outcomeStyle(outcome: string | undefined): string {
  if (!outcome) return "text-slate-500";
  const lower = outcome.toLowerCase();
  if (lower.startsWith("success") || lower.includes("resolved"))
    return "text-emerald-400";
  if (lower.startsWith("fail") || lower.includes("error"))
    return "text-red-400";
  if (lower.includes("pending") || lower.includes("progress"))
    return "text-amber-400";
  return "text-slate-400";
}

function outcomeDot(outcome: string | undefined): string {
  if (!outcome) return "bg-slate-500";
  const lower = outcome.toLowerCase();
  if (lower.startsWith("success") || lower.includes("resolved"))
    return "bg-emerald-500";
  if (lower.startsWith("fail") || lower.includes("error"))
    return "bg-red-500";
  if (lower.includes("pending") || lower.includes("progress"))
    return "bg-amber-500";
  return "bg-slate-500";
}

/* ── format helpers ── */
function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return ts;
  }
}

function formatDate(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
    });
  } catch {
    return "";
  }
}

function truncateId(id: string, len = 12): string {
  if (!id) return "";
  return id.length > len ? id.slice(0, len) + "..." : id;
}

/* ── single row ── */
function AuditRow({
  entry,
  index,
  isExpanded,
  onToggle,
}: {
  entry: AuditEntry;
  index: number;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const sc = stageColor(entry.stage);
  const isEven = index % 2 === 0;

  return (
    <div
      className={`group border-b border-slate-700/50 last:border-b-0 transition-colors duration-150 ${
        isEven ? "bg-slate-800/40" : "bg-slate-800/20"
      } hover:bg-slate-700/30`}
    >
      {/* main row */}
      <button
        type="button"
        onClick={onToggle}
        className="w-full text-left px-4 py-2.5 flex items-center gap-3 cursor-pointer select-none"
      >
        {/* expand chevron */}
        <span className="text-slate-500 shrink-0 transition-transform duration-200">
          {isExpanded ? (
            <ChevronDown className="w-3.5 h-3.5" />
          ) : (
            <ChevronRight className="w-3.5 h-3.5" />
          )}
        </span>

        {/* timestamp */}
        <span className="font-mono text-[11px] text-slate-400 shrink-0 tabular-nums w-[70px]">
          {formatTimestamp(entry.timestamp)}
        </span>

        {/* date (subtle) */}
        <span className="font-mono text-[10px] text-slate-600 shrink-0 w-[48px] hidden lg:inline-block">
          {formatDate(entry.timestamp)}
        </span>

        {/* stage badge */}
        <span
          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider shrink-0 ${sc.bg} ${sc.text}`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${sc.dot}`} />
          {entry.stage}
        </span>

        {/* incident id */}
        <span className="font-mono text-[11px] text-slate-500 shrink-0 w-[110px] truncate">
          {truncateId(entry.incident_id)}
        </span>

        {/* summary */}
        <span className="text-xs text-slate-400 truncate min-w-0 flex-1">
          {entry.summary
            ?.replace(/^#.*\n/gm, "")
            .split("\n")
            .filter((l) => l.trim())[0]
            ?.slice(0, 100) ?? ""}
        </span>

        {/* outcome */}
        <span
          className={`inline-flex items-center gap-1.5 text-[11px] font-medium shrink-0 ${outcomeStyle(entry.outcome)}`}
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${outcomeDot(entry.outcome)}`}
          />
          {entry.outcome?.slice(0, 28) ?? "-"}
        </span>
      </button>

      {/* expanded details */}
      <div
        className={`overflow-hidden transition-all duration-300 ease-in-out ${
          isExpanded ? "max-h-[500px] opacity-100" : "max-h-0 opacity-0"
        }`}
      >
        <div className="px-4 pb-3 pt-0">
          {/* decision + summary rows */}
          <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs mb-3 pl-6">
            {entry.decision && (
              <>
                <span className="text-slate-500 font-medium">Decision</span>
                <span className="text-slate-300">{entry.decision}</span>
              </>
            )}
            {entry.summary && (
              <>
                <span className="text-slate-500 font-medium">Summary</span>
                <span className="text-slate-300 whitespace-pre-wrap">
                  {entry.summary}
                </span>
              </>
            )}
            <span className="text-slate-500 font-medium">Incident</span>
            <span className="text-slate-300 font-mono text-[11px]">
              {entry.incident_id}
            </span>
          </div>

          {/* JSON details */}
          {entry.details && Object.keys(entry.details).length > 0 && (
            <div className="ml-6 rounded-md bg-slate-950/80 border border-slate-700/50 overflow-hidden">
              <div className="px-3 py-1.5 bg-slate-900/50 border-b border-slate-700/50 flex items-center gap-2">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Details
                </span>
              </div>
              <pre
                className="p-3 text-[11px] leading-relaxed overflow-x-auto max-h-64 font-mono"
                dangerouslySetInnerHTML={{
                  __html: syntaxHighlight(
                    JSON.stringify(entry.details, null, 2),
                  ),
                }}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ── main component ── */
export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [filterStage, setFilterStage] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [showSearch, setShowSearch] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const data = await fetchAuditLog();
      setEntries(data);
      setLastRefresh(new Date());
    } catch {
      /* silent */
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 10_000);
    return () => clearInterval(interval);
  }, [load]);

  const toggleExpand = (key: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const scrollToBottom = () =>
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });

  /* filter + search */
  const stages = Array.from(new Set(entries.map((e) => e.stage)));

  const filtered = entries.filter((e) => {
    if (filterStage && e.stage !== filterStage) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        e.stage?.toLowerCase().includes(q) ||
        e.incident_id?.toLowerCase().includes(q) ||
        e.summary?.toLowerCase().includes(q) ||
        e.outcome?.toLowerCase().includes(q) ||
        e.decision?.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="bg-slate-800/60 rounded-xl border border-slate-700/60 flex flex-col overflow-hidden backdrop-blur-sm">
      {/* ── header ── */}
      <div className="px-4 py-3 border-b border-slate-700/50 bg-slate-800/80">
        <div className="flex items-center justify-between">
          {/* left side */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <ScrollText className="w-4 h-4 text-cyan-500" />
              <h2 className="text-sm font-semibold text-slate-200 tracking-wide">
                Audit Trail
              </h2>
            </div>

            {/* entry count pill */}
            <span className="px-2 py-0.5 rounded-full bg-slate-700/60 text-[10px] font-medium text-slate-400 tabular-nums">
              {filtered.length}
              {filterStage || searchQuery
                ? ` / ${entries.length}`
                : ""}{" "}
              entries
            </span>

            {/* refresh indicator */}
            <div className="flex items-center gap-1.5">
              <RefreshCw
                className={`w-3 h-3 text-cyan-500/70 ${
                  isRefreshing ? "animate-spin" : ""
                }`}
              />
              {lastRefresh && (
                <span className="text-[10px] text-slate-600 tabular-nums">
                  {lastRefresh.toLocaleTimeString("en-US", {
                    hour12: false,
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                  })}
                </span>
              )}
            </div>
          </div>

          {/* right side actions */}
          <div className="flex items-center gap-1">
            {/* Export JSON */}
            <button
              onClick={() => {
                const blob = new Blob([JSON.stringify(entries, null, 2)], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a"); a.href = url; a.download = `k8swhisperer-audit-${new Date().toISOString().slice(0,10)}.json`;
                a.click(); URL.revokeObjectURL(url);
              }}
              className="p-1.5 rounded-md text-slate-400 hover:text-emerald-400 hover:bg-slate-700/50 transition-colors"
              title="Export JSON"
            >
              <ArrowDownToLine className="w-3.5 h-3.5" />
            </button>
            {/* Export CSV */}
            <button
              onClick={() => {
                const headers = ["timestamp","incident_id","stage","decision","outcome","summary"];
                const rows = entries.map(e => headers.map(h => `"${String((e as any)[h] || '').replace(/"/g, '""')}"`).join(","));
                const csv = [headers.join(","), ...rows].join("\n");
                const blob = new Blob([csv], { type: "text/csv" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a"); a.href = url; a.download = `k8swhisperer-audit-${new Date().toISOString().slice(0,10)}.csv`;
                a.click(); URL.revokeObjectURL(url);
              }}
              className="px-2 py-1 rounded-md text-[10px] font-mono text-slate-400 hover:text-emerald-400 hover:bg-slate-700/50 transition-colors border border-slate-700/50"
              title="Export CSV"
            >
              CSV
            </button>
            {/* search toggle */}
            <button
              onClick={() => {
                setShowSearch(!showSearch);
                if (showSearch) setSearchQuery("");
              }}
              className={`p-1.5 rounded-md transition-colors ${
                showSearch
                  ? "bg-cyan-500/15 text-cyan-400"
                  : "text-slate-400 hover:text-slate-300 hover:bg-slate-700/50"
              }`}
              title="Search"
            >
              <Search className="w-3.5 h-3.5" />
            </button>

            {/* filter toggle */}
            <button
              onClick={() =>
                setFilterStage(filterStage ? null : stages[0] ?? null)
              }
              className={`p-1.5 rounded-md transition-colors ${
                filterStage
                  ? "bg-cyan-500/15 text-cyan-400"
                  : "text-slate-400 hover:text-slate-300 hover:bg-slate-700/50"
              }`}
              title="Filter by stage"
            >
              <Filter className="w-3.5 h-3.5" />
            </button>

            {/* scroll to bottom */}
            <button
              onClick={scrollToBottom}
              className="p-1.5 rounded-md text-slate-400 hover:text-slate-300 hover:bg-slate-700/50 transition-colors"
              title="Scroll to bottom"
            >
              <ArrowDownToLine className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* search bar */}
        {showSearch && (
          <div className="mt-2">
            <input
              type="text"
              placeholder="Search entries..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-900/60 border border-slate-700/50 rounded-md px-3 py-1.5 text-xs text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 font-mono"
              autoFocus
            />
          </div>
        )}

        {/* stage filter pills */}
        {filterStage !== null && (
          <div className="flex items-center gap-1.5 mt-2 flex-wrap">
            <button
              onClick={() => setFilterStage(null)}
              className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors ${
                !filterStage
                  ? "bg-cyan-500/20 text-cyan-400"
                  : "bg-slate-700/40 text-slate-400 hover:bg-slate-700/60"
              }`}
            >
              All
            </button>
            {stages.map((s) => {
              const sc = stageColor(s);
              const active = filterStage === s;
              return (
                <button
                  key={s}
                  onClick={() => setFilterStage(active ? null : s)}
                  className={`px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider transition-colors ${
                    active
                      ? `${sc.bg} ${sc.text}`
                      : "bg-slate-700/40 text-slate-500 hover:bg-slate-700/60 hover:text-slate-400"
                  }`}
                >
                  {s}
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* ── column headers ── */}
      <div className="px-4 py-1.5 border-b border-slate-700/30 bg-slate-800/50 flex items-center gap-3 text-[10px] font-medium uppercase tracking-wider text-slate-600">
        <span className="w-3.5 shrink-0" />
        <span className="w-[70px] shrink-0">Time</span>
        <span className="w-[48px] shrink-0 hidden lg:inline-block">Date</span>
        <span className="w-[90px] shrink-0">Stage</span>
        <span className="w-[110px] shrink-0">Incident</span>
        <span className="flex-1 min-w-0">Summary</span>
        <span className="shrink-0">Outcome</span>
      </div>

      {/* ── log body ── */}
      <div
        ref={scrollRef}
        className="overflow-y-auto flex-1 max-h-[600px] scrollbar-thin scrollbar-track-slate-900 scrollbar-thumb-slate-700"
      >
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 px-4">
            {entries.length === 0 ? (
              <>
                <div className="w-12 h-12 rounded-full bg-slate-700/30 flex items-center justify-center mb-4">
                  <ScrollText className="w-6 h-6 text-slate-600" />
                </div>
                <p className="text-sm font-medium text-slate-500 mb-1">
                  No audit entries yet
                </p>
                <p className="text-xs text-slate-600 text-center max-w-xs">
                  Entries will appear here as K8sWhisperer processes incidents
                  through observe, detect, diagnose, plan, execute, and explain
                  stages.
                </p>
                <div className="flex items-center gap-2 mt-4 text-[10px] text-slate-600">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  Waiting for activity...
                </div>
              </>
            ) : (
              <>
                <div className="w-12 h-12 rounded-full bg-slate-700/30 flex items-center justify-center mb-4">
                  <Search className="w-6 h-6 text-slate-600" />
                </div>
                <p className="text-sm font-medium text-slate-500 mb-1">
                  No matching entries
                </p>
                <p className="text-xs text-slate-600">
                  Try adjusting your search or filter criteria.
                </p>
              </>
            )}
          </div>
        ) : (
          <>
            {filtered.map((entry, idx) => {
              const key = `${entry.incident_id}-${idx}`;
              return (
                <AuditRow
                  key={key}
                  entry={entry}
                  index={idx}
                  isExpanded={expandedIds.has(key)}
                  onToggle={() => toggleExpand(key)}
                />
              );
            })}
            <div ref={bottomRef} />
          </>
        )}
      </div>

      {/* ── footer status bar ── */}
      {entries.length > 0 && (
        <div className="px-4 py-1.5 border-t border-slate-700/30 bg-slate-800/50 flex items-center justify-between text-[10px] text-slate-600">
          <div className="flex items-center gap-3">
            <span className="tabular-nums">
              {filtered.length} of {entries.length} entries
            </span>
            {filterStage && (
              <span>
                Filtered:{" "}
                <span className={stageColor(filterStage).text}>
                  {filterStage}
                </span>
              </span>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                isRefreshing ? "bg-cyan-500 animate-pulse" : "bg-emerald-500"
              }`}
            />
            <span>Auto-refresh 10s</span>
          </div>
        </div>
      )}
    </div>
  );
}
