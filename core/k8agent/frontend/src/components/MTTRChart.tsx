import {
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Area,
  ComposedChart,
  Cell,
} from "recharts";
import { BarChart3, TrendingUp, Activity, AlertCircle } from "lucide-react";
import type { Incident } from "../types";

interface Props {
  incidents: Incident[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

function getSeverityColor(severity?: string): string {
  if (!severity) return "#06b6d4";
  return SEVERITY_COLORS[severity.toLowerCase()] ?? "#06b6d4";
}

interface ChartPayloadEntry {
  name?: string;
  value?: number;
  color?: string;
  dataKey?: string;
}

interface ChartTooltipProps {
  active?: boolean;
  payload?: ChartPayloadEntry[];
  label?: string;
}

function CustomTooltip({ active, payload, label }: ChartTooltipProps) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-slate-900 border border-slate-700/80 rounded-xl px-4 py-3 shadow-2xl shadow-black/40">
      <p className="text-xs font-semibold text-white mb-2 tracking-wide">{label}</p>
      <div className="space-y-1.5">
        {payload.map((entry, i) => (
          <div key={i} className="flex items-center gap-2 text-xs">
            <div
              className="w-2.5 h-2.5 rounded-full"
              style={{ backgroundColor: entry.color }}
            />
            <span className="text-slate-400">{entry.name}:</span>
            <span className="font-bold text-white font-mono">
              {entry.dataKey === "confidence" ? `${entry.value}%` : entry.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function MTTRChart({ incidents }: Props) {
  if (incidents.length === 0) {
    return (
      <div className="bg-slate-900/60 border border-slate-700/50 rounded-2xl p-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 bg-cyan-500/10 rounded-xl border border-cyan-500/20">
            <BarChart3 size={18} className="text-cyan-400" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white">Incident Analytics</h2>
            <p className="text-xs text-slate-500">Anomaly type distribution and confidence</p>
          </div>
        </div>
        <div className="flex flex-col items-center justify-center h-56">
          <div className="w-14 h-14 rounded-2xl bg-slate-800/60 border border-slate-700/30 flex items-center justify-center mb-3">
            <Activity size={24} className="text-slate-600" />
          </div>
          <p className="text-sm text-slate-500 font-medium">No incidents recorded</p>
          <p className="text-xs text-slate-600 mt-1">
            Trigger chaos or wait for anomalies to populate this chart
          </p>
        </div>
      </div>
    );
  }

  // Aggregate by anomaly type
  const data = incidents.slice(-20);
  const aggregated: Record<
    string,
    { name: string; count: number; totalConf: number; severity: string }
  > = {};
  for (const inc of data) {
    const key = inc.anomaly_type || "Unknown";
    if (!aggregated[key]) {
      aggregated[key] = { name: key, count: 0, totalConf: 0, severity: inc.severity || "medium" };
    }
    aggregated[key].count++;
    aggregated[key].totalConf += (inc.confidence || 0) * 100;
  }

  const chartData = Object.values(aggregated)
    .map((a) => ({
      name: a.name.length > 18 ? a.name.slice(0, 16) + "..." : a.name,
      fullName: a.name,
      count: a.count,
      confidence: Math.round(a.totalConf / a.count),
      severity: a.severity,
    }))
    .sort((a, b) => b.count - a.count);

  const totalIncidents = chartData.reduce((sum, d) => sum + d.count, 0);
  const avgConfidence = Math.round(
    chartData.reduce((sum, d) => sum + d.confidence, 0) / chartData.length
  );
  const topType = chartData[0]?.fullName ?? "N/A";

  return (
    <div className="bg-slate-900/60 border border-slate-700/50 rounded-2xl p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-500/10 rounded-xl border border-cyan-500/20">
            <BarChart3 size={18} className="text-cyan-400" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white">Incident Analytics</h2>
            <p className="text-xs text-slate-500">Anomaly type distribution and confidence scores</p>
          </div>
        </div>
        {incidents.length > 0 && (
          <div className="flex items-center gap-1 px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
            <AlertCircle size={12} className="text-emerald-400" />
            <span className="text-xs font-mono font-bold text-emerald-400">{totalIncidents}</span>
            <span className="text-xs text-emerald-400/60">total</span>
          </div>
        )}
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-3 gap-3 mb-5">
        <div className="bg-slate-800/50 rounded-xl px-3.5 py-2.5 border border-slate-700/30">
          <p className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
            Incidents
          </p>
          <p className="text-lg font-bold text-white font-mono mt-0.5">{totalIncidents}</p>
        </div>
        <div className="bg-slate-800/50 rounded-xl px-3.5 py-2.5 border border-slate-700/30">
          <p className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
            Avg Confidence
          </p>
          <div className="flex items-baseline gap-1 mt-0.5">
            <p className="text-lg font-bold text-white font-mono">{avgConfidence}</p>
            <p className="text-xs text-slate-500">%</p>
          </div>
        </div>
        <div className="bg-slate-800/50 rounded-xl px-3.5 py-2.5 border border-slate-700/30">
          <p className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
            Top Anomaly
          </p>
          <p className="text-sm font-bold text-white mt-0.5 truncate" title={topType}>
            {topType.length > 14 ? topType.slice(0, 12) + "..." : topType}
          </p>
        </div>
      </div>

      {/* Chart */}
      <ResponsiveContainer width="100%" height={280}>
        <ComposedChart data={chartData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
          <defs>
            <linearGradient id="barGradientCyan" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity={1} />
              <stop offset="100%" stopColor="#0891b2" stopOpacity={0.7} />
            </linearGradient>
            <linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#10b981" stopOpacity={0.3} />
              <stop offset="100%" stopColor="#10b981" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          <XAxis
            dataKey="name"
            tick={{ fill: "#64748b", fontSize: 11, fontFamily: "ui-monospace, monospace" }}
            stroke="#334155"
            tickLine={false}
            axisLine={{ stroke: "#334155" }}
          />
          <YAxis
            yAxisId="left"
            tick={{ fill: "#64748b", fontSize: 11, fontFamily: "ui-monospace, monospace" }}
            stroke="#334155"
            tickLine={false}
            axisLine={false}
          />
          <YAxis
            yAxisId="right"
            orientation="right"
            domain={[0, 100]}
            tick={{ fill: "#64748b", fontSize: 11, fontFamily: "ui-monospace, monospace" }}
            stroke="#334155"
            tickLine={false}
            axisLine={false}
            tickFormatter={(v: number) => `${v}%`}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(148,163,184,0.05)" }} />
          <Legend
            wrapperStyle={{ fontFamily: "ui-monospace, monospace", fontSize: 11 }}
            iconType="circle"
            iconSize={8}
            formatter={(value: string) => (
              <span className="text-slate-400 ml-1">{value}</span>
            )}
          />
          <Area
            yAxisId="right"
            type="monotone"
            dataKey="confidence"
            name="Confidence %"
            stroke="#10b981"
            strokeWidth={2}
            fill="url(#areaGradient)"
            dot={{ r: 4, fill: "#10b981", stroke: "#064e3b", strokeWidth: 2 }}
            activeDot={{ r: 6, fill: "#10b981", stroke: "#fff", strokeWidth: 2 }}
          />
          <Bar
            yAxisId="left"
            dataKey="count"
            name="Incidents"
            radius={[6, 6, 0, 0]}
            maxBarSize={48}
          >
            {chartData.map((entry, index) => (
              <Cell
                key={index}
                fill={getSeverityColor(entry.severity)}
                fillOpacity={0.85}
              />
            ))}
          </Bar>
        </ComposedChart>
      </ResponsiveContainer>

      {/* Legend for severity colors */}
      <div className="flex items-center justify-center gap-4 mt-4 pt-3 border-t border-slate-800/60">
        <div className="flex items-center gap-1.5">
          <TrendingUp size={12} className="text-slate-500" />
          <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
            Bar color by severity:
          </span>
        </div>
        {Object.entries(SEVERITY_COLORS).map(([label, color]) => (
          <div key={label} className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
            <span className="text-[10px] text-slate-500 capitalize">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
