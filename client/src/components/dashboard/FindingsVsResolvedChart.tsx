import { useMemo, memo } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import { buildTimeseries } from "@/lib/dashboard-transforms";
import { GlowCard } from "@/components/ui/glow-card";

export const FindingsVsResolvedChart = memo(function FindingsVsResolvedChart({ evaluations = [] }: { evaluations: any[] }) {

  const series = useMemo(() => buildTimeseries(evaluations, 30), [evaluations]);

  return (
    <GlowCard glowColor="cyan" glowIntensity="sm" glass scanLine className="p-2">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span
            className="inline-block h-1.5 w-1.5 rounded-full bg-cyan-400"
            style={{
              boxShadow: "0 0 4px #38bdf8",
              animation: "pulse-glow 2s ease-in-out infinite",
            }}
          />
          <span
            style={{
              fontSize: 9,
              fontFamily: "'IBM Plex Mono', monospace",
              color: "#475569",
              letterSpacing: 1.5,
              textTransform: "uppercase",
            }}
          >
            Findings vs Resolved
          </span>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span
              className="inline-block h-1 w-3 rounded-full"
              style={{ backgroundColor: "#38bdf8" }}
            />
            <span
              style={{
                fontSize: 8,
                fontFamily: "'IBM Plex Mono', monospace",
                color: "#475569",
                textTransform: "uppercase",
              }}
            >
              Findings
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <span
              className="inline-block h-1 w-3 rounded-full"
              style={{ backgroundColor: "#22c55e" }}
            />
            <span
              style={{
                fontSize: 8,
                fontFamily: "'IBM Plex Mono', monospace",
                color: "#475569",
                textTransform: "uppercase",
              }}
            >
              Resolved
            </span>
          </div>
        </div>
      </div>
      <div className="h-[100px]">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={series} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
            <CartesianGrid
              stroke="rgba(56,189,248,0.05)"
              strokeDasharray="3 3"
              vertical={false}
            />
            <XAxis
              dataKey="date"
              tick={{ fontSize: 8, fill: "#334155", fontFamily: "'IBM Plex Mono', monospace" }}
              tickFormatter={(d: string) => d.slice(5)}
              interval="preserveStartEnd"
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fontSize: 8, fill: "#334155", fontFamily: "'IBM Plex Mono', monospace" }}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                background: "rgba(6,9,15,0.95)",
                border: "1px solid rgba(56,189,248,0.15)",
                borderRadius: 4,
                fontSize: 10,
                fontFamily: "'IBM Plex Mono', monospace",
                color: "#e2e8f0",
                boxShadow: "0 0 12px rgba(56,189,248,0.1)",
              }}
              labelStyle={{ color: "#38bdf8", fontFamily: "'IBM Plex Mono', monospace", fontSize: 9 }}
            />
            <Line
              type="monotone"
              dataKey="findings"
              stroke="#38bdf8"
              strokeWidth={2}
              dot={false}
              name="Findings"
              style={{ filter: "drop-shadow(0 0 4px rgba(56,189,248,0.4))" }}
            />
            <Line
              type="monotone"
              dataKey="resolved"
              stroke="#22c55e"
              strokeWidth={2}
              dot={false}
              name="Resolved"
              style={{ filter: "drop-shadow(0 0 4px rgba(34,197,94,0.4))" }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </GlowCard>
  );
});
