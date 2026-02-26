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

export const FindingsVsResolvedChart = memo(function FindingsVsResolvedChart({ evaluations = [] }: { evaluations: any[] }) {
  const series = useMemo(() => buildTimeseries(evaluations, 30), [evaluations]);

  return (
    <div className="rounded-lg border border-border bg-card/50 backdrop-blur-sm p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="inline-block h-2 w-2 rounded-full bg-cyan-400 animate-pulse" style={{ boxShadow: "0 0 6px #38bdf8" }} />
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Findings vs Resolved
          </span>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="inline-block h-0.5 w-3 rounded-full bg-cyan-400" />
            <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Findings</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="inline-block h-0.5 w-3 rounded-full bg-emerald-400" />
            <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">Resolved</span>
          </div>
        </div>
      </div>
      <div className="h-[120px]">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={series} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
            <CartesianGrid stroke="rgba(56,189,248,0.05)" strokeDasharray="3 3" vertical={false} />
            <XAxis
              dataKey="date"
              tick={{ fontSize: 9, fill: "hsl(215 10% 40%)" }}
              tickFormatter={(d: string) => d.slice(5)}
              interval="preserveStartEnd"
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fontSize: 9, fill: "hsl(215 10% 40%)" }}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                background: "hsl(220 30% 6%)",
                border: "1px solid hsl(220 15% 14%)",
                borderRadius: 6,
                fontSize: 11,
                color: "hsl(210 20% 95%)",
                boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
              }}
              labelStyle={{ color: "hsl(189 94% 43%)", fontSize: 10 }}
            />
            <Line type="monotone" dataKey="findings" stroke="#38bdf8" strokeWidth={2} dot={false} name="Findings" style={{ filter: "drop-shadow(0 0 4px rgba(56,189,248,0.4))" }} />
            <Line type="monotone" dataKey="resolved" stroke="#22c55e" strokeWidth={2} dot={false} name="Resolved" style={{ filter: "drop-shadow(0 0 4px rgba(34,197,94,0.4))" }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
});
