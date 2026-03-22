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
    <div className="falcon-panel">
      <div className="falcon-panel-head flex items-center justify-between">
        <span className="font-mono text-[9px] font-normal tracking-[0.18em] uppercase" style={{ color: "var(--falcon-t3)" }}>
          Findings vs Resolved
        </span>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-[6px]">
            <span className="inline-block h-[2px] w-3 rounded-full" style={{ background: "var(--falcon-red)" }} />
            <span className="font-mono text-[9px] tracking-[0.08em] uppercase" style={{ color: "var(--falcon-t3)" }}>Findings</span>
          </div>
          <div className="flex items-center gap-[6px]">
            <span className="inline-block h-[2px] w-3 rounded-full" style={{ background: "var(--falcon-green)" }} />
            <span className="font-mono text-[9px] tracking-[0.08em] uppercase" style={{ color: "var(--falcon-t3)" }}>Resolved</span>
          </div>
        </div>
      </div>

      <div className="p-3" style={{ height: 130 }}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={series} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
            <CartesianGrid stroke="rgba(30,45,69,0.5)" strokeDasharray="3 3" vertical={false} />
            <XAxis
              dataKey="date"
              tick={{ fontSize: 9, fill: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}
              tickFormatter={(d: string) => d.slice(5)}
              interval="preserveStartEnd"
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fontSize: 9, fill: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                background: "var(--falcon-panel)",
                border: "1px solid var(--falcon-border)",
                borderRadius: 4,
                fontSize: 10,
                fontFamily: "var(--font-mono)",
                color: "var(--falcon-t1)",
                boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
              }}
              labelStyle={{ color: "var(--falcon-t3)", fontSize: 9 }}
            />
            <Line
              type="monotone"
              dataKey="findings"
              stroke="var(--falcon-red)"
              strokeWidth={1.5}
              dot={false}
              name="Findings"
            />
            <Line
              type="monotone"
              dataKey="resolved"
              stroke="var(--falcon-green)"
              strokeWidth={1.5}
              dot={false}
              name="Resolved"
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
});
