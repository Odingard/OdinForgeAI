import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
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

export function FindingsVsResolvedChart() {
  const { data: evaluations = [] } = useQuery<any[]>({
    queryKey: ["/api/aev/evaluations"],
  });

  const series = useMemo(() => buildTimeseries(evaluations, 30), [evaluations]);

  return (
    <div className="glass border border-border/50 rounded-lg p-5">
      <h3 className="text-xs uppercase tracking-wider text-muted-foreground/80 font-medium mb-4">
        Findings vs Resolved
      </h3>
      <div className="h-[140px]">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={series} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
            <CartesianGrid
              stroke="hsl(220 15% 14%)"
              strokeDasharray="3 3"
              vertical={false}
            />
            <XAxis
              dataKey="date"
              tick={{ fontSize: 9, fill: "hsl(215 10% 45%)" }}
              tickFormatter={(d: string) => d.slice(5)} // MM-DD
              interval="preserveStartEnd"
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fontSize: 9, fill: "hsl(215 10% 45%)" }}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                background: "hsl(220 25% 7%)",
                border: "1px solid hsl(220 15% 14%)",
                borderRadius: 6,
                fontSize: 11,
              }}
              labelStyle={{ color: "hsl(210 20% 95%)" }}
            />
            <Line
              type="monotone"
              dataKey="findings"
              stroke="#06b6d4"
              strokeWidth={2}
              dot={false}
              name="Findings"
            />
            <Line
              type="monotone"
              dataKey="resolved"
              stroke="#22c55e"
              strokeWidth={2}
              dot={false}
              name="Resolved"
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
