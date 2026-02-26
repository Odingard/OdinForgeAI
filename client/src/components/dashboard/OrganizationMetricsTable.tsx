import { useMemo, memo } from "react";
import { buildOrgMetrics } from "@/lib/dashboard-transforms";

export const OrganizationMetricsTable = memo(function OrganizationMetricsTable({ assets = [], evaluations = [] }: { assets: any[]; evaluations: any[] }) {
  const rows = useMemo(() => buildOrgMetrics(assets, evaluations), [assets, evaluations]);

  return (
    <div className="rounded-lg border border-border bg-card/50 backdrop-blur-sm p-4">
      <div className="flex items-center gap-2 mb-3">
        <span className="inline-block h-2 w-2 rounded-full bg-cyan-400" style={{ boxShadow: "0 0 6px #38bdf8" }} />
        <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
          Org Metrics
        </span>
      </div>
      {rows.length === 0 ? (
        <p className="text-xs text-muted-foreground/40 text-center py-4 uppercase tracking-wider">
          No data
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/30">
                {["Type", "Assets", "Crit", "Open"].map((h) => (
                  <th
                    key={h}
                    className={`text-[10px] font-semibold uppercase tracking-wider text-primary pb-2.5 ${h === "Type" ? "text-left" : "text-right"}`}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.type} className="border-t border-border/10">
                  <td className="text-xs text-muted-foreground py-2 font-medium">{row.name}</td>
                  <td className="text-xs text-muted-foreground text-right py-2 tabular-nums">{row.total}</td>
                  <td className={`text-xs text-right py-2 font-bold tabular-nums ${row.critical > 0 ? "text-red-400" : "text-muted-foreground/20"}`}>
                    {row.critical}
                  </td>
                  <td className={`text-xs text-right py-2 font-bold tabular-nums ${row.open > 0 ? "text-amber-400" : "text-muted-foreground/20"}`}>
                    {row.open}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
});
