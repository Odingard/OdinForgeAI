import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { buildOrgMetrics } from "@/lib/dashboard-transforms";

export function OrganizationMetricsTable() {
  const { data: assets = [] } = useQuery<any[]>({
    queryKey: ["/api/assets"],
  });
  const { data: evaluations = [] } = useQuery<any[]>({
    queryKey: ["/api/aev/evaluations"],
  });

  const rows = useMemo(
    () => buildOrgMetrics(assets, evaluations),
    [assets, evaluations],
  );

  return (
    <div className="glass border border-border/50 rounded-lg p-5">
      <h3 className="text-xs uppercase tracking-wider text-muted-foreground/80 font-medium mb-3">
        Organization Metrics
      </h3>
      {rows.length === 0 ? (
        <p className="text-xs text-muted-foreground/50 text-center py-4">No data</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-muted-foreground/60 uppercase tracking-wider text-[10px]">
                <th className="text-left py-1.5 font-medium">Type</th>
                <th className="text-right py-1.5 font-medium">Assets</th>
                <th className="text-right py-1.5 font-medium">Critical</th>
                <th className="text-right py-1.5 font-medium">Open</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.type}
                  className="border-t border-border/20 hover:bg-muted/10 transition-colors"
                >
                  <td className="py-2 font-medium">{row.name}</td>
                  <td className="py-2 text-right tabular-nums">{row.total}</td>
                  <td className="py-2 text-right tabular-nums">
                    {row.critical > 0 ? (
                      <span className="text-red-400">{row.critical}</span>
                    ) : (
                      <span className="text-muted-foreground/40">0</span>
                    )}
                  </td>
                  <td className="py-2 text-right tabular-nums">
                    {row.open > 0 ? (
                      <span className="text-amber-400">{row.open}</span>
                    ) : (
                      <span className="text-muted-foreground/40">0</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
