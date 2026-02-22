import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { countBySeverity, severityColor } from "@/lib/dashboard-transforms";

const SEVERITY_LABELS = ["critical", "high", "medium", "low"] as const;

export function FindingsSeverityBreakdown() {
  const { data: evaluations = [] } = useQuery<any[]>({
    queryKey: ["/api/aev/evaluations"],
  });

  const counts = useMemo(() => countBySeverity(evaluations), [evaluations]);
  const total = evaluations.length || 1; // avoid /0

  return (
    <div className="glass border border-border/50 rounded-lg p-5">
      <div className="flex items-baseline justify-between mb-4">
        <div>
          <p className="text-2xl font-bold tabular-nums">{evaluations.length}</p>
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/70">
            Findings
          </p>
        </div>
      </div>
      <div className="space-y-3">
        {SEVERITY_LABELS.map((sev) => {
          const count = counts[sev];
          const pct = Math.round((count / total) * 100);
          const color = severityColor(sev);
          return (
            <div key={sev}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium capitalize">{sev}</span>
                <span className="text-xs tabular-nums text-muted-foreground">{count}</span>
              </div>
              <div className="h-1.5 rounded-full bg-muted/40 overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{
                    width: `${pct}%`,
                    backgroundColor: color,
                    boxShadow: `0 0 8px ${color}40`,
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
