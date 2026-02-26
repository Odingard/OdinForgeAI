import { useMemo, memo } from "react";
import { countBySeverity, severityColor } from "@/lib/dashboard-transforms";

const SEVERITY_LABELS = ["critical", "high", "medium", "low"] as const;

export const FindingsSeverityBreakdown = memo(function FindingsSeverityBreakdown({ evaluations = [] }: { evaluations: any[] }) {
  const counts = useMemo(() => countBySeverity(evaluations), [evaluations]);
  const total = evaluations.length || 1;

  return (
    <div className="rounded-lg border border-border bg-card/50 backdrop-blur-sm p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="inline-block h-2 w-2 rounded-full bg-red-400" style={{ boxShadow: "0 0 6px #ef4444" }} />
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Threat Classification
          </span>
        </div>
        <span className="text-lg font-bold text-foreground tabular-nums">
          {evaluations.length}
        </span>
      </div>
      <div className="space-y-3">
        {SEVERITY_LABELS.map((sev) => {
          const count = counts[sev];
          const pct = Math.round((count / total) * 100);
          const color = severityColor(sev);
          const isCritical = sev === "critical" && count > 0;
          return (
            <div key={sev}>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-semibold uppercase tracking-wider" style={{ color }}>
                  {sev}
                </span>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-bold text-foreground tabular-nums">
                    {count}
                  </span>
                  <span className="text-xs text-muted-foreground tabular-nums">
                    {pct}%
                  </span>
                </div>
              </div>
              <div className="rounded-full overflow-hidden h-1.5 bg-primary/5">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{
                    width: `${pct}%`,
                    backgroundColor: color,
                    boxShadow: `0 0 8px ${color}50`,
                    animation: isCritical ? "pulse-glow 2s ease-in-out infinite" : undefined,
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
});
