import { useMemo, memo } from "react";
import { countBySeverity } from "@/lib/dashboard-transforms";

export const FindingsSeverityBreakdown = memo(function FindingsSeverityBreakdown({ evaluations = [] }: { evaluations: any[] }) {
  const counts = useMemo(() => countBySeverity(evaluations), [evaluations]);
  const critCount = counts.critical;

  return (
    <div className={`falcon-kpi ${critCount > 0 ? "hot" : ""}`}>
      <div className="flex items-center gap-[7px] text-[10px] font-medium tracking-wider uppercase" style={{ color: "var(--falcon-t3)" }}>
        <span className="w-[5px] h-[5px] rounded-full" style={{ background: critCount > 0 ? "var(--falcon-red)" : "var(--falcon-t4)" }} />
        Critical Findings
      </div>
      <div
        className="font-mono text-[32px] font-medium leading-none tracking-tight"
        style={{ color: critCount > 0 ? "var(--falcon-red)" : "var(--falcon-t1)", letterSpacing: "-0.02em" }}
      >
        {critCount}
      </div>
      <div className="flex items-center gap-1.5 text-[10px]" style={{ color: "var(--falcon-t3)" }}>
        {critCount > 0 ? (
          <span className="sev-chip sc-crit">Immediate action</span>
        ) : (
          <span>No critical findings</span>
        )}
      </div>
    </div>
  );
});
