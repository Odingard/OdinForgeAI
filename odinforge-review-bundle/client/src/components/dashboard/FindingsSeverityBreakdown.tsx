import { useMemo, memo } from "react";
import { countBySeverity } from "@/lib/dashboard-transforms";

export const FindingsSeverityBreakdown = memo(function FindingsSeverityBreakdown({ evaluations = [] }: { evaluations: any[] }) {
  const counts = useMemo(() => countBySeverity(evaluations), [evaluations]);
  const critCount = counts.critical;
  const isHot = critCount > 0;

  return (
    <div className={`f-kpi ${isHot ? "hot" : ""}`}>
      <div className="f-kpi-lbl">
        <span className={`f-kpi-dot ${isHot ? "r" : ""}`} />
        Critical Findings
      </div>
      <div className={`f-kpi-val ${isHot ? "r" : ""}`}>
        {critCount}
      </div>
      <div className="f-kpi-foot">
        {isHot ? (
          <span className="f-kpi-tag r">Immediate action</span>
        ) : (
          <span>No critical findings</span>
        )}
      </div>
    </div>
  );
});
