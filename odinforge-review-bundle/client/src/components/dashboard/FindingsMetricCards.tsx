import { memo } from "react";

interface Evaluation {
  status: string;
  exploitable?: boolean;
}

export const FindingsMetricCards = memo(function FindingsMetricCards({ evaluations = [] }: { evaluations: Evaluation[] }) {
  const total = evaluations.length;
  const active = evaluations.filter((e) => e.status === "in_progress").length;
  const exploitable = evaluations.filter((e) => e.exploitable === true).length;

  return (
    <div className="f-kpi">
      <div className="f-kpi-lbl">
        <span className="f-kpi-dot b" />
        Active Assessments
      </div>
      <div className="f-kpi-val b">
        {active || total}
      </div>
      <div className="f-kpi-foot">
        {exploitable > 0 ? (
          <span className="f-kpi-tag r">{exploitable} exploitable</span>
        ) : (
          <span>{total} total evaluations</span>
        )}
      </div>
    </div>
  );
});
