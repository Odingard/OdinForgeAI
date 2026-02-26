import { memo } from "react";

interface Evaluation {
  status: string;
  exploitable?: boolean;
}

export const FindingsMetricCards = memo(function FindingsMetricCards({ evaluations = [] }: { evaluations: Evaluation[] }) {
  const total = evaluations.length;
  const active = evaluations.filter((e) => e.status === "in_progress").length;
  const exploitable = evaluations.filter((e) => e.exploitable === true).length;
  const isHot = exploitable > 0;

  return (
    <div className={`falcon-kpi ${isHot ? "hot" : ""}`}>
      <div className="flex items-center gap-[7px] text-[10px] font-medium tracking-wider uppercase" style={{ color: "var(--falcon-t3)" }}>
        <span className="w-[5px] h-[5px] rounded-full" style={{ background: isHot ? "var(--falcon-red)" : "var(--falcon-blue)" }} />
        Active Simulations
      </div>
      <div
        className="font-mono text-[32px] font-medium leading-none tracking-tight"
        style={{ color: "var(--falcon-blue)", letterSpacing: "-0.02em" }}
      >
        {active || total}
      </div>
      <div className="text-[10px] flex items-center gap-1.5" style={{ color: "var(--falcon-t3)" }}>
        {exploitable > 0 && (
          <span className="sev-chip sc-crit">{exploitable} exploitable</span>
        )}
        {exploitable === 0 && <span>{total} total evaluations</span>}
      </div>
    </div>
  );
});
