import { useMemo, memo } from "react";
import { computeRiskScore, riskScoreLabel } from "@/lib/dashboard-transforms";

export const RiskScoreGauge = memo(function RiskScoreGauge({ posture }: { posture: any }) {
  const score = computeRiskScore(posture);
  const label = riskScoreLabel(score);
  const isHot = score >= 70;
  const displayScore = (score / 10).toFixed(1);

  return (
    <div className={`falcon-kpi ${isHot ? "hot" : ""}`}>
      <div className="flex items-center gap-[7px] text-[10px] font-medium tracking-wider uppercase" style={{ color: "var(--falcon-t3)" }}>
        <span className="w-[5px] h-[5px] rounded-full" style={{ background: isHot ? "var(--falcon-red)" : "var(--falcon-t4)" }} />
        Risk Score
      </div>
      <div
        className="font-mono text-[32px] font-medium leading-none tracking-tight"
        style={{ color: isHot ? "var(--falcon-red)" : "var(--falcon-t1)", letterSpacing: "-0.02em" }}
      >
        {displayScore}
      </div>
      <div className="text-[10px]" style={{ color: "var(--falcon-t3)" }}>
        {isHot ? (
          <span className="sev-chip sc-crit">{label.toUpperCase()}</span>
        ) : (
          <span>{label}</span>
        )}
      </div>
    </div>
  );
});
