import { useMemo, memo } from "react";

export const RiskScoreGauge = memo(function RiskScoreGauge({ posture }: { posture: any }) {
  const score = useMemo(() => {
    const raw = posture?.overallScore ?? posture?.score ?? 0;
    return Math.min(10, Math.max(0, raw / 10));
  }, [posture]);

  const isHot = score >= 7;

  return (
    <div className={`f-kpi ${isHot ? "hot" : ""}`}>
      <div className="f-kpi-lbl">
        <span className={`f-kpi-dot ${isHot ? "r" : "b"}`} />
        Threat Level
      </div>
      <div className={`f-kpi-val ${isHot ? "r" : "b"}`}>
        {score.toFixed(1)}
      </div>
      <div className="f-kpi-foot">
        <span className={`f-kpi-tag ${isHot ? "r" : "g"}`}>
          {isHot ? "Critical" : "Normal"}
        </span>
      </div>
    </div>
  );
});
