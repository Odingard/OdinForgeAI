import { useQuery } from "@tanstack/react-query";
import { computeRiskScore, riskScoreColor, riskScoreLabel } from "@/lib/dashboard-transforms";

export function RiskScoreGauge() {
  const { data: posture } = useQuery<any>({
    queryKey: ["/api/defensive-posture/default"],
  });

  const score = computeRiskScore(posture);
  const color = riskScoreColor(score);
  const label = riskScoreLabel(score);

  // SVG arc gauge
  const radius = 52;
  const stroke = 8;
  const circumference = Math.PI * radius; // half circle
  const progress = (score / 100) * circumference;

  return (
    <div className="glass border border-border/50 rounded-lg p-5">
      <h3 className="text-xs uppercase tracking-wider text-muted-foreground/80 font-medium mb-4">
        Risk Score
      </h3>
      <div className="flex flex-col items-center">
        <svg width="130" height="75" viewBox="0 0 130 75">
          {/* Background arc */}
          <path
            d="M 13 70 A 52 52 0 0 1 117 70"
            fill="none"
            stroke="hsl(220 15% 14%)"
            strokeWidth={stroke}
            strokeLinecap="round"
          />
          {/* Progress arc */}
          <path
            d="M 13 70 A 52 52 0 0 1 117 70"
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${progress} ${circumference}`}
            style={{
              filter: `drop-shadow(0 0 6px ${color}40)`,
              transition: "stroke-dasharray 0.8s ease-out",
            }}
          />
          {/* Score text */}
          <text
            x="65"
            y="58"
            textAnchor="middle"
            fill={color}
            fontSize="28"
            fontWeight="800"
            fontFamily="Inter, system-ui"
          >
            {score}
          </text>
          <text
            x="65"
            y="72"
            textAnchor="middle"
            fill="hsl(215 10% 60%)"
            fontSize="10"
            fontFamily="'IBM Plex Mono', monospace"
            style={{ textTransform: "uppercase" }}
          >
            {label}
          </text>
        </svg>
      </div>
      {/* Severity mini bar */}
      <div className="flex gap-0.5 mt-3 rounded-full overflow-hidden h-1.5">
        <div className="bg-red-500 flex-[2]" />
        <div className="bg-orange-500 flex-[3]" />
        <div className="bg-yellow-500 flex-[3]" />
        <div className="bg-green-500 flex-[2]" />
      </div>
    </div>
  );
}
