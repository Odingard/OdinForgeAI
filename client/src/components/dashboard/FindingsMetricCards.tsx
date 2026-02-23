import { memo } from "react";
import { GlowCard } from "@/components/ui/glow-card";

interface Evaluation {
  status: string;
  exploitable?: boolean;
}

export const FindingsMetricCards = memo(function FindingsMetricCards({ evaluations = [] }: { evaluations: Evaluation[] }) {

  const total = evaluations.length;
  const resolved = evaluations.filter((e) => e.status === "completed").length;
  const exploitable = evaluations.filter((e) => e.exploitable === true).length;

  return (
    <GlowCard glowColor="cyan" glowIntensity="sm" glass scanLine className="p-2">
      <div className="flex items-center gap-2 mb-2">
        <span
          className="inline-block h-1.5 w-1.5 rounded-full bg-cyan-400"
          style={{ boxShadow: "0 0 4px #38bdf8" }}
        />
        <span
          style={{
            fontSize: 9,
            fontFamily: "'IBM Plex Mono', monospace",
            color: "#475569",
            letterSpacing: 1.5,
            textTransform: "uppercase",
          }}
        >
          Evaluation Metrics
        </span>
      </div>
      <div className="space-y-1.5">
        <MetricRow label="Total Findings" value={total} color="#38bdf8" borderColor="rgba(56,189,248,0.4)" />
        <MetricRow label="Resolved" value={resolved} color="#22c55e" borderColor="rgba(34,197,94,0.4)" />
        <MetricRow label="Exploitable" value={exploitable} color="#ef4444" borderColor="rgba(239,68,68,0.4)" />
      </div>
    </GlowCard>
  );
});

function MetricRow({
  label,
  value,
  color,
  borderColor,
}: {
  label: string;
  value: number;
  color: string;
  borderColor: string;
}) {
  return (
    <div
      className="flex items-center justify-between py-1.5 px-2 rounded"
      style={{
        background: "rgba(6,9,15,0.5)",
        borderLeft: `2px solid ${borderColor}`,
      }}
    >
      <span
        style={{
          fontSize: 9,
          fontFamily: "'IBM Plex Mono', monospace",
          color: "#64748b",
          letterSpacing: 1,
          textTransform: "uppercase",
        }}
      >
        {label}
      </span>
      <span
        style={{
          fontSize: 14,
          fontWeight: 800,
          color,
          fontFamily: "'Inter', system-ui",
          textShadow: `0 0 10px ${color}40`,
        }}
      >
        {value}
      </span>
    </div>
  );
}
