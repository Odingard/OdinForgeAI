import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { countBySeverity, severityColor } from "@/lib/dashboard-transforms";
import { GlowCard } from "@/components/ui/glow-card";

const SEVERITY_LABELS = ["critical", "high", "medium", "low"] as const;

export function FindingsSeverityBreakdown() {
  const { data: evaluations = [] } = useQuery<any[]>({
    queryKey: ["/api/aev/evaluations"],
  });

  const counts = useMemo(() => countBySeverity(evaluations), [evaluations]);
  const total = evaluations.length || 1;

  return (
    <GlowCard glowColor="cyan" glowIntensity="sm" glass scanLine className="p-4">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <span
            className="inline-block h-1.5 w-1.5 rounded-full bg-red-400"
            style={{ boxShadow: "0 0 4px #ef4444" }}
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
            Threat Classification
          </span>
        </div>
        <span
          style={{
            fontSize: 18,
            fontWeight: 800,
            color: "#f1f5f9",
            fontFamily: "'Inter', system-ui",
            textShadow: "0 0 10px rgba(241,245,249,0.15)",
          }}
        >
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
                <span
                  style={{
                    fontSize: 9,
                    fontFamily: "'IBM Plex Mono', monospace",
                    color: color,
                    letterSpacing: 1,
                    textTransform: "uppercase",
                    fontWeight: 600,
                  }}
                >
                  {sev}
                </span>
                <div className="flex items-center gap-2">
                  <span
                    style={{
                      fontSize: 11,
                      fontFamily: "'IBM Plex Mono', monospace",
                      color: "#e2e8f0",
                      fontWeight: 700,
                    }}
                  >
                    {count}
                  </span>
                  <span
                    style={{
                      fontSize: 9,
                      fontFamily: "'IBM Plex Mono', monospace",
                      color: "#475569",
                    }}
                  >
                    {pct}%
                  </span>
                </div>
              </div>
              <div
                className="rounded-full overflow-hidden"
                style={{ height: 6, background: "rgba(56,189,248,0.04)" }}
              >
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{
                    width: `${pct}%`,
                    backgroundColor: color,
                    boxShadow: `0 0 8px ${color}50, 0 0 16px ${color}20`,
                    animation: isCritical ? "pulse-glow 2s ease-in-out infinite" : undefined,
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </GlowCard>
  );
}
