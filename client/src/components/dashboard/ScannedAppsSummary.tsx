import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { groupAssetsByType } from "@/lib/dashboard-transforms";
import { GlowCard } from "@/components/ui/glow-card";

const TYPE_COLORS: Record<string, string> = {
  web_application: "#38bdf8",
  api: "#22c55e",
  cloud: "#a78bfa",
  network: "#f59e0b",
};

export function ScannedAppsSummary() {
  const { data: assets = [] } = useQuery<any[]>({
    queryKey: ["/api/assets"],
  });

  const groups = useMemo(() => groupAssetsByType(assets), [assets]);
  const total = assets.length;
  const entries = Object.entries(groups)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4);

  return (
    <GlowCard glowColor="cyan" glowIntensity="sm" glass scanLine className="p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
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
            Asset Inventory
          </span>
        </div>
        <span
          style={{
            fontSize: 22,
            fontWeight: 800,
            color: "#f1f5f9",
            fontFamily: "'Inter', system-ui",
            textShadow: "0 0 10px rgba(241,245,249,0.15)",
          }}
        >
          {total}
        </span>
      </div>
      <div className="space-y-2">
        {entries.map(([type, count]) => {
          const accentColor = TYPE_COLORS[type] || "#64748b";
          const label = type
            .replace(/_/g, " ")
            .replace(/\b\w/g, (c) => c.toUpperCase());
          return (
            <div
              key={type}
              className="flex items-center justify-between py-2 px-3 rounded"
              style={{
                background: "rgba(6,9,15,0.5)",
                borderLeft: `2px solid ${accentColor}40`,
              }}
            >
              <span
                style={{
                  fontSize: 10,
                  fontFamily: "'IBM Plex Mono', monospace",
                  color: "#94a3b8",
                  fontWeight: 500,
                }}
              >
                {label}
              </span>
              <span
                style={{
                  fontSize: 14,
                  fontWeight: 700,
                  color: accentColor,
                  fontFamily: "'IBM Plex Mono', monospace",
                  textShadow: `0 0 6px ${accentColor}30`,
                }}
              >
                {count}
              </span>
            </div>
          );
        })}
        {entries.length === 0 && (
          <p
            style={{
              fontSize: 10,
              fontFamily: "'IBM Plex Mono', monospace",
              color: "#334155",
              textAlign: "center",
              padding: "12px 0",
            }}
          >
            NO ASSETS REGISTERED
          </p>
        )}
      </div>
    </GlowCard>
  );
}
