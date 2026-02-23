import { useMemo, memo } from "react";
import { buildOrgMetrics } from "@/lib/dashboard-transforms";
import { GlowCard } from "@/components/ui/glow-card";

export const OrganizationMetricsTable = memo(function OrganizationMetricsTable({ assets = [], evaluations = [] }: { assets: any[]; evaluations: any[] }) {

  const rows = useMemo(
    () => buildOrgMetrics(assets, evaluations),
    [assets, evaluations],
  );

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
          Org Metrics
        </span>
      </div>
      {rows.length === 0 ? (
        <p
          style={{
            fontSize: 10,
            fontFamily: "'IBM Plex Mono', monospace",
            color: "#334155",
            textAlign: "center",
            padding: "12px 0",
          }}
        >
          NO DATA
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full" style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
            <thead>
              <tr>
                {["Type", "Assets", "Crit", "Open"].map((h) => (
                  <th
                    key={h}
                    style={{
                      fontSize: 8,
                      color: "#38bdf8",
                      letterSpacing: 1.5,
                      textTransform: "uppercase",
                      fontWeight: 600,
                      textAlign: h === "Type" ? "left" : "right",
                      paddingBottom: 6,
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.type}
                  style={{ borderTop: "1px solid rgba(56,189,248,0.04)" }}
                >
                  <td
                    style={{
                      fontSize: 10,
                      color: "#94a3b8",
                      padding: "5px 0",
                      fontWeight: 500,
                    }}
                  >
                    {row.name}
                  </td>
                  <td
                    style={{
                      fontSize: 10,
                      color: "#64748b",
                      textAlign: "right",
                      padding: "5px 0",
                    }}
                  >
                    {row.total}
                  </td>
                  <td
                    style={{
                      fontSize: 10,
                      color: row.critical > 0 ? "#ef4444" : "#1e293b",
                      textAlign: "right",
                      padding: "5px 0",
                      fontWeight: row.critical > 0 ? 700 : 400,
                      textShadow: row.critical > 0 ? "0 0 6px rgba(239,68,68,0.3)" : undefined,
                    }}
                  >
                    {row.critical}
                  </td>
                  <td
                    style={{
                      fontSize: 10,
                      color: row.open > 0 ? "#f59e0b" : "#1e293b",
                      textAlign: "right",
                      padding: "5px 0",
                      fontWeight: row.open > 0 ? 700 : 400,
                      textShadow: row.open > 0 ? "0 0 6px rgba(245,158,11,0.3)" : undefined,
                    }}
                  >
                    {row.open}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </GlowCard>
  );
});
