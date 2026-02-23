import { memo, useMemo } from "react";
import { GlowCard } from "@/components/ui/glow-card";

interface Evaluation {
  id: string;
  assetId?: string;
  exposureType?: string;
  priority?: string;
  severity?: string;
  status: string;
  exploitable?: boolean;
  createdAt?: string;
  description?: string;
}

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

const STATUS_COLORS: Record<string, string> = {
  completed: "#22c55e",
  in_progress: "#38bdf8",
  pending: "#f59e0b",
  failed: "#ef4444",
};

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

export const RecentEvaluations = memo(function RecentEvaluations({
  evaluations = [],
}: {
  evaluations: Evaluation[];
}) {
  const recent = useMemo(
    () =>
      [...evaluations]
        .sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime())
        .slice(0, 8),
    [evaluations],
  );

  return (
    <GlowCard glowColor="cyan" glowIntensity="sm" glass scanLine className="p-3">
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
            Recent Evaluations
          </span>
        </div>
        <span
          style={{
            fontSize: 9,
            fontFamily: "'IBM Plex Mono', monospace",
            color: "#334155",
          }}
        >
          {evaluations.length} total
        </span>
      </div>

      {recent.length === 0 ? (
        <div
          className="flex flex-col items-center justify-center py-8"
          style={{ minHeight: 120 }}
        >
          <span
            style={{
              fontSize: 12,
              color: "rgba(148, 163, 184, 0.4)",
              fontFamily: "'Inter', system-ui",
            }}
          >
            No evaluations yet
          </span>
          <span
            style={{
              fontSize: 10,
              color: "rgba(148, 163, 184, 0.25)",
              fontFamily: "'IBM Plex Mono', monospace",
              marginTop: 4,
            }}
          >
            Run an assessment to see results here
          </span>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full" style={{ fontFamily: "'IBM Plex Mono', monospace" }}>
            <thead>
              <tr>
                {["Type", "Severity", "Status", "Exploitable", "When"].map((h) => (
                  <th
                    key={h}
                    style={{
                      fontSize: 8,
                      color: "#38bdf8",
                      letterSpacing: 1.5,
                      textTransform: "uppercase",
                      fontWeight: 600,
                      textAlign: h === "Type" ? "left" : "center",
                      paddingBottom: 8,
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {recent.map((e) => {
                const sev = (e.priority || e.severity || "medium").toLowerCase();
                const sevColor = SEV_COLORS[sev] || "#64748b";
                const statusColor = STATUS_COLORS[e.status] || "#64748b";
                return (
                  <tr
                    key={e.id}
                    style={{ borderTop: "1px solid rgba(56,189,248,0.04)" }}
                  >
                    <td
                      style={{
                        fontSize: 10,
                        color: "#94a3b8",
                        padding: "6px 0",
                        fontWeight: 500,
                        maxWidth: 200,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {(e.exposureType || "assessment")
                        .replace(/_/g, " ")
                        .replace(/\b\w/g, (c) => c.toUpperCase())}
                    </td>
                    <td style={{ textAlign: "center", padding: "6px 0" }}>
                      <span
                        style={{
                          fontSize: 8,
                          fontWeight: 700,
                          color: sevColor,
                          letterSpacing: 1,
                          textTransform: "uppercase",
                          background: `${sevColor}12`,
                          padding: "2px 8px",
                          borderRadius: 100,
                          border: `1px solid ${sevColor}25`,
                        }}
                      >
                        {sev}
                      </span>
                    </td>
                    <td style={{ textAlign: "center", padding: "6px 0" }}>
                      <span
                        style={{
                          fontSize: 8,
                          fontWeight: 600,
                          color: statusColor,
                          letterSpacing: 1,
                          textTransform: "uppercase",
                        }}
                      >
                        {e.status.replace(/_/g, " ")}
                      </span>
                    </td>
                    <td style={{ textAlign: "center", padding: "6px 0" }}>
                      {e.status === "completed" ? (
                        <span
                          style={{
                            fontSize: 9,
                            fontWeight: 700,
                            color: e.exploitable ? "#ef4444" : "#22c55e",
                            textShadow: e.exploitable
                              ? "0 0 6px rgba(239,68,68,0.3)"
                              : "0 0 6px rgba(34,197,94,0.3)",
                          }}
                        >
                          {e.exploitable ? "YES" : "NO"}
                        </span>
                      ) : (
                        <span style={{ fontSize: 9, color: "#334155" }}>—</span>
                      )}
                    </td>
                    <td
                      style={{
                        fontSize: 9,
                        color: "#475569",
                        textAlign: "center",
                        padding: "6px 0",
                      }}
                    >
                      {e.createdAt ? timeAgo(e.createdAt) : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </GlowCard>
  );
});
