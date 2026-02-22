import { useQuery } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Zap } from "lucide-react";
import { queryClient } from "@/lib/queryClient";
import { Evaluation } from "../EvaluationTable";

export function DashboardTopBar() {
  const [, navigate] = useLocation();

  const { data: evaluations = [] } = useQuery<Evaluation[]>({
    queryKey: ["/api/aev/evaluations"],
  });
  const { data: assets = [] } = useQuery<any[]>({
    queryKey: ["/api/assets"],
  });

  const active = evaluations.filter((e) => e.status === "pending" || e.status === "in_progress").length;
  const exploitable = evaluations.filter((e) => e.exploitable === true).length;

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
    queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
    queryClient.invalidateQueries({ queryKey: ["/api/defensive-posture/default"] });
  };

  return (
    <div
      style={{
        background: "rgba(6,9,15,0.95)",
        backdropFilter: "blur(12px)",
        borderBottom: "1px solid rgba(56,189,248,0.08)",
        fontFamily: "'Sora', 'DM Sans', sans-serif",
      }}
      className="rounded-t-lg px-5 py-3"
    >
      <div className="flex items-center justify-between">
        {/* Left: Branding + Status */}
        <div className="flex items-center gap-3">
          <span style={{ fontWeight: 800, fontSize: 18, letterSpacing: -0.5, color: "#f1f5f9" }}>
            ODIN<span style={{ color: "#38bdf8" }}>FORGE</span>
          </span>
          <span
            style={{
              fontSize: 9,
              fontFamily: "'IBM Plex Mono', monospace",
              color: "#38bdf8",
              background: "rgba(56,189,248,0.08)",
              padding: "3px 10px",
              borderRadius: 100,
              border: "1px solid rgba(56,189,248,0.15)",
              letterSpacing: 1.5,
              textTransform: "uppercase",
              fontWeight: 600,
            }}
          >
            Threat Operations
          </span>
          <div className="flex items-center gap-1.5 ml-2">
            <span
              className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-400"
              style={{
                boxShadow: "0 0 6px #22c55e, 0 0 12px rgba(34,197,94,0.4)",
                animation: "pulse-glow 2s ease-in-out infinite",
              }}
            />
            <span
              style={{
                fontSize: 9,
                fontFamily: "'IBM Plex Mono', monospace",
                color: "#22c55e",
                letterSpacing: 1,
                textTransform: "uppercase",
              }}
            >
              Systems Nominal
            </span>
          </div>
        </div>

        {/* Right: Metrics + Actions */}
        <div className="flex items-center gap-4">
          <MetricBox label="Threats Active" value={active} color={active > 0 ? "#f59e0b" : "#38bdf8"} />
          <Divider />
          <MetricBox label="Exploitable" value={exploitable} color={exploitable > 0 ? "#ef4444" : "#22c55e"} />
          <Divider />
          <MetricBox label="Assets" value={assets.length} color="#38bdf8" />
          <Divider />
          <button
            onClick={handleRefresh}
            style={{
              fontSize: 9,
              fontFamily: "'IBM Plex Mono', monospace",
              color: "#64748b",
              background: "rgba(56,189,248,0.05)",
              border: "1px solid rgba(56,189,248,0.1)",
              borderRadius: 4,
              padding: "5px 12px",
              cursor: "pointer",
              letterSpacing: 1,
              textTransform: "uppercase",
              transition: "all 0.2s",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.color = "#38bdf8";
              e.currentTarget.style.borderColor = "rgba(56,189,248,0.3)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.color = "#64748b";
              e.currentTarget.style.borderColor = "rgba(56,189,248,0.1)";
            }}
          >
            Refresh
          </button>
          <button
            onClick={() => navigate("/assess")}
            style={{
              fontSize: 9,
              fontFamily: "'IBM Plex Mono', monospace",
              color: "#f1f5f9",
              background: "linear-gradient(135deg, rgba(6,182,212,0.3), rgba(59,130,246,0.3))",
              border: "1px solid rgba(56,189,248,0.25)",
              borderRadius: 4,
              padding: "5px 14px",
              cursor: "pointer",
              letterSpacing: 1,
              textTransform: "uppercase",
              display: "flex",
              alignItems: "center",
              gap: 5,
              boxShadow: "0 0 12px rgba(56,189,248,0.15)",
              transition: "all 0.2s",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.boxShadow = "0 0 20px rgba(56,189,248,0.3)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.boxShadow = "0 0 12px rgba(56,189,248,0.15)";
            }}
          >
            <Zap size={10} />
            New Assessment
          </button>
        </div>
      </div>
    </div>
  );
}

function MetricBox({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{ textAlign: "right" }}>
      <div
        style={{
          fontSize: 8,
          color: "#475569",
          fontFamily: "'IBM Plex Mono', monospace",
          textTransform: "uppercase",
          letterSpacing: 1.5,
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: 20,
          fontWeight: 800,
          color,
          letterSpacing: -1,
          fontFamily: "'Inter', system-ui",
          textShadow: `0 0 10px ${color}40`,
        }}
      >
        {value}
      </div>
    </div>
  );
}

function Divider() {
  return <div style={{ width: 1, height: 28, background: "rgba(56,189,248,0.08)" }} />;
}
