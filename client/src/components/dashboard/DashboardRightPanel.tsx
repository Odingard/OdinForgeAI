import { FindingsSeverityBreakdown } from "./FindingsSeverityBreakdown";
import { ReachabilityExploitabilityMatrix } from "./ReachabilityExploitabilityMatrix";
import { useLocation } from "wouter";

export function DashboardRightPanel() {
  const [, navigate] = useLocation();

  return (
    <div
      className="space-y-3 overflow-y-auto max-h-[calc(100vh-140px)] pl-1"
      style={{
        borderRight: "1px solid rgba(56,189,248,0.06)",
        paddingRight: 4,
        scrollbarWidth: "none",
      }}
    >
      <div
        className="flex items-center gap-2 px-2 py-1.5"
        style={{ borderBottom: "1px solid rgba(56,189,248,0.04)" }}
      >
        <span
          className="inline-block h-1 w-1 rounded-full bg-red-400"
          style={{ boxShadow: "0 0 3px #ef4444" }}
        />
        <span
          style={{
            fontSize: 8,
            fontFamily: "'IBM Plex Mono', monospace",
            color: "#334155",
            letterSpacing: 1.5,
            textTransform: "uppercase",
          }}
        >
          Threat Analysis
        </span>
      </div>
      <FindingsSeverityBreakdown />
      <ReachabilityExploitabilityMatrix />
      <button
        onClick={() => navigate("/evaluations")}
        style={{
          width: "100%",
          textAlign: "center",
          fontSize: 9,
          fontFamily: "'IBM Plex Mono', monospace",
          color: "#38bdf8",
          background: "rgba(56,189,248,0.04)",
          border: "1px solid rgba(56,189,248,0.1)",
          borderRadius: 4,
          padding: "10px 0",
          cursor: "pointer",
          letterSpacing: 1.5,
          textTransform: "uppercase",
          fontWeight: 600,
          transition: "all 0.2s",
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.borderColor = "rgba(56,189,248,0.3)";
          e.currentTarget.style.boxShadow = "0 0 12px rgba(56,189,248,0.1)";
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.borderColor = "rgba(56,189,248,0.1)";
          e.currentTarget.style.boxShadow = "none";
        }}
      >
        View All Evaluations →
      </button>
    </div>
  );
}
