import { RiskScoreGauge } from "./RiskScoreGauge";
import { FindingsVsResolvedChart } from "./FindingsVsResolvedChart";
import { FindingsMetricCards } from "./FindingsMetricCards";
import { ScannedAppsSummary } from "./ScannedAppsSummary";
import { OrganizationMetricsTable } from "./OrganizationMetricsTable";

export function DashboardLeftPanel() {
  return (
    <div
      className="space-y-1.5 overflow-y-auto max-h-[calc(100vh-100px)] pr-1"
      style={{
        borderLeft: "1px solid rgba(56,189,248,0.06)",
        paddingLeft: 4,
        scrollbarWidth: "none",
      }}
    >
      <div
        className="flex items-center gap-2 px-2 py-1.5"
        style={{ borderBottom: "1px solid rgba(56,189,248,0.04)" }}
      >
        <span
          className="inline-block h-1 w-1 rounded-full bg-cyan-400"
          style={{ boxShadow: "0 0 3px #38bdf8" }}
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
          Threat Metrics
        </span>
      </div>
      <RiskScoreGauge />
      <FindingsVsResolvedChart />
      <FindingsMetricCards />
      <ScannedAppsSummary />
      <OrganizationMetricsTable />
    </div>
  );
}
