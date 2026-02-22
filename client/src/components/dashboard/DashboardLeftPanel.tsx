import { RiskScoreGauge } from "./RiskScoreGauge";
import { FindingsVsResolvedChart } from "./FindingsVsResolvedChart";
import { FindingsMetricCards } from "./FindingsMetricCards";
import { ScannedAppsSummary } from "./ScannedAppsSummary";
import { OrganizationMetricsTable } from "./OrganizationMetricsTable";

export function DashboardLeftPanel() {
  return (
    <div className="space-y-4 overflow-y-auto max-h-[calc(100vh-140px)] pr-1 scrollbar-thin">
      <RiskScoreGauge />
      <FindingsVsResolvedChart />
      <FindingsMetricCards />
      <ScannedAppsSummary />
      <OrganizationMetricsTable />
    </div>
  );
}
