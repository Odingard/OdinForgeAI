import { FindingsSeverityBreakdown } from "./FindingsSeverityBreakdown";
import { ReachabilityExploitabilityMatrix } from "./ReachabilityExploitabilityMatrix";
import { useLocation } from "wouter";

export function DashboardRightPanel() {
  const [, navigate] = useLocation();

  return (
    <div className="space-y-4 overflow-y-auto max-h-[calc(100vh-140px)] pl-1 scrollbar-thin">
      <FindingsSeverityBreakdown />
      <ReachabilityExploitabilityMatrix />
      <button
        onClick={() => navigate("/evaluations")}
        className="w-full text-center text-xs text-cyan-400 hover:text-cyan-300 transition-colors py-3 glass border border-border/50 rounded-lg uppercase tracking-wider font-medium"
      >
        View All Evaluations →
      </button>
    </div>
  );
}
