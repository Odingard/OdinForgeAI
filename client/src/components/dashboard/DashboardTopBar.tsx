import { memo } from "react";
import { useLocation } from "wouter";
import { Zap, RefreshCw } from "lucide-react";
import { queryClient } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import type { DashboardData } from "../Dashboard";

export const DashboardTopBar = memo(function DashboardTopBar({ data }: { data: DashboardData }) {
  const [, navigate] = useLocation();
  const { evaluations, assets } = data;
  const active = evaluations.filter((e) => e.status === "pending" || e.status === "in_progress").length;
  const exploitable = evaluations.filter((e) => e.exploitable === true).length;

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
    queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
    queryClient.invalidateQueries({ queryKey: ["/api/defensive-posture/default"] });
  };

  return (
    <div className="rounded-t-lg px-5 py-3 bg-card/60 backdrop-blur-sm border-b border-border/50">
      <div className="flex items-center justify-between">
        {/* Left: Branding + Status */}
        <div className="flex items-center gap-4">
          <span className="font-extrabold text-lg tracking-tight text-foreground">
            ODIN<span className="text-primary">FORGE</span>
          </span>
          <span className="text-[10px] font-semibold uppercase tracking-widest text-primary bg-primary/8 border border-primary/15 px-3 py-1 rounded-full">
            Threat Operations
          </span>
          <div className="flex items-center gap-2 ml-1">
            <span className="inline-block h-2 w-2 rounded-full bg-emerald-400 glow-green-sm" />
            <span className="text-[10px] font-medium uppercase tracking-wider text-emerald-400">
              Systems Nominal
            </span>
          </div>
        </div>

        {/* Right: Metrics + Actions */}
        <div className="flex items-center gap-5">
          <MetricBox label="Active Threats" value={active} color={active > 0 ? "text-amber-400" : "text-primary"} />
          <div className="w-px h-7 bg-border/50" />
          <MetricBox label="Exploitable" value={exploitable} color={exploitable > 0 ? "text-red-400" : "text-emerald-400"} />
          <div className="w-px h-7 bg-border/50" />
          <MetricBox label="Assets" value={assets.length} color="text-primary" />
          <div className="w-px h-7 bg-border/50" />
          <Button variant="ghost" size="sm" onClick={handleRefresh} className="text-xs h-8 px-3 text-muted-foreground hover:text-foreground">
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
            Refresh
          </Button>
          <Button size="sm" onClick={() => navigate("/assess")} className="text-xs h-8 px-4">
            <Zap className="h-3.5 w-3.5 mr-1.5" />
            New Assessment
          </Button>
        </div>
      </div>
    </div>
  );
});

function MetricBox({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="text-right">
      <div className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground mb-0.5">
        {label}
      </div>
      <div className={`text-lg font-bold tabular-nums tracking-tight ${color}`}>
        {value}
      </div>
    </div>
  );
}
