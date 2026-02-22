import { useLocation } from "wouter";
import { Zap, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { queryClient } from "@/lib/queryClient";

export function DashboardTopBar() {
  const [, navigate] = useLocation();

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
    queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
    queryClient.invalidateQueries({ queryKey: ["/api/defensive-posture/default"] });
  };

  return (
    <div className="flex items-center justify-between gap-4 px-1">
      <div className="flex items-center gap-3">
        <h1 className="text-lg font-bold tracking-tight">
          <span className="text-neon-cyan">Dashboard</span>
        </h1>
        <span className="text-[10px] font-mono px-2.5 py-1 rounded-full glass border border-cyan-500/20 text-cyan-400 uppercase tracking-widest">
          Analytics
        </span>
      </div>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          className="glass hover:glow-teal-sm transition-all h-8 text-xs"
          onClick={handleRefresh}
        >
          <RefreshCw className="h-3 w-3 mr-1.5" />
          Refresh
        </Button>
        <Button
          size="sm"
          className="bg-gradient-to-r from-cyan-600 to-blue-600 glow-teal-sm hover:glow-teal transition-all h-8 text-xs"
          onClick={() => navigate("/assess")}
        >
          <Zap className="h-3 w-3 mr-1.5" />
          New Assessment
        </Button>
      </div>
    </div>
  );
}
