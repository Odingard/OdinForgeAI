import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { groupAssetsByType } from "@/lib/dashboard-transforms";
import { Server, Globe, Cloud, Shield } from "lucide-react";

const TYPE_ICONS: Record<string, typeof Server> = {
  web_application: Globe,
  api: Server,
  cloud: Cloud,
  network: Shield,
};

export function ScannedAppsSummary() {
  const { data: assets = [] } = useQuery<any[]>({
    queryKey: ["/api/assets"],
  });

  const groups = useMemo(() => groupAssetsByType(assets), [assets]);
  const total = assets.length;
  const entries = Object.entries(groups).sort((a, b) => b[1] - a[1]).slice(0, 4);

  return (
    <div className="glass border border-border/50 rounded-lg p-5">
      <h3 className="text-xs uppercase tracking-wider text-muted-foreground/80 font-medium mb-1">
        Scanned Apps
      </h3>
      <p className="text-2xl font-bold tabular-nums text-foreground">{total}</p>
      <p className="text-[10px] text-muted-foreground/60 mb-3">Total Assets</p>
      <div className="grid grid-cols-2 gap-2">
        {entries.map(([type, count]) => {
          const Icon = TYPE_ICONS[type] || Server;
          const label = type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
          return (
            <div
              key={type}
              className="flex items-center gap-2 rounded-md bg-muted/30 px-2.5 py-2"
            >
              <Icon className="h-3.5 w-3.5 text-muted-foreground/60" />
              <div className="min-w-0 flex-1">
                <p className="text-xs font-medium truncate">{label}</p>
                <p className="text-[10px] text-muted-foreground/60 tabular-nums">{count}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
