import { useMemo, memo } from "react";
import { groupAssetsByType } from "@/lib/dashboard-transforms";

const TYPE_COLORS: Record<string, string> = {
  web_application: "text-cyan-400 border-cyan-500/40",
  api: "text-emerald-400 border-emerald-500/40",
  cloud: "text-purple-400 border-purple-500/40",
  network: "text-amber-400 border-amber-500/40",
};

export const ScannedAppsSummary = memo(function ScannedAppsSummary({ assets = [] }: { assets: any[] }) {
  const groups = useMemo(() => groupAssetsByType(assets), [assets]);
  const total = assets.length;
  const entries = Object.entries(groups)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4);

  return (
    <div className="rounded-lg border border-border bg-card/50 backdrop-blur-sm p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="inline-block h-2 w-2 rounded-full bg-cyan-400" style={{ boxShadow: "0 0 6px #38bdf8" }} />
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Asset Inventory
          </span>
        </div>
        <span className="text-lg font-bold text-foreground tabular-nums">
          {total}
        </span>
      </div>
      <div className="space-y-1.5">
        {entries.map(([type, count]) => {
          const colors = TYPE_COLORS[type] || "text-muted-foreground border-border";
          const [textColor, borderColor] = colors.split(" ");
          const label = type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
          return (
            <div
              key={type}
              className={`flex items-center justify-between py-2 px-3 rounded-md bg-background/40 border-l-2 ${borderColor}`}
            >
              <span className="text-xs font-medium text-muted-foreground">{label}</span>
              <span className={`text-sm font-bold tabular-nums ${textColor}`}>{count}</span>
            </div>
          );
        })}
        {entries.length === 0 && (
          <p className="text-xs text-muted-foreground/40 text-center py-4 uppercase tracking-wider">
            No assets registered
          </p>
        )}
      </div>
    </div>
  );
});
