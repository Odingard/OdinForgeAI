import { useMemo, memo } from "react";
import { groupAssetsByType } from "@/lib/dashboard-transforms";

const TYPE_COLORS: Record<string, { dot: string; bar: string }> = {
  web_application: { dot: "var(--falcon-blue)", bar: "var(--falcon-blue)" },
  api: { dot: "var(--falcon-green)", bar: "var(--falcon-green)" },
  cloud: { dot: "var(--falcon-orange)", bar: "var(--falcon-orange)" },
  network: { dot: "var(--falcon-red)", bar: "var(--falcon-red)" },
};

export const ScannedAppsSummary = memo(function ScannedAppsSummary({ assets = [] }: { assets: any[] }) {
  const groups = useMemo(() => groupAssetsByType(assets), [assets]);
  const total = assets.length;
  const entries = Object.entries(groups)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  const maxCount = entries.length > 0 ? entries[0][1] : 1;

  return (
    <div className="falcon-panel">
      <div className="falcon-panel-head flex items-center justify-between">
        <span className="font-mono text-[9px] font-normal tracking-[0.18em] uppercase" style={{ color: "var(--falcon-t3)" }}>
          Targets
        </span>
        <span className="font-mono text-[10px] font-medium" style={{ color: "var(--falcon-t2)" }}>
          {total}
        </span>
      </div>

      <div className="p-3 flex flex-col gap-2">
        {entries.map(([type, count]) => {
          const colors = TYPE_COLORS[type] || { dot: "var(--falcon-t4)", bar: "var(--falcon-t4)" };
          const label = type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
          const pct = Math.round((count / maxCount) * 100);
          return (
            <div key={type} className="flex items-center gap-2">
              <span className="text-[10px] font-mono tracking-[0.04em]" style={{ color: "var(--falcon-t3)", width: 80 }}>
                {label}
              </span>
              <div className="flex-1 h-[3px] rounded-sm overflow-hidden" style={{ background: "var(--falcon-border)" }}>
                <div className="h-full rounded-sm" style={{ width: `${pct}%`, background: colors.bar }} />
              </div>
              <span className="font-mono text-[10px] w-7 text-right" style={{ color: "var(--falcon-t2)" }}>
                {count}
              </span>
            </div>
          );
        })}
        {entries.length === 0 && (
          <p className="text-[10px] text-center py-4 tracking-wider uppercase" style={{ color: "var(--falcon-t4)" }}>
            No assets registered
          </p>
        )}
      </div>
    </div>
  );
});
