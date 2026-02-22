import { AssetFlowSankey } from "./AssetFlowSankey";

export function DashboardCenterPanel() {
  return (
    <div className="glass border border-border/50 rounded-lg overflow-hidden h-full min-h-[400px]">
      <div className="px-4 py-3 border-b border-border/30 flex items-center justify-between">
        <h3 className="text-xs uppercase tracking-wider text-muted-foreground/80 font-medium">
          Asset → Finding Flow
        </h3>
        <span className="text-[10px] font-mono text-cyan-400/50">Sankey</span>
      </div>
      <AssetFlowSankey />
    </div>
  );
}
