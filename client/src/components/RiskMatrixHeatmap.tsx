import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";

interface RiskItem {
  id: string;
  title: string;
  likelihood: number; // 1-5
  impact: number; // 1-5
  riskScore: number;
  severity: "critical" | "high" | "medium" | "low";
}

interface RiskMatrixHeatmapProps {
  items: RiskItem[];
  onItemClick?: (item: RiskItem) => void;
}

export function RiskMatrixHeatmap({ items, onItemClick }: RiskMatrixHeatmapProps) {
  // Group items by likelihood and impact
  const getItemsForCell = (likelihood: number, impact: number) => {
    return items.filter(item => item.likelihood === likelihood && item.impact === impact);
  };

  // Calculate risk level for cell
  const getCellRiskLevel = (likelihood: number, impact: number) => {
    const score = likelihood * impact;
    if (score >= 20) return "critical";
    if (score >= 12) return "high";
    if (score >= 6) return "medium";
    return "low";
  };

  // Get color for cell
  const getCellColor = (riskLevel: string, itemCount: number) => {
    if (itemCount === 0) return "bg-muted/30 border-border";

    switch (riskLevel) {
      case "critical": return "bg-red-500/20 border-red-500/50 hover:bg-red-500/30";
      case "high": return "bg-orange-500/20 border-orange-500/50 hover:bg-orange-500/30";
      case "medium": return "bg-amber-500/20 border-amber-500/50 hover:bg-amber-500/30";
      case "low": return "bg-emerald-500/20 border-emerald-500/50 hover:bg-emerald-500/30";
      default: return "bg-muted/30 border-border";
    }
  };

  const likelihoodLabels = ["Very Low", "Low", "Medium", "High", "Very High"];
  const impactLabels = ["Very Low", "Low", "Medium", "High", "Very High"];

  return (
    <div className="space-y-4">
      {/* Legend */}
      <div className="flex items-center gap-4 text-sm">
        <span className="text-muted-foreground">Risk Level:</span>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1">
            <div className="w-4 h-4 rounded bg-emerald-500/30 border border-emerald-500/50" />
            <span className="text-xs">Low</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-4 h-4 rounded bg-amber-500/30 border border-amber-500/50" />
            <span className="text-xs">Medium</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-4 h-4 rounded bg-orange-500/30 border border-orange-500/50" />
            <span className="text-xs">High</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-4 h-4 rounded bg-red-500/30 border border-red-500/50" />
            <span className="text-xs">Critical</span>
          </div>
        </div>
      </div>

      {/* Matrix */}
      <div className="overflow-x-auto">
        <div className="inline-grid grid-cols-6 gap-2 min-w-full">
          {/* Header row */}
          <div className="font-medium text-sm text-muted-foreground"></div>
          {impactLabels.map((label, i) => (
            <div key={i} className="font-medium text-sm text-center text-muted-foreground">
              {label}
            </div>
          ))}

          {/* Matrix cells */}
          {[5, 4, 3, 2, 1].map((likelihood) => (
            <div key={likelihood} className="contents">
              {/* Row label */}
              <div className="font-medium text-sm text-right pr-2 flex items-center justify-end text-muted-foreground">
                {likelihoodLabels[likelihood - 1]}
              </div>

              {/* Cells for each impact level */}
              {[1, 2, 3, 4, 5].map((impact) => {
                const cellItems = getItemsForCell(likelihood, impact);
                const riskLevel = getCellRiskLevel(likelihood, impact);
                const cellColor = getCellColor(riskLevel, cellItems.length);

                return (
                  <Card
                    key={`${likelihood}-${impact}`}
                    className={`min-h-24 p-3 flex flex-col items-center justify-center cursor-pointer transition-colors ${cellColor}`}
                    onClick={() => cellItems.length > 0 && onItemClick?.(cellItems[0])}
                  >
                    {cellItems.length > 0 ? (
                      <>
                        <div className="text-2xl font-bold mb-1">{cellItems.length}</div>
                        <div className="text-xs text-muted-foreground text-center">
                          {cellItems.length === 1 ? "item" : "items"}
                        </div>
                        {cellItems.length <= 3 && (
                          <div className="mt-2 space-y-1 w-full">
                            {cellItems.map(item => (
                              <div
                                key={item.id}
                                className="text-xs truncate text-center px-1 py-0.5 bg-background/50 rounded"
                                title={item.title}
                              >
                                {item.title.slice(0, 15)}...
                              </div>
                            ))}
                          </div>
                        )}
                      </>
                    ) : (
                      <div className="text-xs text-muted-foreground">-</div>
                    )}
                  </Card>
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Axis labels */}
      <div className="grid grid-cols-2 gap-4 text-center text-sm text-muted-foreground mt-4">
        <div></div>
        <div className="font-medium">Impact →</div>
        <div className="font-medium rotate-0 text-right pr-4">Likelihood →</div>
        <div></div>
      </div>
    </div>
  );
}
