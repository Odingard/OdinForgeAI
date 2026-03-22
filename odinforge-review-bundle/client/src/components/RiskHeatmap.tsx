import { motion } from "framer-motion";
import { Badge } from "@/components/ui/badge";
import type { IntelligentScore } from "@shared/schema";

interface RiskHeatmapProps {
  intelligentScore: IntelligentScore;
  compact?: boolean;
}

export function RiskHeatmap({ intelligentScore, compact = false }: RiskHeatmapProps) {
  const exploitabilityScore = intelligentScore.exploitability?.score || 0;
  const businessScore = intelligentScore.businessImpact?.score || 0;
  const riskScore = intelligentScore.riskRank?.overallScore || 0;
  const financialImpact = intelligentScore.businessImpact?.factors?.financialExposure?.score || 0;

  const compositeScore = Math.round((exploitabilityScore + businessScore + riskScore) / 3);

  const categories = [
    { key: "exploitability", label: "Exploitability", value: exploitabilityScore, weight: 35 },
    { key: "business", label: "Business Impact", value: businessScore, weight: 30 },
    { key: "risk", label: "Risk Level", value: riskScore, weight: 25 },
    { key: "financial", label: "Financial", value: financialImpact, weight: 10 },
  ];

  const getColorForValue = (value: number) => {
    if (value >= 80) return { bg: "bg-red-500", text: "text-red-400", border: "border-red-500/50" };
    if (value >= 60) return { bg: "bg-orange-500", text: "text-orange-400", border: "border-orange-500/50" };
    if (value >= 40) return { bg: "bg-amber-500", text: "text-amber-400", border: "border-amber-500/50" };
    if (value >= 20) return { bg: "bg-emerald-500", text: "text-emerald-400", border: "border-emerald-500/50" };
    return { bg: "bg-blue-500", text: "text-blue-400", border: "border-blue-500/50" };
  };

  const compositeColors = getColorForValue(compositeScore);

  if (compact) {
    return (
      <div className="grid grid-cols-4 gap-1" data-testid="risk-heatmap-compact">
        {categories.map((cat) => {
          const colors = getColorForValue(cat.value);
          return (
            <motion.div
              key={cat.key}
              className={`p-2 rounded-md ${colors.bg} relative overflow-hidden`}
              style={{ opacity: 0.3 + (cat.value / 100) * 0.7 }}
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 0.3 + (cat.value / 100) * 0.7 }}
              transition={{ duration: 0.3 }}
              data-testid={`heatmap-cell-${cat.key}`}
            >
              <div className="text-center">
                <div className="text-xs font-medium text-white">{cat.value}</div>
              </div>
            </motion.div>
          );
        })}
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="risk-heatmap">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h4 className="font-medium text-foreground">Risk Assessment Matrix</h4>
          <p className="text-xs text-muted-foreground">Multi-dimensional risk analysis</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">Composite Score:</span>
          <Badge className={`${compositeColors.bg}/10 ${compositeColors.text} ${compositeColors.border} text-lg px-3`}>
            {compositeScore}
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        {categories.map((cat, index) => {
          const colors = getColorForValue(cat.value);
          return (
            <motion.div
              key={cat.key}
              className={`p-4 rounded-lg bg-muted/30 border ${colors.border}`}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              data-testid={`risk-category-${cat.key}`}
            >
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-sm font-medium text-foreground">{cat.label}</span>
                <span className={`text-lg font-bold ${colors.text}`}>{cat.value}</span>
              </div>
              <div className="h-2 bg-muted/50 rounded-full overflow-hidden">
                <motion.div
                  className={`h-full ${colors.bg} rounded-full`}
                  initial={{ width: 0 }}
                  animate={{ width: `${cat.value}%` }}
                  transition={{ duration: 0.8, delay: index * 0.1 }}
                />
              </div>
              <div className="flex items-center justify-between mt-2">
                <span className="text-[10px] text-muted-foreground">Weight: {cat.weight}%</span>
                <span className="text-[10px] text-muted-foreground">
                  Contribution: {Math.round(cat.value * cat.weight / 100)}pts
                </span>
              </div>
            </motion.div>
          );
        })}
      </div>

      <div className="grid grid-cols-5 gap-1 pt-2">
        {[20, 40, 60, 80, 100].map((threshold, i) => {
          const colors = getColorForValue(threshold - 10);
          return (
            <div key={threshold} className="text-center">
              <div className={`h-3 ${colors.bg} rounded-sm`} style={{ opacity: 0.3 + i * 0.175 }} />
              <span className="text-[10px] text-muted-foreground">{threshold - 20}-{threshold}</span>
            </div>
          );
        })}
      </div>

      {intelligentScore.riskRank?.riskLevel && (
        <div className="pt-2 border-t border-border">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Risk Level:</span>
            <Badge className={getColorForValue(riskScore).bg + "/10 " + getColorForValue(riskScore).text}>
              {intelligentScore.riskRank.riskLevel}
            </Badge>
          </div>
          <div className="flex items-center justify-between text-sm mt-1">
            <span className="text-muted-foreground">Fix Priority:</span>
            <span className={getColorForValue(riskScore).text}>{intelligentScore.riskRank.recommendation?.timeframe || "N/A"}</span>
          </div>
        </div>
      )}
    </div>
  );
}
