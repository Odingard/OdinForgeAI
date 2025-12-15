import { TrendingUp, TrendingDown, Minus, AlertTriangle, Shield, DollarSign, Scale, Users, Building2, Clock } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { IntelligentScore } from "@shared/schema";

interface IntelligentScorePanelProps {
  score: IntelligentScore;
}

export function IntelligentScorePanel({ score }: IntelligentScorePanelProps) {
  const getRiskLevelColor = (level: string) => {
    const colors: Record<string, string> = {
      emergency: "bg-red-600 text-white",
      critical: "bg-red-500/10 text-red-400 border-red-500/30",
      high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
      medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
      low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
      info: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    };
    return colors[level] || colors.medium;
  };

  const getTimeframeLabel = (timeframe: string) => {
    const labels: Record<string, string> = {
      immediate: "Fix Immediately",
      "24_hours": "Fix Within 24 Hours",
      "7_days": "Fix Within 7 Days",
      "30_days": "Fix Within 30 Days",
      "90_days": "Fix Within 90 Days",
      acceptable_risk: "Acceptable Risk",
    };
    return labels[timeframe] || timeframe;
  };

  const getTrendIcon = (trend?: string) => {
    switch (trend) {
      case "improving":
        return <TrendingDown className="h-4 w-4 text-emerald-400" />;
      case "degrading":
        return <TrendingUp className="h-4 w-4 text-red-400" />;
      case "stable":
        return <Minus className="h-4 w-4 text-muted-foreground" />;
      default:
        return null;
    }
  };

  const formatCurrency = (value: number) => {
    if (value >= 1000000) return `$${(value / 1000000).toFixed(1)}M`;
    if (value >= 1000) return `$${(value / 1000).toFixed(0)}K`;
    return `$${value.toFixed(0)}`;
  };

  return (
    <div className="space-y-6" data-testid="intelligent-score-panel">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className="w-20 h-20 rounded-full border-4 border-muted flex items-center justify-center">
              <span className="text-2xl font-bold text-foreground">{score.riskRank.overallScore}</span>
            </div>
            <div className="absolute -bottom-1 -right-1">
              {getTrendIcon(score.riskRank.trendIndicator)}
            </div>
          </div>
          <div>
            <Badge className={getRiskLevelColor(score.riskRank.riskLevel)}>
              {score.riskRank.riskLevel.toUpperCase()}
            </Badge>
            <p className="text-lg font-semibold text-foreground mt-1">{score.riskRank.executiveLabel}</p>
            <p className="text-sm text-muted-foreground">Fix Priority: #{score.riskRank.fixPriority}</p>
          </div>
        </div>
        <div className="text-right">
          <Badge className="bg-cyan-500/10 text-cyan-400 border-cyan-500/30 gap-1">
            <Clock className="h-3 w-3" />
            {getTimeframeLabel(score.riskRank.recommendation.timeframe)}
          </Badge>
        </div>
      </div>

      <div className="p-4 bg-muted/30 rounded-lg border border-border">
        <div className="flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-amber-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-foreground">{score.riskRank.recommendation.action}</p>
            <p className="text-sm text-muted-foreground mt-1">{score.riskRank.recommendation.justification}</p>
          </div>
        </div>
      </div>

      <Tabs defaultValue="exploitability" className="w-full">
        <TabsList className="w-full">
          <TabsTrigger value="exploitability" className="flex-1" data-testid="tab-exploitability">
            Exploitability
          </TabsTrigger>
          <TabsTrigger value="business" className="flex-1" data-testid="tab-business-impact">
            Business Impact
          </TabsTrigger>
        </TabsList>

        <TabsContent value="exploitability" className="mt-4 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Exploitability Score</span>
            <div className="flex items-center gap-2">
              <Progress value={score.exploitability.score} className="w-24 h-2" />
              <span className="font-mono text-sm">{score.exploitability.score}/100</span>
            </div>
          </div>

          <div className="space-y-3">
            <div className="p-3 bg-muted/20 rounded-lg border border-border">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-foreground">Attack Complexity</span>
                <Badge variant="outline">{score.exploitability.factors.attackComplexity.level}</Badge>
              </div>
              <p className="text-xs text-muted-foreground">{score.exploitability.factors.attackComplexity.rationale}</p>
              <Progress value={score.exploitability.factors.attackComplexity.score} className="mt-2 h-1.5" />
            </div>

            <div className="p-3 bg-muted/20 rounded-lg border border-border">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-foreground">Authentication Required</span>
                <Badge variant="outline">{score.exploitability.factors.authenticationRequired.level}</Badge>
              </div>
              <p className="text-xs text-muted-foreground">{score.exploitability.factors.authenticationRequired.rationale}</p>
              <Progress value={score.exploitability.factors.authenticationRequired.score} className="mt-2 h-1.5" />
            </div>

            <div className="p-3 bg-muted/20 rounded-lg border border-border">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-foreground">Detection Likelihood</span>
                <Badge variant="outline">{score.exploitability.factors.detectionLikelihood.level}</Badge>
              </div>
              <div className="text-xs text-muted-foreground">
                Monitoring Coverage: {score.exploitability.factors.detectionLikelihood.monitoringCoverage}%
              </div>
              <Progress value={score.exploitability.factors.detectionLikelihood.score} className="mt-2 h-1.5" />
            </div>

            <div className="p-3 bg-muted/20 rounded-lg border border-border">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-foreground">Exploit Maturity</span>
                <Badge variant="outline">{score.exploitability.factors.exploitMaturity.availability}</Badge>
              </div>
              <div className="text-xs text-muted-foreground">
                Skill Required: {score.exploitability.factors.exploitMaturity.skillRequired.replace("_", " ")}
              </div>
              <Progress value={score.exploitability.factors.exploitMaturity.score} className="mt-2 h-1.5" />
            </div>
          </div>
        </TabsContent>

        <TabsContent value="business" className="mt-4 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">Business Impact Score</span>
            <div className="flex items-center gap-2">
              <Badge className={getRiskLevelColor(score.businessImpact.riskLabel)}>
                {score.businessImpact.riskLabel}
              </Badge>
              <span className="font-mono text-sm">{score.businessImpact.score}/100</span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 bg-muted/20 rounded-lg border border-border">
              <div className="flex items-center gap-2 mb-2">
                <Shield className="h-4 w-4 text-cyan-400" />
                <span className="text-sm font-medium text-foreground">Data Sensitivity</span>
              </div>
              <Badge className="mb-2" variant="outline">
                {score.businessImpact.factors.dataSensitivity.classification}
              </Badge>
              <div className="text-xs text-muted-foreground">
                {score.businessImpact.factors.dataSensitivity.recordsAtRisk} records at risk
              </div>
              <div className="flex flex-wrap gap-1 mt-2">
                {score.businessImpact.factors.dataSensitivity.dataTypes.map((type) => (
                  <Badge key={type} className="text-xs bg-red-500/10 text-red-400 border-red-500/30">
                    {type.toUpperCase()}
                  </Badge>
                ))}
              </div>
            </div>

            <div className="p-3 bg-muted/20 rounded-lg border border-border">
              <div className="flex items-center gap-2 mb-2">
                <DollarSign className="h-4 w-4 text-emerald-400" />
                <span className="text-sm font-medium text-foreground">Financial Exposure</span>
              </div>
              <div className="text-lg font-semibold text-foreground">
                {formatCurrency(score.businessImpact.factors.financialExposure.directLoss.min)} - {formatCurrency(score.businessImpact.factors.financialExposure.directLoss.max)}
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                Regulatory Fines: {formatCurrency(score.businessImpact.factors.financialExposure.regulatoryFines.potential)}
              </div>
            </div>

            <div className="p-3 bg-muted/20 rounded-lg border border-border">
              <div className="flex items-center gap-2 mb-2">
                <Scale className="h-4 w-4 text-purple-400" />
                <span className="text-sm font-medium text-foreground">Compliance Impact</span>
              </div>
              <div className="flex flex-wrap gap-1">
                {score.businessImpact.factors.complianceImpact.affectedFrameworks.map((fw) => (
                  <Badge key={fw} variant="outline" className="text-xs">
                    {fw.toUpperCase()}
                  </Badge>
                ))}
              </div>
              {score.businessImpact.factors.complianceImpact.violations.length > 0 && (
                <div className="text-xs text-muted-foreground mt-2">
                  {score.businessImpact.factors.complianceImpact.violations.length} violation(s) identified
                </div>
              )}
            </div>

            <div className="p-3 bg-muted/20 rounded-lg border border-border">
              <div className="flex items-center gap-2 mb-2">
                <Users className="h-4 w-4 text-orange-400" />
                <span className="text-sm font-medium text-foreground">Blast Radius</span>
              </div>
              <div className="text-sm text-foreground">
                {score.businessImpact.factors.blastRadius.affectedSystems} systems
              </div>
              <div className="text-xs text-muted-foreground">
                {score.businessImpact.factors.blastRadius.affectedUsers} users affected
              </div>
              <Badge className="mt-2" variant="outline">
                {score.businessImpact.factors.blastRadius.propagationRisk}
              </Badge>
            </div>
          </div>

          <div className="p-3 bg-muted/20 rounded-lg border border-border">
            <div className="flex items-center gap-2 mb-2">
              <Building2 className="h-4 w-4 text-blue-400" />
              <span className="text-sm font-medium text-foreground">Reputational Risk</span>
            </div>
            <div className="grid grid-cols-3 gap-4 text-xs">
              <div>
                <span className="text-muted-foreground block">Customer Trust</span>
                <Badge variant="outline" className="mt-1">{score.businessImpact.factors.reputationalRisk.customerTrust}</Badge>
              </div>
              <div>
                <span className="text-muted-foreground block">Media Exposure</span>
                <Badge variant="outline" className="mt-1">{score.businessImpact.factors.reputationalRisk.mediaExposure}</Badge>
              </div>
              <div>
                <span className="text-muted-foreground block">Competitive Impact</span>
                <Badge variant="outline" className="mt-1">{score.businessImpact.factors.reputationalRisk.competitiveAdvantage}</Badge>
              </div>
            </div>
          </div>
        </TabsContent>
      </Tabs>

      {score.riskRank.comparison && (
        <div className="pt-4 border-t border-border">
          <div className="text-xs text-muted-foreground mb-2">Comparison</div>
          <div className="flex items-center gap-4">
            {score.riskRank.comparison.cvssEquivalent && (
              <div className="text-sm">
                <span className="text-muted-foreground">CVSS Equivalent: </span>
                <span className="font-mono">{score.riskRank.comparison.cvssEquivalent.toFixed(1)}</span>
              </div>
            )}
            {score.riskRank.comparison.industryPercentile && (
              <div className="text-sm">
                <span className="text-muted-foreground">Industry Percentile: </span>
                <span className="font-mono">{score.riskRank.comparison.industryPercentile}%</span>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="text-xs text-muted-foreground text-right">
        Calculated: {new Date(score.calculatedAt).toLocaleString()}
      </div>
    </div>
  );
}
