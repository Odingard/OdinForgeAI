import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { AlertTriangle, Clock, TrendingUp, Shield, Filter, ArrowUpRight, Building2, Trash2, Grid3x3, Target, Crosshair, AlertCircle, Link2, Zap } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { useState } from "react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { RiskMatrixHeatmap } from "@/components/RiskMatrixHeatmap";
import { useCoverageMetrics, useCoverageGaps } from "@/hooks/useCoverage";

interface EvaluationWithScore {
  id: string;
  assetId: string;
  exposureType: string;
  priority: string;
  description: string;
  status: string;
  createdAt: string;
  exploitable?: boolean;
  score?: number;
  intelligentScore?: {
    riskRank: {
      overallScore: number;
      riskLevel: string;
      executiveLabel: string;
      fixPriority: number;
      recommendation: {
        action: string;
        timeframe: string;
        justification: string;
      };
    };
    businessImpact: {
      score: number;
      riskLabel: string;
      factors: {
        financialExposure: {
          directLoss: { min: number; max: number };
        };
        complianceImpact: {
          affectedFrameworks: string[];
        };
      };
    };
    exploitability: {
      score: number;
    };
  };
}

export default function RiskDashboard() {
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [timeframeFilter, setTimeframeFilter] = useState<string>("all");

  const { data: evaluations = [], isLoading } = useQuery<EvaluationWithScore[]>({
    queryKey: ["/api/aev/evaluations"],
  });

  const { data: coverage } = useCoverageMetrics();
  const { data: gaps } = useCoverageGaps();

  const { data: breachChains = [] } = useQuery<any[]>({
    queryKey: ["/api/breach-chains"],
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/aev/evaluations/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
      toast({
        title: "Evaluation removed",
        description: "The evaluation has been deleted from the queue",
      });
    },
    onError: () => {
      toast({
        title: "Delete failed",
        description: "Failed to delete the evaluation",
        variant: "destructive",
      });
    },
  });

  const evaluationsWithScores = evaluations.filter(e => e.intelligentScore);

  const filteredEvaluations = evaluationsWithScores
    .filter(e => {
      if (riskFilter !== "all" && e.intelligentScore?.riskRank?.riskLevel !== riskFilter) return false;
      if (timeframeFilter !== "all" && e.intelligentScore?.riskRank?.recommendation?.timeframe !== timeframeFilter) return false;
      return true;
    })
    .sort((a, b) => {
      const aPriority = a.intelligentScore?.riskRank?.fixPriority ?? 100;
      const bPriority = b.intelligentScore?.riskRank?.fixPriority ?? 100;
      return aPriority - bPriority;
    });

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

  const getTimeframeColor = (timeframe: string) => {
    const colors: Record<string, string> = {
      immediate: "bg-red-500/10 text-red-400 border-red-500/30",
      "24_hours": "bg-orange-500/10 text-orange-400 border-orange-500/30",
      "7_days": "bg-amber-500/10 text-amber-400 border-amber-500/30",
      "30_days": "bg-blue-500/10 text-blue-400 border-blue-500/30",
      "90_days": "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
      acceptable_risk: "bg-gray-500/10 text-gray-400 border-gray-500/30",
    };
    return colors[timeframe] || colors["30_days"];
  };

  const getTimeframeLabel = (timeframe: string) => {
    const labels: Record<string, string> = {
      immediate: "Immediate",
      "24_hours": "24 Hours",
      "7_days": "7 Days",
      "30_days": "30 Days",
      "90_days": "90 Days",
      acceptable_risk: "Accept Risk",
    };
    return labels[timeframe] || timeframe;
  };

  const formatCurrency = (value: number) => {
    if (value >= 1000000) return `$${(value / 1000000).toFixed(1)}M`;
    if (value >= 1000) return `$${(value / 1000).toFixed(0)}K`;
    return `$${value.toFixed(0)}`;
  };

  const stats = {
    critical: evaluationsWithScores.filter(e => e.intelligentScore?.riskRank?.riskLevel === "critical" || e.intelligentScore?.riskRank?.riskLevel === "emergency").length,
    high: evaluationsWithScores.filter(e => e.intelligentScore?.riskRank?.riskLevel === "high").length,
    medium: evaluationsWithScores.filter(e => e.intelligentScore?.riskRank?.riskLevel === "medium").length,
    low: evaluationsWithScores.filter(e => e.intelligentScore?.riskRank?.riskLevel === "low" || e.intelligentScore?.riskRank?.riskLevel === "info").length,
    totalExposure: evaluationsWithScores.reduce((sum, e) => {
      const max = e.intelligentScore?.businessImpact?.factors?.financialExposure?.directLoss?.max || 0;
      return sum + max;
    }, 0),
    avgRiskScore: evaluationsWithScores.length > 0
      ? Math.round(evaluationsWithScores.reduce((sum, e) => sum + (e.intelligentScore?.riskRank?.overallScore || 0), 0) / evaluationsWithScores.length)
      : 0,
  };

  // Basic stats from all evaluations (even without intelligent scores)
  const basicStats = {
    total: evaluations.length,
    completed: evaluations.filter(e => e.status === "completed").length,
    exploitable: evaluations.filter(e => e.exploitable).length,
    safe: evaluations.filter(e => e.exploitable === false).length,
    pending: evaluations.filter(e => e.status === "pending" || e.status === "in_progress").length,
    critical: evaluations.filter(e => e.priority === "critical").length,
    high: evaluations.filter(e => e.priority === "high").length,
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div className="animate-pulse space-y-4">
          <div className="h-8 w-48 bg-muted rounded" />
          <div className="grid grid-cols-4 gap-4">
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="h-24 bg-muted rounded-lg" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="risk-dashboard">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6 text-red-400" />
            Risk Dashboard
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Security risks prioritized by business impact
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          {evaluationsWithScores.length > 0 && (
            <>
              <Filter className="h-4 w-4 text-muted-foreground" />
              <Select value={riskFilter} onValueChange={setRiskFilter}>
                <SelectTrigger className="w-[130px] h-8 text-xs" data-testid="select-risk-filter">
                  <SelectValue placeholder="Risk Level" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Levels</SelectItem>
                  <SelectItem value="emergency">Emergency</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
              <Select value={timeframeFilter} onValueChange={setTimeframeFilter}>
                <SelectTrigger className="w-[130px] h-8 text-xs" data-testid="select-timeframe-filter">
                  <SelectValue placeholder="Timeframe" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Timeframes</SelectItem>
                  <SelectItem value="immediate">Immediate</SelectItem>
                  <SelectItem value="24_hours">24 Hours</SelectItem>
                  <SelectItem value="7_days">7 Days</SelectItem>
                  <SelectItem value="30_days">30 Days</SelectItem>
                  <SelectItem value="90_days">90 Days</SelectItem>
                </SelectContent>
              </Select>
            </>
          )}
        </div>
      </div>

      {/* Consolidated Metrics Strip */}
      <Card>
        <CardContent className="pt-5 pb-4">
          {evaluationsWithScores.length > 0 ? (
            <div className={`grid grid-cols-2 sm:grid-cols-3 ${breachChains.length > 0 ? "lg:grid-cols-7" : "lg:grid-cols-6"} gap-4 divide-x-0 lg:divide-x divide-border`}>
              {/* Intelligent Risk Metrics */}
              <div className="text-center lg:text-left">
                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Critical</div>
                <div className={`text-2xl font-bold tabular-nums ${stats.critical > 0 ? 'text-red-400' : 'text-foreground'}`} data-testid="stat-critical">
                  {stats.critical}
                </div>
                {stats.critical > 0 && <div className="text-[10px] text-red-400/80 mt-0.5">Immediate action</div>}
              </div>
              <div className="text-center lg:text-left lg:pl-4">
                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">High</div>
                <div className="text-2xl font-bold tabular-nums text-foreground" data-testid="stat-high">{stats.high}</div>
              </div>
              <div className="text-center lg:text-left lg:pl-4">
                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Exposure</div>
                <div className="text-2xl font-bold tabular-nums text-foreground" data-testid="stat-exposure">{formatCurrency(stats.totalExposure)}</div>
              </div>
              <div className="text-center lg:text-left lg:pl-4">
                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Avg Score</div>
                <div className="text-2xl font-bold tabular-nums text-foreground" data-testid="stat-avg-score">{stats.avgRiskScore}</div>
                <Progress value={stats.avgRiskScore} className="mt-1 h-1" />
              </div>

              {/* Coverage Metrics */}
              {coverage && (
                <>
                  <div className="text-center lg:text-left lg:pl-4">
                    <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1 flex items-center gap-1 justify-center lg:justify-start">
                      <Target className="h-3 w-3" /> Assets
                    </div>
                    <div className="text-2xl font-bold tabular-nums text-foreground" data-testid="stat-asset-coverage">
                      {coverage.assetCoverage.coveragePercent}%
                    </div>
                    <div className="text-[10px] text-muted-foreground mt-0.5">
                      {coverage.assetCoverage.assetsEvaluatedLast30d}/{coverage.assetCoverage.totalActiveAssets} tested
                    </div>
                  </div>
                  <div className="text-center lg:text-left lg:pl-4">
                    <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1 flex items-center gap-1 justify-center lg:justify-start">
                      <Crosshair className="h-3 w-3" /> Tactics
                    </div>
                    <div className="text-2xl font-bold tabular-nums text-foreground" data-testid="stat-technique-coverage">
                      {coverage.techniqueCoverage.tacticsExercised}/{coverage.techniqueCoverage.totalTactics}
                    </div>
                    <div className="text-[10px] text-muted-foreground mt-0.5">
                      {coverage.techniqueCoverage.uniqueTechniqueIds > 0 && `${coverage.techniqueCoverage.uniqueTechniqueIds} techniques`}
                      {coverage.techniqueCoverage.uniqueTechniqueIds === 0 && "ATT\u0026CK coverage"}
                    </div>
                  </div>
                </>
              )}
              {breachChains.length > 0 && (
                <div className="text-center lg:text-left lg:pl-4">
                  <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1 flex items-center gap-1 justify-center lg:justify-start">
                    <Link2 className="h-3 w-3" /> Breach Chains
                  </div>
                  <div className={`text-2xl font-bold tabular-nums ${breachChains.some((c: any) => c.overallRiskScore >= 70) ? "text-red-400" : "text-foreground"}`} data-testid="stat-breach-chains">
                    {breachChains.filter((c: any) => c.status === "completed").length}/{breachChains.length}
                  </div>
                  <div className="text-[10px] text-muted-foreground mt-0.5">
                    {breachChains.some((c: any) => c.status === "running") ? "chain running" : "completed"}
                  </div>
                </div>
              )}
            </div>
          ) : (
            /* Basic metrics from raw evaluation data when no intelligent scores exist */
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 divide-x-0 lg:divide-x divide-border">
              <div className="text-center lg:text-left">
                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Evaluations</div>
                <div className="text-2xl font-bold tabular-nums text-foreground" data-testid="stat-total">
                  {basicStats.total}
                </div>
                <div className="text-[10px] text-muted-foreground mt-0.5">{basicStats.completed} completed</div>
              </div>
              <div className="text-center lg:text-left lg:pl-4">
                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Exploitable</div>
                <div className={`text-2xl font-bold tabular-nums ${basicStats.exploitable > 0 ? 'text-red-400' : 'text-foreground'}`} data-testid="stat-exploitable">
                  {basicStats.exploitable}
                </div>
                {basicStats.exploitable > 0 && <div className="text-[10px] text-red-400/80 mt-0.5">Confirmed vulnerable</div>}
              </div>
              <div className="text-center lg:text-left lg:pl-4">
                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Safe</div>
                <div className="text-2xl font-bold tabular-nums text-emerald-400" data-testid="stat-safe">
                  {basicStats.safe}
                </div>
              </div>
              <div className="text-center lg:text-left lg:pl-4">
                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Critical Priority</div>
                <div className={`text-2xl font-bold tabular-nums ${basicStats.critical > 0 ? 'text-red-400' : 'text-foreground'}`}>
                  {basicStats.critical}
                </div>
              </div>
              <div className="text-center lg:text-left lg:pl-4">
                <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">High Priority</div>
                <div className="text-2xl font-bold tabular-nums text-foreground">
                  {basicStats.high}
                </div>
              </div>
              {breachChains.length > 0 ? (
                <div className="text-center lg:text-left lg:pl-4">
                  <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1 flex items-center gap-1 justify-center lg:justify-start">
                    <Link2 className="h-3 w-3" /> Breach Chains
                  </div>
                  <div className="text-2xl font-bold tabular-nums text-foreground" data-testid="stat-breach-chains">
                    {breachChains.filter((c: any) => c.status === "completed").length}/{breachChains.length}
                  </div>
                </div>
              ) : (
                <div className="text-center lg:text-left lg:pl-4">
                  <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Pending</div>
                  <div className="text-2xl font-bold tabular-nums text-amber-400">
                    {basicStats.pending}
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* ATT&CK Kill Chain — compact inline strip */}
      {coverage && coverage.tacticalBreakdown.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {coverage.tacticalBreakdown.map((tactic) => (
            <div
              key={tactic.tactic}
              className={`inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                tactic.covered
                  ? "border-emerald-500/30 bg-emerald-500/5 text-emerald-400"
                  : "border-border bg-muted/30 text-muted-foreground/60"
              }`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${tactic.covered ? "bg-emerald-400" : "bg-muted-foreground/30"}`} />
              {tactic.displayName}
            </div>
          ))}
          {gaps && gaps.untestedTactics.length > 0 && (
            <div className="inline-flex items-center gap-1 rounded-md px-2.5 py-1 text-[11px] text-muted-foreground">
              <AlertCircle className="h-3 w-3" />
              {gaps.untestedTactics.length} untested
              {gaps.staleAssets.length > 0 && ` · ${gaps.staleAssets.length} stale assets`}
            </div>
          )}
        </div>
      )}

      {/* Main Content: Risk Matrix + Priority Queue */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Risk Matrix */}
        {evaluationsWithScores.length > 0 && (
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Grid3x3 className="h-4 w-4 text-cyan-400" />
                Risk Matrix
              </CardTitle>
            </CardHeader>
            <CardContent>
              <RiskMatrixHeatmap
                items={evaluationsWithScores.map(e => {
                  const score = e.intelligentScore?.riskRank?.overallScore || 50;
                  const exploitability = e.intelligentScore?.exploitability?.score || 50;
                  const businessImpact = e.intelligentScore?.businessImpact?.score || 50;
                  const likelihood = Math.min(5, Math.max(1, Math.ceil(exploitability / 20)));
                  const impact = Math.min(5, Math.max(1, Math.ceil(businessImpact / 20)));
                  return {
                    id: e.id,
                    title: e.assetId,
                    likelihood,
                    impact,
                    riskScore: score,
                    severity: (e.intelligentScore?.riskRank?.riskLevel === "critical" || e.intelligentScore?.riskRank?.riskLevel === "emergency")
                      ? "critical"
                      : e.intelligentScore?.riskRank?.riskLevel === "high"
                      ? "high"
                      : e.intelligentScore?.riskRank?.riskLevel === "medium"
                      ? "medium"
                      : "low",
                  };
                })}
                onItemClick={(item) => {
                  window.location.href = `/?evaluation=${item.id}`;
                }}
              />
            </CardContent>
          </Card>
        )}

        {/* Fix Priority Queue */}
        <Card className={evaluationsWithScores.length === 0 ? "col-span-full" : ""}>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Clock className="h-4 w-4 text-cyan-400" />
              {evaluationsWithScores.length > 0 ? "Fix Priority Queue" : "Evaluation Results"}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {filteredEvaluations.length === 0 && evaluations.length === 0 ? (
              <div className="text-center py-10 text-muted-foreground">
                <Shield className="h-10 w-10 mx-auto mb-3 opacity-30" />
                <p className="text-sm">No evaluations yet</p>
                <p className="text-xs mt-1 mb-4">Run an assessment to populate risk data</p>
                <Button size="sm" onClick={() => navigate("/assess")}>
                  <Zap className="h-3.5 w-3.5 mr-2" />
                  New Assessment
                </Button>
              </div>
            ) : filteredEvaluations.length === 0 && evaluations.length > 0 ? (
              /* Show basic evaluation list when no intelligent scores exist */
              <div className="space-y-2">
                {evaluations
                  .sort((a, b) => {
                    const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
                    return (priorityOrder[a.priority] ?? 4) - (priorityOrder[b.priority] ?? 4);
                  })
                  .map((evaluation, index) => {
                    const priorityColors: Record<string, string> = {
                      critical: "bg-red-500/10 text-red-400 border-red-500/30",
                      high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
                      medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
                      low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
                    };
                    return (
                      <div
                        key={evaluation.id}
                        className="flex items-center gap-3 p-3 rounded-lg border border-border/50 hover:border-border hover:bg-muted/30 transition-colors"
                      >
                        <div className="flex items-center justify-center w-6 h-6 rounded-full bg-muted text-xs font-mono font-bold shrink-0">
                          {index + 1}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="text-sm font-medium text-foreground truncate">{evaluation.assetId}</span>
                            <Badge className={`text-[10px] py-0 ${priorityColors[evaluation.priority] || priorityColors.medium}`}>
                              {evaluation.priority?.toUpperCase()}
                            </Badge>
                            {evaluation.exploitable === true && (
                              <Badge className="text-[10px] py-0 bg-red-500/10 text-red-400 border-red-500/30">
                                EXPLOITABLE
                              </Badge>
                            )}
                            {evaluation.exploitable === false && (
                              <Badge className="text-[10px] py-0 bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                                SAFE
                              </Badge>
                            )}
                          </div>
                          <p className="text-xs text-muted-foreground mt-0.5 truncate">
                            {evaluation.exposureType?.replace(/_/g, " ")} — {evaluation.status}
                          </p>
                        </div>
                        {evaluation.score != null && (
                          <div className="text-right hidden sm:block shrink-0">
                            <div className="font-mono text-sm font-bold text-foreground">
                              {Math.round(evaluation.score * 100) / 100}
                            </div>
                            <div className="text-[10px] text-muted-foreground">score</div>
                          </div>
                        )}
                        <Button variant="ghost" size="icon" className="h-7 w-7 shrink-0" asChild>
                          <a href={`/?evaluation=${evaluation.id}`}>
                            <ArrowUpRight className="h-3.5 w-3.5" />
                          </a>
                        </Button>
                      </div>
                    );
                  })}
                {evaluationsWithScores.length === 0 && evaluations.length > 0 && (
                  <div className="text-center pt-3 pb-1">
                    <p className="text-xs text-muted-foreground">
                      Intelligent risk scores are generated after completed evaluations. Run an assessment to see full risk prioritization.
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-2">
                {filteredEvaluations.map((evaluation, index) => (
                  <div
                    key={evaluation.id}
                    className="flex items-center gap-3 p-3 rounded-lg border border-border/50 hover:border-border hover:bg-muted/30 transition-colors"
                    data-testid={`risk-item-${evaluation.id}`}
                  >
                    <div className="flex items-center justify-center w-6 h-6 rounded-full bg-muted text-xs font-mono font-bold shrink-0">
                      {index + 1}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-sm font-medium text-foreground truncate">{evaluation.assetId}</span>
                        <Badge className={`text-[10px] py-0 ${getRiskLevelColor(evaluation.intelligentScore?.riskRank?.riskLevel || "medium")}`}>
                          {evaluation.intelligentScore?.riskRank?.riskLevel?.toUpperCase()}
                        </Badge>
                        <Badge className={`text-[10px] py-0 ${getTimeframeColor(evaluation.intelligentScore?.riskRank?.recommendation?.timeframe || "30_days")}`}>
                          {getTimeframeLabel(evaluation.intelligentScore?.riskRank?.recommendation?.timeframe || "30_days")}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5 truncate">
                        {evaluation.intelligentScore?.riskRank?.executiveLabel}
                      </p>
                    </div>

                    <div className="text-right hidden sm:block shrink-0">
                      <div className="font-mono text-sm font-bold text-foreground">
                        {evaluation.intelligentScore?.riskRank?.overallScore}
                      </div>
                      <div className="text-[10px] text-muted-foreground">
                        {formatCurrency(evaluation.intelligentScore?.businessImpact?.factors?.financialExposure?.directLoss?.max || 0)}
                      </div>
                    </div>

                    <div className="flex items-center shrink-0">
                      <Button variant="ghost" size="icon" className="h-7 w-7" asChild>
                        <a href={`/?evaluation=${evaluation.id}`} data-testid={`link-evaluation-${evaluation.id}`}>
                          <ArrowUpRight className="h-3.5 w-3.5" />
                        </a>
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        onClick={() => deleteMutation.mutate(evaluation.id)}
                        disabled={deleteMutation.isPending}
                        data-testid={`btn-delete-risk-${evaluation.id}`}
                      >
                        <Trash2 className="h-3.5 w-3.5 text-muted-foreground" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
