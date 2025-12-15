import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Clock, TrendingUp, Shield, Filter, ArrowUpRight, Building2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { useState } from "react";

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
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [timeframeFilter, setTimeframeFilter] = useState<string>("all");

  const { data: evaluations = [], isLoading } = useQuery<EvaluationWithScore[]>({
    queryKey: ["/api/aev/evaluations"],
  });

  const evaluationsWithScores = evaluations.filter(e => e.intelligentScore);

  const filteredEvaluations = evaluationsWithScores
    .filter(e => {
      if (riskFilter !== "all" && e.intelligentScore?.riskRank.riskLevel !== riskFilter) return false;
      if (timeframeFilter !== "all" && e.intelligentScore?.riskRank.recommendation.timeframe !== timeframeFilter) return false;
      return true;
    })
    .sort((a, b) => {
      const aPriority = a.intelligentScore?.riskRank.fixPriority ?? 100;
      const bPriority = b.intelligentScore?.riskRank.fixPriority ?? 100;
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
    critical: evaluationsWithScores.filter(e => e.intelligentScore?.riskRank.riskLevel === "critical" || e.intelligentScore?.riskRank.riskLevel === "emergency").length,
    high: evaluationsWithScores.filter(e => e.intelligentScore?.riskRank.riskLevel === "high").length,
    medium: evaluationsWithScores.filter(e => e.intelligentScore?.riskRank.riskLevel === "medium").length,
    low: evaluationsWithScores.filter(e => e.intelligentScore?.riskRank.riskLevel === "low" || e.intelligentScore?.riskRank.riskLevel === "info").length,
    totalExposure: evaluationsWithScores.reduce((sum, e) => {
      const max = e.intelligentScore?.businessImpact.factors.financialExposure.directLoss.max || 0;
      return sum + max;
    }, 0),
    avgRiskScore: evaluationsWithScores.length > 0
      ? Math.round(evaluationsWithScores.reduce((sum, e) => sum + (e.intelligentScore?.riskRank.overallScore || 0), 0) / evaluationsWithScores.length)
      : 0,
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div className="animate-pulse space-y-4">
          <div className="h-8 w-48 bg-muted rounded" />
          <div className="grid grid-cols-4 gap-4">
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="h-32 bg-muted rounded-lg" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6" data-testid="risk-dashboard">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Risk Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Executive view of security risks prioritized by business impact
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <Select value={riskFilter} onValueChange={setRiskFilter}>
              <SelectTrigger className="w-[140px]" data-testid="select-risk-filter">
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
          </div>
          <Select value={timeframeFilter} onValueChange={setTimeframeFilter}>
            <SelectTrigger className="w-[140px]" data-testid="select-timeframe-filter">
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
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Critical/Emergency</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-foreground" data-testid="stat-critical">{stats.critical}</div>
            <p className="text-xs text-muted-foreground mt-1">Require immediate attention</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">High Priority</CardTitle>
            <TrendingUp className="h-4 w-4 text-orange-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-foreground" data-testid="stat-high">{stats.high}</div>
            <p className="text-xs text-muted-foreground mt-1">Should be addressed soon</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total Exposure</CardTitle>
            <Building2 className="h-4 w-4 text-cyan-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-foreground" data-testid="stat-exposure">{formatCurrency(stats.totalExposure)}</div>
            <p className="text-xs text-muted-foreground mt-1">Maximum financial risk</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Avg Risk Score</CardTitle>
            <Shield className="h-4 w-4 text-purple-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-foreground" data-testid="stat-avg-score">{stats.avgRiskScore}</div>
            <Progress value={stats.avgRiskScore} className="mt-2 h-1.5" />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5 text-cyan-400" />
            Fix Priority Queue
          </CardTitle>
        </CardHeader>
        <CardContent>
          {filteredEvaluations.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Shield className="h-12 w-12 mx-auto mb-3 opacity-30" />
              <p>No evaluations with intelligent scores yet</p>
              <p className="text-sm mt-1">Run an evaluation to see risk prioritization</p>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredEvaluations.map((evaluation, index) => (
                <div
                  key={evaluation.id}
                  className="flex items-center gap-4 p-4 bg-muted/20 rounded-lg border border-border hover-elevate"
                  data-testid={`risk-item-${evaluation.id}`}
                >
                  <div className="flex items-center justify-center w-8 h-8 rounded-full bg-muted font-mono text-sm font-bold">
                    {index + 1}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium text-foreground truncate">{evaluation.assetId}</span>
                      <Badge className={getRiskLevelColor(evaluation.intelligentScore?.riskRank.riskLevel || "medium")}>
                        {evaluation.intelligentScore?.riskRank.riskLevel?.toUpperCase()}
                      </Badge>
                      <Badge className={getTimeframeColor(evaluation.intelligentScore?.riskRank.recommendation.timeframe || "30_days")}>
                        <Clock className="h-3 w-3 mr-1" />
                        {getTimeframeLabel(evaluation.intelligentScore?.riskRank.recommendation.timeframe || "30_days")}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1 truncate">
                      {evaluation.intelligentScore?.riskRank.executiveLabel}
                    </p>
                  </div>

                  <div className="text-right hidden sm:block">
                    <div className="text-sm text-muted-foreground">Financial Exposure</div>
                    <div className="font-semibold text-foreground">
                      {formatCurrency(evaluation.intelligentScore?.businessImpact.factors.financialExposure.directLoss.max || 0)}
                    </div>
                  </div>

                  <div className="text-right hidden md:block">
                    <div className="text-sm text-muted-foreground">Risk Score</div>
                    <div className="font-mono font-bold text-lg text-foreground">
                      {evaluation.intelligentScore?.riskRank.overallScore}
                    </div>
                  </div>

                  <div className="hidden lg:flex flex-wrap gap-1 max-w-[150px]">
                    {evaluation.intelligentScore?.businessImpact.factors.complianceImpact.affectedFrameworks.slice(0, 3).map((fw) => (
                      <Badge key={fw} variant="outline" className="text-xs">
                        {fw.toUpperCase()}
                      </Badge>
                    ))}
                  </div>

                  <Button variant="ghost" size="icon" asChild>
                    <a href={`/?evaluation=${evaluation.id}`} data-testid={`link-evaluation-${evaluation.id}`}>
                      <ArrowUpRight className="h-4 w-4" />
                    </a>
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {evaluationsWithScores.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Risk Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Critical/Emergency</span>
                  <div className="flex items-center gap-2">
                    <Progress value={(stats.critical / evaluationsWithScores.length) * 100} className="w-32 h-2" />
                    <span className="text-sm font-mono w-8">{stats.critical}</span>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">High</span>
                  <div className="flex items-center gap-2">
                    <Progress value={(stats.high / evaluationsWithScores.length) * 100} className="w-32 h-2" />
                    <span className="text-sm font-mono w-8">{stats.high}</span>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Medium</span>
                  <div className="flex items-center gap-2">
                    <Progress value={(stats.medium / evaluationsWithScores.length) * 100} className="w-32 h-2" />
                    <span className="text-sm font-mono w-8">{stats.medium}</span>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Low/Info</span>
                  <div className="flex items-center gap-2">
                    <Progress value={(stats.low / evaluationsWithScores.length) * 100} className="w-32 h-2" />
                    <span className="text-sm font-mono w-8">{stats.low}</span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Top Actions Required</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {filteredEvaluations.slice(0, 5).map((evaluation) => (
                  <div key={evaluation.id} className="flex items-start gap-3">
                    <AlertTriangle className={`h-4 w-4 mt-0.5 ${
                      evaluation.intelligentScore?.riskRank.riskLevel === "critical" || evaluation.intelligentScore?.riskRank.riskLevel === "emergency"
                        ? "text-red-400"
                        : evaluation.intelligentScore?.riskRank.riskLevel === "high"
                        ? "text-orange-400"
                        : "text-amber-400"
                    }`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-foreground truncate">
                        {evaluation.intelligentScore?.riskRank.recommendation.action}
                      </p>
                      <p className="text-xs text-muted-foreground">{evaluation.assetId}</p>
                    </div>
                  </div>
                ))}
                {filteredEvaluations.length === 0 && (
                  <p className="text-sm text-muted-foreground text-center py-4">No actions pending</p>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
