import { useQuery } from "@tanstack/react-query";
import { Server, Shield, AlertTriangle, CheckCircle, Clock } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";

interface Evaluation {
  id: string;
  assetId: string;
  exposureType: string;
  priority: string;
  status: string;
  createdAt: string;
  exploitable?: boolean;
  score?: number;
}

interface AssetSummary {
  assetId: string;
  evaluationCount: number;
  exploitableCount: number;
  highestPriority: string;
  latestEvaluation: string;
  avgScore: number;
  exposureTypes: string[];
}

export default function Assets() {
  const { data: evaluations = [], isLoading } = useQuery<Evaluation[]>({
    queryKey: ["/api/aev/evaluations"],
  });

  const assetSummaries: AssetSummary[] = (() => {
    const assetMap = new Map<string, Evaluation[]>();
    
    evaluations.forEach(e => {
      const existing = assetMap.get(e.assetId) || [];
      assetMap.set(e.assetId, [...existing, e]);
    });

    return Array.from(assetMap.entries()).map(([assetId, evals]) => {
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      const sorted = [...evals].sort((a, b) => 
        (priorityOrder[a.priority as keyof typeof priorityOrder] ?? 4) - 
        (priorityOrder[b.priority as keyof typeof priorityOrder] ?? 4)
      );
      
      const scores = evals.filter(e => e.score !== undefined).map(e => e.score!);
      const avgScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
      
      return {
        assetId,
        evaluationCount: evals.length,
        exploitableCount: evals.filter(e => e.exploitable).length,
        highestPriority: sorted[0]?.priority || "low",
        latestEvaluation: evals.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())[0]?.createdAt || "",
        avgScore,
        exposureTypes: Array.from(new Set(evals.map(e => e.exposureType))),
      };
    }).sort((a, b) => b.exploitableCount - a.exploitableCount);
  })();

  const getPriorityBadge = (priority: string) => {
    const styles: Record<string, string> = {
      critical: "bg-red-500/10 text-red-400 border-red-500/30",
      high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
      medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
      low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    };
    return styles[priority] || styles.low;
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div className="animate-pulse space-y-4">
          <div className="h-8 w-48 bg-muted rounded" />
          <div className="grid grid-cols-3 gap-4">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-40 bg-muted rounded-lg" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="assets-page">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Assets</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Overview of all evaluated assets and their security posture
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total Assets</CardTitle>
            <Server className="h-4 w-4 text-cyan-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-foreground" data-testid="stat-total-assets">
              {assetSummaries.length}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">At Risk</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-foreground" data-testid="stat-at-risk">
              {assetSummaries.filter(a => a.exploitableCount > 0).length}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Secure</CardTitle>
            <CheckCircle className="h-4 w-4 text-emerald-400" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-foreground" data-testid="stat-secure">
              {assetSummaries.filter(a => a.exploitableCount === 0).length}
            </div>
          </CardContent>
        </Card>
      </div>

      {assetSummaries.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Server className="h-12 w-12 mx-auto mb-3 text-muted-foreground opacity-30" />
            <p className="text-muted-foreground">No assets evaluated yet</p>
            <p className="text-sm text-muted-foreground mt-1">Run an evaluation to see assets here</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {assetSummaries.map((asset) => (
            <Card key={asset.assetId} className="hover-elevate" data-testid={`asset-card-${asset.assetId}`}>
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <div className="p-2 rounded-lg bg-muted/50">
                      <Server className="h-4 w-4 text-cyan-400" />
                    </div>
                    <CardTitle className="text-sm font-medium truncate" title={asset.assetId}>
                      {asset.assetId}
                    </CardTitle>
                  </div>
                  <Badge className={getPriorityBadge(asset.highestPriority)}>
                    {asset.highestPriority.toUpperCase()}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Evaluations</span>
                  <span className="font-mono">{asset.evaluationCount}</span>
                </div>
                
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Exploitable</span>
                  <span className={`font-mono ${asset.exploitableCount > 0 ? "text-red-400" : "text-emerald-400"}`}>
                    {asset.exploitableCount}
                  </span>
                </div>

                <div>
                  <div className="flex items-center justify-between text-sm mb-1">
                    <span className="text-muted-foreground">Avg Risk Score</span>
                    <span className="font-mono">{asset.avgScore}</span>
                  </div>
                  <Progress value={asset.avgScore} className="h-1.5" />
                </div>

                <div className="flex items-center gap-1 flex-wrap">
                  {asset.exposureTypes.slice(0, 3).map((type) => (
                    <Badge key={type} variant="outline" className="text-xs">
                      {type.replace("_", " ")}
                    </Badge>
                  ))}
                  {asset.exposureTypes.length > 3 && (
                    <Badge variant="outline" className="text-xs">
                      +{asset.exposureTypes.length - 3}
                    </Badge>
                  )}
                </div>

                <div className="flex items-center gap-1 text-xs text-muted-foreground">
                  <Clock className="h-3 w-3" />
                  <span>Last: {new Date(asset.latestEvaluation).toLocaleDateString()}</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
