import { ArrowLeft, Clock, Activity, FileText, Shield, Target, Lightbulb } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AttackPathVisualizer } from "./AttackPathVisualizer";
import { ExploitabilityGauge } from "./ExploitabilityGauge";
import { RecommendationsPanel } from "./RecommendationsPanel";

interface EvaluationDetailProps {
  evaluation: {
    id: string;
    assetId: string;
    exposureType: string;
    priority: string;
    description: string;
    status: string;
    exploitable?: boolean;
    score?: number;
    confidence?: number;
    createdAt: string;
    duration?: number;
    attackPath?: Array<{
      id: number;
      title: string;
      description: string;
      technique?: string;
      severity: "critical" | "high" | "medium" | "low";
    }>;
    recommendations?: Array<{
      id: string;
      title: string;
      description: string;
      priority: "critical" | "high" | "medium" | "low";
      type: "remediation" | "compensating" | "preventive";
    }>;
  };
  onBack: () => void;
}

export function EvaluationDetail({ evaluation, onBack }: EvaluationDetailProps) {
  const getSeverityBadge = (priority: string) => {
    const classes: Record<string, string> = {
      critical: "bg-red-500/10 text-red-400 border-red-500/30",
      high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
      medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
      low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    };
    return classes[priority] || "";
  };

  return (
    <div className="space-y-6" data-testid="evaluation-detail">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={onBack} data-testid="button-back">
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-2xl font-bold text-foreground">AEV Evaluation</h1>
              <Badge className={evaluation.exploitable 
                ? "bg-red-500/10 text-red-400 border-red-500/30" 
                : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
              }>
                {evaluation.exploitable ? "EXPLOITABLE" : "NOT EXPLOITABLE"}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground font-mono mt-1">{evaluation.id}</p>
          </div>
        </div>
        <div className="flex items-center gap-4 text-sm text-muted-foreground">
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4" />
            <span>{new Date(evaluation.createdAt).toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4" />
            <span>{(evaluation.duration / 1000).toFixed(1)}s</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-border bg-muted/30">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-cyan-500/10">
                  <FileText className="h-5 w-5 text-cyan-400" />
                </div>
                <h2 className="text-lg font-semibold text-foreground">Exposure Summary</h2>
              </div>
            </div>
            <div className="p-6 space-y-6">
              <div className="grid grid-cols-2 gap-6">
                <div>
                  <label className="text-xs uppercase tracking-wider text-muted-foreground mb-1 block">
                    Asset ID
                  </label>
                  <p className="text-foreground font-mono text-sm">{evaluation.assetId}</p>
                </div>
                <div>
                  <label className="text-xs uppercase tracking-wider text-muted-foreground mb-1 block">
                    Exposure Type
                  </label>
                  <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/30">
                    {evaluation.exposureType.replace("_", " ").toUpperCase()}
                  </Badge>
                </div>
                <div>
                  <label className="text-xs uppercase tracking-wider text-muted-foreground mb-1 block">
                    Severity
                  </label>
                  <Badge className={getSeverityBadge(evaluation.priority)}>
                    {evaluation.priority.toUpperCase()}
                  </Badge>
                </div>
                <div>
                  <label className="text-xs uppercase tracking-wider text-muted-foreground mb-1 block">
                    Status
                  </label>
                  <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                    {evaluation.status.toUpperCase()}
                  </Badge>
                </div>
              </div>
              <div>
                <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
                  Description
                </label>
                <p className="text-muted-foreground leading-relaxed">{evaluation.description}</p>
              </div>
            </div>
          </div>

          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-border bg-muted/30">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-orange-500/10">
                  <Target className="h-5 w-5 text-orange-400" />
                </div>
                <h2 className="text-lg font-semibold text-foreground">Attack Path Analysis</h2>
              </div>
            </div>
            <div className="p-6">
              <AttackPathVisualizer 
                steps={evaluation.attackPath} 
                isExploitable={evaluation.exploitable} 
              />
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-border bg-muted/30">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-purple-500/10">
                  <Shield className="h-5 w-5 text-purple-400" />
                </div>
                <h2 className="text-lg font-semibold text-foreground">Exploitability Score</h2>
              </div>
            </div>
            <div className="p-6">
              <ExploitabilityGauge 
                score={evaluation.score} 
                confidence={evaluation.confidence}
                size="md"
              />
            </div>
          </div>

          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-border bg-muted/30">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-emerald-500/10">
                  <Lightbulb className="h-5 w-5 text-emerald-400" />
                </div>
                <h2 className="text-lg font-semibold text-foreground">Recommendations</h2>
              </div>
            </div>
            <div className="p-6">
              <RecommendationsPanel recommendations={evaluation.recommendations} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
