import { Lightbulb, Shield, AlertCircle, CheckCircle, ArrowRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface Recommendation {
  id: string;
  title: string;
  description: string;
  priority: "critical" | "high" | "medium" | "low";
  type: "remediation" | "compensating";
}

interface RecommendationsPanelProps {
  recommendations: Recommendation[];
}

export function RecommendationsPanel({ recommendations }: RecommendationsPanelProps) {
  const remediations = recommendations.filter(r => r.type === "remediation");
  const compensating = recommendations.filter(r => r.type === "compensating");

  const getPriorityIcon = (priority: string) => {
    switch (priority) {
      case "critical": return <AlertCircle className="h-4 w-4 text-red-400" />;
      case "high": return <AlertCircle className="h-4 w-4 text-orange-400" />;
      case "medium": return <Lightbulb className="h-4 w-4 text-amber-400" />;
      default: return <CheckCircle className="h-4 w-4 text-emerald-400" />;
    }
  };

  const getPriorityBadge = (priority: string) => {
    const classes: Record<string, string> = {
      critical: "bg-red-500/10 text-red-400 border-red-500/30",
      high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
      medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
      low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    };
    return <Badge className={classes[priority]}>{priority}</Badge>;
  };

  return (
    <div className="space-y-6" data-testid="recommendations-panel">
      {remediations.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Lightbulb className="h-4 w-4 text-cyan-400" />
            <h4 className="text-sm font-semibold text-foreground uppercase tracking-wider">
              Remediation Steps
            </h4>
          </div>
          <div className="space-y-3">
            {remediations.map((rec, index) => (
              <div 
                key={rec.id}
                className="p-3 rounded-lg border border-border bg-muted/20 hover-elevate"
                data-testid={`remediation-${rec.id}`}
              >
                <div className="flex items-start gap-3">
                  <div className="flex items-center justify-center w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 text-xs font-bold flex-shrink-0">
                    {index + 1}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium text-foreground">{rec.title}</span>
                      {getPriorityBadge(rec.priority)}
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">{rec.description}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {compensating.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Shield className="h-4 w-4 text-purple-400" />
            <h4 className="text-sm font-semibold text-foreground uppercase tracking-wider">
              Compensating Controls
            </h4>
          </div>
          <div className="space-y-2">
            {compensating.map((rec) => (
              <div 
                key={rec.id}
                className="flex items-start gap-2 p-3 rounded-lg border border-border bg-muted/10"
                data-testid={`compensating-${rec.id}`}
              >
                <ArrowRight className="h-4 w-4 text-purple-400 mt-0.5 flex-shrink-0" />
                <div>
                  <span className="text-sm text-foreground">{rec.title}</span>
                  <p className="text-xs text-muted-foreground mt-0.5">{rec.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {recommendations.length === 0 && (
        <div className="text-center py-8">
          <CheckCircle className="h-10 w-10 text-emerald-400 mx-auto mb-3" />
          <p className="text-muted-foreground">No remediation required</p>
        </div>
      )}
    </div>
  );
}
