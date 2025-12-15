import { Shield, AlertTriangle, ChevronRight, Lock, Database, Server, Globe, Key } from "lucide-react";

interface AttackStep {
  id: number;
  title: string;
  description: string;
  technique?: string;
  severity: "critical" | "high" | "medium" | "low";
}

interface AttackPathVisualizerProps {
  steps: AttackStep[];
  isExploitable: boolean;
}

export function AttackPathVisualizer({ steps, isExploitable }: AttackPathVisualizerProps) {
  const getStepIcon = (index: number) => {
    const icons = [Globe, Key, Lock, Server, Database];
    const Icon = icons[index % icons.length];
    return Icon;
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "border-red-500/50 bg-red-500/10 text-red-400";
      case "high": return "border-orange-500/50 bg-orange-500/10 text-orange-400";
      case "medium": return "border-amber-500/50 bg-amber-500/10 text-amber-400";
      case "low": return "border-emerald-500/50 bg-emerald-500/10 text-emerald-400";
      default: return "border-border bg-muted/30 text-muted-foreground";
    }
  };

  if (steps.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <div className="p-4 rounded-full bg-emerald-500/10 mb-4">
          <Shield className="h-10 w-10 text-emerald-400" />
        </div>
        <h4 className="font-semibold text-emerald-400">No Attack Path Identified</h4>
        <p className="text-sm text-muted-foreground mt-1 max-w-xs">
          The AI agents could not find a viable exploit chain for this exposure.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="attack-path-visualizer">
      <div className="flex items-center gap-2 mb-4">
        <AlertTriangle className={`h-5 w-5 ${isExploitable ? "text-red-400" : "text-emerald-400"}`} />
        <span className={`text-sm font-medium ${isExploitable ? "text-red-400" : "text-emerald-400"}`}>
          {steps.length} Step Attack Chain {isExploitable ? "Discovered" : "Analyzed"}
        </span>
      </div>

      <div className="relative">
        {steps.map((step, index) => {
          const StepIcon = getStepIcon(index);
          return (
            <div key={step.id} className="flex gap-4" data-testid={`attack-step-${step.id}`}>
              <div className="flex flex-col items-center">
                <div className={`w-10 h-10 rounded-full flex items-center justify-center border-2 ${
                  isExploitable 
                    ? "border-red-500/50 bg-red-500/10" 
                    : "border-cyan-500/50 bg-cyan-500/10"
                }`}>
                  <span className={`text-sm font-bold ${isExploitable ? "text-red-400" : "text-cyan-400"}`}>
                    {index + 1}
                  </span>
                </div>
                {index < steps.length - 1 && (
                  <div className={`w-0.5 h-16 ${isExploitable ? "bg-red-500/30" : "bg-cyan-500/30"}`} />
                )}
              </div>
              <div className={`flex-1 pb-6 ${index === steps.length - 1 ? "" : ""}`}>
                <div className={`p-4 rounded-lg border ${getSeverityColor(step.severity)}`}>
                  <div className="flex items-start gap-3">
                    <StepIcon className="h-5 w-5 flex-shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <h5 className="font-medium text-foreground">{step.title}</h5>
                        {step.technique && (
                          <code className="text-[10px] px-1.5 py-0.5 rounded bg-background/50 text-muted-foreground">
                            {step.technique}
                          </code>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">{step.description}</p>
                    </div>
                    {index < steps.length - 1 && (
                      <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                    )}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
