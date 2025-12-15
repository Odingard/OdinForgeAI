import { useEffect, useState } from "react";
import {
  Zap,
  Search,
  Link2,
  Shield,
  Lightbulb,
  CheckCircle,
  Loader2,
  AlertTriangle,
  X,
  Target,
  Brain,
} from "lucide-react";
import { Button } from "@/components/ui/button";

interface Stage {
  id: number;
  name: string;
  description: string;
  icon: typeof Search;
}

const stages: Stage[] = [
  {
    id: 1,
    name: "Attack Surface Analysis",
    description: "AI reconnaissance agent mapping vulnerabilities and entry points",
    icon: Search,
  },
  {
    id: 2,
    name: "Autonomous Exploit Chain",
    description: "Multi-agent system discovering and chaining attack vectors",
    icon: Link2,
  },
  {
    id: 3,
    name: "Business Impact Assessment",
    description: "Calculating blast radius, data exposure, and financial risk",
    icon: Shield,
  },
  {
    id: 4,
    name: "Intelligent Remediation",
    description: "Generating context-aware fixes and compensating controls",
    icon: Lightbulb,
  },
];

interface ProgressModalProps {
  isOpen: boolean;
  onClose: () => void;
  assetId: string;
  evaluationId: string;
  progressData?: { stage: string; progress: number; message: string } | null;
}

export function ProgressModal({ isOpen, onClose, assetId, evaluationId, progressData }: ProgressModalProps) {
  const [progress, setProgress] = useState(0);
  const [currentStage, setCurrentStage] = useState(1);
  const [stageMessage, setStageMessage] = useState("Initializing AI agents...");
  const [isComplete, setIsComplete] = useState(false);

  useEffect(() => {
    if (!isOpen) {
      setProgress(0);
      setCurrentStage(1);
      setIsComplete(false);
      setStageMessage("Initializing AI agents...");
      return;
    }
  }, [isOpen]);

  useEffect(() => {
    if (progressData) {
      setProgress(progressData.progress);
      setStageMessage(progressData.message);
      
      const stageMap: Record<string, number> = {
        attack_surface: 1,
        exploit_chain: 2,
        impact: 3,
        remediation: 4,
      };
      setCurrentStage(stageMap[progressData.stage] || 1);
      
      if (progressData.progress >= 100) {
        setIsComplete(true);
      }
    }
  }, [progressData]);

  if (!isOpen) return null;

  const getStageStatus = (stageId: number): "pending" | "active" | "complete" => {
    if (progress >= stageId * 25) return "complete";
    if (currentStage === stageId) return "active";
    return "pending";
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div 
        className="bg-card border border-border rounded-xl w-full max-w-lg shadow-2xl overflow-hidden"
        data-testid="progress-modal"
      >
        <div className="bg-gradient-to-r from-cyan-600/20 via-blue-600/20 to-purple-600/20 border-b border-border p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="relative">
                <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 to-purple-500 blur-lg opacity-50 animate-pulse" />
                <div className="relative p-2 bg-gradient-to-br from-cyan-500 via-blue-500 to-purple-500 rounded-lg">
                  <Brain className="h-5 w-5 text-white" />
                </div>
              </div>
              <div>
                <h3 className="font-semibold text-foreground">Autonomous Validation</h3>
                <p className="text-xs text-muted-foreground font-mono">{assetId}</p>
              </div>
            </div>
            {isComplete && (
              <Button variant="ghost" size="icon" onClick={onClose} data-testid="button-close-progress">
                <X className="h-4 w-4" />
              </Button>
            )}
          </div>
        </div>

        <div className="p-6">
          {!isComplete ? (
            <>
              <div className="mb-6">
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-muted-foreground">AI Agent Progress</span>
                  <span className="font-mono text-foreground">{Math.round(progress)}%</span>
                </div>
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-500 transition-all duration-300 ease-out"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>

              <div className="space-y-3">
                {stages.map((stage) => {
                  const status = getStageStatus(stage.id);
                  const Icon = stage.icon;
                  
                  return (
                    <div
                      key={stage.id}
                      className={`flex items-start gap-3 p-3 rounded-lg border transition-all duration-300 ${
                        status === "active"
                          ? "bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border-cyan-500/30"
                          : status === "complete"
                          ? "bg-emerald-500/10 border-emerald-500/30"
                          : "bg-muted/30 border-border opacity-50"
                      }`}
                      data-testid={`stage-${stage.id}`}
                    >
                      <div className={`p-2 rounded-lg flex-shrink-0 ${
                        status === "active"
                          ? "bg-gradient-to-br from-cyan-500/20 to-blue-500/20"
                          : status === "complete"
                          ? "bg-emerald-500/20"
                          : "bg-muted"
                      }`}>
                        {status === "active" ? (
                          <Loader2 className="h-4 w-4 text-cyan-400 animate-spin" />
                        ) : status === "complete" ? (
                          <CheckCircle className="h-4 w-4 text-emerald-400" />
                        ) : (
                          <Icon className="h-4 w-4 text-muted-foreground" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={`text-sm font-medium ${
                            status === "pending" ? "text-muted-foreground" : "text-foreground"
                          }`}>
                            {stage.name}
                          </span>
                          {status === "active" && (
                            <span className="text-[10px] font-medium text-cyan-400 bg-cyan-500/20 px-1.5 py-0.5 rounded">
                              ACTIVE
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          {status === "active" ? stageMessage : stage.description}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="mt-6 p-3 bg-muted/30 rounded-lg border border-border">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Target className="h-3.5 w-3.5 text-cyan-400 animate-pulse" />
                  <span className="font-mono">{stageMessage}</span>
                </div>
              </div>
            </>
          ) : (
            <div className="space-y-4">
              <div className="p-4 rounded-lg border bg-emerald-500/10 border-emerald-500/30">
                <div className="flex items-center gap-3">
                  <CheckCircle className="h-8 w-8 text-emerald-400" />
                  <div>
                    <h4 className="font-semibold text-lg">Analysis Complete</h4>
                    <p className="text-sm text-muted-foreground">
                      AI validation finished successfully
                    </p>
                  </div>
                </div>
              </div>

              <Button
                onClick={onClose}
                className="w-full bg-gradient-to-r from-cyan-600 to-blue-600"
                data-testid="button-view-details"
              >
                View Full Analysis
              </Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
