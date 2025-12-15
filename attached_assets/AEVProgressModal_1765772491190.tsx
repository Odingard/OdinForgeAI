import { useEffect, useState } from "react";
import {
  Zap,
  Search,
  Link,
  Shield,
  Lightbulb,
  CheckCircle,
  Loader2,
  AlertTriangle,
  X,
  Target,
} from "lucide-react";

export interface AEVProgressData {
  evaluationId: string;
  progress: number;
  stage: string;
  currentStage?: number;
  stageName?: string;
  stageDetails?: string;
}

export interface AEVCompleteData {
  evaluationId: string;
  exploitable: boolean;
  confidence: number;
  score: number;
  status: string;
  error?: string;
}

interface AEVProgressModalProps {
  isOpen: boolean;
  onClose: () => void;
  evaluationId: string | null;
  progress: AEVProgressData | null;
  result: AEVCompleteData | null;
  assetId?: string;
}

interface Stage {
  id: number;
  name: string;
  description: string;
  icon: typeof Search;
  progressRange: [number, number];
}

const stages: Stage[] = [
  {
    id: 1,
    name: "Analyzing Exposure",
    description: "Examining vulnerability characteristics and attack surface",
    icon: Search,
    progressRange: [0, 25],
  },
  {
    id: 2,
    name: "Simulating Exploit Chain",
    description: "Testing potential attack vectors and exploit paths",
    icon: Link,
    progressRange: [25, 50],
  },
  {
    id: 3,
    name: "Impact Assessment",
    description: "Evaluating potential damage and blast radius",
    icon: Shield,
    progressRange: [50, 75],
  },
  {
    id: 4,
    name: "Recommendations",
    description: "Generating remediation strategies and mitigations",
    icon: Lightbulb,
    progressRange: [75, 100],
  },
];

function getCurrentStage(progress: number): number {
  for (let i = stages.length - 1; i >= 0; i--) {
    if (progress >= stages[i].progressRange[0]) {
      return i + 1;
    }
  }
  return 1;
}

function getStageProgress(stageId: number, overallProgress: number): "pending" | "active" | "complete" {
  const stage = stages[stageId - 1];
  if (!stage) return "pending";
  
  if (overallProgress >= stage.progressRange[1]) {
    return "complete";
  } else if (overallProgress >= stage.progressRange[0]) {
    return "active";
  }
  return "pending";
}

export function AEVProgressModal({
  isOpen,
  onClose,
  evaluationId,
  progress,
  result,
  assetId,
}: AEVProgressModalProps) {
  const [currentProgress, setCurrentProgress] = useState(0);
  const [showResult, setShowResult] = useState(false);

  useEffect(() => {
    if (progress) {
      setCurrentProgress(progress.progress);
    }
  }, [progress]);

  useEffect(() => {
    if (result) {
      setCurrentProgress(100);
      setTimeout(() => setShowResult(true), 500);
    } else {
      setShowResult(false);
    }
  }, [result]);

  useEffect(() => {
    if (!isOpen) {
      setCurrentProgress(0);
      setShowResult(false);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const isComplete = result?.status === "completed";
  const isFailed = result?.status === "failed";
  const currentStage = getCurrentStage(currentProgress);

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div 
        className="bg-card border border-border rounded-xl w-full max-w-lg shadow-2xl overflow-hidden"
        data-testid="aev-progress-modal"
      >
        <div className="bg-gradient-to-r from-primary/20 to-orange-500/20 border-b border-border p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary/20 rounded-lg">
                <Zap className="h-5 w-5 text-primary" />
              </div>
              <div>
                <h3 className="font-semibold text-foreground">AEV Evaluation</h3>
                <p className="text-xs text-muted-foreground">
                  {assetId ? `Target: ${assetId}` : evaluationId || "Processing..."}
                </p>
              </div>
            </div>
            {(isComplete || isFailed) && (
              <button
                onClick={onClose}
                className="p-1.5 hover:bg-muted rounded-lg transition-colors"
                data-testid="button-close-progress"
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>
        </div>

        <div className="p-6">
          {!showResult ? (
            <>
              <div className="mb-6">
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-muted-foreground">Progress</span>
                  <span className="font-mono text-foreground">{Math.round(currentProgress)}%</span>
                </div>
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-primary to-orange-500 transition-all duration-500 ease-out"
                    style={{ width: `${currentProgress}%` }}
                  />
                </div>
              </div>

              <div className="space-y-3">
                {stages.map((stage) => {
                  const stageStatus = getStageProgress(stage.id, currentProgress);
                  const Icon = stage.icon;
                  
                  return (
                    <div
                      key={stage.id}
                      className={`flex items-start gap-3 p-3 rounded-lg border transition-all duration-300 ${
                        stageStatus === "active"
                          ? "bg-primary/10 border-primary/30 shadow-sm"
                          : stageStatus === "complete"
                          ? "bg-emerald-500/10 border-emerald-500/30"
                          : "bg-muted/30 border-border opacity-50"
                      }`}
                      data-testid={`stage-${stage.id}`}
                    >
                      <div
                        className={`p-2 rounded-lg flex-shrink-0 ${
                          stageStatus === "active"
                            ? "bg-primary/20"
                            : stageStatus === "complete"
                            ? "bg-emerald-500/20"
                            : "bg-muted"
                        }`}
                      >
                        {stageStatus === "active" ? (
                          <Loader2 className="h-4 w-4 text-primary animate-spin" />
                        ) : stageStatus === "complete" ? (
                          <CheckCircle className="h-4 w-4 text-emerald-400" />
                        ) : (
                          <Icon className="h-4 w-4 text-muted-foreground" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span
                            className={`text-sm font-medium ${
                              stageStatus === "pending"
                                ? "text-muted-foreground"
                                : "text-foreground"
                            }`}
                          >
                            {stage.name}
                          </span>
                          {stageStatus === "active" && (
                            <span className="text-[10px] font-medium text-primary bg-primary/20 px-1.5 py-0.5 rounded">
                              IN PROGRESS
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          {stageStatus === "active" && progress?.stage
                            ? progress.stage
                            : stage.description}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="mt-6 p-3 bg-muted/30 rounded-lg border border-border">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Target className="h-3.5 w-3.5 text-primary" />
                  <span>
                    {progress?.stage || "Initializing autonomous exploit validation..."}
                  </span>
                </div>
              </div>
            </>
          ) : (
            <div className="space-y-4">
              <div
                className={`p-4 rounded-lg border ${
                  isFailed
                    ? "bg-red-500/10 border-red-500/30"
                    : result?.exploitable
                    ? "bg-red-500/10 border-red-500/30"
                    : "bg-emerald-500/10 border-emerald-500/30"
                }`}
              >
                <div className="flex items-center gap-3">
                  {isFailed ? (
                    <AlertTriangle className="h-8 w-8 text-red-400" />
                  ) : result?.exploitable ? (
                    <AlertTriangle className="h-8 w-8 text-red-400" />
                  ) : (
                    <CheckCircle className="h-8 w-8 text-emerald-400" />
                  )}
                  <div>
                    <h4 className="font-semibold text-lg">
                      {isFailed
                        ? "Evaluation Failed"
                        : result?.exploitable
                        ? "Exploitable"
                        : "Not Exploitable"}
                    </h4>
                    <p className="text-sm text-muted-foreground">
                      {isFailed
                        ? result?.error || "An error occurred during evaluation"
                        : result?.exploitable
                        ? "This exposure can be actively exploited"
                        : "No viable exploit path found"}
                    </p>
                  </div>
                </div>
              </div>

              {!isFailed && (
                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 bg-muted/30 rounded-lg border border-border">
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
                      Confidence
                    </div>
                    <div className="text-xl font-bold text-foreground">
                      {Math.round((result?.confidence || 0) * 100)}%
                    </div>
                  </div>
                  <div className="p-3 bg-muted/30 rounded-lg border border-border">
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
                      Risk Score
                    </div>
                    <div
                      className={`text-xl font-bold ${
                        (result?.score || 0) > 70
                          ? "text-red-400"
                          : (result?.score || 0) > 40
                          ? "text-orange-400"
                          : "text-emerald-400"
                      }`}
                    >
                      {result?.score?.toFixed(1) || "0"}
                    </div>
                  </div>
                </div>
              )}

              <button
                onClick={onClose}
                className="w-full px-4 py-2.5 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 transition-colors"
                data-testid="button-view-details"
              >
                View Full Details
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
