import { useEffect, useState, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Search,
  Crosshair,
  Network,
  Workflow,
  TrendingUp,
  CheckCircle,
  Loader2,
  X,
  Target,
  Brain,
  AlertTriangle,
  XCircle,
  Sparkles,
  Shield,
  Clock,
} from "lucide-react";
import { Button } from "@/components/ui/button";

interface PhaseProgress {
  phase: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  startedAt?: string;
  completedAt?: string;
  duration?: number;
  message?: string;
  progress?: number;
  error?: string;
  findingSummary?: string;
}

interface ServerProgressData {
  status: string;
  phaseProgress: PhaseProgress[];
  createdAt: string;
  updatedAt: string;
}

interface Stage {
  id: number;
  name: string;
  agentKey: string;
  description: string;
  icon: typeof Search;
}

const stages: Stage[] = [
  {
    id: 1,
    name: "Recon Agent",
    agentKey: "recon",
    description: "Mapping attack surface, entry points, and reconnaissance",
    icon: Search,
  },
  {
    id: 2,
    name: "Exploit Agent",
    agentKey: "exploit",
    description: "Analyzing CVEs, exploit chains, and misconfigurations",
    icon: Crosshair,
  },
  {
    id: 3,
    name: "Business Logic Agent",
    agentKey: "business_logic",
    description: "Detecting workflow abuse and authorization bypass",
    icon: Workflow,
  },
  {
    id: 4,
    name: "Lateral Movement Agent",
    agentKey: "lateral",
    description: "Identifying pivot paths and privilege escalation",
    icon: Network,
  },
  {
    id: 5,
    name: "Impact Agent",
    agentKey: "impact",
    description: "Assessing data exposure and financial risk",
    icon: TrendingUp,
  },
  {
    id: 6,
    name: "Synthesis",
    agentKey: "synthesis",
    description: "Generating final analysis report",
    icon: Sparkles,
  },
  {
    id: 7,
    name: "Finalization",
    agentKey: "finalization",
    description: "Building attack graph, scoring, and remediation",
    icon: Shield,
  },
];

interface ProgressModalProps {
  isOpen: boolean;
  onClose: () => void;
  assetId: string;
  evaluationId: string;
  progressData?: { agentName?: string; stage: string; progress: number; message: string } | null;
}

export function ProgressModal({ isOpen, onClose, assetId, evaluationId, progressData }: ProgressModalProps) {
  const [wsPhases, setWsPhases] = useState<Map<string, { status: string; message: string }>>(new Map());
  const [isComplete, setIsComplete] = useState(false);
  const [isFailed, setIsFailed] = useState(false);
  const [lastWsUpdate, setLastWsUpdate] = useState<number>(Date.now());
  const [currentMessage, setCurrentMessage] = useState("Initializing AI agents...");
  const [currentAgentName, setCurrentAgentName] = useState("Recon Agent");

  // REST polling for phase progress — fallback when WebSocket is stale
  const { data: serverProgress } = useQuery<ServerProgressData>({
    queryKey: [`/api/aev/evaluations/${evaluationId}/progress`],
    enabled: isOpen && !isComplete && !!evaluationId,
    refetchInterval: 3000,
  });

  // Reset state when modal opens/closes
  useEffect(() => {
    if (!isOpen) {
      setWsPhases(new Map());
      setIsComplete(false);
      setIsFailed(false);
      setLastWsUpdate(Date.now());
      setCurrentMessage("Initializing AI agents...");
      setCurrentAgentName("Recon Agent");
    }
  }, [isOpen]);

  // Handle WebSocket progress events
  useEffect(() => {
    if (progressData) {
      setLastWsUpdate(Date.now());
      setCurrentMessage(progressData.message);
      if (progressData.agentName) {
        setCurrentAgentName(progressData.agentName);
      }

      // Map WS stage to our phase keys
      const stageKey = progressData.stage;
      setWsPhases(prev => {
        const next = new Map(prev);
        next.set(stageKey, { status: "running", message: progressData.message });
        return next;
      });

      if (progressData.progress >= 100 || progressData.stage === "complete") {
        setIsComplete(true);
      }
    }
  }, [progressData]);

  // Handle REST polling data — use when WS is stale (no update in 5s)
  useEffect(() => {
    if (!serverProgress?.phaseProgress?.length) return;

    const timeSinceWs = Date.now() - lastWsUpdate;
    const wsIsStale = timeSinceWs > 5000;

    // Check for completion/failure from server
    if (serverProgress.status === "completed") {
      setIsComplete(true);
      return;
    }
    if (serverProgress.status === "failed") {
      setIsFailed(true);
      return;
    }

    // If WS is stale, derive state from server progress
    if (wsIsStale) {
      const runningPhase = serverProgress.phaseProgress.find(p => p.status === "running");
      if (runningPhase) {
        setCurrentMessage(runningPhase.message || `Running ${runningPhase.phase}...`);
        const stage = stages.find(s => s.agentKey === runningPhase.phase);
        if (stage) setCurrentAgentName(stage.name);
      }
    }
  }, [serverProgress, lastWsUpdate]);

  if (!isOpen) return null;

  // Merge WS + REST phase data to determine status for each stage
  const getPhaseStatus = (stage: Stage): "pending" | "running" | "completed" | "failed" => {
    // Prefer server progress if available
    if (serverProgress?.phaseProgress?.length) {
      const serverPhase = serverProgress.phaseProgress.find(p => p.phase === stage.agentKey);
      if (serverPhase) {
        if (serverPhase.status === "running") return "running";
        if (serverPhase.status === "completed") return "completed";
        if (serverPhase.status === "failed") return "failed";
      }
    }

    // Fall back to WS-derived status
    if (isComplete) return "completed";

    const wsPhase = wsPhases.get(stage.agentKey);
    if (wsPhase) return "running";

    // Infer from current agent position (WS stages come as flat progress)
    const stageIndex = stages.findIndex(s => s.agentKey === stage.agentKey);
    const currentStageIndex = stages.findIndex(s => s.name === currentAgentName);
    if (currentStageIndex >= 0) {
      if (stageIndex < currentStageIndex) return "completed";
      if (stageIndex === currentStageIndex) return "running";
    }

    return "pending";
  };

  const getPhaseMessage = (stage: Stage): string => {
    if (serverProgress?.phaseProgress?.length) {
      const sp = serverProgress.phaseProgress.find(p => p.phase === stage.agentKey);
      if (sp?.findingSummary && sp.status === "completed") return sp.findingSummary;
      if (sp?.message && sp.status === "running") return sp.message;
      if (sp?.error && sp.status === "failed") return sp.error;
    }
    const status = getPhaseStatus(stage);
    if (status === "running") return currentMessage;
    return stage.description;
  };

  const getPhaseDuration = (stage: Stage): number | undefined => {
    if (serverProgress?.phaseProgress?.length) {
      const sp = serverProgress.phaseProgress.find(p => p.phase === stage.agentKey);
      return sp?.duration;
    }
    return undefined;
  };

  // Calculate overall progress from phase statuses
  const completedCount = stages.filter(s => getPhaseStatus(s) === "completed").length;
  const overallProgress = isComplete ? 100 : Math.round((completedCount / stages.length) * 100);

  const hasFailedPhase = stages.some(s => getPhaseStatus(s) === "failed");

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
                <h3 className="font-semibold text-foreground">Multi-Agent Validation</h3>
                <p className="text-xs text-muted-foreground font-mono">{assetId}</p>
              </div>
            </div>
            {(isComplete || isFailed) && (
              <Button variant="ghost" size="icon" onClick={onClose} data-testid="button-close-progress">
                <X className="h-4 w-4" />
              </Button>
            )}
          </div>
        </div>

        <div className="p-6">
          {!isComplete && !isFailed ? (
            <>
              <div className="mb-6">
                <div className="flex justify-between text-sm mb-2 gap-2 flex-wrap">
                  <span className="text-muted-foreground">Active: <span className="text-cyan-400 font-medium">{currentAgentName}</span></span>
                  <span className="font-mono text-foreground">{overallProgress}%</span>
                </div>
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-500 transition-all duration-500 ease-out"
                    style={{ width: `${overallProgress}%` }}
                  />
                </div>
              </div>

              <div className="space-y-2">
                {stages.map((stage) => {
                  const status = getPhaseStatus(stage);
                  const Icon = stage.icon;
                  const duration = getPhaseDuration(stage);
                  const message = getPhaseMessage(stage);

                  return (
                    <div
                      key={stage.id}
                      className={`flex items-start gap-3 p-2.5 rounded-lg border transition-all duration-300 ${
                        status === "running"
                          ? "bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border-cyan-500/30"
                          : status === "completed"
                          ? "bg-emerald-500/10 border-emerald-500/30"
                          : status === "failed"
                          ? "bg-red-500/10 border-red-500/30"
                          : "bg-muted/30 border-border opacity-50"
                      }`}
                      data-testid={`stage-${stage.agentKey}`}
                    >
                      <div className={`p-1.5 rounded-lg flex-shrink-0 ${
                        status === "running"
                          ? "bg-gradient-to-br from-cyan-500/20 to-blue-500/20"
                          : status === "completed"
                          ? "bg-emerald-500/20"
                          : status === "failed"
                          ? "bg-red-500/20"
                          : "bg-muted"
                      }`}>
                        {status === "running" ? (
                          <Loader2 className="h-4 w-4 text-cyan-400 animate-spin" />
                        ) : status === "completed" ? (
                          <CheckCircle className="h-4 w-4 text-emerald-400" />
                        ) : status === "failed" ? (
                          <XCircle className="h-4 w-4 text-red-400" />
                        ) : (
                          <Icon className="h-4 w-4 text-muted-foreground" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`text-sm font-medium ${
                            status === "pending" ? "text-muted-foreground" : "text-foreground"
                          }`}>
                            {stage.name}
                          </span>
                          {status === "running" && (
                            <span className="text-[10px] font-medium text-cyan-400 bg-cyan-500/20 px-1.5 py-0.5 rounded">
                              ACTIVE
                            </span>
                          )}
                          {status === "failed" && (
                            <span className="text-[10px] font-medium text-red-400 bg-red-500/20 px-1.5 py-0.5 rounded">
                              FAILED
                            </span>
                          )}
                          {status === "completed" && duration != null && (
                            <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                              <Clock className="h-3 w-3" />
                              {duration < 1000 ? `${duration}ms` : `${(duration / 1000).toFixed(1)}s`}
                            </span>
                          )}
                        </div>
                        <p className={`text-xs mt-0.5 truncate ${
                          status === "failed" ? "text-red-400" : "text-muted-foreground"
                        }`}>
                          {message}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>

              {hasFailedPhase && (
                <div className="mt-4 p-3 bg-amber-500/10 rounded-lg border border-amber-500/30">
                  <div className="flex items-center gap-2 text-sm">
                    <AlertTriangle className="h-4 w-4 text-amber-400 flex-shrink-0" />
                    <span className="text-amber-400">Some phases failed but analysis continues with available data.</span>
                  </div>
                </div>
              )}

              <div className="mt-4 p-3 bg-muted/30 rounded-lg border border-border">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Target className="h-3.5 w-3.5 text-cyan-400 animate-pulse flex-shrink-0" />
                  <span className="font-mono truncate">{currentMessage}</span>
                </div>
              </div>
            </>
          ) : isFailed ? (
            <div className="space-y-4">
              <div className="p-4 rounded-lg border bg-red-500/10 border-red-500/30">
                <div className="flex items-center gap-3">
                  <XCircle className="h-8 w-8 text-red-400 flex-shrink-0" />
                  <div>
                    <h4 className="font-semibold text-lg">Evaluation Failed</h4>
                    <p className="text-sm text-muted-foreground">
                      The evaluation encountered an error. Check logs for details.
                    </p>
                  </div>
                </div>
              </div>

              <Button
                onClick={onClose}
                className="w-full"
                variant="outline"
                data-testid="button-close-failed"
              >
                Close
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="p-4 rounded-lg border bg-emerald-500/10 border-emerald-500/30">
                <div className="flex items-center gap-3">
                  <CheckCircle className="h-8 w-8 text-emerald-400 flex-shrink-0" />
                  <div>
                    <h4 className="font-semibold text-lg">Analysis Complete</h4>
                    <p className="text-sm text-muted-foreground">
                      All {stages.length} AI agents finished validation
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
