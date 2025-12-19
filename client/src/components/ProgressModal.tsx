import { useEffect, useState } from "react";
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
} from "lucide-react";
import { Button } from "@/components/ui/button";

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
    name: "Lateral Movement Agent",
    agentKey: "lateral",
    description: "Identifying pivot paths and privilege escalation",
    icon: Network,
  },
  {
    id: 4,
    name: "Business Logic Agent",
    agentKey: "business_logic",
    description: "Detecting workflow abuse and authorization bypass",
    icon: Workflow,
  },
  {
    id: 5,
    name: "Impact Agent",
    agentKey: "impact",
    description: "Assessing data exposure and financial risk",
    icon: TrendingUp,
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
  const [progress, setProgress] = useState(0);
  const [currentAgentKey, setCurrentAgentKey] = useState("recon");
  const [currentAgentName, setCurrentAgentName] = useState("Recon Agent");
  const [stageMessage, setStageMessage] = useState("Initializing AI agents...");
  const [isComplete, setIsComplete] = useState(false);
  const [lastUpdateTime, setLastUpdateTime] = useState<number>(Date.now());
  const [isStuck, setIsStuck] = useState(false);

  useEffect(() => {
    if (!isOpen) {
      setProgress(0);
      setCurrentAgentKey("recon");
      setCurrentAgentName("Recon Agent");
      setIsComplete(false);
      setStageMessage("Initializing AI agents...");
      setLastUpdateTime(Date.now());
      setIsStuck(false);
      return;
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen || isComplete) return;
    
    const checkStuck = setInterval(() => {
      const timeSinceUpdate = Date.now() - lastUpdateTime;
      if (timeSinceUpdate > 60000) {
        setIsStuck(true);
      }
    }, 5000);
    
    return () => clearInterval(checkStuck);
  }, [isOpen, isComplete, lastUpdateTime]);

  useEffect(() => {
    if (progressData) {
      setProgress(progressData.progress);
      setStageMessage(progressData.message);
      setCurrentAgentKey(progressData.stage);
      setLastUpdateTime(Date.now());
      setIsStuck(false);
      if (progressData.agentName) {
        setCurrentAgentName(progressData.agentName);
      }
      
      if (progressData.progress >= 100 || progressData.stage === "complete") {
        setIsComplete(true);
      }
    }
  }, [progressData]);

  if (!isOpen) return null;

  const getStageStatus = (stage: Stage): "pending" | "active" | "complete" => {
    const stageIndex = stages.findIndex(s => s.agentKey === stage.agentKey);
    const currentIndex = stages.findIndex(s => s.agentKey === currentAgentKey);
    
    if (currentAgentKey === "synthesis" || currentAgentKey === "complete") {
      return "complete";
    }
    if (stageIndex < currentIndex) return "complete";
    if (stageIndex === currentIndex) return "active";
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
                <h3 className="font-semibold text-foreground">Multi-Agent Validation</h3>
                <p className="text-xs text-muted-foreground font-mono">{assetId}</p>
              </div>
            </div>
            {(isComplete || isStuck) && (
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
                <div className="flex justify-between text-sm mb-2 gap-2 flex-wrap">
                  <span className="text-muted-foreground">Active: <span className="text-cyan-400 font-medium">{currentAgentName}</span></span>
                  <span className="font-mono text-foreground">{Math.round(progress)}%</span>
                </div>
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-500 transition-all duration-300 ease-out"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>

              <div className="space-y-2">
                {stages.map((stage) => {
                  const status = getStageStatus(stage);
                  const Icon = stage.icon;
                  
                  return (
                    <div
                      key={stage.id}
                      className={`flex items-start gap-3 p-2.5 rounded-lg border transition-all duration-300 ${
                        status === "active"
                          ? "bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border-cyan-500/30"
                          : status === "complete"
                          ? "bg-emerald-500/10 border-emerald-500/30"
                          : "bg-muted/30 border-border opacity-50"
                      }`}
                      data-testid={`stage-${stage.agentKey}`}
                    >
                      <div className={`p-1.5 rounded-lg flex-shrink-0 ${
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
                        <div className="flex items-center gap-2 flex-wrap">
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
                        <p className="text-xs text-muted-foreground mt-0.5 truncate">
                          {status === "active" ? stageMessage : stage.description}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>

              {isStuck && (
                <div className="mt-4 p-3 bg-amber-500/10 rounded-lg border border-amber-500/30">
                  <div className="flex items-center gap-2 text-sm">
                    <AlertTriangle className="h-4 w-4 text-amber-400 flex-shrink-0" />
                    <span className="text-amber-400">Evaluation appears stuck. You can close this and check results later.</span>
                  </div>
                </div>
              )}

              <div className="mt-4 p-3 bg-muted/30 rounded-lg border border-border">
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Target className="h-3.5 w-3.5 text-cyan-400 animate-pulse flex-shrink-0" />
                  <span className="font-mono truncate">{stageMessage}</span>
                </div>
              </div>
            </>
          ) : (
            <div className="space-y-4">
              <div className="p-4 rounded-lg border bg-emerald-500/10 border-emerald-500/30">
                <div className="flex items-center gap-3">
                  <CheckCircle className="h-8 w-8 text-emerald-400 flex-shrink-0" />
                  <div>
                    <h4 className="font-semibold text-lg">Analysis Complete</h4>
                    <p className="text-sm text-muted-foreground">
                      All 5 AI agents finished validation
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
