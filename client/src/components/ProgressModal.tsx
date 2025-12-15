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
}

export function ProgressModal({ isOpen, onClose, assetId, evaluationId }: ProgressModalProps) {
  const [progress, setProgress] = useState(0);
  const [currentStage, setCurrentStage] = useState(1);
  const [stageMessage, setStageMessage] = useState("Initializing AI agents...");
  const [isComplete, setIsComplete] = useState(false);
  const [result, setResult] = useState<{
    exploitable: boolean;
    confidence: number;
    score: number;
  } | null>(null);

  useEffect(() => {
    if (!isOpen) {
      setProgress(0);
      setCurrentStage(1);
      setIsComplete(false);
      setResult(null);
      return;
    }

    const messages = [
      "Initializing reconnaissance agent...",
      "Scanning attack surface...",
      "Enumerating potential vulnerabilities...",
      "Launching exploitation agent swarm...",
      "Testing privilege escalation paths...",
      "Simulating lateral movement...",
      "Evaluating data exposure risk...",
      "Calculating business impact...",
      "Generating remediation strategies...",
      "Compiling evidence and recommendations...",
    ];

    let progressValue = 0;
    const interval = setInterval(() => {
      progressValue += Math.random() * 8 + 2;
      if (progressValue >= 100) {
        progressValue = 100;
        setProgress(100);
        setCurrentStage(4);
        clearInterval(interval);
        
        setTimeout(() => {
          setIsComplete(true);
          setResult({
            exploitable: Math.random() > 0.4,
            confidence: 0.75 + Math.random() * 0.2,
            score: 40 + Math.random() * 50,
          });
        }, 500);
        return;
      }
      
      setProgress(progressValue);
      setCurrentStage(Math.min(4, Math.floor(progressValue / 25) + 1));
      setStageMessage(messages[Math.floor(progressValue / 10)] || messages[messages.length - 1]);
    }, 400);

    return () => clearInterval(interval);
  }, [isOpen]);

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
              <div className={`p-4 rounded-lg border ${
                result?.exploitable
                  ? "bg-red-500/10 border-red-500/30"
                  : "bg-emerald-500/10 border-emerald-500/30"
              }`}>
                <div className="flex items-center gap-3">
                  {result?.exploitable ? (
                    <AlertTriangle className="h-8 w-8 text-red-400" />
                  ) : (
                    <CheckCircle className="h-8 w-8 text-emerald-400" />
                  )}
                  <div>
                    <h4 className="font-semibold text-lg">
                      {result?.exploitable ? "Exploitable" : "Not Exploitable"}
                    </h4>
                    <p className="text-sm text-muted-foreground">
                      {result?.exploitable
                        ? "AI agents discovered viable attack paths"
                        : "No successful exploit chains found"}
                    </p>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-muted/30 rounded-lg border border-border">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
                    AI Confidence
                  </div>
                  <div className="text-xl font-bold text-foreground">
                    {Math.round((result?.confidence || 0) * 100)}%
                  </div>
                </div>
                <div className="p-3 bg-muted/30 rounded-lg border border-border">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">
                    Risk Score
                  </div>
                  <div className={`text-xl font-bold ${
                    (result?.score || 0) >= 70 ? "text-red-400" :
                    (result?.score || 0) >= 40 ? "text-amber-400" :
                    "text-emerald-400"
                  }`}>
                    {result?.score?.toFixed(1) || "0"}
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
