import { useQuery } from "@tanstack/react-query";
import { useRoute, Link } from "wouter";
import { useAuth } from "../lib/auth";
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ArrowLeft,
  Activity,
  Clock,
  FileText,
  ChevronRight,
  Loader2,
  AlertCircle,
  Lightbulb,
  Route as RouteIcon,
  BarChart3,
  ShieldCheck,
  ShieldAlert,
  Wrench,
} from "lucide-react";

interface EvaluationInput {
  assetId: string;
  exposureType: string;
  description: string;
  module?: string;
  priority?: string;
}

interface EvaluationResult {
  evaluationId: string;
  exploitable: boolean;
  confidence: number;
  attackPath: string[];
  impact: string;
  recommendedFix: string;
  score: number;
  status: string;
  error?: string;
  duration?: number;
  completedAt?: string;
}

interface EvaluationDetail {
  id: string;
  input: EvaluationInput;
  status: string;
  result?: EvaluationResult;
  createdAt: string;
  updatedAt: string;
}

export default function AEVDetailPage() {
  const { token } = useAuth();
  const [, params] = useRoute("/aev/:id");
  const evaluationId = params?.id;

  const { data: evaluation, isLoading, error } = useQuery<EvaluationDetail>({
    queryKey: [`/api/aev/evaluations/${evaluationId}`],
    enabled: !!evaluationId && !!token,
    retry: 1,
  });

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center" data-testid="loading-state">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-8 h-8 animate-spin text-primary" />
          <p className="text-muted-foreground">Loading evaluation details...</p>
        </div>
      </div>
    );
  }

  if (error || !evaluation) {
    return (
      <div className="min-h-screen p-6">
        <Link href="/aev" className="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground mb-6">
          <ArrowLeft className="w-4 h-4" />
          Back to AEV Dashboard
        </Link>
        <div className="flex flex-col items-center justify-center py-20" data-testid="error-state">
          <AlertCircle className="w-12 h-12 text-destructive mb-4" />
          <h2 className="text-xl font-semibold text-foreground mb-2">Evaluation Not Found</h2>
          <p className="text-muted-foreground">The requested evaluation could not be found or you don't have access to it.</p>
        </div>
      </div>
    );
  }

  const { input, result, status, createdAt } = evaluation;
  const isCompleted = status === "completed" && result;
  const isFailed = status === "failed";
  const isPending = status === "pending" || status === "in_progress";

  const getSeverityColor = (priority?: string) => {
    switch (priority) {
      case "critical": return "text-red-400 bg-red-500/10 border-red-500/30";
      case "high": return "text-orange-400 bg-orange-500/10 border-orange-500/30";
      case "medium": return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
      case "low": return "text-teal-400 bg-teal-500/10 border-teal-500/30";
      default: return "text-muted-foreground bg-muted/10 border-border";
    }
  };

  const getModuleLabel = (module?: string) => {
    switch (module) {
      case "posture": return "OdinPosture";
      case "spear": return "OdinSpear";
      case "sentinel": return "OdinSentinel";
      case "vulnmgmt": return "Vulnerability Management";
      default: return "Unknown";
    }
  };

  const getExposureTypeLabel = (type: string) => {
    switch (type) {
      case "cve": return "CVE";
      case "misconfiguration": return "Misconfiguration";
      case "behavior": return "Behavioral";
      case "network": return "Network";
      case "custom": return "Custom";
      default: return type;
    }
  };

  const getExploitabilityLevel = (score: number) => {
    if (score >= 80) return { level: "Critical", color: "text-red-400", bgColor: "bg-red-500/10" };
    if (score >= 60) return { level: "High", color: "text-orange-400", bgColor: "bg-orange-500/10" };
    if (score >= 40) return { level: "Medium", color: "text-yellow-400", bgColor: "bg-yellow-500/10" };
    if (score >= 20) return { level: "Low", color: "text-teal-400", bgColor: "bg-teal-500/10" };
    return { level: "Minimal", color: "text-green-400", bgColor: "bg-green-500/10" };
  };

  const getConfidenceLevel = (confidence: number) => {
    if (confidence >= 0.9) return { level: "Very High", color: "text-green-400" };
    if (confidence >= 0.75) return { level: "High", color: "text-teal-400" };
    if (confidence >= 0.5) return { level: "Medium", color: "text-yellow-400" };
    if (confidence >= 0.25) return { level: "Low", color: "text-orange-400" };
    return { level: "Very Low", color: "text-red-400" };
  };

  return (
    <div className="min-h-screen p-6 space-y-6" data-testid="aev-detail-page">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link 
            href="/aev" 
            className="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors"
            data-testid="back-link"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-foreground" data-testid="evaluation-title">
                AEV Evaluation
              </h1>
              <span className={`px-2 py-0.5 rounded text-xs font-medium border ${
                isCompleted && result?.exploitable 
                  ? "bg-red-500/10 text-red-400 border-red-500/30"
                  : isCompleted && !result?.exploitable
                  ? "bg-teal-500/10 text-teal-400 border-teal-500/30"
                  : isPending
                  ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/30"
                  : isFailed
                  ? "bg-red-500/10 text-red-400 border-red-500/30"
                  : "bg-muted text-muted-foreground border-border"
              }`} data-testid="status-badge">
                {isCompleted && result?.exploitable ? "EXPLOITABLE" : 
                 isCompleted && !result?.exploitable ? "NOT EXPLOITABLE" :
                 isPending ? "IN PROGRESS" : 
                 isFailed ? "FAILED" : status.toUpperCase()}
              </span>
            </div>
            <p className="text-sm text-muted-foreground mt-1" data-testid="evaluation-id">
              ID: {evaluation.id}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4 text-sm text-muted-foreground">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4" />
            <span data-testid="created-at">Created: {new Date(createdAt).toLocaleString()}</span>
          </div>
          {result?.duration && (
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4" />
              <span data-testid="duration">Duration: {(result.duration / 1000).toFixed(1)}s</span>
            </div>
          )}
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - Exposure Summary and Attack Path */}
        <div className="lg:col-span-2 space-y-6">
          {/* Section 1: Exposure Summary */}
          <div className="bg-card border border-border rounded-lg overflow-hidden" data-testid="exposure-summary-section">
            <div className="px-6 py-4 border-b border-border bg-muted/30">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-primary/10">
                  <FileText className="w-5 h-5 text-primary" />
                </div>
                <h2 className="text-lg font-semibold text-foreground">Exposure Summary</h2>
              </div>
            </div>
            <div className="p-6 space-y-6">
              <div className="grid grid-cols-2 gap-6">
                <div>
                  <label className="text-xs uppercase tracking-wider text-muted-foreground mb-1 block">Asset ID</label>
                  <p className="text-foreground font-mono text-sm" data-testid="asset-id">{input.assetId}</p>
                </div>
                <div>
                  <label className="text-xs uppercase tracking-wider text-muted-foreground mb-1 block">Exposure Type</label>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-1 bg-blue-500/10 text-blue-400 border border-blue-500/30 rounded text-xs font-medium" data-testid="exposure-type">
                      {getExposureTypeLabel(input.exposureType)}
                    </span>
                  </div>
                </div>
                <div>
                  <label className="text-xs uppercase tracking-wider text-muted-foreground mb-1 block">Severity</label>
                  <span className={`inline-flex px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(input.priority)}`} data-testid="severity">
                    {(input.priority || "medium").toUpperCase()}
                  </span>
                </div>
                <div>
                  <label className="text-xs uppercase tracking-wider text-muted-foreground mb-1 block">Source Module</label>
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-primary" />
                    <span className="text-foreground" data-testid="source-module">{getModuleLabel(input.module)}</span>
                  </div>
                </div>
              </div>
              <div>
                <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">Description</label>
                <p className="text-muted-foreground leading-relaxed" data-testid="description">{input.description}</p>
              </div>
            </div>
          </div>

          {/* Section 3: Attack Path Summary */}
          <div className="bg-card border border-border rounded-lg overflow-hidden" data-testid="attack-path-section">
            <div className="px-6 py-4 border-b border-border bg-muted/30">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-orange-500/10">
                  <RouteIcon className="w-5 h-5 text-orange-400" />
                </div>
                <h2 className="text-lg font-semibold text-foreground">Attack Path</h2>
              </div>
            </div>
            <div className="p-6">
              {isPending ? (
                <div className="flex items-center justify-center py-8 text-muted-foreground">
                  <Loader2 className="w-5 h-5 animate-spin mr-2" />
                  <span>Analyzing attack vectors...</span>
                </div>
              ) : isFailed ? (
                <div className="flex items-center justify-center py-8 text-red-400">
                  <AlertCircle className="w-5 h-5 mr-2" />
                  <span>Failed to determine attack path</span>
                </div>
              ) : result?.attackPath && result.attackPath.length > 0 ? (
                <div className="space-y-4">
                  {result.attackPath.map((step, index) => (
                    <div key={index} className="flex items-start gap-4" data-testid={`attack-step-${index}`}>
                      <div className="flex flex-col items-center">
                        <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${
                          result.exploitable 
                            ? "bg-red-500/20 text-red-400 border border-red-500/30" 
                            : "bg-teal-500/20 text-teal-400 border border-teal-500/30"
                        }`}>
                          {index + 1}
                        </div>
                        {index < result.attackPath.length - 1 && (
                          <div className={`w-0.5 h-8 mt-2 ${result.exploitable ? "bg-red-500/30" : "bg-teal-500/30"}`} />
                        )}
                      </div>
                      <div className="flex-1 pt-1">
                        <p className="text-foreground">{step}</p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                  <ShieldCheck className="w-12 h-12 text-teal-400 mb-3" />
                  <p className="font-medium text-teal-400">No Attack Path Identified</p>
                  <p className="text-sm mt-1">This exposure does not have a viable attack chain.</p>
                </div>
              )}
            </div>
          </div>

          {/* Impact Summary */}
          {result?.impact && (
            <div className="bg-card border border-border rounded-lg overflow-hidden" data-testid="impact-section">
              <div className="px-6 py-4 border-b border-border bg-muted/30">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-red-500/10">
                    <AlertTriangle className="w-5 h-5 text-red-400" />
                  </div>
                  <h2 className="text-lg font-semibold text-foreground">Impact Assessment</h2>
                </div>
              </div>
              <div className="p-6">
                <p className="text-foreground leading-relaxed" data-testid="impact-text">{result.impact}</p>
              </div>
            </div>
          )}
        </div>

        {/* Right Column - Scores and Recommendations */}
        <div className="space-y-6">
          {/* Section 2: Exploitability Scores */}
          <div className="bg-card border border-border rounded-lg overflow-hidden" data-testid="scores-section">
            <div className="px-6 py-4 border-b border-border bg-muted/30">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-primary/10">
                  <BarChart3 className="w-5 h-5 text-primary" />
                </div>
                <h2 className="text-lg font-semibold text-foreground">Exploitability Scores</h2>
              </div>
            </div>
            <div className="p-6 space-y-6">
              {isPending ? (
                <div className="flex items-center justify-center py-8 text-muted-foreground">
                  <Loader2 className="w-5 h-5 animate-spin mr-2" />
                  <span>Calculating scores...</span>
                </div>
              ) : isFailed ? (
                <div className="flex items-center justify-center py-8 text-red-400">
                  <XCircle className="w-5 h-5 mr-2" />
                  <span>Scoring failed</span>
                </div>
              ) : result ? (
                <>
                  {/* Main Exploitability Score */}
                  <div className="text-center">
                    <label className="text-xs uppercase tracking-wider text-muted-foreground mb-3 block">Exploitability Score</label>
                    <div className={`inline-flex items-center justify-center w-24 h-24 rounded-full ${
                      getExploitabilityLevel(result.score).bgColor
                    } border-4 border-current`}>
                      <div>
                        <span className={`text-3xl font-bold ${getExploitabilityLevel(result.score).color}`} data-testid="exploit-score">
                          {Math.round(result.score)}
                        </span>
                      </div>
                    </div>
                    <p className={`mt-2 font-medium ${getExploitabilityLevel(result.score).color}`} data-testid="exploit-level">
                      {getExploitabilityLevel(result.score).level} Risk
                    </p>
                  </div>

                  {/* Confidence */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <label className="text-xs uppercase tracking-wider text-muted-foreground">Confidence</label>
                      <span className={`text-sm font-medium ${getConfidenceLevel(result.confidence).color}`} data-testid="confidence-level">
                        {getConfidenceLevel(result.confidence).level}
                      </span>
                    </div>
                    <div className="h-2 bg-muted rounded-full overflow-hidden">
                      <div 
                        className={`h-full rounded-full transition-all duration-500 ${
                          result.confidence >= 0.75 ? "bg-teal-400" :
                          result.confidence >= 0.5 ? "bg-yellow-400" : "bg-orange-400"
                        }`}
                        style={{ width: `${result.confidence * 100}%` }}
                        data-testid="confidence-bar"
                      />
                    </div>
                    <p className="text-right text-sm text-muted-foreground mt-1" data-testid="confidence-value">
                      {Math.round(result.confidence * 100)}%
                    </p>
                  </div>

                  {/* Exploitable Status */}
                  <div className="flex items-center justify-between p-4 rounded-lg bg-muted/30 border border-border">
                    <span className="text-sm text-muted-foreground">Exploitable</span>
                    <div className="flex items-center gap-2" data-testid="exploitable-status">
                      {result.exploitable ? (
                        <>
                          <ShieldAlert className="w-5 h-5 text-red-400" />
                          <span className="font-medium text-red-400">Yes</span>
                        </>
                      ) : (
                        <>
                          <ShieldCheck className="w-5 h-5 text-teal-400" />
                          <span className="font-medium text-teal-400">No</span>
                        </>
                      )}
                    </div>
                  </div>
                </>
              ) : null}
            </div>
          </div>

          {/* Section 4: Recommendations */}
          <div className="bg-card border border-border rounded-lg overflow-hidden" data-testid="recommendations-section">
            <div className="px-6 py-4 border-b border-border bg-muted/30">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-teal-500/10">
                  <Lightbulb className="w-5 h-5 text-teal-400" />
                </div>
                <h2 className="text-lg font-semibold text-foreground">Recommendations</h2>
              </div>
            </div>
            <div className="p-6 space-y-6">
              {isPending ? (
                <div className="flex items-center justify-center py-8 text-muted-foreground">
                  <Loader2 className="w-5 h-5 animate-spin mr-2" />
                  <span>Generating recommendations...</span>
                </div>
              ) : isFailed ? (
                <div className="flex items-center justify-center py-8 text-red-400">
                  <AlertCircle className="w-5 h-5 mr-2" />
                  <span>Unable to generate recommendations</span>
                </div>
              ) : result?.recommendedFix ? (
                <>
                  {/* Primary Remediation */}
                  <div>
                    <div className="flex items-center gap-2 mb-3">
                      <Wrench className="w-4 h-4 text-teal-400" />
                      <label className="text-xs uppercase tracking-wider text-teal-400 font-medium">Remediation Steps</label>
                    </div>
                    <div className="p-4 bg-muted/30 rounded-lg border border-border">
                      <p className="text-foreground leading-relaxed" data-testid="remediation-text">{result.recommendedFix}</p>
                    </div>
                  </div>

                  {/* Compensating Controls */}
                  {result.exploitable && (
                    <div>
                      <div className="flex items-center gap-2 mb-3">
                        <Shield className="w-4 h-4 text-yellow-400" />
                        <label className="text-xs uppercase tracking-wider text-yellow-400 font-medium">Compensating Controls</label>
                      </div>
                      <ul className="space-y-2" data-testid="compensating-controls">
                        <li className="flex items-start gap-2 p-3 bg-muted/30 rounded-lg border border-border">
                          <ChevronRight className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />
                          <span className="text-sm text-muted-foreground">Implement network segmentation to limit lateral movement</span>
                        </li>
                        <li className="flex items-start gap-2 p-3 bg-muted/30 rounded-lg border border-border">
                          <ChevronRight className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />
                          <span className="text-sm text-muted-foreground">Enable enhanced monitoring and alerting for suspicious activity</span>
                        </li>
                        <li className="flex items-start gap-2 p-3 bg-muted/30 rounded-lg border border-border">
                          <ChevronRight className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />
                          <span className="text-sm text-muted-foreground">Review and restrict access permissions for affected systems</span>
                        </li>
                      </ul>
                    </div>
                  )}

                  {/* Priority Banner */}
                  {result.exploitable && (
                    <div className={`p-4 rounded-lg border ${
                      input.priority === "critical" 
                        ? "bg-red-500/10 border-red-500/30" 
                        : input.priority === "high"
                        ? "bg-orange-500/10 border-orange-500/30"
                        : "bg-yellow-500/10 border-yellow-500/30"
                    }`} data-testid="priority-banner">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className={`w-4 h-4 ${
                          input.priority === "critical" 
                            ? "text-red-400" 
                            : input.priority === "high"
                            ? "text-orange-400"
                            : "text-yellow-400"
                        }`} />
                        <span className={`text-sm font-medium ${
                          input.priority === "critical" 
                            ? "text-red-400" 
                            : input.priority === "high"
                            ? "text-orange-400"
                            : "text-yellow-400"
                        }`}>
                          {input.priority === "critical" 
                            ? "Immediate action required" 
                            : input.priority === "high"
                            ? "Address within 24-48 hours"
                            : "Schedule for remediation"}
                        </span>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                  <CheckCircle className="w-12 h-12 text-teal-400 mb-3" />
                  <p className="font-medium text-teal-400">No Action Required</p>
                  <p className="text-sm mt-1 text-center">This exposure does not require immediate remediation.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
