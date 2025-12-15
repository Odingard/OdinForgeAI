import { useState, useCallback, useRef, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Link } from "wouter";
import { useAuth } from "../lib/auth";
import { useWebSocket, WSMessage } from "../hooks/use-websocket";
import { apiRequest, queryClient } from "../lib/queryClient";
import { AEVProgressModal, AEVProgressData, AEVCompleteData } from "../components/AEVProgressModal";
import {
  Zap,
  Play,
  RefreshCw,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
  ChevronDown,
  ChevronUp,
  Target,
  Shield,
  Activity,
  Eye,
  ExternalLink,
  X,
} from "lucide-react";

interface AEVEvaluation {
  id: string;
  assetId: string;
  exposureType: string;
  module?: string;
  priority?: string;
  status: string;
  result?: {
    evaluationId?: string;
    exploitable: boolean;
    confidence: number;
    score: number;
    status: string;
    exploitPath?: string[];
    mitigations?: string[];
    evidence?: string[];
    technicalDetails?: any;
  };
  createdAt: string;
  updatedAt?: string;
}

interface AEVResponse {
  evaluations: AEVEvaluation[];
  total: number;
}

interface AEVStats {
  totalEvaluations: number;
  activeEvaluations: number;
  completedEvaluations: number;
  exploitableCount: number;
  notExploitableCount: number;
  averageConfidence: number;
}

export default function AEVPage() {
  const { token } = useAuth();
  const [selectedEvaluation, setSelectedEvaluation] = useState<AEVEvaluation | null>(null);
  const [showNewEvalModal, setShowNewEvalModal] = useState(false);
  const [sortField, setSortField] = useState<"createdAt" | "status" | "priority">("createdAt");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [filter, setFilter] = useState<string>("all");
  
  const [showProgressModal, setShowProgressModal] = useState(false);
  const [activeEvaluationId, setActiveEvaluationId] = useState<string | null>(null);
  const [activeAssetId, setActiveAssetId] = useState<string>("");
  const [progressData, setProgressData] = useState<AEVProgressData | null>(null);
  const [resultData, setResultData] = useState<AEVCompleteData | null>(null);
  
  const activeEvaluationIdRef = useRef<string | null>(null);
  useEffect(() => {
    activeEvaluationIdRef.current = activeEvaluationId;
  }, [activeEvaluationId]);
  
  const [newEvalForm, setNewEvalForm] = useState({
    assetId: "",
    exposureType: "cve" as "cve" | "misconfiguration" | "behavior" | "network" | "custom",
    description: "",
    module: "vulnmgmt" as "posture" | "spear" | "sentinel" | "vulnmgmt",
    priority: "medium" as "low" | "medium" | "high" | "critical",
  });

  const handleWSMessage = useCallback((message: WSMessage) => {
    const currentId = activeEvaluationIdRef.current;
    if (message.type === "aev_progress" && message.data.evaluationId === currentId) {
      setProgressData({
        evaluationId: message.data.evaluationId,
        progress: message.data.progress,
        stage: message.data.stage,
        currentStage: message.data.currentStage,
        stageName: message.data.stageName,
      });
    } else if (message.type === "aev_complete" && message.data.evaluationId === currentId) {
      setResultData({
        evaluationId: message.data.evaluationId,
        exploitable: message.data.exploitable,
        confidence: message.data.confidence,
        score: message.data.score,
        status: message.data.status,
        error: message.data.error,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/stats"] });
    }
  }, []);

  const { subscribe } = useWebSocket({
    token,
    onMessage: handleWSMessage,
    onConnect: () => subscribe("aev"),
  });

  const { data: aevResponse, isLoading } = useQuery<AEVResponse>({
    queryKey: ["/api/aev/evaluations"],
    refetchInterval: 10000,
    retry: 1,
  });

  const { data: aevStats } = useQuery<AEVStats>({
    queryKey: ["/api/aev/stats"],
    refetchInterval: 30000,
    retry: 1,
  });

  const handleCloseProgressModal = useCallback(() => {
    setShowProgressModal(false);
    setActiveEvaluationId(null);
    setActiveAssetId("");
    setProgressData(null);
    setResultData(null);
  }, []);

  const newEvaluationMutation = useMutation({
    mutationFn: async (data: typeof newEvalForm) => {
      const evaluationId = `aev-${crypto.randomUUID().slice(0, 8)}`;
      
      setActiveAssetId(data.assetId);
      setProgressData(null);
      setResultData(null);
      setActiveEvaluationId(evaluationId);
      activeEvaluationIdRef.current = evaluationId;
      setShowProgressModal(true);
      setShowNewEvalModal(false);
      
      const response = await apiRequest("/api/aev/evaluate", {
        method: "POST",
        body: JSON.stringify({
          evaluationId,
          assetId: data.assetId,
          exposureType: data.exposureType,
          description: data.description,
          module: data.module,
          priority: data.priority,
          data: {},
        }),
      });
      return response;
    },
    onSuccess: () => {
      setNewEvalForm({
        assetId: "",
        exposureType: "cve",
        description: "",
        module: "vulnmgmt",
        priority: "medium",
      });
    },
    onError: () => {
      setShowProgressModal(false);
      setActiveEvaluationId(null);
      activeEvaluationIdRef.current = null;
    },
  });

  const evaluations = aevResponse?.evaluations || [];

  const filteredEvaluations = evaluations.filter((e) => {
    if (filter === "all") return true;
    if (filter === "pending") return e.status === "pending" || e.status === "in_progress";
    if (filter === "completed") return e.status === "completed";
    if (filter === "exploitable") return e.result?.exploitable === true;
    if (filter === "safe") return e.result?.exploitable === false;
    return true;
  });

  const sortedEvaluations = [...filteredEvaluations].sort((a, b) => {
    let comparison = 0;
    if (sortField === "createdAt") {
      comparison = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
    } else if (sortField === "status") {
      comparison = a.status.localeCompare(b.status);
    } else if (sortField === "priority") {
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      const aPriority = (a.priority || "medium") as keyof typeof priorityOrder;
      const bPriority = (b.priority || "medium") as keyof typeof priorityOrder;
      comparison = priorityOrder[aPriority] - priorityOrder[bPriority];
    }
    return sortOrder === "asc" ? comparison : -comparison;
  });

  const stats = aevStats || {
    totalEvaluations: evaluations.length,
    activeEvaluations: evaluations.filter((e) => e.status === "pending" || e.status === "in_progress").length,
    completedEvaluations: evaluations.filter((e) => e.status === "completed").length,
    exploitableCount: evaluations.filter((e) => e.result?.exploitable).length,
    notExploitableCount: evaluations.filter((e) => e.result?.exploitable === false).length,
    averageConfidence: evaluations.length > 0 
      ? Math.round(evaluations.reduce((sum, e) => sum + (e.result?.confidence || 0), 0) / evaluations.length)
      : 0,
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "completed": return "bg-teal-500/10 text-teal-400 border border-teal-500/30";
      case "in_progress": return "bg-yellow-500/10 text-yellow-400 border border-yellow-500/30";
      case "pending": return "bg-blue-500/10 text-blue-400 border border-blue-500/30";
      case "failed": return "bg-red-500/10 text-red-400 border border-red-500/30";
      default: return "bg-muted text-muted-foreground border border-border";
    }
  };

  const getPriorityBadge = (priority?: string) => {
    switch (priority) {
      case "critical": return "badge-critical";
      case "high": return "badge-high";
      case "medium": return "badge-medium";
      case "low": return "badge-low";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const getExposureTypeIcon = (type: string) => {
    switch (type) {
      case "cve": return <AlertTriangle className="h-4 w-4 text-orange-400" />;
      case "misconfiguration": return <Shield className="h-4 w-4 text-blue-400" />;
      case "behavior": return <Activity className="h-4 w-4 text-purple-400" />;
      case "network": return <Target className="h-4 w-4 text-teal-400" />;
      default: return <Zap className="h-4 w-4 text-yellow-400" />;
    }
  };

  const getModuleLabel = (module?: string) => {
    switch (module) {
      case "posture": return "CSPM";
      case "spear": return "PENTEST";
      case "sentinel": return "XDR";
      case "vulnmgmt": return "CVE";
      default: return "GENERAL";
    }
  };

  const toggleSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortOrder("desc");
    }
  };

  const SortIcon = ({ field }: { field: typeof sortField }) => {
    if (sortField !== field) return null;
    return sortOrder === "asc" ? (
      <ChevronUp className="h-3 w-3" />
    ) : (
      <ChevronDown className="h-3 w-3" />
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
            AEV Management
            <span className="text-xs font-medium px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/30">
              EXPLOIT VALIDATION
            </span>
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Autonomous Exploit Validation evaluations and results
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] })}
            className="flex items-center gap-2 px-3 py-1.5 bg-muted hover:bg-muted/80 text-foreground rounded-md text-sm font-medium transition-colors"
            data-testid="button-refresh"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </button>
          <button
            onClick={() => setShowNewEvalModal(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors"
            data-testid="button-new-evaluation"
          >
            <Play className="h-3.5 w-3.5" />
            Run New Evaluation
          </button>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-4">
        <div className="stat-card">
          <div className="text-2xl font-bold text-foreground tabular-nums">{stats.totalEvaluations}</div>
          <div className="text-xs text-muted-foreground uppercase tracking-wider mt-1">Total</div>
        </div>
        <div className="stat-card">
          <div className="text-2xl font-bold text-yellow-400 tabular-nums">{stats.activeEvaluations}</div>
          <div className="text-xs text-muted-foreground uppercase tracking-wider mt-1">Active</div>
        </div>
        <div className="stat-card">
          <div className="text-2xl font-bold text-teal-400 tabular-nums">{stats.completedEvaluations}</div>
          <div className="text-xs text-muted-foreground uppercase tracking-wider mt-1">Completed</div>
        </div>
        <div className="stat-card">
          <div className="text-2xl font-bold text-red-400 tabular-nums">{stats.exploitableCount}</div>
          <div className="text-xs text-muted-foreground uppercase tracking-wider mt-1">Exploitable</div>
        </div>
        <div className="stat-card">
          <div className="text-2xl font-bold text-primary tabular-nums">{stats.averageConfidence}%</div>
          <div className="text-xs text-muted-foreground uppercase tracking-wider mt-1">Avg Confidence</div>
        </div>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        {[
          { value: "all", label: "All" },
          { value: "pending", label: "Pending/Active" },
          { value: "completed", label: "Completed" },
          { value: "exploitable", label: "Exploitable" },
          { value: "safe", label: "Not Exploitable" },
        ].map((f) => (
          <button
            key={f.value}
            onClick={() => setFilter(f.value)}
            className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              filter === f.value
                ? "bg-primary text-primary-foreground"
                : "bg-muted text-muted-foreground hover:text-foreground"
            }`}
            data-testid={`filter-${f.value}`}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div className="card-enterprise overflow-hidden">
        <div className="panel-header">
          <h2 className="panel-title flex items-center gap-2">
            <Zap className="h-4 w-4 text-primary" />
            Evaluations
          </h2>
          <span className="text-xs text-muted-foreground tabular-nums">{sortedEvaluations.length} results</span>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Exposure
                </th>
                <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Type
                </th>
                <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Module
                </th>
                <th 
                  className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
                  onClick={() => toggleSort("priority")}
                >
                  <div className="flex items-center gap-1">
                    Severity
                    <SortIcon field="priority" />
                  </div>
                </th>
                <th 
                  className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
                  onClick={() => toggleSort("status")}
                >
                  <div className="flex items-center gap-1">
                    Status
                    <SortIcon field="status" />
                  </div>
                </th>
                <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Result
                </th>
                <th className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Score
                </th>
                <th 
                  className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground cursor-pointer hover:text-foreground transition-colors"
                  onClick={() => toggleSort("createdAt")}
                >
                  <div className="flex items-center gap-1">
                    Created
                    <SortIcon field="createdAt" />
                  </div>
                </th>
                <th className="px-4 py-3 text-right text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {isLoading ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center">
                    <Loader2 className="h-8 w-8 mx-auto text-muted-foreground animate-spin" />
                    <p className="text-sm text-muted-foreground mt-3">Loading evaluations...</p>
                  </td>
                </tr>
              ) : sortedEvaluations.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-muted-foreground">
                    <Zap className="h-8 w-8 mx-auto opacity-30" />
                    <p className="mt-3 text-sm">No evaluations found</p>
                    <p className="text-xs mt-1">Run a new evaluation to get started</p>
                  </td>
                </tr>
              ) : (
                sortedEvaluations.map((evaluation) => (
                  <tr
                    key={evaluation.id}
                    className="hover:bg-muted/30 transition-colors"
                    data-testid={`evaluation-row-${evaluation.id}`}
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {getExposureTypeIcon(evaluation.exposureType)}
                        <span className="font-medium text-sm text-foreground truncate max-w-[200px]">
                          {evaluation.assetId}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs font-mono bg-muted/50 px-2 py-0.5 rounded capitalize">
                        {evaluation.exposureType}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-[10px] font-semibold bg-primary/10 text-primary px-2 py-0.5 rounded">
                        {getModuleLabel(evaluation.module)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] font-semibold uppercase px-2 py-0.5 rounded ${getPriorityBadge(evaluation.priority)}`}>
                        {evaluation.priority || "medium"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] font-medium px-2 py-0.5 rounded ${getStatusBadge(evaluation.status)}`}>
                        {evaluation.status}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {evaluation.status === "completed" && evaluation.result ? (
                        <div className="flex items-center gap-2">
                          {evaluation.result.exploitable ? (
                            <>
                              <XCircle className="h-4 w-4 text-red-400" />
                              <span className="text-xs font-medium text-red-400">Exploitable</span>
                            </>
                          ) : (
                            <>
                              <CheckCircle className="h-4 w-4 text-teal-400" />
                              <span className="text-xs font-medium text-teal-400">Not Exploitable</span>
                            </>
                          )}
                        </div>
                      ) : evaluation.status === "in_progress" ? (
                        <div className="flex items-center gap-2">
                          <Loader2 className="h-4 w-4 text-yellow-400 animate-spin" />
                          <span className="text-xs text-muted-foreground">Analyzing...</span>
                        </div>
                      ) : (
                        <span className="text-xs text-muted-foreground">Pending</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {evaluation.result?.score !== undefined ? (
                        <div className="flex items-center gap-2">
                          <div className="w-16 bg-muted rounded-full h-1.5 overflow-hidden">
                            <div
                              className={`h-1.5 rounded-full ${
                                evaluation.result.score >= 70 ? "bg-red-500" :
                                evaluation.result.score >= 40 ? "bg-yellow-500" : "bg-teal-500"
                              }`}
                              style={{ width: `${evaluation.result.score}%` }}
                            />
                          </div>
                          <span className="text-xs font-medium tabular-nums">{evaluation.result.score}</span>
                        </div>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1 text-xs text-muted-foreground">
                        <Clock className="h-3 w-3" />
                        {new Date(evaluation.createdAt).toLocaleDateString()}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => setSelectedEvaluation(evaluation)}
                          className="text-xs font-medium text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"
                          data-testid={`button-quick-view-${evaluation.id}`}
                        >
                          <Eye className="h-3 w-3" />
                          Quick
                        </button>
                        <Link
                          href={`/aev/${evaluation.id}`}
                          className="text-xs font-medium text-primary hover:text-primary/80 transition-colors flex items-center gap-1"
                          data-testid={`link-full-details-${evaluation.id}`}
                        >
                          <ExternalLink className="h-3 w-3" />
                          Full Details
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selectedEvaluation && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-card border border-border rounded-lg w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="panel-header sticky top-0 bg-card z-10">
              <h3 className="panel-title flex items-center gap-2">
                <Zap className="h-4 w-4 text-primary" />
                Evaluation Details
              </h3>
              <button
                onClick={() => setSelectedEvaluation(null)}
                className="p-1 hover:bg-muted rounded-md transition-colors"
                data-testid="button-close-details"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="p-6 space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Asset/Exposure ID</div>
                  <div className="font-medium text-foreground mt-1">{selectedEvaluation.assetId}</div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Type</div>
                  <div className="mt-1 flex items-center gap-2">
                    {getExposureTypeIcon(selectedEvaluation.exposureType)}
                    <span className="font-medium capitalize">{selectedEvaluation.exposureType}</span>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Module</div>
                  <div className="mt-1">
                    <span className="text-[10px] font-semibold bg-primary/10 text-primary px-2 py-0.5 rounded">
                      {getModuleLabel(selectedEvaluation.module)}
                    </span>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Priority</div>
                  <div className="mt-1">
                    <span className={`text-[10px] font-semibold uppercase px-2 py-0.5 rounded ${getPriorityBadge(selectedEvaluation.priority)}`}>
                      {selectedEvaluation.priority || "medium"}
                    </span>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Status</div>
                  <div className="mt-1">
                    <span className={`text-[10px] font-medium px-2 py-0.5 rounded ${getStatusBadge(selectedEvaluation.status)}`}>
                      {selectedEvaluation.status.toUpperCase()}
                    </span>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Created</div>
                  <div className="font-medium text-foreground mt-1 flex items-center gap-2">
                    <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                    {new Date(selectedEvaluation.createdAt).toLocaleString()}
                  </div>
                </div>
              </div>

              {selectedEvaluation.result && (
                <>
                  <div className="border-t border-border pt-6">
                    <h4 className="text-sm font-semibold text-foreground mb-4">Evaluation Result</h4>
                    <div className={`p-4 rounded-lg border ${
                      selectedEvaluation.result.exploitable 
                        ? "bg-red-500/10 border-red-500/30" 
                        : "bg-teal-500/10 border-teal-500/30"
                    }`}>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          {selectedEvaluation.result.exploitable ? (
                            <XCircle className="h-6 w-6 text-red-400" />
                          ) : (
                            <CheckCircle className="h-6 w-6 text-teal-400" />
                          )}
                          <div>
                            <div className={`font-bold text-lg ${
                              selectedEvaluation.result.exploitable ? "text-red-400" : "text-teal-400"
                            }`}>
                              {selectedEvaluation.result.exploitable ? "Exploitable" : "Not Exploitable"}
                            </div>
                            <div className="text-xs text-muted-foreground">
                              {selectedEvaluation.result.confidence}% confidence
                            </div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-2xl font-bold tabular-nums">{selectedEvaluation.result.score}</div>
                          <div className="text-[10px] text-muted-foreground uppercase">Risk Score</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {selectedEvaluation.result.exploitPath && selectedEvaluation.result.exploitPath.length > 0 && (
                    <div>
                      <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Exploit Path</div>
                      <div className="bg-muted/30 rounded-md p-3 space-y-1">
                        {selectedEvaluation.result.exploitPath.map((step, idx) => (
                          <div key={idx} className="flex items-start gap-2 text-sm">
                            <span className="text-primary font-mono text-xs">{idx + 1}.</span>
                            <span className="text-foreground">{step}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedEvaluation.result.mitigations && selectedEvaluation.result.mitigations.length > 0 && (
                    <div>
                      <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Recommended Mitigations</div>
                      <div className="space-y-2">
                        {selectedEvaluation.result.mitigations.map((mitigation, idx) => (
                          <div key={idx} className="flex items-start gap-2 text-sm bg-blue-500/10 border border-blue-500/30 rounded-md p-2">
                            <Shield className="h-4 w-4 text-blue-400 flex-shrink-0 mt-0.5" />
                            <span className="text-foreground">{mitigation}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedEvaluation.result.evidence && selectedEvaluation.result.evidence.length > 0 && (
                    <div>
                      <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Evidence</div>
                      <div className="bg-muted/50 rounded-md p-3 font-mono text-xs space-y-1 overflow-x-auto">
                        {selectedEvaluation.result.evidence.map((ev, idx) => (
                          <div key={idx} className="text-muted-foreground">{ev}</div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedEvaluation.result.technicalDetails && (
                    <div>
                      <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Technical Details</div>
                      <pre className="bg-muted/50 rounded-md p-3 font-mono text-xs overflow-x-auto text-muted-foreground">
                        {JSON.stringify(selectedEvaluation.result.technicalDetails, null, 2)}
                      </pre>
                    </div>
                  )}
                </>
              )}
              
              <div className="border-t border-border pt-4 mt-4">
                <Link
                  href={`/aev/${selectedEvaluation.id}`}
                  className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-primary/10 hover:bg-primary/20 border border-primary/30 text-primary rounded-md text-sm font-medium transition-colors"
                  data-testid="link-view-full-details"
                >
                  <ExternalLink className="h-4 w-4" />
                  View Full Analysis Report
                </Link>
              </div>
            </div>
          </div>
        </div>
      )}

      {showNewEvalModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-card border border-border rounded-lg w-full max-w-md">
            <div className="panel-header">
              <h3 className="panel-title flex items-center gap-2">
                <Play className="h-4 w-4 text-primary" />
                New AEV Evaluation
              </h3>
              <button
                onClick={() => setShowNewEvalModal(false)}
                className="p-1 hover:bg-muted rounded-md transition-colors"
                data-testid="button-close-new-eval"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">
                  Asset / Exposure ID *
                </label>
                <input
                  type="text"
                  value={newEvalForm.assetId}
                  onChange={(e) => setNewEvalForm({ ...newEvalForm, assetId: e.target.value })}
                  placeholder="Enter asset or CVE ID..."
                  className="w-full px-3 py-2 bg-muted/30 border border-border rounded-md text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                  data-testid="input-asset-id"
                />
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">
                  Description *
                </label>
                <textarea
                  value={newEvalForm.description}
                  onChange={(e) => setNewEvalForm({ ...newEvalForm, description: e.target.value })}
                  placeholder="Describe the exposure..."
                  rows={3}
                  className="w-full px-3 py-2 bg-muted/30 border border-border rounded-md text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary resize-none"
                  data-testid="input-description"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">
                    Exposure Type
                  </label>
                  <select
                    value={newEvalForm.exposureType}
                    onChange={(e) => setNewEvalForm({ ...newEvalForm, exposureType: e.target.value as any })}
                    className="w-full px-3 py-2 bg-muted/30 border border-border rounded-md text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                    data-testid="select-exposure-type"
                  >
                    <option value="cve">CVE</option>
                    <option value="misconfiguration">Misconfiguration</option>
                    <option value="behavior">Behavior</option>
                    <option value="network">Network</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">
                    Module
                  </label>
                  <select
                    value={newEvalForm.module}
                    onChange={(e) => setNewEvalForm({ ...newEvalForm, module: e.target.value as any })}
                    className="w-full px-3 py-2 bg-muted/30 border border-border rounded-md text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                    data-testid="select-module"
                  >
                    <option value="vulnmgmt">Vulnerability Management</option>
                    <option value="posture">Posture (CSPM)</option>
                    <option value="spear">Spear (Pentest)</option>
                    <option value="sentinel">Sentinel (XDR)</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider block mb-1">
                  Priority
                </label>
                <div className="grid grid-cols-4 gap-2">
                  {(["low", "medium", "high", "critical"] as const).map((priority) => (
                    <button
                      key={priority}
                      type="button"
                      onClick={() => setNewEvalForm({ ...newEvalForm, priority })}
                      className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors capitalize ${
                        newEvalForm.priority === priority
                          ? getPriorityBadge(priority)
                          : "bg-muted text-muted-foreground hover:text-foreground"
                      }`}
                      data-testid={`priority-${priority}`}
                    >
                      {priority}
                    </button>
                  ))}
                </div>
              </div>
              <div className="flex gap-2 pt-4">
                <button
                  onClick={() => setShowNewEvalModal(false)}
                  className="flex-1 px-3 py-2 bg-muted text-foreground rounded-md text-sm font-medium hover:bg-muted/80 transition-colors"
                  data-testid="button-cancel-eval"
                >
                  Cancel
                </button>
                <button
                  onClick={() => newEvaluationMutation.mutate(newEvalForm)}
                  disabled={!newEvalForm.assetId.trim() || !newEvalForm.description.trim() || newEvaluationMutation.isPending}
                  className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-primary text-primary-foreground rounded-md text-sm font-medium hover:bg-primary/90 transition-colors disabled:opacity-50"
                  data-testid="button-submit-eval"
                >
                  {newEvaluationMutation.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <>
                      <Play className="h-4 w-4" />
                      Start Evaluation
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <AEVProgressModal
        isOpen={showProgressModal}
        onClose={handleCloseProgressModal}
        evaluationId={activeEvaluationId}
        progress={progressData}
        result={resultData}
        assetId={activeAssetId}
      />
    </div>
  );
}
