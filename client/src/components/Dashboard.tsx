import { useState, useEffect, useRef, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Loader2, Zap, Download } from "lucide-react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { getStoredTokens } from "@/lib/uiAuth";
import { EvaluationDetail } from "./EvaluationDetail";
import { NewEvaluationModal, EvaluationFormData } from "./NewEvaluationModal";
import { ProgressModal } from "./ProgressModal";
import { EvaluationWizard } from "./EvaluationWizard";
import { OnboardingWizard } from "./OnboardingWizard";
import { Evaluation } from "./EvaluationTable";
import {
  RiskScoreGauge,
  FindingsMetricCards,
  FindingsSeverityBreakdown,
  ReachabilityExploitabilityMatrix,
  RecentEvaluations,
  FindingsVsResolvedChart,
  ScannedAppsSummary,
  OrganizationMetricsTable,
} from "./dashboard/index";

/** Shared data shape passed to all dashboard panels */
export interface DashboardData {
  evaluations: Evaluation[];
  assets: any[];
  posture: any;
}

interface EvaluationDetailData {
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
}

interface ProgressEvent {
  type: "aev_progress" | "aev_complete";
  evaluationId: string;
  agentName?: string;
  stage?: string;
  progress?: number;
  message?: string;
  success?: boolean;
  error?: string;
}

export function Dashboard() {
  const [, navigate] = useLocation();
  const [showNewModal, setShowNewModal] = useState(false);
  const [showWizard, setShowWizard] = useState(false);
  const [showProgressModal, setShowProgressModal] = useState(false);
  const [activeEvaluation, setActiveEvaluation] = useState<{ assetId: string; id: string } | null>(null);
  const [selectedEvaluationId, setSelectedEvaluationId] = useState<string | null>(null);
  const [progressData, setProgressData] = useState<{
    agentName?: string;
    stage: string;
    progress: number;
    message: string;
  } | null>(null);
  const [showOnboarding, setShowOnboarding] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const { data: evaluations = [], isLoading } = useQuery<Evaluation[]>({
    queryKey: ["/api/aev/evaluations"],
  });
  const { data: assets = [] } = useQuery<any[]>({ queryKey: ["/api/assets"] });
  const { data: posture } = useQuery<any>({ queryKey: ["/api/defensive-posture/default"] });

  useEffect(() => {
    if (!isLoading && evaluations.length === 0) {
      const hasSeenOnboarding = localStorage.getItem("hasSeenOnboarding");
      if (!hasSeenOnboarding) {
        setShowOnboarding(true);
        localStorage.setItem("hasSeenOnboarding", "true");
      }
    }
  }, [isLoading, evaluations.length]);

  const { data: selectedEvaluation, isLoading: isLoadingDetail } = useQuery<EvaluationDetailData>({
    queryKey: ["/api/aev/evaluations", selectedEvaluationId],
    enabled: !!selectedEvaluationId,
  });

  const createEvaluationMutation = useMutation({
    mutationFn: async (data: EvaluationFormData) => {
      const response = await apiRequest("POST", "/api/aev/evaluate", data);
      return response.json();
    },
    onSuccess: (data) => {
      setActiveEvaluation({ assetId: data.assetId, id: data.evaluationId });
      setShowProgressModal(true);
    },
  });

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const { accessToken } = getStoredTokens();
    const tokenParam = accessToken ? `?token=${encodeURIComponent(accessToken)}` : "";
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws${tokenParam}`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      try {
        const data: ProgressEvent = JSON.parse(event.data);
        if (data.type === "aev_progress" && data.evaluationId === activeEvaluation?.id) {
          setProgressData({
            agentName: data.agentName,
            stage: data.stage || "",
            progress: data.progress || 0,
            message: data.message || "",
          });
        }
        if (data.type === "aev_complete") {
          if (data.evaluationId === activeEvaluation?.id) {
            setTimeout(() => {
              setShowProgressModal(false);
              setActiveEvaluation(null);
              setProgressData(null);
              queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
            }, 1000);
          } else {
            queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
          }
        }
      } catch {
        // Ignore malformed messages
      }
    };

    return () => { ws.close(); };
  }, [activeEvaluation?.id]);

  const handleNewEvaluation = (data: EvaluationFormData) => {
    setShowNewModal(false);
    createEvaluationMutation.mutate(data);
  };

  if (selectedEvaluationId && selectedEvaluation) {
    return (
      <EvaluationDetail
        evaluation={selectedEvaluation}
        onBack={() => setSelectedEvaluationId(null)}
      />
    );
  }

  if (selectedEvaluationId && isLoadingDetail) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const activeCount = evaluations.filter(e => e.status === "in_progress").length;
  const completedCount = evaluations.filter(e => e.status === "completed").length;

  return (
    <div className="flex flex-col gap-3 min-h-0">
      {/* Page Header */}
      <div className="flex justify-between items-start">
        <div>
          <h1 className="text-lg font-semibold tracking-tight" style={{ color: "var(--falcon-t1)", letterSpacing: "-0.02em" }}>
            Threat Operations
          </h1>
          <div className="flex items-center gap-2 mt-1 text-[11px]" style={{ color: "var(--falcon-t3)" }}>
            <span>{assets.length} targets in scope</span>
            <span className="w-[3px] h-[3px] rounded-full" style={{ background: "var(--falcon-t4)" }} />
            <span>{activeCount} active simulations</span>
            <span className="w-[3px] h-[3px] rounded-full" style={{ background: "var(--falcon-t4)" }} />
            <span>{evaluations.length} total evaluations</span>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            className="inline-flex items-center gap-1.5 py-[7px] px-[14px] rounded text-[11px] font-medium tracking-wide cursor-pointer transition-all"
            style={{ background: "transparent", border: "1px solid var(--falcon-border-2)", color: "var(--falcon-t2)" }}
            onClick={() => navigate("/reports")}
          >
            <Download className="w-3 h-3" />
            Export
          </button>
          <button
            className="inline-flex items-center gap-1.5 py-[7px] px-[14px] rounded text-[11px] font-medium tracking-wide cursor-pointer transition-all"
            style={{ background: "var(--falcon-red)", border: "1px solid var(--falcon-red)", color: "#fff" }}
            onClick={() => setShowWizard(true)}
          >
            <Zap className="w-3 h-3" />
            New Assessment
          </button>
        </div>
      </div>

      {/* KPI Strip */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-[10px]">
        <RiskScoreGauge posture={posture} />
        <FindingsMetricCards evaluations={evaluations} />
        <FindingsSeverityBreakdown evaluations={evaluations} />
        <ReachabilityExploitabilityMatrix evaluations={evaluations} />
      </div>

      {/* Main table + sidebar */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_280px] gap-[10px] flex-1 min-h-0">
        <RecentEvaluations evaluations={evaluations} />
        <div className="flex flex-col gap-[10px]">
          <ScannedAppsSummary assets={assets} />
          <OrganizationMetricsTable assets={assets} evaluations={evaluations} />
        </div>
      </div>

      {/* Timeline chart */}
      <FindingsVsResolvedChart evaluations={evaluations} />

      {/* Modals */}
      <NewEvaluationModal
        isOpen={showNewModal}
        onClose={() => setShowNewModal(false)}
        onSubmit={handleNewEvaluation}
      />
      <EvaluationWizard open={showWizard} onOpenChange={setShowWizard} />
      <ProgressModal
        isOpen={showProgressModal}
        onClose={() => { setShowProgressModal(false); setProgressData(null); }}
        assetId={activeEvaluation?.assetId || ""}
        evaluationId={activeEvaluation?.id || ""}
        progressData={progressData}
      />
      <OnboardingWizard open={showOnboarding} onClose={() => setShowOnboarding(false)} />
    </div>
  );
}
