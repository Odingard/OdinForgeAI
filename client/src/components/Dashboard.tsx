import { useState, useEffect, useRef, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Loader2 } from "lucide-react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { getStoredTokens } from "@/lib/uiAuth";
import { EvaluationDetail } from "./EvaluationDetail";
import { NewEvaluationModal, EvaluationFormData } from "./NewEvaluationModal";
import { ProgressModal } from "./ProgressModal";
import { EvaluationWizard } from "./EvaluationWizard";
import { OnboardingWizard } from "./OnboardingWizard";
import { Evaluation } from "./EvaluationTable";
import {
  DashboardTopBar,
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

  const dashboardData = useMemo<DashboardData>(
    () => ({ evaluations, assets, posture }),
    [evaluations, assets, posture],
  );

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

  return (
    <div className="relative rounded-lg overflow-hidden bg-background min-h-[calc(100vh-80px)]">
      {/* Subtle background effects */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="grid-bg opacity-[0.06] absolute inset-0" />
        <div
          className="absolute rounded-full"
          style={{
            width: 400, height: 400, top: "10%", left: "-5%",
            background: "radial-gradient(circle, rgba(56,189,248,0.03) 0%, transparent 70%)",
            filter: "blur(60px)",
          }}
        />
        <div
          className="absolute rounded-full"
          style={{
            width: 300, height: 300, bottom: "5%", right: "-3%",
            background: "radial-gradient(circle, rgba(139,92,246,0.03) 0%, transparent 70%)",
            filter: "blur(60px)",
          }}
        />
      </div>

      <div className="relative z-10 space-y-4">
        <DashboardTopBar data={dashboardData} />

        {/* Row 1: Key metric cards */}
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 px-4">
          <RiskScoreGauge posture={posture} />
          <FindingsMetricCards evaluations={evaluations} />
          <FindingsSeverityBreakdown evaluations={evaluations} />
          <ReachabilityExploitabilityMatrix evaluations={evaluations} />
        </div>

        {/* Row 2: Recent evaluations + sidebar */}
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_300px] gap-3 px-4">
          <RecentEvaluations evaluations={evaluations} />
          <div className="space-y-3">
            <ScannedAppsSummary assets={assets} />
            <OrganizationMetricsTable assets={assets} evaluations={evaluations} />
          </div>
        </div>

        {/* Row 3: Timeline chart */}
        <div className="px-4 pb-4">
          <FindingsVsResolvedChart evaluations={evaluations} />
        </div>

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
    </div>
  );
}
