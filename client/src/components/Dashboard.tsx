import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import {
  Zap,
  Target,
  ShieldCheck,
  AlertTriangle,
  Activity,
  RefreshCw,
  Loader2,
  Link2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { StatCard } from "./StatCard";
import { FilterBar } from "./FilterBar";
import { EvaluationTable, Evaluation } from "./EvaluationTable";
import { NewEvaluationModal, EvaluationFormData } from "./NewEvaluationModal";
import { ProgressModal } from "./ProgressModal";
import { EvaluationDetail } from "./EvaluationDetail";
import { EvaluationWizard } from "./EvaluationWizard";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { SetupChecklist } from "./SetupChecklist";
import { OnboardingWizard } from "./OnboardingWizard";

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
  const [filter, setFilter] = useState("all");
  const [showNewModal, setShowNewModal] = useState(false);
  const [showWizard, setShowWizard] = useState(false);
  const [showProgressModal, setShowProgressModal] = useState(false);
  const [activeEvaluation, setActiveEvaluation] = useState<{ assetId: string; id: string } | null>(null);
  const [selectedEvaluationId, setSelectedEvaluationId] = useState<string | null>(null);
  const [progressData, setProgressData] = useState<{ agentName?: string; stage: string; progress: number; message: string } | null>(null);
  const [showOnboarding, setShowOnboarding] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const { data: evaluations = [], isLoading, error, refetch } = useQuery<Evaluation[]>({
    queryKey: ["/api/aev/evaluations"],
  });

  const { data: breachChains = [] } = useQuery<any[]>({
    queryKey: ["/api/breach-chains"],
  });

  // Show onboarding for new users (no evaluations)
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
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
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
    };

    ws.onerror = (error) => {
      console.error("WebSocket error:", error);
    };

    return () => {
      ws.close();
    };
  }, [activeEvaluation?.id]);

  const filteredEvaluations = evaluations.filter((e) => {
    if (filter === "all") return true;
    if (filter === "pending") return e.status === "pending" || e.status === "in_progress";
    if (filter === "completed") return e.status === "completed";
    if (filter === "exploitable") return e.exploitable === true;
    if (filter === "safe") return e.exploitable === false;
    return true;
  });

  const stats = {
    total: evaluations.length,
    active: evaluations.filter((e) => e.status === "pending" || e.status === "in_progress").length,
    exploitable: evaluations.filter((e) => e.exploitable).length,
    safe: evaluations.filter((e) => e.exploitable === false).length,
    avgConfidence: evaluations.filter(e => e.confidence).length > 0
      ? Math.round(
          evaluations.filter(e => e.confidence).reduce((sum, e) => sum + (e.confidence || 0), 0) / 
          evaluations.filter(e => e.confidence).length * 100
        )
      : 0,
  };

  const filterOptions = [
    { value: "all", label: "All", count: evaluations.length },
    { value: "pending", label: "Active", count: stats.active },
    { value: "completed", label: "Completed", count: evaluations.filter(e => e.status === "completed").length },
    { value: "exploitable", label: "Exploitable", count: stats.exploitable },
    { value: "safe", label: "Safe", count: stats.safe },
  ];

  const handleNewEvaluation = (data: EvaluationFormData) => {
    setShowNewModal(false);
    createEvaluationMutation.mutate(data);
  };

  const handleViewDetails = (evaluation: Evaluation) => {
    setSelectedEvaluationId(evaluation.id);
  };

  const handleRunEvaluation = (evaluation: Evaluation) => {
    createEvaluationMutation.mutate({
      assetId: evaluation.assetId,
      exposureType: evaluation.exposureType,
      priority: evaluation.priority,
      description: evaluation.description || "",
      adversaryProfile: evaluation.adversaryProfile,
    });
  };

  const handleStartSimulation = (evaluation: Evaluation) => {
    const params = new URLSearchParams({
      assetId: evaluation.assetId,
      exposureType: evaluation.exposureType,
      priority: evaluation.priority,
      fromEvaluation: evaluation.id,
    });
    navigate(`/simulations?${params.toString()}`);
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
    <div className="space-y-6 relative">
      {/* Subtle grid background */}
      <div className="absolute inset-0 grid-bg opacity-30 pointer-events-none" style={{ maskImage: 'linear-gradient(to bottom, transparent, black 10%, black 90%, transparent)' }} />

      <div className="flex items-center justify-between flex-wrap gap-4 relative">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-3 flex-wrap">
            <span className="text-neon-red">Odin</span>
            <span className="text-neon-cyan">Forge</span>
            <span className="text-xs font-medium px-3 py-1 rounded glass glow-cyan-sm text-cyan-400 border border-cyan-500/30 uppercase tracking-wider">
              Autonomous Validation
            </span>
          </h1>
          <p className="text-sm text-muted-foreground/90 mt-2 font-medium">
            AI-powered adversarial exposure validation with autonomous exploit chaining
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="outline"
            size="sm"
            className="glass hover:glow-cyan-sm transition-all"
            data-testid="button-refresh"
            onClick={() => refetch()}
            disabled={isLoading}
          >
            <RefreshCw className={`h-3.5 w-3.5 mr-2 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Button
            size="sm"
            className="bg-gradient-to-r from-cyan-600 to-blue-600 glow-cyan-sm hover:glow-cyan transition-all"
            data-testid="button-start-assessment"
            onClick={() => navigate("/assess")}
          >
            <Zap className="h-3.5 w-3.5 mr-2" />
            New Assessment
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 relative">
        <StatCard
          label="Total Evaluations"
          value={stats.total}
          icon={Target}
          colorClass="text-foreground"
        />
        <StatCard
          label="Active"
          value={stats.active}
          icon={Activity}
          colorClass="text-amber-400"
        />
        <StatCard
          label="Exploitable"
          value={stats.exploitable}
          icon={AlertTriangle}
          colorClass="text-red-400"
          critical={stats.exploitable > 0}
        />
        <StatCard
          label="Safe"
          value={stats.safe}
          icon={ShieldCheck}
          colorClass="text-emerald-400"
        />
        <StatCard
          label="Breach Chains"
          value={breachChains.length}
          icon={Link2}
          colorClass="text-purple-400"
          critical={breachChains.some((c: any) => c.status === "running")}
        />
        <StatCard
          label="Avg Confidence"
          value={`${stats.avgConfidence}%`}
          icon={Zap}
          colorClass="text-cyan-400"
        />
      </div>

      {/* Error banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0" />
          <div className="text-sm">
            <span className="font-medium text-red-400">Failed to load evaluations: </span>
            <span className="text-muted-foreground">{error.message}</span>
          </div>
          <Button variant="outline" size="sm" className="ml-auto" onClick={() => refetch()}>
            Retry
          </Button>
        </div>
      )}

      {/* Setup Checklist for new users */}
      <SetupChecklist />

      <FilterBar
        options={filterOptions}
        activeFilter={filter}
        onFilterChange={setFilter}
      />

      {isLoading ? (
        <div className="flex items-center justify-center h-32">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <EvaluationTable 
          evaluations={filteredEvaluations}
          onViewDetails={handleViewDetails}
          onRunEvaluation={handleRunEvaluation}
          onStartSimulation={handleStartSimulation}
        />
      )}

      <NewEvaluationModal 
        isOpen={showNewModal}
        onClose={() => setShowNewModal(false)}
        onSubmit={handleNewEvaluation}
      />

      <EvaluationWizard
        open={showWizard}
        onOpenChange={setShowWizard}
      />

      <ProgressModal
        isOpen={showProgressModal}
        onClose={() => {
          setShowProgressModal(false);
          setProgressData(null);
        }}
        assetId={activeEvaluation?.assetId || ""}
        evaluationId={activeEvaluation?.id || ""}
        progressData={progressData}
      />

      <OnboardingWizard
        open={showOnboarding}
        onClose={() => setShowOnboarding(false)}
      />
    </div>
  );
}
