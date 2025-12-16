import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { 
  Zap, 
  Target, 
  ShieldCheck, 
  AlertTriangle, 
  Activity, 
  RefreshCw,
  Plus,
  Loader2,
  Wand2,
  FileText,
  ChevronDown
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { StatCard } from "./StatCard";
import { FilterBar } from "./FilterBar";
import { EvaluationTable, Evaluation } from "./EvaluationTable";
import { NewEvaluationModal, EvaluationFormData } from "./NewEvaluationModal";
import { ProgressModal } from "./ProgressModal";
import { EvaluationDetail } from "./EvaluationDetail";
import { EvaluationWizard } from "./EvaluationWizard";
import { apiRequest, queryClient } from "@/lib/queryClient";

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
  const [filter, setFilter] = useState("all");
  const [showNewModal, setShowNewModal] = useState(false);
  const [showWizard, setShowWizard] = useState(false);
  const [showProgressModal, setShowProgressModal] = useState(false);
  const [activeEvaluation, setActiveEvaluation] = useState<{ assetId: string; id: string } | null>(null);
  const [selectedEvaluationId, setSelectedEvaluationId] = useState<string | null>(null);
  const [progressData, setProgressData] = useState<{ agentName?: string; stage: string; progress: number; message: string } | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const { data: evaluations = [], isLoading, refetch } = useQuery<Evaluation[]>({
    queryKey: ["/api/aev/evaluations"],
  });

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
    setActiveEvaluation({ assetId: evaluation.assetId, id: evaluation.id });
    setShowProgressModal(true);
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
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-xl font-bold text-foreground flex items-center gap-2 flex-wrap">
            OdinForge AI
            <span className="text-xs font-medium px-2 py-0.5 rounded bg-gradient-to-r from-cyan-500/20 to-blue-500/20 text-cyan-400 border border-cyan-500/30">
              AUTONOMOUS VALIDATION
            </span>
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            AI-powered adversarial exposure validation with autonomous exploit chaining
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Button 
            variant="outline" 
            size="sm" 
            data-testid="button-refresh"
            onClick={() => refetch()}
            disabled={isLoading}
          >
            <RefreshCw className={`h-3.5 w-3.5 mr-2 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button 
                size="sm"
                className="bg-gradient-to-r from-cyan-600 to-blue-600"
                data-testid="button-new-evaluation"
              >
                <Plus className="h-3.5 w-3.5 mr-2" />
                New Evaluation
                <ChevronDown className="h-3.5 w-3.5 ml-2" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuItem onClick={() => setShowWizard(true)} data-testid="menu-guided-wizard">
                <Wand2 className="h-4 w-4 mr-2" />
                <div>
                  <div className="font-medium">Guided Wizard</div>
                  <div className="text-xs text-muted-foreground">Step-by-step templates</div>
                </div>
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setShowNewModal(true)} data-testid="menu-quick-evaluation">
                <FileText className="h-4 w-4 mr-2" />
                <div>
                  <div className="font-medium">Quick Evaluation</div>
                  <div className="text-xs text-muted-foreground">Manual description input</div>
                </div>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
        <StatCard 
          label="Total Evaluations" 
          value={stats.total} 
          icon={Target}
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
        />
        <StatCard 
          label="Safe" 
          value={stats.safe} 
          icon={ShieldCheck}
          colorClass="text-emerald-400"
        />
        <StatCard 
          label="Avg Confidence" 
          value={`${stats.avgConfidence}%`} 
          icon={Zap}
          colorClass="text-cyan-400"
        />
      </div>

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
    </div>
  );
}
