import { useState, useEffect, useRef, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Loader2, Zap, RefreshCw } from "lucide-react";
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
} from "./dashboard/index";

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

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
    queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
    queryClient.invalidateQueries({ queryKey: ["/api/defensive-posture/default"] });
  };

  return (
    <div className="flex flex-col gap-[14px] min-h-0 flex-1">
      {/* Page Header */}
      <div className="flex justify-between items-start">
        <div>
          <div className="text-[18px] font-semibold tracking-[-0.02em]" style={{ color: "var(--falcon-t1)" }}>
            Dashboard
          </div>
          <div className="mt-1 text-[11px] font-mono tracking-[0.04em]" style={{ color: "var(--falcon-t3)" }}>
            // threat operations overview &middot; {assets.length} targets in scope
          </div>
        </div>
        <div className="flex gap-2">
          <button className="f-btn f-btn-ghost" onClick={handleRefresh}>
            <RefreshCw className="w-3 h-3" />
            Refresh
          </button>
          <button className="f-btn f-btn-primary" onClick={() => setShowWizard(true)}>
            <Zap className="w-3 h-3" />
            New Assessment
          </button>
        </div>
      </div>

      {/* KPI Strip */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-[10px]">
        <RiskScoreGauge posture={posture} />
        <FindingsSeverityBreakdown evaluations={evaluations} />
        <FindingsMetricCards evaluations={evaluations} />
        <ReachabilityExploitabilityMatrix evaluations={evaluations} />
      </div>

      {/* Two-column: table + sidebar */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_300px] gap-3 flex-1 min-h-0">
        <RecentEvaluations evaluations={evaluations} />

        <div className="flex flex-col gap-3">
          <ThreatCard posture={posture} evaluations={evaluations} />
          <ActivityFeed evaluations={evaluations} />
        </div>
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
  );
}

/* ── Threat Ring Card ── */
function ThreatCard({ posture, evaluations }: { posture: any; evaluations: any[] }) {
  const score = posture?.overallScore ?? posture?.score ?? 0;
  const normalized = Math.min(10, Math.max(0, score / 10));
  const displayScore = normalized.toFixed(1);
  const isHot = normalized >= 7;

  const completed = evaluations.filter((e: any) => e.status === "completed");
  const exploitable = completed.filter((e: any) => e.exploitable).length;
  const exploitPct = completed.length > 0 ? Math.round((exploitable / completed.length) * 100) : 0;
  const critCount = evaluations.filter((e: any) => (e.priority || e.severity || "").toLowerCase() === "critical").length;
  const critPct = evaluations.length > 0 ? Math.min(100, Math.round((critCount / evaluations.length) * 100)) : 0;
  const coveragePct = evaluations.length > 0 ? Math.round((completed.length / evaluations.length) * 100) : 0;

  const radius = 33;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (circumference * Math.min(normalized / 10, 1));

  return (
    <div
      className="flex items-center gap-4 p-4 rounded-[6px]"
      style={{ background: "var(--falcon-panel)", border: "1px solid var(--falcon-border)" }}
    >
      <div className="relative w-20 h-20 shrink-0">
        <svg viewBox="0 0 80 80" className="w-20 h-20">
          <circle cx="40" cy="40" r={radius} fill="none" stroke="rgba(232,56,79,0.08)" strokeWidth="7" />
          <circle
            cx="40" cy="40" r={radius} fill="none"
            stroke={isHot ? "url(#threat-grad)" : "var(--falcon-blue)"}
            strokeWidth="7" strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            transform="rotate(-90 40 40)"
          />
          <defs>
            <linearGradient id="threat-grad">
              <stop offset="0%" stopColor="var(--falcon-orange)" />
              <stop offset="100%" stopColor="var(--falcon-red)" />
            </linearGradient>
          </defs>
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className="font-mono text-[20px] font-semibold leading-none" style={{ color: isHot ? "var(--falcon-red)" : "var(--falcon-blue-hi)" }}>
            {displayScore}
          </div>
          <div className="text-[8px] font-medium tracking-[0.12em] uppercase" style={{ color: "var(--falcon-t3)" }}>
            {isHot ? "Critical" : "Normal"}
          </div>
        </div>
      </div>

      <div className="flex-1 flex flex-col gap-[6px]">
        <div className="text-[13px] font-semibold" style={{ color: "var(--falcon-t1)" }}>
          {isHot ? "Critical" : "Moderate"} Risk Level
        </div>
        <div className="text-[11px] font-mono" style={{ color: "var(--falcon-t3)" }}>
          {exploitable} exploitable findings
        </div>
        <div className="flex flex-col gap-[5px] mt-1">
          <ThreatBar label="EXPLOIT" pct={exploitPct} cls="f-tf-r" />
          <ThreatBar label="SURFACE" pct={critPct} cls="f-tf-o" />
          <ThreatBar label="COVERAGE" pct={coveragePct} cls="f-tf-g" />
        </div>
      </div>
    </div>
  );
}

function ThreatBar({ label, pct, cls }: { label: string; pct: number; cls: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="font-mono text-[9px] w-14 tracking-[0.04em]" style={{ color: "var(--falcon-t3)" }}>{label}</span>
      <div className="f-tb-track">
        <div className={`f-tb-fill ${cls}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="font-mono text-[9px] w-6 text-right" style={{ color: "var(--falcon-t2)" }}>{pct}%</span>
    </div>
  );
}

/* ── Activity Feed ── */
function ActivityFeed({ evaluations }: { evaluations: any[] }) {
  const recent = useMemo(() =>
    [...evaluations]
      .filter((e: any) => e.createdAt)
      .sort((a: any, b: any) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .slice(0, 6),
    [evaluations],
  );

  function timeAgo(iso: string): string {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }

  function iconClass(e: any) {
    if (e.exploitable) return "f-act-r";
    if ((e.priority || e.severity || "").toLowerCase() === "critical") return "f-act-o";
    if (e.status === "completed") return "f-act-g";
    return "f-act-b";
  }

  function description(e: any) {
    const type = (e.exposureType || "assessment").replace(/_/g, " ");
    if (e.exploitable) return `Exploit confirmed: ${type}`;
    if (e.status === "in_progress") return `Running: ${type}`;
    if (e.status === "completed") return `Completed: ${type}`;
    return `Queued: ${type}`;
  }

  return (
    <div className="f-panel" style={{ flex: 1, minHeight: 0 }}>
      <div className="f-panel-head">
        <div className="f-panel-title"><span className="f-panel-dot g" />Live Activity</div>
      </div>
      <div className="flex-1 overflow-y-auto">
        {recent.length === 0 ? (
          <div className="flex items-center justify-center py-8">
            <span className="text-[10px]" style={{ color: "var(--falcon-t4)" }}>No recent activity</span>
          </div>
        ) : (
          recent.map((e: any) => (
            <div
              key={e.id}
              className="flex gap-[10px] py-[9px] px-4 cursor-pointer transition-colors"
              style={{ borderBottom: "1px solid rgba(28,42,62,0.5)" }}
              onMouseEnter={(ev) => { ev.currentTarget.style.background = "var(--falcon-panel-2)"; }}
              onMouseLeave={(ev) => { ev.currentTarget.style.background = ""; }}
            >
              <div className={`f-act-icon ${iconClass(e)}`}>
                <Zap className="w-[13px] h-[13px]" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-[12px] font-medium leading-[1.4]" style={{ color: "var(--falcon-t1)" }}>
                  {description(e)}
                </div>
                <div className="flex gap-2 mt-[3px] font-mono text-[9.5px]" style={{ color: "var(--falcon-t3)" }}>
                  <span>{e.createdAt ? timeAgo(e.createdAt) : ""}</span>
                  {e.assetId && (
                    <span className="px-[5px] rounded-sm" style={{ background: "rgba(255,255,255,0.04)", color: "var(--falcon-t2)" }}>
                      {e.assetId.slice(0, 8)}
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
