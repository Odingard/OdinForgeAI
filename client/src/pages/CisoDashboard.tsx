// =============================================================================
// Task 04 - CISO Dashboard
// client/src/pages/CisoDashboard.tsx
//
// Data sources (all existing OdinForge endpoints):
//   GET /api/aev/evaluations           - evaluation list
//   GET /api/intelligence/summary      - Intelligence Engine output (Task 02)
//   GET /api/entity-graph/snapshots    - risk trajectory (Task 01)
//
// Gracefully degrades if intelligence/entity-graph endpoints don't exist yet.
// =============================================================================

import { useState, useMemo } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";

import {
  Card, CardContent, CardHeader, CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";

import {
  Shield, AlertTriangle, Zap, TrendingUp, TrendingDown,
  ChevronRight, ExternalLink, Download, RefreshCw,
  Target, Activity, Lock, GitBranch,
  CheckCircle2, XCircle, Clock, ArrowRight, Eye,
  FileText, Layers, AlertCircle, BarChart3,
} from "lucide-react";

// =============================================================================
// TYPES
// =============================================================================

interface RiskSummary {
  composite_score: number;
  risk_grade: "A" | "B" | "C" | "D" | "F";
  kev_count: number;
  severity_distribution: Record<string, number>;
  top_findings: FindingSummary[];
  trend: "improving" | "stable" | "degrading";
  previous_score: number | null;
}

interface FindingSummary {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  cve_id: string | null;
  is_kev_listed: boolean;
  risk_score: number;
  remediation?: RemediationStep[];
  evidence?: Record<string, unknown>;
  confirmed: boolean;
}

interface RemediationStep {
  priority: number;
  action: string;
  effort: string;
  impact: string;
  evidence_ref?: string;
}

interface BreachChainData {
  id: string;
  evaluation_id: string;
  target: string;
  steps: string[];
  techniques: string[];
  confirmed: boolean;
  severity: "critical" | "high" | "medium" | "low";
  score: number;
  kill_chain_phase?: string;
  narrative?: string;
}

interface EvaluationData {
  id: string;
  status: string;
  exposureType: string;
  executionMode: string;
  score: number | null;
  exploitable: boolean | null;
  createdAt: string;
  completedAt?: string | null;
  updatedAt?: string | null;
  asset?: { hostname: string; assetIdentifier: string };
  intelligentScore?: {
    executiveSummary?: string;
    riskHeadline?: string;
    remediationSteps?: RemediationStep[];
    generatedBy?: string;
  };
  attackGraph?: {
    nodes: Array<{ id: string; technique: string; tactic: string }>;
    edges: Array<{ from: string; to: string }>;
    criticalPaths: string[][];
  };
}

interface RiskSnapshot {
  snapshotted_at: string;
  risk_score: number;
  deal_risk_grade: string | null;
  finding_counts: Record<string, number>;
}

// =============================================================================
// CONSTANTS
// =============================================================================

const SEVERITY_CONFIG = {
  critical: {
    bg: "bg-red-500/10",
    text: "text-red-400",
    border: "border-red-500/30",
    dot: "bg-red-500",
    glow: "shadow-[0_0_12px_hsl(var(--glow-red))]",
    bar: "bg-red-500",
  },
  high: {
    bg: "bg-orange-500/10",
    text: "text-orange-400",
    border: "border-orange-500/30",
    dot: "bg-orange-500",
    glow: "shadow-[0_0_12px_hsl(var(--glow-orange))]",
    bar: "bg-orange-500",
  },
  medium: {
    bg: "bg-amber-500/10",
    text: "text-amber-400",
    border: "border-amber-500/30",
    dot: "bg-amber-500",
    glow: "",
    bar: "bg-amber-500",
  },
  low: {
    bg: "bg-emerald-500/10",
    text: "text-emerald-400",
    border: "border-emerald-500/30",
    dot: "bg-emerald-500",
    glow: "",
    bar: "bg-emerald-500",
  },
  info: {
    bg: "bg-blue-500/10",
    text: "text-blue-400",
    border: "border-blue-500/30",
    dot: "bg-blue-500",
    glow: "",
    bar: "bg-blue-500",
  },
} as const;

const GRADE_CONFIG = {
  A: { color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30", label: "Low Risk" },
  B: { color: "text-cyan-400", bg: "bg-cyan-500/10", border: "border-cyan-500/30", label: "Guarded" },
  C: { color: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/30", label: "Elevated" },
  D: { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", label: "High Risk" },
  F: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", label: "Critical" },
} as const;

// =============================================================================
// SMALL COMPONENTS
// =============================================================================

function SeverityBadge({ severity }: { severity: keyof typeof SEVERITY_CONFIG }) {
  const cfg = SEVERITY_CONFIG[severity];
  return (
    <Badge
      variant="outline"
      className={`${cfg.bg} ${cfg.text} ${cfg.border} font-mono text-xs uppercase tracking-wide`}
    >
      {severity}
    </Badge>
  );
}

function GradeBadge({ grade }: { grade: keyof typeof GRADE_CONFIG }) {
  const cfg = GRADE_CONFIG[grade];
  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-md border ${cfg.bg} ${cfg.border}`}>
      <span className={`text-2xl font-black font-mono ${cfg.color}`}>{grade}</span>
      <span className={`text-xs font-medium ${cfg.color} opacity-80`}>{cfg.label}</span>
    </div>
  );
}

function ScoreRing({ score }: { score: number }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const progress = ((100 - score) / 100) * circumference;

  const color =
    score >= 85 ? "hsl(var(--glow-red))" :
    score >= 70 ? "hsl(var(--glow-orange))" :
    score >= 50 ? "#f59e0b" :
    score >= 30 ? "hsl(var(--glow-cyan))" :
    "#10b981";

  return (
    <div className="relative w-32 h-32 flex items-center justify-center">
      <svg className="absolute inset-0 -rotate-90" width="128" height="128" viewBox="0 0 128 128">
        <circle cx="64" cy="64" r={radius} fill="none" stroke="hsl(220 20% 12%)" strokeWidth="10" />
        <circle
          cx="64" cy="64" r={radius}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={progress}
          style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: "stroke-dashoffset 0.8s ease" }}
        />
      </svg>
      <div className="relative text-center">
        <div className="text-3xl font-black font-mono" style={{ color }}>{score.toFixed(0)}</div>
        <div className="text-[10px] text-muted-foreground font-mono uppercase tracking-widest">score</div>
      </div>
    </div>
  );
}

function TrendIndicator({ current, previous }: { current: number; previous: number | null }) {
  if (previous === null) return null;
  const delta = current - previous;
  if (Math.abs(delta) < 1) {
    return (
      <div className="flex items-center gap-1 text-muted-foreground text-xs">
        <Activity className="w-3 h-3" />
        <span>Stable</span>
      </div>
    );
  }
  const worse = delta > 0;
  return (
    <div className={`flex items-center gap-1 text-xs ${worse ? "text-red-400" : "text-emerald-400"}`}>
      {worse ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
      <span>{worse ? "+" : ""}{delta.toFixed(1)} from last scan</span>
    </div>
  );
}

function MiniSparkline({ snapshots }: { snapshots: RiskSnapshot[] }) {
  if (snapshots.length < 2) return null;

  const scores = snapshots.slice(-12).map(s => s.risk_score);
  const min = Math.min(...scores);
  const max = Math.max(...scores);
  const range = max - min || 1;
  const w = 120;
  const h = 32;
  const points = scores.map((s, i) => {
    const x = (i / (scores.length - 1)) * w;
    const y = h - ((s - min) / range) * h;
    return `${x},${y}`;
  }).join(" ");

  const lastScore = scores[scores.length - 1];
  const color = lastScore >= 70 ? "#f97316" : lastScore >= 50 ? "#f59e0b" : "#22d3ee";

  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="overflow-visible">
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        style={{ filter: `drop-shadow(0 0 3px ${color})` }}
      />
    </svg>
  );
}

// =============================================================================
// FINDING DETAIL DIALOG
// =============================================================================

function FindingDetailDialog({
  finding,
  open,
  onClose,
}: {
  finding: FindingSummary | null;
  open: boolean;
  onClose: () => void;
}) {
  if (!finding) return null;
  const cfg = SEVERITY_CONFIG[finding.severity];

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl bg-[hsl(220_25%_7%)] border-[hsl(220_20%_12%)]">
        <DialogHeader>
          <DialogTitle className="flex items-start gap-3 pr-6">
            <div className={`mt-0.5 w-2 h-2 rounded-full flex-shrink-0 ${cfg.dot} ${cfg.glow}`} />
            <span className="text-base font-semibold leading-snug">{finding.title}</span>
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 pt-1">
          <div className="flex flex-wrap gap-2">
            <SeverityBadge severity={finding.severity} />
            {finding.is_kev_listed && (
              <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 font-mono text-xs">
                KEV
              </Badge>
            )}
            {finding.confirmed && (
              <Badge variant="outline" className="bg-orange-500/10 text-orange-400 border-orange-500/30 text-xs">
                <Zap className="w-3 h-3 mr-1" />
                Confirmed Exploitable
              </Badge>
            )}
            {finding.cve_id && (
              <Badge variant="outline" className="font-mono text-xs text-muted-foreground border-border">
                {finding.cve_id}
              </Badge>
            )}
            <Badge variant="outline" className="text-xs text-muted-foreground border-border">
              {finding.category.replace(/_/g, " ")}
            </Badge>
          </div>

          <div className="space-y-1">
            <div className="flex justify-between text-xs text-muted-foreground">
              <span>Risk Score</span>
              <span className="font-mono text-foreground">{finding.risk_score.toFixed(1)}</span>
            </div>
            <Progress
              value={finding.risk_score}
              className="h-1.5"
              indicatorClassName={cfg.bar}
            />
          </div>

          {finding.remediation && finding.remediation.length > 0 && (
            <div className="space-y-2">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide flex items-center gap-1.5">
                <CheckCircle2 className="w-3 h-3" />
                Remediation
              </div>
              <div className="space-y-2">
                {finding.remediation.map((step, i) => (
                  <div
                    key={i}
                    className="rounded-md border border-[hsl(220_20%_12%)] bg-[hsl(220_30%_4%)] p-3 space-y-1"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-sm text-foreground leading-snug">{step.action}</span>
                      <span className={`text-xs font-mono flex-shrink-0 px-1.5 py-0.5 rounded border ${
                        step.effort === "hours"
                          ? "text-red-400 bg-red-500/10 border-red-500/30"
                          : step.effort === "days"
                          ? "text-orange-400 bg-orange-500/10 border-orange-500/30"
                          : "text-amber-400 bg-amber-500/10 border-amber-500/30"
                      }`}>
                        {step.effort}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground">{step.impact}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {finding.evidence && Object.keys(finding.evidence).length > 0 && (
            <div className="space-y-2">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide flex items-center gap-1.5">
                <FileText className="w-3 h-3" />
                Evidence
              </div>
              <ScrollArea className="h-24">
                <pre className="text-xs font-mono text-muted-foreground bg-[hsl(220_30%_4%)] rounded-md border border-[hsl(220_20%_12%)] p-3 whitespace-pre-wrap break-all">
                  {JSON.stringify(finding.evidence, null, 2)}
                </pre>
              </ScrollArea>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

// =============================================================================
// BREACH CHAIN CARD
// =============================================================================

function BreachChainCard({
  chain,
  rank,
  onClick,
}: {
  chain: BreachChainData;
  rank: number;
  onClick: () => void;
}) {
  const cfg = SEVERITY_CONFIG[chain.severity] ?? SEVERITY_CONFIG.high;

  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-lg border ${cfg.border} bg-[hsl(220_25%_7%)] p-4
        hover:bg-[hsl(220_25%_9%)] transition-colors group`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <div className={`flex-shrink-0 w-7 h-7 rounded-md flex items-center justify-center
            text-xs font-black font-mono ${cfg.bg} ${cfg.text}`}>
            {rank}
          </div>

          <div className="min-w-0 space-y-1.5">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-medium text-foreground truncate">
                {chain.target}
              </span>
              {chain.confirmed && (
                <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-[10px] px-1.5 py-0 font-mono">
                  CONFIRMED
                </Badge>
              )}
            </div>

            {chain.steps.length > 0 && (
              <div className="flex items-center gap-1 flex-wrap">
                {chain.steps.slice(0, 4).map((step, i) => (
                  <div key={i} className="flex items-center gap-1">
                    <span className="text-[11px] text-muted-foreground font-mono bg-[hsl(220_30%_4%)]
                      border border-[hsl(220_20%_12%)] px-1.5 py-0.5 rounded">
                      {step.length > 22 ? step.slice(0, 22) + "\u2026" : step}
                    </span>
                    {i < Math.min(chain.steps.length, 4) - 1 && (
                      <ArrowRight className="w-2.5 h-2.5 text-muted-foreground/50 flex-shrink-0" />
                    )}
                  </div>
                ))}
                {chain.steps.length > 4 && (
                  <span className="text-[11px] text-muted-foreground">+{chain.steps.length - 4} more</span>
                )}
              </div>
            )}

            {chain.techniques.length > 0 && (
              <div className="flex gap-1 flex-wrap">
                {chain.techniques.slice(0, 3).map(t => (
                  <span key={t} className="text-[10px] font-mono text-cyan-400/60
                    bg-cyan-500/5 border border-cyan-500/20 px-1.5 py-0.5 rounded">
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
          <SeverityBadge severity={chain.severity} />
          <div className="flex items-center gap-1 text-muted-foreground group-hover:text-foreground transition-colors">
            <Eye className="w-3 h-3" />
            <span className="text-xs">Details</span>
            <ChevronRight className="w-3 h-3" />
          </div>
        </div>
      </div>
    </button>
  );
}

// =============================================================================
// REMEDIATION PRIORITY QUEUE
// =============================================================================

function RemediationQueue({ findings }: { findings: FindingSummary[] }) {
  const [selectedFinding, setSelectedFinding] = useState<FindingSummary | null>(null);

  const allSteps = useMemo(() => {
    const steps: Array<RemediationStep & { finding: FindingSummary; globalPriority: number }> = [];

    const sorted = [...findings].sort((a, b) => {
      if (a.is_kev_listed !== b.is_kev_listed) return a.is_kev_listed ? -1 : 1;
      return b.risk_score - a.risk_score;
    });

    sorted.forEach((finding, fi) => {
      if (finding.remediation && finding.remediation.length > 0) {
        finding.remediation.forEach((step) => {
          steps.push({ ...step, finding, globalPriority: fi * 10 + step.priority });
        });
      } else {
        steps.push({
          priority: 1,
          action: `Remediate: ${finding.title}`,
          effort: finding.severity === "critical" ? "hours" : finding.severity === "high" ? "days" : "weeks",
          impact: `Removes ${finding.severity} severity ${finding.category.replace(/_/g, " ")} exposure`,
          evidence_ref: finding.title,
          finding,
          globalPriority: fi * 10,
        });
      }
    });

    return steps.slice(0, 12);
  }, [findings]);

  return (
    <>
      <div className="space-y-2">
        {allSteps.map((step, i) => {
          const cfg = SEVERITY_CONFIG[step.finding.severity];
          return (
            <div
              key={i}
              className={`flex items-start gap-3 p-3 rounded-lg border ${cfg.border} ${cfg.bg}
                hover:opacity-90 transition-opacity cursor-pointer`}
              onClick={() => setSelectedFinding(step.finding)}
            >
              <div className={`flex-shrink-0 w-6 h-6 rounded flex items-center justify-center
                text-xs font-black font-mono ${cfg.text}`}>
                {i + 1}
              </div>

              <div className="flex-1 min-w-0 space-y-0.5">
                <p className="text-sm text-foreground leading-snug">{step.action}</p>
                <p className="text-xs text-muted-foreground">{step.impact}</p>
              </div>

              <div className="flex flex-col items-end gap-1 flex-shrink-0">
                <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                  step.effort === "hours"
                    ? "text-red-400 bg-red-500/10 border-red-500/30"
                    : step.effort === "days"
                    ? "text-orange-400 bg-orange-500/10 border-orange-500/30"
                    : "text-amber-400 bg-amber-500/10 border-amber-500/30"
                }`}>
                  {step.effort}
                </span>
                {step.finding.is_kev_listed && (
                  <span className="text-[10px] text-red-400 font-mono">KEV</span>
                )}
              </div>
            </div>
          );
        })}

        {allSteps.length === 0 && (
          <div className="text-center py-8 text-muted-foreground">
            <CheckCircle2 className="w-8 h-8 mx-auto mb-2 text-emerald-400/50" />
            <p className="text-sm">No active remediation items</p>
          </div>
        )}
      </div>

      <FindingDetailDialog
        finding={selectedFinding}
        open={!!selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </>
  );
}

// =============================================================================
// MAIN DASHBOARD
// =============================================================================

export default function CisoDashboard() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const [selectedChain, setSelectedChain] = useState<BreachChainData | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<FindingSummary | null>(null);
  const [activeTab, setActiveTab] = useState("overview");

  const organizationId = (user as any)?.organizationId;

  // -- Data fetching --

  const { data: evaluations = [], isLoading: evalsLoading } = useQuery<EvaluationData[]>({
    queryKey: ["/api/aev/evaluations"],
    enabled: !!organizationId,
  });

  const { data: intelligence } = useQuery<{
    risk_grade: string;
    calibrated_score: number;
    executive_summary: string;
    risk_headline: string;
    remediation_steps: RemediationStep[];
    outcome_predictions: Array<{ outcome_label: string; probability: number }>;
    anomaly_signals: Array<{ signal: string; deviation_pct: number; direction: string }>;
  }>({
    queryKey: ["/api/intelligence/summary"],
    enabled: !!organizationId,
    retry: false,
  });

  const { data: snapshots = [] } = useQuery<RiskSnapshot[]>({
    queryKey: ["/api/entity-graph/snapshots"],
    enabled: !!organizationId,
    retry: false,
  });

  // -- Derived data --

  const { summary, breachChains, findings } = useMemo(() => {
    const completed = evaluations.filter(e => e.status === "completed");

    const allFindings: FindingSummary[] = completed.flatMap(evaluation => {
      const base: FindingSummary[] = [];
      if (evaluation.exploitable) {
        base.push({
          id: evaluation.id,
          title: `Confirmed exploit: ${evaluation.exposureType}`,
          severity: evaluation.score && evaluation.score >= 85 ? "critical" : "high",
          category: evaluation.exposureType,
          cve_id: null,
          is_kev_listed: false,
          risk_score: evaluation.score ?? 75,
          confirmed: true,
          remediation: evaluation.intelligentScore?.remediationSteps,
          evidence: {},
        });
      }
      return base;
    });

    const finalFindings = allFindings.sort((a, b) => b.risk_score - a.risk_score);

    const chains: BreachChainData[] = completed
      .filter(e => e.attackGraph && e.attackGraph.criticalPaths?.length > 0)
      .map(e => ({
        id: e.id,
        evaluation_id: e.id,
        target: e.asset?.hostname ?? e.asset?.assetIdentifier ?? "Unknown target",
        steps: e.attackGraph!.criticalPaths[0] ?? [],
        techniques: e.attackGraph!.nodes.map(n => n.technique).filter(Boolean).slice(0, 4),
        confirmed: e.exploitable ?? false,
        severity: (e.score ?? 0) >= 85 ? "critical" as const :
                  (e.score ?? 0) >= 70 ? "high" as const :
                  (e.score ?? 0) >= 50 ? "medium" as const : "low" as const,
        score: e.score ?? 0,
        narrative: e.intelligentScore?.riskHeadline,
      }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 5);

    const critCount = finalFindings.filter(f => f.severity === "critical").length;
    const highCount = finalFindings.filter(f => f.severity === "high").length;
    const kevCount = finalFindings.filter(f => f.is_kev_listed).length;
    const avgScore = intelligence?.calibrated_score ??
      (finalFindings.length
        ? finalFindings.reduce((s, f) => s + f.risk_score, 0) / finalFindings.length
        : 0);
    const grade = (intelligence?.risk_grade as RiskSummary["risk_grade"]) ??
      (avgScore >= 85 ? "F" : avgScore >= 70 ? "D" : avgScore >= 50 ? "C" : avgScore >= 30 ? "B" : "A");

    const prevScore = snapshots.length >= 2 ? snapshots[snapshots.length - 2].risk_score : null;

    const riskSummary: RiskSummary = {
      composite_score: Math.round(avgScore * 10) / 10,
      risk_grade: grade,
      kev_count: kevCount,
      severity_distribution: {
        critical: critCount,
        high: highCount,
        medium: finalFindings.filter(f => f.severity === "medium").length,
        low: finalFindings.filter(f => f.severity === "low").length,
      },
      top_findings: finalFindings.slice(0, 10),
      trend: prevScore === null ? "stable" : avgScore > prevScore + 2 ? "degrading" : avgScore < prevScore - 2 ? "improving" : "stable",
      previous_score: prevScore,
    };

    return { summary: riskSummary, breachChains: chains, findings: finalFindings };
  }, [evaluations, intelligence, snapshots]);

  const isLoading = evalsLoading;
  const lastScan = evaluations
    .filter(e => e.completedAt || e.updatedAt)
    .sort((a, b) => new Date(b.completedAt ?? b.updatedAt ?? 0).getTime() - new Date(a.completedAt ?? a.updatedAt ?? 0).getTime())[0];

  // -- Handlers --

  const handleExportPDF = async () => {
    try {
      const res = await apiRequest("POST", "/api/reports/generate", {
        type: "ciso_summary",
        organization_id: organizationId,
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `ciso-report-${new Date().toISOString().slice(0, 10)}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
        toast({ title: "Report exported", description: "CISO summary PDF downloaded" });
      }
    } catch {
      toast({ title: "Export failed", description: "Could not generate report", variant: "destructive" });
    }
  };

  // -- Render --

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex items-center gap-3 text-muted-foreground">
          <RefreshCw className="w-4 h-4 animate-spin" />
          <span className="text-sm">Loading security posture...</span>
        </div>
      </div>
    );
  }

  const gradeCfg = GRADE_CONFIG[summary.risk_grade];

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <div className="border-b border-border bg-[hsl(220_25%_7%)] sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30
              flex items-center justify-center">
              <Shield className="w-4 h-4 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-sm font-semibold text-foreground">Security Posture</h1>
              {lastScan && (
                <p className="text-[11px] text-muted-foreground font-mono">
                  Last scan {new Date(lastScan.completedAt ?? lastScan.updatedAt ?? "").toLocaleDateString("en-US", {
                    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
                  })}
                </p>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5 text-xs border-border"
              onClick={() => navigate("/assess")}
            >
              <Target className="w-3.5 h-3.5" />
              New Scan
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5 text-xs border-border"
              onClick={handleExportPDF}
            >
              <Download className="w-3.5 h-3.5" />
              Export PDF
            </Button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">

        {/* Risk Headline (from Intelligence Engine) */}
        {(intelligence?.risk_headline) && (
          <div className={`rounded-lg border ${gradeCfg.border} ${gradeCfg.bg} px-4 py-3
            flex items-start gap-3`}>
            <AlertCircle className={`w-4 h-4 flex-shrink-0 mt-0.5 ${gradeCfg.color}`} />
            <p className={`text-sm font-medium ${gradeCfg.color}`}>
              {intelligence.risk_headline}
            </p>
          </div>
        )}

        {/* Top stats row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card className="col-span-2 md:col-span-1 bg-[hsl(220_25%_7%)] border-[hsl(220_20%_12%)]">
            <CardContent className="pt-5 pb-4 flex flex-col items-center gap-3">
              <ScoreRing score={summary.composite_score} />
              <div className="text-center space-y-1">
                <GradeBadge grade={summary.risk_grade} />
                <TrendIndicator
                  current={summary.composite_score}
                  previous={summary.previous_score}
                />
              </div>
              {snapshots.length >= 2 && (
                <MiniSparkline snapshots={snapshots} />
              )}
            </CardContent>
          </Card>

          {[
            {
              label: "KEV Findings",
              value: summary.kev_count,
              icon: Zap,
              color: "text-red-400",
              bg: "bg-red-500/10",
              border: "border-red-500/30",
              note: "Active exploitation confirmed",
              urgent: summary.kev_count > 0,
            },
            {
              label: "Critical",
              value: summary.severity_distribution.critical ?? 0,
              icon: AlertTriangle,
              color: "text-orange-400",
              bg: "bg-orange-500/10",
              border: "border-orange-500/30",
              note: "Immediate action required",
              urgent: (summary.severity_distribution.critical ?? 0) > 0,
            },
            {
              label: "Breach Chains",
              value: breachChains.length,
              icon: GitBranch,
              color: "text-cyan-400",
              bg: "bg-cyan-500/10",
              border: "border-cyan-500/30",
              note: `${breachChains.filter(c => c.confirmed).length} confirmed exploitable`,
              urgent: breachChains.some(c => c.confirmed),
            },
          ].map(stat => (
            <Card
              key={stat.label}
              className={`bg-[hsl(220_25%_7%)] ${stat.urgent ? `border ${stat.border}` : "border-[hsl(220_20%_12%)]"}`}
            >
              <CardContent className="pt-5 pb-4 flex flex-col justify-between h-full gap-3">
                <div className={`w-9 h-9 rounded-lg ${stat.bg} border ${stat.border}
                  flex items-center justify-center`}>
                  <stat.icon className={`w-4 h-4 ${stat.color}`} />
                </div>
                <div>
                  <div className={`text-3xl font-black font-mono ${stat.color}`}>
                    {stat.value}
                  </div>
                  <div className="text-sm font-medium text-foreground">{stat.label}</div>
                  <div className="text-xs text-muted-foreground mt-0.5">{stat.note}</div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Executive summary (Intelligence Engine) */}
        {intelligence?.executive_summary && (
          <Card className="bg-[hsl(220_25%_7%)] border-[hsl(220_20%_12%)]">
            <CardContent className="pt-5 pb-4">
              <div className="flex items-start gap-3">
                <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30
                  flex items-center justify-center flex-shrink-0">
                  <BarChart3 className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                      Executive Summary
                    </span>
                    <span className="text-[10px] font-mono text-muted-foreground/50">
                      via Intelligence Engine
                    </span>
                  </div>
                  <p className="text-sm text-foreground/90 leading-relaxed">
                    {intelligence.executive_summary}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Main content tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-[hsl(220_25%_7%)] border border-[hsl(220_20%_12%)]">
            <TabsTrigger value="overview" className="text-xs gap-1.5">
              <Layers className="w-3 h-3" />
              Breach Paths
              {breachChains.length > 0 && (
                <span className="ml-1 bg-primary/20 text-primary text-[10px] font-mono
                  px-1.5 rounded-sm">{breachChains.length}</span>
              )}
            </TabsTrigger>
            <TabsTrigger value="remediation" className="text-xs gap-1.5">
              <CheckCircle2 className="w-3 h-3" />
              Remediation
              {findings.length > 0 && (
                <span className="ml-1 bg-orange-500/20 text-orange-400 text-[10px] font-mono
                  px-1.5 rounded-sm">{findings.length}</span>
              )}
            </TabsTrigger>
            <TabsTrigger value="findings" className="text-xs gap-1.5">
              <AlertTriangle className="w-3 h-3" />
              All Findings
            </TabsTrigger>
            {snapshots.length > 0 && (
              <TabsTrigger value="history" className="text-xs gap-1.5">
                <Activity className="w-3 h-3" />
                History
              </TabsTrigger>
            )}
          </TabsList>

          {/* Breach paths tab */}
          <TabsContent value="overview" className="mt-4 space-y-3">
            {breachChains.length === 0 ? (
              <Card className="bg-[hsl(220_25%_7%)] border-[hsl(220_20%_12%)]">
                <CardContent className="py-12 text-center space-y-2">
                  <Lock className="w-8 h-8 mx-auto text-emerald-400/50" />
                  <p className="text-sm text-muted-foreground">No active breach paths detected</p>
                  <p className="text-xs text-muted-foreground/60">
                    Run an evaluation to detect potential attack chains
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-2 gap-1.5 text-xs"
                    onClick={() => navigate("/assess")}
                  >
                    <Target className="w-3.5 h-3.5" />
                    Run Evaluation
                  </Button>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-3">
                {breachChains.map((chain, i) => (
                  <BreachChainCard
                    key={chain.id}
                    chain={chain}
                    rank={i + 1}
                    onClick={() => setSelectedChain(chain)}
                  />
                ))}
              </div>
            )}
          </TabsContent>

          {/* Remediation tab */}
          <TabsContent value="remediation" className="mt-4">
            <Card className="bg-[hsl(220_25%_7%)] border-[hsl(220_20%_12%)]">
              <CardHeader className="pb-3 pt-4 px-4">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                  Priority Queue
                  <span className="text-xs text-muted-foreground font-normal ml-auto">
                    Sorted by risk impact
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-4">
                <ScrollArea className="h-[480px] pr-2">
                  <RemediationQueue findings={findings} />
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>

          {/* All findings tab */}
          <TabsContent value="findings" className="mt-4">
            <Card className="bg-[hsl(220_25%_7%)] border-[hsl(220_20%_12%)]">
              <CardContent className="p-0">
                <ScrollArea className="h-[520px]">
                  <div className="divide-y divide-[hsl(220_20%_12%)]">
                    {findings.length === 0 ? (
                      <div className="py-12 text-center text-muted-foreground text-sm">
                        No findings recorded
                      </div>
                    ) : (
                      findings.map(finding => {
                        const cfg = SEVERITY_CONFIG[finding.severity];
                        return (
                          <button
                            key={finding.id}
                            className="w-full text-left px-4 py-3 hover:bg-[hsl(220_25%_9%)]
                              transition-colors flex items-center gap-3 group"
                            onClick={() => setSelectedFinding(finding)}
                          >
                            <div className={`w-2 h-2 rounded-full flex-shrink-0 ${cfg.dot}`} />

                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-sm text-foreground truncate">
                                  {finding.title}
                                </span>
                                {finding.is_kev_listed && (
                                  <span className="text-[10px] font-mono text-red-400">KEV</span>
                                )}
                                {finding.confirmed && (
                                  <span className="text-[10px] font-mono text-orange-400">CONFIRMED</span>
                                )}
                              </div>
                              <div className="flex items-center gap-2 mt-0.5">
                                <span className="text-xs text-muted-foreground">
                                  {finding.category.replace(/_/g, " ")}
                                </span>
                                {finding.cve_id && (
                                  <span className="text-[10px] font-mono text-muted-foreground/60">
                                    {finding.cve_id}
                                  </span>
                                )}
                              </div>
                            </div>

                            <div className="flex items-center gap-2 flex-shrink-0">
                              <span className={`text-xs font-mono ${cfg.text}`}>
                                {finding.risk_score.toFixed(0)}
                              </span>
                              <SeverityBadge severity={finding.severity} />
                              <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/40
                                group-hover:text-muted-foreground transition-colors" />
                            </div>
                          </button>
                        );
                      })
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Scan history tab */}
          {snapshots.length > 0 && (
            <TabsContent value="history" className="mt-4">
              <Card className="bg-[hsl(220_25%_7%)] border-[hsl(220_20%_12%)]">
                <CardContent className="p-0">
                  <ScrollArea className="h-[400px]">
                    <div className="divide-y divide-[hsl(220_20%_12%)]">
                      {[...snapshots].reverse().map((snap, i) => {
                        const grade = (snap.deal_risk_grade ?? "C") as keyof typeof GRADE_CONFIG;
                        const cfg = GRADE_CONFIG[grade] ?? GRADE_CONFIG.C;
                        const prev = snapshots[snapshots.length - 2 - i];
                        const delta = prev ? snap.risk_score - prev.risk_score : null;

                        return (
                          <div key={i} className="flex items-center gap-4 px-4 py-3">
                            <div className={`w-8 h-8 rounded-md ${cfg.bg} border ${cfg.border}
                              flex items-center justify-center`}>
                              <span className={`text-sm font-black font-mono ${cfg.color}`}>
                                {grade}
                              </span>
                            </div>

                            <div className="flex-1">
                              <div className="text-sm font-mono text-foreground">
                                {snap.risk_score.toFixed(1)}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {new Date(snap.snapshotted_at).toLocaleDateString("en-US", {
                                  month: "short", day: "numeric", year: "numeric",
                                  hour: "2-digit", minute: "2-digit",
                                })}
                              </div>
                            </div>

                            {delta !== null && (
                              <div className={`flex items-center gap-1 text-xs font-mono ${
                                delta > 0 ? "text-red-400" : delta < 0 ? "text-emerald-400" : "text-muted-foreground"
                              }`}>
                                {delta > 0 ? <TrendingUp className="w-3 h-3" /> :
                                 delta < 0 ? <TrendingDown className="w-3 h-3" /> :
                                 <Activity className="w-3 h-3" />}
                                {delta > 0 ? "+" : ""}{delta.toFixed(1)}
                              </div>
                            )}

                            <div className="flex gap-1">
                              {Object.entries(snap.finding_counts ?? {})
                                .filter(([, v]) => (v as number) > 0)
                                .map(([sev, count]) => (
                                  <span
                                    key={sev}
                                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded border
                                      ${SEVERITY_CONFIG[sev as keyof typeof SEVERITY_CONFIG]?.bg ?? "bg-muted/10"}
                                      ${SEVERITY_CONFIG[sev as keyof typeof SEVERITY_CONFIG]?.text ?? "text-muted-foreground"}
                                      ${SEVERITY_CONFIG[sev as keyof typeof SEVERITY_CONFIG]?.border ?? "border-border"}`}
                                  >
                                    {count as number} {sev.slice(0, 1).toUpperCase()}
                                  </span>
                                ))}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </TabsContent>
          )}
        </Tabs>
      </div>

      {/* Breach chain detail dialog */}
      <Dialog open={!!selectedChain} onOpenChange={() => setSelectedChain(null)}>
        <DialogContent className="max-w-2xl bg-[hsl(220_25%_7%)] border-[hsl(220_20%_12%)]">
          {selectedChain && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2 text-base">
                  <GitBranch className="w-4 h-4 text-cyan-400" />
                  Breach Chain - {selectedChain.target}
                </DialogTitle>
              </DialogHeader>

              <div className="space-y-4 pt-1">
                <div className="flex gap-2 flex-wrap">
                  <SeverityBadge severity={selectedChain.severity} />
                  {selectedChain.confirmed && (
                    <Badge variant="outline"
                      className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                      <Zap className="w-3 h-3 mr-1" />
                      Agent Confirmed
                    </Badge>
                  )}
                  {selectedChain.kill_chain_phase && (
                    <Badge variant="outline" className="text-xs text-muted-foreground border-border">
                      {selectedChain.kill_chain_phase}
                    </Badge>
                  )}
                </div>

                {selectedChain.narrative && (
                  <div className="rounded-lg border border-[hsl(220_20%_12%)] bg-[hsl(220_30%_4%)] p-3">
                    <p className="text-sm text-foreground/90">{selectedChain.narrative}</p>
                  </div>
                )}

                {selectedChain.steps.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                      Attack Path ({selectedChain.steps.length} steps)
                    </div>
                    <div className="space-y-1">
                      {selectedChain.steps.map((step, i) => (
                        <div key={i} className="flex items-start gap-2">
                          <div className="flex-shrink-0 w-5 h-5 rounded bg-[hsl(220_30%_4%)]
                            border border-[hsl(220_20%_12%)] flex items-center justify-center mt-0.5">
                            <span className="text-[10px] font-mono text-muted-foreground">{i + 1}</span>
                          </div>
                          <div className="flex items-start gap-2 flex-1">
                            <span className="text-sm text-foreground">{step}</span>
                            {i < selectedChain.steps.length - 1 && (
                              <ArrowRight className="w-3.5 h-3.5 text-muted-foreground/40
                                flex-shrink-0 mt-0.5" />
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {selectedChain.techniques.length > 0 && (
                  <div className="space-y-2">
                    <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                      MITRE ATT&CK Techniques
                    </div>
                    <div className="flex gap-2 flex-wrap">
                      {selectedChain.techniques.map(t => (
                        <a
                          key={t}
                          href={`https://attack.mitre.org/techniques/${t}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs font-mono text-cyan-400 bg-cyan-500/10
                            border border-cyan-500/30 px-2 py-1 rounded hover:bg-cyan-500/20
                            transition-colors flex items-center gap-1"
                        >
                          {t}
                          <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex justify-end pt-1">
                  <Button
                    variant="outline"
                    size="sm"
                    className="gap-1.5 text-xs"
                    onClick={() => {
                      setSelectedChain(null);
                      navigate(`/risk`);
                    }}
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    Full Evaluation
                  </Button>
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      <FindingDetailDialog
        finding={selectedFinding}
        open={!!selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
