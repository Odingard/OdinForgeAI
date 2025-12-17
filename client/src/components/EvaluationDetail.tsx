import { useState } from "react";
import { ArrowLeft, Clock, Activity, FileText, Shield, Target, Lightbulb, Network, Workflow, Cloud, FileSearch, Brain, Wrench, Play, Trash2, Archive, ArchiveRestore, MoreVertical } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { AttackPathVisualizer } from "./AttackPathVisualizer";
import { AttackGraphVisualizer } from "./AttackGraphVisualizer";
import { AnimatedAttackGraph } from "./AnimatedAttackGraph";
import { ExploitabilityGauge } from "./ExploitabilityGauge";
import { RecommendationsPanel } from "./RecommendationsPanel";
import { BusinessLogicFindingsPanel } from "./BusinessLogicFindingsPanel";
import { MultiVectorFindingsPanel } from "./MultiVectorFindingsPanel";
import { WorkflowStateMachineVisualizer } from "./WorkflowStateMachineVisualizer";
import { EvidencePanel } from "./EvidencePanel";
import { IntelligentScorePanel } from "./IntelligentScorePanel";
import { TimeToCompromiseMeter } from "./TimeToCompromiseMeter";
import { ConfidenceGauge } from "./ConfidenceGauge";
import { RiskHeatmap } from "./RiskHeatmap";
import { RemediationPanel } from "./RemediationPanel";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useViewMode } from "@/contexts/ViewModeContext";
import { useAuth } from "@/contexts/AuthContext";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Lock } from "lucide-react";
import type { BusinessLogicFinding, MultiVectorFinding, WorkflowStateMachine, EvidenceArtifact, IntelligentScore, RemediationGuidance } from "@shared/schema";

interface EvaluationDetailProps {
  evaluation: {
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
      discoveredBy?: "recon" | "exploit" | "lateral" | "business-logic" | "impact";
    }>;
    attackGraph?: {
      nodes: Array<{
        id: string;
        label: string;
        description: string;
        nodeType: "entry" | "pivot" | "objective" | "dead-end";
        tactic: string;
        compromiseLevel: "none" | "limited" | "user" | "admin" | "system";
        assets?: string[];
        discoveredBy?: "recon" | "exploit" | "lateral" | "business-logic" | "impact";
      }>;
      edges: Array<{
        id: string;
        source: string;
        target: string;
        technique: string;
        techniqueId?: string;
        description: string;
        successProbability: number;
        complexity: "trivial" | "low" | "medium" | "high" | "expert";
        timeEstimate: number;
        prerequisites?: string[];
        alternatives?: string[];
        edgeType: "primary" | "alternative" | "fallback";
        discoveredBy?: "recon" | "exploit" | "lateral" | "business-logic" | "impact";
      }>;
      entryNodeId: string;
      objectiveNodeIds: string[];
      criticalPath: string[];
      alternativePaths?: string[][];
      killChainCoverage: string[];
      complexityScore: number;
      timeToCompromise: {
        minimum: number;
        expected: number;
        maximum: number;
        unit: "minutes" | "hours" | "days";
      };
      chainedExploits?: Array<{
        name: string;
        techniques: string[];
        combinedImpact: string;
      }>;
    };
    recommendations?: Array<{
      id: string;
      title: string;
      description: string;
      priority: "critical" | "high" | "medium" | "low";
      type: "remediation" | "compensating" | "preventive";
    }>;
    businessLogicFindings?: BusinessLogicFinding[];
    multiVectorFindings?: MultiVectorFinding[];
    workflowAnalysis?: WorkflowStateMachine;
    evidenceArtifacts?: EvidenceArtifact[];
    intelligentScore?: IntelligentScore;
    remediationGuidance?: RemediationGuidance;
  };
  onBack: () => void;
}

export function EvaluationDetail({ evaluation, onBack }: EvaluationDetailProps) {
  const { viewMode } = useViewMode();
  const { needsSanitizedView, hasPermission } = useAuth();
  const [showAnimatedGraph, setShowAnimatedGraph] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [showArchiveDialog, setShowArchiveDialog] = useState(false);
  const { toast } = useToast();
  
  const isSanitized = needsSanitizedView();
  const canViewFullEvidence = hasPermission("evidence:read");

  const isArchived = evaluation.status === "archived";

  const deleteMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("DELETE", `/api/aev/evaluations/${evaluation.id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/stats"] });
      toast({
        title: "Evaluation deleted",
        description: "The evaluation has been permanently removed.",
      });
      onBack();
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to delete evaluation. Please try again.",
        variant: "destructive",
      });
    },
  });

  const archiveMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("PATCH", `/api/aev/evaluations/${evaluation.id}/archive`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/stats"] });
      toast({
        title: "Evaluation archived",
        description: "The evaluation has been moved to the archive.",
      });
      onBack();
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to archive evaluation. Please try again.",
        variant: "destructive",
      });
    },
  });

  const unarchiveMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("PATCH", `/api/aev/evaluations/${evaluation.id}/unarchive`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/aev/evaluations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/aev/stats"] });
      toast({
        title: "Evaluation restored",
        description: "The evaluation has been restored from archive.",
      });
      onBack();
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to restore evaluation. Please try again.",
        variant: "destructive",
      });
    },
  });

  const getSeverityBadge = (priority: string) => {
    const classes: Record<string, string> = {
      critical: "bg-red-500/10 text-red-400 border-red-500/30",
      high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
      medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
      low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    };
    return classes[priority] || "";
  };

  return (
    <div className="space-y-6" data-testid="evaluation-detail">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={onBack} data-testid="button-back">
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-2xl font-bold text-foreground">AEV Evaluation</h1>
              <Badge className={evaluation.exploitable 
                ? "bg-red-500/10 text-red-400 border-red-500/30" 
                : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
              }>
                {evaluation.exploitable ? "EXPLOITABLE" : "NOT EXPLOITABLE"}
              </Badge>
              {isArchived && (
                <Badge className="bg-slate-500/10 text-slate-400 border-slate-500/30">
                  ARCHIVED
                </Badge>
              )}
            </div>
            <p className="text-sm text-muted-foreground font-mono mt-1">{evaluation.id}</p>
          </div>
        </div>
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-4 text-sm text-muted-foreground">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4" />
              <span>{new Date(evaluation.createdAt).toLocaleString()}</span>
            </div>
            {evaluation.duration && (
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4" />
                <span>{(evaluation.duration / 1000).toFixed(1)}s</span>
              </div>
            )}
          </div>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="icon" data-testid="btn-actions-menu">
                <MoreVertical className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {isArchived ? (
                <DropdownMenuItem 
                  onClick={() => unarchiveMutation.mutate()}
                  data-testid="btn-restore"
                >
                  <ArchiveRestore className="h-4 w-4 mr-2" />
                  Restore from Archive
                </DropdownMenuItem>
              ) : (
                <DropdownMenuItem 
                  onClick={() => setShowArchiveDialog(true)}
                  data-testid="btn-archive"
                >
                  <Archive className="h-4 w-4 mr-2" />
                  Archive Evaluation
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem 
                onClick={() => setShowDeleteDialog(true)}
                className="text-destructive focus:text-destructive"
                data-testid="btn-delete"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Delete Permanently
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-border bg-muted/30">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-cyan-500/10">
                  <FileText className="h-5 w-5 text-cyan-400" />
                </div>
                <h2 className="text-lg font-semibold text-foreground">Exposure Summary</h2>
              </div>
            </div>
            <div className="p-6 space-y-6">
              <div className="grid grid-cols-2 gap-6">
                <div>
                  <label className="text-xs uppercase tracking-wider text-muted-foreground mb-1 block">
                    Asset ID
                  </label>
                  <p className="text-foreground font-mono text-sm">{evaluation.assetId}</p>
                </div>
                <div>
                  <label className="text-xs uppercase tracking-wider text-muted-foreground mb-1 block">
                    Exposure Type
                  </label>
                  <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/30">
                    {evaluation.exposureType.replace("_", " ").toUpperCase()}
                  </Badge>
                </div>
                <div>
                  <label className="text-xs uppercase tracking-wider text-muted-foreground mb-1 block">
                    Severity
                  </label>
                  <Badge className={getSeverityBadge(evaluation.priority)}>
                    {evaluation.priority.toUpperCase()}
                  </Badge>
                </div>
                <div>
                  <label className="text-xs uppercase tracking-wider text-muted-foreground mb-1 block">
                    Status
                  </label>
                  <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                    {evaluation.status.toUpperCase()}
                  </Badge>
                </div>
              </div>
              <div>
                <label className="text-xs uppercase tracking-wider text-muted-foreground mb-2 block">
                  Description
                </label>
                <p className="text-muted-foreground leading-relaxed">{evaluation.description}</p>
              </div>
            </div>
          </div>

          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-border bg-muted/30">
              <div className="flex items-center justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-orange-500/10">
                    <Target className="h-5 w-5 text-orange-400" />
                  </div>
                  <h2 className="text-lg font-semibold text-foreground">Attack Path Analysis</h2>
                </div>
                {evaluation.attackGraph && (
                  <Button 
                    variant="outline" 
                    size="sm" 
                    onClick={() => setShowAnimatedGraph(!showAnimatedGraph)}
                    className="gap-2"
                    data-testid="btn-toggle-animation-header"
                  >
                    <Play className="h-3.5 w-3.5" />
                    {showAnimatedGraph ? "Stop Animation" : "Play Attack"}
                  </Button>
                )}
              </div>
            </div>
            <div className="p-6">
              {showAnimatedGraph && evaluation.attackGraph ? (
                <AnimatedAttackGraph 
                  attackGraph={evaluation.attackGraph}
                  isExploitable={evaluation.exploitable ?? false}
                />
              ) : (
                <Tabs defaultValue={evaluation.attackGraph ? "graph" : "linear"} className="w-full">
                  <TabsList className="mb-4">
                    {evaluation.attackGraph && (
                      <TabsTrigger value="graph" className="gap-2" data-testid="tab-graph-view">
                        <Network className="h-4 w-4" />
                        Graph View
                      </TabsTrigger>
                    )}
                    <TabsTrigger value="linear" className="gap-2" data-testid="tab-linear-view">
                      <Target className="h-4 w-4" />
                      Linear View
                    </TabsTrigger>
                  </TabsList>
                  {evaluation.attackGraph && (
                    <TabsContent value="graph">
                      <AttackGraphVisualizer 
                        attackGraph={evaluation.attackGraph} 
                        isExploitable={evaluation.exploitable ?? false} 
                      />
                    </TabsContent>
                  )}
                  <TabsContent value="linear">
                    <AttackPathVisualizer 
                      steps={evaluation.attackPath || []} 
                      isExploitable={evaluation.exploitable ?? false} 
                    />
                  </TabsContent>
                </Tabs>
              )}
            </div>
          </div>

          {evaluation.businessLogicFindings && evaluation.businessLogicFindings.length > 0 && (
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-border bg-muted/30">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-amber-500/10">
                    <Workflow className="h-5 w-5 text-amber-400" />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">Business Logic Findings</h2>
                    <p className="text-xs text-muted-foreground">
                      {evaluation.businessLogicFindings.length} finding{evaluation.businessLogicFindings.length !== 1 ? 's' : ''} detected
                    </p>
                  </div>
                </div>
              </div>
              <div className="p-6">
                <BusinessLogicFindingsPanel findings={evaluation.businessLogicFindings} />
              </div>
            </div>
          )}

          {evaluation.multiVectorFindings && evaluation.multiVectorFindings.length > 0 && (
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-border bg-muted/30">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-cyan-500/10">
                    <Cloud className="h-5 w-5 text-cyan-400" />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">Multi-Vector Findings</h2>
                    <p className="text-xs text-muted-foreground">
                      {evaluation.multiVectorFindings.length} cloud/IAM/SaaS finding{evaluation.multiVectorFindings.length !== 1 ? 's' : ''}
                    </p>
                  </div>
                </div>
              </div>
              <div className="p-6">
                <MultiVectorFindingsPanel findings={evaluation.multiVectorFindings} />
              </div>
            </div>
          )}

          {evaluation.workflowAnalysis && (
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-border bg-muted/30">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-blue-500/10">
                    <Workflow className="h-5 w-5 text-blue-400" />
                  </div>
                  <h2 className="text-lg font-semibold text-foreground">Workflow State Machine</h2>
                </div>
              </div>
              <div className="p-6">
                <WorkflowStateMachineVisualizer workflow={evaluation.workflowAnalysis} />
              </div>
            </div>
          )}

          {evaluation.evidenceArtifacts && evaluation.evidenceArtifacts.length > 0 && (
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-border bg-muted/30">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-indigo-500/10">
                    <FileSearch className="h-5 w-5 text-indigo-400" />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">Evidence Artifacts</h2>
                    <p className="text-xs text-muted-foreground">
                      {isSanitized ? "Summary of evidence (details restricted)" : "Proof of exploit with sanitized data"}
                    </p>
                  </div>
                </div>
              </div>
              <div className="p-6">
                {isSanitized ? (
                  <Alert>
                    <Lock className="h-4 w-4" />
                    <AlertTitle>Evidence Details Restricted</AlertTitle>
                    <AlertDescription>
                      <p className="mb-2">
                        Raw exploit evidence and technical artifacts are not available for your role. 
                        This includes code snippets, payloads, and detailed attack traces.
                      </p>
                      <p className="text-sm text-muted-foreground">
                        <strong>{evaluation.evidenceArtifacts.length}</strong> evidence artifact(s) collected. 
                        Contact a Security Administrator for full access.
                      </p>
                    </AlertDescription>
                  </Alert>
                ) : (
                  <EvidencePanel artifacts={evaluation.evidenceArtifacts} evaluationId={evaluation.id} />
                )}
              </div>
            </div>
          )}
        </div>

        <div className="space-y-6 lg:col-span-1">
          {evaluation.attackGraph?.timeToCompromise && (
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <div className="p-6">
                <TimeToCompromiseMeter 
                  expected={evaluation.attackGraph.timeToCompromise.expected}
                  minimum={evaluation.attackGraph.timeToCompromise.minimum}
                  maximum={evaluation.attackGraph.timeToCompromise.maximum}
                  unit={evaluation.attackGraph.timeToCompromise.unit}
                />
              </div>
            </div>
          )}

          {viewMode === "executive" && evaluation.intelligentScore && (
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-border bg-muted/30">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-red-500/10">
                    <Shield className="h-5 w-5 text-red-400" />
                  </div>
                  <h2 className="text-lg font-semibold text-foreground">Risk Assessment</h2>
                </div>
              </div>
              <div className="p-6">
                <RiskHeatmap intelligentScore={evaluation.intelligentScore} />
              </div>
            </div>
          )}

          {viewMode === "engineer" && evaluation.intelligentScore && (
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-border bg-muted/30">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-purple-500/10">
                    <Brain className="h-5 w-5 text-purple-400" />
                  </div>
                  <h2 className="text-lg font-semibold text-foreground">Intelligent Risk Score</h2>
                </div>
              </div>
              <div className="p-6">
                <IntelligentScorePanel score={evaluation.intelligentScore} />
              </div>
            </div>
          )}

          {!evaluation.intelligentScore && (
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-border bg-muted/30">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-purple-500/10">
                    <Shield className="h-5 w-5 text-purple-400" />
                  </div>
                  <h2 className="text-lg font-semibold text-foreground">Exploitability Score</h2>
                </div>
              </div>
              <div className="p-6">
                <div className="flex items-center justify-center gap-6">
                  <ExploitabilityGauge 
                    score={evaluation.score ?? 0} 
                    confidence={evaluation.confidence ?? 0}
                    size="md"
                  />
                  <ConfidenceGauge 
                    confidence={evaluation.confidence ?? 0}
                    size="md"
                  />
                </div>
              </div>
            </div>
          )}

          {evaluation.remediationGuidance && (
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-border bg-muted/30">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-cyan-500/10">
                    <Wrench className="h-5 w-5 text-cyan-400" />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">Remediation Guidance</h2>
                    <p className="text-xs text-muted-foreground">
                      AI-generated fixes and mitigations
                    </p>
                  </div>
                </div>
              </div>
              <div className="p-6">
                <RemediationPanel guidance={evaluation.remediationGuidance} viewMode={viewMode} />
              </div>
            </div>
          )}

          <div className="bg-card border border-border rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-border bg-muted/30">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-emerald-500/10">
                  <Lightbulb className="h-5 w-5 text-emerald-400" />
                </div>
                <h2 className="text-lg font-semibold text-foreground">Recommendations</h2>
              </div>
            </div>
            <div className="p-6">
              <RecommendationsPanel recommendations={evaluation.recommendations || []} />
            </div>
          </div>
        </div>
      </div>

      <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Evaluation</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to permanently delete this evaluation? This action cannot be undone and all associated data will be lost.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel 
              disabled={deleteMutation.isPending}
              data-testid="btn-cancel-delete"
            >
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteMutation.mutate()}
              disabled={deleteMutation.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              data-testid="btn-confirm-delete"
            >
              {deleteMutation.isPending ? "Deleting..." : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={showArchiveDialog} onOpenChange={setShowArchiveDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Archive Evaluation</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to archive this evaluation? Archived evaluations can be restored later from the actions menu.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel 
              disabled={archiveMutation.isPending}
              data-testid="btn-cancel-archive"
            >
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => archiveMutation.mutate()}
              disabled={archiveMutation.isPending}
              data-testid="btn-confirm-archive"
            >
              {archiveMutation.isPending ? "Archiving..." : "Archive"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
