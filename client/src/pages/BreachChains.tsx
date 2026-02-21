import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import { useBreachChainUpdates } from "@/hooks/useBreachChainUpdates";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import {
  Link2,
  Play,
  Pause,
  StopCircle,
  Trash2,
  Eye,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  Shield,
  Key,
  Server,
  Cloud,
  Container,
  Network,
  AlertTriangle,
  FileText,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Crosshair,
  Zap,
  Lock,
  SkipForward,
  Ban,
  Target,
  Settings2,
  ArrowRight,
  FileBarChart,
} from "lucide-react";
import type { BreachChain, BreachPhaseResult, BreachPhaseContext, BreachPhaseName, AttackGraph } from "@shared/schema";
import { LiveBreachChainGraph } from "@/components/LiveBreachChainGraph";

// Phase metadata for display
const PHASE_META: Record<string, { label: string; icon: typeof Shield; color: string; description: string }> = {
  application_compromise: {
    label: "App Compromise",
    icon: Crosshair,
    color: "text-red-500",
    description: "Exploit application-layer vulnerabilities with active payloads",
  },
  credential_extraction: {
    label: "Credential Extraction",
    icon: Key,
    color: "text-amber-500",
    description: "Harvest credentials from compromised applications",
  },
  cloud_iam_escalation: {
    label: "Cloud IAM Escalation",
    icon: Cloud,
    color: "text-cyan-500",
    description: "Escalate privileges via IAM misconfigurations",
  },
  container_k8s_breakout: {
    label: "K8s Breakout",
    icon: Container,
    color: "text-purple-500",
    description: "Exploit RBAC, secrets, and container escape paths",
  },
  lateral_movement: {
    label: "Lateral Movement",
    icon: Network,
    color: "text-blue-500",
    description: "Pivot across network using harvested credentials",
  },
  impact_assessment: {
    label: "Impact Assessment",
    icon: AlertTriangle,
    color: "text-orange-500",
    description: "Aggregate business impact and compliance gaps",
  },
};

const STATUS_STYLES: Record<string, string> = {
  pending: "bg-muted text-muted-foreground",
  running: "bg-blue-500/20 text-blue-400",
  paused: "bg-amber-500/20 text-amber-400",
  completed: "bg-emerald-500/20 text-emerald-400",
  failed: "bg-destructive/20 text-destructive",
  aborted: "bg-muted text-muted-foreground",
  skipped: "bg-muted text-muted-foreground",
  blocked: "bg-orange-500/20 text-orange-400",
};

const PHASE_STATUS_ICON: Record<string, typeof CheckCircle2> = {
  completed: CheckCircle2,
  running: Loader2,
  failed: XCircle,
  pending: Clock,
  skipped: SkipForward,
  blocked: Ban,
};

const PRIVILEGE_COLORS: Record<string, string> = {
  none: "text-muted-foreground",
  user: "text-blue-400",
  admin: "text-orange-400",
  system: "text-red-400",
  cloud_admin: "text-purple-400",
  domain_admin: "text-red-500",
};

// ============================================================================
// Sub-components
// ============================================================================

function PhaseTimeline({ phaseResults, currentPhase, enabledPhases }: {
  phaseResults: BreachPhaseResult[];
  currentPhase: string | null;
  enabledPhases: BreachPhaseName[];
}) {
  const resultMap = new Map(phaseResults.map(r => [r.phaseName, r]));

  return (
    <div className="space-y-2">
      {enabledPhases.map((phaseName, idx) => {
        const result = resultMap.get(phaseName);
        const meta = PHASE_META[phaseName];
        const isCurrent = currentPhase === phaseName;
        const status = result?.status || (isCurrent ? "running" : "pending");
        const StatusIcon = PHASE_STATUS_ICON[status] || Clock;
        const PhaseIcon = meta?.icon || Shield;

        return (
          <div
            key={phaseName}
            className={`flex items-center gap-3 p-3 rounded-md border transition-all ${
              isCurrent ? "border-primary bg-primary/5" : "border-border"
            }`}
          >
            <div className={`flex items-center justify-center w-8 h-8 rounded-full ${
              status === "completed" ? "bg-emerald-500/20" :
              status === "running" ? "bg-blue-500/20" :
              status === "failed" ? "bg-destructive/20" :
              "bg-muted"
            }`}>
              <StatusIcon className={`h-4 w-4 ${
                status === "completed" ? "text-emerald-400" :
                status === "running" ? "text-blue-400 animate-spin" :
                status === "failed" ? "text-destructive" :
                "text-muted-foreground"
              }`} />
            </div>

            <PhaseIcon className={`h-4 w-4 ${meta?.color || "text-muted-foreground"}`} />

            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">{meta?.label || phaseName}</span>
                {result?.durationMs && (
                  <span className="text-xs text-muted-foreground">
                    {(result.durationMs / 1000).toFixed(1)}s
                  </span>
                )}
              </div>
              {result?.findings && result.findings.length > 0 && (
                <span className="text-xs text-muted-foreground">
                  {result.findings.length} finding{result.findings.length !== 1 ? "s" : ""}
                </span>
              )}
              {result?.error && (
                <span className="text-xs text-destructive truncate block">{result.error}</span>
              )}
            </div>

            {idx < enabledPhases.length - 1 && (
              <ArrowRight className="h-3 w-3 text-muted-foreground/50 shrink-0" />
            )}
          </div>
        );
      })}
    </div>
  );
}

function ContextSummary({ context }: { context: BreachPhaseContext | null }) {
  if (!context) return <p className="text-sm text-muted-foreground">No context data yet</p>;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-3 rounded-md border text-center">
          <div className="text-2xl font-bold text-amber-500">
            {context.credentials?.length || 0}
          </div>
          <div className="text-xs text-muted-foreground">Credentials</div>
        </div>
        <div className="p-3 rounded-md border text-center">
          <div className="text-2xl font-bold text-red-500">
            {context.compromisedAssets?.length || 0}
          </div>
          <div className="text-xs text-muted-foreground">Assets Compromised</div>
        </div>
        <div className="p-3 rounded-md border text-center">
          <div className={`text-2xl font-bold ${PRIVILEGE_COLORS[context.currentPrivilegeLevel] || "text-muted-foreground"}`}>
            {context.currentPrivilegeLevel || "none"}
          </div>
          <div className="text-xs text-muted-foreground">Privilege Level</div>
        </div>
        <div className="p-3 rounded-md border text-center">
          <div className="text-2xl font-bold text-purple-500">
            {context.domainsCompromised?.length || 0}
          </div>
          <div className="text-xs text-muted-foreground">Domains Breached</div>
        </div>
      </div>

      {context.credentials && context.credentials.length > 0 && (
        <div>
          <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
            <Key className="h-4 w-4 text-amber-500" />
            Harvested Credentials
          </h4>
          <div className="space-y-2 max-h-60 overflow-y-auto">
            {context.credentials.map((cred, idx) => (
              <div key={cred.id || idx} className="flex items-center gap-2 p-2 rounded-md border text-sm">
                <Badge variant="outline" className="text-xs shrink-0">{cred.type}</Badge>
                <span className="truncate">{cred.username || "—"}</span>
                {cred.domain && (
                  <span className="text-muted-foreground text-xs">@{cred.domain}</span>
                )}
                <Badge className={`ml-auto text-xs shrink-0 ${
                  cred.accessLevel === "admin" || cred.accessLevel === "system" || cred.accessLevel === "cloud_admin"
                    ? "bg-destructive/20 text-destructive"
                    : "bg-muted"
                }`}>
                  {cred.accessLevel}
                </Badge>
                <span className="text-xs text-muted-foreground shrink-0">{cred.source}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {context.compromisedAssets && context.compromisedAssets.length > 0 && (
        <div>
          <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
            <Server className="h-4 w-4 text-red-500" />
            Compromised Assets
          </h4>
          <div className="space-y-2 max-h-60 overflow-y-auto">
            {context.compromisedAssets.map((asset, idx) => (
              <div key={asset.id || idx} className="flex items-center gap-2 p-2 rounded-md border text-sm">
                <Badge variant="outline" className="text-xs shrink-0">{asset.assetType}</Badge>
                <span className="truncate font-medium">{asset.name}</span>
                <Badge className={`ml-auto text-xs shrink-0 ${
                  asset.accessLevel === "admin" || asset.accessLevel === "system"
                    ? "bg-destructive/20 text-destructive"
                    : "bg-muted"
                }`}>
                  {asset.accessLevel}
                </Badge>
              </div>
            ))}
          </div>
        </div>
      )}

      {context.domainsCompromised && context.domainsCompromised.length > 0 && (
        <div>
          <h4 className="text-sm font-medium mb-2">Domains Breached</h4>
          <div className="flex flex-wrap gap-2">
            {context.domainsCompromised.map((domain, idx) => (
              <Badge key={idx} variant="secondary" className="text-xs">{domain}</Badge>
            ))}
          </div>
        </div>
      )}

      {context.attackPathSteps && context.attackPathSteps.length > 0 && (
        <div>
          <h4 className="text-sm font-medium mb-2">Attack Path ({context.attackPathSteps.length} steps)</h4>
          <ScrollArea className="h-[200px]">
            <div className="space-y-2">
              {context.attackPathSteps.map((step, idx) => (
                <div key={step.stepId || idx} className="p-2 rounded-md border text-sm">
                  <div className="flex items-center gap-2 mb-1">
                    <Badge className="bg-purple-500/20 text-purple-400 text-xs">{step.phaseName}</Badge>
                    <span className="font-medium">{step.technique}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">{step.outcome}</p>
                </div>
              ))}
            </div>
          </ScrollArea>
        </div>
      )}
    </div>
  );
}

function PhaseResultsDetail({ phaseResults }: { phaseResults: BreachPhaseResult[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (!phaseResults || phaseResults.length === 0) {
    return <p className="text-sm text-muted-foreground">No phase results yet</p>;
  }

  return (
    <div className="space-y-3">
      {phaseResults.map((result) => {
        const meta = PHASE_META[result.phaseName];
        const PhaseIcon = meta?.icon || Shield;
        const isOpen = expanded === result.phaseName;
        const criticalFindings = result.findings?.filter(f => f.severity === "critical").length || 0;
        const highFindings = result.findings?.filter(f => f.severity === "high").length || 0;

        return (
          <Collapsible
            key={result.phaseName}
            open={isOpen}
            onOpenChange={(open) => setExpanded(open ? result.phaseName : null)}
          >
            <CollapsibleTrigger asChild>
              <div className="flex items-center gap-3 p-3 rounded-md border cursor-pointer hover:bg-muted/50 transition-colors">
                <PhaseIcon className={`h-4 w-4 ${meta?.color || "text-muted-foreground"}`} />
                <span className="text-sm font-medium flex-1">{meta?.label || result.phaseName}</span>
                <Badge className={STATUS_STYLES[result.status] || "bg-muted"}>
                  {result.status}
                </Badge>
                {result.findings && result.findings.length > 0 && (
                  <span className="text-xs text-muted-foreground">
                    {result.findings.length} finding{result.findings.length !== 1 ? "s" : ""}
                  </span>
                )}
                {criticalFindings > 0 && (
                  <Badge variant="destructive" className="text-xs">{criticalFindings} crit</Badge>
                )}
                {highFindings > 0 && (
                  <Badge className="bg-orange-500/20 text-orange-400 text-xs">{highFindings} high</Badge>
                )}
                {result.durationMs && (
                  <span className="text-xs text-muted-foreground">{(result.durationMs / 1000).toFixed(1)}s</span>
                )}
                {isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              </div>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <div className="ml-7 mt-2 space-y-3 pb-2">
                {result.error && (
                  <div className="p-2 bg-destructive/10 border border-destructive/20 rounded text-xs text-destructive">
                    {result.error}
                  </div>
                )}

                <div className="grid grid-cols-3 gap-3 text-xs">
                  <div className="p-2 rounded border">
                    <span className="text-muted-foreground">Input Credentials:</span>{" "}
                    <span className="font-medium">{result.inputContext?.credentialCount ?? 0}</span>
                  </div>
                  <div className="p-2 rounded border">
                    <span className="text-muted-foreground">Input Assets:</span>{" "}
                    <span className="font-medium">{result.inputContext?.compromisedAssetCount ?? 0}</span>
                  </div>
                  <div className="p-2 rounded border">
                    <span className="text-muted-foreground">Privilege:</span>{" "}
                    <span className="font-medium">{result.inputContext?.privilegeLevel || "none"}</span>
                  </div>
                </div>

                {result.findings && result.findings.length > 0 && (
                  <div>
                    <h5 className="text-xs font-medium mb-2">Findings</h5>
                    <div className="space-y-2 max-h-60 overflow-y-auto">
                      {result.findings.map((finding, idx) => (
                        <div key={finding.id || idx} className="p-2 rounded border text-xs">
                          <div className="flex items-center gap-2 mb-1">
                            <Badge variant={
                              finding.severity === "critical" ? "destructive" :
                              finding.severity === "high" ? "destructive" : "secondary"
                            } className="text-xs">
                              {finding.severity}
                            </Badge>
                            {finding.mitreId && (
                              <Badge className="bg-purple-500/20 text-purple-400 text-xs">{finding.mitreId}</Badge>
                            )}
                            <span className="font-medium">{finding.title}</span>
                          </div>
                          <p className="text-muted-foreground">{finding.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {result.safetyDecisions && result.safetyDecisions.length > 0 && (
                  <div>
                    <h5 className="text-xs font-medium mb-2">Safety Decisions</h5>
                    <div className="space-y-1">
                      {result.safetyDecisions.map((dec, idx) => (
                        <div key={idx} className="flex items-center gap-2 text-xs">
                          <Badge variant={dec.decision === "ALLOW" ? "secondary" : "destructive"} className="text-xs">
                            {dec.decision}
                          </Badge>
                          <span className="text-muted-foreground">{dec.action}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </CollapsibleContent>
          </Collapsible>
        );
      })}
    </div>
  );
}

function ChainDetail({ chain }: { chain: BreachChain }) {
  const phaseResults = (chain.phaseResults || []) as BreachPhaseResult[];
  const context = chain.currentContext as BreachPhaseContext | null;
  const config = chain.config as any;
  const enabledPhases = config?.enabledPhases || [];

  // Real-time graph updates via WebSocket
  const { latestGraph } = useBreachChainUpdates({
    enabled: chain.status === "running" || chain.status === "paused",
    chainId: chain.id,
  });

  const displayGraph = latestGraph ?? (chain.unifiedAttackGraph as AttackGraph | null);
  const hasGraph = displayGraph && displayGraph.nodes?.length > 0;

  return (
    <Tabs defaultValue={hasGraph ? "graph" : "overview"} className="w-full">
      <TabsList className="w-full flex-wrap h-auto justify-start gap-1 p-1">
        <TabsTrigger value="overview">Overview</TabsTrigger>
        <TabsTrigger value="graph">Attack Graph</TabsTrigger>
        <TabsTrigger value="phases">Phase Results</TabsTrigger>
        <TabsTrigger value="context">Breach Context</TabsTrigger>
        {chain.executiveSummary && <TabsTrigger value="summary">Executive Summary</TabsTrigger>}
      </TabsList>

      <TabsContent value="overview" className="mt-4 space-y-4">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Card>
            <CardContent className="pt-4 text-center">
              <div className={`text-3xl font-bold ${
                (chain.overallRiskScore ?? 0) >= 70 ? "text-destructive" :
                (chain.overallRiskScore ?? 0) >= 40 ? "text-orange-500" : "text-emerald-500"
              }`}>
                {chain.overallRiskScore ?? "—"}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Risk Score</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <div className="text-3xl font-bold text-amber-500">
                {chain.totalCredentialsHarvested ?? 0}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Credentials</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <div className="text-3xl font-bold text-red-500">
                {chain.totalAssetsCompromised ?? 0}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Assets Compromised</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <div className="text-3xl font-bold text-purple-500">
                {(chain.domainsBreached as string[] | null)?.length ?? 0}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Domains Breached</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <div className={`text-xl font-bold ${PRIVILEGE_COLORS[chain.maxPrivilegeAchieved || "none"] || "text-muted-foreground"}`}>
                {chain.maxPrivilegeAchieved || "none"}
              </div>
              <div className="text-xs text-muted-foreground mt-1">Max Privilege</div>
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Phase Timeline</CardTitle>
            <CardDescription>Progression through breach chain phases</CardDescription>
          </CardHeader>
          <CardContent>
            <PhaseTimeline
              phaseResults={phaseResults}
              currentPhase={chain.currentPhase}
              enabledPhases={enabledPhases}
            />
          </CardContent>
        </Card>

        {(chain.domainsBreached as string[] | null)?.length ? (
          <div className="flex flex-wrap gap-2">
            <span className="text-sm font-medium">Domains breached:</span>
            {(chain.domainsBreached as string[]).map((d, i) => (
              <Badge key={i} variant="secondary">{d}</Badge>
            ))}
          </div>
        ) : null}
      </TabsContent>

      <TabsContent value="phases" className="mt-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Phase-by-Phase Results</CardTitle>
            <CardDescription>Click a phase to expand its findings</CardDescription>
          </CardHeader>
          <CardContent>
            <PhaseResultsDetail phaseResults={phaseResults} />
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="context" className="mt-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Zap className="h-4 w-4 text-amber-500" />
              Cumulative Breach Context
            </CardTitle>
            <CardDescription>
              Credentials, compromised assets, and attack path accumulated across all phases
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ContextSummary context={context} />
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="graph" className="mt-4">
        <LiveBreachChainGraph
          graph={displayGraph}
          riskScore={chain.overallRiskScore ?? undefined}
          assetsCompromised={chain.totalAssetsCompromised ?? undefined}
          credentialsHarvested={chain.totalCredentialsHarvested ?? undefined}
          currentPhase={chain.currentPhase ?? undefined}
          isRunning={chain.status === "running"}
        />
      </TabsContent>

      {chain.executiveSummary && (
        <TabsContent value="summary" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <FileText className="h-4 w-4" />
                Executive Summary
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="prose prose-sm dark:prose-invert max-w-none whitespace-pre-wrap">
                {chain.executiveSummary}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      )}
    </Tabs>
  );
}

function ChainCard({ chain, onView, onDelete, onResume, onAbort, onGenerateReport }: {
  chain: BreachChain;
  onView: () => void;
  onDelete: () => void;
  onResume: () => void;
  onAbort: () => void;
  onGenerateReport?: () => void;
}) {
  const isRunning = chain.status === "running";
  const isPaused = chain.status === "paused";
  const isActive = isRunning || isPaused;
  const config = chain.config as any;
  const phaseResults = (chain.phaseResults || []) as BreachPhaseResult[];
  const completedPhases = phaseResults.filter(r => r.status === "completed").length;
  const totalPhases = config?.enabledPhases?.length || 6;

  return (
    <Card className="relative overflow-visible">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2 flex-wrap">
          <div className="flex-1 min-w-0">
            <CardTitle className="text-lg truncate flex items-center gap-2">
              <Link2 className="h-5 w-5 text-red-500 shrink-0" />
              {chain.name}
            </CardTitle>
            <CardDescription className="truncate mt-1">
              {chain.description || "Cross-domain breach chain"}
            </CardDescription>
          </div>
          <Badge className={STATUS_STYLES[chain.status] || "bg-muted"}>
            {isRunning && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
            {chain.status}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        {isActive && (
          <div className="mb-4">
            <div className="flex justify-between text-sm text-muted-foreground mb-1">
              <span>{chain.currentPhase ? PHASE_META[chain.currentPhase]?.label || chain.currentPhase : "Starting..."}</span>
              <span>{chain.progress}%</span>
            </div>
            <Progress value={chain.progress} className="h-2" />
          </div>
        )}

        {chain.status === "completed" && (
          <div className="grid grid-cols-4 gap-3 mb-4">
            <div className="text-center p-2 rounded-md bg-muted/50">
              <div className={`text-2xl font-bold ${
                (chain.overallRiskScore ?? 0) >= 70 ? "text-destructive" :
                (chain.overallRiskScore ?? 0) >= 40 ? "text-orange-500" : "text-emerald-500"
              }`}>
                {chain.overallRiskScore ?? "—"}
              </div>
              <div className="text-xs text-muted-foreground">Risk Score</div>
            </div>
            <div className="text-center p-2 rounded-md bg-muted/50">
              <div className="text-2xl font-bold text-amber-500">
                {chain.totalCredentialsHarvested ?? 0}
              </div>
              <div className="text-xs text-muted-foreground">Credentials</div>
            </div>
            <div className="text-center p-2 rounded-md bg-muted/50">
              <div className="text-2xl font-bold text-red-500">
                {chain.totalAssetsCompromised ?? 0}
              </div>
              <div className="text-xs text-muted-foreground">Assets</div>
            </div>
            <div className="text-center p-2 rounded-md bg-muted/50">
              <div className="text-2xl font-bold text-purple-500">
                {completedPhases}/{totalPhases}
              </div>
              <div className="text-xs text-muted-foreground">Phases</div>
            </div>
          </div>
        )}

        <div className="flex gap-2 flex-wrap">
          <Button size="sm" onClick={onView}>
            <Eye className="w-4 h-4 mr-1" />
            View Details
          </Button>
          {chain.status === "completed" && onGenerateReport && (
            <Button size="sm" variant="outline" onClick={onGenerateReport}>
              <FileBarChart className="w-4 h-4 mr-1" />
              Report
            </Button>
          )}
          {isPaused && (
            <Button size="sm" variant="outline" onClick={onResume}>
              <Play className="w-4 h-4 mr-1" />
              Resume
            </Button>
          )}
          {isRunning && (
            <Button size="sm" variant="outline" onClick={onAbort}>
              <StopCircle className="w-4 h-4 mr-1" />
              Abort
            </Button>
          )}
          {!isActive && (
            <Button size="sm" variant="outline" onClick={onDelete}>
              <Trash2 className="w-4 h-4" />
            </Button>
          )}
        </div>

        <div className="mt-3 text-xs text-muted-foreground">
          Started: {chain.startedAt ? new Date(chain.startedAt).toLocaleString() : "Not started"}
          {chain.durationMs && (
            <span className="ml-2">Duration: {(chain.durationMs / 1000).toFixed(0)}s</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// Main Page
// ============================================================================

export default function BreachChains() {
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const { hasPermission } = useAuth();
  const canCreate = hasPermission("evaluations:create");
  const canDelete = hasPermission("evaluations:delete");

  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [selectedChain, setSelectedChain] = useState<BreachChain | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    name: "",
    description: "",
    assetIds: "",
    targetUrl: "",
    executionMode: "safe" as "safe" | "simulation" | "live",
    pauseOnCritical: false,
    enabledPhases: [
      "application_compromise",
      "credential_extraction",
      "cloud_iam_escalation",
      "container_k8s_breakout",
      "lateral_movement",
      "impact_assessment",
    ] as string[],
  });

  const { data: chains = [], isLoading, refetch } = useQuery<BreachChain[]>({
    queryKey: ["/api/breach-chains"],
    refetchInterval: 5000,
  });

  // WebSocket live updates — auto-invalidates queries on breach chain progress
  const hasRunningChains = chains.some(c => c.status === "running");
  useBreachChainUpdates({
    enabled: hasRunningChains,
    onComplete: () => {
      toast({ title: "Breach Chain Complete", description: "A breach chain has finished execution." });
    },
  });

  const createMutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      const assetIds = data.assetIds
        .split(",")
        .map(s => s.trim())
        .filter(Boolean);

      // If targetUrl is provided and no explicit assetIds, use the URL as the asset
      const finalAssetIds = assetIds.length > 0 ? assetIds : data.targetUrl.trim() ? [data.targetUrl.trim()] : [];

      if (finalAssetIds.length === 0) {
        throw new Error("At least one asset ID or target URL is required");
      }

      const payload = {
        name: data.name,
        description: data.description || undefined,
        assetIds: finalAssetIds,
        targetDomains: ["application", "cloud", "k8s", "network"],
        config: {
          enabledPhases: data.enabledPhases,
          executionMode: data.executionMode,
          pauseOnCritical: data.pauseOnCritical,
        },
      };

      const res = await apiRequest("POST", "/api/breach-chains", payload);
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
      setIsCreateOpen(false);
      resetForm();
      toast({
        title: "Breach Chain Started",
        description: `Chain ${data.chainId} is now running through ${data.phases?.length || 6} phases.`,
      });
    },
    onError: (error: Error) => {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    },
  });

  const resumeMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/breach-chains/${id}/resume`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
      toast({ title: "Chain Resumed" });
    },
    onError: (error: Error) => {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    },
  });

  const abortMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/breach-chains/${id}/abort`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
      toast({ title: "Chain Aborted" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/breach-chains/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
      setSelectedChain(null);
      toast({ title: "Chain Deleted" });
    },
  });

  const generateReportMutation = useMutation({
    mutationFn: async (chainId: string) => {
      const res = await apiRequest("POST", "/api/reports/generate", {
        breachChainId: chainId,
      });
      return res.json();
    },
    onSuccess: () => {
      toast({
        title: "Report Generated",
        description: "Breach chain report is ready. Redirecting to Reports...",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/reports"] });
      setTimeout(() => navigate("/reports"), 1000);
    },
    onError: (error: Error) => {
      toast({ title: "Report Failed", description: error.message, variant: "destructive" });
    },
  });

  const resetForm = () => {
    setFormData({
      name: "",
      description: "",
      assetIds: "",
      targetUrl: "",
      executionMode: "safe",
      pauseOnCritical: false,
      enabledPhases: [
        "application_compromise",
        "credential_extraction",
        "cloud_iam_escalation",
        "container_k8s_breakout",
        "lateral_movement",
        "impact_assessment",
      ],
    });
    setShowAdvanced(false);
  };

  const togglePhase = (phase: string) => {
    setFormData(prev => ({
      ...prev,
      enabledPhases: prev.enabledPhases.includes(phase)
        ? prev.enabledPhases.filter(p => p !== phase)
        : [...prev.enabledPhases, phase],
    }));
  };

  // If viewing a single chain, auto-refresh its data
  const { data: detailChain } = useQuery<BreachChain>({
    queryKey: [`/api/breach-chains/${selectedChain?.id}`],
    enabled: !!selectedChain,
    refetchInterval: selectedChain?.status === "running" ? 3000 : 15000,
  });

  const displayChain = detailChain || selectedChain;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Link2 className="h-6 w-6 text-red-500" />
            Cross-Domain Breach Chains
          </h1>
          <p className="text-muted-foreground">
            Chain exploits across application, cloud, container, and network domains
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Dialog open={isCreateOpen} onOpenChange={(open) => {
            setIsCreateOpen(open);
            if (!open) resetForm();
          }}>
            <DialogTrigger asChild>
              <Button disabled={!canCreate}>
                {canCreate ? <Play className="h-4 w-4 mr-2" /> : <Lock className="h-4 w-4 mr-2" />}
                Start Breach Chain
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[600px] max-h-[85vh] overflow-y-auto">
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Link2 className="h-5 w-5 text-red-500" />
                  Start Cross-Domain Breach Chain
                </DialogTitle>
                <DialogDescription>
                  Launch a multi-phase breach simulation that chains exploits across security domains
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Chain Name</label>
                  <Input
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="Q1 2026 Full Breach Simulation"
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">Target URL</label>
                  <Input
                    value={formData.targetUrl}
                    onChange={(e) => setFormData({ ...formData, targetUrl: e.target.value })}
                    placeholder="https://target-app.example.com"
                  />
                  <p className="text-xs text-muted-foreground">
                    The Active Exploit Engine will fire real payloads against this target in Phase 1
                  </p>
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">Asset IDs (optional, comma-separated)</label>
                  <Input
                    value={formData.assetIds}
                    onChange={(e) => setFormData({ ...formData, assetIds: e.target.value })}
                    placeholder="web-server-001, api-gateway-002"
                  />
                  <p className="text-xs text-muted-foreground">
                    If left empty, the target URL will be used as the primary asset
                  </p>
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium">Description (optional)</label>
                  <Textarea
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    placeholder="Validate full attack chain from app compromise to domain admin..."
                    rows={2}
                  />
                </div>

                <Collapsible open={showAdvanced} onOpenChange={setShowAdvanced}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" size="sm" className="w-full justify-between">
                      <span className="flex items-center gap-2">
                        <Settings2 className="h-4 w-4" />
                        Advanced Configuration
                      </span>
                      <ChevronDown className={`h-4 w-4 transition-transform ${showAdvanced ? "rotate-180" : ""}`} />
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="space-y-4 pt-4">
                    <div className="space-y-2">
                      <label className="text-sm font-medium">Execution Mode</label>
                      <Select
                        value={formData.executionMode}
                        onValueChange={(v) => setFormData({ ...formData, executionMode: v as any })}
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="safe">Safe (default)</SelectItem>
                          <SelectItem value="simulation">Simulation</SelectItem>
                          <SelectItem value="live">Live</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="flex items-center justify-between">
                      <label className="text-sm font-medium">Pause on Critical Findings</label>
                      <Switch
                        checked={formData.pauseOnCritical}
                        onCheckedChange={(checked) => setFormData({ ...formData, pauseOnCritical: checked })}
                      />
                    </div>

                    <div className="space-y-2">
                      <label className="text-sm font-medium">Enabled Phases</label>
                      <div className="grid grid-cols-1 gap-2">
                        {Object.entries(PHASE_META).map(([key, meta]) => {
                          const PhaseIcon = meta.icon;
                          const enabled = formData.enabledPhases.includes(key);
                          return (
                            <div
                              key={key}
                              className={`flex items-center gap-3 p-2 rounded-md border cursor-pointer transition-colors ${
                                enabled ? "border-primary bg-primary/5" : "border-border opacity-50"
                              }`}
                              onClick={() => togglePhase(key)}
                            >
                              <Switch checked={enabled} onCheckedChange={() => togglePhase(key)} />
                              <PhaseIcon className={`h-4 w-4 ${meta.color}`} />
                              <div>
                                <span className="text-sm font-medium">{meta.label}</span>
                                <p className="text-xs text-muted-foreground">{meta.description}</p>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </CollapsibleContent>
                </Collapsible>

                <div className="bg-muted/50 p-3 rounded-md">
                  <h4 className="text-sm font-medium flex items-center gap-2">
                    <Target className="w-4 h-4" />
                    What this breach chain does:
                  </h4>
                  <ul className="text-xs text-muted-foreground mt-2 space-y-1">
                    <li className="text-red-400">Phase 1: Fires active exploit payloads (SQLi, XSS, SSRF, auth bypass...)</li>
                    <li className="text-amber-400">Phase 2: Extracts credentials from compromised responses</li>
                    <li className="text-cyan-400">Phase 3: Escalates IAM privileges in cloud environments</li>
                    <li className="text-purple-400">Phase 4: Attempts K8s RBAC abuse and container breakout</li>
                    <li className="text-blue-400">Phase 5: Pivots laterally using harvested credentials</li>
                    <li className="text-orange-400">Phase 6: Aggregates full business impact analysis</li>
                  </ul>
                </div>
              </div>

              <DialogFooter>
                <Button
                  onClick={() => createMutation.mutate(formData)}
                  disabled={!formData.name.trim() || (!formData.assetIds.trim() && !formData.targetUrl.trim()) || createMutation.isPending}
                  className="w-full"
                >
                  {createMutation.isPending ? (
                    <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Starting...</>
                  ) : (
                    <><Play className="h-4 w-4 mr-2" />Launch Breach Chain</>
                  )}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {selectedChain && displayChain ? (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => setSelectedChain(null)}>
              Back to List
            </Button>
            {displayChain.status === "completed" && (
              <Button
                variant="outline"
                onClick={() => generateReportMutation.mutate(displayChain.id)}
                disabled={generateReportMutation.isPending}
              >
                {generateReportMutation.isPending ? (
                  <Loader2 className="w-4 h-4 mr-1 animate-spin" />
                ) : (
                  <FileBarChart className="w-4 h-4 mr-1" />
                )}
                Generate Report
              </Button>
            )}
            {displayChain.status === "paused" && (
              <Button variant="outline" onClick={() => resumeMutation.mutate(displayChain.id)}>
                <Play className="w-4 h-4 mr-1" /> Resume
              </Button>
            )}
            {displayChain.status === "running" && (
              <Button variant="outline" onClick={() => abortMutation.mutate(displayChain.id)}>
                <StopCircle className="w-4 h-4 mr-1" /> Abort
              </Button>
            )}
          </div>
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between gap-4 flex-wrap">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Link2 className="h-5 w-5 text-red-500" />
                    {displayChain.name}
                  </CardTitle>
                  <CardDescription>{displayChain.description || "Cross-domain breach chain"}</CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Badge className={STATUS_STYLES[displayChain.status] || "bg-muted"}>
                    {displayChain.status === "running" && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
                    {displayChain.status}
                  </Badge>
                  {displayChain.status === "running" && (
                    <span className="text-sm text-muted-foreground">{displayChain.progress}%</span>
                  )}
                </div>
              </div>
              {displayChain.status === "running" && (
                <Progress value={displayChain.progress} className="h-2 mt-2" />
              )}
            </CardHeader>
            <CardContent>
              <ChainDetail chain={displayChain} />
            </CardContent>
          </Card>
        </div>
      ) : (
        <>
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
            </div>
          ) : chains.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Link2 className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium">No Breach Chains Yet</h3>
                <p className="text-muted-foreground mt-1">
                  Start a cross-domain breach chain to validate your full attack surface
                </p>
                <Button className="mt-4" onClick={() => setIsCreateOpen(true)} disabled={!canCreate}>
                  <Play className="w-4 h-4 mr-2" />
                  Start Your First Breach Chain
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {chains.map((chain) => (
                <ChainCard
                  key={chain.id}
                  chain={chain}
                  onView={() => setSelectedChain(chain)}
                  onDelete={() => canDelete && deleteMutation.mutate(chain.id)}
                  onResume={() => resumeMutation.mutate(chain.id)}
                  onAbort={() => abortMutation.mutate(chain.id)}
                  onGenerateReport={() => generateReportMutation.mutate(chain.id)}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
