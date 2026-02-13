import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Target,
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  AlertTriangle,
  Network,
  Shield,
  FileText,
  Trash2,
  Eye,
  RefreshCw,
  TrendingUp,
  AlertCircle,
  Globe,
} from "lucide-react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { FullAssessment } from "@shared/schema";

const statusColors: Record<string, string> = {
  pending: "bg-muted text-muted-foreground",
  reconnaissance: "bg-blue-500/20 text-blue-400",
  vulnerability_analysis: "bg-amber-500/20 text-amber-400",
  attack_synthesis: "bg-purple-500/20 text-purple-400",
  lateral_analysis: "bg-cyan-500/20 text-cyan-400",
  impact_assessment: "bg-orange-500/20 text-orange-400",
  completed: "bg-emerald-500/20 text-emerald-400",
  failed: "bg-destructive/20 text-destructive",
};

const statusLabels: Record<string, string> = {
  pending: "Pending",
  reconnaissance: "Reconnaissance",
  vulnerability_analysis: "Vulnerability Analysis",
  attack_synthesis: "Attack Synthesis",
  lateral_analysis: "Lateral Movement Analysis",
  impact_assessment: "Impact Assessment",
  completed: "Completed",
  failed: "Failed",
};

function RiskGauge({ score }: { score: number }) {
  const getColor = (s: number) => {
    if (s >= 80) return "text-destructive";
    if (s >= 60) return "text-orange-500";
    if (s >= 40) return "text-amber-500";
    if (s >= 20) return "text-emerald-500";
    return "text-muted-foreground";
  };

  return (
    <div className="flex flex-col items-center gap-2">
      <div className={`text-4xl font-bold ${getColor(score)}`}>
        {score}
      </div>
      <span className="text-sm text-muted-foreground">Risk Score</span>
    </div>
  );
}

interface LateralPath {
  id: string;
  source: string;
  target: string;
  technique: string;
  method: string;
  likelihood: string;
  prerequisites?: string[];
}

function LateralMovementDisplay({ data }: { data: { paths?: LateralPath[]; highRiskPivots?: string[] } }) {
  const paths = data.paths || [];
  const highRiskPivots = data.highRiskPivots || [];
  
  const getLikelihoodColor = (likelihood: string) => {
    switch (likelihood?.toLowerCase()) {
      case "high": return "bg-destructive/20 text-destructive";
      case "medium": return "bg-amber-500/20 text-amber-400";
      case "low": return "bg-emerald-500/20 text-emerald-400";
      default: return "bg-muted";
    }
  };

  return (
    <div className="space-y-4">
      {highRiskPivots.length > 0 && (
        <div className="p-3 rounded-md bg-destructive/10 border border-destructive/20">
          <h4 className="text-sm font-medium text-destructive mb-2">High-Risk Pivot Points</h4>
          <div className="flex gap-2 flex-wrap">
            {highRiskPivots.map((pivot, idx) => (
              <Badge key={idx} variant="outline" className="border-destructive/50 text-destructive">
                {pivot}
              </Badge>
            ))}
          </div>
        </div>
      )}
      
      {paths.length > 0 ? (
        <div className="space-y-3">
          {paths.map((path, idx) => (
            <div key={path.id || idx} className="p-3 rounded-md border">
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <Badge variant="outline">{path.source}</Badge>
                <span className="text-muted-foreground">to</span>
                <Badge variant="outline">{path.target}</Badge>
                <Badge className={getLikelihoodColor(path.likelihood)}>
                  {path.likelihood} likelihood
                </Badge>
              </div>
              <p className="text-sm mb-1">{path.method}</p>
              <div className="text-xs text-muted-foreground">
                <span className="font-medium">Technique:</span> {path.technique}
              </div>
              {path.prerequisites && path.prerequisites.length > 0 && (
                <div className="mt-2 text-xs">
                  <span className="text-muted-foreground">Prerequisites:</span>
                  <ul className="list-disc list-inside text-muted-foreground">
                    {path.prerequisites.map((prereq, pIdx) => (
                      <li key={pIdx}>{prereq}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">No lateral movement paths identified</p>
      )}
    </div>
  );
}

interface BusinessImpact {
  overallRisk?: string;
  dataAtRisk?: {
    types?: string[];
    estimatedRecords?: string;
    regulatoryImplications?: string[];
  };
  operationalImpact?: {
    systemsAffected?: number;
    potentialDowntime?: string;
    businessProcesses?: string[];
  };
  financialImpact?: {
    estimatedRange?: string;
    factors?: string[];
  };
  reputationalImpact?: string;
}

function BusinessImpactDisplay({ data }: { data: BusinessImpact }) {
  const getRiskColor = (risk: string) => {
    switch (risk?.toLowerCase()) {
      case "critical": return "bg-destructive/20 text-destructive border-destructive/30";
      case "high": return "bg-orange-500/20 text-orange-400 border-orange-500/30";
      case "medium": return "bg-amber-500/20 text-amber-400 border-amber-500/30";
      case "low": return "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
      default: return "bg-muted border-muted";
    }
  };

  return (
    <div className="space-y-4">
      {data.overallRisk && (
        <div className={`p-4 rounded-md border ${getRiskColor(data.overallRisk)}`}>
          <div className="text-center">
            <span className="text-sm text-muted-foreground">Overall Risk Level</span>
            <div className="text-2xl font-bold uppercase">{data.overallRisk}</div>
          </div>
        </div>
      )}
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {data.dataAtRisk && (
          <div className="p-3 rounded-md border">
            <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-destructive" />
              Data at Risk
            </h4>
            {data.dataAtRisk.types && data.dataAtRisk.types.length > 0 && (
              <div className="mb-2">
                <span className="text-xs text-muted-foreground">Types:</span>
                <div className="flex gap-1 flex-wrap mt-1">
                  {data.dataAtRisk.types.map((type, idx) => (
                    <Badge key={idx} variant="outline" className="text-xs">{type}</Badge>
                  ))}
                </div>
              </div>
            )}
            {data.dataAtRisk.estimatedRecords && (
              <p className="text-sm">
                <span className="text-muted-foreground">Est. Records:</span> {data.dataAtRisk.estimatedRecords}
              </p>
            )}
            {data.dataAtRisk.regulatoryImplications && data.dataAtRisk.regulatoryImplications.length > 0 && (
              <div className="mt-2">
                <span className="text-xs text-muted-foreground">Regulatory:</span>
                <div className="flex gap-1 flex-wrap mt-1">
                  {data.dataAtRisk.regulatoryImplications.map((reg, idx) => (
                    <Badge key={idx} variant="secondary" className="text-xs">{reg}</Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {data.operationalImpact && (
          <div className="p-3 rounded-md border">
            <h4 className="text-sm font-medium mb-2">Operational Impact</h4>
            {data.operationalImpact.systemsAffected !== undefined && (
              <p className="text-sm">
                <span className="text-muted-foreground">Systems Affected:</span> {data.operationalImpact.systemsAffected}
              </p>
            )}
            {data.operationalImpact.potentialDowntime && (
              <p className="text-sm">
                <span className="text-muted-foreground">Potential Downtime:</span> {data.operationalImpact.potentialDowntime}
              </p>
            )}
            {data.operationalImpact.businessProcesses && data.operationalImpact.businessProcesses.length > 0 && (
              <div className="mt-2">
                <span className="text-xs text-muted-foreground">Affected Processes:</span>
                <ul className="list-disc list-inside text-sm text-muted-foreground">
                  {data.operationalImpact.businessProcesses.map((proc, idx) => (
                    <li key={idx}>{proc}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {data.financialImpact && (
          <div className="p-3 rounded-md border">
            <h4 className="text-sm font-medium mb-2">Financial Impact</h4>
            {data.financialImpact.estimatedRange && (
              <p className="text-lg font-bold text-destructive">{data.financialImpact.estimatedRange}</p>
            )}
            {data.financialImpact.factors && data.financialImpact.factors.length > 0 && (
              <div className="mt-2">
                <span className="text-xs text-muted-foreground">Contributing Factors:</span>
                <ul className="list-disc list-inside text-sm text-muted-foreground">
                  {data.financialImpact.factors.map((factor, idx) => (
                    <li key={idx}>{factor}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>

      {data.reputationalImpact && (
        <div className="p-3 rounded-md border">
          <h4 className="text-sm font-medium mb-2">Reputational Impact</h4>
          <p className="text-sm text-muted-foreground">{data.reputationalImpact}</p>
        </div>
      )}
    </div>
  );
}

function AssessmentCard({ assessment, onView, onDelete }: { 
  assessment: FullAssessment; 
  onView: () => void;
  onDelete: () => void;
}) {
  const isRunning = !["completed", "failed", "pending"].includes(assessment.status);
  
  return (
    <Card className="relative overflow-visible">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2 flex-wrap">
          <div className="flex-1 min-w-0">
            <CardTitle className="text-lg truncate">{assessment.name}</CardTitle>
            <CardDescription className="truncate mt-1">
              {assessment.description || "Full system security assessment"}
            </CardDescription>
          </div>
          <Badge className={statusColors[assessment.status]}>
            {isRunning && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
            {statusLabels[assessment.status]}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        {isRunning && (
          <div className="mb-4">
            <div className="flex justify-between text-sm text-muted-foreground mb-1">
              <span>{assessment.currentPhase}</span>
              <span>{assessment.progress}%</span>
            </div>
            <Progress value={assessment.progress} className="h-2" />
          </div>
        )}
        
        {assessment.status === "completed" && (
          <div className="grid grid-cols-4 gap-3 mb-4">
            <div className="text-center p-2 rounded-md bg-muted/50">
              <div className="text-2xl font-bold text-foreground">
                {assessment.overallRiskScore ?? "-"}
              </div>
              <div className="text-xs text-muted-foreground">Risk Score</div>
            </div>
            <div className="text-center p-2 rounded-md bg-muted/50">
              <div className="text-2xl font-bold text-foreground">
                {assessment.criticalPathCount ?? 0}
              </div>
              <div className="text-xs text-muted-foreground">Attack Paths</div>
            </div>
            <div className="text-center p-2 rounded-md bg-muted/50">
              <div className="text-2xl font-bold text-foreground">
                {assessment.systemsAnalyzed ?? 0}
              </div>
              <div className="text-xs text-muted-foreground">Systems</div>
            </div>
            <div className="text-center p-2 rounded-md bg-muted/50">
              <div className="text-2xl font-bold text-foreground">
                {assessment.findingsAnalyzed ?? 0}
              </div>
              <div className="text-xs text-muted-foreground">Findings</div>
            </div>
          </div>
        )}
        
        <div className="flex gap-2 flex-wrap">
          <Button size="sm" onClick={onView} data-testid={`button-view-assessment-${assessment.id}`}>
            <Eye className="w-4 h-4 mr-1" />
            View Details
          </Button>
          <Button 
            size="sm" 
            variant="outline" 
            onClick={onDelete}
            data-testid={`button-delete-assessment-${assessment.id}`}
          >
            <Trash2 className="w-4 h-4" />
          </Button>
        </div>
        
        <div className="mt-3 text-xs text-muted-foreground">
          Started: {assessment.startedAt ? new Date(assessment.startedAt).toLocaleString() : "Not started"}
          {assessment.durationMs && (
            <span className="ml-2">Duration: {Math.round(assessment.durationMs / 1000)}s</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function AssessmentDetail({ assessment }: { assessment: FullAssessment }) {
  const attackGraph = assessment.unifiedAttackGraph;
  const recommendations = assessment.recommendations || [];
  
  return (
    <Tabs defaultValue="summary" className="w-full">
      <TabsList className="w-full flex-wrap h-auto justify-start gap-1 p-1">
        <TabsTrigger value="summary">Summary</TabsTrigger>
        {(assessment as any).webAppRecon && (
          <TabsTrigger value="web-recon">Web Recon</TabsTrigger>
        )}
        {(assessment as any).validatedFindings?.length > 0 && (
          <TabsTrigger value="validated-findings">Validated Findings</TabsTrigger>
        )}
        <TabsTrigger value="attack-graph">Attack Graph</TabsTrigger>
        <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
        <TabsTrigger value="lateral">Lateral Movement</TabsTrigger>
        <TabsTrigger value="impact">Business Impact</TabsTrigger>
      </TabsList>
      
      <TabsContent value="summary" className="mt-4 space-y-4">
        <div className="grid grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-4 text-center">
              <RiskGauge score={assessment.overallRiskScore ?? 0} />
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <div className="text-3xl font-bold text-purple-500">
                {assessment.criticalPathCount ?? 0}
              </div>
              <div className="text-sm text-muted-foreground mt-1">Critical Attack Paths</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <div className="text-3xl font-bold text-cyan-500">
                {assessment.systemsAnalyzed ?? 0}
              </div>
              <div className="text-sm text-muted-foreground mt-1">Systems Analyzed</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4 text-center">
              <div className="text-3xl font-bold text-amber-500">
                {assessment.findingsAnalyzed ?? 0}
              </div>
              <div className="text-sm text-muted-foreground mt-1">Findings Analyzed</div>
            </CardContent>
          </Card>
        </div>
        
        {assessment.executiveSummary && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <FileText className="w-4 h-4" />
                Executive Summary
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="prose prose-sm dark:prose-invert max-w-none whitespace-pre-wrap">
                {assessment.executiveSummary}
              </div>
            </CardContent>
          </Card>
        )}
      </TabsContent>

      {/* Web App Reconnaissance Results */}
      {(assessment as any).webAppRecon && (
        <TabsContent value="web-recon" className="mt-4 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Globe className="w-4 h-4" />
                Web Application Reconnaissance
              </CardTitle>
              <CardDescription>
                Target: {(assessment as any).webAppRecon.targetUrl}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-4 gap-4">
                <div className="p-3 rounded-md border text-center">
                  <div className="text-2xl font-bold text-blue-500">
                    {(assessment as any).webAppRecon.attackSurface?.totalEndpoints || 0}
                  </div>
                  <div className="text-xs text-muted-foreground">Endpoints</div>
                </div>
                <div className="p-3 rounded-md border text-center">
                  <div className="text-2xl font-bold text-purple-500">
                    {(assessment as any).webAppRecon.attackSurface?.inputParameters || 0}
                  </div>
                  <div className="text-xs text-muted-foreground">Parameters</div>
                </div>
                <div className="p-3 rounded-md border text-center">
                  <div className="text-2xl font-bold text-cyan-500">
                    {(assessment as any).webAppRecon.attackSurface?.formCount || 0}
                  </div>
                  <div className="text-xs text-muted-foreground">Forms</div>
                </div>
                <div className="p-3 rounded-md border text-center">
                  <div className="text-2xl font-bold text-amber-500">
                    {(((assessment as any).webAppRecon.scanDurationMs || 0) / 1000).toFixed(1)}s
                  </div>
                  <div className="text-xs text-muted-foreground">Scan Time</div>
                </div>
              </div>

              {(assessment as any).webAppRecon.applicationInfo && (
                <div className="space-y-2">
                  <h4 className="font-medium text-sm">Application Info</h4>
                  <div className="flex gap-2 flex-wrap">
                    {(assessment as any).webAppRecon.applicationInfo.technologies?.map((tech: string, idx: number) => (
                      <Badge key={idx} variant="secondary">{tech}</Badge>
                    ))}
                    {(assessment as any).webAppRecon.applicationInfo.frameworks?.map((fw: string, idx: number) => (
                      <Badge key={idx} variant="outline">{fw}</Badge>
                    ))}
                  </div>
                  {(assessment as any).webAppRecon.applicationInfo.missingSecurityHeaders?.length > 0 && (
                    <div className="mt-2">
                      <span className="text-xs text-muted-foreground">Missing Security Headers:</span>
                      <div className="flex gap-1 flex-wrap mt-1">
                        {(assessment as any).webAppRecon.applicationInfo.missingSecurityHeaders.map((h: string, idx: number) => (
                          <Badge key={idx} variant="destructive" className="text-xs">{h}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {(assessment as any).webAppRecon.endpoints?.length > 0 && (
                <div className="space-y-2">
                  <h4 className="font-medium text-sm">Discovered Endpoints ({(assessment as any).webAppRecon.endpoints.length})</h4>
                  <ScrollArea className="h-[300px]">
                    <div className="space-y-2">
                      {(assessment as any).webAppRecon.endpoints.slice(0, 50).map((ep: any, idx: number) => (
                        <div key={idx} className="p-2 rounded-md border text-sm flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2 min-w-0">
                            <Badge variant="outline" className="text-xs shrink-0">{ep.method}</Badge>
                            <span className="truncate text-muted-foreground">{ep.path}</span>
                          </div>
                          <Badge variant={ep.priority === 'high' ? 'destructive' : ep.priority === 'medium' ? 'secondary' : 'outline'} className="text-xs shrink-0">
                            {ep.priority}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      )}

      {/* Validated Findings from Parallel Agents */}
      {(assessment as any).validatedFindings?.length > 0 && (
        <TabsContent value="validated-findings" className="mt-4 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Shield className="w-4 h-4" />
                Validated Security Findings
              </CardTitle>
              <CardDescription>
                {(assessment as any).validatedFindings.length} vulnerabilities confirmed by parallel security agents
              </CardDescription>
            </CardHeader>
            <CardContent>
              {(assessment as any).agentDispatchStats && (
                <div className="grid grid-cols-4 gap-4 mb-4">
                  <div className="p-3 rounded-md border text-center">
                    <div className="text-2xl font-bold text-blue-500">
                      {(assessment as any).agentDispatchStats.completedTasks}
                    </div>
                    <div className="text-xs text-muted-foreground">Tasks Completed</div>
                  </div>
                  <div className="p-3 rounded-md border text-center">
                    <div className="text-2xl font-bold text-green-500">
                      {(assessment as any).validatedFindings.length}
                    </div>
                    <div className="text-xs text-muted-foreground">Confirmed</div>
                  </div>
                  <div className="p-3 rounded-md border text-center">
                    <div className="text-2xl font-bold text-amber-500">
                      {(assessment as any).agentDispatchStats.falsePositivesFiltered}
                    </div>
                    <div className="text-xs text-muted-foreground">False Positives Filtered</div>
                  </div>
                  <div className="p-3 rounded-md border text-center">
                    <div className="text-2xl font-bold text-muted-foreground">
                      {(((assessment as any).agentDispatchStats.executionTimeMs || 0) / 1000).toFixed(1)}s
                    </div>
                    <div className="text-xs text-muted-foreground">Execution Time</div>
                  </div>
                </div>
              )}

              <ScrollArea className="h-[400px]">
                <div className="space-y-3">
                  {(assessment as any).validatedFindings.map((finding: any, idx: number) => (
                    <div key={finding.id || idx} className="p-3 rounded-md border">
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant={
                            finding.severity === 'critical' ? 'destructive' :
                            finding.severity === 'high' ? 'destructive' :
                            finding.severity === 'medium' ? 'secondary' : 'outline'
                          }>
                            {finding.severity?.toUpperCase()}
                          </Badge>
                          <Badge variant="outline">{finding.vulnerabilityType}</Badge>
                          {finding.mitreAttackId && (
                            <Badge className="bg-purple-500/20 text-purple-400 text-xs">{finding.mitreAttackId}</Badge>
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          {finding.cvssEstimate && (
                            <Badge variant="secondary">CVSS: {finding.cvssEstimate}</Badge>
                          )}
                          <Badge variant={finding.verdict === 'confirmed' ? 'destructive' : 'secondary'}>
                            {finding.verdict}
                          </Badge>
                        </div>
                      </div>
                      <div className="text-sm text-muted-foreground mb-2">
                        <span className="font-medium text-foreground">{finding.endpointPath}</span>
                        {finding.parameter && <span> ({finding.parameter})</span>}
                      </div>
                      {finding.evidence && finding.evidence.length > 0 && (
                        <div className="text-xs text-muted-foreground bg-muted/30 p-2 rounded-md mb-2 overflow-x-auto">
                          <code>{Array.isArray(finding.evidence) 
                            ? finding.evidence[0]?.slice(0, 200) + (finding.evidence[0]?.length > 200 ? '...' : '')
                            : String(finding.evidence).slice(0, 200)
                          }</code>
                        </div>
                      )}
                      {finding.recommendations?.length > 0 && (
                        <div className="text-xs">
                          <span className="text-muted-foreground">Recommendations: </span>
                          {finding.recommendations.slice(0, 2).join('; ')}
                        </div>
                      )}
                      {finding.llmValidation && (
                        <div className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3 text-green-500" />
                          LLM Validated: {finding.llmValidation.confidence}% confidence
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      )}
      
      <TabsContent value="attack-graph" className="mt-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Network className="w-4 h-4" />
              Unified Attack Graph
            </CardTitle>
            <CardDescription>
              Cross-system attack paths showing how vulnerabilities chain together
            </CardDescription>
          </CardHeader>
          <CardContent>
            {attackGraph?.criticalPaths && attackGraph.criticalPaths.length > 0 ? (
              <div className="space-y-4">
                <h4 className="font-medium">Critical Attack Paths</h4>
                {attackGraph.criticalPaths.map((path, idx) => (
                  <div key={path.pathId || idx} className="p-3 rounded-md border bg-muted/30">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-sm">Path {idx + 1}</span>
                      <Badge variant={path.riskScore >= 70 ? "destructive" : "secondary"}>
                        Risk: {path.riskScore}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">{path.description}</p>
                    <div className="flex gap-1 mt-2 flex-wrap">
                      {path.nodes.map((node, nodeIdx) => (
                        <Badge key={nodeIdx} variant="outline" className="text-xs">
                          {node}
                        </Badge>
                      ))}
                    </div>
                  </div>
                ))}
                
                {attackGraph.nodes && attackGraph.nodes.length > 0 && (
                  <div className="mt-6">
                    <h4 className="font-medium mb-3">Attack Graph Nodes</h4>
                    <div className="flex gap-2 flex-wrap">
                      {attackGraph.nodes.slice(0, 20).map((node, idx) => (
                        <Badge 
                          key={node.id || idx} 
                          className={`text-xs ${
                            node.type === "vulnerability" ? "bg-destructive/20 text-destructive" :
                            node.type === "technique" ? "bg-purple-500/20 text-purple-400" :
                            node.type === "impact" ? "bg-orange-500/20 text-orange-400" :
                            "bg-muted"
                          }`}
                        >
                          {node.label}
                        </Badge>
                      ))}
                      {attackGraph.nodes.length > 20 && (
                        <span className="text-xs text-muted-foreground">
                          +{attackGraph.nodes.length - 20} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No attack graph data available</p>
            )}
          </CardContent>
        </Card>
      </TabsContent>
      
      <TabsContent value="recommendations" className="mt-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Prioritized Recommendations
            </CardTitle>
          </CardHeader>
          <CardContent>
            {recommendations.length > 0 ? (
              <div className="space-y-3">
                {recommendations.map((rec, idx) => (
                  <div key={rec.id || idx} className="p-3 rounded-md border">
                    <div className="flex items-start justify-between gap-2 flex-wrap">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge className={
                            rec.priority === "critical" ? "bg-destructive/20 text-destructive" :
                            rec.priority === "high" ? "bg-orange-500/20 text-orange-400" :
                            rec.priority === "medium" ? "bg-amber-500/20 text-amber-400" :
                            "bg-muted"
                          }>
                            {rec.priority}
                          </Badge>
                          <span className="font-medium text-sm">{rec.title}</span>
                        </div>
                        <p className="text-sm text-muted-foreground">{rec.description}</p>
                        {rec.affectedSystems && rec.affectedSystems.length > 0 && (
                          <div className="flex gap-1 mt-2 flex-wrap">
                            <span className="text-xs text-muted-foreground">Affected:</span>
                            {rec.affectedSystems.map((sys, sIdx) => (
                              <Badge key={sIdx} variant="outline" className="text-xs">
                                {sys}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                      <div className="text-right text-xs text-muted-foreground">
                        <div>Effort: {rec.effort}</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No recommendations available</p>
            )}
          </CardContent>
        </Card>
      </TabsContent>
      
      <TabsContent value="lateral" className="mt-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="w-4 h-4" />
              Lateral Movement Analysis
            </CardTitle>
          </CardHeader>
          <CardContent>
            {assessment.lateralMovementPaths ? (
              <LateralMovementDisplay data={assessment.lateralMovementPaths as any} />
            ) : (
              <p className="text-sm text-muted-foreground">No lateral movement data available</p>
            )}
          </CardContent>
        </Card>
      </TabsContent>
      
      <TabsContent value="impact" className="mt-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <AlertCircle className="w-4 h-4" />
              Business Impact Analysis
            </CardTitle>
          </CardHeader>
          <CardContent>
            {assessment.businessImpactAnalysis ? (
              <BusinessImpactDisplay data={assessment.businessImpactAnalysis as any} />
            ) : (
              <p className="text-sm text-muted-foreground">No business impact data available</p>
            )}
          </CardContent>
        </Card>
      </TabsContent>
    </Tabs>
  );
}

export default function FullAssessmentPage() {
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const [selectedAssessment, setSelectedAssessment] = useState<FullAssessment | null>(null);

  const { data: assessments = [], isLoading, refetch } = useQuery<FullAssessment[]>({
    queryKey: ["/api/full-assessments"],
    refetchInterval: 5000,
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      return apiRequest("DELETE", `/api/full-assessments/${id}`);
    },
    onSuccess: () => {
      toast({ title: "Deleted", description: "Assessment removed" });
      setSelectedAssessment(null);
      queryClient.invalidateQueries({ queryKey: ["/api/full-assessments"] });
    },
  });

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold">Full Security Assessment</h1>
          <p className="text-muted-foreground">
            Comprehensive multi-system penetration testing and attack path analysis
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => refetch()} data-testid="button-refresh-assessments">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button onClick={() => navigate("/assess")} data-testid="button-start-full-assessment">
            <Play className="w-4 h-4 mr-2" />
            New Assessment
          </Button>
        </div>
      </div>

      {selectedAssessment ? (
        <div className="space-y-4">
          <Button 
            variant="outline" 
            onClick={() => setSelectedAssessment(null)}
            data-testid="button-back-to-list"
          >
            Back to List
          </Button>
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between gap-4 flex-wrap">
                <div>
                  <CardTitle>{selectedAssessment.name}</CardTitle>
                  <CardDescription>
                    {selectedAssessment.description || "Full security assessment"}
                  </CardDescription>
                </div>
                <Badge className={statusColors[selectedAssessment.status]}>
                  {statusLabels[selectedAssessment.status]}
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              <AssessmentDetail assessment={selectedAssessment} />
            </CardContent>
          </Card>
        </div>
      ) : (
        <>
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
            </div>
          ) : assessments.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Target className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium">No Assessments Yet</h3>
                <p className="text-muted-foreground mt-1">
                  Start a full security assessment to analyze all your systems
                </p>
                <Button
                  className="mt-4"
                  onClick={() => navigate("/assess")}
                  data-testid="button-start-first-assessment"
                >
                  <Play className="w-4 h-4 mr-2" />
                  Start Your First Assessment
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {assessments.map((assessment) => (
                <AssessmentCard
                  key={assessment.id}
                  assessment={assessment}
                  onView={() => setSelectedAssessment(assessment)}
                  onDelete={() => deleteMutation.mutate(assessment.id)}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
