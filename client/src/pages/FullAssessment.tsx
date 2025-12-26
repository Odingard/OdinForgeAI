import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Progress } from "@/components/ui/progress";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
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
  AlertCircle
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
              <pre className="text-xs bg-muted/50 p-3 rounded-md overflow-auto max-h-96">
                {JSON.stringify(assessment.lateralMovementPaths, null, 2)}
              </pre>
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
              <pre className="text-xs bg-muted/50 p-3 rounded-md overflow-auto max-h-96">
                {JSON.stringify(assessment.businessImpactAnalysis, null, 2)}
              </pre>
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
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [selectedAssessment, setSelectedAssessment] = useState<FullAssessment | null>(null);
  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");
  
  const { data: assessments = [], isLoading, refetch } = useQuery<FullAssessment[]>({
    queryKey: ["/api/full-assessments"],
    refetchInterval: 5000,
  });
  
  const createMutation = useMutation({
    mutationFn: async (data: { name: string; description: string }) => {
      return apiRequest("POST", "/api/full-assessments", data);
    },
    onSuccess: () => {
      toast({ title: "Assessment Started", description: "Full security assessment is now running" });
      setIsCreateOpen(false);
      setNewName("");
      setNewDescription("");
      queryClient.invalidateQueries({ queryKey: ["/api/full-assessments"] });
    },
    onError: (error) => {
      toast({ title: "Error", description: String(error), variant: "destructive" });
    },
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

  const handleCreate = () => {
    if (!newName.trim()) {
      toast({ title: "Name required", variant: "destructive" });
      return;
    }
    createMutation.mutate({ name: newName, description: newDescription });
  };

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
          <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
            <DialogTrigger asChild>
              <Button data-testid="button-start-full-assessment">
                <Play className="w-4 h-4 mr-2" />
                Start Full Assessment
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Start Full Security Assessment</DialogTitle>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div>
                  <label className="text-sm font-medium">Assessment Name</label>
                  <Input
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    placeholder="Q4 2024 Security Assessment"
                    data-testid="input-assessment-name"
                  />
                </div>
                <div>
                  <label className="text-sm font-medium">Description (optional)</label>
                  <Textarea
                    value={newDescription}
                    onChange={(e) => setNewDescription(e.target.value)}
                    placeholder="Comprehensive assessment of all production systems..."
                    data-testid="input-assessment-description"
                  />
                </div>
                <div className="bg-muted/50 p-3 rounded-md">
                  <h4 className="text-sm font-medium flex items-center gap-2">
                    <Target className="w-4 h-4" />
                    What this assessment does:
                  </h4>
                  <ul className="text-sm text-muted-foreground mt-2 space-y-1">
                    <li>Collects findings from all deployed agents</li>
                    <li>Analyzes vulnerabilities across all systems</li>
                    <li>Maps cross-system attack paths using MITRE ATT&CK</li>
                    <li>Identifies lateral movement opportunities</li>
                    <li>Assesses business impact of potential breaches</li>
                    <li>Generates prioritized remediation recommendations</li>
                  </ul>
                </div>
                <Button 
                  onClick={handleCreate} 
                  disabled={createMutation.isPending}
                  className="w-full"
                  data-testid="button-confirm-start-assessment"
                >
                  {createMutation.isPending ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Play className="w-4 h-4 mr-2" />
                  )}
                  Start Assessment
                </Button>
              </div>
            </DialogContent>
          </Dialog>
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
                  onClick={() => setIsCreateOpen(true)}
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
