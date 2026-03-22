import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useSearch } from "wouter";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Swords, Play, Trash2, Eye, Clock, CheckCircle2, XCircle, Loader2, Shield, Skull, Zap, Lock, Radio, Globe, Cloud, HardDrive, UserX, FileKey, ChevronDown, Settings2, Trophy, Target, AlertTriangle, ArrowRight, TrendingUp, TrendingDown, Timer, Activity, ShieldCheck, ShieldAlert, Lightbulb, ChevronRight } from "lucide-react";
import { format } from "date-fns";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar } from "recharts";
import type { AiSimulation } from "@shared/schema";

interface LiveScanResult {
  id: number;
  evaluationId: string;
  targetHost: string;
  vulnerabilities: any[];
  ports: any[];
}

interface SimulationTemplate {
  id: string;
  name: string;
  description: string;
  icon: typeof Globe;
  iconColor: string;
  exposureType: string;
  priority: string;
  defaultRounds: number;
  scenarioDescription: string;
  assetIdPlaceholder: string;
}

const SIMULATION_TEMPLATES: SimulationTemplate[] = [
  {
    id: "web-breach",
    name: "Web Application Breach",
    description: "SQL injection, XSS, and authentication bypass attacks against web applications",
    icon: Globe,
    iconColor: "text-blue-500",
    exposureType: "api_sequence_abuse",
    priority: "high",
    defaultRounds: 3,
    scenarioDescription: "Simulate a sophisticated attacker targeting web application vulnerabilities including SQL injection, cross-site scripting (XSS), broken authentication, and API abuse. The attacker will attempt to gain unauthorized access, escalate privileges, and exfiltrate sensitive data.",
    assetIdPlaceholder: "web-app-001",
  },
  {
    id: "cloud-attack",
    name: "Cloud Infrastructure Attack",
    description: "Exploit cloud misconfigurations, IAM weaknesses, and container escapes",
    icon: Cloud,
    iconColor: "text-cyan-500",
    exposureType: "misconfiguration",
    priority: "critical",
    defaultRounds: 3,
    scenarioDescription: "Simulate an attacker exploiting cloud infrastructure weaknesses including misconfigured S3 buckets, overly permissive IAM roles, exposed secrets in environment variables, and container escape techniques. Focus on AWS/Azure/GCP attack patterns.",
    assetIdPlaceholder: "cloud-infra-001",
  },
  {
    id: "ransomware",
    name: "Ransomware Simulation",
    description: "Simulate ransomware deployment, lateral movement, and data encryption tactics",
    icon: HardDrive,
    iconColor: "text-red-500",
    exposureType: "network_vulnerability",
    priority: "critical",
    defaultRounds: 5,
    scenarioDescription: "Simulate a ransomware attack scenario including initial access via phishing or RDP exposure, credential harvesting, lateral movement through the network, disabling backups and security tools, and simulated encryption of critical systems.",
    assetIdPlaceholder: "network-segment-001",
  },
  {
    id: "data-exfil",
    name: "Data Exfiltration",
    description: "Test detection of sensitive data theft via multiple exfiltration channels",
    icon: FileKey,
    iconColor: "text-orange-500",
    exposureType: "data_exfiltration",
    priority: "high",
    defaultRounds: 3,
    scenarioDescription: "Simulate an attacker attempting to exfiltrate sensitive data using various techniques including DNS tunneling, steganography, encrypted channels, cloud storage abuse, and code repository theft. Test DLP controls and network monitoring capabilities.",
    assetIdPlaceholder: "data-server-001",
  },
  {
    id: "insider-threat",
    name: "Insider Threat",
    description: "Simulate malicious insider with legitimate credentials abusing access",
    icon: UserX,
    iconColor: "text-purple-500",
    exposureType: "iam_abuse",
    priority: "high",
    defaultRounds: 3,
    scenarioDescription: "Simulate a malicious insider with valid credentials attempting to abuse their access. Includes privilege escalation, unauthorized data access, covering tracks, and attempting to create persistence. Tests behavioral analytics and access controls.",
    assetIdPlaceholder: "user-workstation-001",
  },
];

export default function Simulations() {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const searchString = useSearch();
  
  const canRunSimulation = hasPermission("simulations:run");
  const canDeleteSimulation = hasPermission("simulations:delete");
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState<SimulationTemplate | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [selectedSimulation, setSelectedSimulation] = useState<AiSimulation | null>(null);
  const [formData, setFormData] = useState({
    assetId: "",
    exposureType: "cve",
    priority: "high",
    description: "",
    rounds: 3,
    sourceEvaluationId: "",
  });

  useEffect(() => {
    if (searchString) {
      const params = new URLSearchParams(searchString);
      const assetId = params.get("assetId");
      const exposureType = params.get("exposureType");
      const priority = params.get("priority");
      const fromEvaluation = params.get("fromEvaluation");

      if (assetId && fromEvaluation) {
        setFormData({
          assetId,
          exposureType: exposureType || "cve",
          priority: priority || "high",
          description: `AI vs AI simulation based on evaluation ${fromEvaluation}. Simulate attacker attempting to exploit ${exposureType || "vulnerability"} on asset ${assetId}.`,
          rounds: 3,
          sourceEvaluationId: fromEvaluation,
        });
        setSelectedTemplate({
          id: "from-evaluation",
          name: "From Evaluation",
          description: `Simulation based on evaluation ${fromEvaluation}`,
          icon: Swords,
          iconColor: "text-purple-500",
          exposureType: exposureType || "cve",
          priority: priority || "high",
          defaultRounds: 3,
          scenarioDescription: `AI vs AI simulation based on evaluation ${fromEvaluation}. Simulate attacker attempting to exploit ${exposureType || "vulnerability"} on asset ${assetId}.`,
          assetIdPlaceholder: assetId,
        });
        setShowAdvanced(true);
        setIsCreateOpen(true);
      }
    }
  }, [searchString]);

  const { data: simulations = [], isLoading } = useQuery<AiSimulation[]>({
    queryKey: ["/api/simulations"],
  });

  const { data: liveScanResults = [] } = useQuery<LiveScanResult[]>({
    queryKey: ["/api/aev/live-scans"],
  });

  const createMutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      const payload = {
        ...data,
        sourceEvaluationId: data.sourceEvaluationId && data.sourceEvaluationId !== "none" ? data.sourceEvaluationId : undefined,
      };
      const res = await apiRequest("POST", "/api/simulations", payload);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/simulations"] });
      setIsCreateOpen(false);
      setSelectedTemplate(null);
      setShowAdvanced(false);
      setFormData({ assetId: "", exposureType: "cve", priority: "high", description: "", rounds: 3, sourceEvaluationId: "" });
      toast({ title: "Simulation Started", description: "AI vs AI simulation is now running." });
    },
    onError: (error: Error) => {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/simulations/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/simulations"] });
      toast({ title: "Simulation Deleted" });
    },
    onError: (error: Error) => {
      toast({ title: "Delete Failed", description: error.message, variant: "destructive" });
    },
  });

  const selectTemplate = (template: SimulationTemplate) => {
    setSelectedTemplate(template);
    setFormData({
      assetId: template.assetIdPlaceholder,
      exposureType: template.exposureType,
      priority: template.priority,
      description: template.scenarioDescription,
      rounds: template.defaultRounds,
      sourceEvaluationId: "",
    });
  };

  const resetToTemplateSelection = () => {
    setSelectedTemplate(null);
    setShowAdvanced(false);
    setFormData({ assetId: "", exposureType: "cve", priority: "high", description: "", rounds: 3, sourceEvaluationId: "" });
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "running":
        return <Badge variant="outline" className="text-blue-500 border-blue-500"><Loader2 className="h-3 w-3 mr-1 animate-spin" />Running</Badge>;
      case "completed":
        return <Badge variant="outline" className="text-green-500 border-green-500"><CheckCircle2 className="h-3 w-3 mr-1" />Completed</Badge>;
      case "failed":
        return <Badge variant="outline" className="text-red-500 border-red-500"><XCircle className="h-3 w-3 mr-1" />Failed</Badge>;
      default:
        return <Badge variant="outline" className="text-muted-foreground"><Clock className="h-3 w-3 mr-1" />Pending</Badge>;
    }
  };

  const getSimulationResults = (simulation: AiSimulation) => {
    const results = simulation.simulationResults as any;
    if (!results) return null;
    return {
      attackerSuccesses: results.attackerSuccesses || results.finalAttackScore || 0,
      defenderBlocks: results.defenderBlocks || results.finalDefenseScore || 0,
      attackPath: results.attackPath || [],
      detectionPoints: results.detectionPoints || [],
      missedAttacks: results.missedAttacks || [],
      recommendations: results.recommendations || [],
      winner: results.winner,
      summary: results.summary || results.executiveSummary,
      executiveSummary: results.executiveSummary,
      error: results.error,
      rounds: results.rounds || [],
      totalRounds: results.totalRounds || 0,
      purpleTeamFeedback: results.purpleTeamFeedback,
      fullRecommendations: results.fullRecommendations || [],
      totalProcessingTime: results.totalProcessingTime || 0,
    };
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Swords className="h-6 w-6 text-purple-500" />
            AI vs AI Simulations
          </h1>
          <p className="text-muted-foreground">
            Purple team exercises with autonomous attack and defense AI agents
          </p>
        </div>
        <Dialog open={isCreateOpen} onOpenChange={(open) => {
          setIsCreateOpen(open);
          if (!open) resetToTemplateSelection();
        }}>
          <DialogTrigger asChild>
            <Button data-testid="button-new-simulation" disabled={!canRunSimulation}>
              {canRunSimulation ? <Play className="h-4 w-4 mr-2" /> : <Lock className="h-4 w-4 mr-2" />}
              Start Simulation
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[600px] max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>
                {selectedTemplate ? (
                  <span className="flex items-center gap-2">
                    <selectedTemplate.icon className={`h-5 w-5 ${selectedTemplate.iconColor}`} />
                    {selectedTemplate.name}
                  </span>
                ) : (
                  "Start AI vs AI Simulation"
                )}
              </DialogTitle>
              <DialogDescription>
                {selectedTemplate 
                  ? "Review and customize the simulation settings, then click Start" 
                  : "Choose a simulation template or configure a custom scenario"}
              </DialogDescription>
            </DialogHeader>

            {!selectedTemplate ? (
              <div className="space-y-4 py-4">
                <div className="grid grid-cols-1 gap-3">
                  {SIMULATION_TEMPLATES.map((template) => (
                    <Card 
                      key={template.id} 
                      className="cursor-pointer hover-elevate transition-all"
                      onClick={() => selectTemplate(template)}
                      data-testid={`template-${template.id}`}
                    >
                      <CardContent className="flex items-start gap-4 p-4">
                        <div className={`p-2 rounded-md bg-muted`}>
                          <template.icon className={`h-6 w-6 ${template.iconColor}`} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <h4 className="font-medium text-sm">{template.name}</h4>
                          <p className="text-xs text-muted-foreground mt-1">{template.description}</p>
                          <div className="flex items-center gap-2 mt-2">
                            <Badge variant="secondary" className="text-xs">{template.defaultRounds} rounds</Badge>
                            <Badge variant="outline" className="text-xs">{template.priority} priority</Badge>
                          </div>
                        </div>
                        <Play className="h-4 w-4 text-muted-foreground" />
                      </CardContent>
                    </Card>
                  ))}
                </div>

                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <span className="w-full border-t" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-background px-2 text-muted-foreground">or</span>
                  </div>
                </div>

                <Button 
                  variant="outline" 
                  className="w-full" 
                  onClick={() => {
                    setSelectedTemplate({
                      id: "custom",
                      name: "Custom Simulation",
                      description: "Configure your own scenario",
                      icon: Settings2,
                      iconColor: "text-muted-foreground",
                      exposureType: "cve",
                      priority: "high",
                      defaultRounds: 3,
                      scenarioDescription: "",
                      assetIdPlaceholder: "",
                    });
                    setShowAdvanced(true);
                  }}
                  data-testid="button-custom-simulation"
                >
                  <Settings2 className="h-4 w-4 mr-2" />
                  Configure Custom Simulation
                </Button>
              </div>
            ) : (
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="assetId">Target Asset ID</Label>
                  <Input
                    id="assetId"
                    value={formData.assetId}
                    onChange={(e) => setFormData({ ...formData, assetId: e.target.value })}
                    placeholder={selectedTemplate.assetIdPlaceholder || "e.g., web-server-001"}
                    data-testid="input-simulation-asset"
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="rounds">Simulation Rounds</Label>
                  <Select
                    value={String(formData.rounds)}
                    onValueChange={(v) => setFormData({ ...formData, rounds: parseInt(v) })}
                  >
                    <SelectTrigger data-testid="select-simulation-rounds">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1">1 Round (Quick)</SelectItem>
                      <SelectItem value="2">2 Rounds</SelectItem>
                      <SelectItem value="3">3 Rounds (Standard)</SelectItem>
                      <SelectItem value="5">5 Rounds (Thorough)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {liveScanResults.length > 0 && (
                  <div className="space-y-2">
                    <Label htmlFor="sourceEvaluation" className="flex items-center gap-2">
                      <Radio className="h-4 w-4 text-green-500" />
                      Use Live Scan Data (Optional)
                    </Label>
                    <Select
                      value={formData.sourceEvaluationId}
                      onValueChange={(v) => setFormData({ ...formData, sourceEvaluationId: v })}
                    >
                      <SelectTrigger data-testid="select-live-scan-source">
                        <SelectValue placeholder="Inject real scan data for realism..." />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="none">None (use template scenario)</SelectItem>
                        {liveScanResults.map((scan) => (
                          <SelectItem key={scan.evaluationId} value={scan.evaluationId}>
                            {scan.targetHost} ({scan.ports?.length || 0} ports, {scan.vulnerabilities?.length || 0} vulns)
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                )}

                <Collapsible open={showAdvanced} onOpenChange={setShowAdvanced}>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" size="sm" className="w-full justify-between" data-testid="button-toggle-advanced">
                      <span className="flex items-center gap-2">
                        <Settings2 className="h-4 w-4" />
                        Advanced Options
                      </span>
                      <ChevronDown className={`h-4 w-4 transition-transform ${showAdvanced ? 'rotate-180' : ''}`} />
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="space-y-4 pt-4">
                    <div className="space-y-2">
                      <Label htmlFor="exposureType">Exposure Type</Label>
                      <Select
                        value={formData.exposureType}
                        onValueChange={(v) => setFormData({ ...formData, exposureType: v })}
                      >
                        <SelectTrigger data-testid="select-simulation-type">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="cve">CVE Vulnerability</SelectItem>
                          <SelectItem value="misconfiguration">Misconfiguration</SelectItem>
                          <SelectItem value="network_vulnerability">Network Vulnerability</SelectItem>
                          <SelectItem value="cloud_misconfiguration">Cloud Misconfiguration</SelectItem>
                          <SelectItem value="api_sequence_abuse">API Sequence Abuse</SelectItem>
                          <SelectItem value="iam_abuse">IAM Abuse</SelectItem>
                          <SelectItem value="saas_permission">SaaS Permission Abuse</SelectItem>
                          <SelectItem value="shadow_admin">Shadow Admin</SelectItem>
                          <SelectItem value="data_exfiltration">Data Exfiltration</SelectItem>
                          <SelectItem value="payment_flow">Payment Flow</SelectItem>
                          <SelectItem value="subscription_bypass">Subscription Bypass</SelectItem>
                          <SelectItem value="state_machine">State Machine</SelectItem>
                          <SelectItem value="privilege_boundary">Privilege Boundary</SelectItem>
                          <SelectItem value="workflow_desync">Workflow Desync</SelectItem>
                          <SelectItem value="order_lifecycle">Order Lifecycle</SelectItem>
                          <SelectItem value="app_logic">Application Logic</SelectItem>
                          <SelectItem value="behavioral_anomaly">Behavioral Anomaly</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="priority">Priority Level</Label>
                      <Select
                        value={formData.priority}
                        onValueChange={(v) => setFormData({ ...formData, priority: v })}
                      >
                        <SelectTrigger data-testid="select-simulation-priority">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="critical">Critical</SelectItem>
                          <SelectItem value="high">High</SelectItem>
                          <SelectItem value="medium">Medium</SelectItem>
                          <SelectItem value="low">Low</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="description">Scenario Description</Label>
                      <Textarea
                        id="description"
                        value={formData.description}
                        onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                        placeholder="Describe the attack scenario and target environment..."
                        rows={4}
                        data-testid="input-simulation-description"
                      />
                    </div>
                  </CollapsibleContent>
                </Collapsible>

                <DialogFooter className="flex-col sm:flex-row gap-2">
                  <Button variant="outline" onClick={resetToTemplateSelection} data-testid="button-back-templates">
                    Back to Templates
                  </Button>
                  <Button
                    onClick={() => createMutation.mutate(formData)}
                    disabled={!formData.assetId || !formData.description || createMutation.isPending}
                    data-testid="button-start-simulation"
                  >
                    {createMutation.isPending ? (
                      <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Starting...</>
                    ) : (
                      <><Play className="h-4 w-4 mr-2" />Start Simulation</>
                    )}
                  </Button>
                </DialogFooter>
              </div>
            )}
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      ) : simulations.length === 0 ? (
        <div className="space-y-6">
          <Card>
            <CardContent className="py-12">
              <div className="text-center">
                <Swords className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-medium mb-2">No Simulations Yet</h3>
                <p className="text-muted-foreground mb-4">
                  Start your first AI vs AI simulation to test your defenses
                </p>
                <Button onClick={() => setIsCreateOpen(true)} data-testid="button-start-first-simulation">
                  <Play className="h-4 w-4 mr-2" />
                  Start First Simulation
                </Button>
              </div>
            </CardContent>
          </Card>

          <div>
            <h3 className="text-sm font-medium text-muted-foreground mb-3">Quick Start Templates</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {SIMULATION_TEMPLATES.slice(0, 3).map((template) => (
                <Card 
                  key={template.id} 
                  className="cursor-pointer hover-elevate transition-all"
                  onClick={() => {
                    selectTemplate(template);
                    setIsCreateOpen(true);
                  }}
                  data-testid={`quick-template-${template.id}`}
                >
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <template.icon className={`h-4 w-4 ${template.iconColor}`} />
                      {template.name}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-xs text-muted-foreground">{template.description}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="grid gap-4">
          {simulations.map((simulation) => {
            const results = getSimulationResults(simulation);
            return (
              <Card key={simulation.id} data-testid={`card-simulation-${simulation.id}`}>
                <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0 pb-2">
                  <div className="space-y-1">
                    <CardTitle className="text-base font-medium">{simulation.name}</CardTitle>
                    <CardDescription className="line-clamp-1">{simulation.description}</CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    {getStatusBadge(simulation.simulationStatus || "pending")}
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap items-center justify-between gap-4">
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                      <span>Started: {simulation.startedAt ? format(new Date(simulation.startedAt), "PPp") : "Not started"}</span>
                      {simulation.completedAt && (
                        <span>Completed: {format(new Date(simulation.completedAt), "PPp")}</span>
                      )}
                    </div>
                    
                    {results && simulation.simulationStatus === "completed" && (
                      <div className="flex items-center gap-4">
                        <div className="flex items-center gap-1">
                          <Skull className="h-4 w-4 text-red-500" />
                          <span className="text-sm font-medium">{Math.round(results.attackerSuccesses)}%</span>
                          <span className="text-xs text-muted-foreground">attack</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Shield className="h-4 w-4 text-green-500" />
                          <span className="text-sm font-medium">{Math.round(results.defenderBlocks)}%</span>
                          <span className="text-xs text-muted-foreground">defense</span>
                        </div>
                        {results.winner && (
                          <Badge variant={results.winner === "defender" ? "default" : "destructive"} className="text-xs">
                            {results.winner === "defender" ? "Defender Wins" : results.winner === "attacker" ? "Attacker Wins" : "Draw"}
                          </Badge>
                        )}
                      </div>
                    )}

                    {results?.error && simulation.simulationStatus === "failed" && (
                      <div className="w-full mt-2 p-2 bg-red-500/10 border border-red-500/20 rounded text-xs text-red-500">
                        <span className="font-medium">Error: </span>{results.error}
                      </div>
                    )}

                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setSelectedSimulation(simulation)}
                        disabled={simulation.simulationStatus !== "completed"}
                        data-testid={`button-view-${simulation.id}`}
                      >
                        <Eye className="h-4 w-4 mr-1" />
                        View Results
                      </Button>
                      {canDeleteSimulation && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => deleteMutation.mutate(simulation.id)}
                          data-testid={`button-delete-${simulation.id}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      <Dialog open={!!selectedSimulation} onOpenChange={() => setSelectedSimulation(null)}>
        <DialogContent className="max-w-4xl max-h-[85vh] overflow-y-auto p-0">
          {selectedSimulation && (() => {
            const results = getSimulationResults(selectedSimulation);
            if (!results) return <div className="p-6"><p>No results available</p></div>;

            const attackScore = Math.round(results.attackerSuccesses);
            const defenseScore = Math.round(results.defenderBlocks);
            const winnerIsDefender = results.winner === "defender";
            const winnerIsAttacker = results.winner === "attacker";
            const isDraw = !winnerIsDefender && !winnerIsAttacker;

            // Build round chart data
            const roundChartData = (results.rounds || []).map((r: any) => ({
              name: `R${r.roundNumber}`,
              attack: Math.round((r.attackSuccess || 0) * 100),
              defense: Math.round((r.defenseSuccess || 0) * 100),
            }));

            // Detection effectiveness data for radar chart
            const detectionRate = results.detectionPoints.length > 0 || results.missedAttacks.length > 0
              ? Math.round((results.detectionPoints.length / (results.detectionPoints.length + results.missedAttacks.length)) * 100)
              : 0;
            const coverageRate = results.attackPath.length > 0
              ? Math.round((results.detectionPoints.length / Math.max(results.attackPath.length, 1)) * 100)
              : 0;

            const radarData = [
              { metric: "Detection", value: detectionRate, fullMark: 100 },
              { metric: "Coverage", value: Math.min(coverageRate, 100), fullMark: 100 },
              { metric: "Defense", value: defenseScore, fullMark: 100 },
              { metric: "Blocking", value: Math.min(defenseScore + 10, 100), fullMark: 100 },
              { metric: "Response", value: Math.max(defenseScore - 5, 0), fullMark: 100 },
            ];

            const priorityColors: Record<string, string> = {
              critical: "bg-red-500/10 text-red-500 border-red-500/30",
              high: "bg-orange-500/10 text-orange-500 border-orange-500/30",
              medium: "bg-yellow-500/10 text-yellow-600 border-yellow-500/30",
              low: "bg-blue-500/10 text-blue-500 border-blue-500/30",
            };

            return (
              <div className="flex flex-col">
                {/* Winner Banner */}
                <div className={`px-6 py-4 flex items-center justify-between ${
                  winnerIsDefender ? "bg-gradient-to-r from-emerald-500/15 to-emerald-600/5 border-b border-emerald-500/20" :
                  winnerIsAttacker ? "bg-gradient-to-r from-red-500/15 to-red-600/5 border-b border-red-500/20" :
                  "bg-gradient-to-r from-amber-500/15 to-amber-600/5 border-b border-amber-500/20"
                }`}>
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-full ${
                      winnerIsDefender ? "bg-emerald-500/20" : winnerIsAttacker ? "bg-red-500/20" : "bg-amber-500/20"
                    }`}>
                      <Trophy className={`h-5 w-5 ${
                        winnerIsDefender ? "text-emerald-500" : winnerIsAttacker ? "text-red-500" : "text-amber-500"
                      }`} />
                    </div>
                    <div>
                      <h2 className="font-semibold text-lg">
                        {winnerIsDefender ? "Defender Wins" : winnerIsAttacker ? "Attacker Wins" : "Draw"}
                      </h2>
                      <p className="text-xs text-muted-foreground">{selectedSimulation.name}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-6">
                    <div className="text-center">
                      <div className="flex items-center gap-1.5">
                        <Skull className="h-4 w-4 text-red-500" />
                        <span className="text-2xl font-bold text-red-500">{attackScore}%</span>
                      </div>
                      <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Attack</p>
                    </div>
                    <div className="text-muted-foreground font-bold text-lg">vs</div>
                    <div className="text-center">
                      <div className="flex items-center gap-1.5">
                        <Shield className="h-4 w-4 text-emerald-500" />
                        <span className="text-2xl font-bold text-emerald-500">{defenseScore}%</span>
                      </div>
                      <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Defense</p>
                    </div>
                  </div>
                </div>

                {/* Score Comparison Bars */}
                <div className="px-6 py-4 border-b">
                  <div className="space-y-3">
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="flex items-center gap-1.5 font-medium"><Skull className="h-3 w-3 text-red-500" />Attacker Success</span>
                        <span className="font-mono text-red-500">{attackScore}%</span>
                      </div>
                      <div className="h-3 bg-muted rounded-full overflow-hidden">
                        <div className="h-full bg-gradient-to-r from-red-600 to-red-400 rounded-full transition-all duration-1000" style={{ width: `${attackScore}%` }} />
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="flex items-center gap-1.5 font-medium"><Shield className="h-3 w-3 text-emerald-500" />Defense Effectiveness</span>
                        <span className="font-mono text-emerald-500">{defenseScore}%</span>
                      </div>
                      <div className="h-3 bg-muted rounded-full overflow-hidden">
                        <div className="h-full bg-gradient-to-r from-emerald-600 to-emerald-400 rounded-full transition-all duration-1000" style={{ width: `${defenseScore}%` }} />
                      </div>
                    </div>
                  </div>
                  {results.totalProcessingTime > 0 && (
                    <div className="flex items-center gap-1 mt-3 text-xs text-muted-foreground">
                      <Timer className="h-3 w-3" />
                      Completed in {(results.totalProcessingTime / 1000).toFixed(1)}s
                      {results.totalRounds > 0 && <> across {results.totalRounds} rounds</>}
                    </div>
                  )}
                </div>

                {/* Tabbed Content */}
                <Tabs defaultValue="overview" className="px-6 pt-4 pb-6">
                  <TabsList className="grid grid-cols-4 mb-4">
                    <TabsTrigger value="overview" className="text-xs">Overview</TabsTrigger>
                    <TabsTrigger value="rounds" className="text-xs">Rounds</TabsTrigger>
                    <TabsTrigger value="detection" className="text-xs">Detection</TabsTrigger>
                    <TabsTrigger value="recommendations" className="text-xs">Actions</TabsTrigger>
                  </TabsList>

                  {/* OVERVIEW TAB */}
                  <TabsContent value="overview" className="space-y-5 mt-0">
                    {/* Executive Summary */}
                    {(results.executiveSummary || results.summary) && (
                      <div className="p-4 bg-muted/50 rounded-lg border">
                        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Executive Summary</h4>
                        <p className="text-sm leading-relaxed">{results.executiveSummary || results.summary}</p>
                      </div>
                    )}

                    <div className="grid grid-cols-2 gap-4">
                      {/* Defense Radar Chart */}
                      <Card>
                        <CardHeader className="pb-0 pt-4 px-4">
                          <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Defense Posture</CardTitle>
                        </CardHeader>
                        <CardContent className="pb-2 px-2">
                          <ResponsiveContainer width="100%" height={200}>
                            <RadarChart data={radarData}>
                              <PolarGrid stroke="hsl(var(--border))" />
                              <PolarAngleAxis dataKey="metric" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                              <PolarRadiusAxis angle={90} domain={[0, 100]} tick={false} axisLine={false} />
                              <Radar name="Score" dataKey="value" stroke="hsl(142, 76%, 36%)" fill="hsl(142, 76%, 36%)" fillOpacity={0.2} strokeWidth={2} />
                            </RadarChart>
                          </ResponsiveContainer>
                        </CardContent>
                      </Card>

                      {/* Round Performance Chart */}
                      {roundChartData.length > 0 ? (
                        <Card>
                          <CardHeader className="pb-0 pt-4 px-4">
                            <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Round Performance</CardTitle>
                          </CardHeader>
                          <CardContent className="pb-2 px-2">
                            <ResponsiveContainer width="100%" height={200}>
                              <BarChart data={roundChartData} barGap={2}>
                                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                                <XAxis dataKey="name" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                                <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                                <Tooltip
                                  contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: "12px" }}
                                  labelStyle={{ color: "hsl(var(--foreground))" }}
                                />
                                <Legend wrapperStyle={{ fontSize: "11px" }} />
                                <Bar dataKey="attack" name="Attack" fill="hsl(0, 84%, 60%)" radius={[3, 3, 0, 0]} />
                                <Bar dataKey="defense" name="Defense" fill="hsl(142, 76%, 36%)" radius={[3, 3, 0, 0]} />
                              </BarChart>
                            </ResponsiveContainer>
                          </CardContent>
                        </Card>
                      ) : (
                        <Card>
                          <CardHeader className="pb-2 pt-4 px-4">
                            <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Quick Stats</CardTitle>
                          </CardHeader>
                          <CardContent className="space-y-3 px-4">
                            <div className="flex items-center justify-between">
                              <span className="text-xs text-muted-foreground">Attack Techniques</span>
                              <span className="font-mono text-sm">{results.attackPath.length}</span>
                            </div>
                            <Separator />
                            <div className="flex items-center justify-between">
                              <span className="text-xs text-muted-foreground">Detections</span>
                              <span className="font-mono text-sm text-emerald-500">{results.detectionPoints.length}</span>
                            </div>
                            <Separator />
                            <div className="flex items-center justify-between">
                              <span className="text-xs text-muted-foreground">Gaps Found</span>
                              <span className="font-mono text-sm text-red-500">{results.missedAttacks.length}</span>
                            </div>
                            <Separator />
                            <div className="flex items-center justify-between">
                              <span className="text-xs text-muted-foreground">Recommendations</span>
                              <span className="font-mono text-sm">{results.fullRecommendations.length || results.recommendations.length}</span>
                            </div>
                          </CardContent>
                        </Card>
                      )}
                    </div>

                    {/* Attack Path Flow */}
                    {results.attackPath.length > 0 && (
                      <div>
                        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">Attack Path</h4>
                        <div className="flex items-center gap-1 flex-wrap">
                          {results.attackPath.map((step: string, i: number) => {
                            const isDetected = results.detectionPoints.some((d: string) =>
                              step.toLowerCase().includes(d.toLowerCase()) || d.toLowerCase().includes(step.toLowerCase())
                            );
                            return (
                              <div key={i} className="flex items-center gap-1">
                                <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs border ${
                                  isDetected
                                    ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-400"
                                    : "bg-red-500/10 border-red-500/30 text-red-600 dark:text-red-400"
                                }`}>
                                  {isDetected ? <ShieldCheck className="h-3 w-3" /> : <ShieldAlert className="h-3 w-3" />}
                                  <span>{step}</span>
                                </div>
                                {i < results.attackPath.length - 1 && (
                                  <ChevronRight className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* Purple Team Feedback */}
                    {results.purpleTeamFeedback && (
                      <Card className="border-purple-500/20">
                        <CardHeader className="pb-2 pt-4 px-4">
                          <CardTitle className="text-xs font-semibold uppercase tracking-wider text-purple-500 flex items-center gap-1.5">
                            <Swords className="h-3.5 w-3.5" />
                            Purple Team Insights
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-3 px-4 pb-4">
                          {results.purpleTeamFeedback.overallInsight && (
                            <p className="text-sm leading-relaxed">{results.purpleTeamFeedback.overallInsight}</p>
                          )}
                          <div className="grid grid-cols-2 gap-3">
                            {results.purpleTeamFeedback.attackerAdaptations?.length > 0 && (
                              <div className="space-y-1.5">
                                <h5 className="text-[10px] font-semibold uppercase tracking-wider text-red-500">Attacker Adaptations</h5>
                                {results.purpleTeamFeedback.attackerAdaptations.map((a: string, i: number) => (
                                  <div key={i} className="flex items-start gap-1.5 text-xs text-muted-foreground">
                                    <TrendingUp className="h-3 w-3 text-red-400 mt-0.5 flex-shrink-0" />
                                    <span>{a}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                            {results.purpleTeamFeedback.defenderAdaptations?.length > 0 && (
                              <div className="space-y-1.5">
                                <h5 className="text-[10px] font-semibold uppercase tracking-wider text-emerald-500">Defender Adaptations</h5>
                                {results.purpleTeamFeedback.defenderAdaptations.map((d: string, i: number) => (
                                  <div key={i} className="flex items-start gap-1.5 text-xs text-muted-foreground">
                                    <ShieldCheck className="h-3 w-3 text-emerald-400 mt-0.5 flex-shrink-0" />
                                    <span>{d}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </CardContent>
                      </Card>
                    )}
                  </TabsContent>

                  {/* ROUNDS TAB */}
                  <TabsContent value="rounds" className="space-y-4 mt-0">
                    {results.rounds.length > 0 ? (
                      results.rounds.map((round: any, i: number) => {
                        const rAttack = Math.round((round.attackSuccess || 0) * 100);
                        const rDefense = Math.round((round.defenseSuccess || 0) * 100);
                        const roundWinner = rAttack > rDefense + 10 ? "attacker" : rDefense > rAttack + 10 ? "defender" : "contested";
                        return (
                          <Card key={i} className="overflow-hidden">
                            <div className={`h-1 ${
                              roundWinner === "defender" ? "bg-emerald-500" : roundWinner === "attacker" ? "bg-red-500" : "bg-amber-500"
                            }`} />
                            <CardHeader className="pb-2 pt-3 px-4">
                              <div className="flex items-center justify-between">
                                <CardTitle className="text-sm flex items-center gap-2">
                                  <Activity className="h-4 w-4 text-purple-500" />
                                  Round {round.roundNumber}
                                </CardTitle>
                                <div className="flex items-center gap-3 text-xs">
                                  <span className="flex items-center gap-1">
                                    <Skull className="h-3 w-3 text-red-500" />
                                    <span className="font-mono font-medium text-red-500">{rAttack}%</span>
                                  </span>
                                  <span className="text-muted-foreground">vs</span>
                                  <span className="flex items-center gap-1">
                                    <Shield className="h-3 w-3 text-emerald-500" />
                                    <span className="font-mono font-medium text-emerald-500">{rDefense}%</span>
                                  </span>
                                </div>
                              </div>
                            </CardHeader>
                            <CardContent className="px-4 pb-4 space-y-3">
                              {/* Round score bars */}
                              <div className="flex gap-1 h-2 rounded-full overflow-hidden bg-muted">
                                <div className="bg-red-500 rounded-l-full transition-all" style={{ width: `${rAttack}%` }} />
                                <div className="bg-emerald-500 rounded-r-full transition-all" style={{ width: `${rDefense}%` }} />
                              </div>
                              {/* Round summary */}
                              {round.roundSummary && (
                                <p className="text-xs text-muted-foreground leading-relaxed">{round.roundSummary}</p>
                              )}
                              {/* Round details */}
                              <div className="grid grid-cols-2 gap-3">
                                {round.attackerFindings && (
                                  <div className="p-2.5 bg-red-500/5 rounded-md border border-red-500/10">
                                    <h5 className="text-[10px] font-semibold uppercase tracking-wider text-red-500 mb-1.5">Attacker</h5>
                                    <div className="space-y-1 text-xs text-muted-foreground">
                                      {round.attackerFindings.exploitable !== undefined && (
                                        <div className="flex justify-between">
                                          <span>Exploitable</span>
                                          <span className={round.attackerFindings.exploitable ? "text-red-500" : "text-emerald-500"}>
                                            {round.attackerFindings.exploitable ? "Yes" : "No"}
                                          </span>
                                        </div>
                                      )}
                                      {round.attackerFindings.confidence !== undefined && (
                                        <div className="flex justify-between">
                                          <span>Confidence</span>
                                          <span className="font-mono">{round.attackerFindings.confidence}%</span>
                                        </div>
                                      )}
                                      {round.attackerFindings.impact && (
                                        <p className="text-[11px] mt-1.5 pt-1.5 border-t border-red-500/10">{round.attackerFindings.impact}</p>
                                      )}
                                    </div>
                                  </div>
                                )}
                                {round.defenderFindings && (
                                  <div className="p-2.5 bg-emerald-500/5 rounded-md border border-emerald-500/10">
                                    <h5 className="text-[10px] font-semibold uppercase tracking-wider text-emerald-500 mb-1.5">Defender</h5>
                                    <div className="space-y-1 text-xs text-muted-foreground">
                                      <div className="flex justify-between">
                                        <span>Detected</span>
                                        <span className="font-mono">{Array.isArray(round.defenderFindings.detectedAttacks) ? round.defenderFindings.detectedAttacks.length : round.defenderFindings.detectedAttacks || 0}</span>
                                      </div>
                                      <div className="flex justify-between">
                                        <span>Blocked</span>
                                        <span className="font-mono">{Array.isArray(round.defenderFindings.blockedPaths) ? round.defenderFindings.blockedPaths.length : round.defenderFindings.blockedPaths || 0}</span>
                                      </div>
                                      <div className="flex justify-between">
                                        <span>Alerts</span>
                                        <span className="font-mono">{Array.isArray(round.defenderFindings.alertsGenerated) ? round.defenderFindings.alertsGenerated.length : round.defenderFindings.alertsGenerated || 0}</span>
                                      </div>
                                      {round.defenderFindings.gapsIdentified?.length > 0 && (
                                        <div className="mt-1.5 pt-1.5 border-t border-emerald-500/10">
                                          <span className="text-red-400">Gaps: {round.defenderFindings.gapsIdentified.length}</span>
                                        </div>
                                      )}
                                    </div>
                                  </div>
                                )}
                              </div>
                            </CardContent>
                          </Card>
                        );
                      })
                    ) : (
                      <div className="text-center py-8 text-muted-foreground">
                        <Activity className="h-8 w-8 mx-auto mb-2 opacity-50" />
                        <p className="text-sm">Round-by-round data not available for this simulation.</p>
                        <p className="text-xs mt-1">Run a new simulation to see detailed round breakdowns.</p>
                      </div>
                    )}
                  </TabsContent>

                  {/* DETECTION TAB */}
                  <TabsContent value="detection" className="space-y-5 mt-0">
                    {/* Detection Summary Cards */}
                    <div className="grid grid-cols-3 gap-3">
                      <Card className="bg-emerald-500/5 border-emerald-500/20">
                        <CardContent className="p-4 text-center">
                          <CheckCircle2 className="h-5 w-5 text-emerald-500 mx-auto mb-1" />
                          <div className="text-2xl font-bold text-emerald-500">{results.detectionPoints.length}</div>
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Detected</p>
                        </CardContent>
                      </Card>
                      <Card className="bg-red-500/5 border-red-500/20">
                        <CardContent className="p-4 text-center">
                          <AlertTriangle className="h-5 w-5 text-red-500 mx-auto mb-1" />
                          <div className="text-2xl font-bold text-red-500">{results.missedAttacks.length}</div>
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Missed</p>
                        </CardContent>
                      </Card>
                      <Card className="bg-blue-500/5 border-blue-500/20">
                        <CardContent className="p-4 text-center">
                          <Target className="h-5 w-5 text-blue-500 mx-auto mb-1" />
                          <div className="text-2xl font-bold text-blue-500">{detectionRate}%</div>
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Detection Rate</p>
                        </CardContent>
                      </Card>
                    </div>

                    {/* Detection List */}
                    {results.detectionPoints.length > 0 && (
                      <div>
                        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2.5">Successful Detections</h4>
                        <div className="space-y-1.5">
                          {results.detectionPoints.map((point: string, i: number) => (
                            <div key={i} className="flex items-center gap-2 p-2.5 bg-emerald-500/5 rounded-md border border-emerald-500/10">
                              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500 flex-shrink-0" />
                              <span className="text-xs">{point}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Gaps List */}
                    {results.missedAttacks.length > 0 && (
                      <div>
                        <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2.5">Detection Gaps</h4>
                        <div className="space-y-1.5">
                          {results.missedAttacks.map((gap: string, i: number) => (
                            <div key={i} className="flex items-center gap-2 p-2.5 bg-red-500/5 rounded-md border border-red-500/10">
                              <XCircle className="h-3.5 w-3.5 text-red-500 flex-shrink-0" />
                              <span className="text-xs">{gap}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {results.detectionPoints.length === 0 && results.missedAttacks.length === 0 && (
                      <div className="text-center py-8 text-muted-foreground">
                        <Shield className="h-8 w-8 mx-auto mb-2 opacity-50" />
                        <p className="text-sm">No detection data available for this simulation.</p>
                      </div>
                    )}
                  </TabsContent>

                  {/* RECOMMENDATIONS TAB */}
                  <TabsContent value="recommendations" className="space-y-4 mt-0">
                    {results.fullRecommendations.length > 0 ? (
                      results.fullRecommendations.map((rec: any, i: number) => (
                        <Card key={i} className="overflow-hidden">
                          <div className={`h-1 ${
                            rec.priority === "critical" ? "bg-red-500" :
                            rec.priority === "high" ? "bg-orange-500" :
                            rec.priority === "medium" ? "bg-yellow-500" : "bg-blue-500"
                          }`} />
                          <CardContent className="p-4">
                            <div className="flex items-start justify-between gap-3">
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 mb-1.5">
                                  <Lightbulb className="h-3.5 w-3.5 text-amber-500 flex-shrink-0" />
                                  <h4 className="text-sm font-medium">{rec.title}</h4>
                                </div>
                                <p className="text-xs text-muted-foreground leading-relaxed">{rec.description}</p>
                              </div>
                              <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
                                <Badge variant="outline" className={`text-[10px] ${priorityColors[rec.priority] || ""}`}>
                                  {rec.priority}
                                </Badge>
                                <Badge variant="outline" className="text-[10px]">
                                  {rec.type}
                                </Badge>
                              </div>
                            </div>
                            {(rec.effort || rec.impact) && (
                              <div className="flex items-center gap-3 mt-3 pt-2.5 border-t text-[10px] text-muted-foreground">
                                {rec.effort && (
                                  <span className="flex items-center gap-1">
                                    <Timer className="h-3 w-3" />
                                    Effort: <span className="capitalize font-medium">{rec.effort}</span>
                                  </span>
                                )}
                                {rec.impact && (
                                  <span className="flex items-center gap-1">
                                    <TrendingUp className="h-3 w-3" />
                                    Impact: <span className="capitalize font-medium">{rec.impact}</span>
                                  </span>
                                )}
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      ))
                    ) : results.recommendations.length > 0 ? (
                      results.recommendations.map((rec: any, i: number) => (
                        <Card key={i}>
                          <CardContent className="p-4 flex items-start gap-2.5">
                            <Lightbulb className="h-3.5 w-3.5 text-amber-500 mt-0.5 flex-shrink-0" />
                            <p className="text-xs text-muted-foreground">{typeof rec === 'string' ? rec : rec.title || rec.description || JSON.stringify(rec)}</p>
                          </CardContent>
                        </Card>
                      ))
                    ) : (
                      <div className="text-center py-8 text-muted-foreground">
                        <Lightbulb className="h-8 w-8 mx-auto mb-2 opacity-50" />
                        <p className="text-sm">No recommendations generated for this simulation.</p>
                      </div>
                    )}
                  </TabsContent>
                </Tabs>
              </div>
            );
          })()}
        </DialogContent>
      </Dialog>
    </div>
  );
}
