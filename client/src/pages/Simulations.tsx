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
import { Swords, Play, Trash2, Eye, Clock, CheckCircle2, XCircle, Loader2, Shield, Skull, Zap, Lock, Radio, Globe, Cloud, HardDrive, UserX, FileKey, ChevronDown, Settings2 } from "lucide-react";
import { format } from "date-fns";
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
      summary: results.summary,
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
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Zap className="h-5 w-5 text-purple-500" />
              Simulation Results
            </DialogTitle>
            <DialogDescription>{selectedSimulation?.name}</DialogDescription>
          </DialogHeader>
          {selectedSimulation && (() => {
            const results = getSimulationResults(selectedSimulation);
            if (!results) return <p>No results available</p>;
            return (
              <div className="space-y-6">
                {results.summary && (
                  <div className="p-4 bg-muted/50 rounded-lg">
                    <p className="text-sm">{results.summary}</p>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-4">
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Skull className="h-4 w-4 text-red-500" />
                        Attacker Performance
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-3xl font-bold text-red-500">{Math.round(results.attackerSuccesses)}%</div>
                      <p className="text-xs text-muted-foreground">successful attack techniques</p>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Shield className="h-4 w-4 text-green-500" />
                        Defender Performance
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-3xl font-bold text-green-500">{Math.round(results.defenderBlocks)}%</div>
                      <p className="text-xs text-muted-foreground">attacks detected/blocked</p>
                    </CardContent>
                  </Card>
                </div>

                {results.attackPath.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Attack Path Used</h4>
                    <div className="flex flex-wrap gap-2">
                      {results.attackPath.map((step: string, i: number) => (
                        <Badge key={i} variant="secondary" className="text-xs">{step}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {results.detectionPoints.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Detection Points</h4>
                    <div className="flex flex-wrap gap-2">
                      {results.detectionPoints.map((point: string, i: number) => (
                        <Badge key={i} variant="outline" className="text-xs text-green-600 border-green-600">{point}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {results.missedAttacks.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Gaps Identified</h4>
                    <div className="flex flex-wrap gap-2">
                      {results.missedAttacks.map((gap: string, i: number) => (
                        <Badge key={i} variant="outline" className="text-xs text-red-600 border-red-600">{gap}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {results.recommendations.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Purple Team Recommendations</h4>
                    <ul className="list-disc list-inside text-sm text-muted-foreground space-y-1">
                      {results.recommendations.map((rec: any, i: number) => (
                        <li key={i}>{typeof rec === 'string' ? rec : rec.title || rec.description || JSON.stringify(rec)}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            );
          })()}
        </DialogContent>
      </Dialog>
    </div>
  );
}
