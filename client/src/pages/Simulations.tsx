import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
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
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Swords, Play, Trash2, Eye, Clock, CheckCircle2, XCircle, Loader2, Shield, Skull, Zap, Lock, Radio } from "lucide-react";
import { format } from "date-fns";
import type { AiSimulation } from "@shared/schema";

interface LiveScanResult {
  id: number;
  evaluationId: string;
  targetHost: string;
  vulnerabilities: any[];
  ports: any[];
}

export default function Simulations() {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  
  const canRunSimulation = hasPermission("simulations:run");
  const canDeleteSimulation = hasPermission("simulations:delete");
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [selectedSimulation, setSelectedSimulation] = useState<AiSimulation | null>(null);
  const [formData, setFormData] = useState({
    assetId: "",
    exposureType: "cve",
    priority: "high",
    description: "",
    rounds: 3,
    sourceEvaluationId: "",
  });

  const { data: simulations = [], isLoading } = useQuery<AiSimulation[]>({
    queryKey: ["/api/simulations"],
  });

  // Fetch evaluations with live scan data
  const { data: liveScanResults = [] } = useQuery<LiveScanResult[]>({
    queryKey: ["/api/aev/live-scans"],
  });

  const createMutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      // Only include sourceEvaluationId if it's not empty or "none"
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
      attackerSuccesses: results.attackerSuccesses || 0,
      defenderBlocks: results.defenderBlocks || 0,
      attackPath: results.attackPath || [],
      detectionPoints: results.detectionPoints || [],
      missedAttacks: results.missedAttacks || [],
      recommendations: results.recommendations || [],
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
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button data-testid="button-new-simulation" disabled={!canRunSimulation}>
              {canRunSimulation ? <Play className="h-4 w-4 mr-2" /> : <Lock className="h-4 w-4 mr-2" />}
              Start Simulation
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[500px]">
            <DialogHeader>
              <DialogTitle>Start AI vs AI Simulation</DialogTitle>
              <DialogDescription>
                Configure a purple team exercise where attacker and defender AI agents compete
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="assetId">Target Asset ID</Label>
                <Input
                  id="assetId"
                  value={formData.assetId}
                  onChange={(e) => setFormData({ ...formData, assetId: e.target.value })}
                  placeholder="e.g., web-server-001"
                  data-testid="input-simulation-asset"
                />
              </div>
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
                    <SelectItem value="network">Network Exposure</SelectItem>
                    <SelectItem value="api">API Vulnerability</SelectItem>
                    <SelectItem value="iam_abuse">IAM Abuse</SelectItem>
                    <SelectItem value="data_exfiltration">Data Exfiltration</SelectItem>
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
                <Label htmlFor="rounds">Simulation Rounds</Label>
                <Select
                  value={String(formData.rounds)}
                  onValueChange={(v) => setFormData({ ...formData, rounds: parseInt(v) })}
                >
                  <SelectTrigger data-testid="select-simulation-rounds">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1">1 Round</SelectItem>
                    <SelectItem value="2">2 Rounds</SelectItem>
                    <SelectItem value="3">3 Rounds</SelectItem>
                    <SelectItem value="5">5 Rounds</SelectItem>
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
                  rows={3}
                  data-testid="input-simulation-description"
                />
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
                      <SelectValue placeholder="Select a live scan for real network data..." />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none">None (use simulated data)</SelectItem>
                      {liveScanResults.map((scan) => (
                        <SelectItem key={scan.evaluationId} value={scan.evaluationId}>
                          {scan.targetHost} ({scan.ports?.length || 0} ports, {scan.vulnerabilities?.length || 0} vulns)
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    Inject real network scan findings into the simulation for realistic attack scenarios
                  </p>
                  
                  {formData.sourceEvaluationId && formData.sourceEvaluationId !== "none" && (() => {
                    const selectedScan = liveScanResults.find(s => s.evaluationId === formData.sourceEvaluationId);
                    if (!selectedScan) return null;
                    return (
                      <div className="bg-muted/50 rounded-md p-3 space-y-2 border" data-testid="live-scan-preview">
                        <div className="flex items-center gap-2 text-sm font-medium">
                          <Radio className="h-4 w-4 text-green-500" />
                          Live Scan Data Preview: {selectedScan.targetHost}
                        </div>
                        
                        {selectedScan.ports && selectedScan.ports.length > 0 && (
                          <div className="space-y-1">
                            <span className="text-xs text-muted-foreground">Open Ports ({selectedScan.ports.length}):</span>
                            <div className="flex flex-wrap gap-1">
                              {selectedScan.ports.slice(0, 8).map((port: any, i: number) => (
                                <Badge key={i} variant="outline" className="text-xs">
                                  {port.port}/{port.service || 'unknown'}
                                </Badge>
                              ))}
                              {selectedScan.ports.length > 8 && (
                                <Badge variant="secondary" className="text-xs">+{selectedScan.ports.length - 8} more</Badge>
                              )}
                            </div>
                          </div>
                        )}
                        
                        {selectedScan.vulnerabilities && selectedScan.vulnerabilities.length > 0 && (
                          <div className="space-y-1">
                            <span className="text-xs text-muted-foreground">Vulnerabilities ({selectedScan.vulnerabilities.length}):</span>
                            <div className="flex flex-wrap gap-1">
                              {selectedScan.vulnerabilities.slice(0, 5).map((vuln: any, i: number) => (
                                <Badge 
                                  key={i} 
                                  variant="outline" 
                                  className={`text-xs ${
                                    vuln.severity === 'critical' ? 'border-red-500 text-red-500' :
                                    vuln.severity === 'high' ? 'border-orange-500 text-orange-500' :
                                    vuln.severity === 'medium' ? 'border-yellow-500 text-yellow-500' :
                                    'border-blue-500 text-blue-500'
                                  }`}
                                >
                                  {vuln.type || vuln.description?.slice(0, 20) || 'Unknown'}
                                </Badge>
                              ))}
                              {selectedScan.vulnerabilities.length > 5 && (
                                <Badge variant="secondary" className="text-xs">+{selectedScan.vulnerabilities.length - 5} more</Badge>
                              )}
                            </div>
                          </div>
                        )}
                        
                        <p className="text-xs text-green-600">
                          This real network data will be injected into the AI simulation
                        </p>
                      </div>
                    );
                  })()}
                </div>
              )}
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsCreateOpen(false)}>Cancel</Button>
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
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      ) : simulations.length === 0 ? (
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
                          <span className="text-sm font-medium">{results.attackerSuccesses}%</span>
                          <span className="text-xs text-muted-foreground">attack success</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Shield className="h-4 w-4 text-green-500" />
                          <span className="text-sm font-medium">{results.defenderBlocks}%</span>
                          <span className="text-xs text-muted-foreground">defended</span>
                        </div>
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
                <div className="grid grid-cols-2 gap-4">
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm flex items-center gap-2">
                        <Skull className="h-4 w-4 text-red-500" />
                        Attacker Performance
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-3xl font-bold text-red-500">{results.attackerSuccesses}%</div>
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
                      <div className="text-3xl font-bold text-green-500">{results.defenderBlocks}%</div>
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
                      {results.recommendations.map((rec: string, i: number) => (
                        <li key={i}>{rec}</li>
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
