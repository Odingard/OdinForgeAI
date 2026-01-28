import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useAuth } from "@/contexts/AuthContext";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { formatDistanceToNow } from "date-fns";
import { 
  Server, 
  Activity, 
  AlertTriangle, 
  Trash2, 
  Plus, 
  Copy, 
  CheckCircle2, 
  XCircle,
  MonitorSmartphone,
  Wifi,
  WifiOff,
  Eye,
  Shield,
  Cpu,
  HardDrive,
  MemoryStick,
  RefreshCw,
  Monitor,
  Download,
  Clock,
  Loader2,
  RotateCcw
} from "lucide-react";
import { InstallWizard } from "@/components/InstallWizard";
import { CoverageAutopilot } from "@/components/CoverageAutopilot";
import { Progress } from "@/components/ui/progress";

interface EndpointAgent {
  id: string;
  agentName: string;
  hostname: string | null;
  platform: string | null;
  platformVersion: string | null;
  architecture: string | null;
  ipAddresses: string[] | null;
  status: string;
  lastHeartbeat: string | null;
  lastTelemetry: string | null;
  environment: string | null;
  tags: string[] | null;
  registeredAt: string;
}

interface AgentFinding {
  id: string;
  agentId: string;
  findingType: string;
  severity: string;
  title: string;
  description: string | null;
  affectedComponent: string | null;
  status: string;
  detectedAt: string;
  aevEvaluationId: string | null;
  autoEvaluationTriggered: boolean;
  llmValidation: {
    verdict: string;
    confidence: number;
    reason: string;
    missingEvidence: string[] | null;
  } | null;
  llmValidationVerdict: string | null;
}

interface AgentStats {
  totalAgents: number;
  onlineAgents: number;
  offlineAgents: number;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  newFindings: number;
}

interface ResourceMetrics {
  cpuPercent?: number;
  memoryPercent?: number;
  memoryUsedMB?: number;
  memoryTotalMB?: number;
  diskPercent?: number;
  diskUsedGB?: number;
  diskTotalGB?: number;
}

interface SystemInfo {
  hostname?: string;
  os?: string;
  osVersion?: string;
  arch?: string;
  kernelVersion?: string;
  uptime?: number;
}

interface AgentTelemetry {
  id: string;
  agentId: string;
  systemInfo: SystemInfo | null;
  resourceMetrics: ResourceMetrics | null;
  services: any[] | null;
  openPorts: any[] | null;
  networkConnections: any[] | null;
  collectedAt: string;
}

interface StaleAgent {
  id: string;
  agentName: string;
  hostname: string | null;
  platform: string | null;
  status: string | null;
  lastHeartbeat: string | null;
  createdAt: string;
  registeredAt: string | null;
  reason: string;
}

interface StaleDeploymentJob {
  id: string;
  cloudAssetId: string;
  status: string | null;
  deploymentMethod: string;
  createdAt: string;
  updatedAt: string;
  errorMessage: string | null;
  reason: string;
}

interface StaleResourcesSummary {
  staleAgents: StaleAgent[];
  staleDeploymentJobs: StaleDeploymentJob[];
  expiredTokens: number;
}

export default function Agents() {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  
  const canManageAgent = hasPermission("agents:manage");
  const canDeleteAgent = hasPermission("agents:delete");
  
  const [selectedAgent, setSelectedAgent] = useState<EndpointAgent | null>(null);
  const [telemetryAgentId, setTelemetryAgentId] = useState<string | null>(null);
  const [downloadDialogOpen, setDownloadDialogOpen] = useState(false);
  const [cleanupDialogOpen, setCleanupDialogOpen] = useState(false);
  const [staleResourcesDialogOpen, setStaleResourcesDialogOpen] = useState(false);
  const [cleanupHours, setCleanupHours] = useState("24");
  const [includeNoise, setIncludeNoise] = useState(false);

  const { data: agents = [], isLoading: agentsLoading } = useQuery<EndpointAgent[]>({
    queryKey: ["/api/agents"],
  });

  const { data: stats } = useQuery<AgentStats>({
    queryKey: ["/api/agents/stats/summary"],
  });

  const { data: findings = [] } = useQuery<AgentFinding[]>({
    queryKey: [`/api/agent-findings?includeNoise=${includeNoise}`],
  });

  // Fetch auto-cleanup settings
  interface AutoCleanupConfig {
    enabled: boolean;
    intervalHours: number;
    maxAgeHours: number;
    lastRun: string | null;
    nextRun: string | null;
    deletedCount: number;
  }
  const { data: autoCleanupConfig, refetch: refetchAutoCleanup } = useQuery<AutoCleanupConfig>({
    queryKey: ["/api/agents/auto-cleanup"],
  });

  // Query telemetry for a specific agent when selected, auto-refresh every 30s
  const { data: agentTelemetry, isLoading: telemetryLoading, refetch: refetchTelemetry } = useQuery<AgentTelemetry[]>({
    queryKey: [`/api/agents/${telemetryAgentId}/telemetry`],
    enabled: !!telemetryAgentId,
    refetchInterval: 30000,
  });

  // Get the latest telemetry entry
  const latestTelemetry = agentTelemetry?.[0] || null;
  const selectedTelemetryAgent = agents.find(a => a.id === telemetryAgentId);

  const deleteAgentMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/agents/${id}`);
    },
    onSuccess: () => {
      toast({
        title: "Agent Deleted",
        description: "The agent has been removed.",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/agents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agents/stats/summary"] });
    },
  });

  const cleanupStaleAgentsMutation = useMutation({
    mutationFn: async (maxAgeHours: number = 24) => {
      const response = await apiRequest("POST", "/api/agents/cleanup", { maxAgeHours });
      return response.json();
    },
    onSuccess: (data: { deleted: number; agents: string[]; message: string }) => {
      toast({
        title: "Cleanup Complete",
        description: data.message,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/agents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agents/stats/summary"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Cleanup Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // Stale resources query
  const { data: staleResources, isLoading: staleResourcesLoading, refetch: refetchStaleResources } = useQuery<StaleResourcesSummary>({
    queryKey: ["/api/agents/stale-resources"],
    enabled: staleResourcesDialogOpen,
  });

  // Cleanup all stale resources
  const cleanupAllStaleResourcesMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/agents/stale-resources/cleanup", {
        cleanAgents: true,
        cleanDeploymentJobs: true,
        cleanExpiredTokens: true,
      });
      return response.json();
    },
    onSuccess: (data: { deletedAgents: number; deletedDeploymentJobs: number; deletedTokens: number }) => {
      toast({
        title: "Cleanup Complete",
        description: `Removed ${data.deletedAgents} stale agents, ${data.deletedDeploymentJobs} stuck deployments, ${data.deletedTokens} expired tokens`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/agents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agents/stats/summary"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agents/stale-resources"] });
      setStaleResourcesDialogOpen(false);
    },
    onError: (error: Error) => {
      toast({
        title: "Cleanup Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  // Delete single stale agent
  const deleteStaleAgentMutation = useMutation({
    mutationFn: async (agentId: string) => {
      await apiRequest("DELETE", `/api/agents/stale-resources/agent/${agentId}`);
    },
    onSuccess: () => {
      toast({ title: "Agent Deleted" });
      queryClient.invalidateQueries({ queryKey: ["/api/agents/stale-resources"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agents"] });
    },
  });

  const forceCheckinMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await apiRequest("POST", `/api/agents/${id}/force-checkin`);
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Command Queued",
        description: "Check-in command queued. Agent will respond within 30 seconds.",
      });
      // Refresh agent data after the agent should have responded
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["/api/agents"] });
        queryClient.invalidateQueries({ queryKey: ["/api/agents/stats/summary"] });
      }, 35000); // Slightly longer than command poll interval
    },
    onError: (error: Error) => {
      toast({
        title: "Check-in Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const updateAutoCleanupMutation = useMutation({
    mutationFn: async (config: { enabled?: boolean; intervalHours?: number; maxAgeHours?: number }) => {
      const response = await apiRequest("POST", "/api/agents/auto-cleanup", config);
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Settings Updated",
        description: data.message,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/agents/auto-cleanup"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Update Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const runCleanupNowMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/agents/auto-cleanup/run-now");
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Cleanup Complete",
        description: data.message,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/agents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agents/stats/summary"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agents/auto-cleanup"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Cleanup Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });


  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied",
      description: "API key copied to clipboard",
    });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical": return "destructive";
      case "high": return "destructive";
      case "medium": return "secondary";
      case "low": return "outline";
      default: return "outline";
    }
  };

  const getStatusIcon = (status: string, lastHeartbeat: string | null) => {
    // Pending = pre-registered but never checked in
    if (status === "pending" || (status !== "online" && !lastHeartbeat)) {
      return <Clock className="h-4 w-4 text-blue-400" />;
    }
    switch (status) {
      case "online": return <Wifi className="h-4 w-4 text-green-500" />;
      case "offline": return <WifiOff className="h-4 w-4 text-muted-foreground" />;
      case "stale": return <WifiOff className="h-4 w-4 text-yellow-500" />;
      default: return <WifiOff className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const getStatusLabel = (status: string, lastHeartbeat: string | null) => {
    // Pending = pre-registered but never checked in
    if (status === "pending" || (status !== "online" && !lastHeartbeat)) {
      return "Awaiting Check-in";
    }
    return status;
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold" data-testid="text-page-title">Endpoint Agents</h1>
          <p className="text-muted-foreground">
            Deploy agents on your infrastructure for live security monitoring
          </p>
        </div>
        <div className="flex gap-2">
          <Dialog open={downloadDialogOpen} onOpenChange={setDownloadDialogOpen}>
            <DialogTrigger asChild>
              <Button 
                variant="default"
                data-testid="btn-install-agent"
              >
                <Download className="h-4 w-4 mr-2" />
                Install Agent
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
              <InstallWizard serverUrl={window.location.origin} />
            </DialogContent>
          </Dialog>
          <Dialog open={cleanupDialogOpen} onOpenChange={setCleanupDialogOpen}>
            <DialogTrigger asChild>
              <Button 
                variant="destructive" 
                disabled={!canDeleteAgent}
                data-testid="btn-cleanup-agents"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Cleanup Stale Agents
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Cleanup Stale Agents</DialogTitle>
                <DialogDescription>
                  Remove agents that haven't checked in for a specified period of time.
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label>Remove agents inactive for more than:</Label>
                  <Select value={cleanupHours} onValueChange={setCleanupHours}>
                    <SelectTrigger data-testid="select-cleanup-hours">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1">1 hour</SelectItem>
                      <SelectItem value="6">6 hours</SelectItem>
                      <SelectItem value="12">12 hours</SelectItem>
                      <SelectItem value="24">24 hours (1 day)</SelectItem>
                      <SelectItem value="48">48 hours (2 days)</SelectItem>
                      <SelectItem value="72">72 hours (3 days)</SelectItem>
                      <SelectItem value="168">168 hours (1 week)</SelectItem>
                      <SelectItem value="720">720 hours (30 days)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {stats && (
                  <Alert>
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription>
                      Currently {stats.offlineAgents} agent(s) are offline. This action cannot be undone.
                    </AlertDescription>
                  </Alert>
                )}
                <div className="flex gap-2 justify-end">
                  <Button 
                    variant="outline" 
                    onClick={() => setCleanupDialogOpen(false)}
                    data-testid="btn-cancel-cleanup"
                  >
                    Cancel
                  </Button>
                  <Button 
                    variant="destructive"
                    onClick={() => {
                      cleanupStaleAgentsMutation.mutate(parseInt(cleanupHours));
                      setCleanupDialogOpen(false);
                    }}
                    disabled={cleanupStaleAgentsMutation.isPending}
                    data-testid="btn-confirm-cleanup"
                  >
                    {cleanupStaleAgentsMutation.isPending ? (
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    ) : (
                      <Trash2 className="h-4 w-4 mr-2" />
                    )}
                    Delete Stale Agents
                  </Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Agents</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-total-agents">
              {stats?.totalAgents ?? 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Online</CardTitle>
            <Activity className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600" data-testid="text-online-agents">
              {stats?.onlineAgents ?? 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Findings</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600" data-testid="text-critical-findings">
              {stats?.criticalFindings ?? 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">New Findings</CardTitle>
            <MonitorSmartphone className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="text-new-findings">
              {stats?.newFindings ?? 0}
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="agents" className="space-y-4">
        <TabsList>
          <TabsTrigger value="agents" data-testid="tab-agents">Agents</TabsTrigger>
          <TabsTrigger value="coverage" data-testid="tab-coverage">Coverage Autopilot</TabsTrigger>
          <TabsTrigger value="findings" data-testid="tab-findings">Findings</TabsTrigger>
          <TabsTrigger value="system" data-testid="tab-system">System</TabsTrigger>
          <TabsTrigger value="settings" data-testid="tab-settings">Settings</TabsTrigger>
        </TabsList>

        <TabsContent value="agents" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0">
              <div>
                <CardTitle>Connected Agents</CardTitle>
                <CardDescription>
                  Endpoint agents reporting telemetry to OdinForge
                </CardDescription>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setStaleResourcesDialogOpen(true)}
                data-testid="btn-stale-resources"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Cleanup Stale
              </Button>
            </CardHeader>
            <CardContent>
              {agentsLoading ? (
                <div className="text-center py-8 text-muted-foreground">Loading agents...</div>
              ) : agents.length === 0 ? (
                <div className="text-center py-8">
                  <Server className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <h3 className="font-medium mb-2">No Agents Installed</h3>
                  <p className="text-muted-foreground text-sm mb-4">
                    Install an agent to start collecting live security data
                  </p>
                  <Button onClick={() => setDownloadDialogOpen(true)} data-testid="btn-install-first-agent">
                    <Download className="h-4 w-4 mr-2" />
                    Install First Agent
                  </Button>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Status</TableHead>
                      <TableHead>Name</TableHead>
                      <TableHead>Hostname</TableHead>
                      <TableHead>Platform</TableHead>
                      <TableHead>Environment</TableHead>
                      <TableHead>Last Seen</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {agents.map((agent) => (
                      <TableRow key={agent.id} data-testid={`row-agent-${agent.id}`}>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            {getStatusIcon(agent.status, agent.lastHeartbeat)}
                            <span className="capitalize text-sm">{getStatusLabel(agent.status, agent.lastHeartbeat)}</span>
                          </div>
                        </TableCell>
                        <TableCell className="font-medium">{agent.agentName}</TableCell>
                        <TableCell>{agent.hostname || "-"}</TableCell>
                        <TableCell className="capitalize">{agent.platform || "-"}</TableCell>
                        <TableCell>
                          {agent.environment && (
                            <Badge variant="outline" className="capitalize">
                              {agent.environment}
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          {agent.lastHeartbeat
                            ? formatDistanceToNow(new Date(agent.lastHeartbeat), { addSuffix: true })
                            : "Never"}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => forceCheckinMutation.mutate(agent.id)}
                              disabled={forceCheckinMutation.isPending}
                              title="Force agent to check in with latest data"
                              data-testid={`btn-force-checkin-${agent.id}`}
                            >
                              <RefreshCw className={`h-4 w-4 ${forceCheckinMutation.isPending ? 'animate-spin' : ''}`} />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => setSelectedAgent(agent)}
                              data-testid={`btn-view-agent-${agent.id}`}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                            {canDeleteAgent && (
                              <Button
                                variant="ghost"
                                size="icon"
                                onClick={() => deleteAgentMutation.mutate(agent.id)}
                                data-testid={`btn-delete-agent-${agent.id}`}
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="coverage" className="space-y-4">
          <CoverageAutopilot />
        </TabsContent>

        <TabsContent value="findings" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
              <div>
                <CardTitle>Security Findings</CardTitle>
                <CardDescription>
                  Issues detected by endpoint agents
                </CardDescription>
              </div>
              <div className="flex items-center gap-2">
                <Label htmlFor="include-noise" className="text-sm text-muted-foreground whitespace-nowrap">
                  Show suppressed
                </Label>
                <Switch
                  id="include-noise"
                  checked={includeNoise}
                  onCheckedChange={setIncludeNoise}
                  data-testid="switch-include-noise"
                />
              </div>
            </CardHeader>
            <CardContent>
              {findings.length === 0 ? (
                <div className="text-center py-8">
                  <CheckCircle2 className="h-12 w-12 mx-auto text-green-500 mb-4" />
                  <h3 className="font-medium mb-2">No Findings Yet</h3>
                  <p className="text-muted-foreground text-sm">
                    {includeNoise 
                      ? "No findings detected by agents" 
                      : "No actionable findings detected (suppressed findings hidden)"}
                  </p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Severity</TableHead>
                      <TableHead>Verdict</TableHead>
                      <TableHead>Title</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Component</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Detected</TableHead>
                      <TableHead>Auto-Eval</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {findings.map((finding) => (
                      <TableRow 
                        key={finding.id} 
                        data-testid={`row-finding-${finding.id}`}
                        className={finding.llmValidationVerdict === "noise" ? "opacity-50" : ""}
                      >
                        <TableCell>
                          <Badge variant={getSeverityColor(finding.severity)}>
                            {finding.severity}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {finding.llmValidationVerdict ? (
                            <Badge 
                              variant={
                                finding.llmValidationVerdict === "confirmed" ? "default" :
                                finding.llmValidationVerdict === "noise" ? "outline" :
                                "secondary"
                              }
                              className={
                                finding.llmValidationVerdict === "confirmed" ? "bg-green-600 text-white" :
                                finding.llmValidationVerdict === "noise" ? "text-muted-foreground" :
                                ""
                              }
                            >
                              {finding.llmValidationVerdict}
                            </Badge>
                          ) : (
                            <span className="text-muted-foreground text-sm">-</span>
                          )}
                        </TableCell>
                        <TableCell className="font-medium max-w-xs truncate">
                          {finding.title}
                        </TableCell>
                        <TableCell className="capitalize">
                          {finding.findingType.replace(/_/g, " ")}
                        </TableCell>
                        <TableCell>{finding.affectedComponent || "-"}</TableCell>
                        <TableCell className="capitalize">{finding.status}</TableCell>
                        <TableCell>
                          {formatDistanceToNow(new Date(finding.detectedAt), { addSuffix: true })}
                        </TableCell>
                        <TableCell>
                          {finding.autoEvaluationTriggered ? (
                            <CheckCircle2 className="h-4 w-4 text-green-500" />
                          ) : (
                            <XCircle className="h-4 w-4 text-muted-foreground" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="system" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
              <div>
                <CardTitle>Live System Telemetry</CardTitle>
                <CardDescription>
                  Real-time resource metrics from endpoint agents
                </CardDescription>
              </div>
              <div className="flex items-center gap-2">
                <Select
                  value={telemetryAgentId || ""}
                  onValueChange={(value) => setTelemetryAgentId(value || null)}
                >
                  <SelectTrigger className="w-[200px]" data-testid="select-telemetry-agent">
                    <SelectValue placeholder="Select an agent" />
                  </SelectTrigger>
                  <SelectContent>
                    {agents.filter(a => a.status === "online").map((agent) => (
                      <SelectItem key={agent.id} value={agent.id}>
                        {agent.agentName}
                      </SelectItem>
                    ))}
                    {agents.filter(a => a.status !== "online").map((agent) => (
                      <SelectItem key={agent.id} value={agent.id}>
                        {agent.agentName} (offline)
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {telemetryAgentId && (
                  <Button
                    variant="outline"
                    size="icon"
                    onClick={() => refetchTelemetry()}
                    data-testid="btn-refresh-telemetry"
                  >
                    <RefreshCw className="h-4 w-4" />
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {!telemetryAgentId ? (
                <div className="text-center py-8">
                  <Monitor className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <h3 className="font-medium mb-2">Select an Agent</h3>
                  <p className="text-muted-foreground text-sm">
                    Choose an agent from the dropdown to view live telemetry data
                  </p>
                </div>
              ) : telemetryLoading ? (
                <div className="text-center py-8 text-muted-foreground">Loading telemetry...</div>
              ) : !latestTelemetry ? (
                <div className="text-center py-8">
                  <Activity className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <h3 className="font-medium mb-2">No Telemetry Data</h3>
                  <p className="text-muted-foreground text-sm">
                    This agent hasn't reported any telemetry yet
                  </p>
                </div>
              ) : (
                <div className="space-y-6">
                  {/* Agent Info Header */}
                  <div className="flex items-center justify-between border-b pb-4">
                    <div className="flex items-center gap-3">
                      <Server className="h-5 w-5 text-muted-foreground" />
                      <div>
                        <p className="font-medium">{selectedTelemetryAgent?.agentName}</p>
                        <p className="text-sm text-muted-foreground font-mono">
                          {latestTelemetry.systemInfo?.hostname || selectedTelemetryAgent?.hostname || "Unknown host"}
                        </p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-muted-foreground">Last Updated</p>
                      <p className="text-sm">
                        {formatDistanceToNow(new Date(latestTelemetry.collectedAt), { addSuffix: true })}
                      </p>
                    </div>
                  </div>

                  {/* System Info */}
                  {latestTelemetry.systemInfo && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <p className="text-xs text-muted-foreground">OS</p>
                        <p className="font-mono">{latestTelemetry.systemInfo.os || "-"}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Version</p>
                        <p className="font-mono">{latestTelemetry.systemInfo.osVersion || "-"}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Architecture</p>
                        <p className="font-mono">{latestTelemetry.systemInfo.arch || "-"}</p>
                      </div>
                      <div>
                        <p className="text-xs text-muted-foreground">Kernel</p>
                        <p className="font-mono">{latestTelemetry.systemInfo.kernelVersion || "-"}</p>
                      </div>
                    </div>
                  )}

                  {/* Resource Metrics */}
                  {latestTelemetry.resourceMetrics && (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      {/* CPU */}
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Cpu className="h-4 w-4 text-blue-500" />
                            <span className="text-sm font-medium">CPU Usage</span>
                          </div>
                          <span className="text-sm font-mono">
                            {latestTelemetry.resourceMetrics.cpuPercent?.toFixed(1) ?? "0"}%
                          </span>
                        </div>
                        <Progress 
                          value={latestTelemetry.resourceMetrics.cpuPercent ?? 0} 
                          className="h-2"
                          data-testid="progress-cpu"
                        />
                      </div>

                      {/* Memory */}
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <MemoryStick className="h-4 w-4 text-green-500" />
                            <span className="text-sm font-medium">Memory Usage</span>
                          </div>
                          <span className="text-sm font-mono">
                            {latestTelemetry.resourceMetrics.memoryPercent?.toFixed(1) ?? "0"}%
                          </span>
                        </div>
                        <Progress 
                          value={latestTelemetry.resourceMetrics.memoryPercent ?? 0} 
                          className="h-2"
                          data-testid="progress-memory"
                        />
                        {latestTelemetry.resourceMetrics.memoryUsedMB != null && latestTelemetry.resourceMetrics.memoryTotalMB != null && (
                          <p className="text-xs text-muted-foreground">
                            {(latestTelemetry.resourceMetrics.memoryUsedMB / 1024).toFixed(1)} GB / {(latestTelemetry.resourceMetrics.memoryTotalMB / 1024).toFixed(1)} GB
                          </p>
                        )}
                      </div>

                      {/* Disk */}
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <HardDrive className="h-4 w-4 text-amber-500" />
                            <span className="text-sm font-medium">Disk Usage</span>
                          </div>
                          <span className="text-sm font-mono">
                            {latestTelemetry.resourceMetrics.diskPercent?.toFixed(1) ?? "0"}%
                          </span>
                        </div>
                        <Progress 
                          value={latestTelemetry.resourceMetrics.diskPercent ?? 0} 
                          className="h-2"
                          data-testid="progress-disk"
                        />
                        {latestTelemetry.resourceMetrics.diskUsedGB != null && latestTelemetry.resourceMetrics.diskTotalGB != null && (
                          <p className="text-xs text-muted-foreground">
                            {latestTelemetry.resourceMetrics.diskUsedGB.toFixed(1)} GB / {latestTelemetry.resourceMetrics.diskTotalGB.toFixed(1)} GB
                          </p>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Services and Ports Summary */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t">
                    <div>
                      <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                        <Activity className="h-4 w-4" />
                        Running Services
                      </h4>
                      {latestTelemetry.services && latestTelemetry.services.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {latestTelemetry.services.slice(0, 10).map((service: any, i: number) => (
                            <Badge key={i} variant="secondary" className="text-xs">
                              {typeof service === "string" ? service : service.name || "Unknown"}
                            </Badge>
                          ))}
                          {latestTelemetry.services.length > 10 && (
                            <Badge variant="outline" className="text-xs">
                              +{latestTelemetry.services.length - 10} more
                            </Badge>
                          )}
                        </div>
                      ) : (
                        <p className="text-sm text-muted-foreground">No services reported</p>
                      )}
                    </div>
                    <div>
                      <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                        <Shield className="h-4 w-4" />
                        Open Ports
                      </h4>
                      {latestTelemetry.openPorts && latestTelemetry.openPorts.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {latestTelemetry.openPorts.slice(0, 12).map((port: any, i: number) => (
                            <Badge key={i} variant="outline" className="text-xs font-mono">
                              {typeof port === "number" ? port : port.port || port}
                            </Badge>
                          ))}
                          {latestTelemetry.openPorts.length > 12 && (
                            <Badge variant="outline" className="text-xs">
                              +{latestTelemetry.openPorts.length - 12} more
                            </Badge>
                          )}
                        </div>
                      ) : (
                        <p className="text-sm text-muted-foreground">No open ports reported</p>
                      )}
                    </div>
                  </div>

                  {/* Network Connections */}
                  {latestTelemetry.networkConnections && latestTelemetry.networkConnections.length > 0 && (
                    <div className="pt-4 border-t">
                      <h4 className="text-sm font-medium mb-2">Active Network Connections</h4>
                      <p className="text-sm text-muted-foreground">
                        {latestTelemetry.networkConnections.length} active connections detected
                      </p>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="settings" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Trash2 className="h-5 w-5" />
                Automatic Stale Agent Cleanup
              </CardTitle>
              <CardDescription>
                Automatically remove agents that haven't checked in for a specified period
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between gap-4 p-4 border rounded-md">
                <div className="space-y-1">
                  <Label className="text-base font-medium">Enable Automatic Cleanup</Label>
                  <p className="text-sm text-muted-foreground">
                    When enabled, stale agents will be automatically removed on a schedule
                  </p>
                </div>
                <Button
                  variant={autoCleanupConfig?.enabled ? "default" : "outline"}
                  onClick={() => updateAutoCleanupMutation.mutate({ enabled: !autoCleanupConfig?.enabled })}
                  disabled={updateAutoCleanupMutation.isPending || !canDeleteAgent}
                  data-testid="btn-toggle-auto-cleanup"
                >
                  {autoCleanupConfig?.enabled ? "Enabled" : "Disabled"}
                </Button>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>Run cleanup every:</Label>
                  <Select 
                    value={String(autoCleanupConfig?.intervalHours || 24)} 
                    onValueChange={(val) => updateAutoCleanupMutation.mutate({ intervalHours: parseInt(val) })}
                    disabled={updateAutoCleanupMutation.isPending || !canDeleteAgent}
                  >
                    <SelectTrigger data-testid="select-auto-interval">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1">Every 1 hour</SelectItem>
                      <SelectItem value="6">Every 6 hours</SelectItem>
                      <SelectItem value="12">Every 12 hours</SelectItem>
                      <SelectItem value="24">Every 24 hours</SelectItem>
                      <SelectItem value="48">Every 48 hours</SelectItem>
                      <SelectItem value="168">Every week</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label>Remove agents inactive for more than:</Label>
                  <Select 
                    value={String(autoCleanupConfig?.maxAgeHours || 72)} 
                    onValueChange={(val) => updateAutoCleanupMutation.mutate({ maxAgeHours: parseInt(val) })}
                    disabled={updateAutoCleanupMutation.isPending || !canDeleteAgent}
                  >
                    <SelectTrigger data-testid="select-auto-max-age">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1">1 hour</SelectItem>
                      <SelectItem value="6">6 hours</SelectItem>
                      <SelectItem value="24">24 hours (1 day)</SelectItem>
                      <SelectItem value="48">48 hours (2 days)</SelectItem>
                      <SelectItem value="72">72 hours (3 days)</SelectItem>
                      <SelectItem value="168">168 hours (1 week)</SelectItem>
                      <SelectItem value="720">720 hours (30 days)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {autoCleanupConfig && (
                <div className="p-4 bg-muted rounded-md space-y-2">
                  <h4 className="font-medium flex items-center gap-2">
                    <Clock className="h-4 w-4" />
                    Status
                  </h4>
                  <div className="grid gap-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Status:</span>
                      <Badge variant={autoCleanupConfig.enabled ? "default" : "secondary"}>
                        {autoCleanupConfig.enabled ? "Active" : "Disabled"}
                      </Badge>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Last run:</span>
                      <span>{autoCleanupConfig.lastRun ? formatDistanceToNow(new Date(autoCleanupConfig.lastRun), { addSuffix: true }) : "Never"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Next scheduled run:</span>
                      <span>{autoCleanupConfig.nextRun && autoCleanupConfig.enabled ? formatDistanceToNow(new Date(autoCleanupConfig.nextRun), { addSuffix: true }) : "N/A"}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Total agents cleaned:</span>
                      <span>{autoCleanupConfig.deletedCount}</span>
                    </div>
                  </div>
                </div>
              )}

              <div className="flex gap-2">
                <Button
                  variant="destructive"
                  onClick={() => runCleanupNowMutation.mutate()}
                  disabled={runCleanupNowMutation.isPending || !canDeleteAgent}
                  data-testid="btn-run-cleanup-now"
                >
                  {runCleanupNowMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Trash2 className="h-4 w-4 mr-2" />
                  )}
                  Run Cleanup Now
                </Button>
                <p className="text-sm text-muted-foreground self-center">
                  Immediately delete agents inactive for {autoCleanupConfig?.maxAgeHours || 72} hours
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Agent Details Dialog */}
      <Dialog open={selectedAgent !== null} onOpenChange={(open) => !open && setSelectedAgent(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Server className="h-5 w-5" />
              {selectedAgent?.agentName}
            </DialogTitle>
            <DialogDescription>
              Agent details and system information
            </DialogDescription>
          </DialogHeader>
          {selectedAgent && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Status</Label>
                  <div className="flex items-center gap-2">
                    {getStatusIcon(selectedAgent.status, selectedAgent.lastHeartbeat)}
                    <span className="capitalize font-medium">{getStatusLabel(selectedAgent.status, selectedAgent.lastHeartbeat)}</span>
                  </div>
                </div>
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Environment</Label>
                  <div>
                    <Badge variant="outline" className="capitalize">
                      {selectedAgent.environment || "Unknown"}
                    </Badge>
                  </div>
                </div>
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Hostname</Label>
                  <p className="font-mono text-sm">{selectedAgent.hostname || "-"}</p>
                </div>
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Platform</Label>
                  <p className="font-mono text-sm capitalize">
                    {selectedAgent.platform || "-"} {selectedAgent.platformVersion || ""}
                  </p>
                </div>
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Architecture</Label>
                  <p className="font-mono text-sm">{selectedAgent.architecture || "-"}</p>
                </div>
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Registered</Label>
                  <p className="text-sm">
                    {formatDistanceToNow(new Date(selectedAgent.registeredAt), { addSuffix: true })}
                  </p>
                </div>
                <div className="space-y-1 col-span-2">
                  <Label className="text-xs text-muted-foreground">IP Addresses</Label>
                  <div className="flex flex-wrap gap-1">
                    {selectedAgent.ipAddresses && selectedAgent.ipAddresses.length > 0 ? (
                      selectedAgent.ipAddresses.map((ip, i) => (
                        <Badge key={i} variant="secondary" className="font-mono text-xs">
                          {ip}
                        </Badge>
                      ))
                    ) : (
                      <span className="text-sm text-muted-foreground">No IP addresses reported</span>
                    )}
                  </div>
                </div>
                <div className="space-y-1 col-span-2">
                  <Label className="text-xs text-muted-foreground">Tags</Label>
                  <div className="flex flex-wrap gap-1">
                    {selectedAgent.tags && selectedAgent.tags.length > 0 ? (
                      selectedAgent.tags.map((tag, i) => (
                        <Badge key={i} variant="outline" className="text-xs">
                          {tag}
                        </Badge>
                      ))
                    ) : (
                      <span className="text-sm text-muted-foreground">No tags</span>
                    )}
                  </div>
                </div>
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Last Heartbeat</Label>
                  <p className="text-sm">
                    {selectedAgent.lastHeartbeat
                      ? formatDistanceToNow(new Date(selectedAgent.lastHeartbeat), { addSuffix: true })
                      : "Never"}
                  </p>
                </div>
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Last Telemetry</Label>
                  <p className="text-sm">
                    {selectedAgent.lastTelemetry
                      ? formatDistanceToNow(new Date(selectedAgent.lastTelemetry), { addSuffix: true })
                      : "Never"}
                  </p>
                </div>
              </div>
              <div className="pt-2 border-t">
                <p className="text-xs text-muted-foreground font-mono">ID: {selectedAgent.id}</p>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Stale Resources Cleanup Dialog */}
      <Dialog open={staleResourcesDialogOpen} onOpenChange={setStaleResourcesDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Stale Resources</DialogTitle>
            <DialogDescription>
              View and clean up stale agents, stuck deployments, and expired tokens
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 max-h-[60vh] overflow-y-auto">
            {staleResourcesLoading ? (
              <div className="text-center py-8 text-muted-foreground">
                <Loader2 className="h-6 w-6 animate-spin mx-auto mb-2" />
                Loading stale resources...
              </div>
            ) : (
              <>
                {/* Stale Agents */}
                <div className="space-y-2">
                  <h4 className="font-medium flex items-center gap-2">
                    <Server className="h-4 w-4" />
                    Stale Agents ({staleResources?.staleAgents?.length || 0})
                  </h4>
                  {staleResources?.staleAgents && staleResources.staleAgents.length > 0 ? (
                    <div className="space-y-2">
                      {staleResources.staleAgents.map((agent) => (
                        <div key={agent.id} className="flex items-center justify-between p-3 rounded-md border bg-card">
                          <div>
                            <p className="font-medium text-sm">{agent.agentName}</p>
                            <p className="text-xs text-muted-foreground">{agent.reason}</p>
                          </div>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => deleteStaleAgentMutation.mutate(agent.id)}
                            disabled={deleteStaleAgentMutation.isPending}
                            data-testid={`btn-delete-stale-agent-${agent.id}`}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground pl-6">No stale agents found</p>
                  )}
                </div>

                {/* Stuck Deployment Jobs */}
                <div className="space-y-2">
                  <h4 className="font-medium flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4" />
                    Stuck Deployments ({staleResources?.staleDeploymentJobs?.length || 0})
                  </h4>
                  {staleResources?.staleDeploymentJobs && staleResources.staleDeploymentJobs.length > 0 ? (
                    <div className="space-y-2">
                      {staleResources.staleDeploymentJobs.map((job) => (
                        <div key={job.id} className="flex items-center justify-between p-3 rounded-md border bg-card">
                          <div>
                            <p className="font-medium text-sm">{job.id}</p>
                            <p className="text-xs text-muted-foreground">
                              {job.reason} - {job.deploymentMethod}
                            </p>
                          </div>
                          <Badge variant="secondary">{job.status}</Badge>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground pl-6">No stuck deployments found</p>
                  )}
                </div>

                {/* Expired Tokens */}
                <div className="space-y-2">
                  <h4 className="font-medium flex items-center gap-2">
                    <Clock className="h-4 w-4" />
                    Expired Tokens
                  </h4>
                  <p className="text-sm text-muted-foreground pl-6">
                    {staleResources?.expiredTokens || 0} expired registration tokens
                  </p>
                </div>
              </>
            )}
          </div>
          <div className="flex justify-between pt-4 border-t">
            <Button
              variant="outline"
              onClick={() => refetchStaleResources()}
              disabled={staleResourcesLoading}
              data-testid="btn-refresh-stale"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
            <Button
              variant="destructive"
              onClick={() => cleanupAllStaleResourcesMutation.mutate()}
              disabled={cleanupAllStaleResourcesMutation.isPending || 
                ((staleResources?.staleAgents?.length || 0) === 0 && 
                 (staleResources?.staleDeploymentJobs?.length || 0) === 0 && 
                 (staleResources?.expiredTokens || 0) === 0)}
              data-testid="btn-cleanup-all-stale"
            >
              {cleanupAllStaleResourcesMutation.isPending ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Trash2 className="h-4 w-4 mr-2" />
              )}
              Clean Up All
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
