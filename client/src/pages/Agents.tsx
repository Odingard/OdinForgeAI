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
  Terminal,
  Eye,
  Lock,
  Shield,
  Cpu,
  HardDrive,
  MemoryStick,
  RefreshCw,
  Monitor,
  Download,
  Clock,
  Loader2
} from "lucide-react";
import { DownloadCenter } from "@/components/DownloadCenter";
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

export default function Agents() {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  
  const canRegisterAgent = hasPermission("agents:register");
  const canManageAgent = hasPermission("agents:manage");
  const canDeleteAgent = hasPermission("agents:delete");
  
  const [registerDialogOpen, setRegisterDialogOpen] = useState(false);
  const [newAgentName, setNewAgentName] = useState("");
  const [newAgentPlatform, setNewAgentPlatform] = useState("linux");
  const [newAgentEnvironment, setNewAgentEnvironment] = useState("production");
  const [registeredApiKey, setRegisteredApiKey] = useState<string | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<EndpointAgent | null>(null);
  const [scriptDialogOpen, setScriptDialogOpen] = useState(false);
  const [telemetryAgentId, setTelemetryAgentId] = useState<string | null>(null);
  const [downloadDialogOpen, setDownloadDialogOpen] = useState(false);
  const [cleanupDialogOpen, setCleanupDialogOpen] = useState(false);
  const [cleanupHours, setCleanupHours] = useState("24");

  const { data: agents = [], isLoading: agentsLoading } = useQuery<EndpointAgent[]>({
    queryKey: ["/api/agents"],
  });

  const { data: stats } = useQuery<AgentStats>({
    queryKey: ["/api/agents/stats/summary"],
  });

  const { data: findings = [] } = useQuery<AgentFinding[]>({
    queryKey: ["/api/agent-findings"],
  });

  // Fetch registration token for download center
  const { data: tokenData } = useQuery<{ token: string | null }>({
    queryKey: ["/api/agents/registration-token"],
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

  const registerAgentMutation = useMutation({
    mutationFn: async (data: { agentName: string; platform: string; environment: string }) => {
      const response = await apiRequest("POST", "/api/agents/register", data);
      return response.json();
    },
    onSuccess: (data) => {
      setRegisteredApiKey(data.apiKey);
      queryClient.invalidateQueries({ queryKey: ["/api/agents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agents/stats/summary"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Registration Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

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

  const handleRegister = () => {
    if (!newAgentName.trim()) {
      toast({
        title: "Error",
        description: "Agent name is required",
        variant: "destructive",
      });
      return;
    }
    registerAgentMutation.mutate({
      agentName: newAgentName,
      platform: newAgentPlatform,
      environment: newAgentEnvironment,
    });
  };

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

  const goAgentInstructions = `# OdinForge Agent Installation

## Quick Install (Auto-detect environment)
# Download the agent binary for your platform, then run:

sudo ./odinforge-agent install \\
  --server-url ${window.location.origin} \\
  --api-key YOUR_API_KEY_HERE

# Check installation status
./odinforge-agent status

# Uninstall when needed
sudo ./odinforge-agent uninstall

## Manual Configuration (agent.yaml)
server_url: "${window.location.origin}"
api_key: "YOUR_API_KEY_HERE"
telemetry_interval: 60s
batch_size: 100
queue_path: /var/lib/odinforge/queue.db

# Optional mTLS configuration
mtls:
  enabled: false
  cert_path: /etc/odinforge/agent.crt
  key_path: /etc/odinforge/agent.key
  ca_path: /etc/odinforge/ca.crt

## Docker Deployment
docker run -d \\
  --name odinforge-agent \\
  -e ODINFORGE_SERVER_URL=${window.location.origin} \\
  -e ODINFORGE_API_KEY=YOUR_API_KEY_HERE \\
  -v /var/lib/odinforge:/data \\
  odinforge/agent:latest

## Kubernetes DaemonSet
# Apply the manifests from odinforge-agent/deploy/kubernetes/
kubectl create secret generic odinforge-agent \\
  --from-literal=api-key=YOUR_API_KEY_HERE
kubectl apply -f daemonset.yaml

## Supported Platforms
- Linux (systemd service with security hardening)
- macOS (launchd daemon)
- Windows (Windows Service)
- Docker (container with volume persistence)
- Kubernetes (DaemonSet for cluster-wide deployment)

## Features
- Offline resilience with BoltDB queue
- Batched HTTPS transmission
- Optional mTLS and SPKI pinning
- Auto-restart on failure
- Stable agent ID across restarts
`;

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
                data-testid="btn-download-agent"
              >
                <Download className="h-4 w-4 mr-2" />
                Download Agent
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
              <DownloadCenter serverUrl={window.location.origin} registrationToken={tokenData?.token || undefined} />
            </DialogContent>
          </Dialog>
          <Button variant="outline" onClick={() => setScriptDialogOpen(true)} data-testid="btn-view-script">
            <Terminal className="h-4 w-4 mr-2" />
            Installation Guide
          </Button>
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
          <Dialog open={registerDialogOpen} onOpenChange={(open) => {
            setRegisterDialogOpen(open);
            if (!open) {
              setRegisteredApiKey(null);
              setNewAgentName("");
            }
          }}>
            <DialogTrigger asChild>
              <Button data-testid="btn-register-agent" disabled={!canRegisterAgent}>
                {canRegisterAgent ? <Plus className="h-4 w-4 mr-2" /> : <Lock className="h-4 w-4 mr-2" />}
                Register Agent
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Register New Agent</DialogTitle>
                <DialogDescription>
                  Create credentials for a new endpoint agent
                </DialogDescription>
              </DialogHeader>
              
              {registeredApiKey ? (
                <div className="space-y-4">
                  <div className="bg-green-500/10 border border-green-500/20 rounded-md p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                      <span className="font-medium">Agent Registered Successfully</span>
                    </div>
                    <p className="text-sm text-muted-foreground mb-4">
                      Copy the API key below. It will not be shown again.
                    </p>
                    <div className="flex gap-2">
                      <Input 
                        value={registeredApiKey} 
                        readOnly 
                        className="font-mono text-sm"
                        data-testid="input-api-key"
                      />
                      <Button 
                        variant="outline" 
                        size="icon"
                        onClick={() => copyToClipboard(registeredApiKey)}
                        data-testid="btn-copy-api-key"
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  <Button 
                    className="w-full" 
                    onClick={() => {
                      setRegisterDialogOpen(false);
                      setRegisteredApiKey(null);
                      setNewAgentName("");
                    }}
                    data-testid="btn-close-dialog"
                  >
                    Done
                  </Button>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="agentName">Agent Name</Label>
                    <Input
                      id="agentName"
                      placeholder="e.g., prod-webserver-01"
                      value={newAgentName}
                      onChange={(e) => setNewAgentName(e.target.value)}
                      data-testid="input-agent-name"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Platform</Label>
                    <Select value={newAgentPlatform} onValueChange={setNewAgentPlatform}>
                      <SelectTrigger data-testid="select-platform">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="linux">Linux</SelectItem>
                        <SelectItem value="windows">Windows</SelectItem>
                        <SelectItem value="macos">macOS</SelectItem>
                        <SelectItem value="container">Container</SelectItem>
                        <SelectItem value="kubernetes">Kubernetes</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Environment</Label>
                    <Select value={newAgentEnvironment} onValueChange={setNewAgentEnvironment}>
                      <SelectTrigger data-testid="select-environment">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="production">Production</SelectItem>
                        <SelectItem value="staging">Staging</SelectItem>
                        <SelectItem value="development">Development</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <Button 
                    className="w-full" 
                    onClick={handleRegister}
                    disabled={registerAgentMutation.isPending}
                    data-testid="btn-submit-register"
                  >
                    {registerAgentMutation.isPending ? "Registering..." : "Register Agent"}
                  </Button>
                </div>
              )}
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
          <TabsTrigger value="findings" data-testid="tab-findings">Findings</TabsTrigger>
          <TabsTrigger value="system" data-testid="tab-system">System</TabsTrigger>
          <TabsTrigger value="settings" data-testid="tab-settings">Settings</TabsTrigger>
        </TabsList>

        <TabsContent value="agents" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Connected Agents</CardTitle>
              <CardDescription>
                Endpoint agents reporting telemetry to OdinForge
              </CardDescription>
            </CardHeader>
            <CardContent>
              {agentsLoading ? (
                <div className="text-center py-8 text-muted-foreground">Loading agents...</div>
              ) : agents.length === 0 ? (
                <div className="text-center py-8">
                  <Server className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <h3 className="font-medium mb-2">No Agents Registered</h3>
                  <p className="text-muted-foreground text-sm mb-4">
                    Register an agent to start collecting live security data
                  </p>
                  <Button onClick={() => setRegisterDialogOpen(true)} data-testid="btn-register-first-agent">
                    <Plus className="h-4 w-4 mr-2" />
                    Register First Agent
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

        <TabsContent value="findings" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Security Findings</CardTitle>
              <CardDescription>
                Issues detected by endpoint agents
              </CardDescription>
            </CardHeader>
            <CardContent>
              {findings.length === 0 ? (
                <div className="text-center py-8">
                  <CheckCircle2 className="h-12 w-12 mx-auto text-green-500 mb-4" />
                  <h3 className="font-medium mb-2">No Findings Yet</h3>
                  <p className="text-muted-foreground text-sm">
                    Agent findings will appear here when detected
                  </p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Severity</TableHead>
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
                      <TableRow key={finding.id} data-testid={`row-finding-${finding.id}`}>
                        <TableCell>
                          <Badge variant={getSeverityColor(finding.severity)}>
                            {finding.severity}
                          </Badge>
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

      <Dialog open={scriptDialogOpen} onOpenChange={setScriptDialogOpen}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-hidden flex flex-col">
          <DialogHeader>
            <DialogTitle>OdinForge Agent Installation</DialogTitle>
            <DialogDescription>
              Deploy the Go agent on your endpoints for live security monitoring
            </DialogDescription>
          </DialogHeader>
          <div className="flex-1 overflow-auto">
            <div className="relative">
              <Button
                variant="outline"
                size="sm"
                className="absolute right-2 top-2"
                onClick={() => {
                  navigator.clipboard.writeText(goAgentInstructions);
                  toast({ title: "Copied", description: "Instructions copied to clipboard" });
                }}
                data-testid="btn-copy-script"
              >
                <Copy className="h-4 w-4 mr-2" />
                Copy
              </Button>
              <pre className="bg-muted p-4 rounded-lg overflow-auto text-xs font-mono">
                {goAgentInstructions}
              </pre>
            </div>
          </div>
          <div className="pt-4 border-t">
            <h4 className="font-medium mb-2">Quick Start:</h4>
            <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
              <li>Register an agent above to get an API key</li>
              <li>Download the agent binary for your platform</li>
              <li>Run: sudo ./odinforge-agent install --server-url URL --api-key KEY</li>
              <li>Check status: ./odinforge-agent status</li>
            </ol>
          </div>
        </DialogContent>
      </Dialog>

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
    </div>
  );
}
