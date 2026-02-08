import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import {
  Server,
  Upload,
  Cloud,
  AlertTriangle,
  CheckCircle,
  Trash2,
  RefreshCw,
  FileUp,
  Play,
  Eye,
  Search,
  MoreVertical,
  Database,
  Globe,
  Shield,
  Zap,
  ArrowRight,
  Settings,
  Bot,
  Power,
  XCircle
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { ParticleBackground, GradientOrb } from "@/components/ui/animated-background";
import { HolographicCard } from "@/components/ui/holographic-card";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Switch } from "@/components/ui/switch";
import { AssetDependencyGraph } from "@/components/AssetDependencyGraph";

interface VulnerabilityImport {
  id: string;
  title: string;
  severity: string;
  cveId: string | null;
  affectedHost: string | null;
  affectedPort: number | null;
  status: string | null;
  aevEvaluationId: string | null;
  createdAt: string;
}

interface ImportJob {
  id: string;
  name: string;
  sourceType: string;
  status: string;
  progress: number;
  totalRecords: number | null;
  assetsDiscovered: number | null;
  vulnerabilitiesFound: number | null;
  createdAt: string;
  completedAt: string | null;
}

interface CloudConnection {
  id: string;
  name: string;
  provider: string;
  status: string;
  lastSyncAt: string | null;
  assetsDiscovered: number | null;
  createdAt: string;
}

interface AutoDeployConfig {
  id: string;
  organizationId: string;
  enabled: boolean;
  providers: string[];
  assetTypes: string[];
  targetPlatforms: string[];
  deploymentOptions: {
    maxConcurrentDeployments: number;
    deploymentTimeoutSeconds: number;
    retryFailedDeployments: boolean;
    maxRetries: number;
    skipOfflineAssets: boolean;
  };
  filterRules: {
    includeTags?: Record<string, string>;
    excludeTags?: Record<string, string>;
    includeRegions?: string[];
    excludeRegions?: string[];
    minInstanceSize?: string;
  } | null;
  totalDeploymentsTriggered: number;
  lastDeploymentTriggeredAt: string | null;
  createdAt: string | null;
  updatedAt: string | null;
}

interface InfraStats {
  totalAssets: number;
  totalVulnerabilities: number;
  criticalVulns: number;
  highVulns: number;
  pendingImports: number;
  cloudConnections: number;
}

interface CloudAsset {
  id: string;
  connectionId: string;
  providerResourceId: string;
  name: string;
  assetType: string;
  region: string | null;
  zone: string | null;
  status: string;
  platform: string | null;
  agentDeployable: boolean;
  agentDeploymentStatus: string | null;
  agentId: string | null;
  metadata: Record<string, unknown> | null;
  lastSeenAt: string;
  createdAt: string;
}

interface CloudDiscoveryJob {
  id: string;
  connectionId: string;
  status: string;
  progress: number;
  assetsFound: number;
  regionsScanned: number;
  totalRegions: number;
  currentPhase: string | null;
  errorMessage: string | null;
  startedAt: string | null;
  completedAt: string | null;
}

function CloudConnectionCard({
  connection,
  onTest,
  onDelete,
  getStatusBadge,
  testPending,
}: {
  connection: CloudConnection;
  onTest: () => void;
  onDelete: () => void;
  getStatusBadge: (status: string) => string;
  testPending: boolean;
}) {
  const { toast } = useToast();
  const [credentialsDialogOpen, setCredentialsDialogOpen] = useState(false);
  const [assetsDialogOpen, setAssetsDialogOpen] = useState(false);
  const [deployDialogOpen, setDeployDialogOpen] = useState(false);
  const [iamDialogOpen, setIamDialogOpen] = useState(false);
  const [iamScanResult, setIamScanResult] = useState<{
    findings: Array<{
      id: string;
      findingType: string;
      resourceName: string;
      severity: string;
      title: string;
      description: string;
      recommendation: string;
    }>;
    summary: Record<string, any>;
  } | null>(null);
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [deploymentMethod, setDeploymentMethod] = useState<"cloud-api" | "ssh">("cloud-api");
  const [sshHost, setSSHHost] = useState("");
  const [sshPort, setSSHPort] = useState("22");
  const [sshUsername, setSSHUsername] = useState("");
  const [sshPassword, setSSHPassword] = useState("");
  const [sshPrivateKey, setSSHPrivateKey] = useState("");
  const [sshAuthType, setSSHAuthType] = useState<"password" | "key">("password");
  const [useSudo, setUseSudo] = useState(true);

  const { data: cloudAssets = [], isLoading: assetsLoading } = useQuery<CloudAsset[]>({
    queryKey: ["/api/cloud-connections", connection.id, "assets"],
    enabled: assetsDialogOpen,
  });

  const { data: discoveryJobs = [] } = useQuery<CloudDiscoveryJob[]>({
    queryKey: ["/api/cloud-connections", connection.id, "discovery-jobs"],
  });

  const latestJob = discoveryJobs[0];

  const discoverMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/cloud-connections/${connection.id}/discover`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cloud-connections", connection.id, "discovery-jobs"] });
      toast({ title: "Discovery Started", description: "Asset discovery is now running in the background" });
    },
  });

  const updateCredentialsMutation = useMutation({
    mutationFn: async (credentials: Record<string, string>) => {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      const accessToken = localStorage.getItem("odinforge_access_token");
      if (accessToken) {
        headers["Authorization"] = `Bearer ${accessToken}`;
      }
      const res = await fetch(`/api/cloud-connections/${connection.id}/credentials`, {
        method: "POST",
        headers,
        body: JSON.stringify(credentials),
        credentials: "include",
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to update credentials");
      }
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cloud-connections"] });
      setCredentialsDialogOpen(false);
      toast({ title: "Credentials Updated" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to update credentials", description: error.message, variant: "destructive" });
    },
  });

  const deployAgentMutation = useMutation({
    mutationFn: async (params: { assetId: string; method: "cloud-api" | "ssh"; sshCredentials?: any }) => {
      const body: any = { deploymentMethod: params.method };
      if (params.method === "ssh" && params.sshCredentials) {
        body.sshHost = params.sshCredentials.host;
        body.sshPort = params.sshCredentials.port;
        body.sshUsername = params.sshCredentials.username;
        body.sshPassword = params.sshCredentials.password;
        body.sshPrivateKey = params.sshCredentials.privateKey;
        body.useSudo = params.sshCredentials.useSudo;
      }
      const res = await apiRequest("POST", `/api/cloud-assets/${params.assetId}/deploy-agent`, body);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cloud-connections", connection.id, "assets"] });
      setDeployDialogOpen(false);
      resetDeployForm();
      toast({ title: "Agent Deployment Started" });
    },
    onError: (error: any) => {
      toast({ title: "Deployment Failed", description: error.message, variant: "destructive" });
    },
  });
  
  const resetDeployForm = () => {
    setDeploymentMethod("cloud-api");
    setSSHHost("");
    setSSHPort("22");
    setSSHUsername("");
    setSSHPassword("");
    setSSHPrivateKey("");
    setSSHAuthType("password");
    setUseSudo(true);
    setSelectedAssetId(null);
  };
  
  const handleDeployClick = (asset: CloudAsset) => {
    setSelectedAssetId(asset.id);
    // Pre-fill SSH host from asset's IP addresses if available
    const metadata = asset.metadata as any;
    const publicIp = metadata?.publicIpAddresses?.[0] || metadata?.publicIpAddress;
    const privateIp = metadata?.privateIpAddresses?.[0] || metadata?.privateIpAddress;
    setSSHHost(publicIp || privateIp || "");
    setDeployDialogOpen(true);
  };
  
  const handleDeploySubmit = () => {
    if (!selectedAssetId) return;
    
    if (deploymentMethod === "ssh") {
      if (!sshHost || !sshUsername) {
        toast({ title: "SSH host and username are required", variant: "destructive" });
        return;
      }
      if (sshAuthType === "password" && !sshPassword) {
        toast({ title: "SSH password is required", variant: "destructive" });
        return;
      }
      if (sshAuthType === "key" && !sshPrivateKey) {
        toast({ title: "SSH private key is required", variant: "destructive" });
        return;
      }
      
      deployAgentMutation.mutate({
        assetId: selectedAssetId,
        method: "ssh",
        sshCredentials: {
          host: sshHost,
          port: parseInt(sshPort) || 22,
          username: sshUsername,
          password: sshAuthType === "password" ? sshPassword : undefined,
          privateKey: sshAuthType === "key" ? sshPrivateKey : undefined,
          useSudo,
        },
      });
    } else {
      deployAgentMutation.mutate({ assetId: selectedAssetId, method: "cloud-api" });
    }
  };

  const redeployAgentMutation = useMutation({
    mutationFn: async (assetId: string) => {
      const res = await apiRequest("POST", `/api/cloud-assets/${assetId}/redeploy-agent`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cloud-connections", connection.id, "assets"] });
      toast({ title: "Agent Redeployment Started" });
    },
  });

  const cancelDeploymentMutation = useMutation({
    mutationFn: async (assetId: string) => {
      const res = await apiRequest("POST", `/api/cloud-assets/${assetId}/cancel-deployment`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cloud-connections", connection.id, "assets"] });
      toast({ title: "Deployment Cancelled", description: "The stuck deployment has been cleared" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to Cancel", description: error.message, variant: "destructive" });
    },
  });

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-500/10 text-red-500 border-red-500/30";
      case "high": return "bg-orange-500/10 text-orange-500 border-orange-500/30";
      case "medium": return "bg-yellow-500/10 text-yellow-500 border-yellow-500/30";
      case "low": return "bg-blue-500/10 text-blue-500 border-blue-500/30";
      default: return "bg-muted";
    }
  };

  const getProviderIcon = () => {
    switch (connection.provider) {
      case "aws": return "AWS";
      case "azure": return "Azure";
      case "gcp": return "GCP";
      default: return "Cloud";
    }
  };

  const getAssetTypeIcon = (type: string) => {
    switch(type) {
      case "database": return <Database className="h-4 w-4" />;
      case "web_application": return <Globe className="h-4 w-4" />;
      case "cloud_instance": return <Cloud className="h-4 w-4" />;
      case "firewall": return <Shield className="h-4 w-4" />;
      default: return <Server className="h-4 w-4" />;
    }
  };

  return (
    <>
      <Card className="hover-elevate" data-testid={`cloud-connection-${connection.id}`}>
        <CardHeader className="pb-2">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-lg bg-muted/50">
                <Cloud className="h-4 w-4 text-cyan-400" />
              </div>
              <div>
                <CardTitle className="text-sm font-medium">{connection.name}</CardTitle>
                <CardDescription className="text-xs">{getProviderIcon()}</CardDescription>
              </div>
            </div>
            <div className="flex items-center gap-1">
              <Badge className={getStatusBadge(connection.status)}>
                {connection.status}
              </Badge>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" data-testid={`button-cloud-menu-${connection.id}`}>
                    <MoreVertical className="h-4 w-4" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onClick={onTest} disabled={testPending} data-testid={`menu-test-${connection.id}`}>
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Test Connection
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setCredentialsDialogOpen(true)} data-testid={`menu-credentials-${connection.id}`}>
                    <Shield className="h-4 w-4 mr-2" />
                    Update Credentials
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setAssetsDialogOpen(true)} data-testid={`menu-assets-${connection.id}`}>
                    <Server className="h-4 w-4 mr-2" />
                    View Assets
                  </DropdownMenuItem>
                  <DropdownMenuItem className="text-destructive" onClick={onDelete} data-testid={`menu-delete-${connection.id}`}>
                    <Trash2 className="h-4 w-4 mr-2" />
                    Delete
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Assets Discovered</span>
            <span className="font-mono">{connection.assetsDiscovered || 0}</span>
          </div>
          {connection.lastSyncAt && (
            <div className="text-xs text-muted-foreground">
              Last sync: {new Date(connection.lastSyncAt).toLocaleString()}
            </div>
          )}
          {(connection as any).iamFindings && (
            <div 
              className="rounded-lg border p-2 space-y-1 cursor-pointer hover-elevate"
              onClick={() => {
                setIamScanResult((connection as any).iamFindings);
                setIamDialogOpen(true);
              }}
              data-testid={`iam-findings-summary-${connection.id}`}
            >
              <div className="flex items-center gap-1 text-xs font-medium">
                <Shield className="h-3 w-3 text-cyan-400" />
                <span>IAM Security</span>
              </div>
              <div className="flex gap-2 text-xs">
                {((connection as any).iamFindings?.summary?.criticalFindings || 0) > 0 && (
                  <Badge className="bg-red-500/10 text-red-500 border-red-500/30 text-xs px-1">
                    {(connection as any).iamFindings.summary.criticalFindings} Critical
                  </Badge>
                )}
                {((connection as any).iamFindings?.summary?.highFindings || 0) > 0 && (
                  <Badge className="bg-orange-500/10 text-orange-500 border-orange-500/30 text-xs px-1">
                    {(connection as any).iamFindings.summary.highFindings} High
                  </Badge>
                )}
                {((connection as any).iamFindings?.summary?.mediumFindings || 0) > 0 && (
                  <Badge className="bg-yellow-500/10 text-yellow-500 border-yellow-500/30 text-xs px-1">
                    {(connection as any).iamFindings.summary.mediumFindings} Medium
                  </Badge>
                )}
                {((connection as any).iamFindings?.summary?.criticalFindings || 0) === 0 && 
                 ((connection as any).iamFindings?.summary?.highFindings || 0) === 0 && 
                 ((connection as any).iamFindings?.summary?.mediumFindings || 0) === 0 && (
                  <span className="text-muted-foreground">No security issues</span>
                )}
              </div>
            </div>
          )}
          {latestJob && latestJob.status === "running" && (
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">{latestJob.currentPhase}</span>
                <span>{latestJob.regionsScanned}/{latestJob.totalRegions} regions</span>
              </div>
              <Progress value={latestJob.progress} className="h-1" />
            </div>
          )}
          <Button 
            className="w-full" 
            variant="outline" 
            size="sm"
            onClick={() => discoverMutation.mutate()}
            disabled={discoverMutation.isPending || (latestJob?.status === "running")}
            data-testid={`button-discover-${connection.id}`}
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${latestJob?.status === "running" ? "animate-spin" : ""}`} />
            {latestJob?.status === "running" ? "Discovering..." : "Run Discovery"}
          </Button>
        </CardContent>
      </Card>

      <Dialog open={credentialsDialogOpen} onOpenChange={setCredentialsDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Update Credentials</DialogTitle>
            <DialogDescription>
              Update the credentials for {connection.name}
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={(e) => {
            e.preventDefault();
            const formData = new FormData(e.currentTarget);
            const credentials: Record<string, string> = {};
            formData.forEach((value, key) => {
              if (value) credentials[key] = value as string;
            });
            updateCredentialsMutation.mutate(credentials);
          }}>
            <div className="space-y-4 py-4">
              {connection.provider === "aws" && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="accessKeyId">Access Key ID</Label>
                    <Input id="accessKeyId" name="accessKeyId" placeholder="AKIA..." />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="secretAccessKey">Secret Access Key</Label>
                    <Input id="secretAccessKey" name="secretAccessKey" type="password" />
                  </div>
                </>
              )}
              {connection.provider === "azure" && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="clientId">Client ID</Label>
                    <Input id="clientId" name="clientId" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="clientSecret">Client Secret</Label>
                    <Input id="clientSecret" name="clientSecret" type="password" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="tenantId">Tenant ID</Label>
                    <Input id="tenantId" name="tenantId" />
                  </div>
                </>
              )}
              {connection.provider === "gcp" && (
                <div className="space-y-2">
                  <Label htmlFor="serviceAccountKey">Service Account Key (JSON)</Label>
                  <Input id="serviceAccountKey" name="serviceAccountKey" type="password" />
                </div>
              )}
            </div>
            <DialogFooter>
              <Button type="submit" disabled={updateCredentialsMutation.isPending}>
                Update
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={assetsDialogOpen} onOpenChange={setAssetsDialogOpen}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Cloud Assets - {connection.name}</DialogTitle>
            <DialogDescription>
              {cloudAssets.length} assets discovered
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            {assetsLoading ? (
              <div className="text-center py-8 text-muted-foreground">Loading assets...</div>
            ) : cloudAssets.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No assets discovered yet. Run discovery to find assets.
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Region</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Agent</TableHead>
                    <TableHead className="w-[80px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {cloudAssets.map((asset) => (
                    <TableRow key={asset.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <div className="p-1.5 rounded bg-muted text-cyan-400">
                            {getAssetTypeIcon(asset.assetType)}
                          </div>
                          <div>
                            <div className="font-medium text-sm">{asset.name}</div>
                            <div className="text-xs text-muted-foreground font-mono">
                              {asset.providerResourceId.length > 30 
                                ? `${asset.providerResourceId.slice(0, 30)}...` 
                                : asset.providerResourceId}
                            </div>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-xs">
                          {asset.assetType.replace("_", " ")}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm">
                        {asset.region || "-"}
                        {asset.zone && <span className="text-muted-foreground"> / {asset.zone}</span>}
                      </TableCell>
                      <TableCell>
                        <Badge className={
                          asset.status === "running" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" :
                          asset.status === "stopped" ? "bg-amber-500/10 text-amber-400 border-amber-500/30" :
                          "bg-gray-500/10 text-gray-400 border-gray-500/30"
                        }>
                          {asset.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {asset.agentDeployable ? (
                          <Badge className={
                            asset.agentDeploymentStatus === "success" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" :
                            asset.agentDeploymentStatus === "deploying" || asset.agentDeploymentStatus === "pending" 
                              ? "bg-amber-500/10 text-amber-400 border-amber-500/30" :
                            asset.agentDeploymentStatus === "failed" ? "bg-red-500/10 text-red-400 border-red-500/30" :
                            "bg-gray-500/10 text-gray-400 border-gray-500/30"
                          }>
                            {asset.agentDeploymentStatus === "success" ? "Installed" : asset.agentDeploymentStatus || "Not Deployed"}
                          </Badge>
                        ) : (
                          <span className="text-xs text-muted-foreground">N/A</span>
                        )}
                      </TableCell>
                      <TableCell className="flex items-center gap-1">
                        {asset.agentDeployable && 
                         asset.agentDeploymentStatus !== "success" && 
                         asset.agentDeploymentStatus !== "deploying" && 
                         asset.agentDeploymentStatus !== "pending" && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleDeployClick(asset)}
                            disabled={deployAgentMutation.isPending}
                            data-testid={`button-deploy-agent-${asset.id}`}
                            title="Deploy Agent"
                          >
                            <Play className="h-3 w-3" />
                          </Button>
                        )}
                        {asset.agentDeployable && 
                         (asset.agentDeploymentStatus === "pending" || asset.agentDeploymentStatus === "deploying") && (
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => cancelDeploymentMutation.mutate(asset.id)}
                            disabled={cancelDeploymentMutation.isPending}
                            data-testid={`button-cancel-deploy-${asset.id}`}
                            title="Cancel stuck deployment"
                          >
                            <XCircle className="h-3 w-3" />
                          </Button>
                        )}
                        {asset.agentDeployable && 
                         (asset.agentDeploymentStatus === "success" || asset.agentDeploymentStatus === "failed") && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => redeployAgentMutation.mutate(asset.id)}
                            disabled={redeployAgentMutation.isPending}
                            data-testid={`button-redeploy-agent-${asset.id}`}
                            title="Redeploy Agent"
                          >
                            <RefreshCw className="h-3 w-3" />
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* Agent Deployment Dialog */}
      <Dialog open={deployDialogOpen} onOpenChange={(open) => { if (!open) resetDeployForm(); setDeployDialogOpen(open); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Deploy Agent</DialogTitle>
            <DialogDescription>
              Deploy the OdinForge monitoring agent to this asset.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Deployment Method</Label>
              <Select value={deploymentMethod} onValueChange={(v) => setDeploymentMethod(v as "cloud-api" | "ssh")}>
                <SelectTrigger data-testid="select-deployment-method">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="cloud-api">Cloud API (Recommended)</SelectItem>
                  <SelectItem value="ssh">SSH Connection (Fallback)</SelectItem>
                </SelectContent>
              </Select>
              {deploymentMethod === "cloud-api" ? (
                <div className="p-3 rounded-md bg-green-500/10 border border-green-500/30">
                  <p className="text-sm font-medium text-green-600 dark:text-green-400 flex items-center gap-2">
                    <CheckCircle className="h-4 w-4" />
                    Using Your Cloud Credentials
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    This method uses your configured {connection.provider.toUpperCase()} service account credentials to deploy via{" "}
                    {connection.provider === "aws" ? "SSM Run Command" : 
                     connection.provider === "azure" ? "VM Run Command" : 
                     "compute metadata"}. No additional credentials needed.
                  </p>
                </div>
              ) : (
                <div className="p-3 rounded-md bg-amber-500/10 border border-amber-500/30">
                  <p className="text-sm font-medium text-amber-600 dark:text-amber-400 flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4" />
                    Manual SSH Credentials Required
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Use this if cloud APIs are unavailable or for on-premise servers.
                    You must provide SSH login credentials below.
                  </p>
                </div>
              )}
            </div>
            
            {deploymentMethod === "ssh" && (
              <>
                <div className="space-y-2">
                  <Label htmlFor="ssh-host">SSH Host</Label>
                  <Input 
                    id="ssh-host"
                    value={sshHost}
                    onChange={(e) => setSSHHost(e.target.value)}
                    placeholder="IP address or hostname"
                    data-testid="input-ssh-host"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-2">
                    <Label htmlFor="ssh-port">Port</Label>
                    <Input 
                      id="ssh-port"
                      value={sshPort}
                      onChange={(e) => setSSHPort(e.target.value)}
                      placeholder="22"
                      data-testid="input-ssh-port"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="ssh-username">Username</Label>
                    <Input 
                      id="ssh-username"
                      value={sshUsername}
                      onChange={(e) => setSSHUsername(e.target.value)}
                      placeholder="e.g., ubuntu, ec2-user"
                      data-testid="input-ssh-username"
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label>Authentication</Label>
                  <Select value={sshAuthType} onValueChange={(v) => setSSHAuthType(v as "password" | "key")}>
                    <SelectTrigger data-testid="select-ssh-auth-type">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="password">Password</SelectItem>
                      <SelectItem value="key">Private Key</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {sshAuthType === "password" ? (
                  <div className="space-y-2">
                    <Label htmlFor="ssh-password">Password</Label>
                    <Input 
                      id="ssh-password"
                      type="password"
                      value={sshPassword}
                      onChange={(e) => setSSHPassword(e.target.value)}
                      placeholder="SSH password"
                      data-testid="input-ssh-password"
                    />
                  </div>
                ) : (
                  <div className="space-y-2">
                    <Label htmlFor="ssh-key">Private Key</Label>
                    <textarea 
                      id="ssh-key"
                      className="w-full min-h-[100px] p-2 text-sm font-mono border rounded-md bg-background"
                      value={sshPrivateKey}
                      onChange={(e) => setSSHPrivateKey(e.target.value)}
                      placeholder="-----BEGIN RSA PRIVATE KEY-----"
                      data-testid="input-ssh-private-key"
                    />
                  </div>
                )}
                <div className="flex items-center gap-2">
                  <Switch 
                    id="use-sudo"
                    checked={useSudo}
                    onCheckedChange={setUseSudo}
                    data-testid="switch-use-sudo"
                  />
                  <Label htmlFor="use-sudo" className="text-sm">Use sudo for installation</Label>
                </div>
              </>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { resetDeployForm(); setDeployDialogOpen(false); }} data-testid="button-cancel-deploy">
              Cancel
            </Button>
            <Button onClick={handleDeploySubmit} disabled={deployAgentMutation.isPending} data-testid="button-confirm-deploy">
              {deployAgentMutation.isPending ? "Deploying..." : "Deploy Agent"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={iamDialogOpen} onOpenChange={setIamDialogOpen}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-hidden flex flex-col">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-cyan-400" />
              IAM Security Findings
            </DialogTitle>
            <DialogDescription>
              Security analysis of IAM configurations for {connection.name}
            </DialogDescription>
          </DialogHeader>
          
          {iamScanResult && (
            <div className="flex-1 overflow-hidden flex flex-col space-y-4">
              <div className="flex flex-wrap gap-4 p-3 bg-muted/50 rounded-lg">
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-500">{iamScanResult.summary?.criticalFindings || 0}</div>
                  <div className="text-xs text-muted-foreground">Critical</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-orange-500">{iamScanResult.summary?.highFindings || 0}</div>
                  <div className="text-xs text-muted-foreground">High</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-yellow-500">{iamScanResult.summary?.mediumFindings || 0}</div>
                  <div className="text-xs text-muted-foreground">Medium</div>
                </div>
                <div className="border-l pl-4 ml-2 flex-1">
                  <div className="text-xs text-muted-foreground space-y-1">
                    {connection.provider === "aws" && (
                      <>
                        <div>Users: {iamScanResult.summary?.totalUsers ?? 0}</div>
                        <div>Roles: {iamScanResult.summary?.totalRoles ?? 0}</div>
                        <div>Access Keys: {iamScanResult.summary?.totalAccessKeys ?? 0}</div>
                      </>
                    )}
                    {connection.provider === "azure" && (
                      <>
                        <div>Subscriptions: {iamScanResult.summary?.totalSubscriptions ?? 0}</div>
                        <div>Role Assignments: {iamScanResult.summary?.totalRoleAssignments ?? 0}</div>
                        <div>Service Principals: {iamScanResult.summary?.totalServicePrincipals ?? 0}</div>
                      </>
                    )}
                    {connection.provider === "gcp" && (
                      <>
                        <div>IAM Bindings: {iamScanResult.summary?.totalBindings ?? 0}</div>
                        <div>Service Accounts: {iamScanResult.summary?.totalServiceAccounts ?? 0}</div>
                        <div>Users: {iamScanResult.summary?.totalUsers ?? 0}</div>
                      </>
                    )}
                  </div>
                </div>
              </div>

              <div className="flex-1 overflow-y-auto space-y-3 pr-2">
                {iamScanResult.findings?.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <Shield className="h-12 w-12 mx-auto mb-2 opacity-20" />
                    <p>No security issues found</p>
                  </div>
                ) : (
                  iamScanResult.findings?.map((finding) => (
                    <div 
                      key={finding.id} 
                      className="border rounded-lg p-4 space-y-2"
                      data-testid={`iam-finding-${finding.id}`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <Badge className={getSeverityBadge(finding.severity)}>
                            {finding.severity.toUpperCase()}
                          </Badge>
                          <span className="font-medium text-sm">{finding.title}</span>
                        </div>
                        <Badge variant="outline" className="text-xs">
                          {finding.findingType}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">{finding.description}</p>
                      <div className="text-xs text-cyan-400">
                        <span className="font-medium">Recommendation:</span> {finding.recommendation}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono">
                        Resource: {finding.resourceName}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setIamDialogOpen(false)} data-testid="button-close-iam">
              Close
            </Button>
            <Button 
              onClick={() => { setIamDialogOpen(false); discoverMutation.mutate(); }}
              disabled={discoverMutation.isPending || (latestJob?.status === "running")}
              data-testid="button-rescan-iam"
            >
              <RefreshCw className={`h-4 w-4 mr-2 ${latestJob?.status === "running" ? "animate-spin" : ""}`} />
              Rescan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

export default function Infrastructure() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("scanner-imports");
  const [searchQuery, setSearchQuery] = useState("");
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [cloudDialogOpen, setCloudDialogOpen] = useState(false);

  const { data: stats, isLoading: statsLoading } = useQuery<InfraStats>({
    queryKey: ["/api/infrastructure/stats"],
  });

  const { data: vulnerabilities = [], isLoading: vulnsLoading } = useQuery<VulnerabilityImport[]>({
    queryKey: ["/api/vulnerabilities"],
  });

  const { data: importJobs = [], isLoading: jobsLoading } = useQuery<ImportJob[]>({
    queryKey: ["/api/imports"],
  });

  const { data: cloudConnections = [], isLoading: cloudLoading } = useQuery<CloudConnection[]>({
    queryKey: ["/api/cloud-connections"],
  });

  const { data: autoDeployConfig } = useQuery<AutoDeployConfig>({
    queryKey: ["/api/auto-deploy/config"],
  });

  const toggleAutoDeployMutation = useMutation({
    mutationFn: async (enabled: boolean) => {
      const res = await apiRequest("POST", "/api/auto-deploy/toggle", { enabled });
      return res.json();
    },
    onSuccess: (data: { enabled: boolean }) => {
      queryClient.invalidateQueries({ queryKey: ["/api/auto-deploy/config"] });
      toast({
        title: data.enabled ? "Auto-Deploy Enabled" : "Auto-Deploy Disabled",
        description: data.enabled 
          ? "Agents will be automatically deployed when new assets are discovered" 
          : "Automatic agent deployment has been turned off",
      });
    },
    onError: () => {
      toast({
        title: "Failed to Update",
        description: "Could not update auto-deploy settings",
        variant: "destructive",
      });
    },
  });

  const uploadMutation = useMutation({
    mutationFn: async (data: { content: string; fileName: string; name: string }) => {
      const res = await apiRequest("POST", "/api/imports/upload", data);
      return res.json();
    },
    onSuccess: (data: unknown) => {
      const result = data as { summary: { assetsDiscovered: number; vulnerabilitiesFound: number } };
      queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
      queryClient.invalidateQueries({ queryKey: ["/api/vulnerabilities"] });
      queryClient.invalidateQueries({ queryKey: ["/api/imports"] });
      queryClient.invalidateQueries({ queryKey: ["/api/infrastructure/stats"] });
      setImportDialogOpen(false);
      toast({
        title: "Import Complete",
        description: `Discovered ${result.summary.assetsDiscovered} assets and ${result.summary.vulnerabilitiesFound} vulnerabilities`,
      });
    },
    onError: () => {
      toast({
        title: "Import Failed",
        description: "Failed to process the import file",
        variant: "destructive",
      });
    },
  });

  const evaluateMutation = useMutation({
    mutationFn: async (vulnId: string) => {
      const res = await apiRequest("POST", `/api/vulnerabilities/${vulnId}/evaluate`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/vulnerabilities"] });
      toast({
        title: "AEV Evaluation Started",
        description: "AI-powered exploitability analysis is now running",
      });
    },
  });

  const evaluateAllMutation = useMutation({
    mutationFn: async () => {
      const unevaluated = vulnerabilities.filter(v => !v.aevEvaluationId);
      const criticalHigh = unevaluated.filter(v => v.severity === "critical" || v.severity === "high");
      const toEvaluate = criticalHigh.length > 0 ? criticalHigh.slice(0, 10) : unevaluated.slice(0, 10);
      
      for (const vuln of toEvaluate) {
        await apiRequest("POST", `/api/vulnerabilities/${vuln.id}/evaluate`);
      }
      return toEvaluate.length;
    },
    onSuccess: (count) => {
      queryClient.invalidateQueries({ queryKey: ["/api/vulnerabilities"] });
      toast({
        title: "Batch Evaluation Started",
        description: `Triggered AEV analysis for ${count} vulnerabilities`,
      });
    },
  });

  const deleteImportMutation = useMutation({
    mutationFn: async (id: string) => {
      return apiRequest("DELETE", `/api/imports/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/imports"] });
      queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
      queryClient.invalidateQueries({ queryKey: ["/api/vulnerabilities"] });
      queryClient.invalidateQueries({ queryKey: ["/api/infrastructure/stats"] });
      toast({ title: "Import Deleted" });
    },
  });

  const createCloudMutation = useMutation({
    mutationFn: async (data: { name: string; provider: string }) => {
      const res = await apiRequest("POST", "/api/cloud-connections", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cloud-connections"] });
      setCloudDialogOpen(false);
      toast({ title: "Cloud Connection Created" });
    },
  });

  const testCloudMutation = useMutation({
    mutationFn: async (id: string) => {
      return apiRequest("POST", `/api/cloud-connections/${id}/test`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cloud-connections"] });
      toast({ title: "Connection Test Successful" });
    },
  });

  const deleteCloudMutation = useMutation({
    mutationFn: async (id: string) => {
      return apiRequest("DELETE", `/api/cloud-connections/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cloud-connections"] });
      toast({ title: "Cloud Connection Deleted" });
    },
  });

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      uploadMutation.mutate({
        content,
        fileName: file.name,
        name: file.name.replace(/\.[^/.]+$/, ""),
      });
    };
    reader.readAsText(file);
  };

  const getSeverityBadge = (severity: string) => {
    const styles: Record<string, string> = {
      critical: "bg-red-500/10 text-red-400 border-red-500/30",
      high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
      medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
      low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
      informational: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    };
    return styles[severity] || styles.medium;
  };

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      connected: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
      completed: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
      active: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
      processing: "bg-amber-500/10 text-amber-400 border-amber-500/30",
      pending: "bg-blue-500/10 text-blue-400 border-blue-500/30",
      error: "bg-red-500/10 text-red-400 border-red-500/30",
      failed: "bg-red-500/10 text-red-400 border-red-500/30",
      disconnected: "bg-gray-500/10 text-gray-400 border-gray-500/30",
    };
    return styles[status] || styles.pending;
  };

  const filteredVulns = vulnerabilities.filter(v =>
    v.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    v.cveId?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    v.affectedHost?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const unevaluatedCount = vulnerabilities.filter(v => !v.aevEvaluationId).length;
  const evaluatedCount = vulnerabilities.filter(v => v.aevEvaluationId).length;

  return (
    <div className="space-y-6 relative" data-testid="data-sources-page">
      {/* Animated backgrounds */}
      <ParticleBackground particleCount={40} particleColor="#8b5cf6" opacity={0.2} />
      <GradientOrb color1="#8b5cf6" color2="#06b6d4" size="lg" className="top-10 right-10" />
      <GradientOrb color1="#ef4444" color2="#f97316" size="md" className="bottom-20 left-20" />

      {/* Grid overlay */}
      <div className="absolute inset-0 grid-bg opacity-15 pointer-events-none" />

      <div className="relative z-10 space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Database className="h-6 w-6 text-purple-400 glow-purple-sm" />
            <span className="text-neon-cyan">Data</span>
            <span>Sources</span>
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Import vulnerability data and connect cloud providers for asset discovery
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Dialog open={importDialogOpen} onOpenChange={setImportDialogOpen}>
            <DialogTrigger asChild>
              <Button data-testid="button-import">
                <Upload className="h-4 w-4 mr-2" />
                Import Scanner Data
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Import Scanner Data</DialogTitle>
                <DialogDescription>
                  Upload a vulnerability scan file (Nessus, Qualys, CSV, or JSON format)
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div className="border-2 border-dashed border-muted rounded-lg p-8 text-center">
                  <FileUp className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <Label htmlFor="file-upload" className="cursor-pointer">
                    <span className="text-foreground font-medium">Click to upload</span>
                    <span className="text-muted-foreground"> or drag and drop</span>
                  </Label>
                  <Input
                    id="file-upload"
                    type="file"
                    accept=".csv,.json,.xml,.nessus"
                    className="hidden"
                    onChange={handleFileUpload}
                    data-testid="input-file-upload"
                  />
                  <p className="text-xs text-muted-foreground mt-2">
                    Supported formats: .nessus, .xml, .csv, .json
                  </p>
                </div>
                {uploadMutation.isPending && (
                  <div className="space-y-2">
                    <Progress value={50} />
                    <p className="text-sm text-center text-muted-foreground">Processing...</p>
                  </div>
                )}
              </div>
            </DialogContent>
          </Dialog>

          <Dialog open={cloudDialogOpen} onOpenChange={setCloudDialogOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" data-testid="button-add-cloud">
                <Cloud className="h-4 w-4 mr-2" />
                Add Cloud
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Connect Cloud Account</DialogTitle>
                <DialogDescription>
                  Connect AWS, Azure, or GCP for automatic asset discovery
                </DialogDescription>
              </DialogHeader>
              <form onSubmit={(e) => {
                e.preventDefault();
                const formData = new FormData(e.currentTarget);
                createCloudMutation.mutate({
                  name: formData.get("name") as string,
                  provider: formData.get("provider") as string,
                });
              }}>
                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor="cloud-name">Connection Name</Label>
                    <Input
                      id="cloud-name"
                      name="name"
                      placeholder="Production AWS Account"
                      required
                      data-testid="input-cloud-name"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="cloud-provider">Cloud Provider</Label>
                    <Select name="provider" defaultValue="aws">
                      <SelectTrigger data-testid="select-cloud-provider">
                        <SelectValue placeholder="Select provider" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="aws">Amazon Web Services (AWS)</SelectItem>
                        <SelectItem value="azure">Microsoft Azure</SelectItem>
                        <SelectItem value="gcp">Google Cloud Platform (GCP)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <DialogFooter>
                  <Button type="submit" disabled={createCloudMutation.isPending} data-testid="button-create-cloud">
                    Connect
                  </Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <HolographicCard className="hover-elevate" variant="subtle">
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Vulnerabilities</CardTitle>
            <AlertTriangle className="h-4 w-4 text-amber-400 glow-purple-sm" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="stat-total-vulns">
              {statsLoading ? "..." : stats?.totalVulnerabilities || 0}
            </div>
          </CardContent>
        </HolographicCard>

        <HolographicCard className="hover-elevate" variant="subtle">
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Awaiting Analysis</CardTitle>
            <Zap className="h-4 w-4 text-blue-400 glow-cyan-sm" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-neon-cyan" data-testid="stat-unevaluated">
              {unevaluatedCount}
            </div>
          </CardContent>
        </HolographicCard>

        <HolographicCard className="hover-elevate" variant="subtle">
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Evaluated</CardTitle>
            <CheckCircle className="h-4 w-4 text-emerald-400 glow-green-sm" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-neon-green" data-testid="stat-evaluated">
              {evaluatedCount}
            </div>
          </CardContent>
        </HolographicCard>

        <HolographicCard className="hover-elevate" variant="subtle">
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Cloud Connections</CardTitle>
            <Cloud className="h-4 w-4 text-cyan-400 glow-cyan-sm" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="stat-cloud">
              {statsLoading ? "..." : stats?.cloudConnections || 0}
            </div>
          </CardContent>
        </HolographicCard>
      </div>

      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search vulnerabilities..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9"
            data-testid="input-search"
          />
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="scanner-imports" data-testid="tab-scanner-imports">
            <Upload className="h-4 w-4 mr-2" />
            Scanner Imports ({importJobs.length + vulnerabilities.length})
          </TabsTrigger>
          <TabsTrigger value="cloud" data-testid="tab-cloud">
            <Cloud className="h-4 w-4 mr-2" />
            Cloud Connections ({cloudConnections.length})
          </TabsTrigger>
          <TabsTrigger value="dependencies" data-testid="tab-dependencies">
            <ArrowRight className="h-4 w-4 mr-2" />
            Asset Dependencies
          </TabsTrigger>
        </TabsList>

        <TabsContent value="scanner-imports" className="mt-4 space-y-6">
          {importJobs.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-sm font-medium text-muted-foreground">Recent Imports</h3>
              <div className="grid gap-3">
                {importJobs.map((job) => (
                  <Card key={job.id} data-testid={`card-import-${job.id}`}>
                    <CardHeader className="flex flex-row items-center justify-between gap-4 py-3">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-muted/50">
                          <Upload className="h-4 w-4 text-cyan-400" />
                        </div>
                        <div>
                          <CardTitle className="text-sm font-medium">{job.name}</CardTitle>
                          <CardDescription className="flex items-center gap-2 text-xs">
                            <Badge variant="outline" className="text-xs">{job.sourceType}</Badge>
                            <span>{new Date(job.createdAt).toLocaleString()}</span>
                          </CardDescription>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="text-right text-sm">
                          <div className="flex items-center gap-3 text-muted-foreground">
                            <span><span className="font-mono text-cyan-400">{job.assetsDiscovered || 0}</span> assets</span>
                            <span><span className="font-mono text-amber-400">{job.vulnerabilitiesFound || 0}</span> vulns</span>
                          </div>
                        </div>
                        <Badge className={getStatusBadge(job.status)}>
                          {job.status}
                        </Badge>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem
                              className="text-destructive"
                              onClick={() => deleteImportMutation.mutate(job.id)}
                            >
                              <Trash2 className="h-4 w-4 mr-2" />
                              Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    </CardHeader>
                    {job.status === "processing" && (
                      <CardContent className="pt-0 pb-3">
                        <Progress value={job.progress} className="h-1" />
                      </CardContent>
                    )}
                  </Card>
                ))}
              </div>
            </div>
          )}

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-medium text-muted-foreground">Imported Vulnerabilities</h3>
              {unevaluatedCount > 0 && (
                <Button 
                  size="sm" 
                  onClick={() => evaluateAllMutation.mutate()}
                  disabled={evaluateAllMutation.isPending}
                  data-testid="button-evaluate-all"
                >
                  <Zap className="h-4 w-4 mr-2" />
                  Run AEV Analysis ({Math.min(unevaluatedCount, 10)})
                </Button>
              )}
            </div>
            
            {vulnsLoading || jobsLoading ? (
              <div className="text-center py-12 text-muted-foreground">Loading...</div>
            ) : vulnerabilities.length === 0 ? (
              <Card>
                <CardContent className="py-12 text-center">
                  <AlertTriangle className="h-12 w-12 mx-auto mb-3 text-muted-foreground opacity-30" />
                  <p className="text-muted-foreground">No vulnerabilities imported yet</p>
                  <p className="text-sm text-muted-foreground mt-1">
                    Import scanner data to see vulnerabilities here
                  </p>
                  <Button
                    variant="outline"
                    className="mt-4"
                    onClick={() => setImportDialogOpen(true)}
                    data-testid="button-first-import"
                  >
                    <Upload className="h-4 w-4 mr-2" />
                    Import Scanner Data
                  </Button>
                </CardContent>
              </Card>
            ) : (
              <Card>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Vulnerability</TableHead>
                      <TableHead>CVE</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Affected Host</TableHead>
                      <TableHead>AEV Status</TableHead>
                      <TableHead className="w-[100px]">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredVulns.map((vuln) => (
                      <TableRow key={vuln.id} data-testid={`row-vuln-${vuln.id}`}>
                        <TableCell>
                          <div className="font-medium max-w-[300px] truncate" title={vuln.title}>
                            {vuln.title}
                          </div>
                        </TableCell>
                        <TableCell>
                          {vuln.cveId ? (
                            <Badge variant="outline" className="font-mono text-xs">
                              {vuln.cveId}
                            </Badge>
                          ) : "-"}
                        </TableCell>
                        <TableCell>
                          <Badge className={getSeverityBadge(vuln.severity)}>
                            {vuln.severity.toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <span className="font-mono text-sm">{vuln.affectedHost || "-"}</span>
                          {vuln.affectedPort && (
                            <span className="text-muted-foreground">:{vuln.affectedPort}</span>
                          )}
                        </TableCell>
                        <TableCell>
                          {vuln.aevEvaluationId ? (
                            <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                              <CheckCircle className="h-3 w-3 mr-1" />
                              Analyzed
                            </Badge>
                          ) : (
                            <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/30">
                              Awaiting
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon" data-testid={`button-vuln-actions-${vuln.id}`}>
                                <MoreVertical className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem data-testid={`menu-view-vuln-${vuln.id}`}>
                                <Eye className="h-4 w-4 mr-2" />
                                View Details
                              </DropdownMenuItem>
                              {!vuln.aevEvaluationId && (
                                <DropdownMenuItem
                                  onClick={() => evaluateMutation.mutate(vuln.id)}
                                  disabled={evaluateMutation.isPending}
                                  data-testid={`menu-evaluate-vuln-${vuln.id}`}
                                >
                                  <Zap className="h-4 w-4 mr-2" />
                                  Run AEV Analysis
                                </DropdownMenuItem>
                              )}
                              {vuln.aevEvaluationId && (
                                <DropdownMenuItem data-testid={`menu-view-eval-${vuln.id}`}>
                                  <ArrowRight className="h-4 w-4 mr-2" />
                                  View Evaluation
                                </DropdownMenuItem>
                              )}
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Card>
            )}
          </div>
        </TabsContent>

        <TabsContent value="cloud" className="mt-4">
          {cloudLoading ? (
            <div className="text-center py-12 text-muted-foreground">Loading cloud connections...</div>
          ) : cloudConnections.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Cloud className="h-12 w-12 mx-auto mb-3 text-muted-foreground opacity-30" />
                <p className="text-muted-foreground">No cloud connections yet</p>
                <p className="text-sm text-muted-foreground mt-1">Connect AWS, Azure, or GCP for automatic asset discovery</p>
                <Button
                  variant="outline"
                  className="mt-4"
                  onClick={() => setCloudDialogOpen(true)}
                  data-testid="button-first-cloud"
                >
                  <Cloud className="h-4 w-4 mr-2" />
                  Connect Cloud Account
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-6">
              {/* Auto-Deploy Settings Card */}
              <Card>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-primary/10 rounded-lg">
                        <Bot className="h-5 w-5 text-primary" />
                      </div>
                      <div>
                        <CardTitle className="text-base">Auto-Deploy Agents</CardTitle>
                        <CardDescription className="text-xs">
                          Automatically deploy monitoring agents when new assets are discovered
                        </CardDescription>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="flex items-center gap-2">
                        <Power className={`h-4 w-4 ${autoDeployConfig?.enabled ? 'text-green-500' : 'text-muted-foreground'}`} />
                        <Switch
                          checked={autoDeployConfig?.enabled || false}
                          onCheckedChange={(checked) => toggleAutoDeployMutation.mutate(checked)}
                          disabled={toggleAutoDeployMutation.isPending}
                          data-testid="switch-auto-deploy"
                        />
                      </div>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div className="p-3 bg-muted/30 rounded-md">
                      <p className="text-muted-foreground text-xs mb-1">Status</p>
                      <Badge variant={autoDeployConfig?.enabled ? "default" : "secondary"}>
                        {autoDeployConfig?.enabled ? "Active" : "Inactive"}
                      </Badge>
                    </div>
                    <div className="p-3 bg-muted/30 rounded-md">
                      <p className="text-muted-foreground text-xs mb-1">Deployments Triggered</p>
                      <p className="font-medium">{autoDeployConfig?.totalDeploymentsTriggered || 0}</p>
                    </div>
                    <div className="p-3 bg-muted/30 rounded-md">
                      <p className="text-muted-foreground text-xs mb-1">Providers</p>
                      <div className="flex gap-1 flex-wrap">
                        {(autoDeployConfig?.providers || ["aws", "azure", "gcp"]).map(provider => (
                          <Badge key={provider} variant="outline" className="text-xs">
                            {provider.toUpperCase()}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <div className="p-3 bg-muted/30 rounded-md">
                      <p className="text-muted-foreground text-xs mb-1">Last Triggered</p>
                      <p className="font-medium text-xs">
                        {autoDeployConfig?.lastDeploymentTriggeredAt 
                          ? new Date(autoDeployConfig.lastDeploymentTriggeredAt).toLocaleDateString()
                          : "Never"}
                      </p>
                    </div>
                  </div>
                  {autoDeployConfig?.enabled && (
                    <div className="mt-3 p-2 bg-green-500/10 border border-green-500/20 rounded-md">
                      <p className="text-xs text-green-600 dark:text-green-400 flex items-center gap-2">
                        <CheckCircle className="h-3 w-3" />
                        Auto-deploy is active. Agents will be deployed to new {(autoDeployConfig?.assetTypes || []).join(", ")} instances.
                      </p>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Cloud Connections Grid */}
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
                {cloudConnections.map((conn) => (
                  <CloudConnectionCard
                    key={conn.id}
                    connection={conn}
                    onTest={() => testCloudMutation.mutate(conn.id)}
                    onDelete={() => deleteCloudMutation.mutate(conn.id)}
                    getStatusBadge={getStatusBadge}
                    testPending={testCloudMutation.isPending}
                  />
                ))}
              </div>
            </div>
          )}
        </TabsContent>

        <TabsContent value="dependencies" className="mt-4">
          <Card className="glass border-border/50 glow-purple-sm scan-line">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ArrowRight className="h-5 w-5 text-purple-400" />
                Asset Dependency Graph
              </CardTitle>
              <CardDescription>
                Visualize dependencies and data flows between infrastructure assets
              </CardDescription>
            </CardHeader>
            <CardContent>
              <AssetDependencyGraph
                nodes={(() => {
                  // Generate sample dependency nodes from cloud connections and vulnerabilities
                  const nodes: any[] = [];

                  // Add cloud assets as foundation nodes
                  cloudConnections.slice(0, 5).forEach((conn, i) => {
                    nodes.push({
                      id: `cloud-${conn.id}`,
                      name: conn.name,
                      type: conn.provider === "aws" ? "storage" : conn.provider === "azure" ? "database" : "service",
                      criticality: conn.status === "active" ? "high" : "medium",
                      dependencies: [],
                      vulnerabilityCount: 0,
                    });
                  });

                  // Add vulnerability hosts as dependent nodes
                  const hostMap = new Map();
                  vulnerabilities.slice(0, 10).forEach(vuln => {
                    if (vuln.affectedHost && !hostMap.has(vuln.affectedHost)) {
                      const cloudDeps = nodes.slice(0, Math.min(2, nodes.length)).map(n => n.id);
                      hostMap.set(vuln.affectedHost, {
                        id: `host-${vuln.affectedHost}`,
                        name: vuln.affectedHost,
                        type: vuln.affectedPort === 443 || vuln.affectedPort === 80 ? "load_balancer" : "application",
                        criticality: vuln.severity === "critical" || vuln.severity === "high" ? "critical" : "medium",
                        dependencies: cloudDeps,
                        vulnerabilityCount: vulnerabilities.filter(v => v.affectedHost === vuln.affectedHost).length,
                      });
                    }
                  });

                  nodes.push(...Array.from(hostMap.values()));

                  return nodes.length > 0 ? nodes : [
                    {
                      id: "db-1",
                      name: "Primary Database",
                      type: "database",
                      criticality: "critical",
                      dependencies: [],
                      vulnerabilityCount: 0,
                    },
                    {
                      id: "api-1",
                      name: "API Server",
                      type: "api",
                      criticality: "high",
                      dependencies: ["db-1"],
                      vulnerabilityCount: 2,
                    },
                    {
                      id: "lb-1",
                      name: "Load Balancer",
                      type: "load_balancer",
                      criticality: "high",
                      dependencies: ["api-1"],
                      vulnerabilityCount: 0,
                    },
                  ];
                })()}
                onNodeClick={(node) => {
                  // Handle node click - could show details dialog
                  console.log("Asset clicked:", node);
                }}
              />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
      </div>
    </div>
  );
}
