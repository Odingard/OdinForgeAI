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
  ArrowRight
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
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
      const res = await apiRequest("POST", `/api/cloud-connections/${connection.id}/credentials`, credentials);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cloud-connections"] });
      setCredentialsDialogOpen(false);
      toast({ title: "Credentials Updated" });
    },
    onError: () => {
      toast({ title: "Failed to update credentials", variant: "destructive" });
    },
  });

  const deployAgentMutation = useMutation({
    mutationFn: async (assetId: string) => {
      const res = await apiRequest("POST", `/api/cloud-assets/${assetId}/deploy-agent`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cloud-connections", connection.id, "assets"] });
      toast({ title: "Agent Deployment Started" });
    },
  });

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
                         (asset.agentDeploymentStatus !== "pending" || !asset.agentId) && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => deployAgentMutation.mutate(asset.id)}
                            disabled={deployAgentMutation.isPending}
                            data-testid={`button-deploy-agent-${asset.id}`}
                            title="Deploy Agent"
                          >
                            <Play className="h-3 w-3" />
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
    <div className="space-y-6" data-testid="data-sources-page">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Data Sources</h1>
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
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Vulnerabilities</CardTitle>
            <AlertTriangle className="h-4 w-4 text-amber-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="stat-total-vulns">
              {statsLoading ? "..." : stats?.totalVulnerabilities || 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Awaiting Analysis</CardTitle>
            <Zap className="h-4 w-4 text-blue-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-400" data-testid="stat-unevaluated">
              {unevaluatedCount}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Evaluated</CardTitle>
            <CheckCircle className="h-4 w-4 text-emerald-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-emerald-400" data-testid="stat-evaluated">
              {evaluatedCount}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Cloud Connections</CardTitle>
            <Cloud className="h-4 w-4 text-cyan-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="stat-cloud">
              {statsLoading ? "..." : stats?.cloudConnections || 0}
            </div>
          </CardContent>
        </Card>
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
      </Tabs>
    </div>
  );
}
