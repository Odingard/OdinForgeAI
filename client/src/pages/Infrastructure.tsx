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
  Filter,
  Download,
  MoreVertical,
  Database,
  Globe,
  Shield
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

interface DiscoveredAsset {
  id: string;
  assetIdentifier: string;
  displayName: string | null;
  assetType: string;
  status: string | null;
  ipAddresses: string[] | null;
  hostname: string | null;
  fqdn: string | null;
  cloudProvider: string | null;
  cloudRegion: string | null;
  operatingSystem: string | null;
  criticality: string | null;
  environment: string | null;
  openPorts: Array<{port: number; protocol: string; service?: string}> | null;
  createdAt: string;
}

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

export default function Infrastructure() {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("assets");
  const [searchQuery, setSearchQuery] = useState("");
  const [importDialogOpen, setImportDialogOpen] = useState(false);
  const [cloudDialogOpen, setCloudDialogOpen] = useState(false);
  const [selectedAsset, setSelectedAsset] = useState<DiscoveredAsset | null>(null);

  // Queries
  const { data: stats, isLoading: statsLoading } = useQuery<InfraStats>({
    queryKey: ["/api/infrastructure/stats"],
  });

  const { data: assets = [], isLoading: assetsLoading } = useQuery<DiscoveredAsset[]>({
    queryKey: ["/api/assets"],
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

  // Import mutation
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

  // Create AEV evaluation from vulnerability
  const evaluateMutation = useMutation({
    mutationFn: async (vulnId: string) => {
      const res = await apiRequest("POST", `/api/vulnerabilities/${vulnId}/evaluate`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/vulnerabilities"] });
      toast({
        title: "Evaluation Started",
        description: "AEV analysis has been initiated for this vulnerability",
      });
    },
  });

  // Delete import job
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

  // Create cloud connection
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

  // Test cloud connection
  const testCloudMutation = useMutation({
    mutationFn: async (id: string) => {
      return apiRequest("POST", `/api/cloud-connections/${id}/test`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/cloud-connections"] });
      toast({ title: "Connection Test Successful" });
    },
  });

  // Delete cloud connection
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

  const getAssetTypeIcon = (type: string) => {
    switch(type) {
      case "database": return <Database className="h-4 w-4" />;
      case "web_application": return <Globe className="h-4 w-4" />;
      case "cloud_instance": return <Cloud className="h-4 w-4" />;
      case "firewall": return <Shield className="h-4 w-4" />;
      default: return <Server className="h-4 w-4" />;
    }
  };

  const filteredAssets = assets.filter(a => 
    a.assetIdentifier.toLowerCase().includes(searchQuery.toLowerCase()) ||
    a.displayName?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    a.hostname?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredVulns = vulnerabilities.filter(v =>
    v.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    v.cveId?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    v.affectedHost?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6" data-testid="infrastructure-page">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Infrastructure</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage discovered assets, vulnerability imports, and cloud connections
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Dialog open={importDialogOpen} onOpenChange={setImportDialogOpen}>
            <DialogTrigger asChild>
              <Button data-testid="button-import">
                <Upload className="h-4 w-4 mr-2" />
                Import
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

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Assets</CardTitle>
            <Server className="h-4 w-4 text-cyan-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="stat-total-assets">
              {statsLoading ? "..." : stats?.totalAssets || 0}
            </div>
          </CardContent>
        </Card>

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
            <CardTitle className="text-sm font-medium text-muted-foreground">Critical</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-400" data-testid="stat-critical">
              {statsLoading ? "..." : stats?.criticalVulns || 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">High</CardTitle>
            <AlertTriangle className="h-4 w-4 text-orange-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-400" data-testid="stat-high">
              {statsLoading ? "..." : stats?.highVulns || 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Pending</CardTitle>
            <RefreshCw className="h-4 w-4 text-blue-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="stat-pending">
              {statsLoading ? "..." : stats?.pendingImports || 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Cloud</CardTitle>
            <Cloud className="h-4 w-4 text-emerald-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="stat-cloud">
              {statsLoading ? "..." : stats?.cloudConnections || 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Search */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search assets, vulnerabilities..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9"
            data-testid="input-search"
          />
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="assets" data-testid="tab-assets">
            <Server className="h-4 w-4 mr-2" />
            Assets ({assets.length})
          </TabsTrigger>
          <TabsTrigger value="vulnerabilities" data-testid="tab-vulnerabilities">
            <AlertTriangle className="h-4 w-4 mr-2" />
            Vulnerabilities ({vulnerabilities.length})
          </TabsTrigger>
          <TabsTrigger value="imports" data-testid="tab-imports">
            <Upload className="h-4 w-4 mr-2" />
            Imports ({importJobs.length})
          </TabsTrigger>
          <TabsTrigger value="cloud" data-testid="tab-cloud">
            <Cloud className="h-4 w-4 mr-2" />
            Cloud ({cloudConnections.length})
          </TabsTrigger>
        </TabsList>

        {/* Assets Tab */}
        <TabsContent value="assets" className="mt-4">
          {assetsLoading ? (
            <div className="text-center py-12 text-muted-foreground">Loading assets...</div>
          ) : filteredAssets.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Server className="h-12 w-12 mx-auto mb-3 text-muted-foreground opacity-30" />
                <p className="text-muted-foreground">No assets discovered yet</p>
                <p className="text-sm text-muted-foreground mt-1">Import a scanner file to discover assets</p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>IP / Hostname</TableHead>
                    <TableHead>Environment</TableHead>
                    <TableHead>Ports</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="w-[100px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredAssets.map((asset) => (
                    <TableRow key={asset.id} data-testid={`row-asset-${asset.id}`}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <div className="p-1.5 rounded bg-muted text-cyan-400">
                            {getAssetTypeIcon(asset.assetType)}
                          </div>
                          <div>
                            <div className="font-medium">{asset.displayName || asset.assetIdentifier}</div>
                            {asset.displayName && (
                              <div className="text-xs text-muted-foreground">{asset.assetIdentifier}</div>
                            )}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-xs">
                          {asset.assetType.replace("_", " ")}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="text-sm">
                          {asset.ipAddresses?.[0] || asset.hostname || "-"}
                        </div>
                        {asset.fqdn && (
                          <div className="text-xs text-muted-foreground">{asset.fqdn}</div>
                        )}
                      </TableCell>
                      <TableCell>
                        {asset.environment ? (
                          <Badge variant="outline" className="text-xs">{asset.environment}</Badge>
                        ) : "-"}
                      </TableCell>
                      <TableCell>
                        <span className="text-sm font-mono">
                          {asset.openPorts?.length || 0}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge className={getStatusBadge(asset.status || "active")}>
                          {asset.status || "active"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" data-testid={`button-asset-actions-${asset.id}`}>
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => setSelectedAsset(asset)}>
                              <Eye className="h-4 w-4 mr-2" />
                              View Details
                            </DropdownMenuItem>
                            <DropdownMenuItem>
                              <Play className="h-4 w-4 mr-2" />
                              Run Evaluation
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          )}
        </TabsContent>

        {/* Vulnerabilities Tab */}
        <TabsContent value="vulnerabilities" className="mt-4">
          {vulnsLoading ? (
            <div className="text-center py-12 text-muted-foreground">Loading vulnerabilities...</div>
          ) : filteredVulns.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <AlertTriangle className="h-12 w-12 mx-auto mb-3 text-muted-foreground opacity-30" />
                <p className="text-muted-foreground">No vulnerabilities imported yet</p>
                <p className="text-sm text-muted-foreground mt-1">Import a scanner file to see vulnerabilities</p>
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
                    <TableHead>Port</TableHead>
                    <TableHead>Status</TableHead>
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
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-sm">{vuln.affectedPort || "-"}</span>
                      </TableCell>
                      <TableCell>
                        {vuln.aevEvaluationId ? (
                          <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                            Evaluated
                          </Badge>
                        ) : (
                          <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/30">
                            {vuln.status || "open"}
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
                            <DropdownMenuItem>
                              <Eye className="h-4 w-4 mr-2" />
                              View Details
                            </DropdownMenuItem>
                            {!vuln.aevEvaluationId && (
                              <DropdownMenuItem
                                onClick={() => evaluateMutation.mutate(vuln.id)}
                                disabled={evaluateMutation.isPending}
                              >
                                <Play className="h-4 w-4 mr-2" />
                                Run AEV Analysis
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
        </TabsContent>

        {/* Imports Tab */}
        <TabsContent value="imports" className="mt-4">
          {jobsLoading ? (
            <div className="text-center py-12 text-muted-foreground">Loading imports...</div>
          ) : importJobs.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Upload className="h-12 w-12 mx-auto mb-3 text-muted-foreground opacity-30" />
                <p className="text-muted-foreground">No import jobs yet</p>
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
            <div className="grid gap-4">
              {importJobs.map((job) => (
                <Card key={job.id} data-testid={`card-import-${job.id}`}>
                  <CardHeader className="flex flex-row items-center justify-between gap-4 pb-2">
                    <div>
                      <CardTitle className="text-base">{job.name}</CardTitle>
                      <CardDescription className="flex items-center gap-2 mt-1">
                        <Badge variant="outline" className="text-xs">{job.sourceType}</Badge>
                        <span>
                          {new Date(job.createdAt).toLocaleString()}
                        </span>
                      </CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
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
                  <CardContent>
                    <div className="flex items-center gap-6 text-sm">
                      <div>
                        <span className="text-muted-foreground">Records:</span>
                        <span className="ml-2 font-mono">{job.totalRecords || 0}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Assets:</span>
                        <span className="ml-2 font-mono text-cyan-400">{job.assetsDiscovered || 0}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Vulnerabilities:</span>
                        <span className="ml-2 font-mono text-amber-400">{job.vulnerabilitiesFound || 0}</span>
                      </div>
                    </div>
                    {job.status === "processing" && (
                      <Progress value={job.progress} className="mt-3 h-1" />
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* Cloud Tab */}
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
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
              {cloudConnections.map((conn) => (
                <Card key={conn.id} data-testid={`card-cloud-${conn.id}`}>
                  <CardHeader className="flex flex-row items-center justify-between gap-4 pb-2">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-muted">
                        <Cloud className="h-5 w-5 text-cyan-400" />
                      </div>
                      <div>
                        <CardTitle className="text-base">{conn.name}</CardTitle>
                        <CardDescription>{conn.provider.toUpperCase()}</CardDescription>
                      </div>
                    </div>
                    <Badge className={getStatusBadge(conn.status)}>
                      {conn.status}
                    </Badge>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">Assets Discovered</span>
                        <span className="font-mono">{conn.assetsDiscovered || 0}</span>
                      </div>
                      {conn.lastSyncAt && (
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground">Last Sync</span>
                          <span>{new Date(conn.lastSyncAt).toLocaleString()}</span>
                        </div>
                      )}
                      <div className="flex items-center gap-2 pt-2">
                        <Button
                          size="sm"
                          variant="outline"
                          className="flex-1"
                          onClick={() => testCloudMutation.mutate(conn.id)}
                          disabled={testCloudMutation.isPending}
                          data-testid={`button-test-cloud-${conn.id}`}
                        >
                          <RefreshCw className="h-3 w-3 mr-1" />
                          Sync
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => deleteCloudMutation.mutate(conn.id)}
                          data-testid={`button-delete-cloud-${conn.id}`}
                        >
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* Asset Detail Dialog */}
      <Dialog open={!!selectedAsset} onOpenChange={() => setSelectedAsset(null)}>
        <DialogContent className="max-w-2xl">
          {selectedAsset && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  {getAssetTypeIcon(selectedAsset.assetType)}
                  {selectedAsset.displayName || selectedAsset.assetIdentifier}
                </DialogTitle>
                <DialogDescription>
                  {selectedAsset.assetType.replace("_", " ")} - {selectedAsset.status}
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">Identifier</span>
                    <p className="font-mono">{selectedAsset.assetIdentifier}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Hostname</span>
                    <p className="font-mono">{selectedAsset.hostname || "-"}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">IP Addresses</span>
                    <p className="font-mono">{selectedAsset.ipAddresses?.join(", ") || "-"}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">FQDN</span>
                    <p className="font-mono">{selectedAsset.fqdn || "-"}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Operating System</span>
                    <p>{selectedAsset.operatingSystem || "-"}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Cloud Provider</span>
                    <p>{selectedAsset.cloudProvider?.toUpperCase() || "-"}</p>
                  </div>
                </div>
                {selectedAsset.openPorts && selectedAsset.openPorts.length > 0 && (
                  <div>
                    <span className="text-muted-foreground text-sm">Open Ports</span>
                    <div className="flex flex-wrap gap-2 mt-2">
                      {selectedAsset.openPorts.map((port, i) => (
                        <Badge key={i} variant="outline" className="font-mono">
                          {port.port}/{port.protocol}
                          {port.service && ` (${port.service})`}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
