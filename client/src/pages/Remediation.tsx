import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  Wrench,
  GitPullRequest,
  Settings,
  ExternalLink,
  CheckCircle2,
  XCircle,
  Clock,
  Code,
  FileCode,
  AlertCircle,
  RefreshCw,
  Github,
  GitBranch,
  FileText,
} from "lucide-react";
import { format } from "date-fns";

interface GitConfig {
  provider: "github" | "gitlab";
  token: string;
  baseUrl?: string;
  configured: boolean;
}

interface Finding {
  id: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  affectedResource: string;
  evaluationId?: string;
  hasRemediation: boolean;
}

interface PRStatus {
  id: string;
  status: "created" | "merged" | "closed" | "pending";
  url?: string;
  branchName: string;
  title: string;
  filesChanged: number;
  createdAt?: string;
}

export default function Remediation() {
  const { toast } = useToast();
  const [gitConfigOpen, setGitConfigOpen] = useState(false);
  const [createPROpen, setCreatePROpen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [gitConfig, setGitConfig] = useState<Partial<GitConfig>>({
    provider: "github",
  });
  const [prConfig, setPRConfig] = useState({
    repositoryUrl: "",
    branchName: "",
    labels: "security,odinforge,automated-fix",
    reviewers: "",
  });

  // Mock findings data - in production, fetch from API
  const mockFindings: Finding[] = [
    {
      id: "finding-1",
      type: "s3_public_access",
      severity: "critical",
      title: "S3 Bucket Publicly Accessible",
      description: "S3 bucket allows public read access",
      affectedResource: "production-data-bucket",
      evaluationId: "eval-123",
      hasRemediation: true,
    },
    {
      id: "finding-2",
      type: "iam_admin_policy",
      severity: "high",
      title: "IAM Policy Grants Admin Access",
      description: "IAM policy uses wildcard permissions",
      affectedResource: "app-service-role",
      evaluationId: "eval-123",
      hasRemediation: true,
    },
    {
      id: "finding-3",
      type: "security_group_open",
      severity: "high",
      title: "Security Group Allows 0.0.0.0/0",
      description: "Security group allows unrestricted inbound access",
      affectedResource: "web-server-sg",
      evaluationId: "eval-124",
      hasRemediation: true,
    },
  ];

  // Mock PR status data
  const [prStatuses, setPRStatuses] = useState<PRStatus[]>([
    {
      id: "gh-pr-42",
      status: "created",
      url: "https://github.com/example/infrastructure/pull/42",
      branchName: "odinforge-fix-s3-public-access",
      title: "[OdinForge] Fix: S3 Public Access",
      filesChanged: 2,
      createdAt: new Date().toISOString(),
    },
  ]);

  // Configure Git mutation
  const configureGitMutation = useMutation({
    mutationFn: async (config: Partial<GitConfig>) => {
      return apiRequest("POST", "/api/remediation/configure-pr", config);
    },
    onSuccess: () => {
      toast({
        title: "Git Configuration Saved",
        description: `${gitConfig.provider} credentials configured successfully`,
      });
      setGitConfigOpen(false);
      queryClient.invalidateQueries({ queryKey: ["/api/remediation/config"] });
    },
    onError: (error: any) => {
      toast({
        title: "Configuration Failed",
        description: error.message || "Failed to configure Git credentials",
        variant: "destructive",
      });
    },
  });

  // Create PR mutation
  const createPRMutation = useMutation({
    mutationFn: async ({ findingId, config }: { findingId: string; config: typeof prConfig }) => {
      return apiRequest("POST", `/api/remediation/${findingId}/create-pr`, {
        repositoryUrl: config.repositoryUrl,
        branchName: config.branchName || undefined,
        labels: config.labels.split(",").map(l => l.trim()).filter(Boolean),
        reviewers: config.reviewers.split(",").map(r => r.trim()).filter(Boolean),
      });
    },
    onSuccess: (data: any) => {
      toast({
        title: "Pull Request Created",
        description: `PR created successfully`,
      });
      if (data.pr) {
        setPRStatuses(prev => [...prev, {
          ...data.pr,
          createdAt: new Date().toISOString(),
        }]);
      }
      setCreatePROpen(false);
      setPRConfig({
        repositoryUrl: "",
        branchName: "",
        labels: "security,odinforge,automated-fix",
        reviewers: "",
      });
    },
    onError: (error: any) => {
      toast({
        title: "PR Creation Failed",
        description: error.message || "Failed to create pull request",
        variant: "destructive",
      });
    },
  });

  const handleConfigureGit = () => {
    if (!gitConfig.provider || !gitConfig.token) {
      toast({
        title: "Missing Required Fields",
        description: "Provider and token are required",
        variant: "destructive",
      });
      return;
    }
    configureGitMutation.mutate(gitConfig);
  };

  const handleCreatePR = () => {
    if (!selectedFinding || !prConfig.repositoryUrl) {
      toast({
        title: "Missing Required Fields",
        description: "Finding and repository URL are required",
        variant: "destructive",
      });
      return;
    }
    createPRMutation.mutate({
      findingId: selectedFinding.id,
      config: prConfig,
    });
  };

  const openCreatePRDialog = (finding: Finding) => {
    setSelectedFinding(finding);
    setCreatePROpen(true);
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "critical":
        return <Badge variant="destructive">Critical</Badge>;
      case "high":
        return <Badge className="bg-orange-500 hover:bg-orange-600">High</Badge>;
      case "medium":
        return <Badge className="bg-yellow-500 hover:bg-yellow-600">Medium</Badge>;
      case "low":
        return <Badge variant="outline">Low</Badge>;
      default:
        return <Badge variant="outline">{severity}</Badge>;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "created":
        return <Badge className="bg-blue-500 hover:bg-blue-600 gap-1"><GitPullRequest className="h-3 w-3" />Open</Badge>;
      case "merged":
        return <Badge className="bg-purple-500 hover:bg-purple-600 gap-1"><CheckCircle2 className="h-3 w-3" />Merged</Badge>;
      case "closed":
        return <Badge variant="secondary" className="gap-1"><XCircle className="h-3 w-3" />Closed</Badge>;
      case "pending":
        return <Badge variant="outline" className="gap-1"><Clock className="h-3 w-3" />Pending</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
            <Wrench className="h-8 w-8 text-primary" />
            Remediation Center
          </h1>
          <p className="text-muted-foreground mt-1">
            Automated security fixes and pull request management
          </p>
        </div>
        <Button onClick={() => setGitConfigOpen(true)} className="gap-2">
          <Settings className="h-4 w-4" />
          Configure Git
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-red-500" />
              Findings with Fixes
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{mockFindings.length}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <GitPullRequest className="h-4 w-4 text-blue-500" />
              Active PRs
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">
              {prStatuses.filter(pr => pr.status === "created").length}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-green-500" />
              Merged Fixes
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">
              {prStatuses.filter(pr => pr.status === "merged").length}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <FileCode className="h-4 w-4 text-purple-500" />
              Total Changes
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">
              {prStatuses.reduce((acc, pr) => acc + pr.filesChanged, 0)}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Tabs */}
      <Tabs defaultValue="findings" className="space-y-4">
        <TabsList>
          <TabsTrigger value="findings">Available Fixes</TabsTrigger>
          <TabsTrigger value="prs">Pull Requests</TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Security Findings with Automated Remediation</CardTitle>
              <CardDescription>
                Findings that can be automatically fixed with IaC or code patches
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Severity</TableHead>
                    <TableHead>Finding</TableHead>
                    <TableHead>Resource</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {mockFindings.map((finding) => (
                    <TableRow key={finding.id}>
                      <TableCell>{getSeverityBadge(finding.severity)}</TableCell>
                      <TableCell>
                        <div className="font-medium">{finding.title}</div>
                        <div className="text-sm text-muted-foreground">
                          {finding.description}
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {finding.affectedResource}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{finding.type}</Badge>
                      </TableCell>
                      <TableCell className="text-right space-x-2">
                        <Button
                          size="sm"
                          onClick={() => openCreatePRDialog(finding)}
                          className="gap-2"
                        >
                          <GitPullRequest className="h-4 w-4" />
                          Create PR
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="prs" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Created Pull Requests</CardTitle>
              <CardDescription>
                Track the status of automated remediation PRs
              </CardDescription>
            </CardHeader>
            <CardContent>
              {prStatuses.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <GitBranch className="h-12 w-12 text-muted-foreground mb-3" />
                  <h3 className="text-lg font-semibold">No Pull Requests Yet</h3>
                  <p className="text-muted-foreground text-sm max-w-md mt-1">
                    Create your first automated PR from the Available Fixes tab
                  </p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Status</TableHead>
                      <TableHead>Title</TableHead>
                      <TableHead>Branch</TableHead>
                      <TableHead>Files</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {prStatuses.map((pr) => (
                      <TableRow key={pr.id}>
                        <TableCell>{getStatusBadge(pr.status)}</TableCell>
                        <TableCell className="font-medium">{pr.title}</TableCell>
                        <TableCell className="font-mono text-sm">{pr.branchName}</TableCell>
                        <TableCell>{pr.filesChanged} files</TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {pr.createdAt ? format(new Date(pr.createdAt), "MMM d, HH:mm") : "—"}
                        </TableCell>
                        <TableCell className="text-right">
                          {pr.url && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => window.open(pr.url, "_blank")}
                              className="gap-2"
                            >
                              <ExternalLink className="h-4 w-4" />
                              View PR
                            </Button>
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
      </Tabs>

      {/* Configure Git Dialog */}
      <Dialog open={gitConfigOpen} onOpenChange={setGitConfigOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Github className="h-5 w-5" />
              Configure Git Integration
            </DialogTitle>
            <DialogDescription>
              Set up GitHub or GitLab credentials for automated PR creation
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <Label htmlFor="provider">Provider</Label>
              <Select
                value={gitConfig.provider}
                onValueChange={(value: "github" | "gitlab") =>
                  setGitConfig({ ...gitConfig, provider: value })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="github">GitHub</SelectItem>
                  <SelectItem value="gitlab">GitLab</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="token">Personal Access Token</Label>
              <Input
                id="token"
                type="password"
                placeholder={gitConfig.provider === "github" ? "ghp_..." : "glpat-..."}
                value={gitConfig.token || ""}
                onChange={(e) => setGitConfig({ ...gitConfig, token: e.target.value })}
              />
              <p className="text-xs text-muted-foreground mt-1">
                {gitConfig.provider === "github"
                  ? "Generate at: Settings → Developer settings → Personal access tokens"
                  : "Generate at: Settings → Access Tokens"}
              </p>
            </div>

            <div>
              <Label htmlFor="baseUrl">Base URL (Optional)</Label>
              <Input
                id="baseUrl"
                placeholder={gitConfig.provider === "github" ? "https://api.github.com" : "https://gitlab.com"}
                value={gitConfig.baseUrl || ""}
                onChange={(e) => setGitConfig({ ...gitConfig, baseUrl: e.target.value })}
              />
              <p className="text-xs text-muted-foreground mt-1">
                Only needed for self-hosted instances
              </p>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setGitConfigOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleConfigureGit}
              disabled={configureGitMutation.isPending}
              className="gap-2"
            >
              {configureGitMutation.isPending ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                <CheckCircle2 className="h-4 w-4" />
              )}
              Save Configuration
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create PR Dialog */}
      <Dialog open={createPROpen} onOpenChange={setCreatePROpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <GitPullRequest className="h-5 w-5" />
              Create Pull Request
            </DialogTitle>
            <DialogDescription>
              Generate automated remediation PR for: {selectedFinding?.title}
            </DialogDescription>
          </DialogHeader>

          {selectedFinding && (
            <div className="space-y-4">
              {/* Finding Info */}
              <Card className="bg-muted/50">
                <CardContent className="pt-4">
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <div>
                      <span className="text-muted-foreground">Severity:</span>{" "}
                      {getSeverityBadge(selectedFinding.severity)}
                    </div>
                    <div>
                      <span className="text-muted-foreground">Resource:</span>{" "}
                      <code className="text-xs">{selectedFinding.affectedResource}</code>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <div>
                <Label htmlFor="repoUrl">Repository URL *</Label>
                <Input
                  id="repoUrl"
                  placeholder="https://github.com/your-org/infrastructure"
                  value={prConfig.repositoryUrl}
                  onChange={(e) => setPRConfig({ ...prConfig, repositoryUrl: e.target.value })}
                />
              </div>

              <div>
                <Label htmlFor="branch">Branch Name (Optional)</Label>
                <Input
                  id="branch"
                  placeholder={`odinforge-fix-${selectedFinding.id}`}
                  value={prConfig.branchName}
                  onChange={(e) => setPRConfig({ ...prConfig, branchName: e.target.value })}
                />
              </div>

              <div>
                <Label htmlFor="labels">Labels (comma-separated)</Label>
                <Input
                  id="labels"
                  placeholder="security, odinforge, automated-fix"
                  value={prConfig.labels}
                  onChange={(e) => setPRConfig({ ...prConfig, labels: e.target.value })}
                />
              </div>

              <div>
                <Label htmlFor="reviewers">Reviewers (comma-separated)</Label>
                <Input
                  id="reviewers"
                  placeholder="security-team, devops-lead"
                  value={prConfig.reviewers}
                  onChange={(e) => setPRConfig({ ...prConfig, reviewers: e.target.value })}
                />
              </div>
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setCreatePROpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleCreatePR}
              disabled={createPRMutation.isPending}
              className="gap-2 bg-green-600 hover:bg-green-700"
            >
              {createPRMutation.isPending ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                <GitPullRequest className="h-4 w-4" />
              )}
              Create Pull Request
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
