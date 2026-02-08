import { useState } from "react";
import { formatDistanceToNow } from "date-fns";
import {
  useSandboxSubmissions,
  useSandboxBehavior,
  useSandboxStats,
  useSubmitFile,
  useSubmitUrl,
  useDeleteSandboxSubmission,
  useReanalyzeSubmission,
  useDownloadSandboxReport,
  SandboxSubmission,
} from "@/hooks/useSandbox";
import { DataTable, DataTableColumn, DataTableAction } from "@/components/shared/DataTable";
import { MetricsGrid } from "@/components/shared/MetricsGrid";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import {
  FlaskConical,
  Upload,
  Link as LinkIcon,
  Eye,
  Download,
  Trash2,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2,
  Shield,
  Globe,
  HardDrive,
  Settings,
  Activity,
} from "lucide-react";

export default function Sandbox() {
  const { toast } = useToast();
  const [submitDialogOpen, setSubmitDialogOpen] = useState(false);
  const [submissionType, setSubmissionType] = useState<"file" | "url">("file");
  const [selectedSubmission, setSelectedSubmission] = useState<SandboxSubmission | null>(null);
  const [fileToUpload, setFileToUpload] = useState<File | null>(null);
  const [urlToSubmit, setUrlToSubmit] = useState("");

  const { data: stats } = useSandboxStats();
  const { data: submissions = [], isLoading } = useSandboxSubmissions();
  const { data: behavior } = useSandboxBehavior(selectedSubmission?.id || null);
  const submitFile = useSubmitFile();
  const submitUrl = useSubmitUrl();
  const deleteSubmission = useDeleteSandboxSubmission();
  const reanalyze = useReanalyzeSubmission();
  const downloadReport = useDownloadSandboxReport();

  const metrics = [
    {
      label: "Total Submissions",
      value: stats?.totalSubmissions || 0,
      icon: <FlaskConical className="h-4 w-4" />,
      trend: undefined,
    },
    {
      label: "Analyzing",
      value: stats?.activeAnalyses || 0,
      icon: <Loader2 className="h-4 w-4" />,
      trend: undefined,
    },
    {
      label: "Malicious",
      value: stats?.maliciousCount || 0,
      icon: <XCircle className="h-4 w-4" />,
      variant: (stats?.maliciousCount || 0) > 0 ? "danger" as const : undefined,
      trend: undefined,
    },
    {
      label: "Clean",
      value: stats?.cleanCount || 0,
      icon: <CheckCircle2 className="h-4 w-4" />,
      trend: undefined,
    },
  ];

  // Table columns
  const columns: DataTableColumn<SandboxSubmission>[] = [
    {
      key: "type",
      header: "Type",
      cell: (sub) => (
        <Badge variant="outline">
          {sub.type === "file" ? <HardDrive className="h-3 w-3 mr-1" /> : <Globe className="h-3 w-3 mr-1" />}
          {sub.type}
        </Badge>
      ),
      sortable: true,
    },
    {
      key: "fileName",
      header: "File/URL",
      cell: (sub) => (
        <div className="max-w-xs truncate">
          {sub.type === "file" ? (
            <span className="font-medium">{sub.fileName || "Unknown"}</span>
          ) : (
            <code className="text-xs">{sub.url || "Unknown"}</code>
          )}
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      cell: (sub) => {
        const statusConfig = {
          queued: { variant: "outline" as const, icon: AlertTriangle },
          analyzing: { variant: "default" as const, icon: Loader2 },
          completed: { variant: "outline" as const, icon: CheckCircle2 },
          failed: { variant: "destructive" as const, icon: XCircle },
        }[sub.status];

        const Icon = statusConfig.icon;

        return (
          <Badge variant={statusConfig.variant}>
            <Icon className={`h-3 w-3 mr-1 ${sub.status === "analyzing" ? "animate-spin" : ""}`} />
            {sub.status}
          </Badge>
        );
      },
      sortable: true,
    },
    {
      key: "verdict",
      header: "Verdict",
      cell: (sub) => {
        if (!sub.verdict) return <span className="text-sm text-muted-foreground">-</span>;

        const verdictConfig = {
          clean: { variant: "outline" as const, icon: CheckCircle2, color: "text-green-500" },
          suspicious: { variant: "secondary" as const, icon: AlertTriangle, color: "text-orange-500" },
          malicious: { variant: "destructive" as const, icon: XCircle, color: "text-red-500" },
        }[sub.verdict];

        const Icon = verdictConfig.icon;

        return (
          <Badge variant={verdictConfig.variant}>
            <Icon className={`h-3 w-3 mr-1 ${verdictConfig.color}`} />
            {sub.verdict}
          </Badge>
        );
      },
      sortable: true,
    },
    {
      key: "score",
      header: "Score",
      cell: (sub) => (
        sub.score !== undefined ? (
          <span className={`font-medium ${
            sub.score >= 8 ? "text-red-500" :
            sub.score >= 5 ? "text-orange-500" :
            "text-green-500"
          }`}>
            {sub.score.toFixed(1)}/10
          </span>
        ) : (
          <span className="text-sm text-muted-foreground">-</span>
        )
      ),
      sortable: true,
    },
    {
      key: "submittedAt",
      header: "Submitted",
      cell: (sub) => (
        <span className="text-sm text-muted-foreground">
          {formatDistanceToNow(new Date(sub.submittedAt), { addSuffix: true })}
        </span>
      ),
      sortable: true,
    },
  ];

  // Table actions
  const actions: DataTableAction<SandboxSubmission>[] = [
    {
      label: "View Analysis",
      icon: <Eye className="h-4 w-4" />,
      onClick: (sub) => setSelectedSubmission(sub),
      variant: "ghost",
    },
    {
      label: "Download Report",
      icon: <Download className="h-4 w-4" />,
      onClick: (sub) => downloadReport.mutate({ submissionId: sub.id, format: "pdf" }),
      variant: "ghost",
      hidden: (sub) => sub.status !== "completed",
      disabled: () => downloadReport.isPending,
    },
    {
      label: "Reanalyze",
      icon: <RefreshCw className="h-4 w-4" />,
      onClick: (sub) => reanalyze.mutate(sub.id),
      variant: "ghost",
      hidden: (sub) => sub.status !== "completed" && sub.status !== "failed",
      disabled: () => reanalyze.isPending,
    },
    {
      label: "Delete",
      icon: <Trash2 className="h-4 w-4" />,
      onClick: (sub) => deleteSubmission.mutate(sub.id),
      variant: "ghost",
      disabled: () => deleteSubmission.isPending,
    },
  ];

  const handleSubmit = async () => {
    if (submissionType === "file") {
      if (!fileToUpload) {
        toast({
          title: "No File Selected",
          description: "Please select a file to upload",
          variant: "destructive",
        });
        return;
      }
      await submitFile.mutateAsync({ file: fileToUpload });
      setFileToUpload(null);
    } else {
      if (!urlToSubmit.trim()) {
        toast({
          title: "No URL Entered",
          description: "Please enter a URL to analyze",
          variant: "destructive",
        });
        return;
      }
      await submitUrl.mutateAsync({ url: urlToSubmit });
      setUrlToSubmit("");
    }
    setSubmitDialogOpen(false);
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold" data-testid="text-page-title">
            Sandbox Analysis
          </h1>
          <p className="text-muted-foreground mt-1">
            Safe detonation environment for malware analysis
          </p>
        </div>
        <Dialog open={submitDialogOpen} onOpenChange={setSubmitDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Upload className="h-4 w-4 mr-2" />
              Submit for Analysis
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Submit for Sandbox Analysis</DialogTitle>
              <DialogDescription>
                Upload a file or submit a URL for safe detonation
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <Tabs value={submissionType} onValueChange={(v) => setSubmissionType(v as any)}>
                <TabsList className="grid w-full grid-cols-2">
                  <TabsTrigger value="file">File Upload</TabsTrigger>
                  <TabsTrigger value="url">URL</TabsTrigger>
                </TabsList>

                <TabsContent value="file" className="space-y-4">
                  <div className="space-y-2">
                    <Label>File</Label>
                    <Input
                      type="file"
                      onChange={(e) => setFileToUpload(e.target.files?.[0] || null)}
                    />
                    <p className="text-xs text-muted-foreground">
                      Upload a suspicious file for analysis
                    </p>
                  </div>
                  {fileToUpload && (
                    <div className="text-sm">
                      <span className="text-muted-foreground">Selected:</span>{" "}
                      <span className="font-medium">{fileToUpload.name}</span>
                      <span className="text-muted-foreground ml-2">
                        ({(fileToUpload.size / 1024).toFixed(2)} KB)
                      </span>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="url" className="space-y-4">
                  <div className="space-y-2">
                    <Label>URL</Label>
                    <Input
                      placeholder="https://example.com/suspicious-file"
                      value={urlToSubmit}
                      onChange={(e) => setUrlToSubmit(e.target.value)}
                    />
                    <p className="text-xs text-muted-foreground">
                      Enter a URL to analyze
                    </p>
                  </div>
                </TabsContent>
              </Tabs>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setSubmitDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleSubmit} disabled={submitFile.isPending || submitUrl.isPending}>
                {(submitFile.isPending || submitUrl.isPending) ? "Submitting..." : "Submit"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Metrics */}
      <MetricsGrid metrics={metrics} />

      {/* Submissions Table */}
      <Card>
        <CardHeader>
          <CardTitle>Analysis Queue</CardTitle>
          <CardDescription>
            Files and URLs submitted for sandbox analysis
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            data={submissions}
            columns={columns}
            actions={actions}
            isLoading={isLoading}
            emptyState={{
              icon: <FlaskConical className="h-12 w-12" />,
              title: "No Submissions",
              description: "Submit a file or URL for sandbox analysis",
              action: {
                label: "Submit for Analysis",
                onClick: () => setSubmitDialogOpen(true),
              },
            }}
            searchable={true}
            searchPlaceholder="Search submissions..."
            searchKeys={["fileName", "url", "fileHash"]}
            paginated={true}
            pageSize={20}
            data-testid="submissions-table"
          />
        </CardContent>
      </Card>

      {/* Analysis Details Dialog */}
      <Dialog open={!!selectedSubmission} onOpenChange={() => setSelectedSubmission(null)}>
        <DialogContent className="max-w-6xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Sandbox Analysis Report</DialogTitle>
            <DialogDescription>
              {selectedSubmission?.type === "file" ? selectedSubmission.fileName : selectedSubmission?.url}
            </DialogDescription>
          </DialogHeader>

          {selectedSubmission && (
            <Tabs defaultValue="summary" className="w-full">
              <TabsList className="grid w-full grid-cols-5">
                <TabsTrigger value="summary">Summary</TabsTrigger>
                <TabsTrigger value="network">Network</TabsTrigger>
                <TabsTrigger value="files">Files</TabsTrigger>
                <TabsTrigger value="registry">Registry</TabsTrigger>
                <TabsTrigger value="iocs">IOCs</TabsTrigger>
              </TabsList>

              <TabsContent value="summary" className="space-y-4">
                {/* Verdict Widget */}
                {selectedSubmission.verdict && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Shield className="h-5 w-5" />
                        Verdict
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex items-center gap-4">
                        <div className={`text-4xl font-bold ${
                          selectedSubmission.verdict === "malicious" ? "text-red-500" :
                          selectedSubmission.verdict === "suspicious" ? "text-orange-500" :
                          "text-green-500"
                        }`}>
                          {selectedSubmission.verdict.toUpperCase()}
                        </div>
                        {selectedSubmission.score !== undefined && (
                          <div>
                            <div className="text-2xl font-bold">{selectedSubmission.score.toFixed(1)}/10</div>
                            <div className="text-sm text-muted-foreground">Threat Score</div>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* File Info */}
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">Type:</span>{" "}
                    <Badge variant="outline">{selectedSubmission.type}</Badge>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Status:</span>{" "}
                    <Badge>{selectedSubmission.status}</Badge>
                  </div>
                  {selectedSubmission.fileSize && (
                    <div>
                      <span className="text-muted-foreground">File Size:</span>{" "}
                      <span className="font-medium">{(selectedSubmission.fileSize / 1024).toFixed(2)} KB</span>
                    </div>
                  )}
                  {selectedSubmission.fileHash && (
                    <div className="col-span-2">
                      <span className="text-muted-foreground">Hash:</span>{" "}
                      <code className="text-xs">{selectedSubmission.fileHash}</code>
                    </div>
                  )}
                </div>

                {/* MITRE ATT&CK Techniques */}
                {behavior && behavior.mitreAttackTechniques.length > 0 && (
                  <div>
                    <h3 className="font-medium mb-2">MITRE ATT&CK Techniques Detected</h3>
                    <div className="flex flex-wrap gap-2">
                      {behavior.mitreAttackTechniques.map(technique => (
                        <Badge key={technique.id} variant="destructive" className="gap-1">
                          <code className="text-xs">{technique.techniqueId}</code>
                          {technique.name}
                          <span className="text-xs">({(technique.confidence * 100).toFixed(0)}%)</span>
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </TabsContent>

              <TabsContent value="network" className="space-y-4">
                {behavior && behavior.networkActivity.length > 0 ? (
                  <div className="space-y-2">
                    {behavior.networkActivity.map(activity => (
                      <div key={activity.id} className={`p-3 rounded border ${activity.suspicious ? "border-red-500 bg-red-50 dark:bg-red-950" : "border-border"}`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Globe className="h-4 w-4" />
                            <code className="text-sm">{activity.sourceIp}:{activity.sourcePort} → {activity.destIp}:{activity.destPort}</code>
                            {activity.domain && (
                              <Badge variant="outline" className="text-xs">{activity.domain}</Badge>
                            )}
                          </div>
                          {activity.suspicious && <Badge variant="destructive">Suspicious</Badge>}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No network activity recorded</p>
                )}
              </TabsContent>

              <TabsContent value="files" className="space-y-4">
                {behavior && behavior.fileActivity.length > 0 ? (
                  <div className="space-y-2">
                    {behavior.fileActivity.map(activity => (
                      <div key={activity.id} className={`p-3 rounded border ${activity.suspicious ? "border-red-500 bg-red-50 dark:bg-red-950" : "border-border"}`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <HardDrive className="h-4 w-4" />
                            <Badge variant="outline" className="text-xs capitalize">{activity.action}</Badge>
                            <code className="text-sm">{activity.path}</code>
                          </div>
                          {activity.suspicious && <Badge variant="destructive">Suspicious</Badge>}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No file activity recorded</p>
                )}
              </TabsContent>

              <TabsContent value="registry" className="space-y-4">
                {behavior && behavior.registryActivity.length > 0 ? (
                  <div className="space-y-2">
                    {behavior.registryActivity.map(activity => (
                      <div key={activity.id} className={`p-3 rounded border ${activity.suspicious ? "border-red-500 bg-red-50 dark:bg-red-950" : "border-border"}`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Settings className="h-4 w-4" />
                            <Badge variant="outline" className="text-xs capitalize">{activity.action}</Badge>
                            <code className="text-sm">{activity.key}</code>
                          </div>
                          {activity.suspicious && <Badge variant="destructive">Suspicious</Badge>}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No registry activity recorded</p>
                )}
              </TabsContent>

              <TabsContent value="iocs" className="space-y-4">
                {behavior && behavior.iocs.length > 0 ? (
                  <div className="space-y-2">
                    {behavior.iocs.map((ioc, idx) => (
                      <div key={idx} className={`p-3 rounded border ${ioc.malicious ? "border-red-500 bg-red-50 dark:bg-red-950" : "border-border"}`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-xs uppercase">{ioc.type}</Badge>
                            <code className="text-sm">{ioc.value}</code>
                            {ioc.context && (
                              <span className="text-xs text-muted-foreground">({ioc.context})</span>
                            )}
                          </div>
                          {ioc.malicious && <Badge variant="destructive">Malicious</Badge>}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No IOCs extracted</p>
                )}
              </TabsContent>
            </Tabs>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
