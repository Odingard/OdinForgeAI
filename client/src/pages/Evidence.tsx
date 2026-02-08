import { useState } from "react";
import { formatDistanceToNow } from "date-fns";
import {
  useEvidence,
  useEvidenceSummary,
  useUploadEvidence,
  useDeleteEvidence,
  useVerifyEvidence,
  Evidence as EvidenceType,
} from "@/hooks/useEvidence";
import { MetricsGrid, Metric } from "@/components/shared/MetricsGrid";
import { FilterBar, Filter } from "@/components/shared/FilterBar";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import {
  FileCheck,
  Upload,
  Trash2,
  Download,
  Shield,
  FileImage,
  FileText,
  Network,
  File,
  CheckCircle2,
  AlertCircle,
  HardDrive,
} from "lucide-react";
import { EnhancedEmptyState } from "@/components/shared/EnhancedEmptyState";

export default function Evidence() {
  const { toast } = useToast();
  const [typeFilter, setTypeFilter] = useState("all");
  const [uploadDialogOpen, setUploadDialogOpen] = useState(false);
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceType | null>(null);

  // Upload form state
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadType, setUploadType] = useState("screenshot");
  const [uploadDescription, setUploadDescription] = useState("");
  const [uploadEvaluationId, setUploadEvaluationId] = useState("");

  // Fetch evidence with filters
  const filters = typeFilter !== "all" ? { type: typeFilter } : undefined;
  const { data: evidence = [], isLoading } = useEvidence(filters);
  const { data: summary } = useEvidenceSummary();

  // Mutations
  const uploadEvidence = useUploadEvidence();
  const deleteEvidence = useDeleteEvidence();
  const verifyEvidence = useVerifyEvidence();

  // Metrics
  const metrics: Metric[] = [
    {
      label: "Total Evidence",
      value: summary?.total || 0,
      icon: FileCheck,
      iconColor: "text-cyan-400",
      "data-testid": "metric-total-evidence",
    },
    {
      label: "Unverified",
      value: summary?.unverified || 0,
      icon: AlertCircle,
      iconColor: "text-amber-500",
      valueColor: summary && summary.unverified > 0 ? "text-amber-600" : "",
      "data-testid": "metric-unverified",
    },
    {
      label: "Storage Used",
      value: `${summary?.storageUsedMB.toFixed(1) || 0} MB`,
      icon: HardDrive,
      iconColor: "text-purple-500",
      "data-testid": "metric-storage",
    },
  ];

  // Filter definitions
  const filterDefinitions: Filter[] = [
    {
      key: "type",
      label: "Evidence Type",
      options: [
        { label: "All Types", value: "all" },
        { label: "Screenshots", value: "screenshot" },
        { label: "Logs", value: "log" },
        { label: "Network Captures", value: "network_capture" },
        { label: "Files", value: "file" },
        { label: "Reports", value: "report" },
      ],
      defaultValue: "all",
    },
  ];

  const filterValues = { type: typeFilter };

  const handleFilterChange = (key: string, value: string) => {
    if (key === "type") setTypeFilter(value);
  };

  const handleFilterReset = () => {
    setTypeFilter("all");
  };

  const handleUpload = async () => {
    if (!uploadFile || !uploadEvaluationId) {
      toast({
        title: "Missing Information",
        description: "Please select a file and enter evaluation ID",
        variant: "destructive",
      });
      return;
    }

    await uploadEvidence.mutateAsync({
      evaluationId: uploadEvaluationId,
      type: uploadType,
      file: uploadFile,
      description: uploadDescription,
    });

    // Reset form
    setUploadFile(null);
    setUploadDescription("");
    setUploadEvaluationId("");
    setUploadDialogOpen(false);
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "screenshot":
        return FileImage;
      case "log":
      case "report":
        return FileText;
      case "network_capture":
        return Network;
      default:
        return File;
    }
  };

  const handleDownload = (evidenceItem: EvidenceType) => {
    toast({
      title: "Download Started",
      description: `Downloading ${evidenceItem.fileName || "evidence"}`,
    });
    // In real implementation, would fetch from /api/evidence/:id/download
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold" data-testid="text-page-title">
            Evidence Management
          </h1>
          <p className="text-muted-foreground mt-1">
            Collect, verify, and manage forensic evidence
          </p>
        </div>
        <Dialog open={uploadDialogOpen} onOpenChange={setUploadDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Upload className="h-4 w-4 mr-2" />
              Upload Evidence
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Upload Evidence</DialogTitle>
              <DialogDescription>
                Upload forensic evidence for an evaluation
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label>Evaluation ID</Label>
                <Input
                  placeholder="eval-123..."
                  value={uploadEvaluationId}
                  onChange={(e) => setUploadEvaluationId(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label>Evidence Type</Label>
                <Select value={uploadType} onValueChange={setUploadType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="screenshot">Screenshot</SelectItem>
                    <SelectItem value="log">Log File</SelectItem>
                    <SelectItem value="network_capture">Network Capture</SelectItem>
                    <SelectItem value="file">File</SelectItem>
                    <SelectItem value="report">Report</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>File</Label>
                <Input
                  type="file"
                  onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                />
              </div>
              <div className="space-y-2">
                <Label>Description (Optional)</Label>
                <Textarea
                  placeholder="Describe this evidence..."
                  value={uploadDescription}
                  onChange={(e) => setUploadDescription(e.target.value)}
                  rows={3}
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setUploadDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleUpload} disabled={uploadEvidence.isPending}>
                {uploadEvidence.isPending ? "Uploading..." : "Upload"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Metrics Grid */}
      <MetricsGrid metrics={metrics} columns={3} data-testid="evidence-metrics" />

      {/* Filters */}
      <FilterBar
        filters={filterDefinitions}
        values={filterValues}
        onChange={handleFilterChange}
        onReset={handleFilterReset}
        data-testid="evidence-filters"
      />

      {/* Evidence Gallery */}
      <Card>
        <CardHeader>
          <CardTitle>Evidence Collection</CardTitle>
          <CardDescription>
            Forensic evidence gathered during security evaluations
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-12 text-muted-foreground">
              Loading evidence...
            </div>
          ) : evidence.length === 0 ? (
            <EnhancedEmptyState
              icon={FileCheck}
              title="No Evidence Found"
              description="Upload forensic evidence from security evaluations to build your investigation collection"
              primaryAction={{
                label: "Upload First Evidence",
                onClick: () => setUploadDialogOpen(true),
                icon: Upload,
              }}
              showDemoButton={true}
              steps={[
                "Upload screenshots, logs, or network captures",
                "Link evidence to specific evaluations",
                "Verify file integrity with hash validation",
                "Build comprehensive forensic timelines"
              ]}
            />
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {evidence.map((item) => {
                const TypeIcon = getTypeIcon(item.type);

                return (
                  <Card key={item.id} className="hover-elevate">
                    <CardHeader className="pb-3">
                      <div className="flex items-start justify-between">
                        <div className="flex items-center gap-2">
                          <TypeIcon className="h-4 w-4 text-muted-foreground" />
                          <CardTitle className="text-sm font-medium capitalize">
                            {item.type.replace(/_/g, " ")}
                          </CardTitle>
                        </div>
                        {item.verified ? (
                          <Badge variant="outline">
                            <CheckCircle2 className="h-3 w-3 mr-1 text-green-500" />
                            Verified
                          </Badge>
                        ) : (
                          <Badge variant="secondary">
                            <AlertCircle className="h-3 w-3 mr-1" />
                            Unverified
                          </Badge>
                        )}
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {item.fileName && (
                        <div className="text-xs">
                          <span className="text-muted-foreground">File:</span>{" "}
                          <code className="text-xs">{item.fileName}</code>
                        </div>
                      )}
                      {item.description && (
                        <p className="text-sm text-muted-foreground line-clamp-2">
                          {item.description}
                        </p>
                      )}
                      <div className="flex items-center justify-between text-xs text-muted-foreground">
                        <span>
                          {formatDistanceToNow(new Date(item.createdAt), { addSuffix: true })}
                        </span>
                        {item.fileSize && (
                          <span>{(item.fileSize / 1024).toFixed(1)} KB</span>
                        )}
                      </div>
                      {item.hash && (
                        <div className="text-xs">
                          <span className="text-muted-foreground">Hash:</span>{" "}
                          <code className="text-xs">{item.hash.slice(0, 16)}...</code>
                        </div>
                      )}
                      <div className="flex gap-2 pt-2">
                        <Button
                          variant="outline"
                          size="sm"
                          className="flex-1"
                          onClick={() => setSelectedEvidence(item)}
                        >
                          <Shield className="h-3 w-3 mr-1" />
                          Details
                        </Button>
                        {!item.verified && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => verifyEvidence.mutate(item.id)}
                            disabled={verifyEvidence.isPending}
                          >
                            Verify
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDownload(item)}
                        >
                          <Download className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => deleteEvidence.mutate(item.id)}
                          disabled={deleteEvidence.isPending}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Evidence Details Dialog */}
      <Dialog open={!!selectedEvidence} onOpenChange={() => setSelectedEvidence(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Evidence Details</DialogTitle>
            <DialogDescription>
              <code className="text-xs">{selectedEvidence?.id}</code>
            </DialogDescription>
          </DialogHeader>

          {selectedEvidence && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Type:</span>{" "}
                  <span className="font-medium capitalize">{selectedEvidence.type.replace(/_/g, " ")}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Status:</span>{" "}
                  <Badge variant={selectedEvidence.verified ? "outline" : "secondary"}>
                    {selectedEvidence.verified ? "Verified" : "Unverified"}
                  </Badge>
                </div>
                <div>
                  <span className="text-muted-foreground">Evaluation ID:</span>{" "}
                  <code className="text-xs">{selectedEvidence.evaluationId}</code>
                </div>
                <div>
                  <span className="text-muted-foreground">Created:</span>{" "}
                  <span>{new Date(selectedEvidence.createdAt).toLocaleString()}</span>
                </div>
                {selectedEvidence.fileName && (
                  <div className="col-span-2">
                    <span className="text-muted-foreground">File Name:</span>{" "}
                    <code className="text-xs">{selectedEvidence.fileName}</code>
                  </div>
                )}
                {selectedEvidence.hash && (
                  <div className="col-span-2">
                    <span className="text-muted-foreground">SHA256 Hash:</span>{" "}
                    <code className="text-xs break-all">{selectedEvidence.hash}</code>
                  </div>
                )}
              </div>

              {selectedEvidence.description && (
                <div>
                  <h3 className="font-medium mb-2">Description</h3>
                  <p className="text-sm text-muted-foreground">{selectedEvidence.description}</p>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
