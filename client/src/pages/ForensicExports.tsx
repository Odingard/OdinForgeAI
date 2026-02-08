import { useState } from "react";
import { formatDistanceToNow } from "date-fns";
import {
  useForensicExports,
  useCreateForensicExport,
  useDeleteForensicExport,
  useDownloadForensicExport,
  ForensicExport,
} from "@/hooks/useForensicExports";
import { DataTable, DataTableColumn, DataTableAction } from "@/components/shared/DataTable";
import { StatusTimeline, TimelineEvent } from "@/components/shared/StatusTimeline";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { useToast } from "@/hooks/use-toast";
import {
  Package,
  Download,
  Trash2,
  Eye,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  Lock,
  Hash,
} from "lucide-react";

export default function ForensicExports() {
  const { toast } = useToast();
  const [builderDialogOpen, setBuilderDialogOpen] = useState(false);
  const [selectedExport, setSelectedExport] = useState<ForensicExport | null>(null);

  // Export builder form state
  const [exportFormat, setExportFormat] = useState<"pdf" | "json" | "xml" | "csv" | "zip">("zip");
  const [evaluationIds, setEvaluationIds] = useState("");
  const [encrypted, setEncrypted] = useState(false);
  const [password, setPassword] = useState("");

  const { data: exports = [], isLoading } = useForensicExports();
  const createExport = useCreateForensicExport();
  const deleteExport = useDeleteForensicExport();
  const downloadExport = useDownloadForensicExport();

  // Table columns
  const columns: DataTableColumn<ForensicExport>[] = [
    {
      key: "id",
      header: "Export ID",
      cell: (exp) => (
        <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{exp.id.slice(0, 8)}</code>
      ),
    },
    {
      key: "format",
      header: "Format",
      cell: (exp) => (
        <Badge variant="outline" className="uppercase">
          {exp.format}
        </Badge>
      ),
      sortable: true,
    },
    {
      key: "status",
      header: "Status",
      cell: (exp) => {
        const statusConfig = {
          pending: { variant: "outline" as const, icon: Clock, color: "text-blue-500" },
          processing: { variant: "default" as const, icon: Loader2, color: "text-blue-500" },
          completed: { variant: "outline" as const, icon: CheckCircle2, color: "text-green-500" },
          failed: { variant: "destructive" as const, icon: XCircle, color: "text-red-500" },
        }[exp.status];

        const Icon = statusConfig.icon;

        return (
          <Badge variant={statusConfig.variant}>
            <Icon className={`h-3 w-3 mr-1 ${exp.status === "processing" ? "animate-spin" : ""}`} />
            {exp.status}
          </Badge>
        );
      },
      sortable: true,
    },
    {
      key: "encrypted",
      header: "Security",
      cell: (exp) => (
        exp.encrypted ? (
          <Badge variant="secondary">
            <Lock className="h-3 w-3 mr-1" />
            Encrypted
          </Badge>
        ) : (
          <Badge variant="outline">Unencrypted</Badge>
        )
      ),
    },
    {
      key: "fileSize",
      header: "Size",
      cell: (exp) => (
        exp.fileSize ? (
          <span className="text-sm">{(exp.fileSize / 1024 / 1024).toFixed(2)} MB</span>
        ) : (
          <span className="text-sm text-muted-foreground">-</span>
        )
      ),
    },
    {
      key: "createdAt",
      header: "Created",
      cell: (exp) => (
        <span className="text-sm text-muted-foreground">
          {formatDistanceToNow(new Date(exp.createdAt), { addSuffix: true })}
        </span>
      ),
      sortable: true,
    },
  ];

  // Table actions
  const actions: DataTableAction<ForensicExport>[] = [
    {
      label: "View Details",
      icon: <Eye className="h-4 w-4" />,
      onClick: (exp) => setSelectedExport(exp),
      variant: "ghost",
    },
    {
      label: "Download",
      icon: <Download className="h-4 w-4" />,
      onClick: (exp) => downloadExport.mutate(exp.id),
      variant: "ghost",
      hidden: (exp) => exp.status !== "completed",
      disabled: () => downloadExport.isPending,
    },
    {
      label: "Delete",
      icon: <Trash2 className="h-4 w-4" />,
      onClick: (exp) => deleteExport.mutate(exp.id),
      variant: "ghost",
      disabled: () => deleteExport.isPending,
    },
  ];

  const handleCreateExport = async () => {
    if (!evaluationIds.trim()) {
      toast({
        title: "Missing Information",
        description: "Please enter at least one evaluation ID",
        variant: "destructive",
      });
      return;
    }

    if (encrypted && !password) {
      toast({
        title: "Missing Password",
        description: "Please enter a password for encryption",
        variant: "destructive",
      });
      return;
    }

    const evalIds = evaluationIds.split(",").map(id => id.trim()).filter(Boolean);

    await createExport.mutateAsync({
      format: exportFormat,
      evaluationIds: evalIds,
      encrypted,
      password: encrypted ? password : undefined,
    });

    // Reset form
    setEvaluationIds("");
    setPassword("");
    setEncrypted(false);
    setBuilderDialogOpen(false);
  };

  // Generate timeline for selected export
  const getExportTimeline = (exp: ForensicExport): TimelineEvent[] => {
    const events: TimelineEvent[] = [
      {
        id: "created",
        title: "Export Created",
        description: `${exp.format.toUpperCase()} export package queued`,
        timestamp: exp.createdAt,
        status: "info",
      },
    ];

    if (exp.status === "processing" || exp.status === "completed" || exp.status === "failed") {
      events.push({
        id: "processing",
        title: "Processing Started",
        description: "Gathering evidence and generating package",
        timestamp: exp.createdAt,
        status: exp.status === "processing" ? "pending" : "info",
      });
    }

    if (exp.completedAt) {
      events.push({
        id: "completed",
        title: exp.status === "completed" ? "Package Ready" : "Export Failed",
        description: exp.error || "Export package generated successfully",
        timestamp: exp.completedAt,
        status: exp.status === "completed" ? "success" : "error",
        metadata: exp.hash ? { SHA256: exp.hash } : undefined,
      });
    }

    return events;
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold" data-testid="text-page-title">
            Forensic Export Center
          </h1>
          <p className="text-muted-foreground mt-1">
            Create tamper-proof evidence packages for incident response
          </p>
        </div>
        <Dialog open={builderDialogOpen} onOpenChange={setBuilderDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Package className="h-4 w-4 mr-2" />
              Create Export
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Export Builder</DialogTitle>
              <DialogDescription>
                Create a forensic evidence package
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label>Export Format</Label>
                <Select value={exportFormat} onValueChange={(v) => setExportFormat(v as any)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="zip">ZIP Archive</SelectItem>
                    <SelectItem value="pdf">PDF Report</SelectItem>
                    <SelectItem value="json">JSON Data</SelectItem>
                    <SelectItem value="xml">XML Data</SelectItem>
                    <SelectItem value="csv">CSV Export</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Evaluation IDs</Label>
                <Input
                  placeholder="eval-123, eval-456..."
                  value={evaluationIds}
                  onChange={(e) => setEvaluationIds(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Comma-separated list of evaluation IDs to include
                </p>
              </div>

              <div className="flex items-center space-x-2">
                <Checkbox
                  id="encrypted"
                  checked={encrypted}
                  onCheckedChange={(checked) => setEncrypted(checked as boolean)}
                />
                <Label htmlFor="encrypted" className="text-sm font-normal cursor-pointer">
                  Encrypt export package
                </Label>
              </div>

              {encrypted && (
                <div className="space-y-2">
                  <Label>Encryption Password</Label>
                  <Input
                    type="password"
                    placeholder="Enter password..."
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </div>
              )}

              <div className="rounded-md bg-muted p-3 text-xs space-y-1">
                <div className="flex items-center gap-2 font-medium">
                  <Hash className="h-3 w-3" />
                  Chain of Custody
                </div>
                <p className="text-muted-foreground">
                  Export packages include SHA256 hash verification and automated chain of custody tracking
                </p>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setBuilderDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleCreateExport} disabled={createExport.isPending}>
                {createExport.isPending ? "Creating..." : "Create Export"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Export Queue */}
      <Card>
        <CardHeader>
          <CardTitle>Export Queue</CardTitle>
          <CardDescription>
            Forensic evidence packages with tamper-proof verification
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            data={exports}
            columns={columns}
            actions={actions}
            isLoading={isLoading}
            emptyState={{
              icon: <Package className="h-12 w-12" />,
              title: "No Exports",
              description: "Create your first forensic export package",
              action: {
                label: "Create Export",
                onClick: () => setBuilderDialogOpen(true),
              },
            }}
            searchable={true}
            searchPlaceholder="Search exports..."
            searchKeys={["id", "format", "status"]}
            paginated={true}
            pageSize={20}
            data-testid="exports-table"
          />
        </CardContent>
      </Card>

      {/* Export Details Dialog */}
      <Dialog open={!!selectedExport} onOpenChange={() => setSelectedExport(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Export Package Details</DialogTitle>
            <DialogDescription>
              <code className="text-xs">{selectedExport?.id}</code>
            </DialogDescription>
          </DialogHeader>

          {selectedExport && (
            <div className="space-y-6">
              {/* Export Info */}
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Format:</span>{" "}
                  <Badge variant="outline" className="uppercase ml-2">{selectedExport.format}</Badge>
                </div>
                <div>
                  <span className="text-muted-foreground">Status:</span>{" "}
                  <Badge variant={selectedExport.status === "completed" ? "outline" : selectedExport.status === "failed" ? "destructive" : "default"} className="ml-2">
                    {selectedExport.status}
                  </Badge>
                </div>
                <div>
                  <span className="text-muted-foreground">Encrypted:</span>{" "}
                  <span className="font-medium">{selectedExport.encrypted ? "Yes" : "No"}</span>
                </div>
                {selectedExport.fileSize && (
                  <div>
                    <span className="text-muted-foreground">File Size:</span>{" "}
                    <span className="font-medium">{(selectedExport.fileSize / 1024 / 1024).toFixed(2)} MB</span>
                  </div>
                )}
                <div className="col-span-2">
                  <span className="text-muted-foreground">Evaluations:</span>{" "}
                  <span className="font-medium">{selectedExport.evaluationIds.length} evaluations</span>
                </div>
                {selectedExport.hash && (
                  <div className="col-span-2">
                    <span className="text-muted-foreground">SHA256 Hash:</span>{" "}
                    <code className="text-xs break-all">{selectedExport.hash}</code>
                  </div>
                )}
              </div>

              {/* Timeline */}
              <div>
                <h3 className="font-medium mb-4">Export Timeline</h3>
                <StatusTimeline events={getExportTimeline(selectedExport)} />
              </div>

              {/* Download Button */}
              {selectedExport.status === "completed" && (
                <Button
                  className="w-full"
                  onClick={() => {
                    downloadExport.mutate(selectedExport.id);
                    setSelectedExport(null);
                  }}
                  disabled={downloadExport.isPending}
                >
                  <Download className="h-4 w-4 mr-2" />
                  Download Export Package
                </Button>
              )}

              {/* Error Message */}
              {selectedExport.error && (
                <div className="bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 p-3 rounded text-sm">
                  <div className="flex items-start gap-2">
                    <XCircle className="h-4 w-4 text-red-500 mt-0.5 flex-shrink-0" />
                    <span className="text-red-700 dark:text-red-300">{selectedExport.error}</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
