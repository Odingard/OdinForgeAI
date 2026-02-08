import { useState } from "react";
import { formatDistanceToNow } from "date-fns";
import {
  useScheduledScans,
  useScheduledScanRuns,
  useScheduledScanStats,
  useCreateScheduledScan,
  useUpdateScheduledScan,
  useDeleteScheduledScan,
  useRunScheduledScanNow,
  useToggleScheduledScan,
  ScheduledScan,
  ScanRun,
} from "@/hooks/useScheduledScans";
import { DataTable, DataTableColumn, DataTableAction } from "@/components/shared/DataTable";
import { MetricsGrid } from "@/components/shared/MetricsGrid";
import { StatusTimeline, TimelineEvent } from "@/components/shared/StatusTimeline";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import {
  Calendar,
  Play,
  Trash2,
  Eye,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  Plus,
} from "lucide-react";

export default function ScheduledScans() {
  const { toast } = useToast();
  const [builderDialogOpen, setBuilderDialogOpen] = useState(false);
  const [selectedScan, setSelectedScan] = useState<ScheduledScan | null>(null);

  // Builder form state
  const [scanName, setScanName] = useState("");
  const [scanDescription, setScanDescription] = useState("");
  const [scanType, setScanType] = useState<"vulnerability" | "compliance" | "reconnaissance" | "penetration">("vulnerability");
  const [targetIds, setTargetIds] = useState("");
  const [schedule, setSchedule] = useState("0 0 * * *"); // Daily at midnight

  const { data: stats } = useScheduledScanStats();
  const { data: scans = [], isLoading } = useScheduledScans();
  const { data: scanRuns = [] } = useScheduledScanRuns(selectedScan?.id || null);
  const createScan = useCreateScheduledScan();
  const updateScan = useUpdateScheduledScan();
  const deleteScan = useDeleteScheduledScan();
  const runNow = useRunScheduledScanNow();
  const toggleScan = useToggleScheduledScan();

  const metrics = [
    {
      label: "Total Schedules",
      value: stats?.totalSchedules || 0,
      icon: Calendar,
      trend: undefined,
    },
    {
      label: "Enabled",
      value: stats?.enabledSchedules || 0,
      icon: CheckCircle2,
      trend: undefined,
    },
    {
      label: "Upcoming Runs",
      value: stats?.upcomingRuns || 0,
      icon: Clock,
      trend: undefined,
    },
    {
      label: "Runs Today",
      value: stats?.lastRunsToday || 0,
      icon: Play,
      trend: undefined,
    },
  ];

  // Table columns
  const columns: DataTableColumn<ScheduledScan>[] = [
    {
      key: "name",
      header: "Schedule Name",
      cell: (scan) => (
        <div>
          <div className="font-medium">{scan.name}</div>
          {scan.description && (
            <div className="text-xs text-muted-foreground">{scan.description}</div>
          )}
        </div>
      ),
      sortable: true,
    },
    {
      key: "scanType",
      header: "Type",
      cell: (scan) => (
        <Badge variant="outline" className="capitalize">
          {scan.scanType}
        </Badge>
      ),
      sortable: true,
    },
    {
      key: "schedule",
      header: "Frequency",
      cell: (scan) => (
        <code className="text-xs bg-muted px-1.5 py-0.5 rounded">
          {scan.schedule}
        </code>
      ),
    },
    {
      key: "nextRun",
      header: "Next Run",
      cell: (scan) => (
        scan.nextRun ? (
          <span className="text-sm">
            {formatDistanceToNow(new Date(scan.nextRun), { addSuffix: true })}
          </span>
        ) : (
          <span className="text-sm text-muted-foreground">-</span>
        )
      ),
      sortable: true,
    },
    {
      key: "lastRun",
      header: "Last Run",
      cell: (scan) => (
        scan.lastRun ? (
          <span className="text-sm text-muted-foreground">
            {formatDistanceToNow(new Date(scan.lastRun), { addSuffix: true })}
          </span>
        ) : (
          <span className="text-sm text-muted-foreground">Never</span>
        )
      ),
      sortable: true,
    },
    {
      key: "enabled",
      header: "Status",
      cell: (scan) => (
        <Switch
          checked={scan.enabled}
          onCheckedChange={(checked) => toggleScan.mutate({ scanId: scan.id, enabled: checked })}
          disabled={toggleScan.isPending}
        />
      ),
    },
  ];

  // Table actions
  const actions: DataTableAction<ScheduledScan>[] = [
    {
      label: "View History",
      icon: <Eye className="h-4 w-4" />,
      onClick: (scan) => setSelectedScan(scan),
      variant: "ghost",
    },
    {
      label: "Run Now",
      icon: <Play className="h-4 w-4" />,
      onClick: (scan) => runNow.mutate(scan.id),
      variant: "ghost",
      disabled: () => runNow.isPending,
    },
    {
      label: "Delete",
      icon: <Trash2 className="h-4 w-4" />,
      onClick: (scan) => deleteScan.mutate(scan.id),
      variant: "ghost",
      disabled: () => deleteScan.isPending,
    },
  ];

  const handleCreateScan = async () => {
    if (!scanName.trim() || !targetIds.trim()) {
      toast({
        title: "Missing Information",
        description: "Please enter a name and at least one target ID",
        variant: "destructive",
      });
      return;
    }

    const targets = targetIds.split(",").map(id => id.trim()).filter(Boolean);

    await createScan.mutateAsync({
      name: scanName,
      description: scanDescription || undefined,
      scanType,
      targetIds: targets,
      schedule,
    });

    // Reset form
    setScanName("");
    setScanDescription("");
    setTargetIds("");
    setBuilderDialogOpen(false);
  };

  // Convert scan runs to timeline events
  const getRunTimeline = (runs: ScanRun[]): TimelineEvent[] => {
    return runs.map(run => ({
      id: run.id,
      title: run.status === "completed" ? "Scan Completed" : run.status === "failed" ? "Scan Failed" : "Scan Running",
      description: run.findingsCount !== undefined ? `Found ${run.findingsCount} issues` : run.error || "",
      timestamp: run.startTime,
      status: run.status === "completed" ? "success" : run.status === "failed" ? "error" : run.status === "running" ? "pending" : "info",
    }));
  };

  // Common cron expressions
  const cronPresets = [
    { label: "Daily at midnight", value: "0 0 * * *" },
    { label: "Weekly on Monday", value: "0 0 * * 1" },
    { label: "Monthly on 1st", value: "0 0 1 * *" },
    { label: "Every 6 hours", value: "0 */6 * * *" },
    { label: "Every hour", value: "0 * * * *" },
  ];

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold" data-testid="text-page-title">
            Scheduled Scans
          </h1>
          <p className="text-muted-foreground mt-1">
            Manage automated security scan schedules
          </p>
        </div>
        <Dialog open={builderDialogOpen} onOpenChange={setBuilderDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              Create Schedule
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Scan Schedule</DialogTitle>
              <DialogDescription>
                Set up an automated security scan
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label>Schedule Name</Label>
                <Input
                  placeholder="Weekly vulnerability scan"
                  value={scanName}
                  onChange={(e) => setScanName(e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <Label>Description (optional)</Label>
                <Textarea
                  placeholder="Scan description..."
                  value={scanDescription}
                  onChange={(e) => setScanDescription(e.target.value)}
                  rows={2}
                />
              </div>

              <div className="space-y-2">
                <Label>Scan Type</Label>
                <Select value={scanType} onValueChange={(v) => setScanType(v as any)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="vulnerability">Vulnerability Scan</SelectItem>
                    <SelectItem value="compliance">Compliance Check</SelectItem>
                    <SelectItem value="reconnaissance">Reconnaissance</SelectItem>
                    <SelectItem value="penetration">Penetration Test</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Target IDs</Label>
                <Input
                  placeholder="asset-123, asset-456..."
                  value={targetIds}
                  onChange={(e) => setTargetIds(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  Comma-separated list of asset IDs to scan
                </p>
              </div>

              <div className="space-y-2">
                <Label>Schedule (Cron Expression)</Label>
                <Select value={schedule} onValueChange={setSchedule}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {cronPresets.map(preset => (
                      <SelectItem key={preset.value} value={preset.value}>
                        {preset.label} ({preset.value})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  placeholder="0 0 * * *"
                  value={schedule}
                  onChange={(e) => setSchedule(e.target.value)}
                  className="font-mono text-sm"
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setBuilderDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleCreateScan} disabled={createScan.isPending}>
                {createScan.isPending ? "Creating..." : "Create Schedule"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Metrics */}
      <MetricsGrid metrics={metrics} />

      {/* Schedules Table */}
      <Card>
        <CardHeader>
          <CardTitle>Scan Schedules</CardTitle>
          <CardDescription>
            Automated security scans with configurable frequencies
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            data={scans}
            columns={columns}
            actions={actions}
            isLoading={isLoading}
            emptyState={{
              icon: <Calendar className="h-12 w-12" />,
              title: "No Schedules",
              description: "Create your first scheduled scan",
              action: {
                label: "Create Schedule",
                onClick: () => setBuilderDialogOpen(true),
              },
            }}
            searchable={true}
            searchPlaceholder="Search schedules..."
            searchKeys={["name", "description", "scanType"]}
            paginated={true}
            pageSize={20}
            data-testid="schedules-table"
          />
        </CardContent>
      </Card>

      {/* Run History Dialog */}
      <Dialog open={!!selectedScan} onOpenChange={() => setSelectedScan(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{selectedScan?.name}</DialogTitle>
            <DialogDescription>
              Scan execution history
            </DialogDescription>
          </DialogHeader>

          {selectedScan && (
            <div className="space-y-6">
              {/* Schedule Info */}
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Type:</span>{" "}
                  <Badge variant="outline" className="capitalize ml-2">{selectedScan.scanType}</Badge>
                </div>
                <div>
                  <span className="text-muted-foreground">Frequency:</span>{" "}
                  <code className="text-xs ml-2">{selectedScan.schedule}</code>
                </div>
                <div>
                  <span className="text-muted-foreground">Next Run:</span>{" "}
                  <span className="font-medium">
                    {selectedScan.nextRun
                      ? formatDistanceToNow(new Date(selectedScan.nextRun), { addSuffix: true })
                      : "Not scheduled"}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Targets:</span>{" "}
                  <span className="font-medium">{selectedScan.targetIds.length}</span>
                </div>
              </div>

              {/* Run History Timeline */}
              <div>
                <h3 className="font-medium mb-4">Execution History</h3>
                {scanRuns.length > 0 ? (
                  <StatusTimeline events={getRunTimeline(scanRuns)} />
                ) : (
                  <p className="text-sm text-muted-foreground">No execution history</p>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
