import { useState } from "react";
import { formatDistanceToNow } from "date-fns";
import { useJobs, useJobStats, useCancelJob, useRetryJob, useDeleteJob, Job } from "@/hooks/useJobs";
import { useJobUpdates } from "@/hooks/useJobUpdates";
import { DataTable, DataTableColumn, DataTableAction } from "@/components/shared/DataTable";
import { MetricsGrid, Metric } from "@/components/shared/MetricsGrid";
import { FilterBar, Filter } from "@/components/shared/FilterBar";
import { StatusTimeline, TimelineEvent } from "@/components/shared/StatusTimeline";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  ListChecks,
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  RotateCcw,
  Trash2,
  Eye,
  Ban,
  Loader2,
  AlertCircle,
} from "lucide-react";

export default function Jobs() {
  const [statusFilter, setStatusFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [selectedJob, setSelectedJob] = useState<Job | null>(null);

  // Fetch jobs with filters
  const filters = {
    ...(statusFilter !== "all" && { status: statusFilter }),
    ...(typeFilter !== "all" && { type: typeFilter }),
  };
  const { data: jobs = [], isLoading } = useJobs(Object.keys(filters).length > 0 ? filters : undefined);
  const { data: stats } = useJobStats();

  // Real-time updates via WebSocket
  useJobUpdates({ enabled: true });

  // Mutations
  const cancelJob = useCancelJob();
  const retryJob = useRetryJob();
  const deleteJob = useDeleteJob();

  // Metrics for grid
  const metrics: Metric[] = [
    {
      label: "Total Jobs",
      value: stats?.total || 0,
      icon: ListChecks,
      iconColor: "text-cyan-400",
      "data-testid": "metric-total-jobs",
    },
    {
      label: "Running",
      value: stats?.running || 0,
      icon: Play,
      iconColor: "text-blue-500",
      valueColor: "text-blue-600",
      "data-testid": "metric-running-jobs",
    },
    {
      label: "Completed",
      value: stats?.completed || 0,
      icon: CheckCircle2,
      iconColor: "text-green-500",
      valueColor: "text-green-600",
      "data-testid": "metric-completed-jobs",
    },
    {
      label: "Failed",
      value: stats?.failed || 0,
      icon: XCircle,
      iconColor: "text-red-500",
      valueColor: "text-red-600",
      "data-testid": "metric-failed-jobs",
    },
  ];

  // Filter definitions
  const filterDefinitions: Filter[] = [
    {
      key: "status",
      label: "Status",
      options: [
        { label: "All Statuses", value: "all" },
        { label: "Pending", value: "pending" },
        { label: "Running", value: "running" },
        { label: "Completed", value: "completed" },
        { label: "Failed", value: "failed" },
        { label: "Cancelled", value: "cancelled" },
      ],
      defaultValue: "all",
    },
    {
      key: "type",
      label: "Job Type",
      options: [
        { label: "All Types", value: "all" },
        { label: "Evaluation", value: "evaluation" },
        { label: "Breach Chain", value: "breach_chain" },
        { label: "Network Scan", value: "network_scan" },
        { label: "External Recon", value: "external_recon" },
        { label: "Report", value: "report" },
        { label: "AI Simulation", value: "ai_simulation" },
      ],
      defaultValue: "all",
    },
  ];

  const filterValues = {
    status: statusFilter,
    type: typeFilter,
  };

  const handleFilterChange = (key: string, value: string) => {
    if (key === "status") setStatusFilter(value);
    if (key === "type") setTypeFilter(value);
  };

  const handleFilterReset = () => {
    setStatusFilter("all");
    setTypeFilter("all");
  };

  // Table columns
  const columns: DataTableColumn<Job>[] = [
    {
      key: "id",
      header: "Job ID",
      cell: (job) => (
        <code className="text-xs bg-muted px-1 py-0.5 rounded">{job.id.slice(0, 8)}</code>
      ),
    },
    {
      key: "type",
      header: "Type",
      cell: (job) => (
        <span className="capitalize text-sm">{job.type.replace(/_/g, " ")}</span>
      ),
      sortable: true,
    },
    {
      key: "status",
      header: "Status",
      cell: (job) => {
        const statusConfig = {
          pending: { variant: "outline" as const, icon: Clock, color: "text-blue-500" },
          running: { variant: "default" as const, icon: Loader2, color: "text-blue-500" },
          completed: { variant: "outline" as const, icon: CheckCircle2, color: "text-green-500" },
          failed: { variant: "destructive" as const, icon: XCircle, color: "text-red-500" },
          cancelled: { variant: "secondary" as const, icon: Ban, color: "text-gray-500" },
        }[job.status];

        const Icon = statusConfig.icon;

        return (
          <Badge variant={statusConfig.variant}>
            <Icon className={`h-3 w-3 mr-1 ${job.status === "running" ? "animate-spin" : ""}`} />
            {job.status}
          </Badge>
        );
      },
      sortable: true,
    },
    {
      key: "createdAt",
      header: "Created",
      cell: (job) => (
        <span className="text-sm text-muted-foreground">
          {formatDistanceToNow(new Date(job.createdAt), { addSuffix: true })}
        </span>
      ),
      sortable: true,
    },
    {
      key: "duration",
      header: "Duration",
      cell: (job) => {
        if (job.status === "pending") return <span className="text-sm text-muted-foreground">-</span>;

        const start = new Date(job.startedAt || job.createdAt);
        const end = job.completedAt ? new Date(job.completedAt) : new Date();
        const duration = Math.floor((end.getTime() - start.getTime()) / 1000);

        if (duration < 60) return <span className="text-sm">{duration}s</span>;
        if (duration < 3600) return <span className="text-sm">{Math.floor(duration / 60)}m {duration % 60}s</span>;
        return <span className="text-sm">{Math.floor(duration / 3600)}h {Math.floor((duration % 3600) / 60)}m</span>;
      },
    },
  ];

  // Table actions
  const actions: DataTableAction<Job>[] = [
    {
      label: "View Details",
      icon: <Eye className="h-4 w-4" />,
      onClick: (job) => setSelectedJob(job),
      variant: "ghost",
    },
    {
      label: "Retry Job",
      icon: <RotateCcw className="h-4 w-4" />,
      onClick: (job) => retryJob.mutate(job.id),
      variant: "ghost",
      hidden: (job) => job.status !== "failed",
      disabled: () => retryJob.isPending,
    },
    {
      label: "Cancel Job",
      icon: <Ban className="h-4 w-4" />,
      onClick: (job) => cancelJob.mutate(job.id),
      variant: "ghost",
      hidden: (job) => job.status !== "pending" && job.status !== "running",
      disabled: () => cancelJob.isPending,
    },
    {
      label: "Delete Job",
      icon: <Trash2 className="h-4 w-4" />,
      onClick: (job) => deleteJob.mutate(job.id),
      variant: "ghost",
      hidden: (job) => job.status === "running",
      disabled: () => deleteJob.isPending,
    },
  ];

  // Generate timeline events for selected job
  const getJobTimeline = (job: Job): TimelineEvent[] => {
    const events: TimelineEvent[] = [
      {
        id: "created",
        title: "Job Created",
        description: `Job queued for execution`,
        timestamp: job.createdAt,
        status: "info",
      },
    ];

    if (job.startedAt) {
      events.push({
        id: "started",
        title: "Job Started",
        description: "Execution began",
        timestamp: job.startedAt,
        status: job.status === "running" ? "pending" : "info",
      });
    }

    if (job.completedAt) {
      events.push({
        id: "completed",
        title: job.status === "completed" ? "Job Completed" : job.status === "failed" ? "Job Failed" : "Job Cancelled",
        description: job.error || (job.status === "completed" ? "Execution completed successfully" : "Execution terminated"),
        timestamp: job.completedAt,
        status: job.status === "completed" ? "success" : "error",
        metadata: job.error ? { error: job.error } : undefined,
      });
    }

    return events;
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold" data-testid="text-page-title">
          Jobs & Queue Monitoring
        </h1>
        <p className="text-muted-foreground mt-1">
          Monitor background jobs, queue status, and execution history
        </p>
      </div>

      {/* Metrics Grid */}
      <MetricsGrid metrics={metrics} columns={4} data-testid="jobs-metrics" />

      {/* Filters */}
      <FilterBar
        filters={filterDefinitions}
        values={filterValues}
        onChange={handleFilterChange}
        onReset={handleFilterReset}
        data-testid="jobs-filters"
      />

      {/* Jobs Table */}
      <Card>
        <CardHeader>
          <CardTitle>Job Queue</CardTitle>
          <CardDescription>
            Real-time view of all background jobs and their status
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            data={jobs}
            columns={columns}
            actions={actions}
            isLoading={isLoading}
            emptyState={{
              icon: <ListChecks className="h-12 w-12" />,
              title: "No Jobs Found",
              description: "No jobs match the selected filters",
            }}
            searchable={true}
            searchPlaceholder="Search jobs..."
            searchKeys={["id", "type", "status"]}
            paginated={true}
            pageSize={20}
            data-testid="jobs-table"
          />
        </CardContent>
      </Card>

      {/* Job Details Dialog */}
      <Dialog open={!!selectedJob} onOpenChange={() => setSelectedJob(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Job Details</DialogTitle>
            <DialogDescription>
              <code className="text-xs">{selectedJob?.id}</code>
            </DialogDescription>
          </DialogHeader>

          {selectedJob && (
            <div className="space-y-6">
              {/* Job Info */}
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Type:</span>{" "}
                  <span className="font-medium capitalize">{selectedJob.type.replace(/_/g, " ")}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Status:</span>{" "}
                  <Badge variant={selectedJob.status === "completed" ? "outline" : selectedJob.status === "failed" ? "destructive" : "default"}>
                    {selectedJob.status}
                  </Badge>
                </div>
                <div>
                  <span className="text-muted-foreground">Created:</span>{" "}
                  <span>{new Date(selectedJob.createdAt).toLocaleString()}</span>
                </div>
                {selectedJob.completedAt && (
                  <div>
                    <span className="text-muted-foreground">Completed:</span>{" "}
                    <span>{new Date(selectedJob.completedAt).toLocaleString()}</span>
                  </div>
                )}
              </div>

              {/* Timeline */}
              <div>
                <h3 className="font-medium mb-4">Execution Timeline</h3>
                <StatusTimeline events={getJobTimeline(selectedJob)} />
              </div>

              {/* Job Data */}
              {selectedJob.data && (
                <div>
                  <h3 className="font-medium mb-2">Job Parameters</h3>
                  <pre className="bg-muted p-3 rounded text-xs overflow-x-auto">
                    {JSON.stringify(selectedJob.data, null, 2)}
                  </pre>
                </div>
              )}

              {/* Result */}
              {selectedJob.result && (
                <div>
                  <h3 className="font-medium mb-2">Result</h3>
                  <pre className="bg-muted p-3 rounded text-xs overflow-x-auto">
                    {JSON.stringify(selectedJob.result, null, 2)}
                  </pre>
                </div>
              )}

              {/* Error */}
              {selectedJob.error && (
                <div>
                  <h3 className="font-medium mb-2 text-red-600">Error</h3>
                  <div className="bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 p-3 rounded text-sm">
                    <div className="flex items-start gap-2">
                      <AlertCircle className="h-4 w-4 text-red-500 mt-0.5 flex-shrink-0" />
                      <span className="text-red-700 dark:text-red-300">{selectedJob.error}</span>
                    </div>
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
