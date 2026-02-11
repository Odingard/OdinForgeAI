import { useState } from "react";
import { useAuditLogs, useAuditLogStats, AuditLog } from "@/hooks/useAuditLogs";
import { formatDTG } from "@/lib/utils";
import { DataTable, DataTableColumn, DataTableAction } from "@/components/shared/DataTable";
import { MetricsGrid, Metric } from "@/components/shared/MetricsGrid";
import { FilterBar, Filter } from "@/components/shared/FilterBar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import {
  FileText,
  User,
  AlertTriangle,
  Users,
  Eye,
  Download,
  Shield,
  Activity,
  Terminal,
} from "lucide-react";

export default function AuditLogs() {
  const { toast } = useToast();
  const [actorTypeFilter, setActorTypeFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);

  // Fetch audit logs with filters
  const filters = {
    ...(actorTypeFilter !== "all" && { actorType: actorTypeFilter }),
    ...(severityFilter !== "all" && { severity: severityFilter }),
  };
  const { data: logs = [], isLoading } = useAuditLogs(Object.keys(filters).length > 0 ? filters : undefined);
  const { data: stats } = useAuditLogStats();

  // Metrics
  const metrics: Metric[] = [
    {
      label: "Total Events",
      value: stats?.total || 0,
      icon: FileText,
      iconColor: "text-cyan-400",
      "data-testid": "metric-total-events",
    },
    {
      label: "Today",
      value: stats?.today || 0,
      icon: Activity,
      iconColor: "text-blue-500",
      "data-testid": "metric-today-events",
    },
    {
      label: "Critical",
      value: stats?.critical || 0,
      icon: AlertTriangle,
      iconColor: "text-red-500",
      valueColor: "text-red-600",
      "data-testid": "metric-critical-events",
    },
    {
      label: "Unique Users",
      value: stats?.uniqueUsers || 0,
      icon: Users,
      iconColor: "text-purple-500",
      "data-testid": "metric-unique-users",
    },
  ];

  // Filter definitions
  const filterDefinitions: Filter[] = [
    {
      key: "actorType",
      label: "Actor Type",
      options: [
        { label: "All Types", value: "all" },
        { label: "User", value: "user" },
        { label: "Agent", value: "agent" },
        { label: "System", value: "system" },
      ],
      defaultValue: "all",
    },
    {
      key: "severity",
      label: "Severity",
      options: [
        { label: "All Severities", value: "all" },
        { label: "Info", value: "info" },
        { label: "Warning", value: "warning" },
        { label: "Error", value: "error" },
        { label: "Critical", value: "critical" },
      ],
      defaultValue: "all",
    },
  ];

  const filterValues = {
    actorType: actorTypeFilter,
    severity: severityFilter,
  };

  const handleFilterChange = (key: string, value: string) => {
    if (key === "actorType") setActorTypeFilter(value);
    if (key === "severity") setSeverityFilter(value);
  };

  const handleFilterReset = () => {
    setActorTypeFilter("all");
    setSeverityFilter("all");
  };

  // Export logs as CSV
  const handleExport = () => {
    const headers = ["Timestamp", "Actor Type", "Action", "Resource", "IP Address", "Severity"];
    const rows = logs.map(log => [
      new Date(log.timestamp).toISOString(),
      log.actorType,
      log.action,
      log.targetResource,
      log.ipAddress || "-",
      log.severity || "info",
    ]);

    const csv = [headers, ...rows].map(row => row.join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-logs-${new Date().toISOString().split("T")[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);

    toast({
      title: "Export Complete",
      description: `Exported ${logs.length} audit log entries`,
    });
  };

  // Table columns
  const columns: DataTableColumn<AuditLog>[] = [
    {
      key: "timestamp",
      header: "Timestamp",
      cell: (log) => (
        <span className="text-sm text-muted-foreground font-mono">
          {formatDTG(log.timestamp)}
        </span>
      ),
      sortable: true,
    },
    {
      key: "actorType",
      header: "Actor",
      cell: (log) => {
        const icons = {
          user: User,
          agent: Terminal,
          system: Shield,
        };
        const Icon = icons[log.actorType];

        return (
          <div className="flex items-center gap-2">
            <Icon className="h-3 w-3 text-muted-foreground" />
            <span className="capitalize text-sm">{log.actorType}</span>
          </div>
        );
      },
      sortable: true,
    },
    {
      key: "action",
      header: "Action",
      cell: (log) => (
        <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{log.action}</code>
      ),
    },
    {
      key: "targetResource",
      header: "Resource",
      cell: (log) => (
        <span className="text-sm">{log.targetResource}</span>
      ),
    },
    {
      key: "ipAddress",
      header: "IP Address",
      cell: (log) => (
        <code className="text-xs text-muted-foreground">{log.ipAddress || "-"}</code>
      ),
    },
    {
      key: "severity",
      header: "Severity",
      cell: (log) => {
        const severity = log.severity || "info";
        const severityConfig = {
          info: { variant: "outline" as const, color: "" },
          warning: { variant: "secondary" as const, color: "text-amber-600" },
          error: { variant: "destructive" as const, color: "text-red-600" },
          critical: { variant: "destructive" as const, color: "text-red-600" },
        }[severity];

        return (
          <Badge variant={severityConfig.variant} className={severityConfig.color}>
            {severity}
          </Badge>
        );
      },
      sortable: true,
    },
  ];

  // Table actions
  const actions: DataTableAction<AuditLog>[] = [
    {
      label: "View Details",
      icon: <Eye className="h-4 w-4" />,
      onClick: (log) => setSelectedLog(log),
      variant: "ghost",
    },
  ];

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold" data-testid="text-page-title">
            Audit Logs
          </h1>
          <p className="text-muted-foreground mt-1">
            Security event timeline and compliance audit trail
          </p>
        </div>
        <Button variant="outline" onClick={handleExport} disabled={logs.length === 0}>
          <Download className="h-4 w-4 mr-2" />
          Export CSV
        </Button>
      </div>

      {/* Metrics Grid */}
      <MetricsGrid metrics={metrics} columns={4} data-testid="audit-metrics" />

      {/* Filters */}
      <FilterBar
        filters={filterDefinitions}
        values={filterValues}
        onChange={handleFilterChange}
        onReset={handleFilterReset}
        data-testid="audit-filters"
      />

      {/* Audit Logs Table */}
      <Card>
        <CardHeader>
          <CardTitle>Security Events</CardTitle>
          <CardDescription>
            Complete audit trail of all system activities
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            data={logs}
            columns={columns}
            actions={actions}
            isLoading={isLoading}
            emptyState={{
              icon: <FileText className="h-12 w-12" />,
              title: "No Audit Logs",
              description: "No audit events match the selected filters",
            }}
            searchable={true}
            searchPlaceholder="Search logs..."
            searchKeys={["action", "targetResource", "actorId"]}
            paginated={true}
            pageSize={50}
            data-testid="audit-table"
          />
        </CardContent>
      </Card>

      {/* Log Details Dialog */}
      <Dialog open={!!selectedLog} onOpenChange={() => setSelectedLog(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Audit Log Details</DialogTitle>
            <DialogDescription>
              <code className="text-xs">{selectedLog?.id}</code>
            </DialogDescription>
          </DialogHeader>

          {selectedLog && (
            <div className="space-y-4">
              {/* Event Info */}
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Action:</span>{" "}
                  <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{selectedLog.action}</code>
                </div>
                <div>
                  <span className="text-muted-foreground">Actor Type:</span>{" "}
                  <span className="font-medium capitalize">{selectedLog.actorType}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Resource:</span>{" "}
                  <span className="font-medium">{selectedLog.targetResource}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Timestamp:</span>{" "}
                  <span className="font-mono">{formatDTG(selectedLog.timestamp)}</span>
                </div>
                {selectedLog.actorId && (
                  <div>
                    <span className="text-muted-foreground">Actor ID:</span>{" "}
                    <code className="text-xs">{selectedLog.actorId}</code>
                  </div>
                )}
                {selectedLog.ipAddress && (
                  <div>
                    <span className="text-muted-foreground">IP Address:</span>{" "}
                    <code className="text-xs">{selectedLog.ipAddress}</code>
                  </div>
                )}
                {selectedLog.evaluationId && (
                  <div>
                    <span className="text-muted-foreground">Evaluation ID:</span>{" "}
                    <code className="text-xs">{selectedLog.evaluationId}</code>
                  </div>
                )}
                {selectedLog.severity && (
                  <div>
                    <span className="text-muted-foreground">Severity:</span>{" "}
                    <Badge variant={selectedLog.severity === "critical" || selectedLog.severity === "error" ? "destructive" : "outline"}>
                      {selectedLog.severity}
                    </Badge>
                  </div>
                )}
              </div>

              {/* Changes */}
              {selectedLog.changes && Object.keys(selectedLog.changes).length > 0 && (
                <div>
                  <h3 className="font-medium mb-2">Changes</h3>
                  <pre className="bg-muted p-3 rounded text-xs overflow-x-auto">
                    {JSON.stringify(selectedLog.changes, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
