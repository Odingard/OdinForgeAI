import { useState } from "react";
import { formatDistanceToNow } from "date-fns";
import { useQuery } from "@tanstack/react-query";
import { DataTable, DataTableColumn, DataTableAction } from "@/components/shared/DataTable";
import { MetricsGrid } from "@/components/shared/MetricsGrid";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Radar,
  Eye,
  XCircle,
  CheckCircle2,
  Loader2,
  AlertTriangle,
  FileText,
} from "lucide-react";

interface LiveScan {
  id: string;
  name: string;
  type: "vulnerability" | "compliance" | "reconnaissance" | "penetration";
  status: "running" | "completed" | "failed" | "cancelled";
  progress: number;
  startTime: string;
  endTime?: string;
  targetCount: number;
  findingsCount?: number;
  criticalFindings?: number;
  highFindings?: number;
}

interface ScanFinding {
  id: string;
  scanId: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  target: string;
  cve?: string;
  cvssScore?: number;
  remediation?: string;
  evidence?: string;
}

export default function LiveScans() {
  const [selectedScan, setSelectedScan] = useState<LiveScan | null>(null);

  const { data: scans = [], isLoading } = useQuery<LiveScan[]>({
    queryKey: ["/api/aev/live-scans"],
    refetchInterval: 5000, // Poll every 5 seconds for real-time updates
  });

  const { data: scanFindings = [] } = useQuery<ScanFinding[]>({
    queryKey: [`/api/aev/live-scans/${selectedScan?.id}/findings`],
    enabled: !!selectedScan,
    refetchInterval: 10000,
  });

  // Calculate metrics
  const activeScans = scans.filter(s => s.status === "running").length;
  const completedToday = scans.filter(s =>
    s.status === "completed" &&
    new Date(s.startTime).toDateString() === new Date().toDateString()
  ).length;
  const totalFindings = scans.reduce((sum, s) => sum + (s.findingsCount || 0), 0);
  const criticalFindings = scans.reduce((sum, s) => sum + (s.criticalFindings || 0), 0);

  const metrics = [
    {
      label: "Active Scans",
      value: activeScans,
      icon: <Radar className="h-4 w-4" />,
      trend: undefined,
    },
    {
      label: "Completed Today",
      value: completedToday,
      icon: <CheckCircle2 className="h-4 w-4" />,
      trend: undefined,
    },
    {
      label: "Total Findings",
      value: totalFindings,
      icon: <FileText className="h-4 w-4" />,
      trend: undefined,
    },
    {
      label: "Critical Findings",
      value: criticalFindings,
      icon: <AlertTriangle className="h-4 w-4" />,
      variant: criticalFindings > 0 ? "danger" as const : undefined,
      trend: undefined,
    },
  ];

  // Active scans with progress
  const activeScansData = scans.filter(s => s.status === "running");

  // Table columns
  const columns: DataTableColumn<LiveScan>[] = [
    {
      key: "name",
      header: "Scan Name",
      cell: (scan) => <span className="font-medium">{scan.name}</span>,
      sortable: true,
    },
    {
      key: "type",
      header: "Type",
      cell: (scan) => (
        <Badge variant="outline" className="capitalize">
          {scan.type}
        </Badge>
      ),
      sortable: true,
    },
    {
      key: "status",
      header: "Status",
      cell: (scan) => {
        const statusConfig = {
          running: { variant: "default" as const, icon: Loader2, color: "text-blue-500" },
          completed: { variant: "outline" as const, icon: CheckCircle2, color: "text-green-500" },
          failed: { variant: "destructive" as const, icon: XCircle, color: "text-red-500" },
          cancelled: { variant: "outline" as const, icon: XCircle, color: "text-gray-500" },
        }[scan.status];

        const Icon = statusConfig.icon;

        return (
          <Badge variant={statusConfig.variant}>
            <Icon className={`h-3 w-3 mr-1 ${scan.status === "running" ? "animate-spin" : ""}`} />
            {scan.status}
          </Badge>
        );
      },
      sortable: true,
    },
    {
      key: "progress",
      header: "Progress",
      cell: (scan) => (
        <div className="w-full">
          {scan.status === "running" ? (
            <div className="flex items-center gap-2">
              <Progress value={scan.progress} className="flex-1" />
              <span className="text-xs text-muted-foreground w-10">{scan.progress}%</span>
            </div>
          ) : (
            <span className="text-sm text-muted-foreground">
              {scan.status === "completed" ? "100%" : "-"}
            </span>
          )}
        </div>
      ),
    },
    {
      key: "findingsCount",
      header: "Findings",
      cell: (scan) => (
        scan.findingsCount !== undefined ? (
          <div className="flex items-center gap-2">
            <Badge variant="outline">{scan.findingsCount}</Badge>
            {(scan.criticalFindings || 0) > 0 && (
              <Badge variant="destructive" className="text-xs">
                {scan.criticalFindings} critical
              </Badge>
            )}
          </div>
        ) : (
          <span className="text-sm text-muted-foreground">-</span>
        )
      ),
      sortable: true,
    },
    {
      key: "startTime",
      header: "Started",
      cell: (scan) => (
        <span className="text-sm text-muted-foreground">
          {formatDistanceToNow(new Date(scan.startTime), { addSuffix: true })}
        </span>
      ),
      sortable: true,
    },
  ];

  // Table actions
  const actions: DataTableAction<LiveScan>[] = [
    {
      label: "View Details",
      icon: <Eye className="h-4 w-4" />,
      onClick: (scan) => setSelectedScan(scan),
      variant: "ghost",
    },
  ];

  // Findings columns
  const findingsColumns: DataTableColumn<ScanFinding>[] = [
    {
      key: "severity",
      header: "Severity",
      cell: (finding) => {
        const variantMap = {
          critical: "destructive",
          high: "default",
          medium: "secondary",
          low: "outline",
          info: "outline",
        } as const;
        return (
          <Badge variant={variantMap[finding.severity]} className="capitalize">
            {finding.severity}
          </Badge>
        );
      },
      sortable: true,
    },
    {
      key: "title",
      header: "Finding",
      cell: (finding) => (
        <div>
          <div className="font-medium">{finding.title}</div>
          {finding.cve && (
            <code className="text-xs text-muted-foreground">{finding.cve}</code>
          )}
        </div>
      ),
    },
    {
      key: "target",
      header: "Target",
      cell: (finding) => <code className="text-xs">{finding.target}</code>,
    },
    {
      key: "cvssScore",
      header: "CVSS",
      cell: (finding) => (
        finding.cvssScore ? (
          <span className={`font-medium ${
            finding.cvssScore >= 9 ? "text-red-500" :
            finding.cvssScore >= 7 ? "text-orange-500" :
            finding.cvssScore >= 4 ? "text-yellow-500" :
            "text-green-500"
          }`}>
            {finding.cvssScore.toFixed(1)}
          </span>
        ) : (
          <span className="text-sm text-muted-foreground">-</span>
        )
      ),
      sortable: true,
    },
  ];

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-semibold" data-testid="text-page-title">
          Live Scan Results
        </h1>
        <p className="text-muted-foreground mt-1">
          Real-time security scan monitoring and results
        </p>
      </div>

      {/* Metrics */}
      <MetricsGrid metrics={metrics} />

      {/* Active Scans Widget */}
      {activeScansData.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin" />
              Active Scans
            </CardTitle>
            <CardDescription>
              Scans currently in progress
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {activeScansData.map(scan => (
              <div key={scan.id} className="space-y-2">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="font-medium">{scan.name}</span>
                    <Badge variant="outline" className="ml-2 capitalize text-xs">
                      {scan.type}
                    </Badge>
                  </div>
                  <span className="text-sm text-muted-foreground">
                    {scan.progress}%
                  </span>
                </div>
                <Progress value={scan.progress} />
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>{scan.targetCount} targets</span>
                  <span>Started {formatDistanceToNow(new Date(scan.startTime), { addSuffix: true })}</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Scan History Table */}
      <Card>
        <CardHeader>
          <CardTitle>Scan History</CardTitle>
          <CardDescription>
            All security scans and their results
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            data={scans}
            columns={columns}
            actions={actions}
            isLoading={isLoading}
            emptyState={{
              icon: <Radar className="h-12 w-12" />,
              title: "No Scans",
              description: "No security scans have been run yet",
            }}
            searchable={true}
            searchPlaceholder="Search scans..."
            searchKeys={["name", "type"]}
            paginated={true}
            pageSize={20}
            data-testid="scans-table"
          />
        </CardContent>
      </Card>

      {/* Scan Details Dialog */}
      <Dialog open={!!selectedScan} onOpenChange={() => setSelectedScan(null)}>
        <DialogContent className="max-w-6xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{selectedScan?.name}</DialogTitle>
            <DialogDescription>
              <Badge variant="outline" className="capitalize">
                {selectedScan?.type}
              </Badge>
            </DialogDescription>
          </DialogHeader>

          {selectedScan && (
            <Tabs defaultValue="findings" className="w-full">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="findings">
                  Findings ({scanFindings.length})
                </TabsTrigger>
                <TabsTrigger value="details">Details</TabsTrigger>
              </TabsList>

              <TabsContent value="findings" className="space-y-4">
                <DataTable
                  data={scanFindings}
                  columns={findingsColumns}
                  emptyState={{
                    icon: <CheckCircle2 className="h-12 w-12" />,
                    title: "No Findings",
                    description: "This scan did not discover any security issues",
                  }}
                  searchable={true}
                  searchPlaceholder="Search findings..."
                  searchKeys={["title", "description", "target", "cve"]}
                  paginated={true}
                  pageSize={10}
                />
              </TabsContent>

              <TabsContent value="details" className="space-y-4">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">Scan ID:</span>{" "}
                    <code className="text-xs">{selectedScan.id}</code>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Type:</span>{" "}
                    <span className="font-medium capitalize">{selectedScan.type}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Status:</span>{" "}
                    <Badge variant={selectedScan.status === "completed" ? "outline" : "default"}>
                      {selectedScan.status}
                    </Badge>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Targets:</span>{" "}
                    <span className="font-medium">{selectedScan.targetCount}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Started:</span>{" "}
                    <span className="font-medium">
                      {new Date(selectedScan.startTime).toLocaleString()}
                    </span>
                  </div>
                  {selectedScan.endTime && (
                    <div>
                      <span className="text-muted-foreground">Completed:</span>{" "}
                      <span className="font-medium">
                        {new Date(selectedScan.endTime).toLocaleString()}
                      </span>
                    </div>
                  )}
                </div>
              </TabsContent>
            </Tabs>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
