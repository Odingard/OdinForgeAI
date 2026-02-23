import { useState } from "react";
import {
  useComplianceFrameworks,
  useComplianceControls,
  useComplianceCoverage,
  useComplianceGaps,
  useGenerateComplianceReport,
  ComplianceControl,
  ComplianceGap,
} from "@/hooks/useCompliance";
import { DataTable, DataTableColumn } from "@/components/shared/DataTable";
import { MetricsGrid, Metric } from "@/components/shared/MetricsGrid";
import { TimeSeriesChart, TimeSeriesDataPoint, TimeSeriesMetric } from "@/components/shared/TimeSeriesChart";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import {
  Shield,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Download,
  TrendingUp,
  Target,
  AlertCircle,
} from "lucide-react";

export default function Compliance() {
  const { toast } = useToast();
  const [selectedFramework, setSelectedFramework] = useState("SOC2");
  const [reportFormat, setReportFormat] = useState<"pdf" | "json" | "csv">("pdf");

  const { data: frameworks = [] } = useComplianceFrameworks();
  const { data: controls = [] } = useComplianceControls(selectedFramework);
  const { data: coverage = [] } = useComplianceCoverage(selectedFramework);
  const { data: gaps = [] } = useComplianceGaps(selectedFramework);
  const generateReport = useGenerateComplianceReport();

  // Get coverage for selected framework
  const frameworkCoverage = coverage.find(c => c.framework === selectedFramework);
  const coveragePercentage = frameworkCoverage?.coveragePercentage || 0;

  // Count controls by status
  const controlsByStatus = {
    completed: controls.filter(c => c.status === "completed").length,
    in_progress: controls.filter(c => c.status === "in_progress").length,
    not_started: controls.filter(c => c.status === "not_started").length,
    not_applicable: controls.filter(c => c.status === "not_applicable").length,
  };

  // Metrics for selected framework
  const metrics: Metric[] = [
    {
      label: "Coverage",
      value: `${coveragePercentage.toFixed(1)}%`,
      icon: Target,
      iconColor: coveragePercentage >= 80 ? "text-green-500" : coveragePercentage >= 60 ? "text-amber-500" : "text-red-500",
      valueColor: coveragePercentage >= 80 ? "text-green-600" : coveragePercentage >= 60 ? "text-amber-600" : "text-red-600",
      "data-testid": "metric-coverage",
    },
    {
      label: "Compliant Controls",
      value: frameworkCoverage?.compliantControls || 0,
      icon: CheckCircle2,
      iconColor: "text-green-500",
      valueColor: "text-green-600",
      "data-testid": "metric-compliant",
    },
    {
      label: "Gaps",
      value: frameworkCoverage?.nonCompliantControls || 0,
      icon: AlertTriangle,
      iconColor: "text-amber-500",
      valueColor: "text-amber-600",
      "data-testid": "metric-gaps",
    },
    {
      label: "Total Controls",
      value: frameworkCoverage?.totalControls || 0,
      icon: Shield,
      iconColor: "text-cyan-400",
      "data-testid": "metric-total-controls",
    },
  ];

  // Generate mock compliance trend data
  const complianceTrendData: TimeSeriesDataPoint[] = Array.from({ length: 12 }, (_, i) => ({
    timestamp: `Month ${i + 1}`,
    coverage: Math.min(coveragePercentage + Math.random() * 10 - 5, 100),
  }));

  const trendMetrics: TimeSeriesMetric[] = [
    { key: "coverage", label: "Coverage %", color: "hsl(var(--chart-1))" },
  ];

  // Control columns
  const controlColumns: DataTableColumn<ComplianceControl>[] = [
    {
      key: "controlId",
      header: "Control ID",
      cell: (control) => (
        <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{control.controlId}</code>
      ),
    },
    {
      key: "title",
      header: "Title",
      cell: (control) => (
        <span className="text-sm font-medium">{control.title}</span>
      ),
    },
    {
      key: "category",
      header: "Category",
      cell: (control) => (
        <Badge variant="outline">{control.category}</Badge>
      ),
      sortable: true,
    },
    {
      key: "severity",
      header: "Severity",
      cell: (control) => {
        const severityConfig = {
          critical: { variant: "destructive" as const, color: "text-red-600" },
          high: { variant: "destructive" as const, color: "text-orange-600" },
          medium: { variant: "secondary" as const, color: "text-amber-600" },
          low: { variant: "outline" as const, color: "" },
        }[control.severity];

        return (
          <Badge variant={severityConfig.variant} className={severityConfig.color}>
            {control.severity}
          </Badge>
        );
      },
      sortable: true,
    },
    {
      key: "status",
      header: "Status",
      cell: (control) => {
        const statusConfig = {
          completed: { variant: "outline" as const, icon: CheckCircle2, color: "text-green-500" },
          in_progress: { variant: "default" as const, icon: TrendingUp, color: "text-blue-500" },
          not_started: { variant: "secondary" as const, icon: AlertCircle, color: "text-gray-500" },
          not_applicable: { variant: "outline" as const, icon: AlertCircle, color: "text-gray-500" },
        }[control.status];

        const Icon = statusConfig.icon;

        return (
          <Badge variant={statusConfig.variant}>
            <Icon className={`h-3 w-3 mr-1 ${statusConfig.color}`} />
            {control.status.replace(/_/g, " ")}
          </Badge>
        );
      },
      sortable: true,
    },
    {
      key: "evidenceCount",
      header: "Evidence",
      cell: (control) => (
        <span className="text-sm">{control.evidenceCount}</span>
      ),
    },
  ];

  // Gap columns
  const gapColumns: DataTableColumn<ComplianceGap>[] = [
    {
      key: "controlId",
      header: "Control ID",
      cell: (gap) => (
        <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{gap.controlId}</code>
      ),
    },
    {
      key: "title",
      header: "Title",
      cell: (gap) => (
        <span className="text-sm font-medium">{gap.title}</span>
      ),
    },
    {
      key: "severity",
      header: "Severity",
      cell: (gap) => {
        const severityConfigMap: Record<string, "destructive" | "secondary" | "outline"> = {
          critical: "destructive",
          high: "destructive",
          medium: "secondary",
          low: "outline",
        };
        const severityConfig = severityConfigMap[gap.severity] || "outline";

        return <Badge variant={severityConfig}>{gap.severity}</Badge>;
      },
      sortable: true,
    },
    {
      key: "recommendation",
      header: "Recommendation",
      cell: (gap) => (
        <span className="text-sm text-muted-foreground">{gap.recommendation}</span>
      ),
    },
    {
      key: "estimatedEffort",
      header: "Effort",
      cell: (gap) => (
        <Badge variant="outline">{gap.estimatedEffort}</Badge>
      ),
    },
  ];

  const handleGenerateReport = async () => {
    await generateReport.mutateAsync({
      framework: selectedFramework,
      format: reportFormat,
      includeEvidence: true,
    });
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold" data-testid="text-page-title">
            Compliance Dashboard
          </h1>
          <p className="text-muted-foreground mt-1">
            Track compliance across multiple security frameworks
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Select value={reportFormat} onValueChange={(v) => setReportFormat(v as any)}>
            <SelectTrigger className="w-[120px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="pdf">PDF</SelectItem>
              <SelectItem value="json">JSON</SelectItem>
              <SelectItem value="csv">CSV</SelectItem>
            </SelectContent>
          </Select>
          <Button onClick={handleGenerateReport} disabled={generateReport.isPending}>
            <Download className="h-4 w-4 mr-2" />
            {generateReport.isPending ? "Generating..." : "Export Report"}
          </Button>
        </div>
      </div>

      {/* Framework Tabs */}
      <Tabs value={selectedFramework} onValueChange={setSelectedFramework}>
        <TabsList className="grid w-full grid-cols-7">
          <TabsTrigger value="SOC2">SOC 2</TabsTrigger>
          <TabsTrigger value="ISO27001">ISO 27001</TabsTrigger>
          <TabsTrigger value="NIST">NIST</TabsTrigger>
          <TabsTrigger value="PCI-DSS">PCI-DSS</TabsTrigger>
          <TabsTrigger value="HIPAA">HIPAA</TabsTrigger>
          <TabsTrigger value="GDPR">GDPR</TabsTrigger>
          <TabsTrigger value="FedRAMP">FedRAMP</TabsTrigger>
        </TabsList>

        <TabsContent value={selectedFramework} className="space-y-6 mt-6">
          {/* Metrics */}
          <MetricsGrid metrics={metrics} columns={4} data-testid="compliance-metrics" />

          {/* Coverage Progress */}
          <Card>
            <CardHeader>
              <CardTitle>Compliance Progress</CardTitle>
              <CardDescription>
                Overall compliance coverage for {selectedFramework}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">Coverage</span>
                  <span className="text-sm font-medium">{coveragePercentage.toFixed(1)}%</span>
                </div>
                <Progress value={coveragePercentage} className="h-2" />
              </div>

              <div className="grid grid-cols-4 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Completed:</span>{" "}
                  <span className="font-medium text-green-600">{controlsByStatus.completed}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">In Progress:</span>{" "}
                  <span className="font-medium text-blue-600">{controlsByStatus.in_progress}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Not Started:</span>{" "}
                  <span className="font-medium text-gray-600">{controlsByStatus.not_started}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Not Applicable:</span>{" "}
                  <span className="font-medium">{controlsByStatus.not_applicable}</span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Compliance Trend */}
          <TimeSeriesChart
            data={complianceTrendData}
            metrics={trendMetrics}
            type="area"
            title="Compliance Trend"
            description="Coverage percentage over the last 12 months"
            height={250}
            data-testid="compliance-trend-chart"
          />

          {/* Controls Table */}
          <Card>
            <CardHeader>
              <CardTitle>Control Matrix</CardTitle>
              <CardDescription>
                All controls for {selectedFramework} framework
              </CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable
                data={controls}
                columns={controlColumns}
                isLoading={false}
                emptyState={{
                  icon: <Shield className="h-12 w-12" />,
                  title: "No Controls",
                  description: "No controls found for this framework",
                }}
                searchable={true}
                searchPlaceholder="Search controls..."
                searchKeys={["controlId", "title", "category"]}
                paginated={true}
                pageSize={20}
                data-testid="controls-table"
              />
            </CardContent>
          </Card>

          {/* Gap Analysis */}
          {gaps.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Gap Analysis</CardTitle>
                <CardDescription>
                  Controls requiring attention for {selectedFramework}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable
                  data={gaps}
                  columns={gapColumns}
                  emptyState={{
                    icon: <CheckCircle2 className="h-12 w-12" />,
                    title: "No Gaps Found",
                    description: "All controls are compliant",
                  }}
                  searchable={true}
                  searchPlaceholder="Search gaps..."
                  searchKeys={["controlId", "title", "recommendation"]}
                  paginated={true}
                  pageSize={10}
                  data-testid="gaps-table"
                />
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
