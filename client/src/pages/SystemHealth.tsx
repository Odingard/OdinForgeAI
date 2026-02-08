import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { MetricsGrid, Metric } from "@/components/shared/MetricsGrid";
import { TimeSeriesChart, TimeSeriesDataPoint, TimeSeriesMetric } from "@/components/shared/TimeSeriesChart";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Activity,
  Server,
  Database,
  Wifi,
  HardDrive,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  TrendingUp,
  Clock,
} from "lucide-react";
import { queryClient } from "@/lib/queryClient";

interface SystemHealthData {
  uptime: number;
  activeAgents: number;
  queueDepth: number;
  evaluationRate: number;
}

interface ComponentHealth {
  name: string;
  status: "healthy" | "degraded" | "down";
  lastCheck: string;
  responseTime?: number;
  message?: string;
}

export default function SystemHealth() {
  const [refreshKey, setRefreshKey] = useState(0);

  // Fetch system metrics
  const { data: defensivePosture } = useQuery({
    queryKey: ["/api/stats/defensive-posture", refreshKey],
    refetchInterval: 30000,
  });

  const { data: agentStats } = useQuery({
    queryKey: ["/api/agents/stats/summary", refreshKey],
    refetchInterval: 15000,
  });

  const { data: jobStats } = useQuery({
    queryKey: ["/api/jobs/stats", refreshKey],
    refetchInterval: 15000,
  });

  const { data: aevStats } = useQuery({
    queryKey: ["/api/aev/stats", refreshKey],
    refetchInterval: 30000,
  });

  // Calculate uptime (mock - would come from server in real implementation)
  const uptime = 99.9; // percentage
  const uptimeHours = 720; // hours

  // Main metrics
  const metrics: Metric[] = [
    {
      label: "System Uptime",
      value: `${uptime}%`,
      icon: Activity,
      iconColor: "text-green-500",
      valueColor: "text-green-600",
      trend: {
        value: 0.2,
        label: "vs last month",
        direction: "up",
      },
      "data-testid": "metric-uptime",
    },
    {
      label: "Active Agents",
      value: (agentStats as any)?.onlineAgents || 0,
      icon: Server,
      iconColor: "text-cyan-400",
      "data-testid": "metric-active-agents",
    },
    {
      label: "Queue Depth",
      value: ((jobStats as any)?.pending || 0) + ((jobStats as any)?.running || 0),
      icon: Clock,
      iconColor: "text-amber-500",
      "data-testid": "metric-queue-depth",
    },
    {
      label: "Evaluations/Day",
      value: (aevStats as any)?.totalEvaluations || 0,
      icon: TrendingUp,
      iconColor: "text-blue-500",
      "data-testid": "metric-eval-rate",
    },
    {
      label: "Total Findings",
      value: (agentStats as any)?.totalFindings || 0,
      icon: AlertTriangle,
      iconColor: "text-orange-500",
      "data-testid": "metric-total-findings",
    },
    {
      label: "Critical Issues",
      value: (agentStats as any)?.criticalFindings || 0,
      icon: AlertTriangle,
      iconColor: "text-red-500",
      valueColor: "text-red-600",
      "data-testid": "metric-critical-findings",
    },
  ];

  // Component health status (mock data - would come from health check endpoints)
  const components: ComponentHealth[] = [
    {
      name: "PostgreSQL Database",
      status: "healthy",
      lastCheck: new Date().toISOString(),
      responseTime: 5,
    },
    {
      name: "Redis Cache",
      status: "healthy",
      lastCheck: new Date().toISOString(),
      responseTime: 2,
    },
    {
      name: "WebSocket Server",
      status: (agentStats as any)?.onlineAgents ? "healthy" : "degraded",
      lastCheck: new Date().toISOString(),
      message: (agentStats as any)?.onlineAgents ? `${(agentStats as any).onlineAgents} active connections` : "No active connections",
    },
    {
      name: "S3 Storage",
      status: "healthy",
      lastCheck: new Date().toISOString(),
      responseTime: 12,
    },
    {
      name: "Job Queue",
      status: ((jobStats as any)?.running || 0) > 50 ? "degraded" : "healthy",
      lastCheck: new Date().toISOString(),
      message: `${(jobStats as any)?.running || 0} running, ${(jobStats as any)?.pending || 0} pending`,
    },
  ];

  // Generate mock time series data for charts
  const generateTimeSeriesData = (hours: number = 24): TimeSeriesDataPoint[] => {
    const data: TimeSeriesDataPoint[] = [];
    const now = Date.now();

    for (let i = hours; i >= 0; i--) {
      const timestamp = new Date(now - i * 60 * 60 * 1000);
      const hour = timestamp.getHours();

      data.push({
        timestamp: `${hour}:00`,
        agents: Math.floor(Math.random() * 5) + ((agentStats as any)?.onlineAgents || 3),
        jobs: Math.floor(Math.random() * 10) + 5,
        evaluations: Math.floor(Math.random() * 8) + 2,
      });
    }

    return data;
  };

  const timeSeriesData = useMemo(() => generateTimeSeriesData(24), [agentStats]);

  const agentMetrics: TimeSeriesMetric[] = [
    { key: "agents", label: "Active Agents", color: "hsl(var(--chart-1))" },
  ];

  const activityMetrics: TimeSeriesMetric[] = [
    { key: "jobs", label: "Job Throughput", color: "hsl(var(--chart-2))" },
    { key: "evaluations", label: "Evaluations", color: "hsl(var(--chart-3))" },
  ];

  const handleRefresh = () => {
    setRefreshKey(prev => prev + 1);
    queryClient.invalidateQueries({ queryKey: ["/api/stats/defensive-posture"] });
    queryClient.invalidateQueries({ queryKey: ["/api/agents/stats/summary"] });
    queryClient.invalidateQueries({ queryKey: ["/api/jobs/stats"] });
    queryClient.invalidateQueries({ queryKey: ["/api/aev/stats"] });
  };

  const getStatusColor = (status: ComponentHealth["status"]) => {
    switch (status) {
      case "healthy":
        return "text-green-500";
      case "degraded":
        return "text-amber-500";
      case "down":
        return "text-red-500";
      default:
        return "text-gray-500";
    }
  };

  const getStatusIcon = (status: ComponentHealth["status"]) => {
    switch (status) {
      case "healthy":
        return CheckCircle2;
      case "degraded":
      case "down":
        return AlertTriangle;
      default:
        return Activity;
    }
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold" data-testid="text-page-title">
            System Health
          </h1>
          <p className="text-muted-foreground mt-1">
            Monitor platform health, performance metrics, and component status
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={handleRefresh}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Metrics Grid */}
      <MetricsGrid metrics={metrics} columns={6} data-testid="health-metrics" />

      {/* Time Series Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <TimeSeriesChart
          data={timeSeriesData}
          metrics={agentMetrics}
          type="area"
          title="Agent Heartbeats"
          description="Active agents over the last 24 hours"
          height={250}
          data-testid="chart-agent-heartbeats"
        />

        <TimeSeriesChart
          data={timeSeriesData}
          metrics={activityMetrics}
          type="line"
          title="System Activity"
          description="Job throughput and evaluation rate"
          height={250}
          data-testid="chart-system-activity"
        />
      </div>

      {/* Component Health */}
      <Card>
        <CardHeader>
          <CardTitle>Component Health</CardTitle>
          <CardDescription>
            Status of critical system components
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {components.map((component) => {
              const StatusIcon = getStatusIcon(component.status);
              const statusColor = getStatusColor(component.status);

              return (
                <Card key={component.name} className="hover-elevate">
                  <CardHeader className="pb-3">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2">
                        <StatusIcon className={`h-4 w-4 ${statusColor}`} />
                        <CardTitle className="text-sm font-medium">
                          {component.name}
                        </CardTitle>
                      </div>
                      <Badge
                        variant={component.status === "healthy" ? "outline" : component.status === "degraded" ? "secondary" : "destructive"}
                      >
                        {component.status}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {component.responseTime !== undefined && (
                      <div className="text-xs text-muted-foreground">
                        Response: <span className="font-medium text-foreground">{component.responseTime}ms</span>
                      </div>
                    )}
                    {component.message && (
                      <div className="text-xs text-muted-foreground">
                        {component.message}
                      </div>
                    )}
                    <div className="text-xs text-muted-foreground">
                      Last checked: {new Date(component.lastCheck).toLocaleTimeString()}
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* System Info */}
      <Card>
        <CardHeader>
          <CardTitle>System Information</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-muted-foreground">Platform Version:</span>{" "}
              <span className="font-medium">2.1.0</span>
            </div>
            <div>
              <span className="text-muted-foreground">Uptime:</span>{" "}
              <span className="font-medium">{uptimeHours}h</span>
            </div>
            <div>
              <span className="text-muted-foreground">Total Agents:</span>{" "}
              <span className="font-medium">{(agentStats as any)?.totalAgents || 0}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Total Jobs:</span>{" "}
              <span className="font-medium">{(jobStats as any)?.total || 0}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
