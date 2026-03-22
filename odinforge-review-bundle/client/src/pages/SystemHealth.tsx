import { useQuery } from "@tanstack/react-query";
import { MetricsGrid, Metric } from "@/components/shared/MetricsGrid";
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

interface ComponentHealth {
  name: string;
  status: "healthy" | "degraded" | "down";
  responseTime?: number;
  message?: string;
}

interface HealthStatusResponse {
  components: ComponentHealth[];
  uptime: {
    ms: number;
    hours: number;
    minutes: number;
    formatted: string;
  };
  version: string;
  ts: string;
}

interface AgentStatsResponse {
  totalAgents: number;
  onlineAgents: number;
  offlineAgents: number;
  staleAgents: number;
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  newFindings: number;
}

interface JobStatsResponse {
  waiting: number;
  active: number;
  completed: number;
  failed: number;
  delayed: number;
  usingRedis: boolean;
}

interface AevStatsResponse {
  total: number;
  active: number;
  completed: number;
  exploitable: number;
  safe: number;
  avgConfidence: number;
  totalEvaluations: number;
}

export default function SystemHealth() {
  const { data: healthStatus, isLoading: healthLoading } = useQuery<HealthStatusResponse>({
    queryKey: ["/api/system/health-status"],
    refetchInterval: 15000,
  });

  const { data: agentStats } = useQuery<AgentStatsResponse>({
    queryKey: ["/api/agents/stats/summary"],
    refetchInterval: 15000,
  });

  const { data: jobStats } = useQuery<JobStatsResponse>({
    queryKey: ["/api/jobs/stats"],
    refetchInterval: 15000,
  });

  const { data: aevStats } = useQuery<AevStatsResponse>({
    queryKey: ["/api/aev/stats"],
    refetchInterval: 30000,
  });

  // Main metrics — all from real API data
  const metrics: Metric[] = [
    {
      label: "System Uptime",
      value: healthStatus?.uptime?.formatted || "—",
      icon: Activity,
      iconColor: "text-green-500",
      valueColor: "text-green-600",
      "data-testid": "metric-uptime",
    },
    {
      label: "Active Agents",
      value: agentStats?.onlineAgents ?? 0,
      icon: Server,
      iconColor: "text-cyan-400",
      "data-testid": "metric-active-agents",
    },
    {
      label: "Queue Depth",
      value: (jobStats?.waiting ?? 0) + (jobStats?.active ?? 0),
      icon: Clock,
      iconColor: "text-amber-500",
      "data-testid": "metric-queue-depth",
    },
    {
      label: "Evaluations",
      value: aevStats?.totalEvaluations ?? 0,
      icon: TrendingUp,
      iconColor: "text-blue-500",
      "data-testid": "metric-eval-rate",
    },
    {
      label: "Total Findings",
      value: agentStats?.totalFindings ?? 0,
      icon: AlertTriangle,
      iconColor: "text-orange-500",
      "data-testid": "metric-total-findings",
    },
    {
      label: "Critical Issues",
      value: agentStats?.criticalFindings ?? 0,
      icon: AlertTriangle,
      iconColor: "text-red-500",
      valueColor: "text-red-600",
      "data-testid": "metric-critical-findings",
    },
  ];

  // Component health from real server checks
  const components: ComponentHealth[] = healthStatus?.components || [];

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ["/api/system/health-status"] });
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

  const getComponentIcon = (name: string) => {
    if (name.includes("PostgreSQL") || name.includes("Database")) return Database;
    if (name.includes("Redis")) return HardDrive;
    if (name.includes("WebSocket")) return Wifi;
    if (name.includes("S3") || name.includes("Storage")) return HardDrive;
    if (name.includes("Queue") || name.includes("Job")) return Server;
    return Activity;
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

      {/* Component Health */}
      <Card>
        <CardHeader>
          <CardTitle>Component Health</CardTitle>
          <CardDescription>
            Live status of critical infrastructure components
          </CardDescription>
        </CardHeader>
        <CardContent>
          {healthLoading ? (
            <div className="text-sm text-muted-foreground">Checking component health...</div>
          ) : components.length === 0 ? (
            <div className="text-sm text-muted-foreground">No health data available</div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {components.map((component) => {
                const StatusIcon = getStatusIcon(component.status);
                const ComponentIcon = getComponentIcon(component.name);
                const statusColor = getStatusColor(component.status);

                return (
                  <Card key={component.name} className="hover-elevate">
                    <CardHeader className="pb-3">
                      <div className="flex items-start justify-between">
                        <div className="flex items-center gap-2">
                          <ComponentIcon className="h-4 w-4 text-muted-foreground" />
                          <CardTitle className="text-sm font-medium">
                            {component.name}
                          </CardTitle>
                        </div>
                        <Badge
                          variant={component.status === "healthy" ? "outline" : component.status === "degraded" ? "secondary" : "destructive"}
                          className="flex items-center gap-1"
                        >
                          <StatusIcon className={`h-3 w-3 ${statusColor}`} />
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
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Agent Overview */}
      {agentStats && (
        <Card>
          <CardHeader>
            <CardTitle>Agent Fleet Status</CardTitle>
            <CardDescription>
              Endpoint agent health and finding summary
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div className="space-y-1">
                <span className="text-muted-foreground">Total Agents</span>
                <p className="text-lg font-semibold">{agentStats.totalAgents}</p>
              </div>
              <div className="space-y-1">
                <span className="text-muted-foreground">Online</span>
                <p className="text-lg font-semibold text-green-600">{agentStats.onlineAgents}</p>
              </div>
              <div className="space-y-1">
                <span className="text-muted-foreground">Offline</span>
                <p className="text-lg font-semibold text-red-500">{agentStats.offlineAgents}</p>
              </div>
              <div className="space-y-1">
                <span className="text-muted-foreground">Stale</span>
                <p className="text-lg font-semibold text-amber-500">{agentStats.staleAgents}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Queue & Jobs */}
      {jobStats && (
        <Card>
          <CardHeader>
            <CardTitle>Job Queue</CardTitle>
            <CardDescription>
              Background job processing status
              {jobStats.usingRedis ? " (Redis-backed)" : " (In-memory)"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-sm">
              <div className="space-y-1">
                <span className="text-muted-foreground">Waiting</span>
                <p className="text-lg font-semibold">{jobStats.waiting}</p>
              </div>
              <div className="space-y-1">
                <span className="text-muted-foreground">Active</span>
                <p className="text-lg font-semibold text-blue-500">{jobStats.active}</p>
              </div>
              <div className="space-y-1">
                <span className="text-muted-foreground">Completed</span>
                <p className="text-lg font-semibold text-green-600">{jobStats.completed}</p>
              </div>
              <div className="space-y-1">
                <span className="text-muted-foreground">Failed</span>
                <p className="text-lg font-semibold text-red-500">{jobStats.failed}</p>
              </div>
              <div className="space-y-1">
                <span className="text-muted-foreground">Delayed</span>
                <p className="text-lg font-semibold text-amber-500">{jobStats.delayed}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* System Info */}
      <Card>
        <CardHeader>
          <CardTitle>System Information</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="text-muted-foreground">Platform Version:</span>{" "}
              <span className="font-medium">{healthStatus?.version || "—"}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Uptime:</span>{" "}
              <span className="font-medium">{healthStatus?.uptime?.formatted || "—"}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Total Agents:</span>{" "}
              <span className="font-medium">{agentStats?.totalAgents ?? 0}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Redis:</span>{" "}
              <span className="font-medium">{jobStats?.usingRedis ? "Connected" : "In-memory fallback"}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
