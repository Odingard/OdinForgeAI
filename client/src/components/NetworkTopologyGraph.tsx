import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Server, Network, Shield, AlertTriangle } from "lucide-react";

interface AgentNode {
  id: string;
  hostname: string;
  ipAddress: string;
  status: "online" | "offline" | "degraded";
  connections: string[]; // IDs of connected agents
  riskLevel?: "low" | "medium" | "high" | "critical";
  role?: "controller" | "worker" | "sensor";
}

interface NetworkTopologyGraphProps {
  agents: AgentNode[];
  onAgentClick?: (agent: AgentNode) => void;
}

export function NetworkTopologyGraph({ agents, onAgentClick }: NetworkTopologyGraphProps) {
  // Group agents by role
  const controllers = agents.filter(a => a.role === "controller");
  const workers = agents.filter(a => a.role === "worker");
  const sensors = agents.filter(a => a.role === "sensor" || !a.role);

  const getStatusColor = (status: string) => {
    switch (status) {
      case "online": return "border-green-500 bg-green-500/10";
      case "degraded": return "border-orange-500 bg-orange-500/10";
      case "offline": return "border-red-500 bg-red-500/10";
      default: return "border-border bg-muted/30";
    }
  };

  const getStatusIndicator = (status: string) => {
    switch (status) {
      case "online": return "bg-green-500";
      case "degraded": return "bg-orange-500";
      case "offline": return "bg-red-500";
      default: return "bg-gray-500";
    }
  };

  const getRiskBadge = (riskLevel?: string) => {
    if (!riskLevel) return null;

    const variants = {
      low: "outline" as const,
      medium: "secondary" as const,
      high: "default" as const,
      critical: "destructive" as const,
    };

    return (
      <Badge variant={variants[riskLevel]} className="text-xs">
        {riskLevel}
      </Badge>
    );
  };

  const AgentCard = ({ agent }: { agent: AgentNode }) => {
    const Icon = agent.role === "controller" ? Shield : agent.role === "worker" ? Server : Network;
    const hasRisk = agent.riskLevel && ["high", "critical"].includes(agent.riskLevel);

    return (
      <Card
        className={`p-3 ${getStatusColor(agent.status)} cursor-pointer hover-elevate transition-all ${
          hasRisk ? "ring-2 ring-red-500/50" : ""
        }`}
        onClick={() => onAgentClick?.(agent)}
      >
        <div className="flex items-start gap-2">
          <div className="relative">
            <Icon className="h-5 w-5" />
            <div className={`absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full ${getStatusIndicator(agent.status)}`} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className="font-medium text-sm truncate">{agent.hostname}</span>
              {hasRisk && <AlertTriangle className="h-3 w-3 text-red-500 flex-shrink-0" />}
            </div>
            <code className="text-xs text-muted-foreground block truncate">{agent.ipAddress}</code>
            <div className="flex items-center gap-2 mt-1">
              {getRiskBadge(agent.riskLevel)}
              {agent.connections.length > 0 && (
                <span className="text-xs text-muted-foreground">
                  {agent.connections.length} connections
                </span>
              )}
            </div>
          </div>
        </div>
      </Card>
    );
  };

  // Calculate connections for rendering
  const renderConnections = (fromAgents: AgentNode[], toAgents: AgentNode[]) => {
    const connections: Array<{ from: AgentNode; to: AgentNode }> = [];

    fromAgents.forEach(from => {
      from.connections.forEach(connId => {
        const to = toAgents.find(a => a.id === connId);
        if (to) {
          connections.push({ from, to });
        }
      });
    });

    return connections;
  };

  return (
    <div className="space-y-6">
      {/* Legend */}
      <div className="flex items-center gap-6 text-sm flex-wrap">
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">Status:</span>
          <div className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full bg-green-500" />
            <span className="text-xs">Online</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full bg-orange-500" />
            <span className="text-xs">Degraded</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full bg-red-500" />
            <span className="text-xs">Offline</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">Role:</span>
          <div className="flex items-center gap-1">
            <Shield className="h-3 w-3" />
            <span className="text-xs">Controller</span>
          </div>
          <div className="flex items-center gap-1">
            <Server className="h-3 w-3" />
            <span className="text-xs">Worker</span>
          </div>
          <div className="flex items-center gap-1">
            <Network className="h-3 w-3" />
            <span className="text-xs">Sensor</span>
          </div>
        </div>
      </div>

      {/* Topology */}
      <div className="space-y-8">
        {/* Controllers Layer */}
        {controllers.length > 0 && (
          <div>
            <div className="text-xs uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
              <Shield className="h-3 w-3" />
              Controller Nodes ({controllers.length})
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {controllers.map(agent => (
                <AgentCard key={agent.id} agent={agent} />
              ))}
            </div>
          </div>
        )}

        {/* Workers Layer */}
        {workers.length > 0 && (
          <div>
            <div className="relative">
              {/* Connection lines */}
              {controllers.length > 0 && (
                <div className="absolute -top-4 left-1/2 transform -translate-x-1/2 w-0.5 h-4 bg-border" />
              )}
            </div>
            <div className="text-xs uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
              <Server className="h-3 w-3" />
              Worker Nodes ({workers.length})
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
              {workers.map(agent => (
                <AgentCard key={agent.id} agent={agent} />
              ))}
            </div>
          </div>
        )}

        {/* Sensors Layer */}
        {sensors.length > 0 && (
          <div>
            <div className="relative">
              {/* Connection lines */}
              {(controllers.length > 0 || workers.length > 0) && (
                <div className="absolute -top-4 left-1/2 transform -translate-x-1/2 w-0.5 h-4 bg-border" />
              )}
            </div>
            <div className="text-xs uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
              <Network className="h-3 w-3" />
              Sensor Nodes ({sensors.length})
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-3">
              {sensors.map(agent => (
                <AgentCard key={agent.id} agent={agent} />
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Connection Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
        <Card className="p-4">
          <div className="text-sm text-muted-foreground mb-1">Total Agents</div>
          <div className="text-2xl font-bold">{agents.length}</div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-muted-foreground mb-1">Online</div>
          <div className="text-2xl font-bold text-green-500">
            {agents.filter(a => a.status === "online").length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-muted-foreground mb-1">High Risk</div>
          <div className="text-2xl font-bold text-red-500">
            {agents.filter(a => a.riskLevel === "high" || a.riskLevel === "critical").length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-muted-foreground mb-1">Total Connections</div>
          <div className="text-2xl font-bold">
            {agents.reduce((sum, a) => sum + a.connections.length, 0)}
          </div>
        </Card>
      </div>
    </div>
  );
}
