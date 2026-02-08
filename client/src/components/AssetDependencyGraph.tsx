import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Database, Server, Globe, Shield, ArrowRight, AlertCircle } from "lucide-react";

interface DependencyNode {
  id: string;
  name: string;
  type: "database" | "application" | "load_balancer" | "api" | "service" | "storage";
  criticality: "low" | "medium" | "high" | "critical";
  dependencies: string[]; // IDs of nodes this depends on
  vulnerabilityCount?: number;
}

interface AssetDependencyGraphProps {
  nodes: DependencyNode[];
  onNodeClick?: (node: DependencyNode) => void;
}

export function AssetDependencyGraph({ nodes, onNodeClick }: AssetDependencyGraphProps) {
  // Build dependency tree - find root nodes (nodes with no dependencies)
  const rootNodes = nodes.filter(node => node.dependencies.length === 0);

  // Group nodes by depth level
  const getNodeDepth = (nodeId: string, visited: Set<string> = new Set()): number => {
    if (visited.has(nodeId)) return 0; // Circular dependency protection

    const node = nodes.find(n => n.id === nodeId);
    if (!node || node.dependencies.length === 0) return 0;

    visited.add(nodeId);
    const depths = node.dependencies.map(depId => getNodeDepth(depId, new Set(visited)) + 1);
    return Math.max(...depths);
  };

  // Group nodes by depth
  const maxDepth = Math.max(...nodes.map(n => getNodeDepth(n.id)));
  const layers: DependencyNode[][] = [];

  for (let i = 0; i <= maxDepth; i++) {
    layers[i] = nodes.filter(n => getNodeDepth(n.id) === i);
  }

  const getIcon = (type: string) => {
    switch (type) {
      case "database": return Database;
      case "application": return Server;
      case "load_balancer": return Globe;
      case "api": return Shield;
      default: return Server;
    }
  };

  const getCriticalityColor = (criticality: string) => {
    switch (criticality) {
      case "critical": return "border-red-500 bg-red-500/10 text-red-400";
      case "high": return "border-orange-500 bg-orange-500/10 text-orange-400";
      case "medium": return "border-amber-500 bg-amber-500/10 text-amber-400";
      case "low": return "border-emerald-500 bg-emerald-500/10 text-emerald-400";
      default: return "border-border bg-muted/30";
    }
  };

  const getCriticalityBadgeVariant = (criticality: string) => {
    switch (criticality) {
      case "critical": return "destructive" as const;
      case "high": return "default" as const;
      case "medium": return "secondary" as const;
      default: return "outline" as const;
    }
  };

  const getDependents = (nodeId: string) => {
    return nodes.filter(n => n.dependencies.includes(nodeId));
  };

  const NodeCard = ({ node }: { node: DependencyNode }) => {
    const Icon = getIcon(node.type);
    const dependents = getDependents(node.id);
    const hasVulnerabilities = (node.vulnerabilityCount || 0) > 0;

    return (
      <Card
        className={`p-4 ${getCriticalityColor(node.criticality)} cursor-pointer hover-elevate transition-all border-2 ${
          hasVulnerabilities ? "ring-2 ring-red-500/50" : ""
        }`}
        onClick={() => onNodeClick?.(node)}
      >
        <div className="space-y-2">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              <Icon className="h-5 w-5 flex-shrink-0" />
              <div>
                <div className="font-medium text-sm">{node.name}</div>
                <Badge variant="outline" className="text-xs mt-1 capitalize">
                  {node.type.replace("_", " ")}
                </Badge>
              </div>
            </div>
            {hasVulnerabilities && (
              <AlertCircle className="h-4 w-4 text-red-500 flex-shrink-0" />
            )}
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant={getCriticalityBadgeVariant(node.criticality)} className="text-xs">
              {node.criticality}
            </Badge>
            {node.vulnerabilityCount && node.vulnerabilityCount > 0 && (
              <Badge variant="destructive" className="text-xs">
                {node.vulnerabilityCount} vulns
              </Badge>
            )}
          </div>

          <div className="text-xs text-muted-foreground">
            <div>↑ {dependents.length} dependent(s)</div>
            <div>↓ {node.dependencies.length} dependency(ies)</div>
          </div>
        </div>
      </Card>
    );
  };

  const renderDependencyArrows = (fromNode: DependencyNode, layer: number) => {
    if (fromNode.dependencies.length === 0) return null;

    return (
      <div className="flex items-center justify-center my-2">
        <div className="flex flex-col items-center gap-1">
          <ArrowRight className="h-4 w-4 text-muted-foreground rotate-90" />
          <div className="text-xs text-muted-foreground">depends on</div>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Legend */}
      <div className="flex items-center gap-6 text-sm flex-wrap">
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground">Criticality:</span>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded border-2 border-emerald-500 bg-emerald-500/10" />
            <span className="text-xs">Low</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded border-2 border-amber-500 bg-amber-500/10" />
            <span className="text-xs">Medium</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded border-2 border-orange-500 bg-orange-500/10" />
            <span className="text-xs">High</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded border-2 border-red-500 bg-red-500/10" />
            <span className="text-xs">Critical</span>
          </div>
        </div>
      </div>

      {/* Dependency Layers */}
      <div className="space-y-6">
        {layers.map((layer, layerIndex) => {
          if (layer.length === 0) return null;

          const layerLabel = layerIndex === 0
            ? "Foundation Layer (No Dependencies)"
            : layerIndex === maxDepth
            ? "Top Layer (Most Dependent)"
            : `Layer ${layerIndex}`;

          return (
            <div key={layerIndex}>
              <div className="text-xs uppercase tracking-wider text-muted-foreground mb-3">
                {layerLabel} ({layer.length} asset{layer.length !== 1 ? "s" : ""})
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {layer.map(node => (
                  <NodeCard key={node.id} node={node} />
                ))}
              </div>
              {/* Arrow between layers */}
              {layerIndex < layers.length - 1 && layers[layerIndex + 1].length > 0 && (
                <div className="flex items-center justify-center my-4">
                  <div className="flex flex-col items-center gap-1">
                    <div className="w-0.5 h-8 bg-border" />
                    <ArrowRight className="h-4 w-4 text-muted-foreground rotate-90" />
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Critical Path Highlight */}
      {nodes.filter(n => n.criticality === "critical").length > 0 && (
        <Card className="p-4 bg-red-500/5 border-red-500/30">
          <div className="flex items-center gap-2 mb-2">
            <AlertCircle className="h-4 w-4 text-red-400" />
            <span className="font-medium text-red-400">Critical Assets</span>
          </div>
          <div className="text-sm text-muted-foreground">
            {nodes.filter(n => n.criticality === "critical").length} critical assets in the dependency chain.
            Compromise of these assets could have severe impact on dependent systems.
          </div>
          <div className="flex flex-wrap gap-2 mt-3">
            {nodes
              .filter(n => n.criticality === "critical")
              .map(node => (
                <Badge key={node.id} variant="destructive" className="text-xs">
                  {node.name}
                </Badge>
              ))}
          </div>
        </Card>
      )}

      {/* Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="p-4">
          <div className="text-sm text-muted-foreground mb-1">Total Assets</div>
          <div className="text-2xl font-bold">{nodes.length}</div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-muted-foreground mb-1">Critical Assets</div>
          <div className="text-2xl font-bold text-red-500">
            {nodes.filter(n => n.criticality === "critical").length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-muted-foreground mb-1">With Vulnerabilities</div>
          <div className="text-2xl font-bold text-orange-500">
            {nodes.filter(n => (n.vulnerabilityCount || 0) > 0).length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-muted-foreground mb-1">Dependency Depth</div>
          <div className="text-2xl font-bold">{maxDepth + 1}</div>
        </Card>
      </div>
    </div>
  );
}
