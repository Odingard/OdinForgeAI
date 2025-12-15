import { useState } from "react";
import { 
  Target, Shield, AlertTriangle, Clock, Gauge, Network, 
  ChevronDown, ChevronUp, Zap, ArrowRight, Layers
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";

interface AttackNode {
  id: string;
  label: string;
  description: string;
  nodeType: "entry" | "pivot" | "objective" | "dead-end";
  tactic: string;
  compromiseLevel: "none" | "limited" | "user" | "admin" | "system";
  assets?: string[];
  discoveredBy?: "recon" | "exploit" | "lateral" | "business-logic" | "impact";
}

interface AttackEdge {
  id: string;
  source: string;
  target: string;
  technique: string;
  techniqueId?: string;
  description: string;
  successProbability: number;
  complexity: "trivial" | "low" | "medium" | "high" | "expert";
  timeEstimate: number;
  prerequisites?: string[];
  alternatives?: string[];
  edgeType: "primary" | "alternative" | "fallback";
  discoveredBy?: "recon" | "exploit" | "lateral" | "business-logic" | "impact";
}

interface AttackGraph {
  nodes: AttackNode[];
  edges: AttackEdge[];
  entryNodeId: string;
  objectiveNodeIds: string[];
  criticalPath: string[];
  alternativePaths?: string[][];
  killChainCoverage: string[];
  complexityScore: number;
  timeToCompromise: {
    minimum: number;
    expected: number;
    maximum: number;
    unit: "minutes" | "hours" | "days";
  };
  chainedExploits?: Array<{
    name: string;
    techniques: string[];
    combinedImpact: string;
  }>;
}

interface AttackGraphVisualizerProps {
  attackGraph: AttackGraph;
  isExploitable: boolean;
}

export function AttackGraphVisualizer({ attackGraph, isExploitable }: AttackGraphVisualizerProps) {
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());
  const [showAlternativePaths, setShowAlternativePaths] = useState(false);

  const toggleNode = (nodeId: string) => {
    const newExpanded = new Set(expandedNodes);
    if (newExpanded.has(nodeId)) {
      newExpanded.delete(nodeId);
    } else {
      newExpanded.add(nodeId);
    }
    setExpandedNodes(newExpanded);
  };

  const getNodeTypeIcon = (nodeType: string) => {
    switch (nodeType) {
      case "entry": return Target;
      case "pivot": return Network;
      case "objective": return Zap;
      case "dead-end": return Shield;
      default: return Network;
    }
  };

  const getNodeTypeColor = (nodeType: string, isOnCriticalPath: boolean) => {
    if (isOnCriticalPath) {
      switch (nodeType) {
        case "entry": return "border-cyan-500 bg-cyan-500/10";
        case "objective": return "border-red-500 bg-red-500/10";
        default: return "border-orange-500 bg-orange-500/10";
      }
    }
    return "border-border bg-muted/30";
  };

  const getCompromiseLevelColor = (level: string) => {
    switch (level) {
      case "system": return "bg-red-500/10 text-red-400 border-red-500/30";
      case "admin": return "bg-orange-500/10 text-orange-400 border-orange-500/30";
      case "user": return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "limited": return "bg-blue-500/10 text-blue-400 border-blue-500/30";
      default: return "bg-muted text-muted-foreground border-border";
    }
  };

  const getComplexityColor = (complexity: string) => {
    switch (complexity) {
      case "trivial": return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "low": return "bg-blue-500/10 text-blue-400 border-blue-500/30";
      case "medium": return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "high": return "bg-orange-500/10 text-orange-400 border-orange-500/30";
      case "expert": return "bg-red-500/10 text-red-400 border-red-500/30";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const getSuccessProbColor = (prob: number) => {
    if (prob >= 80) return "text-red-400";
    if (prob >= 60) return "text-orange-400";
    if (prob >= 40) return "text-amber-400";
    return "text-emerald-400";
  };

  const formatTactic = (tactic: string) => {
    return tactic.split("-").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
  };

  const isNodeOnCriticalPath = (nodeId: string) => {
    return attackGraph.criticalPath.includes(nodeId);
  };

  const getEdgesFromNode = (nodeId: string) => {
    return attackGraph.edges.filter(e => e.source === nodeId);
  };

  const getNodeById = (nodeId: string) => {
    return attackGraph.nodes.find(n => n.id === nodeId);
  };

  const orderedNodes = attackGraph.criticalPath
    .map(id => getNodeById(id))
    .filter((n): n is AttackNode => n !== undefined);

  if (attackGraph.nodes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <div className="p-4 rounded-full bg-emerald-500/10 mb-4">
          <Shield className="h-10 w-10 text-emerald-400" />
        </div>
        <h4 className="font-semibold text-emerald-400">No Attack Graph Generated</h4>
        <p className="text-sm text-muted-foreground mt-1 max-w-xs">
          The AI agents could not construct an attack graph for this exposure.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6" data-testid="attack-graph-visualizer">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-muted/30 rounded-lg p-4 border border-border">
          <div className="flex items-center gap-2 mb-2">
            <Gauge className="h-4 w-4 text-muted-foreground" />
            <span className="text-xs uppercase tracking-wider text-muted-foreground">Complexity</span>
          </div>
          <div className="text-2xl font-bold text-foreground">{attackGraph.complexityScore}</div>
          <div className="text-xs text-muted-foreground">out of 100</div>
        </div>
        
        <div className="bg-muted/30 rounded-lg p-4 border border-border">
          <div className="flex items-center gap-2 mb-2">
            <Clock className="h-4 w-4 text-muted-foreground" />
            <span className="text-xs uppercase tracking-wider text-muted-foreground">Time to Compromise</span>
          </div>
          <div className="text-2xl font-bold text-foreground">{attackGraph.timeToCompromise.expected}</div>
          <div className="text-xs text-muted-foreground">{attackGraph.timeToCompromise.unit}</div>
        </div>
        
        <div className="bg-muted/30 rounded-lg p-4 border border-border">
          <div className="flex items-center gap-2 mb-2">
            <Network className="h-4 w-4 text-muted-foreground" />
            <span className="text-xs uppercase tracking-wider text-muted-foreground">Attack Steps</span>
          </div>
          <div className="text-2xl font-bold text-foreground">{attackGraph.criticalPath.length}</div>
          <div className="text-xs text-muted-foreground">critical path</div>
        </div>
        
        <div className="bg-muted/30 rounded-lg p-4 border border-border">
          <div className="flex items-center gap-2 mb-2">
            <Layers className="h-4 w-4 text-muted-foreground" />
            <span className="text-xs uppercase tracking-wider text-muted-foreground">Kill Chain Coverage</span>
          </div>
          <div className="text-2xl font-bold text-foreground">{attackGraph.killChainCoverage.length}</div>
          <div className="text-xs text-muted-foreground">tactics</div>
        </div>
      </div>

      <div className="bg-muted/20 rounded-lg p-4 border border-border">
        <div className="flex items-center gap-2 mb-3">
          <AlertTriangle className={`h-4 w-4 ${isExploitable ? "text-red-400" : "text-emerald-400"}`} />
          <span className="text-sm font-medium text-foreground">MITRE ATT&CK Kill Chain Coverage</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {attackGraph.killChainCoverage.map((tactic, index) => (
            <Badge 
              key={tactic} 
              className="bg-cyan-500/10 text-cyan-400 border-cyan-500/30"
              data-testid={`kill-chain-tactic-${index}`}
            >
              {formatTactic(tactic)}
            </Badge>
          ))}
        </div>
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h4 className="font-semibold text-foreground flex items-center gap-2">
            <Target className="h-4 w-4" />
            Critical Attack Path
          </h4>
          {attackGraph.alternativePaths && attackGraph.alternativePaths.length > 0 && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowAlternativePaths(!showAlternativePaths)}
              data-testid="button-toggle-alt-paths"
            >
              {showAlternativePaths ? "Hide" : "Show"} {attackGraph.alternativePaths.length} Alternative Path(s)
            </Button>
          )}
        </div>

        <div className="relative">
          {orderedNodes.map((node, index) => {
            const NodeIcon = getNodeTypeIcon(node.nodeType);
            const outgoingEdges = getEdgesFromNode(node.id);
            const nextNodeId = attackGraph.criticalPath[index + 1];
            const criticalEdge = outgoingEdges.find(e => e.target === nextNodeId);
            const isExpanded = expandedNodes.has(node.id);

            return (
              <div key={node.id} data-testid={`graph-node-${node.id}`}>
                <Collapsible open={isExpanded} onOpenChange={() => toggleNode(node.id)}>
                  <div className="flex gap-4">
                    <div className="flex flex-col items-center">
                      <div className={`w-12 h-12 rounded-full flex items-center justify-center border-2 ${
                        getNodeTypeColor(node.nodeType, true)
                      }`}>
                        <NodeIcon className={`h-5 w-5 ${
                          node.nodeType === "entry" ? "text-cyan-400" :
                          node.nodeType === "objective" ? "text-red-400" :
                          "text-orange-400"
                        }`} />
                      </div>
                      {index < orderedNodes.length - 1 && (
                        <div className="w-0.5 flex-1 min-h-8 bg-gradient-to-b from-orange-500/50 to-orange-500/20" />
                      )}
                    </div>
                    
                    <div className="flex-1 pb-4">
                      <CollapsibleTrigger asChild>
                        <div 
                          className="p-4 rounded-lg border border-border bg-card hover-elevate cursor-pointer"
                          data-testid={`node-trigger-${node.id}`}
                        >
                          <div className="flex items-start justify-between gap-4">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap mb-1">
                                <Badge className={getCompromiseLevelColor(node.compromiseLevel)}>
                                  {node.compromiseLevel.toUpperCase()}
                                </Badge>
                                <Badge className="bg-purple-500/10 text-purple-400 border-purple-500/30">
                                  {formatTactic(node.tactic)}
                                </Badge>
                                <Badge className={
                                  node.nodeType === "entry" ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/30" :
                                  node.nodeType === "objective" ? "bg-red-500/10 text-red-400 border-red-500/30" :
                                  "bg-muted text-muted-foreground border-border"
                                }>
                                  {node.nodeType.toUpperCase()}
                                </Badge>
                              </div>
                              <h5 className="font-medium text-foreground">{node.label}</h5>
                              <p className="text-sm text-muted-foreground mt-1 line-clamp-2">{node.description}</p>
                            </div>
                            {isExpanded ? (
                              <ChevronUp className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                            ) : (
                              <ChevronDown className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                            )}
                          </div>
                        </div>
                      </CollapsibleTrigger>

                      <CollapsibleContent>
                        <div className="mt-2 p-4 rounded-lg border border-border bg-muted/30 space-y-3">
                          {node.assets && node.assets.length > 0 && (
                            <div>
                              <label className="text-xs uppercase tracking-wider text-muted-foreground block mb-1">
                                Affected Assets
                              </label>
                              <div className="flex flex-wrap gap-1">
                                {node.assets.map((asset, i) => (
                                  <code key={i} className="text-xs px-2 py-0.5 rounded bg-background/50 text-foreground">
                                    {asset}
                                  </code>
                                ))}
                              </div>
                            </div>
                          )}
                          {node.discoveredBy && (
                            <div>
                              <label className="text-xs uppercase tracking-wider text-muted-foreground block mb-1">
                                Discovered By
                              </label>
                              <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/30">
                                {node.discoveredBy.toUpperCase()} Agent
                              </Badge>
                            </div>
                          )}
                        </div>
                      </CollapsibleContent>

                      {criticalEdge && (
                        <div className="mt-3 ml-4 flex items-start gap-3">
                          <ArrowRight className="h-4 w-4 text-orange-400 mt-1 flex-shrink-0" />
                          <div className="flex-1 p-3 rounded-lg border border-dashed border-orange-500/30 bg-orange-500/5">
                            <div className="flex items-center gap-2 flex-wrap mb-1">
                              <span className="text-sm font-medium text-foreground">{criticalEdge.technique}</span>
                              {criticalEdge.techniqueId && (
                                <code className="text-[10px] px-1.5 py-0.5 rounded bg-background/50 text-muted-foreground">
                                  {criticalEdge.techniqueId}
                                </code>
                              )}
                              <Badge className={getComplexityColor(criticalEdge.complexity)}>
                                {criticalEdge.complexity.toUpperCase()}
                              </Badge>
                              <span className={`text-xs font-medium ${getSuccessProbColor(criticalEdge.successProbability)}`}>
                                {criticalEdge.successProbability}% success
                              </span>
                            </div>
                            <p className="text-xs text-muted-foreground">{criticalEdge.description}</p>
                            <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                              <span className="flex items-center gap-1">
                                <Clock className="h-3 w-3" />
                                {criticalEdge.timeEstimate} min
                              </span>
                              {criticalEdge.prerequisites && criticalEdge.prerequisites.length > 0 && (
                                <span>Prerequisites: {criticalEdge.prerequisites.length}</span>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </Collapsible>
              </div>
            );
          })}
        </div>
      </div>

      {attackGraph.chainedExploits && attackGraph.chainedExploits.length > 0 && (
        <div className="bg-red-500/5 border border-red-500/30 rounded-lg p-4">
          <h4 className="font-semibold text-red-400 mb-3 flex items-center gap-2">
            <Zap className="h-4 w-4" />
            Chained Exploit Combinations
          </h4>
          <div className="space-y-3">
            {attackGraph.chainedExploits.map((chain, index) => (
              <div 
                key={index} 
                className="p-3 bg-background/30 rounded-lg"
                data-testid={`chained-exploit-${index}`}
              >
                <div className="font-medium text-foreground mb-1">{chain.name}</div>
                <div className="flex flex-wrap gap-1 mb-2">
                  {chain.techniques.map((tech, i) => (
                    <code key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">
                      {tech}
                    </code>
                  ))}
                </div>
                <p className="text-xs text-muted-foreground">{chain.combinedImpact}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
