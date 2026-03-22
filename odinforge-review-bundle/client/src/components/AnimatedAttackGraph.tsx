import { useState, useEffect, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  Play,
  Pause,
  RotateCcw,
  Target,
  Shield,
  AlertTriangle,
  XCircle,
  Clock,
} from "lucide-react";
import type { AttackGraph, AttackNode, AttackEdge } from "@shared/schema";

interface AnimatedAttackGraphProps {
  attackGraph: AttackGraph;
  isExploitable: boolean;
  showControls?: boolean;
}

interface NodePosition {
  x: number;
  y: number;
}

export function AnimatedAttackGraph({ 
  attackGraph, 
  isExploitable,
  showControls = true 
}: AnimatedAttackGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [isAnimating, setIsAnimating] = useState(true);
  const [animationStep, setAnimationStep] = useState(0);
  const [nodePositions, setNodePositions] = useState<Record<string, NodePosition>>({});

  const criticalPath = attackGraph.criticalPath || [];
  const nodes = attackGraph.nodes || [];
  const edges = attackGraph.edges || [];

  useEffect(() => {
    const positions: Record<string, NodePosition> = {};
    const levelGroups: Record<number, AttackNode[]> = {};
    
    nodes.forEach(node => {
      const pathIndex = criticalPath.indexOf(node.id);
      const level = pathIndex >= 0 ? pathIndex : criticalPath.length;
      if (!levelGroups[level]) levelGroups[level] = [];
      levelGroups[level].push(node);
    });

    const maxLevel = Math.max(...Object.keys(levelGroups).map(Number));
    const width = 600;
    const height = 400;
    const levelWidth = width / (maxLevel + 2);

    Object.entries(levelGroups).forEach(([levelStr, nodesAtLevel]) => {
      const level = parseInt(levelStr);
      const x = (level + 1) * levelWidth;
      const levelHeight = height / (nodesAtLevel.length + 1);
      
      nodesAtLevel.forEach((node, i) => {
        positions[node.id] = {
          x,
          y: (i + 1) * levelHeight,
        };
      });
    });

    setNodePositions(positions);
  }, [nodes, criticalPath]);

  useEffect(() => {
    if (!isAnimating) return;
    
    const interval = setInterval(() => {
      setAnimationStep(prev => {
        if (prev >= criticalPath.length) {
          return 0;
        }
        return prev + 1;
      });
    }, 1500);

    return () => clearInterval(interval);
  }, [isAnimating, criticalPath.length]);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.target === containerRef.current || (e.target as HTMLElement).closest('.graph-canvas')) {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  }, [pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!isDragging) return;
    setPan({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  }, [isDragging, dragStart]);

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
  }, []);

  const getNodeColor = (node: AttackNode, isActive: boolean, isOnPath: boolean) => {
    if (node.nodeType === "entry") return "bg-cyan-500";
    if (node.nodeType === "objective") return isExploitable ? "bg-red-500" : "bg-emerald-500";
    if (node.nodeType === "dead-end") return "bg-gray-500";
    if (isActive) return "bg-amber-500";
    if (isOnPath) return "bg-orange-400";
    return "bg-blue-500";
  };

  const getNodeIcon = (nodeType: string) => {
    switch (nodeType) {
      case "entry": return <Target className="h-4 w-4 text-white" />;
      case "objective": return <AlertTriangle className="h-4 w-4 text-white" />;
      case "dead-end": return <XCircle className="h-4 w-4 text-white" />;
      default: return <Shield className="h-4 w-4 text-white" />;
    }
  };

  const getEdgeProgress = (edge: AttackEdge) => {
    const sourceIndex = criticalPath.indexOf(edge.source);
    const targetIndex = criticalPath.indexOf(edge.target);
    
    if (sourceIndex === -1 || targetIndex === -1) return 0;
    if (animationStep > targetIndex) return 100;
    if (animationStep === targetIndex) return 50;
    return 0;
  };

  const resetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setAnimationStep(0);
  };

  const selectedNodeData = selectedNode ? nodes.find(n => n.id === selectedNode) : null;

  return (
    <div className="space-y-4" data-testid="animated-attack-graph">
      {showControls && (
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="icon"
              onClick={() => setZoom(z => Math.min(z + 0.2, 2))}
              data-testid="btn-zoom-in"
            >
              <ZoomIn className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="icon"
              onClick={() => setZoom(z => Math.max(z - 0.2, 0.5))}
              data-testid="btn-zoom-out"
            >
              <ZoomOut className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="icon"
              onClick={resetView}
              data-testid="btn-reset-view"
            >
              <RotateCcw className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              size="icon"
              onClick={() => setIsAnimating(!isAnimating)}
              data-testid="btn-toggle-animation-graph"
            >
              {isAnimating ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
            </Button>
          </div>
          <div className="flex items-center gap-4 text-sm text-muted-foreground">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-cyan-500" />
              <span>Entry</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-blue-500" />
              <span>Pivot</span>
            </div>
            <div className="flex items-center gap-2">
              <div className={`w-3 h-3 rounded-full ${isExploitable ? "bg-red-500" : "bg-emerald-500"}`} />
              <span>Objective</span>
            </div>
          </div>
        </div>
      )}

      <div
        ref={containerRef}
        className="relative bg-muted/30 rounded-lg border border-border overflow-hidden cursor-grab active:cursor-grabbing"
        style={{ height: 400 }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        data-testid="graph-canvas"
      >
        <div
          className="graph-canvas absolute inset-0"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: "center center",
            transition: isDragging ? "none" : "transform 0.2s ease",
          }}
        >
          <svg className="absolute inset-0 w-full h-full pointer-events-none">
            <defs>
              <marker
                id="arrowhead"
                markerWidth="10"
                markerHeight="7"
                refX="9"
                refY="3.5"
                orient="auto"
              >
                <polygon points="0 0, 10 3.5, 0 7" fill="currentColor" className="text-muted-foreground" />
              </marker>
              <marker
                id="arrowhead-active"
                markerWidth="10"
                markerHeight="7"
                refX="9"
                refY="3.5"
                orient="auto"
              >
                <polygon points="0 0, 10 3.5, 0 7" fill="currentColor" className="text-amber-500" />
              </marker>
            </defs>
            {edges.map(edge => {
              const sourcePos = nodePositions[edge.source];
              const targetPos = nodePositions[edge.target];
              if (!sourcePos || !targetPos) return null;

              const isOnPath = criticalPath.includes(edge.source) && criticalPath.includes(edge.target);
              const progress = getEdgeProgress(edge);
              const isActive = progress > 0 && progress < 100;

              return (
                <g key={edge.id}>
                  <motion.line
                    x1={sourcePos.x}
                    y1={sourcePos.y}
                    x2={targetPos.x}
                    y2={targetPos.y}
                    stroke={isActive ? "rgb(245 158 11)" : isOnPath ? "rgb(251 146 60)" : "rgb(100 116 139)"}
                    strokeWidth={isOnPath ? 3 : 2}
                    strokeDasharray={edge.edgeType === "alternative" ? "5,5" : edge.edgeType === "fallback" ? "2,4" : undefined}
                    markerEnd={isActive ? "url(#arrowhead-active)" : "url(#arrowhead)"}
                    initial={{ pathLength: 0, opacity: 0 }}
                    animate={{ pathLength: 1, opacity: 1 }}
                    transition={{ duration: 0.5, delay: 0.1 }}
                  />
                  {isActive && (
                    <motion.circle
                      r={4}
                      fill="rgb(245 158 11)"
                      initial={{ cx: sourcePos.x, cy: sourcePos.y }}
                      animate={{
                        cx: sourcePos.x + (targetPos.x - sourcePos.x) * 0.5,
                        cy: sourcePos.y + (targetPos.y - sourcePos.y) * 0.5,
                      }}
                      transition={{ duration: 0.75, repeat: Infinity }}
                    />
                  )}
                </g>
              );
            })}
          </svg>

          {nodes.map((node, index) => {
            const pos = nodePositions[node.id];
            if (!pos) return null;

            const pathIndex = criticalPath.indexOf(node.id);
            const isOnPath = pathIndex >= 0;
            const isActive = pathIndex === animationStep;

            return (
              <motion.div
                key={node.id}
                className="absolute"
                style={{
                  left: pos.x - 24,
                  top: pos.y - 24,
                }}
                initial={{ scale: 0, opacity: 0 }}
                animate={{
                  scale: isActive ? 1.2 : 1,
                  opacity: 1,
                }}
                transition={{ delay: index * 0.1, duration: 0.3 }}
              >
                <button
                  className={`w-12 h-12 rounded-full flex items-center justify-center ${getNodeColor(node, isActive, isOnPath)} shadow-lg transition-all hover:ring-2 hover:ring-white/30`}
                  onClick={() => setSelectedNode(selectedNode === node.id ? null : node.id)}
                  data-testid={`node-${node.id}`}
                >
                  {getNodeIcon(node.nodeType)}
                </button>
                <div className="absolute top-full left-1/2 -translate-x-1/2 mt-1 text-xs text-center whitespace-nowrap text-foreground font-medium max-w-[80px] truncate">
                  {node.label}
                </div>
                {isActive && (
                  <motion.div
                    className="absolute inset-0 rounded-full border-2 border-amber-500"
                    initial={{ scale: 1, opacity: 1 }}
                    animate={{ scale: 1.5, opacity: 0 }}
                    transition={{ duration: 1, repeat: Infinity }}
                  />
                )}
              </motion.div>
            );
          })}
        </div>

        <div className="absolute bottom-4 left-4 right-4">
          <div className="flex items-center gap-2 bg-background/80 backdrop-blur-sm rounded-lg p-2 border border-border">
            <Clock className="h-4 w-4 text-muted-foreground" />
            <span className="text-xs text-muted-foreground">Time to Compromise:</span>
            <span className="text-sm font-medium text-foreground">
              {attackGraph.timeToCompromise.expected} {attackGraph.timeToCompromise.unit}
            </span>
            <span className="text-xs text-muted-foreground ml-2">
              (range: {attackGraph.timeToCompromise.minimum}-{attackGraph.timeToCompromise.maximum})
            </span>
          </div>
        </div>
      </div>

      <AnimatePresence>
        {selectedNodeData && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 10 }}
          >
            <Card className="p-4" data-testid="node-details-panel">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h4 className="font-semibold text-foreground">{selectedNodeData.label}</h4>
                  <p className="text-sm text-muted-foreground mt-1">{selectedNodeData.description}</p>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => setSelectedNode(null)}
                >
                  <XCircle className="h-4 w-4" />
                </Button>
              </div>
              <div className="flex flex-wrap gap-2 mt-3">
                <Badge className="bg-purple-500/10 text-purple-400 border-purple-500/30">
                  {selectedNodeData.tactic}
                </Badge>
                <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/30">
                  {selectedNodeData.compromiseLevel} access
                </Badge>
                <Badge className={
                  selectedNodeData.nodeType === "entry" ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/30" :
                  selectedNodeData.nodeType === "objective" ? "bg-red-500/10 text-red-400 border-red-500/30" :
                  "bg-gray-500/10 text-gray-400 border-gray-500/30"
                }>
                  {selectedNodeData.nodeType}
                </Badge>
              </div>
              {selectedNodeData.assets && selectedNodeData.assets.length > 0 && (
                <div className="mt-3 pt-3 border-t border-border">
                  <span className="text-xs text-muted-foreground">Affected Assets:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selectedNodeData.assets.map((asset, i) => (
                      <Badge key={i} className="bg-muted text-muted-foreground text-xs">
                        {asset}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </Card>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
