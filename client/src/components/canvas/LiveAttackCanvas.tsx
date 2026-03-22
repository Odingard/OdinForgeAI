import { useState, useEffect, useCallback } from "react";
import "../../styles/canvas.css";

// ── Types ────────────────────────────────────────────────────────────────────

interface CanvasNode {
  id: string;
  label: string;
  zone: string;
  role: string;
  x: number;
  y: number;
  isPrimary: boolean;
  hasGlow: boolean;
  exploited: boolean;
  replayed: boolean;
}

interface CanvasEdge {
  id: string;
  from: string;
  to: string;
  confirmed: boolean;
  replayed: boolean;
  isPrimary: boolean;
}

interface LiveAttackCanvasProps {
  canvasEvents: any[];
  reasoningStream: any[];
  operatorSummary: any;
  chainId: string;
}

// ── Zone → fill color mapping ────────────────────────────────────────────────

const ZONE_COLORS: Record<string, string> = {
  public: "#3b82f6",        // blue-500
  authenticated: "#eab308", // yellow-500
  privileged: "#ef4444",    // red-500
  internal_like: "#a855f7", // purple-500
};

const DEFAULT_NODE_COLOR = "#6b7280"; // gray-500

// ── Role → x-position band ──────────────────────────────────────────────────

function xForRole(role: string, width: number): number {
  switch (role) {
    case "entry":  return width * 0.15;
    case "pivot":  return width * 0.5;
    case "target": return width * 0.85;
    default:       return width * 0.5;
  }
}

// ── Component ────────────────────────────────────────────────────────────────

export function LiveAttackCanvas({
  canvasEvents,
  reasoningStream: _reasoningStream,
  operatorSummary: _operatorSummary,
  chainId,
}: LiveAttackCanvasProps) {
  const [nodes, setNodes] = useState<Map<string, CanvasNode>>(new Map());
  const [edges, setEdges] = useState<Map<string, CanvasEdge>>(new Map());
  const [primaryNodeIds, setPrimaryNodeIds] = useState<Set<string>>(new Set());

  // Track which events we have already processed
  const [processedCount, setProcessedCount] = useState(0);

  // Reset state when chainId changes
  useEffect(() => {
    setNodes(new Map());
    setEdges(new Map());
    setPrimaryNodeIds(new Set());
    setProcessedCount(0);
  }, [chainId]);

  // Process new canvas events incrementally
  const processEvent = useCallback(
    (evt: any) => {
      const canvasType: string = evt.canvasType || evt.type || "";
      const sourceId: string = evt.source || "";
      const targetId: string = evt.target || "";

      switch (canvasType) {
        case "node_discovered": {
          if (!sourceId) break;
          setNodes((prev) => {
            const next = new Map(prev);
            if (!next.has(sourceId)) {
              const role = evt.context?.role || guessRole(sourceId, next.size);
              const svgWidth = 800;
              const svgHeight = 500;
              const jitterY = 100 + Math.random() * (svgHeight - 200);
              next.set(sourceId, {
                id: sourceId,
                label: truncateLabel(sourceId),
                zone: evt.zone || "public",
                role,
                x: xForRole(role, svgWidth),
                y: jitterY,
                isPrimary: false,
                hasGlow: false,
                exploited: false,
                replayed: false,
              });
            }
            return next;
          });
          break;
        }

        case "node_classified": {
          if (!sourceId) break;
          setNodes((prev) => {
            const existing = prev.get(sourceId);
            if (!existing) return prev;
            const next = new Map(prev);
            next.set(sourceId, {
              ...existing,
              zone: evt.zone || existing.zone,
              hasGlow: true,
            });
            return next;
          });
          break;
        }

        case "edge_confirmed": {
          const edgeId = `${sourceId}->${targetId || "?"}`;
          setEdges((prev) => {
            const next = new Map(prev);
            next.set(edgeId, {
              id: edgeId,
              from: sourceId,
              to: targetId,
              confirmed: true,
              replayed: false,
              isPrimary: false,
            });
            return next;
          });
          break;
        }

        case "replay_succeeded": {
          if (targetId) {
            setNodes((prev) => {
              const existing = prev.get(targetId);
              if (!existing) return prev;
              const next = new Map(prev);
              next.set(targetId, { ...existing, replayed: true });
              return next;
            });
          }
          // Also mark any edge to this target as replayed
          setEdges((prev) => {
            let changed = false;
            const next = new Map(prev);
            next.forEach((edge, key) => {
              if (edge.to === targetId && !edge.replayed) {
                next.set(key, { ...edge, replayed: true });
                changed = true;
              }
            });
            return changed ? next : prev;
          });
          break;
        }

        case "primary_path_changed": {
          // sourceId contains pathId — mark matching nodes
          // For now treat all nodes on the current path as primary;
          // since the server doesn't send explicit node lists for a path,
          // we mark all confirmed-edge-connected nodes as primary.
          setEdges((prev) => {
            const next = new Map(prev);
            const newPrimary = new Set<string>();
            next.forEach((edge, key) => {
              if (edge.confirmed) {
                next.set(key, { ...edge, isPrimary: true });
                newPrimary.add(edge.from);
                if (edge.to) newPrimary.add(edge.to);
              }
            });
            setPrimaryNodeIds(newPrimary);
            return next;
          });
          setNodes((prev) => {
            const next = new Map(prev);
            let changed = false;
            next.forEach((node, key) => {
              const shouldBePrimary = primaryNodeIds.has(key);
              if (node.isPrimary !== shouldBePrimary) {
                next.set(key, { ...node, isPrimary: shouldBePrimary });
                changed = true;
              }
            });
            return changed ? next : prev;
          });
          break;
        }

        case "artifact_gained": {
          if (!sourceId) break;
          setNodes((prev) => {
            const existing = prev.get(sourceId);
            if (!existing) return prev;
            const next = new Map(prev);
            next.set(sourceId, { ...existing, hasGlow: true, exploited: true });
            return next;
          });
          break;
        }
      }
    },
    [primaryNodeIds],
  );

  useEffect(() => {
    if (canvasEvents.length <= processedCount) return;
    const newEvents = canvasEvents.slice(processedCount);
    for (const evt of newEvents) {
      processEvent(evt);
    }
    setProcessedCount(canvasEvents.length);
  }, [canvasEvents, processedCount, processEvent]);

  // ── Render ──────────────────────────────────────────────────────────────

  const nodeArray = Array.from(nodes.values());
  const edgeArray = Array.from(edges.values());
  const hasPrimary = primaryNodeIds.size > 0;

  return (
    <svg
      viewBox="0 0 800 500"
      className="w-full h-full bg-[hsl(var(--card))] rounded-lg border border-[hsl(var(--border))]"
      preserveAspectRatio="xMidYMid meet"
    >
      {/* Edges */}
      {edgeArray.map((edge) => {
        const fromNode = nodes.get(edge.from);
        const toNode = edge.to ? nodes.get(edge.to) : null;
        if (!fromNode) return null;
        const x1 = fromNode.x;
        const y1 = fromNode.y;
        const x2 = toNode ? toNode.x : fromNode.x + 80;
        const y2 = toNode ? toNode.y : fromNode.y;

        const dimmed = hasPrimary && !edge.isPrimary;

        let strokeColor = "#4b5563"; // gray-600
        let strokeDash = "6 4";       // dashed = inferred
        let className = "canvas-edge";

        if (edge.confirmed) {
          strokeColor = "#9ca3af"; // gray-400
          strokeDash = "none";
        }

        if (edge.replayed) {
          strokeColor = "#22c55e"; // green-500
          className = "canvas-edge canvas-edge-replay";
          strokeDash = "8 4";
        }

        if (edge.isPrimary && !edge.replayed) {
          strokeColor = "#ffffff";
        }

        return (
          <line
            key={edge.id}
            x1={x1}
            y1={y1}
            x2={x2}
            y2={y2}
            stroke={strokeColor}
            strokeWidth={edge.isPrimary ? 2.5 : 1.5}
            strokeDasharray={strokeDash}
            className={`${className}${dimmed ? " canvas-node-dimmed" : ""}`}
          />
        );
      })}

      {/* Nodes */}
      {nodeArray.map((node) => {
        const fill = ZONE_COLORS[node.zone] || DEFAULT_NODE_COLOR;
        const r = node.hasGlow ? 14 : 10;
        const dimmed = hasPrimary && !node.isPrimary && !primaryNodeIds.has(node.id);

        let outlineColor = "transparent";
        let outlineWidth = 0;
        if (node.exploited) {
          outlineColor = "#f97316"; // orange-500
          outlineWidth = 2;
        }
        if (node.replayed) {
          outlineColor = "#22c55e"; // green-500
          outlineWidth = 2;
        }
        if (node.isPrimary || primaryNodeIds.has(node.id)) {
          outlineColor = "#ffffff";
          outlineWidth = 3;
        }

        const nodeClass = [
          "canvas-node",
          (node.isPrimary || primaryNodeIds.has(node.id)) ? "canvas-node-primary" : "",
          dimmed ? "canvas-node-dimmed" : "",
        ]
          .filter(Boolean)
          .join(" ");

        return (
          <g key={node.id} className={nodeClass}>
            <circle
              cx={node.x}
              cy={node.y}
              r={r}
              fill={fill}
              stroke={outlineColor}
              strokeWidth={outlineWidth}
            />
            <text
              x={node.x}
              y={node.y + r + 14}
              textAnchor="middle"
              className="fill-[hsl(var(--foreground))]"
              fontSize={10}
              fontFamily="monospace"
            >
              {node.label}
            </text>
          </g>
        );
      })}

      {/* Empty state */}
      {nodeArray.length === 0 && (
        <text
          x={400}
          y={250}
          textAnchor="middle"
          className="fill-gray-500"
          fontSize={14}
          fontFamily="monospace"
        >
          Waiting for canvas events...
        </text>
      )}
    </svg>
  );
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function truncateLabel(url: string): string {
  try {
    const u = new URL(url);
    const path = u.pathname.length > 20 ? u.pathname.slice(0, 20) + "..." : u.pathname;
    return u.hostname.replace(/^www\./, "") + path;
  } catch {
    return url.length > 28 ? url.slice(0, 28) + "..." : url;
  }
}

function guessRole(_id: string, existingCount: number): string {
  // First node is entry, last-ish is target, middle is pivot
  if (existingCount === 0) return "entry";
  if (existingCount < 3) return "pivot";
  return Math.random() > 0.6 ? "target" : "pivot";
}
