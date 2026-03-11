import { useState } from "react";
import type { AttackGraph } from "@shared/schema";

// ============================================================================
// TACTIC COLORS (matches LiveBreachChainGraph)
// ============================================================================

const TACTICS_COLORS: Record<string, string> = {
  "reconnaissance": "#64748b",
  "resource-development": "#64748b",
  "initial-access": "#ef4444",
  "execution": "#f97316",
  "persistence": "#a855f7",
  "privilege-escalation": "#ec4899",
  "defense-evasion": "#6366f1",
  "credential-access": "#f59e0b",
  "discovery": "#06b6d4",
  "lateral-movement": "#3b82f6",
  "collection": "#8b5cf6",
  "command-and-control": "#6366f1",
  "exfiltration": "#f43f5e",
  "impact": "#dc2626",
};

// ============================================================================
// HELPERS
// ============================================================================

function formatMs(ms: number): string {
  if (ms < 60000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3600000) return `${Math.round(ms / 60000)}m`;
  return `${(ms / 3600000).toFixed(1)}h`;
}

// ============================================================================
// PROPS
// ============================================================================

interface BreachTimelineProps {
  graph: AttackGraph;
  activeNodeId?: string;
  onNodeClick?: (nodeId: string) => void;
}

// ============================================================================
// COMPONENT
// ============================================================================

export function BreachTimeline({ graph, activeNodeId, onNodeClick }: BreachTimelineProps) {
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const criticalPath = graph.criticalPath || [];
  const nodeMap = new Map(graph.nodes.map(n => [n.id, n]));
  const edgeMap = new Map(
    graph.edges.map(e => [`${e.source}->${e.target}`, e])
  );

  // Build ordered list of { node, timeEstimate } along critical path
  interface PathStep {
    id: string;
    label: string;
    tactic: string;
    timeEstimateMs: number;
  }

  const steps: PathStep[] = [];
  let totalMs = 0;

  for (let i = 0; i < criticalPath.length; i++) {
    const id = criticalPath[i];
    const node = nodeMap.get(id);
    if (!node) continue;

    // Time estimate from the edge connecting this node to the next
    let timeMs = 0;
    if (i < criticalPath.length - 1) {
      const nextId = criticalPath[i + 1];
      const edge = edgeMap.get(`${id}->${nextId}`);
      if (edge?.timeEstimate) {
        // timeEstimate in schema is a plain number — treat as ms
        timeMs = edge.timeEstimate;
      }
    }

    totalMs += timeMs;
    steps.push({
      id,
      label: node.label,
      tactic: node.tactic || "execution",
      timeEstimateMs: timeMs,
    });
  }

  // Decide block widths: proportional if we have time data, equal otherwise
  const hasTimeData = steps.some(s => s.timeEstimateMs > 0);
  const totalParts = hasTimeData
    ? Math.max(totalMs, 1)
    : steps.length;

  if (steps.length === 0) {
    return (
      <div style={{
        padding: "12px 16px",
        fontSize: 12,
        color: "var(--falcon-t4)",
        fontFamily: "var(--font-mono)",
      }}>
        No critical path data yet
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {/* Timeline strip */}
      <div
        style={{
          display: "flex",
          alignItems: "stretch",
          gap: 2,
          position: "relative",
        }}
      >
        {steps.map((step, idx) => {
          const flexPart = hasTimeData
            ? Math.max(step.timeEstimateMs, totalParts / steps.length / 4)
            : 1;
          const color = TACTICS_COLORS[step.tactic] || "#64748b";
          const isActive = activeNodeId === step.id;
          const isHovered = hoveredId === step.id;
          const showTooltip = isHovered;

          return (
            <div
              key={step.id}
              style={{
                flex: flexPart,
                minWidth: 40,
                position: "relative",
                cursor: onNodeClick ? "pointer" : "default",
              }}
              onMouseEnter={() => setHoveredId(step.id)}
              onMouseLeave={() => setHoveredId(null)}
              onClick={() => onNodeClick?.(step.id)}
            >
              {/* Block */}
              <div
                style={{
                  height: 36,
                  background: isActive
                    ? color
                    : `${color}33`,
                  border: `1px solid ${isActive || isHovered ? color : `${color}55`}`,
                  borderRadius: 4,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  transition: "all 0.15s ease",
                  boxShadow: isActive ? `0 0 8px ${color}55` : "none",
                  overflow: "hidden",
                }}
              >
                <span
                  style={{
                    fontSize: 9,
                    fontWeight: 600,
                    fontFamily: "var(--font-mono)",
                    color: isActive ? "#fff" : color,
                    textTransform: "uppercase",
                    letterSpacing: 0.3,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    padding: "0 4px",
                  }}
                >
                  {step.label.length > 14 ? step.label.slice(0, 12) + "…" : step.label}
                </span>
              </div>

              {/* Connector line between blocks (except last) */}
              {idx < steps.length - 1 && (
                <div
                  style={{
                    position: "absolute",
                    right: -3,
                    top: "50%",
                    transform: "translateY(-50%)",
                    width: 6,
                    height: 1,
                    background: "var(--falcon-border)",
                    zIndex: 1,
                  }}
                />
              )}

              {/* Tooltip */}
              {showTooltip && (
                <div
                  style={{
                    position: "absolute",
                    bottom: "calc(100% + 8px)",
                    left: "50%",
                    transform: "translateX(-50%)",
                    background: "var(--falcon-panel)",
                    border: `1px solid ${color}55`,
                    borderRadius: 6,
                    padding: "6px 10px",
                    zIndex: 20,
                    whiteSpace: "nowrap",
                    pointerEvents: "none",
                    boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
                  }}
                >
                  <div style={{ fontSize: 11, fontWeight: 600, color: "var(--falcon-t1)" }}>
                    {step.label}
                  </div>
                  {step.timeEstimateMs > 0 && (
                    <div style={{ fontSize: 10, color, fontFamily: "var(--font-mono)" }}>
                      {formatMs(step.timeEstimateMs)}
                    </div>
                  )}
                  {/* Arrow */}
                  <div
                    style={{
                      position: "absolute",
                      bottom: -5,
                      left: "50%",
                      transform: "translateX(-50%)",
                      width: 0,
                      height: 0,
                      borderLeft: "5px solid transparent",
                      borderRight: "5px solid transparent",
                      borderTop: `5px solid ${color}55`,
                    }}
                  />
                </div>
              )}
            </div>
          );
        })}

        {/* Total time badge */}
        {hasTimeData && totalMs > 0 && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              paddingLeft: 10,
              flexShrink: 0,
            }}
          >
            <span
              style={{
                fontSize: 10,
                fontWeight: 700,
                fontFamily: "var(--font-mono)",
                color: "var(--falcon-t3)",
                whiteSpace: "nowrap",
              }}
            >
              Total: {formatMs(totalMs)}
            </span>
          </div>
        )}
      </div>

      {/* Step count */}
      <div style={{ fontSize: 10, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>
        {steps.length} steps in critical path
        {!hasTimeData && " — time estimates not available"}
      </div>
    </div>
  );
}
