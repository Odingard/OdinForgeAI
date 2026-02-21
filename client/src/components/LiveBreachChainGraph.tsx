import { useEffect, useRef, useState, useCallback } from "react";
import type { AttackGraph, AttackNode, AttackEdge } from "@shared/schema";

// ============================================================================
// TYPES
// ============================================================================

interface LiveBreachChainGraphProps {
  graph: AttackGraph | null;
  riskScore?: number;
  assetsCompromised?: number;
  credentialsHarvested?: number;
  currentPhase?: string;
  isRunning?: boolean;
}

interface LayoutNode {
  id: string;
  label: string;
  tactic: string;
  nodeType: string;
  x: number;
  y: number;
  targetX: number;
  targetY: number;
  opacity: number;
  description: string;
  compromiseLevel: string;
  assets: string[];
}

interface LayoutEdge {
  from: string;
  to: string;
  technique: string;
  techniqueId?: string;
  probability: number;
  edgeType: string;
  description: string;
}

// ============================================================================
// VISUAL CONSTANTS (from DemoBreachChain aesthetic)
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

const NODE_COLORS: Record<string, { bg: string; border: string; glow: string }> = {
  entry: { bg: "#0f172a", border: "#64748b", glow: "rgba(100,116,139,0.3)" },
  pivot: { bg: "#0a0a1a", border: "#3b82f6", glow: "rgba(59,130,246,0.4)" },
  objective: { bg: "#1a0505", border: "#dc2626", glow: "rgba(220,38,38,0.5)" },
  "dead-end": { bg: "#1a1a1a", border: "#4b5563", glow: "rgba(75,85,99,0.3)" },
};

const NODE_ICONS: Record<string, string> = {
  entry: "\u25C9",     // target
  pivot: "\u21C4",     // arrows
  objective: "\u2622", // biohazard
  "dead-end": "\u2717",// X
};

const TACTIC_ORDER = [
  "reconnaissance", "resource-development", "initial-access", "execution",
  "persistence", "privilege-escalation", "defense-evasion", "credential-access",
  "discovery", "lateral-movement", "collection", "command-and-control",
  "exfiltration", "impact",
];

const KILL_CHAIN_DISPLAY = [
  "Reconnaissance", "Initial Access", "Execution", "Credential Access",
  "Lateral Movement", "Privilege Escalation", "Collection", "Impact",
];

const KILL_CHAIN_DISPLAY_IDS = [
  "reconnaissance", "initial-access", "execution", "credential-access",
  "lateral-movement", "privilege-escalation", "collection", "impact",
];

// ============================================================================
// LAYOUT
// ============================================================================

function layoutGraph(
  nodes: AttackNode[],
  edges: AttackEdge[],
  criticalPath: string[],
  width: number,
  height: number
): { layoutNodes: LayoutNode[]; layoutEdges: LayoutEdge[] } {
  // Group nodes by tactic column
  const tacticGroups: Record<string, AttackNode[]> = {};
  for (const node of nodes) {
    const tactic = node.tactic || "execution";
    if (!tacticGroups[tactic]) tacticGroups[tactic] = [];
    tacticGroups[tactic].push(node);
  }

  // Sort tactics by kill chain order
  const activeTactics = TACTIC_ORDER.filter(t => tacticGroups[t]);
  const colCount = Math.max(activeTactics.length, 1);
  const colWidth = (width - 120) / (colCount + 1);

  const layoutNodes: LayoutNode[] = [];
  const positions = new Map<string, { x: number; y: number }>();

  // Place critical path nodes on the main spine first
  const criticalSet = new Set(criticalPath);
  const placedNodes = new Set<string>();

  // Place by tactic column
  activeTactics.forEach((tactic, colIdx) => {
    const nodesInCol = tacticGroups[tactic];
    // Sort: critical path nodes first
    nodesInCol.sort((a, b) => {
      const aOnPath = criticalSet.has(a.id) ? 0 : 1;
      const bOnPath = criticalSet.has(b.id) ? 0 : 1;
      return aOnPath - bOnPath;
    });

    const x = 80 + (colIdx + 1) * colWidth;
    const rowHeight = (height - 160) / (nodesInCol.length + 1);

    nodesInCol.forEach((node, rowIdx) => {
      const y = 100 + (rowIdx + 1) * rowHeight;
      positions.set(node.id, { x, y });
      placedNodes.add(node.id);

      layoutNodes.push({
        id: node.id,
        label: node.label,
        tactic: node.tactic || "execution",
        nodeType: node.nodeType,
        x, y,
        targetX: x,
        targetY: y,
        opacity: 1,
        description: node.description,
        compromiseLevel: node.compromiseLevel || "none",
        assets: node.assets || [],
      });
    });
  });

  // Place any unplaced nodes (shouldn't happen, but safety)
  for (const node of nodes) {
    if (!placedNodes.has(node.id)) {
      const x = width / 2;
      const y = height / 2;
      positions.set(node.id, { x, y });
      layoutNodes.push({
        id: node.id,
        label: node.label,
        tactic: node.tactic || "execution",
        nodeType: node.nodeType,
        x, y, targetX: x, targetY: y, opacity: 1,
        description: node.description,
        compromiseLevel: node.compromiseLevel || "none",
        assets: node.assets || [],
      });
    }
  }

  // Map edges
  const layoutEdges: LayoutEdge[] = edges.map(edge => ({
    from: edge.source,
    to: edge.target,
    technique: edge.techniqueId || edge.technique,
    techniqueId: edge.techniqueId,
    probability: edge.successProbability ?? 75,
    edgeType: edge.edgeType || "primary",
    description: edge.description,
  }));

  return { layoutNodes, layoutEdges };
}

// ============================================================================
// COMPONENT
// ============================================================================

export function LiveBreachChainGraph({
  graph,
  riskScore,
  assetsCompromised,
  credentialsHarvested,
  currentPhase,
  isRunning,
}: LiveBreachChainGraphProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const animRef = useRef<number>(0);
  const timeRef = useRef(0);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [dims, setDims] = useState({ w: 1200, h: 700 });
  const layoutRef = useRef<{ layoutNodes: LayoutNode[]; layoutEdges: LayoutEdge[] }>({
    layoutNodes: [],
    layoutEdges: [],
  });
  const prevNodeIdsRef = useRef<Set<string>>(new Set());
  const nodeOpacitiesRef = useRef<Map<string, number>>(new Map());

  // Responsive sizing
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      const w = Math.max(width, 600);
      const h = Math.max(height, 500);
      setDims({ w, h });
    });
    ro.observe(container);
    return () => ro.disconnect();
  }, []);

  // Re-layout when graph changes
  useEffect(() => {
    if (!graph || !graph.nodes?.length) {
      layoutRef.current = { layoutNodes: [], layoutEdges: [] };
      return;
    }

    const { layoutNodes, layoutEdges } = layoutGraph(
      graph.nodes,
      graph.edges || [],
      graph.criticalPath || [],
      dims.w,
      dims.h - 90 // account for header/killchain bar
    );

    // Track new nodes for fade-in animation
    const newIds = new Set(layoutNodes.map(n => n.id));
    for (const node of layoutNodes) {
      if (!prevNodeIdsRef.current.has(node.id)) {
        nodeOpacitiesRef.current.set(node.id, 0); // start transparent
      }
    }
    prevNodeIdsRef.current = newIds;

    layoutRef.current = { layoutNodes, layoutEdges };
  }, [graph, dims.w, dims.h]);

  // Mouse hit detection
  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top - 90; // offset for header

    const nodes = layoutRef.current.layoutNodes;
    let found: string | null = null;
    for (const node of nodes) {
      const dx = mx - node.x;
      const dy = my - node.y;
      if (dx * dx + dy * dy < 900) {
        found = node.id;
        break;
      }
    }
    setHoveredNode(found);
  }, []);

  // Canvas animation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = dims.w * dpr;
    canvas.height = dims.h * dpr;
    ctx.scale(dpr, dpr);

    function draw() {
      timeRef.current += 0.012;
      const t = timeRef.current;
      ctx!.clearRect(0, 0, dims.w, dims.h);

      const { layoutNodes: nodes, layoutEdges: edges } = layoutRef.current;
      if (nodes.length === 0) {
        // Empty state
        ctx!.save();
        ctx!.font = "14px 'IBM Plex Mono', monospace";
        ctx!.fillStyle = "rgba(148, 163, 184, 0.5)";
        ctx!.textAlign = "center";
        ctx!.fillText(
          isRunning ? "Waiting for first phase to complete..." : "No attack graph data",
          dims.w / 2,
          dims.h / 2
        );
        ctx!.restore();
        animRef.current = requestAnimationFrame(draw);
        return;
      }

      const nodeMap = new Map(nodes.map(n => [n.id, n]));

      // Fade in new nodes
      for (const node of nodes) {
        const currentOpacity = nodeOpacitiesRef.current.get(node.id) ?? 1;
        if (currentOpacity < 1) {
          nodeOpacitiesRef.current.set(node.id, Math.min(1, currentOpacity + 0.02));
        }
      }

      // Offset for header/killchain bar
      ctx!.save();
      ctx!.translate(0, 90);

      // Draw edges
      edges.forEach((edge, i) => {
        const from = nodeMap.get(edge.from);
        const to = nodeMap.get(edge.to);
        if (!from || !to) return;

        const fromOpacity = nodeOpacitiesRef.current.get(edge.from) ?? 1;
        const toOpacity = nodeOpacitiesRef.current.get(edge.to) ?? 1;
        const edgeOpacity = Math.min(fromOpacity, toOpacity);

        const dashOffset = -t * 40 + i * 20;

        // Curved midpoint
        const mx = (from.x + to.x) / 2 + (i % 2 === 0 ? 30 : -30);
        const my = (from.y + to.y) / 2 + (i % 3 === 0 ? -20 : 20);

        // Edge glow
        ctx!.save();
        ctx!.globalAlpha = edgeOpacity;
        ctx!.strokeStyle = `rgba(56, 189, 248, ${0.08 + Math.sin(t + i) * 0.03})`;
        ctx!.lineWidth = 6;
        ctx!.beginPath();
        ctx!.moveTo(from.x, from.y);
        ctx!.quadraticCurveTo(mx, my, to.x, to.y);
        ctx!.stroke();
        ctx!.restore();

        // Edge line
        ctx!.save();
        ctx!.globalAlpha = edgeOpacity;
        ctx!.strokeStyle = `rgba(56, 189, 248, ${0.25 + (edge.probability / 100) * 0.2})`;
        ctx!.lineWidth = edge.edgeType === "primary" ? 1.5 : 1;
        if (edge.edgeType === "alternative") {
          ctx!.setLineDash([5, 5]);
        } else if (edge.edgeType === "fallback") {
          ctx!.setLineDash([2, 4]);
        } else {
          ctx!.setLineDash([6, 8]);
        }
        ctx!.lineDashOffset = dashOffset;
        ctx!.beginPath();
        ctx!.moveTo(from.x, from.y);
        ctx!.quadraticCurveTo(mx, my, to.x, to.y);
        ctx!.stroke();
        ctx!.restore();

        // Animated particle
        const particleT = ((t * 0.3 + i * 0.15) % 1);
        const pt = 1 - particleT;
        const px = pt * pt * from.x + 2 * pt * particleT * mx + particleT * particleT * to.x;
        const py = pt * pt * from.y + 2 * pt * particleT * my + particleT * particleT * to.y;

        ctx!.save();
        ctx!.globalAlpha = edgeOpacity;
        ctx!.beginPath();
        ctx!.arc(px, py, 3, 0, Math.PI * 2);
        ctx!.fillStyle = `rgba(56, 189, 248, ${0.7 + Math.sin(t * 3) * 0.3})`;
        ctx!.fill();
        ctx!.beginPath();
        ctx!.arc(px, py, 8, 0, Math.PI * 2);
        ctx!.fillStyle = "rgba(56, 189, 248, 0.15)";
        ctx!.fill();
        ctx!.restore();

        // Arrow head
        const arrowT = 0.85;
        const apt = 1 - arrowT;
        const ax = apt * apt * from.x + 2 * apt * arrowT * mx + arrowT * arrowT * to.x;
        const ay = apt * apt * from.y + 2 * apt * arrowT * my + arrowT * arrowT * to.y;
        const adx = to.x - mx;
        const ady = to.y - my;
        const angle = Math.atan2(ady, adx);

        ctx!.save();
        ctx!.globalAlpha = edgeOpacity;
        ctx!.translate(ax, ay);
        ctx!.rotate(angle);
        ctx!.fillStyle = "rgba(56, 189, 248, 0.5)";
        ctx!.beginPath();
        ctx!.moveTo(6, 0);
        ctx!.lineTo(-4, -4);
        ctx!.lineTo(-4, 4);
        ctx!.closePath();
        ctx!.fill();
        ctx!.restore();

        // Technique label
        ctx!.save();
        ctx!.globalAlpha = edgeOpacity * 0.6;
        ctx!.font = "10px 'IBM Plex Mono', monospace";
        ctx!.fillStyle = "rgba(148, 163, 184, 0.5)";
        ctx!.textAlign = "center";
        ctx!.fillText(edge.technique, mx, my - 8);
        ctx!.restore();
      });

      // Draw nodes
      nodes.forEach((node, idx) => {
        const colors = NODE_COLORS[node.nodeType] || NODE_COLORS.pivot;
        const isHovered = hoveredNode === node.id;
        const nodeOpacity = nodeOpacitiesRef.current.get(node.id) ?? 1;
        const pulse = 1 + Math.sin(t * 2 + idx) * 0.04;
        const r = (isHovered ? 32 : 26) * pulse;

        ctx!.save();
        ctx!.globalAlpha = nodeOpacity;

        // Outer glow
        const gradient = ctx!.createRadialGradient(node.x, node.y, r * 0.5, node.x, node.y, r * 2.5);
        gradient.addColorStop(0, colors.glow);
        gradient.addColorStop(1, "transparent");
        ctx!.fillStyle = gradient;
        ctx!.beginPath();
        ctx!.arc(node.x, node.y, r * 2.5, 0, Math.PI * 2);
        ctx!.fill();

        // Node circle
        ctx!.beginPath();
        ctx!.arc(node.x, node.y, r, 0, Math.PI * 2);
        ctx!.fillStyle = colors.bg;
        ctx!.fill();
        ctx!.strokeStyle = colors.border;
        ctx!.lineWidth = isHovered ? 2.5 : 1.5;
        ctx!.stroke();

        // Node icon
        ctx!.fillStyle = colors.border;
        ctx!.font = `${isHovered ? 14 : 12}px sans-serif`;
        ctx!.textAlign = "center";
        ctx!.textBaseline = "middle";
        ctx!.fillText(NODE_ICONS[node.nodeType] || "\u25CF", node.x, node.y);

        // Node label
        ctx!.font = "bold 11px 'Sora', sans-serif";
        ctx!.fillStyle = isHovered ? "#f1f5f9" : "#cbd5e1";
        ctx!.textAlign = "center";
        ctx!.textBaseline = "top";
        const maxLabelWidth = 100;
        const label = node.label.length > 18 ? node.label.slice(0, 16) + "..." : node.label;
        ctx!.fillText(label, node.x, node.y + r + 8, maxLabelWidth);

        // Tactic label
        ctx!.font = "9px 'IBM Plex Mono', monospace";
        const tacticColor = TACTICS_COLORS[node.tactic] || "#64748b";
        ctx!.fillStyle = tacticColor;
        ctx!.fillText(
          node.tactic.replace(/-/g, " ").toUpperCase(),
          node.x,
          node.y + r + 22,
          maxLabelWidth
        );

        // Hover detail
        if (isHovered) {
          ctx!.font = "10px 'IBM Plex Mono', monospace";
          ctx!.fillStyle = "rgba(56, 189, 248, 0.7)";
          ctx!.textBaseline = "bottom";
          ctx!.fillText(
            node.assets.length > 0 ? node.assets[0] : "",
            node.x,
            node.y - r - 16,
            200
          );
          ctx!.fillStyle = "rgba(148, 163, 184, 0.6)";
          const detail = node.description.length > 60 ? node.description.slice(0, 58) + "..." : node.description;
          ctx!.fillText(detail, node.x, node.y - r - 4, 250);
        }

        ctx!.restore();
      });

      ctx!.restore(); // pop the translate(0, 90)

      animRef.current = requestAnimationFrame(draw);
    }

    draw();
    return () => cancelAnimationFrame(animRef.current);
  }, [dims, hoveredNode, isRunning]);

  // Determine kill chain coverage
  const coveredTactics = new Set<string>(graph?.killChainCoverage || []);

  // Time to compromise display
  const ttc = graph?.timeToCompromise;
  const ttcDisplay = ttc ? `${ttc.expected} ${ttc.unit}` : "--";

  return (
    <div
      style={{
        background: "#06090f",
        fontFamily: "'Sora', 'DM Sans', sans-serif",
        color: "#f1f5f9",
        borderRadius: 8,
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: "16px 24px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          borderBottom: "1px solid rgba(56,189,248,0.08)",
          background: "rgba(6,9,15,0.9)",
          backdropFilter: "blur(12px)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontWeight: 800, fontSize: 16, letterSpacing: -0.5 }}>
            ODIN<span style={{ color: "#38bdf8" }}>FORGE</span>
          </span>
          <span
            style={{
              fontSize: 10,
              fontFamily: "'IBM Plex Mono', monospace",
              color: isRunning ? "#22c55e" : "#38bdf8",
              background: isRunning ? "rgba(34,197,94,0.1)" : "rgba(56,189,248,0.1)",
              padding: "3px 10px",
              borderRadius: 100,
              border: `1px solid ${isRunning ? "rgba(34,197,94,0.2)" : "rgba(56,189,248,0.15)"}`,
            }}
          >
            {isRunning ? "LIVE BREACH CHAIN" : "BREACH CHAIN"}
          </span>
          {currentPhase && (
            <span
              style={{
                fontSize: 10,
                fontFamily: "'IBM Plex Mono', monospace",
                color: "#f59e0b",
                background: "rgba(245,158,11,0.1)",
                padding: "3px 10px",
                borderRadius: 100,
                border: "1px solid rgba(245,158,11,0.15)",
              }}
            >
              {currentPhase.replace(/_/g, " ").toUpperCase()}
            </span>
          )}
        </div>
        <div style={{ display: "flex", gap: 20, alignItems: "center" }}>
          <MetricBox label="Risk Score" value={riskScore ?? "--"} color={riskScore && riskScore >= 80 ? "#ef4444" : riskScore && riskScore >= 50 ? "#f59e0b" : "#38bdf8"} />
          <Divider />
          <MetricBox label="Time to Compromise" value={ttcDisplay} color="#f59e0b" />
          <Divider />
          <MetricBox label="Assets Compromised" value={assetsCompromised ?? "--"} color="#38bdf8" />
          <Divider />
          <MetricBox label="Credentials Harvested" value={credentialsHarvested ?? "--"} color="#a855f7" />
        </div>
      </div>

      {/* Kill Chain Bar */}
      <div
        style={{
          display: "flex",
          gap: 2,
          padding: "0 24px",
          background: "rgba(6,9,15,0.6)",
          borderBottom: "1px solid rgba(56,189,248,0.06)",
        }}
      >
        {KILL_CHAIN_DISPLAY.map((tactic, i) => {
          const tacticId = KILL_CHAIN_DISPLAY_IDS[i];
          const active = coveredTactics.has(tacticId);
          return (
            <div
              key={tactic}
              style={{
                flex: 1,
                padding: "8px 0",
                textAlign: "center",
                fontSize: 9,
                fontFamily: "'IBM Plex Mono', monospace",
                fontWeight: 600,
                letterSpacing: 0.5,
                color: active ? (TACTICS_COLORS[tacticId] || "#64748b") : "#334155",
                borderBottom: `2px solid ${active ? (TACTICS_COLORS[tacticId] || "#1e293b") : "#1e293b"}`,
                textTransform: "uppercase",
                transition: "color 0.3s, border-color 0.3s",
              }}
            >
              {tactic}
            </div>
          );
        })}
      </div>

      {/* Canvas */}
      <div
        ref={containerRef}
        style={{ width: "100%", height: 600, position: "relative" }}
      >
        <canvas
          ref={canvasRef}
          style={{ width: "100%", height: "100%", cursor: hoveredNode ? "pointer" : "default" }}
          onMouseMove={handleMouseMove}
          onMouseLeave={() => setHoveredNode(null)}
        />

        {/* Legend */}
        <div
          style={{
            position: "absolute",
            bottom: 16,
            left: 24,
            display: "flex",
            gap: 16,
            fontSize: 10,
            fontFamily: "'IBM Plex Mono', monospace",
            color: "#64748b",
          }}
        >
          {[
            { color: "#64748b", label: "Entry Point" },
            { color: "#3b82f6", label: "Pivot" },
            { color: "#dc2626", label: "Objective" },
            { color: "#4b5563", label: "Dead End" },
          ].map((item) => (
            <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <div style={{ width: 7, height: 7, borderRadius: "50%", background: item.color }} />
              {item.label}
            </div>
          ))}
        </div>

        {/* Watermark */}
        <div
          style={{
            position: "absolute",
            bottom: 16,
            right: 24,
            fontSize: 10,
            fontFamily: "'IBM Plex Mono', monospace",
            color: "rgba(56,189,248,0.3)",
          }}
        >
          odinforgeai.com — Live Breach Chain
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// SUB-COMPONENTS
// ============================================================================

function MetricBox({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div style={{ textAlign: "right" }}>
      <div
        style={{
          fontSize: 9,
          color: "#64748b",
          fontFamily: "'IBM Plex Mono', monospace",
          textTransform: "uppercase",
          letterSpacing: 1,
        }}
      >
        {label}
      </div>
      <div style={{ fontSize: 22, fontWeight: 800, color, letterSpacing: -1 }}>
        {value}
      </div>
    </div>
  );
}

function Divider() {
  return <div style={{ width: 1, height: 32, background: "rgba(56,189,248,0.1)" }} />;
}
