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
  isSpine: boolean;         // true = phase node on main path
  isSatellite: boolean;     // true = finding node shown as small satellite
  collapsedCount: number;   // number of hidden children (for "+N" badge)
  radius: number;           // render size
  remediationStatus?: "open" | "in_progress" | "verified_fixed" | "accepted_risk";
  businessImpact?: {
    summary: string;
    dataExposed?: string;
    systemsReachable?: string[];
    regulatoryRisk?: string;
    estimatedBlastRadius: "contained" | "department" | "organization" | "customer-facing";
    financialImpact?: string;
  };
  // Enriched artifact data (spec v1.0 §4.1)
  artifacts?: AttackNode["artifacts"];
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

// Plain English labels for non-technical stakeholders
const TACTIC_PLAIN_ENGLISH: Record<string, string> = {
  "reconnaissance": "Scouting Your Systems",
  "resource-development": "Building Attack Tools",
  "initial-access": "Breaking In",
  "execution": "Running Malicious Code",
  "persistence": "Maintaining Access",
  "privilege-escalation": "Gaining Higher Privileges",
  "defense-evasion": "Avoiding Detection",
  "credential-access": "Stealing Credentials",
  "discovery": "Mapping Internal Systems",
  "lateral-movement": "Spreading to Other Systems",
  "collection": "Gathering Sensitive Data",
  "command-and-control": "Remote Control",
  "exfiltration": "Stealing Data Out",
  "impact": "Causing Damage",
};

// Business impact descriptions for each tactic
const TACTIC_BUSINESS_IMPACT: Record<string, string> = {
  "reconnaissance": "Attacker identifies your systems, domains, and infrastructure",
  "resource-development": "Attacker prepares custom tools targeting your environment",
  "initial-access": "Attacker finds a way into your network or application",
  "execution": "Attacker is actively running code on your systems",
  "persistence": "Attacker has created backdoors to return even after you respond",
  "privilege-escalation": "Attacker has gained admin-level access to your systems",
  "defense-evasion": "Attacker is hiding their activity from your security tools",
  "credential-access": "Attacker has obtained usernames, passwords, or API keys",
  "discovery": "Attacker is discovering databases, file shares, and internal services",
  "lateral-movement": "Attacker has moved from one system to another inside your network",
  "collection": "Attacker is accessing customer data, financial records, or IP",
  "command-and-control": "Attacker is remotely controlling compromised systems",
  "exfiltration": "Attacker is transferring your data outside your organization",
  "impact": "Attacker can disrupt operations, encrypt data, or cause financial loss",
};

const KILL_CHAIN_DISPLAY = [
  "Scouting", "Break-In", "Execute", "Steal Creds",
  "Spread", "Escalate", "Collect", "Damage",
];

const KILL_CHAIN_DISPLAY_IDS = [
  "reconnaissance", "initial-access", "execution", "credential-access",
  "lateral-movement", "privilege-escalation", "collection", "impact",
];

// Max satellite (finding) nodes shown per phase node
const MAX_SATELLITES_PER_PHASE = 2;

// ============================================================================
// LAYOUT — Spine + Satellite approach
//
// Industry standard: phase nodes flow along a clean arc (the "spine"),
// individual findings collapse into their parent phase with a "+N" badge.
// Only the top 2 critical findings per phase are shown as small satellites.
// ============================================================================

function layoutGraph(
  nodes: AttackNode[],
  edges: AttackEdge[],
  criticalPath: string[],
  width: number,
  height: number
): { layoutNodes: LayoutNode[]; layoutEdges: LayoutEdge[] } {
  const criticalSet = new Set(criticalPath);
  const layoutNodes: LayoutNode[] = [];
  const layoutEdges: LayoutEdge[] = [];

  // Build adjacency: parent → children (edges from spine node to finding nodes)
  const childrenOf = new Map<string, AttackNode[]>();
  const edgeByPair = new Map<string, AttackEdge>();
  for (const edge of edges) {
    edgeByPair.set(`${edge.source}->${edge.target}`, edge);
  }
  for (const edge of edges) {
    const sourceOnSpine = criticalSet.has(edge.source);
    const targetOnSpine = criticalSet.has(edge.target);
    // A satellite is a node connected FROM a spine node but not itself on the spine
    if (sourceOnSpine && !targetOnSpine) {
      const targetNode = nodes.find(n => n.id === edge.target);
      if (targetNode) {
        if (!childrenOf.has(edge.source)) childrenOf.set(edge.source, []);
        childrenOf.get(edge.source)!.push(targetNode);
      }
    }
  }

  // Separate spine nodes from finding nodes
  const spineNodes = nodes.filter(n => criticalSet.has(n.id));
  // Maintain critical path order
  const orderedSpine = criticalPath
    .map(id => spineNodes.find(n => n.id === id))
    .filter((n): n is AttackNode => !!n);

  // If spine is empty, fall back to showing all nodes (shouldn't happen)
  if (orderedSpine.length === 0) {
    // Fallback: show up to 10 nodes in a simple row
    const shown = nodes.slice(0, 10);
    const spacing = (width - 160) / (shown.length + 1);
    shown.forEach((node, i) => {
      const x = 80 + (i + 1) * spacing;
      const y = height / 2;
      layoutNodes.push(makeLayoutNode(node, x, y, true, false, 0, 26));
    });
    for (const edge of edges) {
      if (shown.some(n => n.id === edge.source) && shown.some(n => n.id === edge.target)) {
        layoutEdges.push(makeLayoutEdge(edge));
      }
    }
    return { layoutNodes, layoutEdges };
  }

  // ---- Lay out spine nodes along a flowing arc ----
  const cx = width / 2;
  const cy = height / 2;
  const radiusX = Math.min(width * 0.38, 460);
  const radiusY = Math.min(height * 0.34, 280);
  const spineCount = orderedSpine.length;

  // Arc from top-left to bottom-right (like DemoBreachChain)
  const spinePositions = new Map<string, { x: number; y: number }>();

  orderedSpine.forEach((node, i) => {
    // Distribute along an S-curve from top-left to bottom-right
    const t = spineCount <= 1 ? 0.5 : i / (spineCount - 1);
    // S-curve: smooth left-to-right with vertical wave
    const x = cx + (t - 0.5) * 2 * radiusX;
    const waveY = Math.sin(t * Math.PI) * radiusY * 0.4; // gentle arc upward in the middle
    const y = cy - radiusY * 0.3 + t * radiusY * 0.6 - waveY;

    spinePositions.set(node.id, { x, y });

    // Count total children and determine how many are collapsed
    const children = childrenOf.get(node.id) || [];
    const collapsedCount = Math.max(0, children.length - MAX_SATELLITES_PER_PHASE);

    layoutNodes.push(makeLayoutNode(node, x, y, true, false, collapsedCount, 28));
  });

  // ---- Lay out spine-to-spine edges ----
  for (let i = 0; i < orderedSpine.length - 1; i++) {
    const from = orderedSpine[i];
    const to = orderedSpine[i + 1];
    const edge = edgeByPair.get(`${from.id}->${to.id}`);
    if (edge) {
      layoutEdges.push(makeLayoutEdge(edge));
    } else {
      // Synthesize a spine edge if none exists (phases are always connected sequentially)
      layoutEdges.push({
        from: from.id,
        to: to.id,
        technique: "",
        probability: 80,
        edgeType: "primary",
        description: "",
      });
    }
  }

  // ---- Lay out satellite nodes (top N findings per phase) ----
  for (const spineNode of orderedSpine) {
    const children = childrenOf.get(spineNode.id) || [];
    if (children.length === 0) continue;

    // Sort by severity: critical first, then high
    const sorted = [...children].sort((a, b) => {
      const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      return (sevOrder[a.compromiseLevel === "admin" ? "critical" : "high"] ?? 2)
           - (sevOrder[b.compromiseLevel === "admin" ? "critical" : "high"] ?? 2);
    });

    const shown = sorted.slice(0, MAX_SATELLITES_PER_PHASE);
    const parentPos = spinePositions.get(spineNode.id)!;

    shown.forEach((child, j) => {
      // Position satellites below and slightly to the side of their parent
      const angleOffset = (j - (shown.length - 1) / 2) * 0.6;
      const satX = parentPos.x + Math.sin(angleOffset) * 70;
      const satY = parentPos.y + 75 + j * 50;

      layoutNodes.push(makeLayoutNode(child, satX, satY, false, true, 0, 16));

      // Edge from parent to satellite
      const edge = edgeByPair.get(`${spineNode.id}->${child.id}`);
      if (edge) {
        layoutEdges.push(makeLayoutEdge(edge));
      }
    });
  }

  return { layoutNodes, layoutEdges };
}

function makeLayoutNode(
  node: AttackNode,
  x: number,
  y: number,
  isSpine: boolean,
  isSatellite: boolean,
  collapsedCount: number,
  radius: number,
): LayoutNode {
  return {
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
    isSpine,
    isSatellite,
    collapsedCount,
    radius,
    remediationStatus: node.remediationStatus,
    businessImpact: node.businessImpact,
    artifacts: node.artifacts,
  };
}

function makeLayoutEdge(edge: AttackEdge): LayoutEdge {
  return {
    from: edge.source,
    to: edge.target,
    technique: edge.techniqueId || edge.technique,
    techniqueId: edge.techniqueId,
    probability: edge.successProbability ?? 75,
    edgeType: edge.edgeType || "primary",
    description: edge.description,
  };
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
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number } | null>(null);
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
      if (!entries[0]) return;
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
      const hitR = node.radius + 6; // generous hit area
      if (dx * dx + dy * dy < hitR * hitR) {
        found = node.id;
        break;
      }
      // Also detect hits on the "+N findings" badge
      if (node.collapsedCount > 0) {
        const badgeX = node.x + node.radius * 0.75;
        const badgeY = node.y - node.radius * 0.75;
        const bdx = mx - badgeX;
        const bdy = my - badgeY;
        const badgeHitR = 15; // generous badge hit area
        if (bdx * bdx + bdy * bdy < badgeHitR * badgeHitR) {
          found = node.id;
          break;
        }
      }
    }
    setHoveredNode(found);
    if (found) {
      // Tooltip position: offset from cursor so it doesn't obscure the node
      setTooltipPos({ x: e.clientX - rect.left + 16, y: e.clientY - rect.top + 90 + 12 });
    } else {
      setTooltipPos(null);
    }
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
        const isSpineEdge = from.isSpine && to.isSpine;
        const isSatEdge = from.isSatellite || to.isSatellite;

        const dashOffset = -t * 40 + i * 20;

        // Curved midpoint — subtle for satellite edges, pronounced for spine
        const curveAmount = isSatEdge ? 10 : 30;
        const mx = (from.x + to.x) / 2 + (i % 2 === 0 ? curveAmount : -curveAmount);
        const my = (from.y + to.y) / 2 + (i % 3 === 0 ? -(curveAmount * 0.7) : curveAmount * 0.7);

        // Edge glow (spine edges only)
        if (isSpineEdge) {
          ctx!.save();
          ctx!.globalAlpha = edgeOpacity;
          ctx!.strokeStyle = `rgba(56, 189, 248, ${0.08 + Math.sin(t + i) * 0.03})`;
          ctx!.lineWidth = 6;
          ctx!.beginPath();
          ctx!.moveTo(from.x, from.y);
          ctx!.quadraticCurveTo(mx, my, to.x, to.y);
          ctx!.stroke();
          ctx!.restore();
        }

        // Edge line
        ctx!.save();
        ctx!.globalAlpha = edgeOpacity * (isSatEdge ? 0.4 : 1);
        const baseAlpha = isSatEdge ? 0.12 : 0.25;
        ctx!.strokeStyle = `rgba(56, 189, 248, ${baseAlpha + (edge.probability / 100) * 0.2})`;
        ctx!.lineWidth = isSatEdge ? 0.8 : (edge.edgeType === "primary" ? 1.5 : 1);
        if (isSatEdge) {
          ctx!.setLineDash([3, 6]);
        } else if (edge.edgeType === "alternative") {
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

        // Animated particle (spine edges only)
        if (isSpineEdge) {
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
        }

        // Arrow head (spine edges only)
        if (isSpineEdge) {
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
        }

        // Technique label (spine edges only — reduces clutter)
        if (isSpineEdge && edge.technique) {
          ctx!.save();
          ctx!.globalAlpha = edgeOpacity * 0.6;
          ctx!.font = "10px 'IBM Plex Mono', monospace";
          ctx!.fillStyle = "rgba(148, 163, 184, 0.5)";
          ctx!.textAlign = "center";
          ctx!.fillText(edge.technique, mx, my - 8);
          ctx!.restore();
        }
      });

      // Draw nodes — satellites first (behind), then spine nodes (in front)
      const satellites = nodes.filter(n => n.isSatellite);
      const spines = nodes.filter(n => n.isSpine);

      // Satellite nodes (small, subtle)
      satellites.forEach((node, idx) => {
        const colors = NODE_COLORS[node.nodeType] || NODE_COLORS.pivot;
        const isHovered = hoveredNode === node.id;
        const nodeOpacity = nodeOpacitiesRef.current.get(node.id) ?? 1;
        const r = isHovered ? node.radius + 4 : node.radius;

        // Remediation override colors
        const remStatus = node.remediationStatus;
        const remFill = remStatus === "verified_fixed" ? "#22c55e"
          : remStatus === "in_progress" ? "#eab308"
          : remStatus === "accepted_risk" ? "#6b7280"
          : null;
        const remPulse = remStatus === "in_progress"
          ? 0.5 + Math.sin(t * 4) * 0.5   // 0..1 oscillation for pulsing outline
          : 1;
        const remIcon = remStatus === "verified_fixed" ? "\u2713"
          : remStatus === "accepted_risk" ? "\u2717"
          : null;

        ctx!.save();
        ctx!.globalAlpha = nodeOpacity * 0.8;

        // Subtle glow
        const glowColor = remFill ? `${remFill}44` : colors.glow;
        const gradient = ctx!.createRadialGradient(node.x, node.y, r * 0.3, node.x, node.y, r * 1.8);
        gradient.addColorStop(0, glowColor);
        gradient.addColorStop(1, "transparent");
        ctx!.fillStyle = gradient;
        ctx!.beginPath();
        ctx!.arc(node.x, node.y, r * 1.8, 0, Math.PI * 2);
        ctx!.fill();

        // Node circle
        ctx!.beginPath();
        ctx!.arc(node.x, node.y, r, 0, Math.PI * 2);
        ctx!.fillStyle = remFill ?? colors.bg;
        ctx!.fill();
        ctx!.strokeStyle = remStatus === "in_progress"
          ? `rgba(234,179,8,${remPulse})`
          : remFill ?? colors.border;
        ctx!.lineWidth = isHovered ? 1.5 : 0.8;
        ctx!.stroke();

        // Remediation icon or default dot icon
        ctx!.fillStyle = remFill ? "#fff" : colors.border;
        ctx!.font = remIcon ? "bold 9px sans-serif" : "8px sans-serif";
        ctx!.textAlign = "center";
        ctx!.textBaseline = "middle";
        ctx!.fillText(remIcon ?? "\u25CF", node.x, node.y);

        // Label (only when hovered)
        if (isHovered) {
          ctx!.font = "bold 10px 'Sora', sans-serif";
          ctx!.fillStyle = "#f1f5f9";
          ctx!.textBaseline = "top";
          const label = node.label.length > 24 ? node.label.slice(0, 22) + "..." : node.label;
          ctx!.fillText(label, node.x, node.y + r + 6, 140);

          ctx!.font = "10px 'IBM Plex Mono', monospace";
          ctx!.fillStyle = "rgba(56, 189, 248, 0.7)";
          ctx!.textBaseline = "bottom";
          ctx!.fillText(
            node.assets.length > 0 ? node.assets[0] : "",
            node.x,
            node.y - r - 12,
            200
          );
          ctx!.fillStyle = "rgba(148, 163, 184, 0.6)";
          const detail = node.description.length > 60 ? node.description.slice(0, 58) + "..." : node.description;
          ctx!.fillText(detail, node.x, node.y - r - 2, 250);
        }

        ctx!.restore();
      });

      // Spine nodes (large, prominent)
      spines.forEach((node, idx) => {
        const colors = NODE_COLORS[node.nodeType] || NODE_COLORS.pivot;
        const isHovered = hoveredNode === node.id;
        const nodeOpacity = nodeOpacitiesRef.current.get(node.id) ?? 1;
        const pulse = 1 + Math.sin(t * 2 + idx) * 0.04;
        const r = (isHovered ? node.radius + 6 : node.radius) * pulse;

        // Remediation override colors
        const remStatus = node.remediationStatus;
        const remFill = remStatus === "verified_fixed" ? "#22c55e"
          : remStatus === "in_progress" ? "#eab308"
          : remStatus === "accepted_risk" ? "#6b7280"
          : null;
        const remPulse = remStatus === "in_progress"
          ? 0.4 + Math.abs(Math.sin(t * 4)) * 0.6
          : 1;
        const remIcon = remStatus === "verified_fixed" ? "\u2713"
          : remStatus === "accepted_risk" ? "\u2717"
          : null;

        ctx!.save();
        ctx!.globalAlpha = nodeOpacity;

        // Outer glow
        const glowColor = remFill ? `${remFill}55` : colors.glow;
        const gradient = ctx!.createRadialGradient(node.x, node.y, r * 0.5, node.x, node.y, r * 2.5);
        gradient.addColorStop(0, glowColor);
        gradient.addColorStop(1, "transparent");
        ctx!.fillStyle = gradient;
        ctx!.beginPath();
        ctx!.arc(node.x, node.y, r * 2.5, 0, Math.PI * 2);
        ctx!.fill();

        // Node circle
        ctx!.beginPath();
        ctx!.arc(node.x, node.y, r, 0, Math.PI * 2);
        ctx!.fillStyle = remFill ? `${remFill}33` : colors.bg;
        ctx!.fill();
        ctx!.strokeStyle = remStatus === "in_progress"
          ? `rgba(234,179,8,${remPulse})`
          : remFill ?? colors.border;
        ctx!.lineWidth = isHovered ? 2.5 : 1.5;
        ctx!.stroke();

        // Node icon — remediation overrides default icon
        ctx!.fillStyle = remFill ?? colors.border;
        ctx!.font = `${isHovered ? 16 : 14}px sans-serif`;
        ctx!.textAlign = "center";
        ctx!.textBaseline = "middle";
        ctx!.fillText(remIcon ?? NODE_ICONS[node.nodeType] ?? "\u25CF", node.x, node.y);

        // Node label
        ctx!.font = "bold 11px 'Sora', sans-serif";
        ctx!.fillStyle = isHovered ? "#f1f5f9" : "#cbd5e1";
        ctx!.textAlign = "center";
        ctx!.textBaseline = "top";
        const maxLabelWidth = 120;
        const label = node.label.length > 20 ? node.label.slice(0, 18) + "..." : node.label;
        ctx!.fillText(label, node.x, node.y + r + 8, maxLabelWidth);

        // Tactic label — plain English for non-technical readers
        ctx!.font = "9px 'IBM Plex Mono', monospace";
        const tacticColor = TACTICS_COLORS[node.tactic] || "#64748b";
        ctx!.fillStyle = tacticColor;
        const plainTactic = TACTIC_PLAIN_ENGLISH[node.tactic] || node.tactic.replace(/-/g, " ");
        ctx!.fillText(
          plainTactic.toUpperCase(),
          node.x,
          node.y + r + 22,
          maxLabelWidth + 20
        );

        // "+N findings" badge for collapsed children
        if (node.collapsedCount > 0) {
          const badgeX = node.x + r * 0.75;
          const badgeY = node.y - r * 0.75;
          const badgeText = `+${node.collapsedCount}`;
          const badgeR = 11;

          ctx!.beginPath();
          ctx!.arc(badgeX, badgeY, badgeR, 0, Math.PI * 2);
          ctx!.fillStyle = "rgba(245, 158, 11, 0.9)";
          ctx!.fill();
          ctx!.strokeStyle = "#06090f";
          ctx!.lineWidth = 2;
          ctx!.stroke();

          ctx!.font = "bold 9px 'IBM Plex Mono', monospace";
          ctx!.fillStyle = "#fff";
          ctx!.textAlign = "center";
          ctx!.textBaseline = "middle";
          ctx!.fillText(badgeText, badgeX, badgeY);
        }

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
          onClick={() => {
            if (hoveredNode) {
              setSelectedNode(selectedNode === hoveredNode ? null : hoveredNode);
            } else {
              setSelectedNode(null);
            }
          }}
        />

        {/* Hover Tooltip (spec v1.0 §8.1) */}
        {hoveredNode && tooltipPos && (() => {
          const node = layoutRef.current.layoutNodes.find(n => n.id === hoveredNode);
          if (!node) return null;
          const art = node.artifacts;
          return (
            <div
              style={{
                position: "absolute",
                left: tooltipPos.x,
                top: tooltipPos.y,
                pointerEvents: "none",
                zIndex: 20,
                background: "rgba(6,9,15,0.95)",
                border: "1px solid rgba(56,189,248,0.3)",
                borderRadius: 6,
                padding: "8px 12px",
                minWidth: 200,
                maxWidth: 280,
                backdropFilter: "blur(8px)",
                boxShadow: "0 4px 16px rgba(0,0,0,0.6)",
                fontFamily: "'IBM Plex Mono', monospace",
              }}
            >
              <div style={{ fontSize: 11, fontWeight: 700, color: "#f1f5f9", marginBottom: 4 }}>
                {node.label}
              </div>
              {art?.ip && (
                <div style={{ fontSize: 10, color: "#38bdf8" }}>IP: {art.ip}</div>
              )}
              {art?.hostname && (
                <div style={{ fontSize: 10, color: "#94a3b8" }}>Host: {art.hostname}</div>
              )}
              {art?.attackTechniqueId && (
                <div style={{ fontSize: 10, color: "#a78bfa" }}>
                  {art.attackTechniqueId} — {art.attackTechniqueName || ""}
                </div>
              )}
              {art?.subAgentId && (
                <div style={{ fontSize: 9, color: "#475569", marginTop: 2 }}>
                  Agent: {art.subAgentId}
                  {art.subAgentStatus && (
                    <span style={{
                      marginLeft: 6,
                      color: art.subAgentStatus === "active" ? "#22c55e"
                           : art.subAgentStatus === "dead-end" ? "#ef4444" : "#94a3b8",
                    }}>
                      [{art.subAgentStatus}]
                    </span>
                  )}
                </div>
              )}
              <div style={{ fontSize: 9, color: "#475569", marginTop: 4 }}>
                Click for full details
              </div>
            </div>
          );
        })()}

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

        {/* Click-to-expand Node Detail Panel */}
        {selectedNode && (() => {
          const node = layoutRef.current.layoutNodes.find(n => n.id === selectedNode);
          if (!node) return null;
          const severity = node.compromiseLevel === "admin" ? "critical"
            : node.compromiseLevel === "user" ? "high"
            : node.compromiseLevel === "limited" ? "medium" : "low";
          const severityConfig = {
            critical: { color: "#ef4444", bg: "rgba(239,68,68,0.1)", label: "Critical Risk", icon: "\u26A0" },
            high: { color: "#f59e0b", bg: "rgba(245,158,11,0.1)", label: "High Risk", icon: "\u26A0" },
            medium: { color: "#3b82f6", bg: "rgba(59,130,246,0.1)", label: "Medium Risk", icon: "\u2139" },
            low: { color: "#22c55e", bg: "rgba(34,197,94,0.1)", label: "Low Risk", icon: "\u2713" },
          }[severity] || { color: "#64748b", bg: "rgba(100,116,139,0.1)", label: "Info", icon: "\u2139" };

          return (
            <div
              style={{
                position: "absolute",
                top: 16,
                right: 16,
                width: 320,
                background: "rgba(6,9,15,0.95)",
                border: `1px solid ${severityConfig.color}33`,
                borderRadius: 8,
                padding: 16,
                backdropFilter: "blur(12px)",
                boxShadow: `0 8px 32px rgba(0,0,0,0.5), 0 0 16px ${severityConfig.color}11`,
                zIndex: 10,
              }}
            >
              {/* Severity Traffic Light */}
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                <div style={{
                  width: 28, height: 28, borderRadius: "50%",
                  background: severityConfig.bg, border: `2px solid ${severityConfig.color}`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 14, color: severityConfig.color,
                }}>
                  {severityConfig.icon}
                </div>
                <div>
                  <div style={{
                    fontSize: 11, fontWeight: 700, color: severityConfig.color,
                    fontFamily: "'IBM Plex Mono', monospace", textTransform: "uppercase",
                  }}>
                    {severityConfig.label}
                  </div>
                  <div style={{ fontSize: 9, color: "#64748b" }}>
                    {node.nodeType === "entry" ? "Entry Point" : node.nodeType === "objective" ? "Attacker Goal" : "Attack Step"}
                  </div>
                </div>
                <div
                  style={{
                    marginLeft: "auto", cursor: "pointer", color: "#64748b",
                    fontSize: 16, padding: "0 4px",
                  }}
                  onClick={(e) => { e.stopPropagation(); setSelectedNode(null); }}
                >
                  {"\u2715"}
                </div>
              </div>

              {/* Node Name */}
              <div style={{
                fontSize: 13, fontWeight: 700, color: "#f1f5f9", marginBottom: 6,
              }}>
                {node.label}
              </div>

              {/* Plain English Description */}
              <div style={{
                fontSize: 12, color: "#94a3b8", lineHeight: 1.5, marginBottom: 12,
              }}>
                {node.description || TACTIC_BUSINESS_IMPACT[node.tactic] || "No additional details available."}
              </div>

              {/* What This Means (business impact) */}
              <div style={{
                background: severityConfig.bg, borderRadius: 6, padding: "10px 12px",
                marginBottom: 12,
              }}>
                <div style={{
                  fontSize: 9, color: severityConfig.color, fontWeight: 700,
                  fontFamily: "'IBM Plex Mono', monospace", marginBottom: 4,
                  textTransform: "uppercase", letterSpacing: 0.5,
                }}>
                  What This Means
                </div>
                <div style={{ fontSize: 11, color: "#cbd5e1", lineHeight: 1.5 }}>
                  {TACTIC_BUSINESS_IMPACT[node.tactic] || "This step in the attack chain could expose your organization to risk."}
                </div>
              </div>

              {/* Affected Assets */}
              {node.assets.length > 0 && (
                <div style={{ marginBottom: 8 }}>
                  <div style={{
                    fontSize: 9, color: "#64748b", fontWeight: 600,
                    fontFamily: "'IBM Plex Mono', monospace", marginBottom: 4,
                    textTransform: "uppercase", letterSpacing: 0.5,
                  }}>
                    Affected Systems
                  </div>
                  {node.assets.map((asset, i) => (
                    <div key={i} style={{
                      fontSize: 11, color: "#38bdf8", padding: "2px 0",
                      fontFamily: "'IBM Plex Mono', monospace",
                    }}>
                      {asset}
                    </div>
                  ))}
                </div>
              )}

              {/* Business Impact */}
              {node.businessImpact && (
                <div style={{ marginTop: 12, borderTop: "1px solid rgba(255,255,255,0.1)", paddingTop: 12 }}>
                  <div style={{ fontSize: 11, color: "var(--falcon-t3)", marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.05em" }}>Business Impact</div>

                  {/* Blast radius indicator */}
                  {node.businessImpact.estimatedBlastRadius && (
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                    <span style={{ fontSize: 11 }}>Blast Radius:</span>
                    <span style={{
                      fontSize: 11, fontWeight: 700, padding: "2px 8px", borderRadius: 4,
                      background: node.businessImpact.estimatedBlastRadius === "customer-facing" ? "#ef4444" :
                                  node.businessImpact.estimatedBlastRadius === "organization" ? "#f97316" :
                                  node.businessImpact.estimatedBlastRadius === "department" ? "#eab308" : "#6b7280",
                      color: "#fff",
                    }}>
                      {node.businessImpact.estimatedBlastRadius.toUpperCase().replace("-", " ")}
                    </span>
                  </div>
                  )}

                  {/* Summary */}
                  <p style={{ fontSize: 12, color: "var(--falcon-t2)", margin: "0 0 8px" }}>
                    {node.businessImpact.summary}
                  </p>

                  {/* Data exposed */}
                  {node.businessImpact.dataExposed && (
                    <div style={{ fontSize: 11, color: "#f97316", marginBottom: 6 }}>
                      ⚠ {node.businessImpact.dataExposed}
                    </div>
                  )}

                  {/* Regulatory risk */}
                  {node.businessImpact.regulatoryRisk && (
                    <div style={{ fontSize: 11, background: "rgba(239,68,68,0.15)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 6, padding: "6px 10px", color: "#fca5a5" }}>
                      🔴 {node.businessImpact.regulatoryRisk}
                    </div>
                  )}

                  {/* Financial impact */}
                  {node.businessImpact.financialImpact && (
                    <div style={{ fontSize: 11, color: "var(--falcon-t3)", marginTop: 6 }}>
                      💰 {node.businessImpact.financialImpact}
                    </div>
                  )}
                </div>
              )}

              {/* Attack Phase */}
              <div style={{
                fontSize: 10, color: "#475569", paddingTop: 8,
                borderTop: "1px solid rgba(56,189,248,0.08)",
                fontFamily: "'IBM Plex Mono', monospace",
              }}>
                Phase: {TACTIC_PLAIN_ENGLISH[node.tactic] || node.tactic}
              </div>

              {/* ── Enriched Artifact Sections (spec v1.0 §4.2) ── */}
              {node.artifacts && (() => {
                const art = node.artifacts;
                return (
                  <div style={{ marginTop: 12, borderTop: "1px solid rgba(56,189,248,0.15)", paddingTop: 12 }}>

                    {/* Network Artifacts */}
                    {(art.ip || art.hostname || art.subnet || art.domain) && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 9, color: "#38bdf8", fontWeight: 700, fontFamily: "'IBM Plex Mono', monospace", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>
                          Network Artifacts
                        </div>
                        {art.ip && <div style={{ fontSize: 10, color: "#94a3b8" }}>IP: <span style={{ color: "#38bdf8" }}>{art.ip}</span></div>}
                        {art.hostname && <div style={{ fontSize: 10, color: "#94a3b8" }}>Host: <span style={{ color: "#e2e8f0" }}>{art.hostname}</span></div>}
                        {art.subnet && <div style={{ fontSize: 10, color: "#94a3b8" }}>Subnet: <span style={{ color: "#e2e8f0" }}>{art.subnet}</span></div>}
                        {art.domain && <div style={{ fontSize: 10, color: "#94a3b8" }}>Domain: <span style={{ color: "#e2e8f0" }}>{art.domain}</span></div>}
                      </div>
                    )}

                    {/* ATT&CK Technique */}
                    {art.attackTechniqueId && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 9, color: "#a78bfa", fontWeight: 700, fontFamily: "'IBM Plex Mono', monospace", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>
                          MITRE ATT&CK
                        </div>
                        <div style={{ fontSize: 10, color: "#e2e8f0", fontFamily: "'IBM Plex Mono', monospace" }}>
                          {art.attackTechniqueId}
                          {art.subTechniqueId && <span style={{ color: "#94a3b8" }}>.{art.subTechniqueId}</span>}
                          {" — "}{art.attackTechniqueName || ""}
                        </div>
                        {art.attackTacticName && (
                          <div style={{ fontSize: 9, color: "#64748b" }}>Tactic: {art.attackTacticName}</div>
                        )}
                        {art.procedure && (
                          <div style={{ fontSize: 10, color: "#94a3b8", marginTop: 2, lineHeight: 1.5 }}>{art.procedure}</div>
                        )}
                      </div>
                    )}

                    {/* Exploit Details */}
                    {(art.exploitMethod || art.exploitResult) && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 9, color: "#f59e0b", fontWeight: 700, fontFamily: "'IBM Plex Mono', monospace", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>
                          Exploit
                        </div>
                        {art.exploitMethod && (
                          <div style={{ fontSize: 10, color: "#94a3b8" }}>Method: <span style={{ color: "#fbbf24" }}>{art.exploitMethod}</span></div>
                        )}
                        {art.exploitResult && (
                          <div style={{ fontSize: 10, color: "#94a3b8" }}>Result: <span style={{ color: "#e2e8f0" }}>{art.exploitResult}</span></div>
                        )}
                      </div>
                    )}

                    {/* Open Ports */}
                    {art.openPorts && art.openPorts.length > 0 && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 9, color: "#64748b", fontWeight: 700, fontFamily: "'IBM Plex Mono', monospace", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>
                          Open Ports
                        </div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                          {art.openPorts.slice(0, 12).map((p, i) => (
                            <span key={i} style={{
                              fontSize: 10, color: "#38bdf8", background: "rgba(56,189,248,0.08)",
                              border: "1px solid rgba(56,189,248,0.2)", borderRadius: 3, padding: "1px 5px",
                              fontFamily: "'IBM Plex Mono', monospace",
                            }}>
                              {p.port}{p.service ? `/${p.service}` : ""}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* CVE IDs */}
                    {art.cveIds && art.cveIds.length > 0 && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 9, color: "#ef4444", fontWeight: 700, fontFamily: "'IBM Plex Mono', monospace", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>
                          CVEs
                        </div>
                        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                          {art.cveIds.slice(0, 6).map((cve, i) => (
                            <span key={i} style={{
                              fontSize: 10, color: "#fca5a5", background: "rgba(239,68,68,0.08)",
                              border: "1px solid rgba(239,68,68,0.2)", borderRadius: 3, padding: "1px 5px",
                              fontFamily: "'IBM Plex Mono', monospace",
                            }}>
                              {cve}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Credentials */}
                    {art.credentials && art.credentials.length > 0 && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 9, color: "#f97316", fontWeight: 700, fontFamily: "'IBM Plex Mono', monospace", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>
                          Credentials Harvested
                        </div>
                        {art.credentials.slice(0, 4).map((cred, i) => (
                          <div key={i} style={{
                            background: "rgba(249,115,22,0.06)", border: "1px solid rgba(249,115,22,0.15)",
                            borderRadius: 4, padding: "5px 8px", marginBottom: 4,
                          }}>
                            <div style={{ fontSize: 10, color: "#fb923c", fontFamily: "'IBM Plex Mono', monospace" }}>
                              {cred.username}
                              <span style={{
                                marginLeft: 6, fontSize: 9, padding: "1px 4px", borderRadius: 2,
                                background: cred.privilegeTier === "domain_admin" ? "#ef4444"
                                          : cred.privilegeTier === "local_admin" ? "#f97316"
                                          : cred.privilegeTier === "service_account" ? "#eab308" : "#6b7280",
                                color: "#fff",
                              }}>
                                {cred.privilegeTier.replace("_", " ").toUpperCase()}
                              </span>
                            </div>
                            <div style={{ fontSize: 9, color: "#64748b" }}>
                              Source: {cred.sourceSystem}
                              {cred.reusedOn && cred.reusedOn.length > 0 && ` · Reused on ${cred.reusedOn.length} system${cred.reusedOn.length > 1 ? "s" : ""}`}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Commands Run */}
                    {art.commandsRun && art.commandsRun.length > 0 && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 9, color: "#64748b", fontWeight: 700, fontFamily: "'IBM Plex Mono', monospace", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>
                          Commands Executed
                        </div>
                        {art.commandsRun.slice(0, 5).map((cmd, i) => (
                          <div key={i} style={{
                            fontSize: 10, color: "#94a3b8", fontFamily: "'IBM Plex Mono', monospace",
                            background: "rgba(15,23,42,0.8)", border: "1px solid rgba(255,255,255,0.05)",
                            borderRadius: 3, padding: "2px 6px", marginBottom: 2,
                            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                          }}>
                            $ {cmd}
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Defense Coverage */}
                    {((art.defensesFired && art.defensesFired.length > 0) || (art.defensesMissed && art.defensesMissed.length > 0)) && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 9, color: "#64748b", fontWeight: 700, fontFamily: "'IBM Plex Mono', monospace", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>
                          Defense Coverage
                        </div>
                        {art.defensesFired && art.defensesFired.length > 0 && (
                          <div style={{ marginBottom: 4 }}>
                            <span style={{ fontSize: 9, color: "#22c55e" }}>✓ FIRED: </span>
                            <span style={{ fontSize: 9, color: "#4ade80" }}>{art.defensesFired.join(", ")}</span>
                          </div>
                        )}
                        {art.defensesMissed && art.defensesMissed.length > 0 && (
                          <div>
                            <span style={{ fontSize: 9, color: "#ef4444" }}>✗ MISSED: </span>
                            <span style={{ fontSize: 9, color: "#fca5a5" }}>{art.defensesMissed.join(", ")}</span>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Sub-Agent Info */}
                    {art.subAgentId && (
                      <div style={{ marginBottom: 6 }}>
                        <div style={{ fontSize: 9, color: "#475569", fontFamily: "'IBM Plex Mono', monospace" }}>
                          Sub-Agent: {art.subAgentId}
                          {art.subAgentStatus && (
                            <span style={{
                              marginLeft: 6,
                              color: art.subAgentStatus === "active" ? "#22c55e"
                                   : art.subAgentStatus === "dead-end" ? "#ef4444" : "#64748b",
                            }}>
                              [{art.subAgentStatus}]
                            </span>
                          )}
                        </div>
                        {art.childNodeIds && art.childNodeIds.length > 0 && (
                          <div style={{ fontSize: 9, color: "#475569" }}>
                            {art.childNodeIds.length} child node{art.childNodeIds.length > 1 ? "s" : ""} spawned
                          </div>
                        )}
                      </div>
                    )}

                    {/* Discovered At */}
                    {art.discoveredAt && (
                      <div style={{ fontSize: 9, color: "#334155", fontFamily: "'IBM Plex Mono', monospace", marginTop: 4 }}>
                        Discovered: {new Date(art.discoveredAt).toLocaleTimeString()}
                      </div>
                    )}
                  </div>
                );
              })()}
            </div>
          );
        })()}
      </div>

      {/* Executive Summary — auto-generated plain English narrative */}
      {graph && graph.nodes && graph.nodes.length > 0 && (
        <ExecutiveSummary graph={graph} riskScore={riskScore} />
      )}
    </div>
  );
}

// ============================================================================
// SUB-COMPONENTS
// ============================================================================

// ============================================================================
// EXECUTIVE SUMMARY — Auto-generated plain English narrative
// ============================================================================

function ExecutiveSummary({ graph, riskScore }: { graph: AttackGraph; riskScore?: number }) {
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const criticalPath = graph.criticalPath || [];
  const ttc = graph.timeToCompromise;

  // Count node types
  const entryPoints = nodes.filter(n => n.nodeType === "entry").length;
  const objectives = nodes.filter(n => n.nodeType === "objective").length;
  const totalSteps = criticalPath.length;

  // Gather unique tactics on the critical path
  const criticalTactics = new Set<string>();
  for (const nodeId of criticalPath) {
    const node = nodes.find(n => n.id === nodeId);
    if (node?.tactic) criticalTactics.add(node.tactic);
  }

  // Count compromised assets
  const allAssets = new Set<string>();
  for (const node of nodes) {
    for (const asset of (node.assets || [])) allAssets.add(asset);
  }

  // Risk level text
  const riskLevel = !riskScore ? "unknown"
    : riskScore >= 80 ? "critical"
    : riskScore >= 60 ? "high"
    : riskScore >= 40 ? "moderate"
    : "low";

  const riskColors: Record<string, { text: string; bg: string; border: string }> = {
    critical: { text: "#ef4444", bg: "rgba(239,68,68,0.08)", border: "rgba(239,68,68,0.2)" },
    high: { text: "#f59e0b", bg: "rgba(245,158,11,0.08)", border: "rgba(245,158,11,0.2)" },
    moderate: { text: "#3b82f6", bg: "rgba(59,130,246,0.08)", border: "rgba(59,130,246,0.2)" },
    low: { text: "#22c55e", bg: "rgba(34,197,94,0.08)", border: "rgba(34,197,94,0.2)" },
    unknown: { text: "#64748b", bg: "rgba(100,116,139,0.08)", border: "rgba(100,116,139,0.2)" },
  };
  const rc = riskColors[riskLevel];

  // Build the narrative
  const narrative = buildNarrative(totalSteps, entryPoints, objectives, allAssets.size, criticalTactics, ttc, riskLevel);

  return (
    <div
      style={{
        padding: "16px 24px",
        borderTop: "1px solid rgba(56,189,248,0.06)",
        background: "rgba(6,9,15,0.8)",
      }}
    >
      {/* Section Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
        <div style={{
          fontSize: 11, fontWeight: 700, color: "#94a3b8",
          fontFamily: "'IBM Plex Mono', monospace",
          textTransform: "uppercase", letterSpacing: 1,
        }}>
          Executive Summary
        </div>
        <div style={{
          fontSize: 10, fontWeight: 700, color: rc.text,
          background: rc.bg, border: `1px solid ${rc.border}`,
          padding: "2px 10px", borderRadius: 100,
          fontFamily: "'IBM Plex Mono', monospace",
          textTransform: "uppercase",
        }}>
          {riskLevel} risk
        </div>
      </div>

      {/* Narrative */}
      <div style={{
        fontSize: 13, color: "#cbd5e1", lineHeight: 1.7,
        maxWidth: 900,
      }}>
        {narrative}
      </div>

      {/* Key Numbers */}
      <div style={{
        display: "flex", gap: 24, marginTop: 14, paddingTop: 12,
        borderTop: "1px solid rgba(56,189,248,0.06)",
      }}>
        <SummaryMetric label="Attack Steps" value={totalSteps} />
        <SummaryMetric label="Entry Points" value={entryPoints} />
        <SummaryMetric label="Systems at Risk" value={allAssets.size} />
        <SummaryMetric label="Attack Goals" value={objectives} />
        {ttc && <SummaryMetric label="Time to Breach" value={`${ttc.expected} ${ttc.unit}`} />}
      </div>
    </div>
  );
}

function buildNarrative(
  steps: number,
  entries: number,
  objectives: number,
  assets: number,
  tactics: Set<string>,
  ttc: AttackGraph["timeToCompromise"],
  riskLevel: string
): string {
  const parts: string[] = [];

  // Opening
  if (riskLevel === "critical" || riskLevel === "high") {
    parts.push(`This assessment identified a ${riskLevel}-risk attack path that an adversary could use to compromise your organization.`);
  } else {
    parts.push(`This assessment identified an attack path with ${riskLevel} overall risk to your organization.`);
  }

  // Attack path description
  if (steps > 0) {
    parts.push(`The attack chain consists of ${steps} step${steps !== 1 ? "s" : ""}, starting from ${entries} entry point${entries !== 1 ? "s" : ""}.`);
  }

  // Business impact
  if (tactics.has("credential-access")) {
    parts.push("The attacker could steal login credentials, potentially accessing sensitive accounts.");
  }
  if (tactics.has("lateral-movement")) {
    parts.push("Once inside, the attacker can spread to other systems across your network.");
  }
  if (tactics.has("exfiltration")) {
    parts.push("There is a path for the attacker to extract sensitive data outside your organization.");
  }
  if (tactics.has("impact")) {
    parts.push("The attacker could cause direct business disruption, including data destruction or ransomware.");
  }

  // Systems at risk
  if (assets > 0) {
    parts.push(`${assets} system${assets !== 1 ? "s" : ""} ${assets !== 1 ? "are" : "is"} at risk along this attack path.`);
  }

  // Time to compromise
  if (ttc) {
    parts.push(`Estimated time to full compromise: ${ttc.expected} ${ttc.unit}.`);
  }

  return parts.join(" ");
}

function SummaryMetric({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <div style={{
        fontSize: 9, color: "#475569", fontFamily: "'IBM Plex Mono', monospace",
        textTransform: "uppercase", letterSpacing: 0.5,
      }}>
        {label}
      </div>
      <div style={{ fontSize: 16, fontWeight: 700, color: "#e2e8f0" }}>
        {value}
      </div>
    </div>
  );
}

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
