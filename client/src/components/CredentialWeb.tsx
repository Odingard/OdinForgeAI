/**
 * CredentialWeb — Live credential graph visualization (spec v1.0 §5.1, §8.2)
 *
 * Every credential as a node, connected to: source system, systems where
 * reused, what was unlocked. Color-coded by privilege tier.
 *
 * Clicking a credential node shows full detail.
 * Feature flag: BREACH_CHAIN_CREDENTIAL_WEB
 */

import { useEffect, useRef, useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { BREACH_ENHANCEMENT_FLAGS, isBreachFlagEnabled } from "@shared/schema";

// ── Types ──────────────────────────────────────────────────────────────────

type PrivilegeTier = "domain_admin" | "local_admin" | "service_account" | "standard_user";

interface CredentialWebNode {
  id: string;
  username: string;
  privilegeTier: PrivilegeTier;
  sourceSystem: string;
  discoveredAt: string;
  reusedOn: Array<{ target: string; timestamp: string; success: boolean }>;
  unlocked: string[];
  hasHash: boolean;
  hasCleartext: boolean;
}

interface CredentialWebProps {
  breachChainId: string;
  isRunning?: boolean;
  onClose?: () => void;
}

// Privilege tier colors (spec §8.2)
const TIER_COLORS: Record<PrivilegeTier, { color: string; bg: string; label: string }> = {
  domain_admin:    { color: "#ef4444", bg: "rgba(239,68,68,0.15)", label: "Domain Admin" },
  local_admin:     { color: "#f97316", bg: "rgba(249,115,22,0.15)", label: "Local Admin" },
  service_account: { color: "#eab308", bg: "rgba(234,179,8,0.15)", label: "Service Account" },
  standard_user:   { color: "#e2e8f0", bg: "rgba(226,232,240,0.08)", label: "Standard User" },
};

// ── Layout ─────────────────────────────────────────────────────────────────

interface GraphNode {
  id: string;
  label: string;
  type: "credential" | "system" | "unlocked";
  tier?: PrivilegeTier;
  x: number;
  y: number;
  radius: number;
}

interface GraphEdge {
  from: string;
  to: string;
  type: "discovered_at" | "reused_on" | "unlocked";
  success?: boolean;
}

function buildGraph(
  creds: CredentialWebNode[],
  width: number,
  height: number
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const systemNodes = new Map<string, GraphNode>();

  const cx = width / 2;
  const cy = height / 2;

  // Place credential nodes in a circle
  creds.forEach((cred, i) => {
    const angle = (i / creds.length) * Math.PI * 2 - Math.PI / 2;
    const r = Math.min(width, height) * 0.28;
    const x = cx + Math.cos(angle) * r;
    const y = cy + Math.sin(angle) * r;

    nodes.push({
      id: `cred-${cred.id}`,
      label: cred.username,
      type: "credential",
      tier: cred.privilegeTier,
      x, y,
      radius: cred.privilegeTier === "domain_admin" ? 20 : cred.privilegeTier === "local_admin" ? 16 : 12,
    });

    // Source system node
    const sysKey = `sys-${cred.sourceSystem}`;
    if (!systemNodes.has(sysKey)) {
      const sysAngle = angle - 0.3;
      const sysR = r + 70;
      const sysNode: GraphNode = {
        id: sysKey,
        label: cred.sourceSystem,
        type: "system",
        x: cx + Math.cos(sysAngle) * sysR,
        y: cy + Math.sin(sysAngle) * sysR,
        radius: 8,
      };
      systemNodes.set(sysKey, sysNode);
      nodes.push(sysNode);
    }
    edges.push({ from: sysKey, to: `cred-${cred.id}`, type: "discovered_at" });

    // Reused-on nodes
    cred.reusedOn.forEach((reuse, j) => {
      const rKey = `reuse-${reuse.target}`;
      if (!systemNodes.has(rKey)) {
        const rAngle = angle + 0.3 + j * 0.2;
        const rR = r + 70;
        const rNode: GraphNode = {
          id: rKey,
          label: reuse.target,
          type: "system",
          x: cx + Math.cos(rAngle) * rR,
          y: cy + Math.sin(rAngle) * rR,
          radius: 8,
        };
        systemNodes.set(rKey, rNode);
        nodes.push(rNode);
      }
      edges.push({
        from: `cred-${cred.id}`,
        to: rKey,
        type: "reused_on",
        success: reuse.success,
      });
    });

    // Unlocked targets
    cred.unlocked.forEach((target, j) => {
      const uKey = `unlock-${target}`;
      if (!systemNodes.has(uKey)) {
        const uAngle = angle + 0.15 + j * 0.25;
        const uR = r + 120;
        const uNode: GraphNode = {
          id: uKey,
          label: target,
          type: "unlocked",
          x: cx + Math.cos(uAngle) * uR,
          y: cy + Math.sin(uAngle) * uR,
          radius: 10,
        };
        systemNodes.set(uKey, uNode);
        nodes.push(uNode);
      }
      edges.push({ from: `cred-${cred.id}`, to: uKey, type: "unlocked" });
    });
  });

  return { nodes, edges };
}

// ── Component ──────────────────────────────────────────────────────────────

export function CredentialWeb({ breachChainId, isRunning, onClose }: CredentialWebProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const animRef = useRef<number>(0);
  const timeRef = useRef(0);
  const [dims, setDims] = useState({ w: 800, h: 500 });
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);
  const [selectedCred, setSelectedCred] = useState<CredentialWebNode | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const graphRef = useRef<{ nodes: GraphNode[]; edges: GraphEdge[] }>({ nodes: [], edges: [] });

  const { data: credentials = [] } = useQuery<CredentialWebNode[]>({
    queryKey: ["/api/breach-chains", breachChainId, "credentials"],
    queryFn: async () => {
      const res = await fetch(`/api/breach-chains/${breachChainId}/credentials`, {
        credentials: "include",
      });
      if (!res.ok) return [];
      return res.json();
    },
    enabled: !!breachChainId,
    refetchInterval: isRunning ? 3000 : false,
  });

  // Responsive sizing
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      setDims({ w: Math.max(width, 400), h: Math.max(height, 300) });
    });
    ro.observe(container);
    return () => ro.disconnect();
  }, []);

  // Re-layout when credentials change
  useEffect(() => {
    if (credentials.length === 0) { graphRef.current = { nodes: [], edges: [] }; return; }
    graphRef.current = buildGraph(credentials, dims.w, dims.h);
  }, [credentials, dims.w, dims.h]);

  // Canvas render loop
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
      timeRef.current += 0.01;
      const t = timeRef.current;
      ctx!.clearRect(0, 0, dims.w, dims.h);

      const { nodes, edges } = graphRef.current;
      if (nodes.length === 0) {
        ctx!.font = "12px 'IBM Plex Mono', monospace";
        ctx!.fillStyle = "rgba(148,163,184,0.4)";
        ctx!.textAlign = "center";
        ctx!.fillText("No credentials harvested yet", dims.w / 2, dims.h / 2);
        animRef.current = requestAnimationFrame(draw);
        return;
      }

      const nodeMap = new Map(nodes.map(n => [n.id, n]));

      // Draw edges
      for (const edge of edges) {
        const from = nodeMap.get(edge.from);
        const to = nodeMap.get(edge.to);
        if (!from || !to) continue;

        const edgeColor = edge.type === "unlocked" ? "rgba(239,68,68,0.5)"
          : edge.type === "reused_on" && edge.success ? "rgba(249,115,22,0.4)"
          : "rgba(56,189,248,0.2)";

        ctx!.save();
        ctx!.strokeStyle = edgeColor;
        ctx!.lineWidth = edge.type === "unlocked" ? 1.5 : 1;
        ctx!.setLineDash(edge.type === "discovered_at" ? [] : [4, 4]);
        ctx!.lineDashOffset = -t * 20;
        ctx!.beginPath();
        ctx!.moveTo(from.x, from.y);
        ctx!.lineTo(to.x, to.y);
        ctx!.stroke();
        ctx!.restore();
      }

      // Draw nodes
      for (const node of nodes) {
        const isHovered = hoveredNode?.id === node.id;
        const credColor = node.tier ? TIER_COLORS[node.tier].color : "#64748b";
        const fillColor = node.type === "credential" ? credColor
          : node.type === "unlocked" ? "rgba(239,68,68,0.3)"
          : "rgba(56,189,248,0.15)";
        const borderColor = node.type === "credential" ? credColor
          : node.type === "unlocked" ? "#ef4444"
          : "#38bdf8";

        // Glow for credential nodes
        if (node.type === "credential" && node.tier) {
          ctx!.save();
          ctx!.shadowColor = credColor;
          ctx!.shadowBlur = isHovered ? 20 : 8 + Math.sin(t * 2) * 3;
        }

        ctx!.beginPath();
        ctx!.arc(node.x, node.y, node.radius + (isHovered ? 2 : 0), 0, Math.PI * 2);
        ctx!.fillStyle = fillColor;
        ctx!.fill();
        ctx!.strokeStyle = borderColor;
        ctx!.lineWidth = node.type === "credential" ? 1.5 : 1;
        ctx!.stroke();

        if (node.type === "credential" && node.tier) ctx!.restore();

        // Label
        ctx!.font = `${node.type === "credential" ? "10px" : "8px"} 'IBM Plex Mono', monospace`;
        ctx!.fillStyle = node.type === "credential" ? "#f1f5f9" : "#94a3b8";
        ctx!.textAlign = "center";
        ctx!.fillText(
          node.label.length > 14 ? node.label.slice(0, 12) + "…" : node.label,
          node.x,
          node.y + node.radius + 12
        );
      }

      animRef.current = requestAnimationFrame(draw);
    }

    draw();
    return () => cancelAnimationFrame(animRef.current);
  }, [dims, hoveredNode]);

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const { nodes } = graphRef.current;
    let found: GraphNode | null = null;
    for (const node of nodes) {
      const dx = mx - node.x;
      const dy = my - node.y;
      if (dx * dx + dy * dy < (node.radius + 8) ** 2) { found = node; break; }
    }
    setHoveredNode(found);
    if (found) setTooltipPos({ x: e.clientX - rect.left + 12, y: e.clientY - rect.top + 12 });
  }, []);

  const handleClick = useCallback(() => {
    if (!hoveredNode || hoveredNode.type !== "credential") return;
    const credId = hoveredNode.id.replace("cred-", "");
    const cred = credentials.find(c => c.id === credId);
    if (cred) setSelectedCred(selectedCred?.id === credId ? null : cred);
  }, [hoveredNode, credentials, selectedCred]);

  const tierCounts = Object.fromEntries(
    Object.keys(TIER_COLORS).map(tier => [
      tier,
      credentials.filter(c => c.privilegeTier === tier).length,
    ])
  ) as Record<PrivilegeTier, number>;

  return (
    <div style={{ background: "#080c14", border: "1px solid rgba(56,189,248,0.15)", borderRadius: 8, overflow: "hidden", fontFamily: "'IBM Plex Mono', monospace" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", padding: "10px 14px", borderBottom: "1px solid rgba(56,189,248,0.08)", background: "rgba(56,189,248,0.03)" }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "#f1f5f9", textTransform: "uppercase", letterSpacing: 1 }}>
            Credential Web
          </div>
          <div style={{ fontSize: 9, color: "#64748b", marginTop: 1 }}>
            {credentials.length} credential{credentials.length !== 1 ? "s" : ""} harvested
            {isRunning && <span style={{ marginLeft: 8, color: "#22c55e" }}>● LIVE</span>}
          </div>
        </div>
        {/* Tier legend */}
        <div style={{ display: "flex", gap: 10, marginRight: 12 }}>
          {(Object.entries(TIER_COLORS) as Array<[PrivilegeTier, typeof TIER_COLORS[PrivilegeTier]]>).map(([tier, cfg]) => (
            <div key={tier} style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: cfg.color }} />
              <span style={{ fontSize: 9, color: "#64748b" }}>
                {cfg.label.split(" ")[0]} ({tierCounts[tier] ?? 0})
              </span>
            </div>
          ))}
        </div>
        {onClose && (
          <div onClick={onClose} style={{ cursor: "pointer", color: "#64748b", fontSize: 16, padding: "0 4px" }}>×</div>
        )}
      </div>

      {/* Canvas */}
      <div ref={containerRef} style={{ position: "relative", width: "100%", height: 400 }}>
        <canvas
          ref={canvasRef}
          style={{ width: "100%", height: "100%", cursor: hoveredNode?.type === "credential" ? "pointer" : "default" }}
          onMouseMove={handleMouseMove}
          onMouseLeave={() => setHoveredNode(null)}
          onClick={handleClick}
        />

        {/* Hover tooltip */}
        {hoveredNode && (
          <div style={{
            position: "absolute", left: tooltipPos.x, top: tooltipPos.y,
            background: "rgba(6,9,15,0.95)", border: "1px solid rgba(56,189,248,0.3)",
            borderRadius: 6, padding: "6px 10px", pointerEvents: "none", zIndex: 10,
          }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: hoveredNode.tier ? TIER_COLORS[hoveredNode.tier].color : "#94a3b8" }}>
              {hoveredNode.label}
            </div>
            {hoveredNode.tier && (
              <div style={{ fontSize: 9, color: "#64748b" }}>{TIER_COLORS[hoveredNode.tier].label}</div>
            )}
            {hoveredNode.type === "credential" && (
              <div style={{ fontSize: 9, color: "#475569", marginTop: 2 }}>Click for details</div>
            )}
          </div>
        )}

        {/* Selected credential detail panel */}
        {selectedCred && (
          <div style={{
            position: "absolute", top: 8, right: 8, width: 240,
            background: "rgba(6,9,15,0.97)", border: `1px solid ${TIER_COLORS[selectedCred.privilegeTier].color}44`,
            borderRadius: 6, padding: 12, zIndex: 20,
          }}>
            <div style={{ display: "flex", alignItems: "center", marginBottom: 8 }}>
              <div style={{ flex: 1, fontSize: 11, fontWeight: 700, color: TIER_COLORS[selectedCred.privilegeTier].color }}>
                {selectedCred.username}
              </div>
              <div onClick={() => setSelectedCred(null)} style={{ cursor: "pointer", color: "#64748b", fontSize: 14 }}>×</div>
            </div>
            <div style={{ fontSize: 9, marginBottom: 6 }}>
              <span style={{ color: "#64748b" }}>Tier: </span>
              <span style={{ color: TIER_COLORS[selectedCred.privilegeTier].color }}>{TIER_COLORS[selectedCred.privilegeTier].label}</span>
            </div>
            <div style={{ fontSize: 9, color: "#64748b", marginBottom: 2 }}>Source: <span style={{ color: "#94a3b8" }}>{selectedCred.sourceSystem}</span></div>
            {selectedCred.hasHash && <div style={{ fontSize: 9, color: "#f59e0b" }}>⚠ Hash captured</div>}
            {selectedCred.hasCleartext && <div style={{ fontSize: 9, color: "#ef4444" }}>⚠ Cleartext captured</div>}
            {selectedCred.reusedOn.length > 0 && (
              <div style={{ marginTop: 6 }}>
                <div style={{ fontSize: 9, color: "#f97316", marginBottom: 2 }}>Reused on {selectedCred.reusedOn.length} system{selectedCred.reusedOn.length > 1 ? "s" : ""}:</div>
                {selectedCred.reusedOn.slice(0, 4).map((r, i) => (
                  <div key={i} style={{ fontSize: 9, color: r.success ? "#4ade80" : "#ef4444", paddingLeft: 6 }}>
                    {r.success ? "✓" : "✗"} {r.target}
                  </div>
                ))}
              </div>
            )}
            {selectedCred.unlocked.length > 0 && (
              <div style={{ marginTop: 6 }}>
                <div style={{ fontSize: 9, color: "#ef4444", marginBottom: 2 }}>Unlocked {selectedCred.unlocked.length} target{selectedCred.unlocked.length > 1 ? "s" : ""}:</div>
                {selectedCred.unlocked.slice(0, 3).map((t, i) => (
                  <div key={i} style={{ fontSize: 9, color: "#fca5a5", paddingLeft: 6 }}>→ {t}</div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export function CredentialWebGated(props: CredentialWebProps) {
  if (!isBreachFlagEnabled(BREACH_ENHANCEMENT_FLAGS.CREDENTIAL_WEB)) return null;
  return <CredentialWeb {...props} />;
}
