import { useEffect, useRef, useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { buildSankeyData, severityColor, type SankeyData } from "@/lib/dashboard-transforms";

// ── Visual constants ───────────────────────────────────────────────────

const PAD_X = 60;
const PAD_Y = 40;
const NODE_W = 18;
const NODE_GAP = 8;
const MIN_LINK_W = 2;

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

// ── Component ──────────────────────────────────────────────────────────

export function AssetFlowSankey() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const animRef = useRef<number>(0);
  const timeRef = useRef(0);
  const [dims, setDims] = useState({ w: 800, h: 500 });

  const { data: assets = [] } = useQuery<any[]>({ queryKey: ["/api/assets"] });
  const { data: evaluations = [] } = useQuery<any[]>({ queryKey: ["/api/aev/evaluations"] });

  const sankeyData = useMemo(() => buildSankeyData(assets, evaluations), [assets, evaluations]);

  // ── Responsive sizing ────────────────────────────────────────────────
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

  // ── Canvas animation loop ───────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = dims.w * dpr;
    canvas.height = dims.h * dpr;
    ctx.scale(dpr, dpr);

    const layout = computeLayout(sankeyData, dims.w, dims.h);

    function draw() {
      timeRef.current += 0.008;
      const t = timeRef.current;
      ctx!.clearRect(0, 0, dims.w, dims.h);

      if (layout.leftNodes.length === 0) {
        drawEmptyState(ctx!, dims.w, dims.h);
        animRef.current = requestAnimationFrame(draw);
        return;
      }

      // Draw links (bezier curves)
      for (const link of layout.links) {
        drawLink(ctx!, link, t);
      }

      // Draw left nodes (asset groups)
      for (const node of layout.leftNodes) {
        drawLeftNode(ctx!, node, t);
      }

      // Draw right nodes (severity groups)
      for (const node of layout.rightNodes) {
        drawRightNode(ctx!, node, t);
      }

      animRef.current = requestAnimationFrame(draw);
    }

    draw();
    return () => cancelAnimationFrame(animRef.current);
  }, [dims, sankeyData]);

  return (
    <div
      ref={containerRef}
      className="w-full h-full relative"
      style={{ minHeight: 400 }}
    >
      <canvas
        ref={canvasRef}
        style={{ width: "100%", height: "100%" }}
      />
      {/* Watermark */}
      <div className="absolute bottom-3 right-4 text-[10px] font-mono text-cyan-400/20">
        Asset → Finding Flow
      </div>
    </div>
  );
}

// ── Layout computation ─────────────────────────────────────────────────

interface LayoutNode {
  label: string;
  count: number;
  x: number;
  y: number;
  h: number;
  color: string;
  severity?: string;
}

interface LayoutLink {
  sx: number; sy: number; sh: number;
  tx: number; ty: number; th: number;
  color: string;
  value: number;
  severity: string;
}

interface Layout {
  leftNodes: LayoutNode[];
  rightNodes: LayoutNode[];
  links: LayoutLink[];
}

function computeLayout(data: SankeyData, w: number, h: number): Layout {
  if (data.leftNodes.length === 0 || data.rightNodes.length === 0) {
    return { leftNodes: [], rightNodes: [], links: [] };
  }

  const drawW = w - PAD_X * 2;
  const drawH = h - PAD_Y * 2;

  // Left column positions
  const leftTotal = data.leftNodes.reduce((s, n) => s + n.count, 0) || 1;
  const leftNodes: LayoutNode[] = [];
  let leftY = PAD_Y;
  for (const n of data.leftNodes) {
    const nodeH = Math.max(20, (n.count / leftTotal) * (drawH - (data.leftNodes.length - 1) * NODE_GAP));
    leftNodes.push({
      label: n.label,
      count: n.count,
      x: PAD_X,
      y: leftY,
      h: nodeH,
      color: "#06b6d4",
    });
    leftY += nodeH + NODE_GAP;
  }

  // Right column positions
  const rightTotal = data.rightNodes.reduce((s, n) => s + n.count, 0) || 1;
  const rightNodes: LayoutNode[] = [];
  let rightY = PAD_Y;
  for (const n of data.rightNodes) {
    const nodeH = Math.max(20, (n.count / rightTotal) * (drawH - (data.rightNodes.length - 1) * NODE_GAP));
    rightNodes.push({
      label: n.label,
      count: n.count,
      x: PAD_X + drawW - NODE_W,
      y: rightY,
      h: nodeH,
      color: SEVERITY_COLORS[n.severity] || "#64748b",
      severity: n.severity,
    });
    rightY += nodeH + NODE_GAP;
  }

  // Build links — track consumed space on each node
  const leftConsumed = new Map<string, number>();
  const rightConsumed = new Map<string, number>();

  const links: LayoutLink[] = [];
  for (const link of data.links) {
    const leftNode = leftNodes.find((n) => n.label === link.source);
    const rightNode = rightNodes.find((n) => n.severity === link.severity);
    if (!leftNode || !rightNode) continue;

    const leftUsed = leftConsumed.get(link.source) || 0;
    const rightUsed = rightConsumed.get(link.severity) || 0;

    const linkH = Math.max(
      MIN_LINK_W,
      (link.value / leftTotal) * leftNode.h,
    );
    const linkHR = Math.max(
      MIN_LINK_W,
      (link.value / rightTotal) * rightNode.h,
    );

    links.push({
      sx: leftNode.x + NODE_W,
      sy: leftNode.y + leftUsed,
      sh: linkH,
      tx: rightNode.x,
      ty: rightNode.y + rightUsed,
      th: linkHR,
      color: SEVERITY_COLORS[link.severity] || "#64748b",
      value: link.value,
      severity: link.severity,
    });

    leftConsumed.set(link.source, leftUsed + linkH);
    rightConsumed.set(link.severity, rightUsed + linkHR);
  }

  return { leftNodes, rightNodes, links };
}

// ── Drawing helpers ────────────────────────────────────────────────────

function drawLink(ctx: CanvasRenderingContext2D, link: LayoutLink, t: number) {
  const { sx, sy, sh, tx, ty, th, color } = link;
  const midX = (sx + tx) / 2;

  // Glow pass
  ctx.save();
  ctx.globalAlpha = 0.08 + Math.sin(t * 1.5) * 0.02;
  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.moveTo(sx, sy);
  ctx.bezierCurveTo(midX, sy, midX, ty, tx, ty);
  ctx.lineTo(tx, ty + th);
  ctx.bezierCurveTo(midX, ty + th, midX, sy + sh, sx, sy + sh);
  ctx.closePath();
  ctx.fill();
  ctx.restore();

  // Sharp pass
  ctx.save();
  ctx.globalAlpha = 0.25 + Math.sin(t * 2 + link.value) * 0.05;
  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.moveTo(sx, sy);
  ctx.bezierCurveTo(midX, sy, midX, ty, tx, ty);
  ctx.lineTo(tx, ty + th);
  ctx.bezierCurveTo(midX, ty + th, midX, sy + sh, sx, sy + sh);
  ctx.closePath();
  ctx.fill();
  ctx.restore();

  // Animated particle
  const particleT = ((t * 0.25 + link.value * 0.1) % 1);
  const pt = particleT;
  const px = cubicBezier(pt, sx, midX, midX, tx);
  const py = cubicBezier(pt, sy + sh / 2, sy + sh / 2, ty + th / 2, ty + th / 2);

  ctx.save();
  ctx.beginPath();
  ctx.arc(px, py, 3, 0, Math.PI * 2);
  ctx.fillStyle = color;
  ctx.globalAlpha = 0.6 + Math.sin(t * 4) * 0.3;
  ctx.fill();
  // Particle glow
  ctx.beginPath();
  ctx.arc(px, py, 8, 0, Math.PI * 2);
  ctx.fillStyle = color;
  ctx.globalAlpha = 0.12;
  ctx.fill();
  ctx.restore();
}

function drawLeftNode(ctx: CanvasRenderingContext2D, node: LayoutNode, t: number) {
  const pulse = 1 + Math.sin(t * 1.2) * 0.01;

  // Node bar
  ctx.save();
  ctx.fillStyle = node.color;
  ctx.globalAlpha = 0.7;
  const r = 3;
  roundRect(ctx, node.x, node.y, NODE_W * pulse, node.h, r);
  ctx.fill();
  // Glow
  ctx.shadowColor = node.color;
  ctx.shadowBlur = 12;
  ctx.globalAlpha = 0.3;
  roundRect(ctx, node.x, node.y, NODE_W * pulse, node.h, r);
  ctx.fill();
  ctx.restore();

  // Label
  ctx.save();
  ctx.font = "bold 11px 'Inter', system-ui";
  ctx.fillStyle = "#e2e8f0";
  ctx.textAlign = "right";
  ctx.textBaseline = "middle";
  ctx.fillText(node.label, node.x - 8, node.y + node.h / 2);
  // Count
  ctx.font = "10px 'IBM Plex Mono', monospace";
  ctx.fillStyle = "#64748b";
  ctx.fillText(`(${node.count})`, node.x - 8, node.y + node.h / 2 + 14);
  ctx.restore();
}

function drawRightNode(ctx: CanvasRenderingContext2D, node: LayoutNode, t: number) {
  const pulse = 1 + Math.sin(t * 1.5 + 1) * 0.01;

  // Node bar
  ctx.save();
  ctx.fillStyle = node.color;
  ctx.globalAlpha = 0.7;
  const r = 3;
  roundRect(ctx, node.x, node.y, NODE_W * pulse, node.h, r);
  ctx.fill();
  ctx.shadowColor = node.color;
  ctx.shadowBlur = 12;
  ctx.globalAlpha = 0.3;
  roundRect(ctx, node.x, node.y, NODE_W * pulse, node.h, r);
  ctx.fill();
  ctx.restore();

  // Label
  ctx.save();
  ctx.font = "bold 11px 'Inter', system-ui";
  ctx.fillStyle = "#e2e8f0";
  ctx.textAlign = "left";
  ctx.textBaseline = "middle";
  ctx.fillText(node.label, node.x + NODE_W + 10, node.y + node.h / 2);
  // Count
  ctx.font = "10px 'IBM Plex Mono', monospace";
  ctx.fillStyle = node.color;
  ctx.fillText(String(node.count), node.x + NODE_W + 10, node.y + node.h / 2 + 14);
  ctx.restore();
}

function drawEmptyState(ctx: CanvasRenderingContext2D, w: number, h: number) {
  ctx.save();
  ctx.font = "14px 'Inter', system-ui";
  ctx.fillStyle = "rgba(148, 163, 184, 0.4)";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText("No asset data available", w / 2, h / 2 - 10);
  ctx.font = "11px 'IBM Plex Mono', monospace";
  ctx.fillStyle = "rgba(148, 163, 184, 0.25)";
  ctx.fillText("Run evaluations to see asset → finding flow", w / 2, h / 2 + 14);
  ctx.restore();
}

// ── Math helpers ───────────────────────────────────────────────────────

function cubicBezier(t: number, p0: number, p1: number, p2: number, p3: number): number {
  const u = 1 - t;
  return u * u * u * p0 + 3 * u * u * t * p1 + 3 * u * t * t * p2 + t * t * t * p3;
}

function roundRect(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  w: number,
  h: number,
  r: number,
) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r);
  ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}
