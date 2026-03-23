import { useState, useEffect, useCallback, useRef } from "react";
import type { EvidenceData, AssetProofItem } from "./EvidencePanel";
import "../../styles/canvas.css";

// ── Types ────────────────────────────────────────────────────────────────────

interface CanvasNode {
  id: string;
  label: string;
  x: number;
  y: number;
  r: number;
  col: string;
  data: EvidenceData;
}

interface CanvasEdge {
  id: string;
  fromId: string;
  toId: string;
  col: string;
  dashed: boolean;
  crossLink: boolean;
}

export interface LiveAttackCanvasProps {
  canvasEvents: any[];
  reasoningStream: any[];
  operatorSummary: any;
  chainId: string;
  onNodeClick?: (data: EvidenceData) => void;
}

// ── Layout constants ─────────────────────────────────────────────────────────

const SVG_W = 510;
const SVG_H = 295;

const PHASE_X: Record<string, number> = {
  application_compromise: 90,
  credential_extraction: 210,
  cloud_iam_escalation: 370,
  container_k8s_breakout: 200,
  lateral_movement: 370,
  impact_assessment: 300,
};

const PHASE_COL: Record<string, string> = {
  application_compromise: "#ef4444",
  credential_extraction: "#f59e0b",
  cloud_iam_escalation: "#3b82f6",
  container_k8s_breakout: "#8b5cf6",
  lateral_movement: "#06b6d4",
  impact_assessment: "#ef4444",
};

const SEV_COL: Record<string, string> = {
  critical: "#ef4444",
  high: "#f59e0b",
  medium: "#3b82f6",
  low: "#334155",
  info: "#334155",
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function truncateLabel(raw: string, maxLen = 10): string {
  if (raw.length <= maxLen) return raw;
  return raw.slice(0, maxLen);
}

function hashJitter(s: string, range: number): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  }
  return ((h % range) + range) % range;
}

function buildAssets(evt: any): AssetProofItem[] {
  const assets: AssetProofItem[] = [];
  const ctx = evt.context || {};
  if (ctx.targetUrl || evt.targetUrl) assets.push({ k: "target", v: ctx.targetUrl || evt.targetUrl, c: "blue" });
  if (ctx.ip) assets.push({ k: "IP address", v: ctx.ip, c: "red" });
  if (ctx.port) assets.push({ k: "port", v: String(ctx.port), c: "" });
  if (ctx.technique || evt.technique) assets.push({ k: "technique", v: ctx.technique || evt.technique, c: "" });
  if (ctx.service) assets.push({ k: "service", v: ctx.service, c: "" });
  if (evt.detail) assets.push({ k: "detail", v: evt.detail, c: "" });
  // Surface-discovery context: zone, sensitivity, phase, kind
  if (evt.zone) assets.push({ k: "zone", v: evt.zone, c: "" });
  if (evt.sensitivity) assets.push({ k: "sensitivity", v: evt.sensitivity, c: "" });
  if (evt.phase) assets.push({ k: "phase", v: evt.phase, c: "" });
  if (evt.kind) assets.push({ k: "role", v: evt.kind, c: "" });
  if (evt.source && !ctx.targetUrl && !evt.targetUrl) assets.push({ k: "source", v: evt.source, c: "blue" });
  return assets;
}

function buildEvidenceData(evt: any): EvidenceData {
  const ctx = evt.context || {};
  return {
    title: evt.label || evt.detail || evt.source || "Unknown",
    sev: evt.severity || ctx.severity || "info",
    technique: ctx.technique || evt.technique || undefined,
    mitre: ctx.mitre || evt.mitre || undefined,
    assets: buildAssets(evt),
    status: ctx.statusCode || evt.statusCode || undefined,
    evidence: ctx.evidence || evt.responseSnippet || ctx.responseSnippet || undefined,
    extracted: ctx.extracted || undefined,
    curl: ctx.curlCommand || evt.curlCommand || undefined,
    ts: evt.timestamp || undefined,
    hash: ctx.hash || evt.evidenceHash || null,
  };
}

// ── Component ────────────────────────────────────────────────────────────────

export function LiveAttackCanvas({
  canvasEvents,
  reasoningStream: _reasoningStream,
  operatorSummary: _operatorSummary,
  chainId,
  onNodeClick,
}: LiveAttackCanvasProps) {
  const [nodes, setNodes] = useState<Map<string, CanvasNode>>(new Map());
  const [edges, setEdges] = useState<CanvasEdge[]>([]);
  const [processedCount, setProcessedCount] = useState(0);
  const [hintText, setHintText] = useState("click any node to inspect evidence & context");
  const [hintActive, setHintActive] = useState(false);
  const yCounters = useRef<Record<string, number>>({});

  useEffect(() => {
    setNodes(new Map());
    setEdges([]);
    setProcessedCount(0);
    yCounters.current = {};
  }, [chainId]);

  const processEvent = useCallback(
    (evt: any) => {
      const canvasType: string = evt.canvasType || evt.type || "";

      switch (canvasType) {
        case "node_discovered": {
          const id = evt.source || evt.nodeId || "";
          if (!id) break;
          setNodes((prev) => {
            if (prev.has(id)) return prev;
            const next = new Map(prev);
            const phase: string = evt.phase || evt.zone || "application_compromise";
            const sev: string = evt.severity || "medium";
            const baseX = PHASE_X[phase] || SVG_W * 0.5;
            const col = SEV_COL[sev] || PHASE_COL[phase] || "#6b7280";
            const count = yCounters.current[phase] || 0;
            yCounters.current[phase] = count + 1;
            const baseY = 40 + count * 32 + hashJitter(id, 15);
            const jitterX = hashJitter(id + "x", 50) - 25;
            const r = sev === "critical" || evt.kind === "phase_spine" ? 17 : 13;
            const label = evt.label ? truncateLabel(evt.label) : truncateLabel(id);

            next.set(id, {
              id,
              label,
              x: Math.max(r + 2, Math.min(SVG_W - r - 2, baseX + jitterX)),
              y: Math.max(r + 2, Math.min(SVG_H - r - 2, baseY)),
              r,
              col,
              data: buildEvidenceData(evt),
            });
            return next;
          });
          break;
        }

        case "edge_confirmed": {
          const from = evt.source || evt.fromNodeId || "";
          const to = evt.target || evt.toNodeId || "";
          if (!from || !to) break;
          const edgeId = `${from}->${to}`;
          setEdges((prev) => {
            if (prev.some((e) => e.id === edgeId)) return prev;
            return [
              ...prev,
              {
                id: edgeId,
                fromId: from,
                toId: to,
                col: evt.col || "#ef4444",
                dashed: evt.dashed ?? false,
                crossLink: evt.crossLink ?? false,
              },
            ];
          });
          break;
        }

        case "node_classified": {
          const id = evt.source || evt.nodeId || "";
          if (!id) break;
          setNodes((prev) => {
            const existing = prev.get(id);
            if (!existing) return prev;
            const next = new Map(prev);
            const updatedData = { ...existing.data };
            if (evt.detail) updatedData.evidence = evt.detail;
            if (evt.severity) updatedData.sev = evt.severity;
            next.set(id, {
              ...existing,
              data: updatedData,
              col: SEV_COL[evt.severity || ""] || existing.col,
            });
            return next;
          });
          break;
        }

        case "artifact_gained": {
          const id = evt.source || evt.nodeId || "";
          if (!id) break;
          setNodes((prev) => {
            const existing = prev.get(id);
            if (!existing) return prev;
            const next = new Map(prev);
            const updatedData = { ...existing.data };
            if (evt.detail) updatedData.extracted = evt.detail;
            next.set(id, { ...existing, data: updatedData });
            return next;
          });
          break;
        }
      }
    },
    [],
  );

  useEffect(() => {
    if (canvasEvents.length <= processedCount) return;
    const newEvents = canvasEvents.slice(processedCount);
    for (const evt of newEvents) {
      processEvent(evt);
    }
    setProcessedCount(canvasEvents.length);
  }, [canvasEvents, processedCount, processEvent]);

  // Resolve edge coordinates from node positions at render time
  const resolvedEdges = edges.map((edge) => {
    const fromNode = nodes.get(edge.fromId);
    const toNode = nodes.get(edge.toId);
    if (!fromNode || !toNode) return null;
    return { ...edge, x1: fromNode.x, y1: fromNode.y, x2: toNode.x, y2: toNode.y };
  }).filter((e): e is CanvasEdge & { x1: number; y1: number; x2: number; y2: number } => e !== null);

  const nodeArray = Array.from(nodes.values());

  return (
    <div className="cv-gf">
      <div className="cv-gh">
        <span className="cv-gh-t">network breach map</span>
        <span
          className="cv-gh-hint"
          style={{ color: hintActive ? "#60a5fa" : undefined }}
        >
          {hintText}
        </span>
      </div>
      <div className="cv-gb">
        <svg
          className="cv-gs"
          viewBox={`0 0 ${SVG_W} ${SVG_H}`}
          preserveAspectRatio="xMidYMid meet"
        >
          <defs>
            <marker
              id="ar"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="4"
              markerHeight="4"
              orient="auto-start-reverse"
            >
              <path
                d="M2 1L8 5L2 9"
                fill="none"
                stroke="context-stroke"
                strokeWidth="1.5"
                strokeLinecap="round"
              />
            </marker>
          </defs>

          {/* Edges */}
          {resolvedEdges.map((edge) => (
            <line
              key={edge.id}
              x1={edge.x1}
              y1={edge.y1}
              x2={edge.x2}
              y2={edge.y2}
              stroke={edge.col}
              strokeWidth={edge.crossLink ? 1 : 0.7}
              strokeDasharray={edge.dashed ? "3 3" : edge.crossLink ? "6 3" : "400"}
              strokeDashoffset={edge.dashed ? "0" : "400"}
              strokeOpacity={edge.dashed ? 0.2 : edge.crossLink ? 0.5 : 1}
              markerEnd="url(#ar)"
              className={edge.dashed ? "" : "cv-edge-draw"}
            />
          ))}

          {/* Nodes */}
          {nodeArray.map((node) => (
            <g
              key={node.id}
              className="cv-node-appear"
              style={{
                cursor: "pointer",
                transformOrigin: `${node.x}px ${node.y}px`,
              }}
              onClick={() => {
                if (onNodeClick) {
                  onNodeClick(node.data);
                }
              }}
              onMouseEnter={() => {
                setHintText(node.data.title);
                setHintActive(true);
              }}
              onMouseLeave={() => {
                setHintText("click any node to inspect evidence & context");
                setHintActive(false);
              }}
            >
              <circle
                cx={node.x}
                cy={node.y}
                r={node.r + 5}
                fill="transparent"
                stroke="transparent"
              />
              <circle
                cx={node.x}
                cy={node.y}
                r={node.r}
                fill="#0d1117"
                stroke={node.col}
                strokeWidth="1.5"
              />
              <text
                x={node.x}
                y={node.y}
                textAnchor="middle"
                dominantBaseline="central"
                fontSize={node.r > 15 ? 10 : 7}
                fontFamily="monospace"
                fill={node.col}
              >
                {node.label}
              </text>
            </g>
          ))}

          {/* Empty state */}
          {nodeArray.length === 0 && (
            <text
              x={SVG_W / 2}
              y={SVG_H / 2}
              textAnchor="middle"
              fontFamily="monospace"
              fontSize="10"
              fill="#334155"
            >
              network map loading...
            </text>
          )}
        </svg>
      </div>
    </div>
  );
}
