import { useState, useEffect, useRef, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import { useBreachChainUpdates } from "@/hooks/useBreachChainUpdates";
import { Play, StopCircle, Eye, Plus, Download, RotateCcw, Shield, FileText, Trash2 } from "lucide-react";
import type { BreachChain, BreachPhaseResult, AttackGraph } from "@shared/schema";

// ── Types ────────────────────────────────────────────────────────────────────

interface NodeData {
  title: string; sev: string; mitre?: string; technique?: string;
  assets?: { k: string; v: string; c?: string }[];
  status?: number; evidence?: string; extracted?: string;
  curl?: string; ts?: string; hash?: string;
}

interface GraphNode { id: string; x: number; y: number; r: number; label: string; col: string; data: NodeData; }
interface GraphEdge { x1: number; y1: number; x2: number; y2: number; col: string; dashed: boolean; cx: boolean; delay: number; }

// ── Constants ────────────────────────────────────────────────────────────────

const PHASE_LABELS: Record<string, string> = {
  application_compromise:   "APP",
  credential_extraction:    "CREDS",
  cloud_iam_escalation:     "IAM",
  container_k8s_breakout:   "K8S",
  lateral_movement:         "LATERAL",
  impact_assessment:        "IMPACT",
};

const PHASE_ORDER = [
  "application_compromise", "credential_extraction", "cloud_iam_escalation",
  "container_k8s_breakout", "lateral_movement", "impact_assessment",
];

const SEV_COLOR: Record<string, string> = {
  critical: "var(--red)", high: "var(--amber)",
  medium: "var(--blue)", low: "var(--blue)", info: "var(--t3)",
};

const SEV_CLS: Record<string, string> = {
  critical: "f-chip f-chip-crit", high: "f-chip f-chip-high",
  medium: "f-chip f-chip-med", low: "f-chip f-chip-low", info: "f-chip f-chip-gray",
};

// ── SVG helpers ──────────────────────────────────────────────────────────────

function mkEl(tag: string, attrs: Record<string, string>) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  Object.entries(attrs).forEach(([k, v]) => el.setAttribute(k, v));
  return el;
}

// ── Evidence Panel ───────────────────────────────────────────────────────────

function EvidencePanel({ data, title, onClose }: { data: NodeData; title: string; onClose: () => void }) {
  const sevCls = data.sev === "critical" ? "f-chip f-chip-crit" : data.sev === "high" ? "f-chip f-chip-high" : "f-chip f-chip-gray";
  return (
    <div className="flex flex-col h-full" style={{ borderLeft: "1px solid var(--border)" }}>
      <div className="flex items-center justify-between px-3 py-[7px] flex-shrink-0"
        style={{ borderBottom: "1px solid var(--border)", background: "var(--panel2)" }}>
        <span className="font-mono text-[9px] tracking-[.1em] uppercase text-ellipsis overflow-hidden whitespace-nowrap max-w-[180px]"
          style={{ color: "var(--t3)" }}>{title}</span>
        <button onClick={onClose} className="font-mono text-[13px] leading-none px-[3px]"
          style={{ background: "transparent", border: "none", color: "var(--t3)", cursor: "pointer" }}>✕</button>
      </div>
      <div className="flex-1 overflow-y-auto p-3 font-mono text-[9px]">
        <span className={sevCls} style={{ marginBottom: 10, display: "inline-block" }}>
          {data.sev?.toUpperCase()}
        </span>

        {data.mitre && (
          <div style={{ marginBottom: 10 }}>
            <div className="ev-label-row">MITRE ATT&CK</div>
            <div style={{ color: "var(--t1)", fontSize: 10, lineHeight: 1.5 }}>{data.mitre} — {data.technique}</div>
          </div>
        )}

        {data.assets && data.assets.length > 0 && (
          <>
            <div style={{ height: 1, background: "var(--border)", margin: "10px 0" }} />
            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 8, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--amber)", marginBottom: 5, display: "flex", alignItems: "center", gap: 5 }}>
                <span style={{ width: 5, height: 5, borderRadius: "50%", background: "var(--amber)", display: "inline-block" }} />
                ASSET PROOF
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "3px 10px", lineHeight: 1.65 }}>
                {data.assets.map((a, i) => (
                  <>
                    <span key={`k${i}`} style={{ color: "var(--t3)", whiteSpace: "nowrap" }}>{a.k}</span>
                    <span key={`v${i}`} style={{ color: a.c === "red" ? "var(--red)" : a.c === "amber" ? "var(--amber)" : a.c === "blue" ? "var(--blue)" : a.c === "green" ? "var(--green)" : "var(--t1)", fontWeight: a.c === "red" ? 700 : undefined, wordBreak: "break-all" }}>{a.v}</span>
                  </>
                ))}
              </div>
            </div>
          </>
        )}

        {data.status && (
          <>
            <div style={{ height: 1, background: "var(--border)", margin: "10px 0" }} />
            <div style={{ marginBottom: 10 }}>
              <div style={{ fontSize: 8, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--t3)", marginBottom: 4 }}>HTTP STATUS</div>
              <div style={{ fontSize: 11, color: data.status === 200 ? "var(--green)" : "var(--amber)" }}>{data.status} OK — confirmed live</div>
            </div>
          </>
        )}

        {data.evidence && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 8, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--t3)", marginBottom: 4 }}>EVIDENCE SNIPPET</div>
            <div style={{ fontSize: 8.5, padding: 8, background: "var(--bg)", border: "1px solid var(--border2)", color: "var(--t2)", lineHeight: 1.65, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{data.evidence}</div>
          </div>
        )}

        {data.extracted && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 8, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--red)", marginBottom: 4, display: "flex", alignItems: "center", gap: 5 }}>
              <span style={{ width: 5, height: 5, borderRadius: "50%", background: "var(--red)", display: "inline-block" }} />
              EXTRACTED DATA
            </div>
            <div style={{ fontSize: 8.5, padding: 8, background: "rgba(232,56,79,.05)", border: "1px solid var(--red-border)", color: "var(--red)", lineHeight: 1.65, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{data.extracted}</div>
          </div>
        )}

        {data.curl && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 8, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--t3)", marginBottom: 4 }}>REPRODUCE</div>
            <div style={{ fontSize: 8.5, padding: 8, background: "var(--bg)", border: "1px solid var(--border2)", color: "var(--t2)", lineHeight: 1.65, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{data.curl}</div>
          </div>
        )}

        {data.ts && (
          <>
            <div style={{ height: 1, background: "var(--border)", margin: "10px 0" }} />
            <div style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 8, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--t3)", marginBottom: 3 }}>CONFIRMED AT</div>
              <div style={{ fontSize: 9, color: "var(--t3)" }}>{data.ts}</div>
            </div>
          </>
        )}

        {data.hash && (
          <div style={{ fontSize: 7.5, padding: "5px 7px", background: "var(--bg)", border: "1px solid var(--border)", color: "var(--t4)", wordBreak: "break-all", marginTop: 8 }}>
            <span style={{ color: "var(--t3)" }}>SHA-256: </span>{data.hash}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Network Map ──────────────────────────────────────────────────────────────

function NetworkMap({
  chain, graph, nodes: liveNodes, edges: liveEdges,
}: {
  chain: BreachChain;
  graph: AttackGraph | null;
  nodes: any[];
  edges: any[];
}) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [selectedNode, setSelectedNode] = useState<{ data: NodeData; title: string } | null>(null);
  const [hint, setHint] = useState("click any confirmed node for full evidence");
  const nodeStore = useRef<Record<string, NodeData>>({});
  const drawnIds = useRef<Set<string>>(new Set());
  const drawnEdges = useRef<Set<string>>(new Set());

  function drawEdge(x1: number, y1: number, x2: number, y2: number, col: string, dashed: boolean, cx: boolean, delay: number) {
    setTimeout(() => {
      const s = svgRef.current; if (!s) return;
      const ln = mkEl("line", { x1: String(x1), y1: String(y1), x2: String(x2), y2: String(y2), stroke: col, "stroke-width": cx ? "0.9" : "0.7", "marker-end": "url(#ar)" });
      if (dashed) { ln.setAttribute("stroke-dasharray", "3 3"); ln.setAttribute("stroke-opacity", "0.2"); }
      else { ln.setAttribute("stroke-dasharray", cx ? "6 3" : "400"); ln.setAttribute("stroke-dashoffset", "400"); ln.setAttribute("stroke-opacity", cx ? "0.45" : "1"); (ln as SVGElement & { style: CSSStyleDeclaration }).style.animation = "dl .5s ease forwards"; }
      s.insertBefore(ln, s.firstChild);
    }, delay);
  }

  function drawNode(n: GraphNode) {
    const s = svgRef.current; if (!s) return;
    nodeStore.current[n.id] = n.data;
    const g = mkEl("g", { cursor: n.data.sev === "info" ? "default" : "pointer" });
    (g as SVGElement & { style: CSSStyleDeclaration }).style.transformOrigin = `${n.x}px ${n.y}px`;
    (g as SVGElement & { style: CSSStyleDeclaration }).style.animation = "pn .35s cubic-bezier(.34,1.56,.64,1) forwards";
    (g as SVGElement & { style: CSSStyleDeclaration }).style.opacity = "0";
    const hit = mkEl("circle", { cx: String(n.x), cy: String(n.y), r: String(n.r + 5), fill: "transparent", stroke: "transparent" });
    const circ = mkEl("circle", { cx: String(n.x), cy: String(n.y), r: String(n.r), fill: "var(--panel)", stroke: n.col, "stroke-width": "1.5" });
    const txt = mkEl("text", { x: String(n.x), y: String(n.y), "text-anchor": "middle", "dominant-baseline": "central", "font-size": n.r > 15 ? "10" : "7", "font-family": "var(--font-mono)", fill: n.col });
    txt.textContent = n.label;
    g.appendChild(hit); g.appendChild(circ); g.appendChild(txt);
    if (n.data.sev !== "info") {
      g.addEventListener("click", () => setSelectedNode({ data: n.data, title: n.data.title }));
      g.addEventListener("mouseenter", () => { (circ as Element).setAttribute("stroke-width", "2.5"); setHint(n.data.title); });
      g.addEventListener("mouseleave", () => { (circ as Element).setAttribute("stroke-width", "1.5"); setHint("click any confirmed node for full evidence"); });
    }
    s.appendChild(g);
  }

  // Build graph from live nodes/edges when available
  useEffect(() => {
    if (liveNodes.length === 0) return;
    const RED = "var(--red)", AMB = "var(--amber)", BLU = "var(--blue)", GRY = "var(--t4)";
    // Map liveNodes to positioned graph nodes
    // Positions: phases spread spatially across canvas
    const phasePos: Record<string, { x: number; y: number }> = {
      application_compromise:  { x: 52,  y: 38  },
      credential_extraction:   { x: 205, y: 50  },
      cloud_iam_escalation:    { x: 370, y: 30  },
      container_k8s_breakout:  { x: 200, y: 168 },
      lateral_movement:        { x: 365, y: 168 },
      impact_assessment:       { x: 295, y: 248 },
    };
    liveNodes.forEach((n: any) => {
      if (drawnIds.current.has(n.nodeId)) return;
      drawnIds.current.add(n.nodeId);
      const pos = phasePos[n.phase] ?? { x: 260, y: 148 };
      const isSpine = n.kind === "phase_spine";
      const col = n.severity === "critical" ? RED : n.severity === "high" ? AMB : isSpine ? "var(--t2)" : GRY;
      const nodeData: NodeData = {
        title: n.label, sev: n.severity ?? "info",
        technique: n.technique, ts: n.timestamp,
      };
      drawNode({ id: n.nodeId, x: pos.x, y: pos.y, r: isSpine ? 17 : 13, label: n.label?.slice(0, 6) ?? "?", col, data: nodeData });
    });
    liveEdges.forEach((e: any) => {
      const key = `${e.fromNodeId}-${e.toNodeId}`;
      if (drawnEdges.current.has(key)) return;
      drawnEdges.current.add(key);
      // Simple fallback positioning — edges draw between drawn node positions
      drawEdge(0, 0, 0, 0, e.confirmed ? RED : GRY, !e.confirmed, false, 0);
    });
  }, [liveNodes, liveEdges]);

  // Fallback: draw a summary graph from completed phase results
  useEffect(() => {
    if (liveNodes.length > 0) return;
    if (!chain.phaseResults?.length) return;
    const s = svgRef.current; if (!s) return;
    // Clear existing drawn nodes
    while (s.children.length > 1) s.removeChild(s.lastChild!); // keep defs
    drawnIds.current.clear(); drawnEdges.current.clear();

    const phaseCoords = [
      { x: 52, y: 38 }, { x: 205, y: 50 }, { x: 370, y: 30 },
      { x: 200, y: 168 }, { x: 365, y: 168 }, { x: 295, y: 248 },
    ];
    const RED = "var(--red)", AMB = "var(--amber)", GRN = "var(--green)", GRY = "var(--t3)";

    chain.phaseResults.forEach((phase, i) => {
      const pos = phaseCoords[i] ?? { x: 260, y: 148 };
      const hasBreach = (phase.findings || []).some((f: any) => f.severity === "critical");
      const col = phase.status === "completed" ? (hasBreach ? RED : GRN) : phase.status === "running" ? AMB : GRY;
      const data: NodeData = {
        title: `Phase ${i + 1} — ${PHASE_LABELS[phase.phaseName] ?? phase.phaseName}`,
        sev: hasBreach ? "critical" : phase.status === "completed" ? "info" : "info",
        technique: `${(phase.findings || []).length} findings`,
        ts: phase.completedAt ?? undefined,
      };
      drawNode({ id: `phase-${i}`, x: pos.x, y: pos.y, r: 17, label: String(i + 1), col, data });
      if (i > 0) drawEdge(phaseCoords[i - 1].x, phaseCoords[i - 1].y, pos.x, pos.y, GRY, false, false, 300 + i * 200);
      (phase.findings || []).slice(0, 3).forEach((f: any, fi: number) => {
        const fCol = SEV_COLOR[f.severity] ?? GRY;
        const fx = pos.x + (fi % 2 === 0 ? 80 : -80);
        const fy = pos.y + Math.floor(fi / 2) * 28 - 14;
        const fData: NodeData = {
          title: f.title ?? "Finding", sev: f.severity ?? "medium",
          technique: f.technique, mitre: f.mitreId,
          evidence: f.description, ts: f.confirmedAt,
        };
        drawNode({ id: `f-${i}-${fi}`, x: fx, y: fy, r: 11, label: (f.severity ?? "med").slice(0, 4), col: fCol, data: fData });
        drawEdge(pos.x, pos.y, fx, fy, fCol, false, false, 500 + i * 200 + fi * 100);
      });
    });
  }, [chain.phaseResults, liveNodes.length]);

  return (
    <div className="flex flex-1 min-h-0 overflow-hidden">
      {/* Map */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <div className="flex items-center justify-between px-3 py-[6px] flex-shrink-0"
          style={{ borderBottom: "1px solid var(--border)", background: "var(--panel2)" }}>
          <span className="font-mono text-[9px] tracking-[.1em] uppercase" style={{ color: "var(--t3)" }}>network breach map</span>
          <span className="font-mono text-[7px]" style={{ color: "var(--t4)" }}>{hint}</span>
        </div>
        <div className="flex-1 overflow-hidden">
          <svg ref={svgRef} style={{ width: "100%", height: "100%", display: "block" }} viewBox="0 0 510 295" preserveAspectRatio="xMidYMid meet">
            <defs>
              <style>{`
                @keyframes pn{from{opacity:0;transform:scale(0)}to{opacity:1;transform:scale(1)}}
                @keyframes dl{from{stroke-dashoffset:400}to{stroke-dashoffset:0}}
              `}</style>
              <marker id="ar" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="4" markerHeight="4" orient="auto-start-reverse">
                <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" strokeWidth="1.5" strokeLinecap="round"/>
              </marker>
            </defs>
            {liveNodes.length === 0 && !chain.phaseResults?.length && (
              <text x="255" y="148" textAnchor="middle" fontFamily="monospace" fontSize="10" fill="var(--t4)">
                {chain.status === "pending" ? "engagement queued — awaiting start" : "initializing network map..."}
              </text>
            )}
          </svg>
        </div>
      </div>

      {/* Evidence panel */}
      {selectedNode && (
        <div style={{ width: 264, flexShrink: 0 }}>
          <EvidencePanel data={selectedNode.data} title={selectedNode.title} onClose={() => setSelectedNode(null)} />
        </div>
      )}
    </div>
  );
}

// ── Feed row ─────────────────────────────────────────────────────────────────

function FeedRow({ ts, agent, agCls, msg, msgCls }: { ts: string; agent: string; agCls: string; msg: string; msgCls?: string }) {
  const agStyle: Record<string, { color: string; border: string; background: string }> = {
    EXPLOIT: { color: "var(--red)",   border: "var(--red-border)",   background: "var(--red-dim)"   },
    RECON:   { color: "var(--blue)",  border: "var(--blue-border)",  background: "var(--blue-dim)"  },
    CLOUD:   { color: "var(--amber)", border: "var(--amber-border)", background: "var(--amber-dim)" },
    LATERAL: { color: "var(--green)", border: "var(--green-border)", background: "var(--green-dim)" },
    SYS:     { color: "var(--t3)",    border: "var(--border2)",      background: "rgba(255,255,255,.03)" },
  };
  const s = agStyle[agent] ?? agStyle.SYS;
  const textColor = msgCls === "ok" ? "var(--green)" : msgCls === "crit" ? "var(--red)" : msgCls === "warn" ? "var(--amber)" : "var(--t2)";
  return (
    <div className="flex gap-[6px] font-mono text-[9px] leading-[1.55]" style={{ animation: "fadein .15s ease" }}>
      <span style={{ color: "var(--t4)", flexShrink: 0, minWidth: 36, fontSize: 8, marginTop: 1 }}>{ts}</span>
      <span style={{ flexShrink: 0, fontSize: 7, padding: "1px 4px", fontWeight: 700, minWidth: 44, textAlign: "center", marginTop: 2, ...s }}>{agent}</span>
      <span style={{ flex: 1, color: textColor }}>{msg}</span>
    </div>
  );
}

// ── Chain Detail View ─────────────────────────────────────────────────────────

function ChainDetailView({ chain, onBack }: { chain: BreachChain; onBack: () => void }) {
  const { toast } = useToast();
  const { nodes, edges, liveEvents, latestGraph } = useBreachChainUpdates({
    enabled: chain.status === "running" || chain.status === "paused",
    chainId: chain.id,
  });
  const [elapsed, setElapsed] = useState(0);
  const tiRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (chain.status === "running") {
      tiRef.current = setInterval(() => setElapsed(e => e + 1), 1000);
    }
    return () => { if (tiRef.current) clearInterval(tiRef.current); };
  }, [chain.status]);

  const abortMut = useMutation({ mutationFn: () => apiRequest("POST", `/api/breach-chains/${chain.id}/abort`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] }); toast({ title: "Chain aborted" }); },
    onError: (e: Error) => toast({ title: "Abort failed", description: e.message, variant: "destructive" }),
  });
  const deleteMut = useMutation({
    mutationFn: () => apiRequest("DELETE", `/api/breach-chains/${chain.id}`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] }); toast({ title: "Engagement deleted" }); onBack(); },
    onError: (e: Error) => toast({ title: "Delete failed", description: e.message, variant: "destructive" }),
  });

  const totalFindings = (chain.phaseResults || []).flatMap((p: any) => p.findings || []).length;
  const critFindings  = (chain.phaseResults || []).flatMap((p: any) => p.findings || []).filter((f: any) => f.severity === "critical").length;
  const totalCreds    = chain.totalCredentialsHarvested ?? 0;
  const currentPhaseIdx = PHASE_ORDER.indexOf(chain.currentPhase ?? "");
  const timer = `${String(Math.floor(elapsed / 60)).padStart(2, "0")}:${String(elapsed % 60).padStart(2, "0")}`;

  // Build feed from liveEvents + phase completions
  const feedRows: { ts: string; agent: string; msg: string; cls: string }[] = [
    { ts: "00:00", agent: "SYS", msg: `target: ${(chain as any).targetUrl ?? chain.targetDomains?.[0] ?? chain.name} — engagement started`, cls: "dim" },
    ...(chain.phaseResults || []).map((p: any, i: number) => ({
      ts: "—", agent: p.phaseName?.includes("cloud") ? "CLOUD" : p.phaseName?.includes("lateral") ? "LATERAL" : p.phaseName?.includes("recon") ? "RECON" : "EXPLOIT",
      msg: `${PHASE_LABELS[p.phaseName] ?? p.phaseName} — ${p.status} — ${(p.findings || []).length} findings`,
      cls: p.status === "completed" && (p.findings || []).some((f: any) => f.severity === "critical") ? "crit" : "ok",
    })),
    ...liveEvents.map((e: any) => ({
      ts: "live", agent: e.eventKind?.includes("cred") ? "EXPLOIT" : e.eventKind?.includes("cloud") ? "CLOUD" : "EXPLOIT",
      msg: e.detail ?? e.target, cls: "warn",
    })),
  ];

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Chain header */}
      <div className="flex items-center gap-3 px-4 py-3 flex-shrink-0" style={{ borderBottom: "1px solid var(--border)", background: "var(--panel)" }}>
        <button onClick={onBack} className="flex items-center gap-[6px] font-mono text-[10px] px-[8px] py-[4px] cursor-pointer transition-all"
          style={{ color: "var(--t3)", border: "1px solid var(--border2)", background: "transparent" }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = "var(--t1)"; }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = "var(--t3)"; }}>
          ← All Chains
        </button>
        <div>
          <div className="font-mono text-[12px] font-semibold" style={{ color: "var(--t1)" }}>{(chain as any).targetUrl ?? chain.targetDomains?.[0] ?? chain.name}</div>
          <div className="font-mono text-[9px]" style={{ color: "var(--t3)" }}>
            {chain.id?.slice(0, 16)} · full-chain · {chain.config?.executionMode ?? "live"} · {(chain as any).targetIp ?? "resolving..."}
          </div>
        </div>

        {chain.status === "running" && (
          <div className="flex items-center gap-[6px] px-[10px] py-[4px] ml-2" style={{ background: "var(--green-dim)", border: "1px solid var(--green-border)" }}>
            <div className="w-[5px] h-[5px] rounded-full" style={{ background: "var(--green)", animation: "f-pulse 1.4s infinite" }} />
            <span className="font-mono text-[9px]" style={{ color: "var(--green)" }}>running</span>
          </div>
        )}
        {chain.status === "completed" && (
          <div className="flex items-center gap-[6px] px-[10px] py-[4px] ml-2" style={{ background: "rgba(255,255,255,.04)", border: "1px solid var(--border2)" }}>
            <span className="font-mono text-[9px]" style={{ color: "var(--t3)" }}>completed</span>
          </div>
        )}

        <div className="ml-auto flex items-center gap-3">
          {/* Stats inline */}
          {[
            { v: String(critFindings), l: "critical", c: critFindings > 0 ? "var(--red)" : undefined },
            { v: String(totalFindings), l: "findings", c: undefined },
            { v: String(totalCreds), l: "creds", c: totalCreds > 0 ? "var(--amber)" : undefined },
            { v: timer, l: "elapsed", c: undefined },
            { v: chain.overallRiskScore ? String(chain.overallRiskScore) : "—", l: "grade", c: chain.overallRiskScore ? "var(--red)" : undefined },
          ].map(({ v, l, c }) => (
            <div key={l} className="flex flex-col items-center" style={{ gap: 1, minWidth: 36 }}>
              <div className="font-mono text-[12px] font-medium leading-none" style={{ color: c ?? "var(--t1)" }}>{v}</div>
              <div className="font-mono text-[8px] tracking-[.1em] uppercase" style={{ color: "var(--t3)" }}>{l}</div>
            </div>
          ))}
          {(chain.status === "running" || chain.status === "paused") && (
            <button onClick={() => abortMut.mutate()} disabled={abortMut.isPending} className="f-btn f-btn-danger" style={{ fontSize: 11, padding: "5px 10px" }}>
              <StopCircle className="w-[11px] h-[11px]" /> {abortMut.isPending ? "Aborting..." : "Abort"}
            </button>
          )}
          {chain.status !== "running" && (
            <button
              onClick={() => { if (window.confirm("Delete this engagement? This cannot be undone.")) deleteMut.mutate(); }}
              disabled={deleteMut.isPending}
              className="f-btn f-btn-ghost"
              style={{ fontSize: 11, padding: "5px 10px", color: "var(--red)" }}
              title="Delete engagement"
            >
              <Trash2 className="w-[11px] h-[11px]" /> {deleteMut.isPending ? "Deleting..." : "Delete"}
            </button>
          )}
        </div>
      </div>

      {/* Phase bar */}
      <div className="flex flex-shrink-0" style={{ borderBottom: "1px solid var(--border)" }}>
        {PHASE_ORDER.map((phase, i) => {
          const pr = (chain.phaseResults || []).find((p: any) => p.phaseName === phase);
          const isCurrent = currentPhaseIdx === i;
          const isDone = pr?.status === "completed";
          const hasBreach = (pr?.findings || []).some((f: any) => f.severity === "critical");
          const col = isCurrent ? "var(--amber)" : isDone && hasBreach ? "var(--red)" : isDone ? "var(--green)" : "var(--t4)";
          return (
            <div key={phase} className="flex-1 text-center font-mono cursor-default transition-all"
              style={{ padding: "6px 4px", fontSize: 9, letterSpacing: ".08em", borderRight: i < 5 ? "1px solid var(--border)" : "none", color: col, background: isCurrent ? "rgba(245,158,11,.04)" : undefined }}>
              <div style={{ fontSize: 8, opacity: .6, marginBottom: 2 }}>0{i + 1}</div>
              {PHASE_LABELS[phase]}
            </div>
          );
        })}
      </div>

      {/* Body: feed + map */}
      <div className="flex flex-1 min-h-0 overflow-hidden">
        {/* Feed */}
        <div className="flex flex-col flex-shrink-0" style={{ width: 300, borderRight: "1px solid var(--border)" }}>
          <div className="flex items-center justify-between px-3 py-[6px] flex-shrink-0" style={{ borderBottom: "1px solid var(--border)", background: "var(--panel2)" }}>
            <span className="font-mono text-[9px] tracking-[.1em] uppercase" style={{ color: "var(--t3)" }}>live action feed</span>
            {chain.status === "running" && (
              <span className="font-mono text-[8px] px-[6px] py-[1px]" style={{ color: "var(--amber)", border: "1px solid var(--amber-border)", background: "var(--amber-dim)" }}>
                phase {currentPhaseIdx + 1}
              </span>
            )}
          </div>
          <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-[2px]" style={{ background: "var(--bg)" }}>
            {feedRows.map((r, i) => (
              <FeedRow key={i} ts={r.ts} agent={r.agent} agCls="" msg={r.msg} msgCls={r.cls} />
            ))}
            {chain.status === "running" && (
              <div className="flex gap-[6px] font-mono text-[9px] mt-1">
                <span style={{ color: "var(--t4)", minWidth: 36, fontSize: 8 }}></span>
                <span className="inline-block w-[6px] h-[10px] align-middle" style={{ background: "var(--t3)", animation: "f-blink .8s step-end infinite" }} />
              </div>
            )}
          </div>
        </div>

        {/* Network map */}
        <NetworkMap chain={chain} graph={latestGraph} nodes={nodes} edges={edges} />
      </div>
    </div>
  );
}

// ── Chains List View ──────────────────────────────────────────────────────────

function ChainsListView({ chains, onSelect, onCreate }: {
  chains: BreachChain[];
  onSelect: (c: BreachChain) => void;
  onCreate: () => void;
}) {
  const { toast } = useToast();
  const deleteChainMut = useMutation({
    mutationFn: (chainId: string) => apiRequest("DELETE", `/api/breach-chains/${chainId}`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] }); toast({ title: "Engagement deleted" }); },
    onError: (e: Error) => toast({ title: "Delete failed", description: e.message, variant: "destructive" }),
  });
  const totalCrit = chains.reduce((s, c) =>
    s + (c.phaseResults || []).flatMap((p: any) => p.findings || []).filter((f: any) => f.severity === "critical").length, 0);
  const running   = chains.filter(c => c.status === "running").length;
  const completed = chains.filter(c => c.status === "completed").length;
  const breached  = chains.filter(c => (c.phaseResults || []).some((p: any) => (p.findings || []).some((f: any) => f.severity === "critical"))).length;

  const chipCls = (s: string) => {
    if (s === "running") return "f-chip f-chip-ok";
    if (s === "completed") return "f-chip f-chip-gray";
    if (s === "failed") return "f-chip f-chip-crit";
    if (s === "paused") return "f-chip f-chip-high";
    return "f-chip f-chip-gray";
  };

  const critCount = (c: BreachChain) =>
    (c.phaseResults || []).flatMap((p: any) => p.findings || []).filter((f: any) => f.severity === "critical").length;

  return (
    <div className="flex flex-col gap-4">
      {/* KPI row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
        {[
          { dot: "b", val: String(running),   lbl: "Active Ops",       cls: running > 0 ? "b" : "" },
          { dot: "r", val: String(totalCrit), lbl: "Critical Findings", cls: totalCrit > 0 ? "r" : "" },
          { dot: "o", val: String(chains.reduce((s, c) => s + (c.totalCredentialsHarvested ?? 0), 0)), lbl: "Credentials", cls: "o" },
          { dot: "g", val: String(completed), lbl: "Completed",        cls: "g" },
          { dot: "r", val: breached > 0 ? "F" : "—", lbl: "Risk Grade",cls: breached > 0 ? "r" : "" },
        ].map(({ dot, val, lbl, cls }) => (
          <div key={lbl} className={`f-kpi ${breached > 0 && lbl === "Risk Grade" ? "hot" : ""}`}>
            <div className="f-kpi-lbl"><span className={`f-kpi-dot ${dot}`} />{lbl}</div>
            <div className={`f-kpi-val ${cls}`}>{val}</div>
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="f-panel">
        <div className="f-panel-head">
          <span className="f-panel-title"><span className="f-panel-dot" />Engagements</span>
          <button onClick={onCreate} className="f-btn f-btn-primary" style={{ fontSize: 11, padding: "5px 12px" }}>
            <Plus className="w-[11px] h-[11px]" /> New Engagement
          </button>
        </div>
        <div className="f-tbl">
          <div className="f-tbl-head" style={{ gridTemplateColumns: "2fr 1.2fr 1fr 1fr 1fr 100px" }}>
            {["target / chain id", "status", "phase", "findings", "grade", "actions"].map(h => (
              <div key={h} className="f-th" style={h === "actions" ? { textAlign: "right" } : {}}>{h}</div>
            ))}
          </div>
          <div className="f-tbl-body">
            {chains.length === 0 && (
              <div className="f-table-empty font-mono text-[11px]" style={{ padding: "40px 16px", textAlign: "center", color: "var(--t4)" }}>
                no engagements yet — start your first breach chain
              </div>
            )}
            {chains.map(chain => {
              const crit = critCount(chain);
              const high = (chain.phaseResults || []).flatMap((p: any) => p.findings || []).filter((f: any) => f.severity === "high").length;
              const phIdx = PHASE_ORDER.indexOf(chain.currentPhase ?? "");
              return (
                <div key={chain.id} className="f-tbl-row" style={{ gridTemplateColumns: "2fr 1.2fr 1fr 1fr 1fr 100px" }} onClick={() => onSelect(chain)}>
                  <div>
                    <div className="f-td n">{(chain as any).targetUrl ?? chain.targetDomains?.[0] ?? chain.name}</div>
                    <div className="f-td sub">{chain.id?.slice(0, 16)} · {(chain as any).profile ?? chain.config?.adversaryProfile ?? "full-chain"} · {chain.config?.executionMode ?? "live"}</div>
                  </div>
                  <div className="f-td"><span className={chipCls(chain.status)}>{chain.status}</span></div>
                  <div className="f-td m" style={{ color: chain.status === "running" ? "var(--amber)" : "var(--t3)" }}>
                    {phIdx >= 0 ? `${phIdx + 1} · ${PHASE_LABELS[chain.currentPhase ?? ""] ?? "—"}` : "—"}
                  </div>
                  <div className="f-td m">
                    <span style={{ color: crit > 0 ? "var(--red)" : "var(--t2)" }}>{crit} crit</span>
                    {high > 0 && <span style={{ color: "var(--t2)" }}> / {high} high</span>}
                  </div>
                  <div className="f-td m font-bold" style={{ color: crit > 0 ? "var(--red)" : "var(--t3)" }}>
                    {chain.overallRiskScore ?? "—"}
                  </div>
                  <div className="f-td flex gap-[5px] justify-end" onClick={e => e.stopPropagation()}>
                    <button onClick={() => onSelect(chain)} title="View" className="f-icon-btn"
                      style={{ width: 26, height: 26, display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid var(--border2)", background: "transparent", cursor: "pointer" }}>
                      <Eye className="w-[11px] h-[11px]" style={{ stroke: "var(--t3)" }} />
                    </button>
                    {chain.status === "completed" && (
                      <button title="Download Technical Report" className="f-icon-btn"
                        onClick={() => {
                          const token = localStorage.getItem("odinforge_access_token");
                          const url = `/api/breach-chains/${chain.id}/report/technical-pdf`;
                          fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
                            .then(r => { if (!r.ok) throw new Error(`${r.status}`); return r.blob(); })
                            .then(blob => {
                              const a = document.createElement("a");
                              a.href = URL.createObjectURL(blob);
                              a.download = `breach-chain-${chain.id.slice(0, 8)}-technical.pdf`;
                              a.click();
                              URL.revokeObjectURL(a.href);
                            })
                            .catch(() => {/* silent — toast would need hook context */});
                        }}
                        style={{ width: 26, height: 26, display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid var(--border2)", background: "transparent", cursor: "pointer" }}>
                        <Download className="w-[11px] h-[11px]" style={{ stroke: "var(--t3)" }} />
                      </button>
                    )}
                    {chain.status !== "running" && (
                      <button
                        onClick={() => { if (window.confirm("Delete this engagement? This cannot be undone.")) deleteChainMut.mutate(chain.id); }}
                        title="Delete"
                        className="f-icon-btn"
                        style={{ width: 26, height: 26, display: "flex", alignItems: "center", justifyContent: "center", border: "1px solid var(--border2)", background: "transparent", cursor: "pointer" }}>
                        <Trash2 className="w-[11px] h-[11px]" style={{ stroke: "var(--red)" }} />
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── New Engagement Modal ──────────────────────────────────────────────────────

function NewEngagementModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const { toast } = useToast();
  const [targetUrl, setTargetUrl] = useState("");
  const [profile, setProfile]     = useState("full_chain");
  const [mode, setMode]           = useState("live");

  const createMut = useMutation({
    mutationFn: () => apiRequest("POST", "/api/breach-chains", {
      name: new URL(targetUrl).hostname,
      assetIds: [targetUrl],
      targetDomains: ["application"],
      config: {
        executionMode: mode,
        enabledPhases: profile === "full_chain"
          ? ["application_compromise", "credential_extraction", "cloud_iam_escalation", "container_k8s_breakout"]
          : ["application_compromise", "credential_extraction", "cloud_iam_escalation", "container_k8s_breakout", "lateral_movement", "impact_assessment"],
      },
    }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] }); toast({ title: "Engagement started" }); onSuccess(); onClose(); },
    onError: (e: any) => toast({ title: "Failed", description: e.message, variant: "destructive" }),
  });

  const ProfileOpt = ({ val, label, sub, color }: { val: string; label: string; sub: string; color: string }) => (
    <div onClick={() => setProfile(val)} className="cursor-pointer text-center p-[10px] transition-all"
      style={{ border: `1px solid ${profile === val ? "var(--red-border)" : "var(--border2)"}`, background: profile === val ? "var(--red-dim)" : "transparent" }}>
      <div className="font-mono text-[10px] font-bold" style={{ color: profile === val ? "var(--red)" : "var(--t2)" }}>{label}</div>
      <div className="font-mono text-[8px] mt-[3px]" style={{ color: "var(--t3)" }}>{sub}</div>
    </div>
  );

  const ModeOpt = ({ val, label, sub, color }: { val: string; label: string; sub: string; color: string }) => (
    <div onClick={() => setMode(val)} className="cursor-pointer text-center p-[10px] transition-all"
      style={{ border: `1px solid ${mode === val ? "var(--red-border)" : "var(--border2)"}`, background: mode === val ? "var(--red-dim)" : "transparent" }}>
      <div className="font-mono text-[10px] font-bold" style={{ color: mode === val ? color : "var(--t2)" }}>{label}</div>
      <div className="font-mono text-[8px] mt-[3px]" style={{ color: "var(--t3)" }}>{sub}</div>
    </div>
  );

  return (
    <div className="f-modal-overlay" onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="f-modal" style={{ maxWidth: 480 }}>
        <div className="f-modal-head">
          <div className="f-modal-title">New Engagement</div>
          <div className="f-modal-desc">Configure breach chain parameters</div>
        </div>
        <div className="f-modal-body flex flex-col gap-4">
          <div>
            <div className="font-mono text-[9px] tracking-[.12em] uppercase mb-[6px]" style={{ color: "var(--t3)" }}>Target URL</div>
            <input value={targetUrl} onChange={e => setTargetUrl(e.target.value)}
              className="w-full font-mono text-[12px] px-[11px] py-[9px] outline-none transition-colors"
              style={{ background: "var(--bg)", border: "1px solid var(--border2)", color: "var(--t1)" }}
              placeholder="https://target.example.com"
              onFocus={e => { (e.currentTarget as HTMLElement).style.borderColor = "var(--red)"; }}
              onBlur={e => { (e.currentTarget as HTMLElement).style.borderColor = "var(--border2)"; }} />
          </div>
          <div>
            <div className="font-mono text-[9px] tracking-[.12em] uppercase mb-[8px]" style={{ color: "var(--t3)" }}>Profile</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
              <ProfileOpt val="full_chain" label="Standard" sub="Phases 1–4" color="var(--red)" />
              <ProfileOpt val="deep"       label="Deep"     sub="All 6 phases" color="var(--red)" />
              <ProfileOpt val="mssp"       label="MSSP"     sub="White-label" color="var(--red)" />
            </div>
          </div>
          <div>
            <div className="font-mono text-[9px] tracking-[.12em] uppercase mb-[8px]" style={{ color: "var(--t3)" }}>Execution Mode</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
              <ModeOpt val="safe"       label="Safe"       sub="Passive only"   color="var(--green)" />
              <ModeOpt val="simulation" label="Simulation" sub="Safe payloads"  color="var(--amber)" />
              <ModeOpt val="live"       label="Live"       sub="Real exploits"  color="var(--red)"   />
            </div>
          </div>
        </div>
        <div className="f-modal-footer">
          <button onClick={onClose} className="f-btn f-btn-ghost">Cancel</button>
          <button onClick={() => createMut.mutate()} disabled={!targetUrl || createMut.isPending} className="f-btn f-btn-primary">
            <Play className="w-[11px] h-[11px]" />
            {createMut.isPending ? "Starting..." : "Start Engagement"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Root ──────────────────────────────────────────────────────────────────────

export default function BreachChains() {
  const { data: chains = [], isLoading } = useQuery<BreachChain[]>({
    queryKey: ["/api/breach-chains"],
    refetchInterval: (query) => {
      const data = query.state.data as BreachChain[] | undefined;
      return data?.some(c => c.status === "running") ? 5000 : 30000;
    },
  });
  const [selectedChain, setSelectedChain] = useState<BreachChain | null>(null);
  const [showNewModal, setShowNewModal]   = useState(false);

  // No auto-select — let the user choose which chain to view

  if (isLoading) return (
    <div className="flex items-center justify-center h-full">
      <div className="text-center">
        <div className="h-5 w-5 border-2 border-t-transparent rounded-full animate-spin mx-auto mb-3"
          style={{ borderColor: "var(--red)", borderTopColor: "transparent" }} />
        <p className="font-mono text-[9px] tracking-widest" style={{ color: "var(--t4)" }}>LOADING</p>
      </div>
    </div>
  );

  // Sync selected chain with latest data
  const activeChain = selectedChain ? chains.find(c => c.id === selectedChain.id) ?? selectedChain : null;

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0, height: "100%" }}>
      {activeChain ? (
        <ChainDetailView chain={activeChain} onBack={() => setSelectedChain(null)} />
      ) : (
        <ChainsListView chains={chains} onSelect={setSelectedChain} onCreate={() => setShowNewModal(true)} />
      )}
      {showNewModal && <NewEngagementModal onClose={() => setShowNewModal(false)} onSuccess={() => {}} />}
    </div>
  );
}
