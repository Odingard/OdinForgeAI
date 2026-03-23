import { useMemo, useState, useEffect, useRef, useCallback } from "react";
import { LiveAttackCanvas } from "./LiveAttackCanvas";
import { ActionFeed } from "./ActionFeed";
import { EvidencePanel } from "./EvidencePanel";
import type { EvidenceData } from "./EvidencePanel";
import "../../styles/canvas.css";

// ── Types ────────────────────────────────────────────────────────────────────

interface CanvasPanelProps {
  chainId: string;
  canvasEvents: any[];
  reasoningStream: any[];
  operatorSummary: any;
  /** Pass chain data so we can render completed chains, not just live ones */
  chain?: any;
}

// ── Risk grade helper ────────────────────────────────────────────────────────

function gradeColor(grade: string | null | undefined): string {
  if (!grade) return "#334155";
  switch (grade.toUpperCase()) {
    case "A": return "#22c55e";
    case "B": return "#22c55e";
    case "C": return "#f59e0b";
    case "D": return "#f59e0b";
    case "F": return "#ef4444";
    default:  return "#334155";
  }
}

// ── Elapsed timer ────────────────────────────────────────────────────────────

function formatElapsed(seconds: number): string {
  const mm = String(Math.floor(seconds / 60)).padStart(2, "0");
  const ss = String(seconds % 60).padStart(2, "0");
  return `${mm}:${ss}`;
}

// ── Status helpers ───────────────────────────────────────────────────────────

function statusDotClass(status: string | undefined): string {
  if (!status) return "cv-dot";
  if (status === "running" || status === "scanning") return "cv-dot run";
  if (status === "completed" || status === "failed") return "cv-dot done";
  return "cv-dot";
}

function statusLabel(status: string | undefined): string {
  if (!status) return "ready";
  if (status === "running") return "scanning";
  if (status === "completed") return "breach confirmed";
  if (status === "failed") return "assessment failed";
  return status;
}

/**
 * Build a short, readable label for a finding node.
 * Prefers "technique endpoint" format, falls back to title.
 */
function buildFindingLabel(finding: any): string {
  const technique = finding.technique || "";
  const title = finding.title || finding.description || "";

  // Try to extract a short endpoint path from the title (e.g. "/login.jsp")
  const pathMatch = title.match(/\/([\w.\-/]+)/);
  const shortPath = pathMatch ? "/" + pathMatch[1].slice(0, 14) : "";

  if (technique && shortPath) {
    // e.g. "JWT bypass /login.jsp"
    const techShort = technique.length > 12 ? technique.slice(0, 11) + "\u2026" : technique;
    return `${techShort} ${shortPath}`;
  }
  if (technique) return technique;
  if (title.length > 25) return title.slice(0, 24) + "\u2026";
  return title || "finding";
}

/**
 * Synthesize canvas events + reasoning stream + operator summary
 * from a completed chain's stored data. This ensures the canvas
 * shows results even when the chain finished before the user opened it.
 */
function synthesizeFromChain(chain: any): {
  canvasEvents: any[];
  reasoningStream: any[];
  operatorSummary: any;
} {
  if (!chain) return { canvasEvents: [], reasoningStream: [], operatorSummary: null };

  const canvasEvents: any[] = [];
  const reasoningStream: any[] = [];
  const phaseResults = (chain.phaseResults || []) as any[];
  const graph = chain.unifiedAttackGraph;
  const ts = chain.completedAt || chain.startedAt || new Date().toISOString();

  // Track all node IDs we create (for edge building)
  const allNodeIds: string[] = [];
  // Map phase -> list of finding node IDs (for inter-phase edges)
  const phaseNodeIds: Record<string, string[]> = {};

  // ── 1. Create an entry node representing the target ──────────────────────
  const entryNodeId = "entry_target";
  canvasEvents.push({
    canvasType: "node_discovered",
    source: entryNodeId,
    phase: "application_compromise",
    severity: "info",
    label: chain.targetUrl ? new URL(chain.targetUrl).hostname : "target",
    detail: `Entry point: ${chain.targetUrl || "unknown"}`,
    kind: "phase_spine",
    timestamp: ts,
  });
  allNodeIds.push(entryNodeId);

  // ── 2. Build nodes from phaseResults findings (primary source) ───────────
  for (const phase of phaseResults) {
    const phaseName: string = phase.phaseName || "application_compromise";
    const findings = phase.findings || [];
    if (findings.length === 0) continue; // Skip empty phases

    if (!phaseNodeIds[phaseName]) phaseNodeIds[phaseName] = [];

    for (const finding of findings) {
      const nodeId = finding.id || `finding_${allNodeIds.length}`;
      const label = buildFindingLabel(finding);

      canvasEvents.push({
        canvasType: "node_discovered",
        source: nodeId,
        phase: phaseName,
        severity: finding.severity || "medium",
        label,
        detail: finding.description || finding.title || "",
        kind: "finding",
        technique: finding.technique || finding.mitreId || undefined,
        statusCode: finding.statusCode || undefined,
        context: {
          technique: finding.technique || undefined,
          mitre: finding.mitreId || undefined,
          statusCode: finding.statusCode || undefined,
          evidence: finding.responseBody?.slice(0, 300) || undefined,
          severity: finding.severity || "medium",
        },
        confirmed: true,
        timestamp: phase.completedAt || ts,
      });
      allNodeIds.push(nodeId);
      phaseNodeIds[phaseName].push(nodeId);
    }
  }

  // ── 3. Build edges ───────────────────────────────────────────────────────
  // If the attack graph has edges, use them (matching by label/id)
  const graphEdgesUsed = new Set<string>();
  if (graph?.edges) {
    // Build a lookup from graph node labels/ids to our finding node IDs
    const graphNodeToFinding = new Map<string, string>();
    if (graph.nodes) {
      for (const gNode of graph.nodes) {
        // Try to match graph nodes to finding nodes by label overlap
        for (const nodeId of allNodeIds) {
          if (nodeId === gNode.id || nodeId === gNode.label) {
            graphNodeToFinding.set(gNode.id, nodeId);
            break;
          }
        }
      }
    }

    for (const edge of graph.edges) {
      const fromId = graphNodeToFinding.get(edge.source);
      const toId = graphNodeToFinding.get(edge.target);
      if (fromId && toId) {
        const edgeKey = `${fromId}->${toId}`;
        if (!graphEdgesUsed.has(edgeKey)) {
          canvasEvents.push({
            canvasType: "edge_confirmed",
            source: fromId,
            target: toId,
            detail: edge.technique || edge.description,
            confirmed: true,
            timestamp: ts,
          });
          graphEdgesUsed.add(edgeKey);
        }
      }
    }
  }

  // Generate structural edges: entry -> phase 1 findings, phase N -> phase N+1
  const phaseOrder = [
    "application_compromise",
    "credential_extraction",
    "cloud_iam_escalation",
    "container_k8s_breakout",
    "lateral_movement",
    "impact_assessment",
  ];

  // Entry -> first phase findings
  const firstPhaseWithFindings = phaseOrder.find((p) => (phaseNodeIds[p]?.length || 0) > 0);
  if (firstPhaseWithFindings) {
    for (const nodeId of phaseNodeIds[firstPhaseWithFindings]) {
      const edgeKey = `${entryNodeId}->${nodeId}`;
      if (!graphEdgesUsed.has(edgeKey)) {
        canvasEvents.push({
          canvasType: "edge_confirmed",
          source: entryNodeId,
          target: nodeId,
          col: "#6b7280",
          confirmed: true,
          timestamp: ts,
        });
        graphEdgesUsed.add(edgeKey);
      }
    }
  }

  // Inter-phase edges: connect last finding in phase N to each finding in phase N+1
  let prevPhaseNodes: string[] | null = null;
  for (const phaseName of phaseOrder) {
    const currentNodes = phaseNodeIds[phaseName];
    if (!currentNodes || currentNodes.length === 0) continue;

    if (prevPhaseNodes && prevPhaseNodes.length > 0) {
      // Connect the last node of the previous phase to each node in this phase
      const bridgeNode = prevPhaseNodes[prevPhaseNodes.length - 1];
      for (const nodeId of currentNodes) {
        const edgeKey = `${bridgeNode}->${nodeId}`;
        if (!graphEdgesUsed.has(edgeKey)) {
          canvasEvents.push({
            canvasType: "edge_confirmed",
            source: bridgeNode,
            target: nodeId,
            col: "#475569",
            dashed: true,
            confirmed: true,
            timestamp: ts,
          });
          graphEdgesUsed.add(edgeKey);
        }
      }
    }
    prevPhaseNodes = currentNodes;
  }

  // ── 4. Build reasoning from phase results ────────────────────────────────
  for (const phase of phaseResults) {
    const phaseName = phase.phaseName || "unknown";
    const findingCount = (phase.findings || []).length;
    const status = phase.status || "unknown";

    reasoningStream.push({
      reasoningIntent: "summarize",
      target: "",
      message: `Phase ${phaseName}: ${status} \u2014 ${findingCount} findings`,
      timestamp: phase.completedAt || ts,
    });

    for (const finding of phase.findings || []) {
      const technique = finding.technique || finding.exploitChain || undefined;
      const title = finding.title || finding.description?.slice(0, 80) || "";
      const detailParts = [`${finding.severity?.toUpperCase()}: ${title}`];
      if (finding.confidence) detailParts.push(`${Math.round(finding.confidence * 100)}% confidence`);
      if (finding.matchedPatterns?.length) detailParts.push(`${finding.matchedPatterns.length} pattern matches`);

      reasoningStream.push({
        reasoningIntent: "validate",
        target: technique || phaseName,
        message: `${finding.severity?.toUpperCase()}: ${title}`,
        detail: detailParts.join(" \u2014 "),
        technique,
        timestamp: phase.completedAt || ts,
      });
    }
  }

  if (chain.executiveSummary) {
    reasoningStream.push({
      reasoningIntent: "summarize",
      target: "",
      message: chain.executiveSummary,
      timestamp: chain.completedAt || ts,
    });
  }

  // ── 5. Build operator summary ────────────────────────────────────────────
  const totalFindings = phaseResults.reduce((s: number, p: any) => s + (p.findings?.length || 0), 0);
  const operatorSummary = {
    currentObjective: chain.status === "completed" ? "Assessment complete" : chain.status === "failed" ? "Assessment failed" : "Running",
    currentPrimaryPath: chain.executiveSummary?.slice(0, 80) || null,
    findingsCount: totalFindings,
    pathsCount: allNodeIds.length,
    replaySuccesses: 0,
    credentialCount: chain.totalCredentialsHarvested || 0,
    riskGrade: chain.riskGrade || null,
    status: chain.status,
    targetUrl: chain.targetUrl || null,
    durationMs: chain.durationMs || null,
    lastMeaningfulChange: chain.status === "completed"
      ? `Completed in ${chain.durationMs ? Math.round(chain.durationMs / 1000) + "s" : "unknown"}`
      : chain.status,
    activeArtifact: chain.totalCredentialsHarvested ? `${chain.totalCredentialsHarvested} credentials` : null,
  };

  return { canvasEvents, reasoningStream, operatorSummary };
}

// ── Component ────────────────────────────────────────────────────────────────

export function CanvasPanel({
  chainId,
  canvasEvents: liveCanvasEvents,
  reasoningStream: liveReasoningStream,
  operatorSummary: liveOperatorSummary,
  chain,
}: CanvasPanelProps) {
  const hasLiveData = liveCanvasEvents.length > 0 || liveReasoningStream.length > 0;

  const synthesized = useMemo(
    () => (!hasLiveData && chain ? synthesizeFromChain(chain) : null),
    [hasLiveData, chain],
  );

  const canvasEvents = hasLiveData ? liveCanvasEvents : (synthesized?.canvasEvents || []);
  const reasoningStream = hasLiveData ? liveReasoningStream : (synthesized?.reasoningStream || []);
  const operatorSummary = liveOperatorSummary || synthesized?.operatorSummary || null;

  // Evidence panel state
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceData | null>(null);

  const handleNodeClick = useCallback((data: EvidenceData) => {
    setSelectedEvidence(data);
  }, []);

  const handleCloseEvidence = useCallback(() => {
    setSelectedEvidence(null);
  }, []);

  // Elapsed timer
  const [elapsed, setElapsed] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const status = operatorSummary?.status || chain?.status;
    if (status === "running") {
      if (!timerRef.current) {
        timerRef.current = setInterval(() => {
          setElapsed((prev) => prev + 1);
        }, 1000);
      }
    } else {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
      if (operatorSummary?.durationMs || chain?.durationMs) {
        const ms = operatorSummary?.durationMs || chain?.durationMs;
        setElapsed(Math.round(ms / 1000));
      }
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [operatorSummary?.status, operatorSummary?.durationMs, chain?.status, chain?.durationMs]);

  // Stats
  const findingsCount = operatorSummary?.findingsCount ?? 0;
  const credentialCount = operatorSummary?.credentialCount ?? 0;
  const nodeCount = operatorSummary?.pathsCount ?? canvasEvents.filter((e: any) => e.canvasType === "node_discovered").length;
  const grade = operatorSummary?.riskGrade || chain?.riskGrade || null;
  const status = operatorSummary?.status || chain?.status;
  const targetUrl = operatorSummary?.targetUrl || chain?.targetUrl || "\u2014 awaiting target \u2014";

  // Current phase from reasoning
  const currentPhase = operatorSummary?.currentPhase || null;

  return (
    <div className="cv-root" style={{ fontFamily: "monospace", fontSize: "12px" }}>
      {/* ── Top Bar ─────────────────────────────────────────────────────── */}
      <div className="cv-top">
        <span className="cv-brand">OdinForge AEV</span>
        <span className="cv-tgt">{targetUrl}</span>
        <div className="cv-sts">
          <div className="cv-sv">
            <span className="cv-sv-n" style={{ color: "#ef4444" }}>{findingsCount}</span>{" "}findings
          </div>
          <div className="cv-sv">
            <span className="cv-sv-n" style={{ color: "#f59e0b" }}>{credentialCount}</span>{" "}creds
          </div>
          <div className="cv-sv">
            <span className="cv-sv-n">{nodeCount}</span>{" "}nodes
          </div>
          <div className="cv-sv">
            <span className="cv-sv-n">{formatElapsed(elapsed)}</span>
          </div>
          <div className="cv-sv">
            <span className="cv-sv-n" style={{ color: gradeColor(grade) }}>
              {grade || "\u2014"}
            </span>{" "}grade
          </div>
        </div>
        <div className="cv-chip">
          <div className={statusDotClass(status)} />
          <span>{statusLabel(status)}</span>
        </div>
      </div>

      {/* ── Body: Left column + Right evidence panel ────────────────────── */}
      <div className="cv-body">
        <div className="cv-left">
          {/* Action Feed (top ~185px) */}
          <ActionFeed events={reasoningStream} currentPhase={currentPhase} />

          {/* Network Breach Map (fills remaining space) */}
          <LiveAttackCanvas
            canvasEvents={canvasEvents}
            reasoningStream={reasoningStream}
            operatorSummary={operatorSummary}
            chainId={chainId}
            onNodeClick={handleNodeClick}
          />
        </div>

        {/* Evidence Panel (right, 270px, collapsible) */}
        <EvidencePanel data={selectedEvidence} onClose={handleCloseEvidence} />
      </div>
    </div>
  );
}
