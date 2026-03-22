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

  // Map attack graph tactics to breach phases for layout
  const tacticToPhase: Record<string, string> = {
    'reconnaissance': 'application_compromise',
    'resource-development': 'application_compromise',
    'initial-access': 'application_compromise',
    'execution': 'application_compromise',
    'persistence': 'credential_extraction',
    'privilege-escalation': 'cloud_iam_escalation',
    'defense-evasion': 'application_compromise',
    'credential-access': 'credential_extraction',
    'discovery': 'application_compromise',
    'lateral-movement': 'lateral_movement',
    'collection': 'lateral_movement',
    'command-and-control': 'container_k8s_breakout',
    'exfiltration': 'impact_assessment',
    'impact': 'impact_assessment',
  };

  // Build canvas nodes from attack graph
  if (graph?.nodes) {
    for (const node of graph.nodes) {
      const phase = tacticToPhase[node.tactic] || (
        node.nodeType === 'objective' ? 'impact_assessment'
          : node.nodeType === 'entry' ? 'application_compromise'
            : 'credential_extraction'
      );
      const severity = node.tactic?.includes('credential') || node.tactic?.includes('privilege')
        ? 'critical'
        : node.nodeType === 'objective' ? 'critical' : 'high';

      canvasEvents.push({
        canvasType: 'node_discovered',
        source: node.label || node.id,
        phase,
        severity,
        label: node.label || node.id,
        detail: node.description,
        kind: node.nodeType === 'entry' ? 'phase_spine' : 'finding',
        technique: node.technique,
        confirmed: true,
        timestamp: ts,
      });
    }
  }

  // Build canvas edges from attack graph
  if (graph?.edges) {
    for (const edge of graph.edges) {
      canvasEvents.push({
        canvasType: 'edge_confirmed',
        source: edge.source,
        target: edge.target,
        detail: edge.technique || edge.description,
        confirmed: true,
        timestamp: ts,
      });
    }
  }

  // Build reasoning from phase results
  for (const phase of phaseResults) {
    const phaseName = phase.phaseName || 'unknown';
    const findingCount = (phase.findings || []).length;
    const status = phase.status || 'unknown';

    reasoningStream.push({
      reasoningIntent: 'summarize',
      target: '',
      message: `Phase ${phaseName}: ${status} \u2014 ${findingCount} findings`,
      timestamp: phase.completedAt || ts,
    });

    for (const finding of (phase.findings || [])) {
      reasoningStream.push({
        reasoningIntent: 'validate',
        target: finding.technique || phaseName,
        message: `${finding.severity?.toUpperCase()}: ${finding.title || finding.description?.slice(0, 80)}`,
        timestamp: phase.completedAt || ts,
      });
    }
  }

  if (chain.executiveSummary) {
    reasoningStream.push({
      reasoningIntent: 'summarize',
      target: '',
      message: chain.executiveSummary,
      timestamp: chain.completedAt || ts,
    });
  }

  // Build operator summary
  const totalFindings = phaseResults.reduce((s: number, p: any) => s + (p.findings?.length || 0), 0);
  const operatorSummary = {
    currentObjective: chain.status === 'completed' ? 'Assessment complete' : chain.status === 'failed' ? 'Assessment failed' : 'Running',
    currentPrimaryPath: chain.executiveSummary?.slice(0, 80) || null,
    findingsCount: totalFindings,
    pathsCount: graph?.nodes?.length || 0,
    replaySuccesses: 0,
    credentialCount: chain.totalCredentialsHarvested || 0,
    riskGrade: chain.riskGrade || null,
    status: chain.status,
    targetUrl: chain.targetUrl || null,
    durationMs: chain.durationMs || null,
    lastMeaningfulChange: chain.status === 'completed'
      ? `Completed in ${chain.durationMs ? Math.round(chain.durationMs / 1000) + 's' : 'unknown'}`
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
