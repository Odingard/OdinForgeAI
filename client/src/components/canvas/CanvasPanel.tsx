import { useMemo } from "react";
import { LiveAttackCanvas } from "./LiveAttackCanvas";
import { CanvasLegend } from "./CanvasLegend";
import { ReasoningStream } from "../reasoning/ReasoningStream";

// ── Types ────────────────────────────────────────────────────────────────────

interface CanvasPanelProps {
  chainId: string;
  canvasEvents: any[];
  reasoningStream: any[];
  operatorSummary: any;
  /** Pass chain data so we can render completed chains, not just live ones */
  chain?: any;
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

  // Build canvas nodes from attack graph
  if (graph?.nodes) {
    for (const node of graph.nodes) {
      canvasEvents.push({
        canvasType: 'node_discovered',
        source: node.label || node.id,
        zone: node.tactic || 'unknown',
        sensitivity: 'generic',
        confirmed: true,
        timestamp: ts,
      });
      canvasEvents.push({
        canvasType: 'node_classified',
        source: node.label || node.id,
        zone: node.tactic || 'unknown',
        detail: node.description,
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
      message: `Phase ${phaseName}: ${status} — ${findingCount} findings`,
      timestamp: phase.completedAt || ts,
    });

    // Add each finding as a validate event
    for (const finding of (phase.findings || [])) {
      reasoningStream.push({
        reasoningIntent: 'validate',
        target: finding.technique || phaseName,
        message: `${finding.severity?.toUpperCase()}: ${finding.title || finding.description?.slice(0, 80)}`,
        timestamp: phase.completedAt || ts,
      });
    }
  }

  // Add executive summary as final reasoning
  if (chain.executiveSummary) {
    reasoningStream.push({
      reasoningIntent: 'summarize',
      target: '',
      message: chain.executiveSummary,
      timestamp: chain.completedAt || ts,
    });
  }

  // Build operator summary from chain data
  const totalFindings = phaseResults.reduce((s: number, p: any) => s + (p.findings?.length || 0), 0);
  const operatorSummary = {
    currentObjective: chain.status === 'completed' ? 'Assessment complete' : chain.status === 'failed' ? 'Assessment failed' : 'Running',
    currentPrimaryPath: chain.executiveSummary?.slice(0, 80) || null,
    findingsCount: totalFindings,
    pathsCount: graph?.nodes?.length || 0,
    replaySuccesses: 0,
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
  // If we have live events, use them. Otherwise synthesize from stored chain data.
  const hasLiveData = liveCanvasEvents.length > 0 || liveReasoningStream.length > 0;

  const synthesized = useMemo(
    () => (!hasLiveData && chain ? synthesizeFromChain(chain) : null),
    [hasLiveData, chain]
  );

  const canvasEvents = hasLiveData ? liveCanvasEvents : (synthesized?.canvasEvents || []);
  const reasoningStream = hasLiveData ? liveReasoningStream : (synthesized?.reasoningStream || []);
  const operatorSummary = liveOperatorSummary || synthesized?.operatorSummary || null;
  return (
    <div className="flex flex-col h-full gap-2">
      {/* Top row: Canvas + Operator Panel */}
      <div className="flex flex-1 min-h-0 gap-2">
        {/* Attack Canvas */}
        <div className="flex-1 min-w-0 flex flex-col gap-1">
          <LiveAttackCanvas
            canvasEvents={canvasEvents}
            reasoningStream={reasoningStream}
            operatorSummary={operatorSummary}
            chainId={chainId}
          />
          <CanvasLegend />
        </div>

        {/* Operator Panel */}
        <div className="w-72 shrink-0 bg-[hsl(var(--card))] rounded-lg border border-[hsl(var(--border))] p-4 overflow-y-auto">
          <h3 className="text-sm font-semibold text-[hsl(var(--foreground))] mb-3 uppercase tracking-wider">
            Operator
          </h3>

          <OperatorField
            label="Objective"
            value={operatorSummary?.currentObjective}
          />
          <OperatorField
            label="Primary Path"
            value={operatorSummary?.currentPrimaryPath}
            fallback="None"
          />
          <OperatorField
            label="Findings"
            value={operatorSummary?.findingsCount?.toString()}
            fallback="0"
          />
          <OperatorField
            label="Paths"
            value={operatorSummary?.pathsCount?.toString()}
            fallback="0"
          />
          <OperatorField
            label="Replay Successes"
            value={operatorSummary?.replaySuccesses?.toString()}
            fallback="0"
          />
          <OperatorField
            label="Last Change"
            value={operatorSummary?.lastMeaningfulChange}
          />
          <OperatorField
            label="Active Artifact"
            value={operatorSummary?.activeArtifact}
            fallback="None"
          />
        </div>
      </div>

      {/* Bottom row: Reasoning Stream */}
      <div className="h-48 shrink-0">
        <ReasoningStream events={reasoningStream} />
      </div>
    </div>
  );
}

// ── Operator Field ───────────────────────────────────────────────────────────

function OperatorField({
  label,
  value,
  fallback = "...",
}: {
  label: string;
  value?: string | null;
  fallback?: string;
}) {
  return (
    <div className="mb-2.5">
      <div className="text-[10px] uppercase tracking-wider text-gray-500 mb-0.5">
        {label}
      </div>
      <div className="text-xs text-gray-300 break-words">
        {value || fallback}
      </div>
    </div>
  );
}
