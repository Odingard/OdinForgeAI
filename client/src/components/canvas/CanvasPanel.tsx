import { LiveAttackCanvas } from "./LiveAttackCanvas";
import { CanvasLegend } from "./CanvasLegend";
import { ReasoningStream } from "../reasoning/ReasoningStream";

// ── Types ────────────────────────────────────────────────────────────────────

interface CanvasPanelProps {
  chainId: string;
  canvasEvents: any[];
  reasoningStream: any[];
  operatorSummary: any;
}

// ── Component ────────────────────────────────────────────────────────────────

export function CanvasPanel({
  chainId,
  canvasEvents,
  reasoningStream,
  operatorSummary,
}: CanvasPanelProps) {
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
