// ── Canvas Legend ─────────────────────────────────────────────────────────────

export function CanvasLegend() {
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-1 px-3 py-1.5 text-[10px] text-gray-400 font-mono">
      {/* Node colors */}
      <LegendDot color="bg-blue-500" label="Entry" />
      <LegendDot color="bg-yellow-500" label="Pivot" />
      <LegendDot color="bg-red-500" label="Target" />

      <span className="text-gray-600">|</span>

      {/* States */}
      <LegendDot color="bg-gray-600" outline="ring-2 ring-orange-500" label="Exploited" />
      <LegendDot color="bg-gray-600" outline="ring-2 ring-green-500" label="Replayed" />
      <LegendDot color="bg-gray-600" outline="ring-2 ring-white" label="Primary" />

      <span className="text-gray-600">|</span>

      {/* Edge types */}
      <LegendEdge dashed label="Inferred" color="bg-gray-500" />
      <LegendEdge dashed={false} label="Validated" color="bg-gray-400" />
      <LegendEdge dashed label="Replay" color="bg-green-500" />
    </div>
  );
}

// ── Sub-components ───────────────────────────────────────────────────────────

function LegendDot({
  color,
  outline,
  label,
}: {
  color: string;
  outline?: string;
  label: string;
}) {
  return (
    <span className="flex items-center gap-1">
      <span className={`inline-block w-2.5 h-2.5 rounded-full ${color} ${outline || ""}`} />
      {label}
    </span>
  );
}

function LegendEdge({
  dashed,
  label,
  color,
}: {
  dashed: boolean;
  label: string;
  color: string;
}) {
  return (
    <span className="flex items-center gap-1">
      <span className="relative inline-block w-4 h-0.5">
        <span
          className={`absolute inset-0 ${color} ${dashed ? "border-t border-dashed border-current" : ""}`}
          style={dashed ? { height: 0 } : undefined}
        />
        {!dashed && <span className={`absolute inset-0 ${color} rounded-full`} />}
      </span>
      {label}
    </span>
  );
}
