import { memo } from "react";

interface Evaluation {
  status: string;
  exploitable?: boolean;
}

export const FindingsMetricCards = memo(function FindingsMetricCards({ evaluations = [] }: { evaluations: Evaluation[] }) {
  const total = evaluations.length;
  const resolved = evaluations.filter((e) => e.status === "completed").length;
  const exploitable = evaluations.filter((e) => e.exploitable === true).length;

  return (
    <div className="rounded-lg border border-border bg-card/50 backdrop-blur-sm p-4">
      <div className="flex items-center gap-2 mb-3">
        <span className="inline-block h-2 w-2 rounded-full bg-cyan-400" style={{ boxShadow: "0 0 6px #38bdf8" }} />
        <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
          Evaluation Metrics
        </span>
      </div>
      <div className="space-y-2.5">
        <MetricRow label="Total Findings" value={total} colorClass="text-cyan-400 border-cyan-500/40" />
        <MetricRow label="Resolved" value={resolved} colorClass="text-emerald-400 border-emerald-500/40" />
        <MetricRow label="Exploitable" value={exploitable} colorClass="text-red-400 border-red-500/40" />
      </div>
    </div>
  );
});

function MetricRow({ label, value, colorClass }: { label: string; value: number; colorClass: string }) {
  const [textColor, borderColor] = colorClass.split(" ");
  return (
    <div className={`flex items-center justify-between py-2.5 px-3 rounded-md bg-background/40 border-l-2 ${borderColor}`}>
      <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      <span className={`text-base font-bold tabular-nums ${textColor}`}>
        {value}
      </span>
    </div>
  );
}
