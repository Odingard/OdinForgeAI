import { useQuery } from "@tanstack/react-query";

interface Evaluation {
  status: string;
  exploitable?: boolean;
}

export function FindingsMetricCards() {
  const { data: evaluations = [] } = useQuery<Evaluation[]>({
    queryKey: ["/api/aev/evaluations"],
  });

  const total = evaluations.length;
  const resolved = evaluations.filter((e) => e.status === "completed").length;
  const exploitable = evaluations.filter((e) => e.exploitable === true).length;

  return (
    <div className="glass border border-border/50 rounded-lg p-5">
      <div className="grid grid-cols-3 gap-4">
        <MetricItem label="Findings" value={total} color="text-foreground" />
        <MetricItem label="Resolved" value={resolved} color="text-emerald-400" />
        <MetricItem label="Exploitable" value={exploitable} color="text-red-400" />
      </div>
    </div>
  );
}

function MetricItem({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="text-center">
      <p className={`text-2xl font-bold tabular-nums ${color}`}>{value}</p>
      <p className="text-[10px] uppercase tracking-wider text-muted-foreground/70 mt-1">{label}</p>
    </div>
  );
}
