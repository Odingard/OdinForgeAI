import { memo, useMemo } from "react";
import { Badge } from "@/components/ui/badge";

interface Evaluation {
  id: string;
  assetId?: string;
  exposureType?: string;
  priority?: string;
  severity?: string;
  status: string;
  exploitable?: boolean;
  createdAt?: string;
  description?: string;
}

const SEV_STYLES: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
};

const STATUS_STYLES: Record<string, string> = {
  completed: "text-emerald-400",
  in_progress: "text-cyan-400",
  pending: "text-amber-400",
  failed: "text-red-400",
};

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

export const RecentEvaluations = memo(function RecentEvaluations({
  evaluations = [],
}: {
  evaluations: Evaluation[];
}) {
  const recent = useMemo(
    () =>
      [...evaluations]
        .sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime())
        .slice(0, 8),
    [evaluations],
  );

  return (
    <div className="rounded-lg border border-border bg-card/50 backdrop-blur-sm p-4">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <span className="inline-block h-2 w-2 rounded-full bg-cyan-400" style={{ boxShadow: "0 0 6px #38bdf8" }} />
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Recent Evaluations
          </span>
        </div>
        <span className="text-xs text-muted-foreground">
          {evaluations.length} total
        </span>
      </div>

      {recent.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-10">
          <span className="text-sm text-muted-foreground/40">No evaluations yet</span>
          <span className="text-xs text-muted-foreground/25 mt-1">Run an assessment to see results here</span>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/30">
                {["Type", "Severity", "Status", "Exploitable", "When"].map((h) => (
                  <th
                    key={h}
                    className={`text-[10px] font-semibold uppercase tracking-wider text-primary pb-3 ${h === "Type" ? "text-left" : "text-center"}`}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {recent.map((e) => {
                const sev = (e.priority || e.severity || "medium").toLowerCase();
                return (
                  <tr key={e.id} className="border-t border-border/10 hover:bg-primary/[0.02] transition-colors">
                    <td className="text-xs text-muted-foreground py-2.5 font-medium max-w-[200px] truncate">
                      {(e.exposureType || "assessment")
                        .replace(/_/g, " ")
                        .replace(/\b\w/g, (c) => c.toUpperCase())}
                    </td>
                    <td className="text-center py-2.5">
                      <Badge variant="outline" className={`text-[10px] font-semibold uppercase ${SEV_STYLES[sev] || "bg-muted"}`}>
                        {sev}
                      </Badge>
                    </td>
                    <td className={`text-center py-2.5 text-[10px] font-semibold uppercase tracking-wider ${STATUS_STYLES[e.status] || "text-muted-foreground"}`}>
                      {e.status.replace(/_/g, " ")}
                    </td>
                    <td className="text-center py-2.5">
                      {e.status === "completed" ? (
                        <span className={`text-xs font-bold ${e.exploitable ? "text-red-400" : "text-emerald-400"}`}>
                          {e.exploitable ? "YES" : "NO"}
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground/30">—</span>
                      )}
                    </td>
                    <td className="text-center py-2.5 text-xs text-muted-foreground">
                      {e.createdAt ? timeAgo(e.createdAt) : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
});
