import { memo, useMemo } from "react";

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

function sevClass(sev: string) {
  if (sev === "critical") return "sev-chip sc-crit";
  if (sev === "high") return "sev-chip sc-high";
  if (sev === "medium") return "sev-chip sc-med";
  return "sev-chip sc-low";
}

function statusDot(status: string) {
  if (status === "in_progress") return "sp-dot sp-live";
  if (status === "pending") return "sp-dot sp-queue";
  return "sp-dot sp-done";
}

function statusText(status: string) {
  if (status === "in_progress") return "spt-live";
  if (status === "pending") return "spt-queue";
  return "spt-done";
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
        .slice(0, 12),
    [evaluations],
  );

  return (
    <div className="falcon-panel flex flex-col min-h-0" style={{ overflow: "hidden" }}>
      {/* Header */}
      <div className="falcon-panel-head flex items-center justify-between">
        <span className="font-mono text-[9px] font-normal tracking-[0.18em] uppercase" style={{ color: "var(--falcon-t3)" }}>
          Recent Evaluations
        </span>
        <span className="font-mono text-[10px]" style={{ color: "var(--falcon-t4)" }}>
          {evaluations.length} total
        </span>
      </div>

      {/* Table head */}
      <div
        className="grid items-center px-4 py-2 flex-shrink-0"
        style={{
          gridTemplateColumns: "1.8fr 88px 130px 68px 90px",
          background: "var(--falcon-bg)",
          borderBottom: "1px solid var(--falcon-border)",
        }}
      >
        {["Exposure", "Severity", "Status", "Exploit", "When"].map((h) => (
          <span
            key={h}
            className="font-mono text-[9px] font-normal tracking-[0.18em] uppercase flex items-center gap-[5px]"
            style={{ color: "var(--falcon-t3)" }}
          >
            {h}
          </span>
        ))}
      </div>

      {/* Table body */}
      <div className="flex-1 overflow-y-auto">
        {recent.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-10">
            <span className="text-[11px]" style={{ color: "var(--falcon-t4)" }}>No evaluations yet</span>
            <span className="text-[10px] mt-1" style={{ color: "var(--falcon-t4)" }}>Run an assessment to see results</span>
          </div>
        ) : (
          recent.map((e) => {
            const sev = (e.priority || e.severity || "medium").toLowerCase();
            return (
              <div
                key={e.id}
                className="grid items-center px-4 py-[10px] cursor-pointer transition-colors"
                style={{
                  gridTemplateColumns: "1.8fr 88px 130px 68px 90px",
                  borderBottom: "1px solid rgba(30,45,69,0.5)",
                }}
                onMouseEnter={(ev) => { (ev.currentTarget as HTMLDivElement).style.background = "var(--falcon-panel-2)"; }}
                onMouseLeave={(ev) => { (ev.currentTarget as HTMLDivElement).style.background = "transparent"; }}
              >
                {/* Exposure type */}
                <div>
                  <div className="text-[12px] font-semibold truncate" style={{ color: "var(--falcon-t1)" }}>
                    {(e.exposureType || "assessment")
                      .replace(/_/g, " ")
                      .replace(/\b\w/g, (c) => c.toUpperCase())}
                  </div>
                  {e.assetId && (
                    <div className="font-mono text-[10px] mt-[2px]" style={{ color: "var(--falcon-t3)" }}>
                      {e.assetId.slice(0, 12)}
                    </div>
                  )}
                </div>

                {/* Severity chip */}
                <div>
                  <span className={sevClass(sev)}>{sev.toUpperCase()}</span>
                </div>

                {/* Status pill */}
                <div className="status-pill">
                  <span className={statusDot(e.status)} />
                  <span className={`font-mono text-[10px] tracking-[0.08em] ${statusText(e.status)}`}>
                    {e.status === "in_progress" ? "RUNNING" : e.status === "pending" ? "QUEUED" : e.status.toUpperCase()}
                  </span>
                </div>

                {/* Exploitable */}
                <div className="font-mono text-[11px]">
                  {e.status === "completed" ? (
                    <span style={{ color: e.exploitable ? "var(--falcon-red)" : "var(--falcon-green)", fontWeight: 500 }}>
                      {e.exploitable ? "YES" : "NO"}
                    </span>
                  ) : (
                    <span style={{ color: "var(--falcon-t4)" }}>—</span>
                  )}
                </div>

                {/* When */}
                <div className="font-mono text-[10px]" style={{ color: "var(--falcon-t3)" }}>
                  {e.createdAt ? timeAgo(e.createdAt) : "—"}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
});
