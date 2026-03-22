import { memo, useMemo } from "react";
import { useLocation } from "wouter";

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
  return `${Math.floor(hrs / 24)}d ago`;
}

function chipClass(sev: string) {
  if (sev === "critical") return "f-chip f-chip-crit";
  if (sev === "high") return "f-chip f-chip-high";
  if (sev === "medium") return "f-chip f-chip-med";
  return "f-chip f-chip-low";
}

function statusDotClass(status: string) {
  if (status === "in_progress") return "f-s-dot f-sd-live";
  if (status === "pending") return "f-s-dot f-sd-queue";
  if (status === "failed") return "f-s-dot f-sd-err";
  return "f-s-dot f-sd-done";
}

function statusTextClass(status: string) {
  if (status === "in_progress") return "f-st-live";
  if (status === "pending") return "f-st-queue";
  if (status === "failed") return "f-st-err";
  return "f-st-done";
}

function statusLabel(status: string) {
  if (status === "in_progress") return "LIVE";
  if (status === "pending") return "QUEUED";
  return status.toUpperCase();
}

const GRID_COLS = "1.8fr 90px 110px 70px 90px";

export const RecentEvaluations = memo(function RecentEvaluations({
  evaluations = [],
}: {
  evaluations: Evaluation[];
}) {
  const [, navigate] = useLocation();

  const recent = useMemo(
    () =>
      [...evaluations]
        .sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime())
        .slice(0, 10),
    [evaluations],
  );

  return (
    <div className="f-panel" style={{ flex: 1, minHeight: 0 }}>
      {/* Panel header */}
      <div className="f-panel-head">
        <div className="f-panel-title">
          <span className="f-panel-dot" />
          Recent Evaluations
        </div>
        <span
          className="f-panel-link"
          onClick={() => navigate("/full-assessment")}
        >
          View all →
        </span>
      </div>

      {/* Table */}
      <div className="f-tbl" style={{ flex: 1 }}>
        {/* Header row */}
        <div className="f-tbl-head" style={{ gridTemplateColumns: GRID_COLS }}>
          <span className="f-th">Target</span>
          <span className="f-th">Severity</span>
          <span className="f-th">Phase</span>
          <span className="f-th">Findings</span>
          <span className="f-th">Status</span>
        </div>

        {/* Body */}
        <div className="f-tbl-body">
          {recent.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10">
              <span className="text-[11px]" style={{ color: "var(--falcon-t4)" }}>No evaluations yet</span>
              <span className="text-[10px] mt-1" style={{ color: "var(--falcon-t4)" }}>Run an assessment to see results</span>
            </div>
          ) : (
            recent.map((e) => {
              const sev = (e.priority || e.severity || "medium").toLowerCase();
              const exposureLabel = (e.exposureType || "assessment")
                .replace(/_/g, " ")
                .replace(/\b\w/g, (c) => c.toUpperCase());

              return (
                <div
                  key={e.id}
                  className="f-tbl-row"
                  style={{ gridTemplateColumns: GRID_COLS }}
                >
                  {/* Target */}
                  <div>
                    <div className="f-td n">{exposureLabel}</div>
                    {e.assetId && (
                      <div className="f-td sub">{e.assetId.slice(0, 16)}</div>
                    )}
                  </div>

                  {/* Severity chip */}
                  <div>
                    <span className={chipClass(sev)}>{sev.toUpperCase()}</span>
                  </div>

                  {/* Phase */}
                  <div className="f-td">
                    {e.status === "in_progress" ? "Exploitation" :
                     e.status === "pending" ? "Queued" :
                     e.status === "completed" ? "Complete" : "Reporting"}
                  </div>

                  {/* Findings count */}
                  <div className="f-td m" style={{
                    color: e.exploitable ? "var(--falcon-red)" :
                           sev === "critical" ? "var(--falcon-red)" :
                           sev === "high" ? "var(--falcon-orange)" : undefined
                  }}>
                    {e.exploitable ? "YES" : "—"}
                  </div>

                  {/* Status */}
                  <div>
                    <span className="f-status">
                      <span className={statusDotClass(e.status)} />
                      <span className={statusTextClass(e.status)}>
                        {statusLabel(e.status)}
                      </span>
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
});
