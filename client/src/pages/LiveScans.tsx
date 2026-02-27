import { useState, lazy, Suspense } from "react";
import { formatDistanceToNow } from "date-fns";
import { useQuery } from "@tanstack/react-query";

const SessionsPanel = lazy(() => import("@/pages/Sessions"));

interface LiveScan {
  id: string;
  name: string;
  type: "vulnerability" | "compliance" | "reconnaissance" | "penetration";
  status: "running" | "completed" | "failed" | "cancelled";
  progress: number;
  startTime: string;
  endTime?: string;
  targetCount: number;
  findingsCount?: number;
  criticalFindings?: number;
  highFindings?: number;
}

interface ScanFinding {
  id: string;
  scanId: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  target: string;
  cve?: string;
  cvssScore?: number;
  remediation?: string;
  evidence?: string;
}

function statusDot(status: string) {
  if (status === "running") return "f-s-dot f-sd-live";
  if (status === "completed") return "f-s-dot f-sd-done";
  if (status === "failed") return "f-s-dot f-sd-err";
  return "f-s-dot f-sd-queue";
}

function statusText(status: string) {
  if (status === "running") return "f-st-live";
  if (status === "completed") return "f-st-done";
  if (status === "failed") return "f-st-err";
  return "f-st-queue";
}

function sevChip(severity: string) {
  if (severity === "critical") return "f-chip f-chip-crit";
  if (severity === "high") return "f-chip f-chip-high";
  if (severity === "medium") return "f-chip f-chip-med";
  return "f-chip f-chip-low";
}

export default function LiveScans() {
  const [pageTab, setPageTab] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get("tab") || "active-scans";
  });
  const [selectedScan, setSelectedScan] = useState<LiveScan | null>(null);
  const [detailTab, setDetailTab] = useState("findings");

  const { data: scans = [], isLoading } = useQuery<LiveScan[]>({
    queryKey: ["/api/aev/live-scans"],
    refetchInterval: 5000,
  });

  const { data: scanFindings = [] } = useQuery<ScanFinding[]>({
    queryKey: [`/api/aev/live-scans/${selectedScan?.id}/findings`],
    enabled: !!selectedScan,
    refetchInterval: 10000,
  });

  const activeScans = scans.filter(s => s.status === "running").length;
  const completedToday = scans.filter(s =>
    s.status === "completed" &&
    new Date(s.startTime).toDateString() === new Date().toDateString()
  ).length;
  const totalFindings = scans.reduce((sum, s) => sum + (s.findingsCount || 0), 0);
  const criticalFindings = scans.reduce((sum, s) => sum + (s.criticalFindings || 0), 0);
  const activeScansData = scans.filter(s => s.status === "running");

  const GRID_COLS = "1.8fr 100px 90px 1fr 80px 100px 70px";
  const FINDINGS_COLS = "80px 1.5fr 1fr 70px";

  return (
    <div data-testid="text-page-title">
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 18, fontWeight: 700, color: "var(--falcon-t1)", margin: 0 }}>Live Scans</h1>
        <p style={{ fontSize: 11, color: "var(--falcon-t3)", marginTop: 4, fontFamily: "var(--font-mono)" }}>
          // real-time security scan monitoring
        </p>
      </div>

      {/* Tab bar */}
      <div className="f-tab-bar">
        <button className={`f-tab ${pageTab === "active-scans" ? "active" : ""}`} onClick={() => setPageTab("active-scans")}>Active Scans</button>
        <button className={`f-tab ${pageTab === "sessions" ? "active" : ""}`} onClick={() => setPageTab("sessions")}>Sessions</button>
      </div>

      {pageTab === "active-scans" && (
        <>
          {/* KPI strip */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 20 }}>
            <div className="f-kpi">
              <div className="f-kpi-lbl"><span className="f-kpi-dot b" />Active Scans</div>
              <div className="f-kpi-val b">{activeScans}</div>
              <div className="f-kpi-foot">currently running</div>
            </div>
            <div className="f-kpi">
              <div className="f-kpi-lbl"><span className="f-kpi-dot g" />Completed Today</div>
              <div className="f-kpi-val g">{completedToday}</div>
              <div className="f-kpi-foot">finished scans</div>
            </div>
            <div className="f-kpi">
              <div className="f-kpi-lbl"><span className="f-kpi-dot" />Total Findings</div>
              <div className="f-kpi-val">{totalFindings}</div>
              <div className="f-kpi-foot">across all scans</div>
            </div>
            <div className={`f-kpi ${criticalFindings > 0 ? "hot" : ""}`}>
              <div className="f-kpi-lbl"><span className={`f-kpi-dot ${criticalFindings > 0 ? "r" : ""}`} />Critical</div>
              <div className={`f-kpi-val ${criticalFindings > 0 ? "r" : ""}`}>{criticalFindings}</div>
              <div className="f-kpi-foot">
                {criticalFindings > 0 ? <span className="f-kpi-tag r">action needed</span> : "none found"}
              </div>
            </div>
          </div>

          {/* Active scans progress */}
          {activeScansData.length > 0 && (
            <div className="f-panel" style={{ marginBottom: 16 }}>
              <div className="f-panel-head">
                <div className="f-panel-title"><span className="f-panel-dot" style={{ background: "var(--falcon-green)", animation: "f-pulse 2s ease-in-out infinite" }} />Active Scans</div>
              </div>
              <div style={{ padding: "12px 16px" }}>
                {activeScansData.map(scan => (
                  <div key={scan.id} style={{ marginBottom: 12 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>{scan.name}</span>
                        <span className="f-chip f-chip-gray">{scan.type.toUpperCase()}</span>
                      </div>
                      <span style={{ fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--falcon-t2)" }}>{scan.progress}%</span>
                    </div>
                    <div className="f-tb-track" style={{ height: 4 }}>
                      <div className="f-tb-fill f-tf-b" style={{ width: `${scan.progress}%` }} />
                    </div>
                    <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4, fontSize: 10, color: "var(--falcon-t4)" }}>
                      <span>{scan.targetCount} targets</span>
                      <span>Started {formatDistanceToNow(new Date(scan.startTime), { addSuffix: true })}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Scan history table */}
          <div className="f-panel" style={{ flex: 1, minHeight: 0 }}>
            <div className="f-panel-head">
              <div className="f-panel-title"><span className="f-panel-dot b" />Scan History</div>
            </div>
            <div className="f-tbl" style={{ flex: 1 }}>
              <div className="f-tbl-head" style={{ gridTemplateColumns: GRID_COLS }}>
                <span className="f-th">Scan Name</span>
                <span className="f-th">Type</span>
                <span className="f-th">Status</span>
                <span className="f-th">Progress</span>
                <span className="f-th">Findings</span>
                <span className="f-th">Started</span>
                <span className="f-th">Action</span>
              </div>
              <div className="f-tbl-body">
                {isLoading ? (
                  <div style={{ padding: "40px 0", textAlign: "center", fontSize: 11, color: "var(--falcon-t4)" }}>Loading scans...</div>
                ) : scans.length === 0 ? (
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "40px 0" }}>
                    <span style={{ fontSize: 11, color: "var(--falcon-t4)" }}>No scans</span>
                    <span style={{ fontSize: 10, color: "var(--falcon-t4)", marginTop: 4 }}>No security scans have been run yet</span>
                  </div>
                ) : (
                  scans.map(scan => (
                    <div key={scan.id} className="f-tbl-row" style={{ gridTemplateColumns: GRID_COLS }}>
                      <div className="f-td n">{scan.name}</div>
                      <div><span className="f-chip f-chip-gray">{scan.type.toUpperCase()}</span></div>
                      <div>
                        <span className="f-status">
                          <span className={statusDot(scan.status)} />
                          <span className={statusText(scan.status)}>{scan.status.toUpperCase()}</span>
                        </span>
                      </div>
                      <div>
                        {scan.status === "running" ? (
                          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                            <div className="f-tb-track">
                              <div className="f-tb-fill f-tf-b" style={{ width: `${scan.progress}%` }} />
                            </div>
                            <span className="f-td m" style={{ width: 28 }}>{scan.progress}%</span>
                          </div>
                        ) : (
                          <span className="f-td m">{scan.status === "completed" ? "100%" : "—"}</span>
                        )}
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                        <span className="f-td m">{scan.findingsCount ?? "—"}</span>
                        {(scan.criticalFindings || 0) > 0 && (
                          <span className="f-chip f-chip-crit" style={{ fontSize: 9 }}>{scan.criticalFindings} crit</span>
                        )}
                      </div>
                      <div className="f-td" style={{ fontSize: 11 }}>
                        {formatDistanceToNow(new Date(scan.startTime), { addSuffix: true })}
                      </div>
                      <div>
                        <button className="f-btn f-btn-ghost" style={{ fontSize: 10, padding: "2px 8px" }}
                          onClick={() => setSelectedScan(scan)}>View</button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </>
      )}

      {pageTab === "sessions" && (
        <Suspense fallback={<div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 256, color: "var(--falcon-t4)", fontSize: 12 }}>Loading sessions...</div>}>
          <SessionsPanel />
        </Suspense>
      )}

      {/* Scan detail modal */}
      {selectedScan && (
        <div className="f-modal-overlay" onClick={() => setSelectedScan(null)}>
          <div className="f-modal f-modal-xl" onClick={e => e.stopPropagation()}>
            <div className="f-modal-head">
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <h2 className="f-modal-title">{selectedScan.name}</h2>
                  <div className="f-modal-desc">
                    <span className="f-chip f-chip-gray">{selectedScan.type?.toUpperCase()}</span>
                  </div>
                </div>
                <button className="f-btn f-btn-ghost" style={{ padding: "4px 8px" }} onClick={() => setSelectedScan(null)}>✕</button>
              </div>
            </div>

            <div className="f-tab-bar" style={{ padding: "0 20px", marginBottom: 0 }}>
              <button className={`f-tab ${detailTab === "findings" ? "active" : ""}`} onClick={() => setDetailTab("findings")}>
                Findings ({scanFindings.length})
              </button>
              <button className={`f-tab ${detailTab === "details" ? "active" : ""}`} onClick={() => setDetailTab("details")}>
                Details
              </button>
            </div>

            <div className="f-modal-body">
              {detailTab === "findings" && (
                scanFindings.length === 0 ? (
                  <div style={{ textAlign: "center", padding: "40px 0", fontSize: 11, color: "var(--falcon-t4)" }}>
                    No findings discovered
                  </div>
                ) : (
                  <div className="f-tbl">
                    <div className="f-tbl-head" style={{ gridTemplateColumns: FINDINGS_COLS }}>
                      <span className="f-th">Severity</span>
                      <span className="f-th">Finding</span>
                      <span className="f-th">Target</span>
                      <span className="f-th">CVSS</span>
                    </div>
                    <div className="f-tbl-body" style={{ maxHeight: 400 }}>
                      {scanFindings.map(finding => (
                        <div key={finding.id} className="f-tbl-row" style={{ gridTemplateColumns: FINDINGS_COLS }}>
                          <div><span className={sevChip(finding.severity)}>{finding.severity.toUpperCase()}</span></div>
                          <div>
                            <div className="f-td n">{finding.title}</div>
                            {finding.cve && <div className="f-td sub">{finding.cve}</div>}
                          </div>
                          <div className="f-td sub">{finding.target}</div>
                          <div className="f-td m" style={{
                            color: finding.cvssScore ? (
                              finding.cvssScore >= 9 ? "var(--falcon-red)" :
                              finding.cvssScore >= 7 ? "var(--falcon-orange)" :
                              finding.cvssScore >= 4 ? "var(--falcon-yellow)" : "var(--falcon-green)"
                            ) : undefined
                          }}>
                            {finding.cvssScore ? finding.cvssScore.toFixed(1) : "—"}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )
              )}

              {detailTab === "details" && (
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, fontSize: 12 }}>
                  <div style={{ color: "var(--falcon-t3)" }}>Scan ID: <code style={{ fontSize: 10, color: "var(--falcon-t2)" }}>{selectedScan.id}</code></div>
                  <div style={{ color: "var(--falcon-t3)" }}>Type: <span style={{ color: "var(--falcon-t1)", fontWeight: 600 }}>{selectedScan.type}</span></div>
                  <div style={{ color: "var(--falcon-t3)" }}>Status: <span className={statusText(selectedScan.status)}>{selectedScan.status.toUpperCase()}</span></div>
                  <div style={{ color: "var(--falcon-t3)" }}>Targets: <span style={{ color: "var(--falcon-t1)" }}>{selectedScan.targetCount}</span></div>
                  <div style={{ color: "var(--falcon-t3)" }}>Started: <span style={{ color: "var(--falcon-t1)" }}>{new Date(selectedScan.startTime).toLocaleString()}</span></div>
                  {selectedScan.endTime && (
                    <div style={{ color: "var(--falcon-t3)" }}>Completed: <span style={{ color: "var(--falcon-t1)" }}>{new Date(selectedScan.endTime).toLocaleString()}</span></div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
