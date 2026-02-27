import { useState } from "react";
import { formatDistanceToNow } from "date-fns";
import {
  useScheduledScans,
  useScheduledScanRuns,
  useScheduledScanStats,
  useCreateScheduledScan,
  useDeleteScheduledScan,
  useRunScheduledScanNow,
  useToggleScheduledScan,
  ScheduledScan,
  ScanRun,
} from "@/hooks/useScheduledScans";
import { useToast } from "@/hooks/use-toast";

function statusDot(status: string) {
  if (status === "completed" || status === "success") return "f-s-dot f-sd-done";
  if (status === "running" || status === "pending") return "f-s-dot f-sd-live";
  if (status === "failed" || status === "error") return "f-s-dot f-sd-err";
  return "f-s-dot f-sd-queue";
}

function statusTextCls(status: string) {
  if (status === "completed" || status === "success") return "f-st-done";
  if (status === "running" || status === "pending") return "f-st-live";
  if (status === "failed" || status === "error") return "f-st-err";
  return "f-st-queue";
}

export default function ScheduledScans() {
  const { toast } = useToast();
  const [builderDialogOpen, setBuilderDialogOpen] = useState(false);
  const [selectedScan, setSelectedScan] = useState<ScheduledScan | null>(null);

  const [scanName, setScanName] = useState("");
  const [scanDescription, setScanDescription] = useState("");
  const [scanType, setScanType] = useState<"vulnerability" | "compliance" | "reconnaissance" | "penetration">("vulnerability");
  const [targetIds, setTargetIds] = useState("");
  const [schedule, setSchedule] = useState("0 0 * * *");

  const { data: stats } = useScheduledScanStats();
  const { data: scans = [], isLoading } = useScheduledScans();
  const { data: scanRuns = [] } = useScheduledScanRuns(selectedScan?.id || null);
  const createScan = useCreateScheduledScan();
  const deleteScan = useDeleteScheduledScan();
  const runNow = useRunScheduledScanNow();
  const toggleScan = useToggleScheduledScan();

  const handleCreateScan = async () => {
    if (!scanName.trim() || !targetIds.trim()) {
      toast({ title: "Missing Information", description: "Please enter a name and at least one target ID", variant: "destructive" });
      return;
    }
    const targets = targetIds.split(",").map(id => id.trim()).filter(Boolean);
    await createScan.mutateAsync({ name: scanName, description: scanDescription || undefined, scanType, targetIds: targets, schedule });
    setScanName(""); setScanDescription(""); setTargetIds("");
    setBuilderDialogOpen(false);
  };

  const cronPresets = [
    { label: "Daily at midnight", value: "0 0 * * *" },
    { label: "Weekly on Monday", value: "0 0 * * 1" },
    { label: "Monthly on 1st", value: "0 0 1 * *" },
    { label: "Every 6 hours", value: "0 */6 * * *" },
    { label: "Every hour", value: "0 * * * *" },
  ];

  const GRID_COLS = "1.5fr 100px 130px 110px 110px 70px 120px";

  return (
    <div data-testid="text-page-title">
      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 18, fontWeight: 700, color: "var(--falcon-t1)", margin: 0 }}>Scheduled Scans</h1>
          <p style={{ fontSize: 11, color: "var(--falcon-t3)", marginTop: 4, fontFamily: "var(--font-mono)" }}>
            // automated security scan schedules
          </p>
        </div>
        <button className="f-btn f-btn-primary" onClick={() => setBuilderDialogOpen(true)}>+ Create Schedule</button>
      </div>

      {/* KPI strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 20 }}>
        <div className="f-kpi">
          <div className="f-kpi-lbl"><span className="f-kpi-dot b" />Total Schedules</div>
          <div className="f-kpi-val b">{stats?.totalSchedules || 0}</div>
          <div className="f-kpi-foot">configured</div>
        </div>
        <div className="f-kpi">
          <div className="f-kpi-lbl"><span className="f-kpi-dot g" />Enabled</div>
          <div className="f-kpi-val g">{stats?.enabledSchedules || 0}</div>
          <div className="f-kpi-foot">active schedules</div>
        </div>
        <div className="f-kpi">
          <div className="f-kpi-lbl"><span className="f-kpi-dot o" />Upcoming</div>
          <div className="f-kpi-val o">{stats?.upcomingRuns || 0}</div>
          <div className="f-kpi-foot">pending runs</div>
        </div>
        <div className="f-kpi">
          <div className="f-kpi-lbl"><span className="f-kpi-dot" />Runs Today</div>
          <div className="f-kpi-val">{stats?.lastRunsToday || 0}</div>
          <div className="f-kpi-foot">completed today</div>
        </div>
      </div>

      {/* Schedules table */}
      <div className="f-panel" style={{ flex: 1, minHeight: 0 }}>
        <div className="f-panel-head">
          <div className="f-panel-title"><span className="f-panel-dot b" />Scan Schedules</div>
        </div>
        <div className="f-tbl" style={{ flex: 1 }}>
          <div className="f-tbl-head" style={{ gridTemplateColumns: GRID_COLS }}>
            <span className="f-th">Schedule</span>
            <span className="f-th">Type</span>
            <span className="f-th">Frequency</span>
            <span className="f-th">Next Run</span>
            <span className="f-th">Last Run</span>
            <span className="f-th">Status</span>
            <span className="f-th">Actions</span>
          </div>
          <div className="f-tbl-body">
            {isLoading ? (
              <div style={{ padding: "40px 0", textAlign: "center", fontSize: 11, color: "var(--falcon-t4)" }}>Loading schedules...</div>
            ) : scans.length === 0 ? (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "40px 0" }}>
                <span style={{ fontSize: 11, color: "var(--falcon-t4)" }}>No schedules</span>
                <span style={{ fontSize: 10, color: "var(--falcon-t4)", marginTop: 4 }}>Create your first scheduled scan</span>
                <button className="f-btn f-btn-primary" style={{ marginTop: 12 }} onClick={() => setBuilderDialogOpen(true)}>Create Schedule</button>
              </div>
            ) : (
              scans.map(scan => (
                <div key={scan.id} className="f-tbl-row" style={{ gridTemplateColumns: GRID_COLS }}>
                  <div>
                    <div className="f-td n">{scan.name}</div>
                    {scan.description && <div className="f-td sub">{scan.description}</div>}
                  </div>
                  <div><span className="f-chip f-chip-gray">{scan.scanType.toUpperCase()}</span></div>
                  <div><code style={{ fontSize: 10, color: "var(--falcon-t2)", background: "var(--falcon-panel-2)", padding: "2px 6px", borderRadius: 3 }}>{scan.schedule}</code></div>
                  <div className="f-td">{scan.nextRun ? formatDistanceToNow(new Date(scan.nextRun), { addSuffix: true }) : "—"}</div>
                  <div className="f-td">{scan.lastRun ? formatDistanceToNow(new Date(scan.lastRun), { addSuffix: true }) : "Never"}</div>
                  <div>
                    <button
                      className={`f-switch ${scan.enabled ? "on" : ""}`}
                      onClick={() => toggleScan.mutate({ scanId: scan.id, enabled: !scan.enabled })}
                      aria-label={scan.enabled ? "Disable schedule" : "Enable schedule"}
                    />
                  </div>
                  <div style={{ display: "flex", gap: 4 }}>
                    <button className="f-btn f-btn-ghost" style={{ fontSize: 10, padding: "2px 6px" }} onClick={() => setSelectedScan(scan)}>History</button>
                    <button className="f-btn f-btn-secondary" style={{ fontSize: 10, padding: "2px 6px" }} onClick={() => runNow.mutate(scan.id)} disabled={runNow.isPending}>Run</button>
                    <button className="f-btn f-btn-ghost" style={{ fontSize: 10, padding: "2px 6px", color: "var(--falcon-red)" }} onClick={() => deleteScan.mutate(scan.id)}>Del</button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Create schedule modal */}
      {builderDialogOpen && (
        <div className="f-modal-overlay" onClick={() => setBuilderDialogOpen(false)}>
          <div className="f-modal" onClick={e => e.stopPropagation()}>
            <div className="f-modal-head">
              <h2 className="f-modal-title">Create Scan Schedule</h2>
              <p className="f-modal-desc">Set up an automated security scan</p>
            </div>
            <div className="f-modal-body" style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div>
                <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)", display: "block", marginBottom: 6 }}>Schedule Name</label>
                <input style={{ width: "100%", padding: "8px 12px", background: "var(--falcon-panel)", border: "1px solid var(--falcon-border)", borderRadius: 6, color: "var(--falcon-t1)", fontSize: 12 }}
                  placeholder="Weekly vulnerability scan" value={scanName} onChange={(e) => setScanName(e.target.value)} />
              </div>
              <div>
                <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)", display: "block", marginBottom: 6 }}>Description</label>
                <textarea style={{ width: "100%", padding: "8px 12px", background: "var(--falcon-panel)", border: "1px solid var(--falcon-border)", borderRadius: 6, color: "var(--falcon-t1)", fontSize: 12, resize: "vertical" }}
                  placeholder="Scan description..." value={scanDescription} onChange={(e) => setScanDescription(e.target.value)} rows={2} />
              </div>
              <div>
                <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)", display: "block", marginBottom: 6 }}>Scan Type</label>
                <select className="f-select" value={scanType} onChange={(e) => setScanType(e.target.value as any)}>
                  <option value="vulnerability">Vulnerability Scan</option>
                  <option value="compliance">Compliance Check</option>
                  <option value="reconnaissance">Reconnaissance</option>
                  <option value="penetration">Penetration Test</option>
                </select>
              </div>
              <div>
                <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)", display: "block", marginBottom: 6 }}>Target IDs</label>
                <input style={{ width: "100%", padding: "8px 12px", background: "var(--falcon-panel)", border: "1px solid var(--falcon-border)", borderRadius: 6, color: "var(--falcon-t1)", fontSize: 12 }}
                  placeholder="asset-123, asset-456..." value={targetIds} onChange={(e) => setTargetIds(e.target.value)} />
                <p style={{ fontSize: 10, color: "var(--falcon-t4)", marginTop: 4 }}>Comma-separated list of asset IDs</p>
              </div>
              <div>
                <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)", display: "block", marginBottom: 6 }}>Schedule</label>
                <select className="f-select" value={schedule} onChange={(e) => setSchedule(e.target.value)}>
                  {cronPresets.map(p => <option key={p.value} value={p.value}>{p.label} ({p.value})</option>)}
                </select>
              </div>
            </div>
            <div className="f-modal-footer">
              <button className="f-btn f-btn-ghost" onClick={() => setBuilderDialogOpen(false)}>Cancel</button>
              <button className="f-btn f-btn-primary" onClick={handleCreateScan} disabled={createScan.isPending}>
                {createScan.isPending ? "Creating..." : "Create Schedule"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Run history modal */}
      {selectedScan && (
        <div className="f-modal-overlay" onClick={() => setSelectedScan(null)}>
          <div className="f-modal f-modal-lg" onClick={e => e.stopPropagation()}>
            <div className="f-modal-head">
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div>
                  <h2 className="f-modal-title">{selectedScan.name}</h2>
                  <p className="f-modal-desc">Scan execution history</p>
                </div>
                <button className="f-btn f-btn-ghost" style={{ padding: "4px 8px" }} onClick={() => setSelectedScan(null)}>✕</button>
              </div>
            </div>
            <div className="f-modal-body">
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, fontSize: 12, marginBottom: 20 }}>
                <div style={{ color: "var(--falcon-t3)" }}>Type: <span className="f-chip f-chip-gray" style={{ marginLeft: 4 }}>{selectedScan.scanType.toUpperCase()}</span></div>
                <div style={{ color: "var(--falcon-t3)" }}>Frequency: <code style={{ fontSize: 10, color: "var(--falcon-t2)" }}>{selectedScan.schedule}</code></div>
                <div style={{ color: "var(--falcon-t3)" }}>Next Run: <span style={{ color: "var(--falcon-t1)" }}>{selectedScan.nextRun ? formatDistanceToNow(new Date(selectedScan.nextRun), { addSuffix: true }) : "Not scheduled"}</span></div>
                <div style={{ color: "var(--falcon-t3)" }}>Targets: <span style={{ color: "var(--falcon-t1)" }}>{selectedScan.targetIds.length}</span></div>
              </div>

              <h3 style={{ fontSize: 13, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 12 }}>Execution History</h3>
              {scanRuns.length > 0 ? (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {scanRuns.map(run => (
                    <div key={run.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 12px", border: "1px solid var(--falcon-border)", borderRadius: 6, fontSize: 12 }}>
                      <span className={statusDot(run.status)} />
                      <span className={statusTextCls(run.status)} style={{ fontWeight: 600, fontSize: 11 }}>
                        {run.status === "completed" ? "Completed" : run.status === "failed" ? "Failed" : "Running"}
                      </span>
                      <span style={{ color: "var(--falcon-t3)", fontSize: 11 }}>
                        {run.findingsCount !== undefined ? `${run.findingsCount} findings` : run.error || ""}
                      </span>
                      <span style={{ marginLeft: "auto", color: "var(--falcon-t4)", fontSize: 10 }}>
                        {new Date(run.startTime).toLocaleString()}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p style={{ fontSize: 11, color: "var(--falcon-t4)" }}>No execution history</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
