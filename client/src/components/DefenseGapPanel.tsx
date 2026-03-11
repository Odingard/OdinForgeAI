/**
 * DefenseGapPanel — Real-time defense coverage visualization (spec v1.0 §8.3)
 *
 * Shows: detections that fired, detections that missed, techniques that evaded.
 * Linked to specific nodes in the breach chain.
 *
 * Feature flag: BREACH_CHAIN_DEFENSE_GAP
 */

import { useQuery } from "@tanstack/react-query";


// ── Types ──────────────────────────────────────────────────────────────────

interface DefenseEvent {
  nodeId: string;
  nodeLabel: string;
  tactic: string;
  techniqueId?: string;
  techniqueName?: string;
  timestamp: string;
  // What fired
  detectionsFired: string[];
  // What should have fired but didn't
  detectionsMissed: string[];
  // Evasion details
  evasionNotes?: string;
}

interface DefenseGapSummary {
  totalTechniques: number;
  totalDetected: number;
  totalMissed: number;
  coveragePct: number;
  byTactic: Record<string, { detected: number; missed: number }>;
  events: DefenseEvent[];
}

interface DefenseGapPanelProps {
  breachChainId: string;
  selectedNodeId?: string | null;
  isRunning?: boolean;
  onClose?: () => void;
}

// ── Component ──────────────────────────────────────────────────────────────

export function DefenseGapPanel({ breachChainId, selectedNodeId, isRunning, onClose }: DefenseGapPanelProps) {
  const { data: summary } = useQuery<DefenseGapSummary>({
    queryKey: ["/api/breach-chains", breachChainId, "defense-gaps"],
    queryFn: async () => {
      const res = await fetch(`/api/breach-chains/${breachChainId}/defense-gaps`, {
        credentials: "include",
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    enabled: !!breachChainId,
    refetchInterval: isRunning ? 5000 : false,
  });

  if (!summary) {
    return (
      <div style={containerStyle}>
        <div style={headerStyle}>
          <div style={{ flex: 1 }}>
            <div style={titleStyle}>Defense Gap Analysis</div>
            <div style={{ fontSize: 9, color: "#64748b" }}>Awaiting engagement data…</div>
          </div>
          {onClose && <CloseBtn onClick={onClose} />}
        </div>
        <div style={{ padding: 20, textAlign: "center", color: "#334155", fontSize: 11 }}>
          No defense data yet. Start a breach chain engagement to see gap analysis.
        </div>
      </div>
    );
  }

  const coverageColor = summary.coveragePct >= 80 ? "#22c55e"
    : summary.coveragePct >= 50 ? "#f97316" : "#ef4444";

  // Filter events to selected node if one is active
  const displayEvents = selectedNodeId
    ? summary.events.filter(e => e.nodeId === selectedNodeId)
    : summary.events;

  return (
    <div style={containerStyle}>
      {/* Header */}
      <div style={headerStyle}>
        <div style={{ flex: 1 }}>
          <div style={titleStyle}>Defense Gap Analysis</div>
          <div style={{ fontSize: 9, color: "#64748b" }}>
            {summary.totalDetected} detected · {summary.totalMissed} missed
            {isRunning && <span style={{ marginLeft: 8, color: "#22c55e" }}>● LIVE</span>}
          </div>
        </div>
        {onClose && <CloseBtn onClick={onClose} />}
      </div>

      {/* Coverage bar */}
      <div style={{ padding: "10px 14px", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
          <span style={{ fontSize: 10, color: "#94a3b8" }}>Detection Coverage</span>
          <span style={{ fontSize: 12, fontWeight: 700, color: coverageColor }}>
            {summary.coveragePct}%
          </span>
        </div>
        <div style={{ height: 6, background: "rgba(255,255,255,0.06)", borderRadius: 3, overflow: "hidden" }}>
          <div style={{
            height: "100%", width: `${summary.coveragePct}%`, borderRadius: 3,
            background: coverageColor, transition: "width 0.5s",
          }} />
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4 }}>
          <span style={{ fontSize: 9, color: "#22c55e" }}>✓ {summary.totalDetected} fired</span>
          <span style={{ fontSize: 9, color: "#ef4444" }}>✗ {summary.totalMissed} missed</span>
        </div>
      </div>

      {/* By-tactic breakdown */}
      {Object.keys(summary.byTactic).length > 0 && (
        <div style={{ padding: "8px 14px", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
          <div style={{ fontSize: 9, color: "#475569", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 6 }}>By Tactic</div>
          {Object.entries(summary.byTactic).map(([tactic, counts]) => {
            const total = counts.detected + counts.missed;
            const pct = total > 0 ? Math.round((counts.detected / total) * 100) : 0;
            return (
              <div key={tactic} style={{ marginBottom: 5 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 2 }}>
                  <span style={{ fontSize: 9, color: "#64748b", textTransform: "capitalize" }}>
                    {tactic.replace(/-/g, " ")}
                  </span>
                  <span style={{ fontSize: 9, color: pct >= 80 ? "#22c55e" : pct >= 50 ? "#f97316" : "#ef4444" }}>
                    {pct}%
                  </span>
                </div>
                <div style={{ height: 3, background: "rgba(255,255,255,0.05)", borderRadius: 2 }}>
                  <div style={{
                    height: "100%", width: `${pct}%`,
                    background: pct >= 80 ? "#22c55e" : pct >= 50 ? "#f97316" : "#ef4444",
                    borderRadius: 2, transition: "width 0.3s",
                  }} />
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Event list */}
      <div style={{ maxHeight: 320, overflowY: "auto", padding: "8px 14px" }}>
        {selectedNodeId && (
          <div style={{ fontSize: 9, color: "#38bdf8", marginBottom: 6 }}>
            Showing events for selected node
          </div>
        )}
        {displayEvents.length === 0 ? (
          <div style={{ fontSize: 10, color: "#334155", textAlign: "center", padding: 16 }}>
            {selectedNodeId ? "No defense events for this node" : "No events yet"}
          </div>
        ) : (
          displayEvents.map((event, i) => (
            <div key={i} style={{
              marginBottom: 8, background: "rgba(15,23,42,0.6)",
              border: "1px solid rgba(255,255,255,0.05)", borderRadius: 4, padding: "8px 10px",
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: "#f1f5f9" }}>{event.nodeLabel}</span>
                <span style={{ fontSize: 9, color: "#475569" }}>
                  {new Date(event.timestamp).toLocaleTimeString()}
                </span>
              </div>
              {event.techniqueId && (
                <div style={{ fontSize: 9, color: "#a78bfa", marginBottom: 4 }}>
                  {event.techniqueId} — {event.techniqueName}
                </div>
              )}
              {event.detectionsFired.length > 0 && (
                <div style={{ marginBottom: 3 }}>
                  <span style={{ fontSize: 9, color: "#22c55e" }}>✓ FIRED: </span>
                  {event.detectionsFired.map((d, j) => (
                    <span key={j} style={{
                      fontSize: 9, color: "#4ade80", background: "rgba(34,197,94,0.08)",
                      border: "1px solid rgba(34,197,94,0.15)", borderRadius: 2, padding: "0 4px", marginRight: 3,
                    }}>
                      {d}
                    </span>
                  ))}
                </div>
              )}
              {event.detectionsMissed.length > 0 && (
                <div style={{ marginBottom: 3 }}>
                  <span style={{ fontSize: 9, color: "#ef4444" }}>✗ MISSED: </span>
                  {event.detectionsMissed.map((d, j) => (
                    <span key={j} style={{
                      fontSize: 9, color: "#fca5a5", background: "rgba(239,68,68,0.08)",
                      border: "1px solid rgba(239,68,68,0.15)", borderRadius: 2, padding: "0 4px", marginRight: 3,
                    }}>
                      {d}
                    </span>
                  ))}
                </div>
              )}
              {event.evasionNotes && (
                <div style={{ fontSize: 9, color: "#64748b", fontStyle: "italic", marginTop: 2 }}>
                  {event.evasionNotes}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// ── Shared styles ──────────────────────────────────────────────────────────

const containerStyle: React.CSSProperties = {
  background: "#080c14",
  border: "1px solid rgba(56,189,248,0.15)",
  borderRadius: 8,
  overflow: "hidden",
  fontFamily: "'IBM Plex Mono', monospace",
};

const headerStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  padding: "10px 14px",
  borderBottom: "1px solid rgba(56,189,248,0.08)",
  background: "rgba(56,189,248,0.03)",
};

const titleStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 700,
  color: "#f1f5f9",
  textTransform: "uppercase",
  letterSpacing: 1,
};

function CloseBtn({ onClick }: { onClick: () => void }) {
  return (
    <div onClick={onClick} style={{ cursor: "pointer", color: "#64748b", fontSize: 16, padding: "0 4px" }}>
      ×
    </div>
  );
}

