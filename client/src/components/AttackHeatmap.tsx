/**
 * AttackHeatmap — Live ATT&CK Navigator-style heatmap (spec v1.0 §6.3, §8)
 *
 * Updates in real-time as techniques are exercised during an active engagement.
 * Accessible via toggle from the main engagement dashboard.
 *
 * Feature flag: BREACH_CHAIN_ATTACK_HEATMAP
 */

import { useEffect, useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";


// ── Types ──────────────────────────────────────────────────────────────────

interface HeatmapEntry {
  techniqueId: string;
  techniqueName: string;
  tactics: string[];
  status: "exercised" | "attempted" | "failed" | "untested";
  color: string;
}

interface AttackHeatmapProps {
  breachChainId: string;
  isRunning?: boolean;
  onClose?: () => void;
}

// ATT&CK tactic display order (matching Navigator layout)
const TACTIC_DISPLAY = [
  { id: "reconnaissance",       label: "Recon" },
  { id: "resource-development", label: "Resource Dev" },
  { id: "initial-access",       label: "Initial Access" },
  { id: "execution",            label: "Execution" },
  { id: "persistence",          label: "Persistence" },
  { id: "privilege-escalation", label: "Priv Esc" },
  { id: "defense-evasion",      label: "Defense Evasion" },
  { id: "credential-access",    label: "Cred Access" },
  { id: "discovery",            label: "Discovery" },
  { id: "lateral-movement",     label: "Lateral Movement" },
  { id: "collection",           label: "Collection" },
  { id: "command-and-control",  label: "C2" },
  { id: "exfiltration",         label: "Exfiltration" },
  { id: "impact",               label: "Impact" },
];

const STATUS_COLOR: Record<string, string> = {
  exercised: "#ef4444",   // red — successfully executed
  attempted: "#f97316",   // orange — attempted but outcome unclear
  failed:    "#eab308",   // yellow — attempted + failed
  untested:  "#0f172a",   // dark — not touched
};

const STATUS_LABEL: Record<string, string> = {
  exercised: "Exercised",
  attempted: "Attempted",
  failed:    "Failed",
  untested:  "Not Tested",
};

// ── Component ──────────────────────────────────────────────────────────────

export function AttackHeatmap({ breachChainId, isRunning, onClose }: AttackHeatmapProps) {
  const [hoveredTechnique, setHoveredTechnique] = useState<HeatmapEntry | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  const { data: heatmapData, refetch } = useQuery<HeatmapEntry[]>({
    queryKey: ["/api/breach-chains", breachChainId, "heatmap"],
    queryFn: async () => {
      const res = await fetch(`/api/breach-chains/${breachChainId}/heatmap`, {
        credentials: "include",
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    enabled: !!breachChainId,
    refetchInterval: isRunning ? 3000 : false, // poll every 3s while running
  });

  // Group techniques by tactic
  const byTactic = useCallback((tacticId: string): HeatmapEntry[] => {
    return (heatmapData || []).filter(e => e.tactics.includes(tacticId));
  }, [heatmapData]);

  const totalExercised = (heatmapData || []).filter(e => e.status === "exercised").length;
  const totalTechniques = (heatmapData || []).length;
  const coveragePct = totalTechniques > 0 ? Math.round((totalExercised / totalTechniques) * 100) : 0;

  return (
    <div style={{
      background: "#080c14",
      border: "1px solid rgba(56,189,248,0.2)",
      borderRadius: 8,
      overflow: "hidden",
      fontFamily: "'IBM Plex Mono', monospace",
    }}>
      {/* Header */}
      <div style={{
        display: "flex", alignItems: "center", padding: "12px 16px",
        borderBottom: "1px solid rgba(56,189,248,0.1)",
        background: "rgba(56,189,248,0.04)",
      }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: "#f1f5f9", textTransform: "uppercase", letterSpacing: 1 }}>
            ATT&CK Coverage Heatmap
          </div>
          <div style={{ fontSize: 10, color: "#64748b", marginTop: 2 }}>
            {totalExercised} / {totalTechniques} techniques exercised &nbsp;·&nbsp;
            <span style={{ color: coveragePct > 50 ? "#ef4444" : coveragePct > 25 ? "#f97316" : "#64748b" }}>
              {coveragePct}% coverage
            </span>
            {isRunning && (
              <span style={{ marginLeft: 8, color: "#22c55e" }}>● LIVE</span>
            )}
          </div>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center", marginRight: 12 }}>
          {Object.entries(STATUS_COLOR).map(([status, color]) => (
            <div key={status} style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <div style={{ width: 8, height: 8, borderRadius: 2, background: color, border: "1px solid rgba(255,255,255,0.1)" }} />
              <span style={{ fontSize: 9, color: "#64748b", textTransform: "capitalize" }}>{STATUS_LABEL[status]}</span>
            </div>
          ))}
        </div>
        {onClose && (
          <div
            onClick={onClose}
            style={{ cursor: "pointer", color: "#64748b", fontSize: 16, padding: "0 4px" }}
          >
            ×
          </div>
        )}
      </div>

      {/* Navigator Grid */}
      <div style={{ overflowX: "auto", padding: "12px 16px" }}>
        <div style={{ display: "flex", gap: 8, minWidth: "max-content" }}>
          {TACTIC_DISPLAY.map(({ id, label }) => {
            const techniques = byTactic(id);
            const exercised = techniques.filter(t => t.status === "exercised").length;
            const hasActivity = techniques.some(t => t.status !== "untested");
            return (
              <div key={id} style={{ minWidth: 88 }}>
                {/* Tactic header */}
                <div style={{
                  fontSize: 9, fontWeight: 700, color: hasActivity ? "#38bdf8" : "#334155",
                  textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 6,
                  paddingBottom: 4, borderBottom: `1px solid ${hasActivity ? "rgba(56,189,248,0.2)" : "rgba(255,255,255,0.05)"}`,
                  textAlign: "center",
                }}>
                  {label}
                  {exercised > 0 && (
                    <span style={{ color: "#ef4444", marginLeft: 4 }}>({exercised})</span>
                  )}
                </div>

                {/* Technique cells */}
                <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                  {techniques.length === 0 ? (
                    <div style={{ height: 24, background: "#0f172a", borderRadius: 2 }} />
                  ) : (
                    techniques.slice(0, 12).map((t, _ti) => (
                      <div
                        key={t.techniqueId}
                        onMouseEnter={(e) => {
                          setHoveredTechnique(t);
                          setTooltipPos({ x: e.clientX, y: e.clientY });
                        }}
                        onMouseMove={(e) => setTooltipPos({ x: e.clientX, y: e.clientY })}
                        onMouseLeave={() => setHoveredTechnique(null)}
                        style={{
                          height: 22, background: STATUS_COLOR[t.status] || "#0f172a",
                          borderRadius: 2, cursor: "pointer",
                          border: `1px solid ${t.status !== "untested" ? "rgba(255,255,255,0.1)" : "transparent"}`,
                          opacity: t.status === "untested" ? 0.4 : 1,
                          transition: "opacity 0.2s, transform 0.1s",
                          display: "flex", alignItems: "center", justifyContent: "center",
                          overflow: "hidden",
                        }}
                        onMouseOver={(e) => { (e.currentTarget as HTMLDivElement).style.transform = "scale(1.05)"; }}
                        onMouseOut={(e) => { (e.currentTarget as HTMLDivElement).style.transform = "scale(1)"; }}
                      >
                        <span style={{
                          fontSize: 8, color: t.status !== "untested" ? "#fff" : "#334155",
                          fontFamily: "'IBM Plex Mono', monospace", overflow: "hidden",
                          textOverflow: "ellipsis", whiteSpace: "nowrap", padding: "0 3px",
                        }}>
                          {t.techniqueId}
                        </span>
                      </div>
                    ))
                  )}
                  {techniques.length > 12 && (
                    <div style={{ fontSize: 8, color: "#475569", textAlign: "center", padding: "2px 0" }}>
                      +{techniques.length - 12} more
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Tooltip (portal-style — fixed position) */}
      {hoveredTechnique && (
        <div
          style={{
            position: "fixed",
            left: tooltipPos.x + 12,
            top: tooltipPos.y - 8,
            zIndex: 9999,
            background: "rgba(6,9,15,0.97)",
            border: "1px solid rgba(56,189,248,0.3)",
            borderRadius: 6,
            padding: "8px 12px",
            maxWidth: 280,
            pointerEvents: "none",
            boxShadow: "0 4px 16px rgba(0,0,0,0.6)",
            fontFamily: "'IBM Plex Mono', monospace",
          }}
        >
          <div style={{ fontSize: 11, fontWeight: 700, color: "#f1f5f9", marginBottom: 2 }}>
            {hoveredTechnique.techniqueId} — {hoveredTechnique.techniqueName}
          </div>
          <div style={{ fontSize: 9, color: "#64748b", marginBottom: 4 }}>
            {hoveredTechnique.tactics.join(", ")}
          </div>
          <div style={{
            fontSize: 10, fontWeight: 600,
            color: STATUS_COLOR[hoveredTechnique.status],
          }}>
            {STATUS_LABEL[hoveredTechnique.status]}
          </div>
        </div>
      )}
    </div>
  );
}

