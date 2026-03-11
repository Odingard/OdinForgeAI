/**
 * EngagementConfigModal — Pre-engagement setup (spec v1.0 §7)
 *
 * Configures all engagement parameters BEFORE any sub-agent is deployed
 * and before any packet is sent. This config drives all downstream AI
 * decision-making.
 *
 * State machine: CONFIGURED → INITIALIZING → ACTIVE (enforced server-side)
 * Feature flag: BREACH_CHAIN_ENGAGEMENT_CONFIG
 */

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import type { BreachChainConfig } from "@shared/schema";

// ── Types ──────────────────────────────────────────────────────────────────

interface EngagementConfig {
  objective: "data_exfiltration" | "credential_compromise" | "ransomware_simulation" | "full_kill_chain" | "custom";
  noiseLevel: "silent" | "moderate" | "aggressive";
  evasionPosture: "none" | "basic" | "advanced";
  threatActorProfile: string;
  maxAssetsToTouch: number;
  subAgentRecursionDepth: number;
  credentialReusePolicy: "reuse_allowed" | "report_only";
  defenseValidationMode: "active_probing" | "passive_observation";
  targetIPRanges: string;   // newline-separated
  targetDomains: string;    // newline-separated
  executionMode: "safe" | "simulation" | "live";
}

interface EngagementConfigModalProps {
  breachChainId: string;
  currentConfig?: Partial<BreachChainConfig>;
  onClose: () => void;
  onConfigured: (config: BreachChainConfig) => void;
}

const THREAT_ACTOR_PROFILES = [
  { id: "generic",  label: "Generic Threat Actor" },
  { id: "APT29",    label: "APT29 — Cozy Bear (Russian SVR)" },
  { id: "APT41",    label: "APT41 (Chinese state-sponsored)" },
  { id: "Lazarus",  label: "Lazarus Group (DPRK)" },
  { id: "FIN7",     label: "FIN7 (Financially motivated)" },
  { id: "custom",   label: "Custom Profile" },
];

const OBJECTIVES = [
  { id: "full_kill_chain",        label: "Full Kill Chain", desc: "All 8 phases, end-to-end" },
  { id: "data_exfiltration",      label: "Data Exfiltration", desc: "Focus on collection + exfil" },
  { id: "credential_compromise",  label: "Credential Compromise", desc: "Credential harvesting + lateral movement" },
  { id: "ransomware_simulation",  label: "Ransomware Simulation", desc: "Encrypt-in-place simulation" },
  { id: "custom",                 label: "Custom", desc: "Define your own objective" },
];

// ── Component ──────────────────────────────────────────────────────────────

export function EngagementConfigModal({
  breachChainId,
  currentConfig,
  onClose,
  onConfigured,
}: EngagementConfigModalProps) {
  const qc = useQueryClient();

  const [config, setConfig] = useState<EngagementConfig>({
    objective: "full_kill_chain",
    noiseLevel: "moderate",
    evasionPosture: "basic",
    threatActorProfile: "generic",
    maxAssetsToTouch: 20,
    subAgentRecursionDepth: 5,
    credentialReusePolicy: "reuse_allowed",
    defenseValidationMode: "active_probing",
    targetIPRanges: "",
    targetDomains: "",
    executionMode: currentConfig?.executionMode ?? "simulation",
  });

  const [validationError, setValidationError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"scope" | "behavior" | "adversary" | "limits">("scope");

  const { mutate: saveConfig, isPending } = useMutation({
    mutationFn: async (cfg: EngagementConfig) => {
      const res = await fetch(`/api/breach-chains/${breachChainId}/config`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          engagement: {
            objective: cfg.objective,
            noiseLevel: cfg.noiseLevel,
            evasionPosture: cfg.evasionPosture,
            threatActorProfile: cfg.threatActorProfile,
            maxAssetsToTouch: cfg.maxAssetsToTouch,
            subAgentRecursionDepth: cfg.subAgentRecursionDepth,
            credentialReusePolicy: cfg.credentialReusePolicy,
            defenseValidationMode: cfg.defenseValidationMode,
            targetIPRanges: cfg.targetIPRanges.split("\n").map(s => s.trim()).filter(Boolean),
            targetDomains: cfg.targetDomains.split("\n").map(s => s.trim()).filter(Boolean),
          },
          executionMode: cfg.executionMode,
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    },
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ["/api/breach-chains"] });
      onConfigured(data);
      onClose();
    },
    onError: (err) => setValidationError(String(err)),
  });

  const validate = (): string | null => {
    if (config.maxAssetsToTouch < 1) return "Max assets must be at least 1";
    if (config.subAgentRecursionDepth < 1 || config.subAgentRecursionDepth > 10) return "Recursion depth must be 1-10";
    if (config.executionMode === "live" && config.targetIPRanges.trim() === "" && config.targetDomains.trim() === "") {
      return "Live mode requires at least one target IP range or domain";
    }
    return null;
  };

  const handleSave = () => {
    const err = validate();
    if (err) { setValidationError(err); return; }
    setValidationError(null);
    saveConfig(config);
  };

  const set = <K extends keyof EngagementConfig>(key: K, value: EngagementConfig[K]) =>
    setConfig(c => ({ ...c, [key]: value }));

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 1000,
      background: "rgba(0,0,0,0.75)", backdropFilter: "blur(4px)",
      display: "flex", alignItems: "center", justifyContent: "center",
    }}
    onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div style={{
        width: 580, maxHeight: "90vh", overflowY: "auto",
        background: "#080c14", border: "1px solid rgba(56,189,248,0.25)",
        borderRadius: 10, fontFamily: "'IBM Plex Mono', monospace",
        boxShadow: "0 24px 64px rgba(0,0,0,0.8)",
      }}>
        {/* Header */}
        <div style={{
          padding: "16px 20px", borderBottom: "1px solid rgba(56,189,248,0.1)",
          background: "rgba(56,189,248,0.04)", display: "flex", alignItems: "center",
        }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#f1f5f9", textTransform: "uppercase", letterSpacing: 1 }}>
              Engagement Configuration
            </div>
            <div style={{ fontSize: 10, color: "#64748b", marginTop: 2 }}>
              Configure before deployment. All parameters drive AI decision-making.
            </div>
          </div>
          <div onClick={onClose} style={{ cursor: "pointer", color: "#64748b", fontSize: 18, padding: "0 4px" }}>×</div>
        </div>

        {/* Execution mode banner */}
        <div style={{ padding: "10px 20px", background: "rgba(15,23,42,0.5)", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
          <div style={{ fontSize: 10, color: "#64748b", marginBottom: 6 }}>EXECUTION MODE</div>
          <div style={{ display: "flex", gap: 8 }}>
            {(["safe", "simulation", "live"] as const).map((mode) => (
              <button
                key={mode}
                onClick={() => set("executionMode", mode)}
                style={{
                  flex: 1, padding: "8px 0", borderRadius: 4, cursor: "pointer",
                  fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5,
                  fontFamily: "'IBM Plex Mono', monospace",
                  background: config.executionMode === mode
                    ? (mode === "live" ? "rgba(239,68,68,0.2)" : mode === "simulation" ? "rgba(249,115,22,0.15)" : "rgba(34,197,94,0.12)")
                    : "rgba(255,255,255,0.03)",
                  border: `1px solid ${config.executionMode === mode
                    ? (mode === "live" ? "#ef4444" : mode === "simulation" ? "#f97316" : "#22c55e")
                    : "rgba(255,255,255,0.06)"}`,
                  color: config.executionMode === mode
                    ? (mode === "live" ? "#ef4444" : mode === "simulation" ? "#f97316" : "#22c55e")
                    : "#475569",
                }}
              >
                {mode}
                {mode === "live" && <span style={{ marginLeft: 4, fontSize: 8 }}>⚡</span>}
              </button>
            ))}
          </div>
          {config.executionMode === "live" && (
            <div style={{ marginTop: 6, fontSize: 9, color: "#ef4444", background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.15)", borderRadius: 3, padding: "4px 8px" }}>
              ⚡ LIVE MODE — Real network actions will be taken against specified targets
            </div>
          )}
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
          {(["scope", "behavior", "adversary", "limits"] as const).map((tab) => (
            <div
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                flex: 1, padding: "10px 0", textAlign: "center", cursor: "pointer",
                fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5,
                color: activeTab === tab ? "#38bdf8" : "#475569",
                borderBottom: `2px solid ${activeTab === tab ? "#38bdf8" : "transparent"}`,
              }}
            >
              {tab}
            </div>
          ))}
        </div>

        {/* Tab content */}
        <div style={{ padding: "16px 20px" }}>

          {/* SCOPE tab */}
          {activeTab === "scope" && (
            <div>
              <Field label="Objective">
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {OBJECTIVES.map((obj) => (
                    <label key={obj.id} style={{ display: "flex", alignItems: "flex-start", gap: 8, cursor: "pointer" }}>
                      <input
                        type="radio"
                        checked={config.objective === obj.id}
                        onChange={() => set("objective", obj.id as EngagementConfig["objective"])}
                        style={{ marginTop: 2 }}
                      />
                      <div>
                        <div style={{ fontSize: 11, color: "#f1f5f9" }}>{obj.label}</div>
                        <div style={{ fontSize: 9, color: "#64748b" }}>{obj.desc}</div>
                      </div>
                    </label>
                  ))}
                </div>
              </Field>

              <Field label="Target IP Ranges (one per line)">
                <textarea
                  value={config.targetIPRanges}
                  onChange={(e) => set("targetIPRanges", e.target.value)}
                  placeholder={"192.168.1.0/24\n10.0.0.0/8"}
                  rows={3}
                  style={textareaStyle}
                />
              </Field>

              <Field label="Target Domains (one per line)">
                <textarea
                  value={config.targetDomains}
                  onChange={(e) => set("targetDomains", e.target.value)}
                  placeholder={"example.com\n*.internal.example.com"}
                  rows={2}
                  style={textareaStyle}
                />
              </Field>
            </div>
          )}

          {/* BEHAVIOR tab */}
          {activeTab === "behavior" && (
            <div>
              <Field label="Noise Level">
                <div style={{ display: "flex", gap: 6 }}>
                  {(["silent", "moderate", "aggressive"] as const).map((n) => (
                    <Chip key={n} active={config.noiseLevel === n} onClick={() => set("noiseLevel", n)}
                      color={n === "aggressive" ? "#ef4444" : n === "moderate" ? "#f97316" : "#22c55e"}>
                      {n}
                    </Chip>
                  ))}
                </div>
                <div style={{ fontSize: 9, color: "#475569", marginTop: 4 }}>
                  Silent: mimics APT stealth  ·  Moderate: balanced  ·  Aggressive: speed over stealth
                </div>
              </Field>

              <Field label="Evasion Posture">
                <div style={{ display: "flex", gap: 6 }}>
                  {(["none", "basic", "advanced"] as const).map((e) => (
                    <Chip key={e} active={config.evasionPosture === e} onClick={() => set("evasionPosture", e)}
                      color={e === "advanced" ? "#a78bfa" : e === "basic" ? "#38bdf8" : "#64748b"}>
                      {e}
                    </Chip>
                  ))}
                </div>
              </Field>

              <Field label="Credential Reuse Policy">
                <div style={{ display: "flex", gap: 6 }}>
                  <Chip active={config.credentialReusePolicy === "reuse_allowed"} onClick={() => set("credentialReusePolicy", "reuse_allowed")} color="#38bdf8">
                    Reuse Allowed
                  </Chip>
                  <Chip active={config.credentialReusePolicy === "report_only"} onClick={() => set("credentialReusePolicy", "report_only")} color="#64748b">
                    Report Only
                  </Chip>
                </div>
              </Field>

              <Field label="Defense Validation Mode">
                <div style={{ display: "flex", gap: 6 }}>
                  <Chip active={config.defenseValidationMode === "active_probing"} onClick={() => set("defenseValidationMode", "active_probing")} color="#ef4444">
                    Active Probing
                  </Chip>
                  <Chip active={config.defenseValidationMode === "passive_observation"} onClick={() => set("defenseValidationMode", "passive_observation")} color="#64748b">
                    Passive Observation
                  </Chip>
                </div>
              </Field>
            </div>
          )}

          {/* ADVERSARY tab */}
          {activeTab === "adversary" && (
            <div>
              <Field label="Threat Actor Profile">
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {THREAT_ACTOR_PROFILES.map((p) => (
                    <label key={p.id} style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
                      <input
                        type="radio"
                        checked={config.threatActorProfile === p.id}
                        onChange={() => set("threatActorProfile", p.id)}
                      />
                      <span style={{ fontSize: 11, color: config.threatActorProfile === p.id ? "#f1f5f9" : "#64748b" }}>
                        {p.label}
                      </span>
                    </label>
                  ))}
                </div>
                <div style={{ marginTop: 8, fontSize: 9, color: "#475569" }}>
                  Profile weights ATT&CK technique selection toward known actor TTPs.
                </div>
              </Field>
            </div>
          )}

          {/* LIMITS tab */}
          {activeTab === "limits" && (
            <div>
              <Field label={`Max Assets to Touch: ${config.maxAssetsToTouch}`}>
                <input
                  type="range" min={1} max={100} value={config.maxAssetsToTouch}
                  onChange={(e) => set("maxAssetsToTouch", parseInt(e.target.value))}
                  style={{ width: "100%", accentColor: "#38bdf8" }}
                />
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: "#475569" }}>
                  <span>1 (minimal)</span><span>50 (standard)</span><span>100 (full blast)</span>
                </div>
              </Field>

              <Field label={`Sub-Agent Recursion Depth: ${config.subAgentRecursionDepth}`}>
                <input
                  type="range" min={1} max={10} value={config.subAgentRecursionDepth}
                  onChange={(e) => set("subAgentRecursionDepth", parseInt(e.target.value))}
                  style={{ width: "100%", accentColor: "#a78bfa" }}
                />
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 9, color: "#475569" }}>
                  <span>1 (shallow)</span><span>5 (default)</span><span>10 (deep)</span>
                </div>
                <div style={{ fontSize: 9, color: "#475569", marginTop: 4 }}>
                  Each discovered node spawns a sub-agent up to this depth.
                </div>
              </Field>
            </div>
          )}

        </div>

        {/* Validation error */}
        {validationError && (
          <div style={{ margin: "0 20px 12px", padding: "8px 12px", background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.25)", borderRadius: 4, fontSize: 10, color: "#fca5a5" }}>
            ⚠ {validationError}
          </div>
        )}

        {/* Footer */}
        <div style={{
          padding: "12px 20px", borderTop: "1px solid rgba(255,255,255,0.05)",
          display: "flex", justifyContent: "flex-end", gap: 8,
        }}>
          <button onClick={onClose} style={btnStyle("#475569", "rgba(255,255,255,0.05)")}>
            Cancel
          </button>
          <button onClick={handleSave} disabled={isPending} style={btnStyle("#38bdf8", "rgba(56,189,248,0.1)")}>
            {isPending ? "Saving…" : "Save Configuration"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontSize: 9, color: "#64748b", fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 6 }}>
        {label}
      </div>
      {children}
    </div>
  );
}

function Chip({ active, onClick, color, children }: { active: boolean; onClick: () => void; color: string; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "5px 10px", borderRadius: 4, cursor: "pointer", fontSize: 10,
        fontWeight: 600, fontFamily: "'IBM Plex Mono', monospace", textTransform: "capitalize",
        background: active ? `rgba(${hexToRgb(color)},0.15)` : "rgba(255,255,255,0.03)",
        border: `1px solid ${active ? color : "rgba(255,255,255,0.06)"}`,
        color: active ? color : "#475569",
      }}
    >
      {children}
    </button>
  );
}

const textareaStyle: React.CSSProperties = {
  width: "100%", boxSizing: "border-box",
  background: "rgba(15,23,42,0.8)", border: "1px solid rgba(255,255,255,0.08)",
  borderRadius: 4, color: "#94a3b8", fontSize: 10, padding: "6px 8px",
  fontFamily: "'IBM Plex Mono', monospace", resize: "vertical",
};

function btnStyle(color: string, bg: string): React.CSSProperties {
  return {
    padding: "8px 16px", borderRadius: 4, cursor: "pointer",
    fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5,
    fontFamily: "'IBM Plex Mono', monospace", background: bg,
    border: `1px solid ${color}`, color,
  };
}

function hexToRgb(hex: string): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `${r},${g},${b}`;
}

