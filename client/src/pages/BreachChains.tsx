import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import { useBreachChainUpdates } from "@/hooks/useBreachChainUpdates";
import { BreachChainExport } from "@/components/BreachChainExport";
import { CanvasPanel } from "@/components/canvas/CanvasPanel";
import { PortfolioPanel } from "@/components/portfolio/PortfolioPanel";
import {
  Link2,
  Play,
  Pause,
  StopCircle,
  Trash2,
  Eye,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  Shield,
  Key,
  Server,
  Cloud,
  Container,
  Network,
  AlertTriangle,
  FileText,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Crosshair,
  Zap,
  Lock,
  SkipForward,
  Ban,
  Target,
  Settings2,
  ArrowRight,
  FileBarChart,
  Download,
  LayoutGrid,
  List,
} from "lucide-react";
import type { BreachChain, BreachPhaseResult, BreachPhaseContext, BreachPhaseName, AttackGraph } from "@shared/schema";
import { LiveBreachChainGraph } from "@/components/LiveBreachChainGraph";
import { ChainComparison } from "@/components/ChainComparison";
import { ChainSparkline } from "@/components/ChainSparkline";
import { AttackHeatmap } from "@/components/AttackHeatmap";
import { CredentialWeb } from "@/components/CredentialWeb";
import { DefenseGapPanel } from "@/components/DefenseGapPanel";

// Phase metadata for display
const PHASE_META: Record<string, { label: string; icon: typeof Shield; color: string; description: string }> = {
  application_compromise: {
    label: "App Compromise",
    icon: Crosshair,
    color: "var(--falcon-red)",
    description: "Exploit application-layer vulnerabilities with active payloads",
  },
  credential_extraction: {
    label: "Credential Extraction",
    icon: Key,
    color: "var(--falcon-yellow)",
    description: "Harvest credentials from compromised applications",
  },
  cloud_iam_escalation: {
    label: "Cloud IAM Escalation",
    icon: Cloud,
    color: "var(--falcon-blue-hi)",
    description: "Escalate privileges via IAM misconfigurations",
  },
  container_k8s_breakout: {
    label: "K8s Breakout",
    icon: Container,
    color: "#a78bfa",
    description: "Exploit RBAC, secrets, and container escape paths",
  },
  lateral_movement: {
    label: "Lateral Movement",
    icon: Network,
    color: "var(--falcon-blue-hi)",
    description: "Pivot across network using harvested credentials",
  },
  impact_assessment: {
    label: "Impact Assessment",
    icon: AlertTriangle,
    color: "var(--falcon-orange)",
    description: "Aggregate business impact and compliance gaps",
  },
};

const STATUS_STYLES: Record<string, { color: string; bg: string }> = {
  pending: { color: "var(--falcon-t3)", bg: "var(--falcon-panel-2)" },
  running: { color: "var(--falcon-blue-hi)", bg: "rgba(59,130,246,0.15)" },
  paused: { color: "var(--falcon-yellow)", bg: "rgba(245,158,11,0.15)" },
  completed: { color: "var(--falcon-green)", bg: "rgba(16,185,129,0.15)" },
  failed: { color: "var(--falcon-red)", bg: "rgba(239,68,68,0.15)" },
  aborted: { color: "var(--falcon-t3)", bg: "var(--falcon-panel-2)" },
  skipped: { color: "var(--falcon-t3)", bg: "var(--falcon-panel-2)" },
  blocked: { color: "var(--falcon-orange)", bg: "rgba(249,115,22,0.15)" },
};

const PHASE_STATUS_ICON: Record<string, typeof CheckCircle2> = {
  completed: CheckCircle2,
  running: Loader2,
  failed: XCircle,
  pending: Clock,
  skipped: SkipForward,
  blocked: Ban,
};

const PRIVILEGE_COLORS: Record<string, string> = {
  none: "var(--falcon-t3)",
  user: "var(--falcon-blue-hi)",
  admin: "var(--falcon-orange)",
  system: "var(--falcon-red)",
  cloud_admin: "#a78bfa",
  domain_admin: "var(--falcon-red)",
};

function statusIconColor(status: string): string {
  if (status === "completed") return "var(--falcon-green)";
  if (status === "running") return "var(--falcon-blue-hi)";
  if (status === "failed") return "var(--falcon-red)";
  return "var(--falcon-t4)";
}

function statusIconBg(status: string): string {
  if (status === "completed") return "rgba(16,185,129,0.15)";
  if (status === "running") return "rgba(59,130,246,0.15)";
  if (status === "failed") return "rgba(239,68,68,0.15)";
  return "var(--falcon-panel-2)";
}

function sevChip(severity: string): string {
  if (severity === "critical") return "f-chip f-chip-crit";
  if (severity === "high") return "f-chip f-chip-high";
  if (severity === "medium") return "f-chip f-chip-med";
  return "f-chip f-chip-low";
}

// ============================================================================
// Sub-components
// ============================================================================

function PhaseTimeline({ phaseResults, currentPhase, enabledPhases }: {
  phaseResults: BreachPhaseResult[];
  currentPhase: string | null;
  enabledPhases: BreachPhaseName[];
}) {
  const resultMap = new Map(phaseResults.map(r => [r.phaseName, r]));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {enabledPhases.map((phaseName, idx) => {
        const result = resultMap.get(phaseName);
        const meta = PHASE_META[phaseName];
        const isCurrent = currentPhase === phaseName;
        const status = result?.status || (isCurrent ? "running" : "pending");
        const StatusIcon = PHASE_STATUS_ICON[status] || Clock;
        const PhaseIcon = meta?.icon || Shield;

        return (
          <div
            key={phaseName}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 12,
              padding: "10px 12px",
              borderRadius: 6,
              border: `1px solid ${isCurrent ? "var(--falcon-blue-hi)" : "var(--falcon-border)"}`,
              background: isCurrent ? "rgba(59,130,246,0.05)" : "transparent",
              transition: "all 0.15s ease",
            }}
          >
            <div style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              width: 28,
              height: 28,
              borderRadius: "50%",
              background: statusIconBg(status),
              flexShrink: 0,
            }}>
              <StatusIcon
                style={{ width: 14, height: 14, color: statusIconColor(status) }}
                className={status === "running" ? "animate-spin" : ""}
              />
            </div>

            <PhaseIcon style={{ width: 14, height: 14, color: meta?.color || "var(--falcon-t4)", flexShrink: 0 }} />

            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>{meta?.label || phaseName}</span>
                {result?.durationMs && (
                  <span style={{ fontSize: 10, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>
                    {(result.durationMs / 1000).toFixed(1)}s
                  </span>
                )}
              </div>
              {result?.findings && result.findings.length > 0 && (
                <span style={{ fontSize: 10, color: "var(--falcon-t4)" }}>
                  {result.findings.length} finding{result.findings.length !== 1 ? "s" : ""}
                </span>
              )}
              {result?.error && (
                <span style={{ fontSize: 10, color: "var(--falcon-red)", display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{result.error}</span>
              )}
            </div>

            {idx < enabledPhases.length - 1 && (
              <ArrowRight style={{ width: 12, height: 12, color: "var(--falcon-t4)", opacity: 0.5, flexShrink: 0 }} />
            )}
          </div>
        );
      })}
    </div>
  );
}

function ContextSummary({ context }: { context: BreachPhaseContext | null }) {
  if (!context) return <p style={{ fontSize: 12, color: "var(--falcon-t4)" }}>No context data yet</p>;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
        <div className="f-kpi">
          <div className="f-kpi-lbl"><span className="f-kpi-dot y" />Credentials</div>
          <div className="f-kpi-val y">{context.credentials?.length || 0}</div>
          <div className="f-kpi-foot">harvested</div>
        </div>
        <div className="f-kpi">
          <div className="f-kpi-lbl"><span className="f-kpi-dot r" />Assets Compromised</div>
          <div className="f-kpi-val r">{context.compromisedAssets?.length || 0}</div>
          <div className="f-kpi-foot">total</div>
        </div>
        <div className="f-kpi">
          <div className="f-kpi-lbl"><span className="f-kpi-dot" />Privilege Level</div>
          <div className="f-kpi-val" style={{ color: PRIVILEGE_COLORS[context.currentPrivilegeLevel] || "var(--falcon-t3)" }}>
            {context.currentPrivilegeLevel || "none"}
          </div>
          <div className="f-kpi-foot">current</div>
        </div>
        <div className="f-kpi">
          <div className="f-kpi-lbl"><span className="f-kpi-dot" style={{ background: "#a78bfa" }} />Domains Breached</div>
          <div className="f-kpi-val" style={{ color: "#a78bfa" }}>{context.domainsCompromised?.length || 0}</div>
          <div className="f-kpi-foot">total</div>
        </div>
      </div>

      {context.credentials && context.credentials.length > 0 && (
        <div>
          <h4 style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8, display: "flex", alignItems: "center", gap: 8 }}>
            <Key style={{ width: 14, height: 14, color: "var(--falcon-yellow)" }} />
            Harvested Credentials
          </h4>
          <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 240, overflowY: "auto" }}>
            {context.credentials.map((cred, idx) => (
              <div key={cred.id || idx} style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "6px 10px",
                borderRadius: 6,
                border: "1px solid var(--falcon-border)",
                fontSize: 12,
              }}>
                <span className="f-chip f-chip-gray" style={{ flexShrink: 0 }}>{cred.type}</span>
                <span style={{ color: "var(--falcon-t1)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{cred.username || "\u2014"}</span>
                {cred.domain && (
                  <span style={{ color: "var(--falcon-t4)", fontSize: 11 }}>@{cred.domain}</span>
                )}
                <span
                  style={{
                    marginLeft: "auto",
                    flexShrink: 0,
                    fontSize: 10,
                    fontWeight: 600,
                    padding: "2px 6px",
                    borderRadius: 4,
                    color: cred.accessLevel === "admin" || cred.accessLevel === "system" || cred.accessLevel === "cloud_admin"
                      ? "var(--falcon-red)" : "var(--falcon-t3)",
                    background: cred.accessLevel === "admin" || cred.accessLevel === "system" || cred.accessLevel === "cloud_admin"
                      ? "rgba(239,68,68,0.15)" : "var(--falcon-panel-2)",
                  }}
                >
                  {cred.accessLevel}
                </span>
                <span style={{ fontSize: 10, color: "var(--falcon-t4)", flexShrink: 0 }}>{cred.source}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {context.compromisedAssets && context.compromisedAssets.length > 0 && (
        <div>
          <h4 style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8, display: "flex", alignItems: "center", gap: 8 }}>
            <Server style={{ width: 14, height: 14, color: "var(--falcon-red)" }} />
            Compromised Assets
          </h4>
          <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 240, overflowY: "auto" }}>
            {context.compromisedAssets.map((asset, idx) => (
              <div key={asset.id || idx} style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "6px 10px",
                borderRadius: 6,
                border: "1px solid var(--falcon-border)",
                fontSize: 12,
              }}>
                <span className="f-chip f-chip-gray" style={{ flexShrink: 0 }}>{asset.assetType}</span>
                <span style={{ color: "var(--falcon-t1)", fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{asset.name}</span>
                <span
                  style={{
                    marginLeft: "auto",
                    flexShrink: 0,
                    fontSize: 10,
                    fontWeight: 600,
                    padding: "2px 6px",
                    borderRadius: 4,
                    color: asset.accessLevel === "admin" || asset.accessLevel === "system"
                      ? "var(--falcon-red)" : "var(--falcon-t3)",
                    background: asset.accessLevel === "admin" || asset.accessLevel === "system"
                      ? "rgba(239,68,68,0.15)" : "var(--falcon-panel-2)",
                  }}
                >
                  {asset.accessLevel}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {context.domainsCompromised && context.domainsCompromised.length > 0 && (
        <div>
          <h4 style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Domains Breached</h4>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {context.domainsCompromised.map((domain, idx) => (
              <span key={idx} className="f-chip f-chip-gray">{domain}</span>
            ))}
          </div>
        </div>
      )}

      {context.attackPathSteps && context.attackPathSteps.length > 0 && (
        <div>
          <h4 style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Attack Path ({context.attackPathSteps.length} steps)</h4>
          <div style={{ overflowY: "auto", maxHeight: 200 }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {context.attackPathSteps.map((step, idx) => (
                <div key={step.stepId || idx} style={{
                  padding: "6px 10px",
                  borderRadius: 6,
                  border: "1px solid var(--falcon-border)",
                  fontSize: 12,
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                    <span style={{
                      fontSize: 10,
                      fontWeight: 600,
                      padding: "2px 6px",
                      borderRadius: 4,
                      color: "#a78bfa",
                      background: "rgba(167,139,250,0.15)",
                    }}>
                      {step.phaseName}
                    </span>
                    <span style={{ fontWeight: 600, color: "var(--falcon-t1)" }}>{step.technique}</span>
                  </div>
                  <p style={{ color: "var(--falcon-t4)", fontSize: 11, margin: 0 }}>{step.outcome}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function PhaseResultsDetail({ phaseResults }: { phaseResults: BreachPhaseResult[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (!phaseResults || phaseResults.length === 0) {
    return <p style={{ fontSize: 12, color: "var(--falcon-t4)" }}>No phase results yet</p>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {phaseResults.map((result) => {
        const meta = PHASE_META[result.phaseName];
        const PhaseIcon = meta?.icon || Shield;
        const isOpen = expanded === result.phaseName;
        const criticalFindings = result.findings?.filter(f => f.severity === "critical").length || 0;
        const highFindings = result.findings?.filter(f => f.severity === "high").length || 0;
        const sty = STATUS_STYLES[result.status] || STATUS_STYLES.pending;

        return (
          <div key={result.phaseName}>
            <button
              className={`f-collapse-trigger ${isOpen ? "open" : ""}`}
              onClick={() => setExpanded(isOpen ? null : result.phaseName)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "10px 12px",
                borderRadius: 6,
                border: "1px solid var(--falcon-border)",
                cursor: "pointer",
                transition: "background 0.15s ease",
                width: "100%",
                background: "transparent",
                color: "inherit",
                textAlign: "left",
                font: "inherit",
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "var(--falcon-panel-2)"; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
            >
              <PhaseIcon style={{ width: 14, height: 14, color: meta?.color || "var(--falcon-t4)" }} />
              <span style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)", flex: 1 }}>{meta?.label || result.phaseName}</span>
              <span style={{
                fontSize: 10,
                fontWeight: 600,
                padding: "2px 8px",
                borderRadius: 4,
                color: sty.color,
                background: sty.bg,
              }}>
                {result.status}
              </span>
              {result.findings && result.findings.length > 0 && (
                <span style={{ fontSize: 10, color: "var(--falcon-t4)" }}>
                  {result.findings.length} finding{result.findings.length !== 1 ? "s" : ""}
                </span>
              )}
              {criticalFindings > 0 && (
                <span className="f-chip f-chip-crit" style={{ fontSize: 9 }}>{criticalFindings} crit</span>
              )}
              {highFindings > 0 && (
                <span className="f-chip f-chip-high" style={{ fontSize: 9 }}>{highFindings} high</span>
              )}
              {result.durationMs && (
                <span style={{ fontSize: 10, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>{(result.durationMs / 1000).toFixed(1)}s</span>
              )}
              {isOpen ? <ChevronDown style={{ width: 14, height: 14, color: "var(--falcon-t3)" }} /> : <ChevronRight style={{ width: 14, height: 14, color: "var(--falcon-t3)" }} />}
            </button>
            {isOpen && (
              <div style={{ marginLeft: 28, marginTop: 8, display: "flex", flexDirection: "column", gap: 10, paddingBottom: 8 }}>
                {result.status === "skipped" && (
                  <div style={{
                    padding: 8,
                    background: "rgba(251,191,36,0.08)",
                    border: "1px solid rgba(251,191,36,0.2)",
                    borderRadius: 4,
                    fontSize: 11,
                    color: "#f59e0b",
                  }}>
                    Phase skipped: {result.error || "Prerequisite conditions not met (e.g., no compromised assets or credentials from prior phases)"}
                  </div>
                )}
                {result.error && result.status !== "skipped" && (
                  <div style={{
                    padding: 8,
                    background: "rgba(239,68,68,0.08)",
                    border: "1px solid rgba(239,68,68,0.2)",
                    borderRadius: 4,
                    fontSize: 11,
                    color: "var(--falcon-red)",
                  }}>
                    {result.error}
                  </div>
                )}
                {/* Sub-agent activity summary */}
                {(result as any).subAgentRuns && (result as any).subAgentRuns.length > 0 && (
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    <span style={{ fontSize: 10, fontWeight: 600, color: "var(--falcon-t2)" }}>Sub-Agent Activity</span>
                    {((result as any).subAgentRuns as Array<{ name: string; status: string; findingsCount?: number }>).map((run, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 10, padding: "4px 8px", borderRadius: 4, background: "var(--falcon-panel-2)" }}>
                        <span style={{ color: run.status === "completed" ? "var(--falcon-green)" : run.status === "failed" ? "var(--falcon-red)" : "var(--falcon-t3)", fontWeight: 600 }}>
                          {run.status === "completed" ? "✓" : run.status === "failed" ? "✗" : "⟳"}
                        </span>
                        <span style={{ color: "var(--falcon-t1)", flex: 1 }}>{run.name}</span>
                        {run.findingsCount !== undefined && <span style={{ color: "var(--falcon-t4)" }}>{run.findingsCount} findings</span>}
                      </div>
                    ))}
                  </div>
                )}

                {/* Agent Dispatch Summary (Parallel Micro-Agent stats) */}
                {(result as any).agentDispatchSummary && (
                  <div style={{
                    padding: "8px 12px",
                    borderRadius: 6,
                    background: "linear-gradient(135deg, rgba(99, 102, 241, 0.08), rgba(59, 130, 246, 0.08))",
                    border: "1px solid rgba(99, 102, 241, 0.2)",
                    fontSize: 11,
                  }}>
                    <span style={{ fontWeight: 600, color: "var(--falcon-t1)", fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5 }}>
                      Parallel Agent Dispatch
                    </span>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, marginTop: 6 }}>
                      <div>
                        <span style={{ color: "var(--falcon-t4)" }}>Agents: </span>
                        <span style={{ fontWeight: 600, color: "var(--falcon-t1)" }}>{(result as any).agentDispatchSummary.totalAgents}</span>
                      </div>
                      <div>
                        <span style={{ color: "var(--falcon-t4)" }}>Tier 1: </span>
                        <span style={{ fontWeight: 600, color: "var(--falcon-green)" }}>{(result as any).agentDispatchSummary.tier1Completed}</span>
                      </div>
                      <div>
                        <span style={{ color: "var(--falcon-t4)" }}>Findings: </span>
                        <span style={{ fontWeight: 600, color: (result as any).agentDispatchSummary.totalFindings > 0 ? "var(--falcon-red)" : "var(--falcon-t3)" }}>
                          {(result as any).agentDispatchSummary.totalFindings}
                        </span>
                      </div>
                      <div>
                        <span style={{ color: "var(--falcon-t4)" }}>Filtered: </span>
                        <span style={{ fontWeight: 600, color: "var(--falcon-t3)" }}>{(result as any).agentDispatchSummary.falsePositivesFiltered}</span>
                      </div>
                      <div style={{ gridColumn: "span 2" }}>
                        <span style={{ color: "var(--falcon-t4)" }}>Time: </span>
                        <span style={{ fontWeight: 600, color: "var(--falcon-t1)" }}>
                          {((result as any).agentDispatchSummary.executionTimeMs / 1000).toFixed(1)}s
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, fontSize: 11 }}>
                  <div style={{ padding: 8, borderRadius: 4, border: "1px solid var(--falcon-border)" }}>
                    <span style={{ color: "var(--falcon-t4)" }}>Input Credentials:</span>{" "}
                    <span style={{ fontWeight: 600, color: "var(--falcon-t1)" }}>{result.inputContext?.credentialCount ?? 0}</span>
                  </div>
                  <div style={{ padding: 8, borderRadius: 4, border: "1px solid var(--falcon-border)" }}>
                    <span style={{ color: "var(--falcon-t4)" }}>Input Assets:</span>{" "}
                    <span style={{ fontWeight: 600, color: "var(--falcon-t1)" }}>{result.inputContext?.compromisedAssetCount ?? 0}</span>
                  </div>
                  <div style={{ padding: 8, borderRadius: 4, border: "1px solid var(--falcon-border)" }}>
                    <span style={{ color: "var(--falcon-t4)" }}>Privilege:</span>{" "}
                    <span style={{ fontWeight: 600, color: "var(--falcon-t1)" }}>{result.inputContext?.privilegeLevel || "none"}</span>
                  </div>
                </div>

                {result.findings && result.findings.length > 0 && (
                  <div>
                    <h5 style={{ fontSize: 11, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Findings</h5>
                    <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 600, overflowY: "auto" }}>
                      {result.findings.map((finding, idx) => (
                        <div key={finding.id || idx} style={{
                          padding: 8,
                          borderRadius: 4,
                          border: "1px solid var(--falcon-border)",
                          fontSize: 11,
                        }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                            <span className={sevChip(finding.severity)}>{finding.severity}</span>
                            {finding.mitreId && (
                              <span style={{
                                fontSize: 10,
                                fontWeight: 600,
                                padding: "2px 6px",
                                borderRadius: 4,
                                color: "#a78bfa",
                                background: "rgba(167,139,250,0.15)",
                              }}>
                                {finding.mitreId}
                              </span>
                            )}
                            <span style={{ fontWeight: 600, color: "var(--falcon-t1)" }}>{finding.title}</span>
                          </div>
                          <p style={{ color: "var(--falcon-t4)", margin: 0 }}>{finding.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {result.safetyDecisions && result.safetyDecisions.length > 0 && (
                  <div>
                    <h5 style={{ fontSize: 11, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Safety Decisions</h5>
                    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      {result.safetyDecisions.map((dec, idx) => (
                        <div key={idx} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11 }}>
                          <span style={{
                            fontSize: 10,
                            fontWeight: 600,
                            padding: "2px 6px",
                            borderRadius: 4,
                            color: dec.decision === "ALLOW" ? "var(--falcon-green)" : "var(--falcon-red)",
                            background: dec.decision === "ALLOW" ? "rgba(16,185,129,0.15)" : "rgba(239,68,68,0.15)",
                          }}>
                            {dec.decision}
                          </span>
                          <span style={{ color: "var(--falcon-t4)" }}>{dec.action}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function ChainDetail({ chain }: { chain: BreachChain }) {
  const { toast } = useToast();
  const phaseResults = (chain.phaseResults || []) as BreachPhaseResult[];
  const context = chain.currentContext as BreachPhaseContext | null;
  const config = chain.config as any;
  const enabledPhases = config?.enabledPhases || [];

  // Real-time graph updates via WebSocket — additive live model
  const {
    latestGraph,
    liveEvents,
    nodes,
    edges,
    surfaceSignals,
    reasoningEvents,
    reasoningStream,
    canvasEvents,
    operatorSummary,
  } = useBreachChainUpdates({
    enabled: chain.status === "running" || chain.status === "paused",
    chainId: chain.id,
  });

  const displayGraph = latestGraph ?? (chain.unifiedAttackGraph as AttackGraph | null);
  const hasGraph = displayGraph && displayGraph.nodes?.length > 0;

  const [tab, setTab] = useState("canvas"); // Always default to canvas — shows live or synthesized
  const [showExport, setShowExport] = useState(false);
  const [highlightedNode, setHighlightedNode] = useState<string | undefined>(undefined);

  // Engagement Package seal mutation
  const sealMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/breach-chains/${chain.id}/seal`);
      return res.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: [`/api/breach-chains/${chain.id}`] });
      toast({
        title: "Engagement Package Sealed",
        description: `Risk Grade: ${data.package?.metadata?.riskGrade || "N/A"} — ${data.package?.metadata?.customerFindings ?? 0} findings delivered. ${data.deactivatedApiKeys ?? 0} API keys deactivated.`,
      });
    },
    onError: (error: Error) => {
      toast({ title: "Seal Failed", description: error.message, variant: "destructive" });
    },
  });

  // Download branded CISO PDF report from server-side renderer
  const downloadCISOPdf = async () => {
    try {
      const res = await apiRequest("GET", `/api/breach-chains/${chain.id}/report/pdf`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `OdinForge-CISO-Report-${chain.id}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      toast({ title: "Downloaded", description: "CISO PDF report downloaded." });
    } catch (error: any) {
      toast({ title: "Download Failed", description: error.message, variant: "destructive" });
    }
  };

  // Download branded Technical PDF report from server-side renderer
  const downloadTechnicalPdf = async () => {
    try {
      const res = await apiRequest("GET", `/api/breach-chains/${chain.id}/report/technical-pdf`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `OdinForge-Technical-Report-${chain.id}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      toast({ title: "Downloaded", description: "Technical PDF report downloaded." });
    } catch (error: any) {
      toast({ title: "Download Failed", description: error.message, variant: "destructive" });
    }
  };

  // Download engagement package component
  const downloadPackageComponent = async (component: string) => {
    try {
      // CISO report downloads as branded PDF, not raw JSON
      if (component === "ciso") {
        return downloadCISOPdf();
      }
      const res = await apiRequest("GET", `/api/breach-chains/${chain.id}/package?component=${component}`);
      if (component === "replay") {
        const html = await res.text();
        const blob = new Blob([html], { type: "text/html" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `odinforge-replay-${chain.id}.html`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `odinforge-${component}-${chain.id}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
      toast({ title: "Downloaded", description: `${component} package component downloaded.` });
    } catch (error: any) {
      toast({ title: "Download Failed", description: error.message, variant: "destructive" });
    }
  };

  const isSealed = !!(chain as any).engagementPackage;

  // Narrative query
  const { data: narrative } = useQuery({
    queryKey: [`/api/breach-chains/${chain.id}/narrative`],
    enabled: !!chain.id && chain.status === "completed",
  });

  // Remediation mutation
  const remediateMutation = useMutation({
    mutationFn: async ({ nodeId, status }: { nodeId: string; status: string }) => {
      await apiRequest("POST", `/api/breach-chains/${chain.id}/nodes/${nodeId}/remediate`, { status });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/breach-chains/${chain.id}`] });
      queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
      toast({ title: "Remediation Updated", description: "Node status has been updated." });
    },
    onError: (error: Error) => {
      toast({ title: "Update Failed", description: error.message, variant: "destructive" });
    },
  });

  // Remediation panel data
  const allNodes = displayGraph?.nodes || [];
  const criticalPathSet = new Set(displayGraph?.criticalPath || []);
  const criticalNodes = allNodes.filter(n => criticalPathSet.has(n.id));
  const fixedCount = criticalNodes.filter(n => n.remediationStatus === "verified_fixed").length;

  return (
    <div style={{ width: "100%" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div className="f-tab-bar" style={{ flex: 1 }}>
          <button className={`f-tab ${tab === "canvas" ? "active" : ""}`} onClick={() => setTab("canvas")}>Live Canvas</button>
          <button className={`f-tab ${tab === "phases" ? "active" : ""}`} onClick={() => setTab("phases")}>Phase Results</button>
        </div>
        <div style={{ display: "flex", gap: 8, flexShrink: 0, paddingLeft: 12 }}>
          <button
            className="f-btn f-btn-secondary"
            style={{ fontSize: 11, padding: "4px 10px" }}
            onClick={() => downloadCISOPdf()}
          >
            <FileBarChart style={{ width: 12, height: 12, marginRight: 5 }} />
            CISO PDF
          </button>
          <button
            className="f-btn f-btn-secondary"
            style={{ fontSize: 11, padding: "4px 10px" }}
            onClick={() => downloadTechnicalPdf()}
          >
            <FileBarChart style={{ width: 12, height: 12, marginRight: 5 }} />
            Technical PDF
          </button>
          <button
            className="f-btn f-btn-secondary"
            style={{ fontSize: 11, padding: "4px 10px" }}
            onClick={() => setShowExport(true)}
          >
            <Download style={{ width: 12, height: 12, marginRight: 5 }} />
            Board Export
          </button>
          {chain.status === "completed" && !isSealed && (
            <button
              className="f-btn f-btn-primary"
              style={{ fontSize: 11, padding: "4px 10px" }}
              disabled={sealMutation.isPending}
              onClick={() => {
                if (confirm("Seal this engagement package? This action is irreversible — all per-engagement API keys will be deactivated.")) {
                  sealMutation.mutate();
                }
              }}
            >
              <Lock style={{ width: 12, height: 12, marginRight: 5 }} />
              {sealMutation.isPending ? "Sealing..." : "Seal Package"}
            </button>
          )}
          {isSealed && (
            <div style={{ position: "relative" }} className="f-dropdown-wrap">
              <button
                className="f-btn f-btn-primary"
                style={{ fontSize: 11, padding: "4px 10px" }}
                onClick={() => setTab("package" as any)}
              >
                <Shield style={{ width: 12, height: 12, marginRight: 5 }} />
                Package ✓
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Export modal */}
      {showExport && (
        <BreachChainExport
          chain={chain}
          graph={displayGraph}
          narrative={narrative}
          onClose={() => setShowExport(false)}
        />
      )}

      {tab === "canvas" && (
        <CanvasPanel
          chainId={chain.id}
          canvasEvents={canvasEvents}
          reasoningStream={reasoningStream}
          operatorSummary={operatorSummary}
          chain={chain}
        />
      )}






      {(tab as string) === "package" && isSealed && (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div className="f-card" style={{ padding: 16 }}>
            <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12, display: "flex", alignItems: "center", gap: 8 }}>
              <Shield style={{ width: 16, height: 16, color: "var(--falcon-green)" }} />
              Sealed Engagement Package
            </h3>
            <p style={{ fontSize: 12, color: "var(--falcon-t3)", marginBottom: 16 }}>
              This engagement package has been sealed. All findings are backed by the OdinForge EvidenceContract — only PROVEN and CORROBORATED findings are included.
            </p>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10 }}>
              {[
                { key: "ciso", label: "CISO Report (PDF)", desc: "Risk Grade, breach narrative, compliance implications" },
                { key: "engineer", label: "Engineer Report", desc: "Full chain trace, HTTP evidence, remediation diffs" },
                { key: "evidence", label: "Evidence JSON", desc: "Machine-readable findings for SIEM ingestion" },
                { key: "defenders-mirror", label: "Defender's Mirror", desc: "Sigma, YARA, Splunk SPL detection rules" },
                { key: "replay", label: "Breach Replay", desc: "Self-contained HTML attack path visualization" },
              ].map(c => (
                <button
                  key={c.key}
                  className="f-card"
                  style={{ padding: 12, cursor: "pointer", textAlign: "left", border: "1px solid var(--falcon-b2)" }}
                  onClick={() => downloadPackageComponent(c.key)}
                >
                  <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>{c.label}</div>
                  <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>{c.desc}</div>
                  <div style={{ marginTop: 8, fontSize: 10, color: "var(--falcon-accent)" }}>
                    <Download style={{ width: 10, height: 10, marginRight: 4, display: "inline" }} />
                    Download
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Engagement Config Modal */}
    </div>
  );
}

function ChainCard({ chain, onView, onDelete, onResume, onAbort, onGenerateReport, compareMode, isSelectedForCompare, onToggleCompare }: {
  chain: BreachChain;
  onView: () => void;
  onDelete: () => void;
  onResume: () => void;
  onAbort: () => void;
  onGenerateReport?: () => void;
  compareMode?: boolean;
  isSelectedForCompare?: boolean;
  onToggleCompare?: () => void;
}) {
  const isRunning = chain.status === "running";
  const isPaused = chain.status === "paused";
  const isActive = isRunning || isPaused;
  const config = chain.config as any;
  const phaseResults = (chain.phaseResults || []) as BreachPhaseResult[];
  const completedPhases = phaseResults.filter(r => r.status === "completed").length;
  const totalPhases = config?.enabledPhases?.length || 6;
  const sty = STATUS_STYLES[chain.status] || STATUS_STYLES.pending;

  return (
    <div className="f-panel" style={{ position: "relative", overflow: "visible", outline: compareMode && isSelectedForCompare ? "2px solid var(--falcon-blue-hi)" : "none" }}>
      {compareMode && (
        <div
          style={{ position: "absolute", top: 10, right: 10, zIndex: 2, cursor: "pointer" }}
          onClick={(e) => { e.stopPropagation(); }}
        >
          <input
            type="checkbox"
            checked={!!isSelectedForCompare}
            onChange={(e) => { e.stopPropagation(); onToggleCompare?.(); }}
            style={{ width: 16, height: 16, cursor: "pointer" }}
          />
        </div>
      )}
      <div className="f-panel-head">
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8, flexWrap: "wrap", flex: 1 }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="f-panel-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Link2 style={{ width: 16, height: 16, color: "var(--falcon-red)", flexShrink: 0 }} />
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{chain.name}</span>
              <ChainSparkline chainId={chain.id} width={80} height={20} />
            </div>
            <p style={{ fontSize: 10, color: "var(--falcon-t4)", marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {chain.description || "Cross-domain breach chain"}
            </p>
          </div>
          <span style={{
            fontSize: 10,
            fontWeight: 600,
            padding: "2px 8px",
            borderRadius: 4,
            color: sty.color,
            background: sty.bg,
            display: "inline-flex",
            alignItems: "center",
            gap: 4,
            flexShrink: 0,
          }}>
            {isRunning && <Loader2 style={{ width: 10, height: 10 }} className="animate-spin" />}
            {chain.status}
          </span>
        </div>
      </div>
      <div style={{ padding: "12px 16px" }}>
        {isActive && (
          <div style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--falcon-t4)", marginBottom: 6 }}>
              <span>{chain.currentPhase ? PHASE_META[chain.currentPhase]?.label || chain.currentPhase : "Starting..."}</span>
              <span style={{ fontFamily: "var(--font-mono)" }}>{chain.progress}%</span>
            </div>
            <div className="f-tb-track" style={{ height: 4 }}>
              <div className="f-tb-fill f-tf-b" style={{ width: `${chain.progress}%` }} />
            </div>
          </div>
        )}

        {chain.status === "completed" && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: 14 }}>
            <div style={{ textAlign: "center", padding: 8, borderRadius: 6, background: "var(--falcon-panel-2)" }}>
              <div style={{
                fontSize: 20,
                fontWeight: 700,
                fontFamily: "var(--font-mono)",
                color: (chain.overallRiskScore ?? 0) >= 70 ? "var(--falcon-red)" :
                  (chain.overallRiskScore ?? 0) >= 40 ? "var(--falcon-orange)" : "var(--falcon-green)",
              }}>
                {chain.overallRiskScore ?? "\u2014"}
              </div>
              <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Risk Score</div>
            </div>
            <div style={{ textAlign: "center", padding: 8, borderRadius: 6, background: "var(--falcon-panel-2)" }}>
              <div style={{ fontSize: 20, fontWeight: 700, fontFamily: "var(--font-mono)", color: "var(--falcon-yellow)" }}>
                {chain.totalCredentialsHarvested ?? 0}
              </div>
              <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Credentials</div>
            </div>
            <div style={{ textAlign: "center", padding: 8, borderRadius: 6, background: "var(--falcon-panel-2)" }}>
              <div style={{ fontSize: 20, fontWeight: 700, fontFamily: "var(--font-mono)", color: "var(--falcon-red)" }}>
                {chain.totalAssetsCompromised ?? 0}
              </div>
              <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Assets</div>
            </div>
            <div style={{ textAlign: "center", padding: 8, borderRadius: 6, background: "var(--falcon-panel-2)" }}>
              <div style={{ fontSize: 20, fontWeight: 700, fontFamily: "var(--font-mono)", color: "#a78bfa" }}>
                {completedPhases}/{totalPhases}
              </div>
              <div style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Phases</div>
            </div>
          </div>
        )}

        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          <button className="f-btn f-btn-primary" style={{ fontSize: 11, padding: "4px 10px" }} onClick={onView}>
            <Eye style={{ width: 13, height: 13, marginRight: 4 }} />
            View Details
          </button>
          {chain.status === "completed" && onGenerateReport && (
            <button className="f-btn f-btn-secondary" style={{ fontSize: 11, padding: "4px 10px" }} onClick={onGenerateReport}>
              <FileBarChart style={{ width: 13, height: 13, marginRight: 4 }} />
              Report
            </button>
          )}
          {isPaused && (
            <button className="f-btn f-btn-secondary" style={{ fontSize: 11, padding: "4px 10px" }} onClick={onResume}>
              <Play style={{ width: 13, height: 13, marginRight: 4 }} />
              Resume
            </button>
          )}
          {isRunning && (
            <button className="f-btn f-btn-secondary" style={{ fontSize: 11, padding: "4px 10px" }} onClick={onAbort}>
              <StopCircle style={{ width: 13, height: 13, marginRight: 4 }} />
              Abort
            </button>
          )}
          {!isActive && (
            <button className="f-btn f-btn-ghost" style={{ fontSize: 11, padding: "4px 10px" }} onClick={onDelete}>
              <Trash2 style={{ width: 13, height: 13 }} />
            </button>
          )}
        </div>

        <div style={{ marginTop: 10, fontSize: 10, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>
          Started: {chain.startedAt ? new Date(chain.startedAt).toLocaleString() : "Not started"}
          {chain.durationMs && (
            <span style={{ marginLeft: 8 }}>Duration: {(chain.durationMs / 1000).toFixed(0)}s</span>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Main Page
// ============================================================================

export default function BreachChains() {
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const { hasPermission } = useAuth();
  const canCreate = hasPermission("evaluations:create");
  const canDelete = hasPermission("evaluations:delete");

  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [selectedChain, setSelectedChain] = useState<BreachChain | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const [compareMode, setCompareMode] = useState(false);
  const [selectedForCompare, setSelectedForCompare] = useState<string[]>([]);
  const [showComparison, setShowComparison] = useState(false);
  const [viewMode, setViewMode] = useState<"chains" | "portfolio">("chains");

  // Form state
  const [formData, setFormData] = useState({
    name: "",
    description: "",
    assetIds: "",
    targetUrl: "",
    executionMode: "safe" as "safe" | "simulation" | "live",
    pauseOnCritical: false,
    enabledPhases: [
      "application_compromise",
      "credential_extraction",
      "cloud_iam_escalation",
      "container_k8s_breakout",
      "lateral_movement",
      "impact_assessment",
    ] as string[],
    // Engagement configuration
    adversaryProfile: "generic",
    noiseLevel: "moderate" as "silent" | "moderate" | "aggressive",
    evasionPosture: "basic" as "none" | "basic" | "advanced",
    maxAssetsToTouch: 20,
    credentialReusePolicy: "reuse_allowed" as "reuse_allowed" | "report_only",
  });
  const [showEngConfig, setShowEngConfig] = useState(false);

  const { data: chains = [], isLoading, refetch } = useQuery<BreachChain[]>({
    queryKey: ["/api/breach-chains"],
    refetchInterval: 5000,
  });

  // WebSocket live updates — auto-invalidates queries on breach chain progress
  const hasRunningChains = chains.some(c => c.status === "running");
  useBreachChainUpdates({
    enabled: hasRunningChains,
    onComplete: () => {
      toast({ title: "Breach Chain Complete", description: "A breach chain has finished execution." });
    },
  });

  const createMutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      const assetIds = data.assetIds
        .split(",")
        .map(s => s.trim())
        .filter(Boolean);

      // If targetUrl is provided and no explicit assetIds, use the URL as the asset
      const finalAssetIds = assetIds.length > 0 ? assetIds : data.targetUrl.trim() ? [data.targetUrl.trim()] : [];

      if (finalAssetIds.length === 0) {
        throw new Error("At least one asset ID or target URL is required");
      }

      const payload = {
        name: data.name,
        description: data.description || undefined,
        assetIds: finalAssetIds,
        targetDomains: ["application", "cloud", "k8s", "network"],
        config: {
          enabledPhases: data.enabledPhases,
          executionMode: data.executionMode,
          pauseOnCritical: data.pauseOnCritical,
          adversaryProfile: data.adversaryProfile,
          noiseLevel: data.noiseLevel,
          evasionPosture: data.evasionPosture,
          maxAssetsToTouch: data.maxAssetsToTouch,
          credentialReusePolicy: data.credentialReusePolicy,
        },
      };

      const res = await apiRequest("POST", "/api/breach-chains", payload);
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
      setIsCreateOpen(false);
      resetForm();
      toast({
        title: "Breach Chain Started",
        description: `Chain ${data.chainId} is now running through ${data.phases?.length || 6} phases.`,
      });
    },
    onError: (error: Error) => {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    },
  });

  const resumeMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/breach-chains/${id}/resume`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
      toast({ title: "Chain Resumed" });
    },
    onError: (error: Error) => {
      toast({ title: "Error", description: error.message, variant: "destructive" });
    },
  });

  const abortMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("POST", `/api/breach-chains/${id}/abort`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
      toast({ title: "Chain Aborted" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/breach-chains/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
      setSelectedChain(null);
      toast({ title: "Chain Deleted" });
    },
  });

  const generateReportMutation = useMutation({
    mutationFn: async (chainId: string) => {
      const res = await apiRequest("POST", "/api/reports/generate", {
        breachChainId: chainId,
      });
      return res.json();
    },
    onSuccess: () => {
      toast({
        title: "Report Generated",
        description: "Breach chain report is ready. Redirecting to Reports...",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/reports"] });
      setTimeout(() => navigate("/reports"), 1000);
    },
    onError: (error: Error) => {
      toast({ title: "Report Failed", description: error.message, variant: "destructive" });
    },
  });

  const resetForm = () => {
    setFormData({
      name: "",
      description: "",
      assetIds: "",
      targetUrl: "",
      executionMode: "safe",
      pauseOnCritical: false,
      enabledPhases: [
        "application_compromise",
        "credential_extraction",
        "cloud_iam_escalation",
        "container_k8s_breakout",
        "lateral_movement",
        "impact_assessment",
      ],
      adversaryProfile: "generic",
      noiseLevel: "moderate",
      evasionPosture: "basic",
      maxAssetsToTouch: 20,
      credentialReusePolicy: "reuse_allowed",
    });
    setShowAdvanced(false);
    setShowEngConfig(false);
  };

  const togglePhase = (phase: string) => {
    setFormData(prev => ({
      ...prev,
      enabledPhases: prev.enabledPhases.includes(phase)
        ? prev.enabledPhases.filter(p => p !== phase)
        : [...prev.enabledPhases, phase],
    }));
  };

  // If viewing a single chain, auto-refresh its data
  const { data: detailChain } = useQuery<BreachChain>({
    queryKey: [`/api/breach-chains/${selectedChain?.id}`],
    enabled: !!selectedChain,
    refetchInterval: selectedChain?.status === "running" ? 3000 : 15000,
  });

  const displayChain = detailChain || selectedChain;

  const inputStyle: React.CSSProperties = {
    width: "100%",
    padding: "8px 12px",
    background: "var(--falcon-panel)",
    border: "1px solid var(--falcon-border)",
    borderRadius: 6,
    color: "var(--falcon-t1)",
    fontSize: 12,
    outline: "none",
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Page Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
        <div>
          <h1 style={{ fontSize: 18, fontWeight: 700, color: "var(--falcon-t1)", margin: 0 }}>Breach Chain Intelligence</h1>
          <p style={{ fontSize: 11, color: "var(--falcon-t3)", marginTop: 4, fontFamily: "var(--font-mono)" }}>
            Real attack paths. Verified exploitation. Proven risk.
          </p>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <button className="f-btn f-btn-secondary" onClick={() => refetch()}>
            <RefreshCw style={{ width: 13, height: 13, marginRight: 6 }} />
            Refresh
          </button>
          <button
            className={`f-btn ${compareMode ? "f-btn-primary" : "f-btn-ghost"}`}
            onClick={() => { setCompareMode(!compareMode); setSelectedForCompare([]); }}
          >
            {compareMode ? `Comparing (${selectedForCompare.length}/2)` : "Compare Chains"}
          </button>
          {compareMode && selectedForCompare.length === 2 && (
            <button className="f-btn f-btn-primary" onClick={() => setShowComparison(true)}>
              Compare Now
            </button>
          )}
          <button
            className="f-btn f-btn-primary"
            disabled={!canCreate}
            onClick={() => setIsCreateOpen(true)}
          >
            {canCreate ? <Play style={{ width: 13, height: 13, marginRight: 6 }} /> : <Lock style={{ width: 13, height: 13, marginRight: 6 }} />}
            Start Breach Chain
          </button>
        </div>
      </div>

      {/* View mode toggle */}
      <div style={{ display: "flex", gap: 4, background: "var(--falcon-panel-2)", borderRadius: 6, padding: 3, width: "fit-content" }}>
        <button
          onClick={() => setViewMode("chains")}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            padding: "5px 12px",
            borderRadius: 4,
            border: "none",
            fontSize: 11,
            fontWeight: 600,
            cursor: "pointer",
            transition: "all 0.15s ease",
            color: viewMode === "chains" ? "var(--falcon-t1)" : "var(--falcon-t4)",
            background: viewMode === "chains" ? "var(--falcon-panel)" : "transparent",
          }}
        >
          <List style={{ width: 13, height: 13 }} />
          Chain List
        </button>
        <button
          onClick={() => setViewMode("portfolio")}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            padding: "5px 12px",
            borderRadius: 4,
            border: "none",
            fontSize: 11,
            fontWeight: 600,
            cursor: "pointer",
            transition: "all 0.15s ease",
            color: viewMode === "portfolio" ? "var(--falcon-t1)" : "var(--falcon-t4)",
            background: viewMode === "portfolio" ? "var(--falcon-panel)" : "transparent",
          }}
        >
          <LayoutGrid style={{ width: 13, height: 13 }} />
          Portfolio
        </button>
      </div>

      {/* Portfolio view */}
      {viewMode === "portfolio" && (
        <PortfolioPanel
          onSelectRun={(chainId) => {
            const chain = chains.find((c) => c.id === chainId);
            if (chain) {
              setSelectedChain(chain);
              setViewMode("chains");
            }
          }}
        />
      )}

      {/* Chains view */}
      {viewMode === "chains" && <>

      {/* Create Breach Chain Modal */}
      {isCreateOpen && (
        <div className="f-modal-overlay" onClick={() => { setIsCreateOpen(false); resetForm(); }}>
          <div className="f-modal f-modal-lg" onClick={e => e.stopPropagation()} style={{ maxHeight: "85vh", overflowY: "auto" }}>
            <div className="f-modal-head">
              <h2 className="f-modal-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Link2 style={{ width: 16, height: 16, color: "var(--falcon-red)" }} />
                Start Cross-Domain Breach Chain
              </h2>
              <p className="f-modal-desc">
                Launch a multi-phase breach simulation that chains exploits across security domains
              </p>
            </div>

            <div className="f-modal-body">
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Chain Name</label>
                  <input
                    style={inputStyle}
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="Q1 2026 Full Breach Simulation"
                  />
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Target URL</label>
                  <input
                    style={inputStyle}
                    value={formData.targetUrl}
                    onChange={(e) => setFormData({ ...formData, targetUrl: e.target.value })}
                    placeholder="https://target-app.example.com"
                  />
                  <p style={{ fontSize: 10, color: "var(--falcon-t4)" }}>
                    The Active Exploit Engine will fire real payloads against this target in Phase 1
                  </p>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Asset IDs (optional, comma-separated)</label>
                  <input
                    style={inputStyle}
                    value={formData.assetIds}
                    onChange={(e) => setFormData({ ...formData, assetIds: e.target.value })}
                    placeholder="web-server-001, api-gateway-002"
                  />
                  <p style={{ fontSize: 10, color: "var(--falcon-t4)" }}>
                    If left empty, the target URL will be used as the primary asset
                  </p>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Description (optional)</label>
                  <textarea
                    style={{ ...inputStyle, resize: "vertical", minHeight: 48 }}
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    placeholder="Validate full attack chain from app compromise to domain admin..."
                    rows={2}
                  />
                </div>

                {/* Execution Mode — always visible, required choice */}
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Execution Mode</label>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8 }}>
                    {([
                      { value: "safe", label: "Safe", desc: "Passive recon only", color: "#22c55e", bg: "rgba(34,197,94,0.08)", border: "rgba(34,197,94,0.3)" },
                      { value: "simulation", label: "Simulation", desc: "Safe payloads, no damage", color: "#f97316", bg: "rgba(249,115,22,0.08)", border: "rgba(249,115,22,0.3)" },
                      { value: "live", label: "Live", desc: "Real exploit payloads", color: "#ef4444", bg: "rgba(239,68,68,0.08)", border: "rgba(239,68,68,0.3)" },
                    ] as const).map(mode => (
                      <button
                        key={mode.value}
                        type="button"
                        onClick={() => setFormData({ ...formData, executionMode: mode.value as any })}
                        style={{
                          padding: "10px 8px", borderRadius: 6, cursor: "pointer",
                          background: formData.executionMode === mode.value ? mode.bg : "transparent",
                          border: `2px solid ${formData.executionMode === mode.value ? mode.border : "var(--falcon-border)"}`,
                          display: "flex", flexDirection: "column", alignItems: "center", gap: 4,
                          transition: "all 0.15s",
                        }}
                      >
                        <span style={{ fontSize: 12, fontWeight: 700, color: formData.executionMode === mode.value ? mode.color : "var(--falcon-t2)" }}>{mode.label}</span>
                        <span style={{ fontSize: 9, color: "var(--falcon-t4)" }}>{mode.desc}</span>
                      </button>
                    ))}
                  </div>
                  {formData.executionMode === "live" && (
                    <div style={{ padding: "8px 10px", background: "rgba(239,68,68,0.06)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: 4, fontSize: 10, color: "#fca5a5", marginTop: 4 }}>
                      ⚡ <strong>LIVE MODE</strong> — Real exploit payloads will be fired against the target. Ensure you have authorization.
                    </div>
                  )}
                </div>

                <div>
                  <button
                    className={`f-collapse-trigger ${showAdvanced ? "open" : ""}`}
                    onClick={() => setShowAdvanced(!showAdvanced)}
                    style={{
                      width: "100%",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      fontSize: 12,
                      padding: "8px 12px",
                      background: "transparent",
                      border: "1px solid var(--falcon-border)",
                      borderRadius: 6,
                      color: "var(--falcon-t1)",
                      cursor: "pointer",
                    }}
                  >
                    <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <Settings2 style={{ width: 14, height: 14 }} />
                      Phase Selection & Options
                    </span>
                    <ChevronDown style={{ width: 14, height: 14, transition: "transform 0.2s", transform: showAdvanced ? "rotate(180deg)" : "rotate(0deg)" }} />
                  </button>
                  {showAdvanced && (
                    <div style={{ display: "flex", flexDirection: "column", gap: 16, paddingTop: 16 }}>

                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                        <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Pause on Critical Findings</label>
                        <button
                          className={`f-switch ${formData.pauseOnCritical ? "on" : ""}`}
                          onClick={() => setFormData({ ...formData, pauseOnCritical: !formData.pauseOnCritical })}
                        />
                      </div>

                      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                        <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Enabled Phases</label>
                        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                          {Object.entries(PHASE_META).map(([key, meta]) => {
                            const PhaseIcon = meta.icon;
                            const enabled = formData.enabledPhases.includes(key);
                            return (
                              <div
                                key={key}
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  gap: 10,
                                  padding: 8,
                                  borderRadius: 6,
                                  border: `1px solid ${enabled ? "var(--falcon-blue-hi)" : "var(--falcon-border)"}`,
                                  background: enabled ? "rgba(59,130,246,0.05)" : "transparent",
                                  cursor: "pointer",
                                  opacity: enabled ? 1 : 0.5,
                                  transition: "all 0.15s ease",
                                }}
                                onClick={() => togglePhase(key)}
                              >
                                <button
                                  className={`f-switch ${enabled ? "on" : ""}`}
                                  onClick={(e) => { e.stopPropagation(); togglePhase(key); }}
                                />
                                <PhaseIcon style={{ width: 14, height: 14, color: meta.color }} />
                                <div>
                                  <span style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>{meta.label}</span>
                                  <p style={{ fontSize: 10, color: "var(--falcon-t4)", margin: 0 }}>{meta.description}</p>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Engagement Configuration — adversary profile, noise, evasion */}
                <div>
                  <button
                    className={`f-collapse-trigger ${showEngConfig ? "open" : ""}`}
                    onClick={() => setShowEngConfig(!showEngConfig)}
                    style={{
                      width: "100%",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      fontSize: 12,
                      padding: "8px 12px",
                      background: "transparent",
                      border: "1px solid var(--falcon-border)",
                      borderRadius: 6,
                      color: "var(--falcon-t1)",
                      cursor: "pointer",
                    }}
                  >
                    <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <Crosshair style={{ width: 14, height: 14 }} />
                      Engagement Configuration
                    </span>
                    <ChevronDown style={{ width: 14, height: 14, transition: "transform 0.2s", transform: showEngConfig ? "rotate(180deg)" : "rotate(0deg)" }} />
                  </button>
                  {showEngConfig && (
                    <div style={{ display: "flex", flexDirection: "column", gap: 16, paddingTop: 16 }}>
                      {/* Adversary Profile */}
                      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                        <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Threat Actor Profile</label>
                        <select
                          style={{ ...inputStyle, cursor: "pointer" }}
                          value={formData.adversaryProfile}
                          onChange={(e) => setFormData({ ...formData, adversaryProfile: e.target.value })}
                        >
                          <option value="generic">Generic Threat Actor</option>
                          <option value="APT29">APT29 — Cozy Bear (Russian SVR)</option>
                          <option value="APT41">APT41 (Chinese state-sponsored)</option>
                          <option value="Lazarus">Lazarus Group (DPRK)</option>
                          <option value="FIN7">FIN7 (Financially motivated)</option>
                        </select>
                      </div>

                      {/* Noise Level */}
                      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                        <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Noise Level</label>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8 }}>
                          {([
                            { value: "silent", label: "Silent", desc: "Minimal traffic", color: "#22c55e" },
                            { value: "moderate", label: "Moderate", desc: "Balanced approach", color: "#f97316" },
                            { value: "aggressive", label: "Aggressive", desc: "Max coverage", color: "#ef4444" },
                          ] as const).map(opt => (
                            <button
                              key={opt.value}
                              type="button"
                              onClick={() => setFormData({ ...formData, noiseLevel: opt.value })}
                              style={{
                                padding: "8px 6px", borderRadius: 6, cursor: "pointer",
                                background: formData.noiseLevel === opt.value ? `${opt.color}11` : "transparent",
                                border: `2px solid ${formData.noiseLevel === opt.value ? `${opt.color}55` : "var(--falcon-border)"}`,
                                display: "flex", flexDirection: "column", alignItems: "center", gap: 2,
                              }}
                            >
                              <span style={{ fontSize: 11, fontWeight: 700, color: formData.noiseLevel === opt.value ? opt.color : "var(--falcon-t2)" }}>{opt.label}</span>
                              <span style={{ fontSize: 9, color: "var(--falcon-t4)" }}>{opt.desc}</span>
                            </button>
                          ))}
                        </div>
                      </div>

                      {/* Evasion Posture */}
                      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                        <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Evasion Posture</label>
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8 }}>
                          {([
                            { value: "none", label: "None", desc: "No evasion" },
                            { value: "basic", label: "Basic", desc: "Header rotation" },
                            { value: "advanced", label: "Advanced", desc: "Full TTP evasion" },
                          ] as const).map(opt => (
                            <button
                              key={opt.value}
                              type="button"
                              onClick={() => setFormData({ ...formData, evasionPosture: opt.value })}
                              style={{
                                padding: "8px 6px", borderRadius: 6, cursor: "pointer",
                                background: formData.evasionPosture === opt.value ? "rgba(59,130,246,0.08)" : "transparent",
                                border: `2px solid ${formData.evasionPosture === opt.value ? "rgba(59,130,246,0.3)" : "var(--falcon-border)"}`,
                                display: "flex", flexDirection: "column", alignItems: "center", gap: 2,
                              }}
                            >
                              <span style={{ fontSize: 11, fontWeight: 700, color: formData.evasionPosture === opt.value ? "var(--falcon-blue-hi)" : "var(--falcon-t2)" }}>{opt.label}</span>
                              <span style={{ fontSize: 9, color: "var(--falcon-t4)" }}>{opt.desc}</span>
                            </button>
                          ))}
                        </div>
                      </div>

                      {/* Max Assets + Credential Reuse */}
                      <div style={{ display: "flex", gap: 12 }}>
                        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 6 }}>
                          <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Max Assets</label>
                          <input
                            type="number"
                            style={inputStyle}
                            value={formData.maxAssetsToTouch}
                            min={1}
                            max={100}
                            onChange={(e) => setFormData({ ...formData, maxAssetsToTouch: parseInt(e.target.value) || 20 })}
                          />
                        </div>
                        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 6 }}>
                          <label style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Credential Reuse</label>
                          <select
                            style={{ ...inputStyle, cursor: "pointer" }}
                            value={formData.credentialReusePolicy}
                            onChange={(e) => setFormData({ ...formData, credentialReusePolicy: e.target.value as any })}
                          >
                            <option value="reuse_allowed">Reuse Allowed</option>
                            <option value="report_only">Report Only</option>
                          </select>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                <div style={{ background: "var(--falcon-panel-2)", padding: 12, borderRadius: 6 }}>
                  <h4 style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)", display: "flex", alignItems: "center", gap: 8, margin: 0, marginBottom: 8 }}>
                    <Target style={{ width: 14, height: 14 }} />
                    What this breach chain does:
                  </h4>
                  <ul style={{ margin: 0, paddingLeft: 16, display: "flex", flexDirection: "column", gap: 4, fontSize: 11 }}>
                    <li style={{ color: "var(--falcon-red)" }}>Phase 1: Fires active exploit payloads (SQLi, XSS, SSRF, auth bypass...)</li>
                    <li style={{ color: "var(--falcon-yellow)" }}>Phase 2: Extracts credentials from compromised responses</li>
                    <li style={{ color: "var(--falcon-blue-hi)" }}>Phase 3: Escalates IAM privileges in cloud environments</li>
                    <li style={{ color: "#a78bfa" }}>Phase 4: Attempts K8s RBAC abuse and container breakout</li>
                    <li style={{ color: "var(--falcon-blue-hi)" }}>Phase 5: Pivots laterally using harvested credentials</li>
                    <li style={{ color: "var(--falcon-orange)" }}>Phase 6: Aggregates full business impact analysis</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="f-modal-footer">
              <button className="f-btn f-btn-ghost" onClick={() => { setIsCreateOpen(false); resetForm(); }}>
                Cancel
              </button>
              <button
                className="f-btn f-btn-primary"
                style={{ flex: 1, justifyContent: "center" }}
                onClick={() => createMutation.mutate(formData)}
                disabled={!formData.name.trim() || (!formData.assetIds.trim() && !formData.targetUrl.trim()) || createMutation.isPending}
              >
                {createMutation.isPending ? (
                  <><Loader2 style={{ width: 14, height: 14, marginRight: 8 }} className="animate-spin" />Starting...</>
                ) : (
                  <><Play style={{ width: 14, height: 14, marginRight: 8 }} />Launch Breach Chain</>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {selectedChain && displayChain ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <button className="f-btn f-btn-secondary" onClick={() => setSelectedChain(null)}>
              Back to List
            </button>
            {displayChain.status === "completed" && (
              <button
                className="f-btn f-btn-secondary"
                onClick={() => generateReportMutation.mutate(displayChain.id)}
                disabled={generateReportMutation.isPending}
              >
                {generateReportMutation.isPending ? (
                  <Loader2 style={{ width: 13, height: 13, marginRight: 4 }} className="animate-spin" />
                ) : (
                  <FileBarChart style={{ width: 13, height: 13, marginRight: 4 }} />
                )}
                Generate Report
              </button>
            )}
            {displayChain.status === "paused" && (
              <button className="f-btn f-btn-secondary" onClick={() => resumeMutation.mutate(displayChain.id)}>
                <Play style={{ width: 13, height: 13, marginRight: 4 }} /> Resume
              </button>
            )}
            {displayChain.status === "running" && (
              <button className="f-btn f-btn-secondary" onClick={() => abortMutation.mutate(displayChain.id)}>
                <StopCircle style={{ width: 13, height: 13, marginRight: 4 }} /> Abort
              </button>
            )}
          </div>
          <div className="f-panel">
            <div className="f-panel-head">
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16, flexWrap: "wrap", flex: 1 }}>
                <div>
                  <div className="f-panel-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <Link2 style={{ width: 16, height: 16, color: "var(--falcon-red)" }} />
                    {displayChain.name}
                  </div>
                  <p style={{ fontSize: 10, color: "var(--falcon-t4)", margin: "2px 0 0 0" }}>{displayChain.description || "Cross-domain breach chain"}</p>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{
                    fontSize: 10,
                    fontWeight: 600,
                    padding: "2px 8px",
                    borderRadius: 4,
                    color: (STATUS_STYLES[displayChain.status] || STATUS_STYLES.pending).color,
                    background: (STATUS_STYLES[displayChain.status] || STATUS_STYLES.pending).bg,
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 4,
                  }}>
                    {displayChain.status === "running" && <Loader2 style={{ width: 10, height: 10 }} className="animate-spin" />}
                    {displayChain.status}
                  </span>
                  {displayChain.status === "running" && (
                    <span style={{ fontSize: 11, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>{displayChain.progress}%</span>
                  )}
                </div>
              </div>
            </div>
            {displayChain.status === "running" && (
              <div style={{ padding: "0 16px 4px 16px" }}>
                <div className="f-tb-track" style={{ height: 4 }}>
                  <div className="f-tb-fill f-tf-b" style={{ width: `${displayChain.progress}%` }} />
                </div>
              </div>
            )}
            <div style={{ padding: "12px 16px" }}>
              <ChainDetail chain={displayChain} />
            </div>
          </div>
        </div>
      ) : (
        <>
          {isLoading ? (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "48px 0" }}>
              <Loader2 style={{ width: 28, height: 28, color: "var(--falcon-t4)" }} className="animate-spin" />
            </div>
          ) : chains.length === 0 ? (
            <div className="f-panel">
              <div style={{ padding: "48px 0", textAlign: "center" }}>
                <Link2 style={{ width: 40, height: 40, color: "var(--falcon-t4)", margin: "0 auto 16px auto", display: "block" }} />
                <h3 style={{ fontSize: 14, fontWeight: 600, color: "var(--falcon-t1)", margin: 0 }}>No Breach Chains Yet</h3>
                <p style={{ fontSize: 11, color: "var(--falcon-t4)", marginTop: 6 }}>
                  Start a cross-domain breach chain to validate your full attack surface
                </p>
                <button className="f-btn f-btn-primary" style={{ marginTop: 16 }} onClick={() => setIsCreateOpen(true)} disabled={!canCreate}>
                  <Play style={{ width: 13, height: 13, marginRight: 6 }} />
                  Start Your First Breach Chain
                </button>
              </div>
            </div>
          ) : (
            <div style={{ display: "grid", gap: 16, gridTemplateColumns: "repeat(auto-fill, minmax(380px, 1fr))" }}>
              {chains.map((chain) => (
                <ChainCard
                  key={chain.id}
                  chain={chain}
                  onView={() => setSelectedChain(chain)}
                  onDelete={() => canDelete && deleteMutation.mutate(chain.id)}
                  onResume={() => resumeMutation.mutate(chain.id)}
                  onAbort={() => abortMutation.mutate(chain.id)}
                  onGenerateReport={() => generateReportMutation.mutate(chain.id)}
                  compareMode={compareMode}
                  isSelectedForCompare={selectedForCompare.includes(chain.id)}
                  onToggleCompare={() => {
                    setSelectedForCompare(prev =>
                      prev.includes(chain.id)
                        ? prev.filter(id => id !== chain.id)
                        : prev.length < 2
                          ? [...prev, chain.id]
                          : prev
                    );
                  }}
                />
              ))}
            </div>
          )}
        </>
      )}

      {showComparison && selectedForCompare.length === 2 && (
        <ChainComparison
          chainA={{ id: selectedForCompare[0], name: chains.find(c => c.id === selectedForCompare[0])?.name ?? "" }}
          chainB={{ id: selectedForCompare[1], name: chains.find(c => c.id === selectedForCompare[1])?.name ?? "" }}
          onClose={() => { setShowComparison(false); setCompareMode(false); setSelectedForCompare([]); }}
        />
      )}

      </>}
      {/* End of chains view conditional */}
    </div>
  );
}
