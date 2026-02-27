import { useState, lazy, Suspense } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import {
  Target,
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  AlertTriangle,
  Network,
  Shield,
  FileText,
  Trash2,
  Eye,
  RefreshCw,
  TrendingUp,
  AlertCircle,
  Globe,
} from "lucide-react";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { FullAssessment } from "@shared/schema";

const ApprovalsPanel = lazy(() => import("@/pages/Approvals"));
const SandboxPanel = lazy(() => import("@/pages/Sandbox"));
const ExternalReconPanel = lazy(() => import("@/components/ExternalRecon").then(m => ({ default: m.ExternalRecon })));

const statusColors: Record<string, { color: string; bg: string; border: string }> = {
  pending:                { color: "var(--falcon-t3)", bg: "rgba(255,255,255,0.03)", border: "var(--falcon-border)" },
  reconnaissance:         { color: "var(--falcon-blue-hi)", bg: "var(--falcon-blue-dim)", border: "rgba(59,130,246,0.3)" },
  vulnerability_analysis: { color: "var(--falcon-yellow)", bg: "var(--falcon-yellow-dim)", border: "rgba(234,179,8,0.25)" },
  attack_synthesis:       { color: "#a78bfa", bg: "rgba(167,139,250,0.1)", border: "rgba(167,139,250,0.3)" },
  lateral_analysis:       { color: "var(--falcon-blue-hi)", bg: "var(--falcon-blue-dim)", border: "rgba(59,130,246,0.3)" },
  impact_assessment:      { color: "var(--falcon-orange)", bg: "var(--falcon-orange-dim)", border: "rgba(242,140,40,0.3)" },
  completed:              { color: "var(--falcon-green)", bg: "var(--falcon-green-dim)", border: "rgba(34,197,94,0.25)" },
  failed:                 { color: "var(--falcon-red)", bg: "var(--falcon-red-dim)", border: "var(--falcon-red-border)" },
};

const statusLabels: Record<string, string> = {
  pending: "Pending",
  reconnaissance: "Reconnaissance",
  vulnerability_analysis: "Vulnerability Analysis",
  attack_synthesis: "Attack Synthesis",
  lateral_analysis: "Lateral Movement Analysis",
  impact_assessment: "Impact Assessment",
  completed: "Completed",
  failed: "Failed",
};

function StatusChip({ status }: { status: string }) {
  const s = statusColors[status] || statusColors.pending;
  return (
    <span className="f-chip" style={{ color: s.color, background: s.bg, borderColor: s.border }}>
      {statusLabels[status] || status}
    </span>
  );
}

function sevChip(level: string) {
  if (level === "critical") return "f-chip f-chip-crit";
  if (level === "high") return "f-chip f-chip-high";
  if (level === "medium") return "f-chip f-chip-med";
  if (level === "low") return "f-chip f-chip-low";
  return "f-chip f-chip-gray";
}

function RiskGauge({ score }: { score: number }) {
  const getColor = (s: number) => {
    if (s >= 80) return "var(--falcon-red)";
    if (s >= 60) return "var(--falcon-orange)";
    if (s >= 40) return "var(--falcon-yellow)";
    if (s >= 20) return "var(--falcon-green)";
    return "var(--falcon-t3)";
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
      <div style={{ fontSize: 32, fontWeight: 700, color: getColor(score), lineHeight: 1 }}>
        {score}
      </div>
      <span style={{ fontSize: 11, color: "var(--falcon-t3)" }}>Risk Score</span>
    </div>
  );
}

interface LateralPath {
  id: string;
  source: string;
  target: string;
  technique: string;
  method: string;
  likelihood: string;
  prerequisites?: string[];
}

function LateralMovementDisplay({ data }: { data: { paths?: LateralPath[]; highRiskPivots?: string[] } }) {
  const paths = data.paths || [];
  const highRiskPivots = data.highRiskPivots || [];

  const getLikelihoodChip = (likelihood: string) => {
    switch (likelihood?.toLowerCase()) {
      case "high": return "f-chip f-chip-crit";
      case "medium": return "f-chip f-chip-med";
      case "low": return "f-chip f-chip-ok";
      default: return "f-chip f-chip-gray";
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {highRiskPivots.length > 0 && (
        <div style={{ padding: 12, borderRadius: 6, background: "var(--falcon-red-dim)", border: "1px solid var(--falcon-red-border)" }}>
          <h4 style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-red)", marginBottom: 8 }}>High-Risk Pivot Points</h4>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {highRiskPivots.map((pivot, idx) => (
              <span key={idx} className="f-chip f-chip-crit">{pivot}</span>
            ))}
          </div>
        </div>
      )}

      {paths.length > 0 ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {paths.map((path, idx) => (
            <div key={path.id || idx} style={{ padding: 12, borderRadius: 6, border: "1px solid var(--falcon-border)", background: "var(--falcon-panel)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
                <span className="f-chip f-chip-gray">{path.source}</span>
                <span style={{ color: "var(--falcon-t3)", fontSize: 11 }}>to</span>
                <span className="f-chip f-chip-gray">{path.target}</span>
                <span className={getLikelihoodChip(path.likelihood)}>
                  {path.likelihood} likelihood
                </span>
              </div>
              <p style={{ fontSize: 12, color: "var(--falcon-t2)", marginBottom: 4 }}>{path.method}</p>
              <div style={{ fontSize: 11, color: "var(--falcon-t3)" }}>
                <span style={{ fontWeight: 600 }}>Technique:</span> {path.technique}
              </div>
              {path.prerequisites && path.prerequisites.length > 0 && (
                <div style={{ marginTop: 8, fontSize: 11 }}>
                  <span style={{ color: "var(--falcon-t3)" }}>Prerequisites:</span>
                  <ul style={{ listStyle: "disc inside", color: "var(--falcon-t3)", margin: "4px 0 0 0", padding: 0 }}>
                    {path.prerequisites.map((prereq, pIdx) => (
                      <li key={pIdx}>{prereq}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <p style={{ fontSize: 12, color: "var(--falcon-t3)" }}>No lateral movement paths identified</p>
      )}
    </div>
  );
}

interface BusinessImpact {
  overallRisk?: string;
  dataAtRisk?: {
    types?: string[];
    estimatedRecords?: string;
    regulatoryImplications?: string[];
  };
  operationalImpact?: {
    systemsAffected?: number;
    potentialDowntime?: string;
    businessProcesses?: string[];
  };
  financialImpact?: {
    estimatedRange?: string;
    factors?: string[];
  };
  reputationalImpact?: string;
}

function BusinessImpactDisplay({ data }: { data: BusinessImpact }) {
  const getRiskStyle = (risk: string): { color: string; bg: string; border: string } => {
    switch (risk?.toLowerCase()) {
      case "critical": return { color: "var(--falcon-red)", bg: "var(--falcon-red-dim)", border: "var(--falcon-red-border)" };
      case "high": return { color: "var(--falcon-orange)", bg: "var(--falcon-orange-dim)", border: "rgba(242,140,40,0.3)" };
      case "medium": return { color: "var(--falcon-yellow)", bg: "var(--falcon-yellow-dim)", border: "rgba(234,179,8,0.25)" };
      case "low": return { color: "var(--falcon-green)", bg: "var(--falcon-green-dim)", border: "rgba(34,197,94,0.25)" };
      default: return { color: "var(--falcon-t3)", bg: "var(--falcon-panel)", border: "var(--falcon-border)" };
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {data.overallRisk && (() => {
        const rs = getRiskStyle(data.overallRisk);
        return (
          <div style={{ padding: 16, borderRadius: 6, border: `1px solid ${rs.border}`, background: rs.bg, textAlign: "center" }}>
            <span style={{ fontSize: 11, color: "var(--falcon-t3)" }}>Overall Risk Level</span>
            <div style={{ fontSize: 20, fontWeight: 700, textTransform: "uppercase", color: rs.color }}>{data.overallRisk}</div>
          </div>
        );
      })()}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        {data.dataAtRisk && (
          <div style={{ padding: 12, borderRadius: 6, border: "1px solid var(--falcon-border)", background: "var(--falcon-panel)" }}>
            <h4 style={{ fontSize: 12, fontWeight: 600, marginBottom: 8, display: "flex", alignItems: "center", gap: 6, color: "var(--falcon-t1)" }}>
              <AlertTriangle style={{ width: 14, height: 14, color: "var(--falcon-red)" }} />
              Data at Risk
            </h4>
            {data.dataAtRisk.types && data.dataAtRisk.types.length > 0 && (
              <div style={{ marginBottom: 8 }}>
                <span style={{ fontSize: 10, color: "var(--falcon-t3)" }}>Types:</span>
                <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 4 }}>
                  {data.dataAtRisk.types.map((type, idx) => (
                    <span key={idx} className="f-chip f-chip-gray">{type}</span>
                  ))}
                </div>
              </div>
            )}
            {data.dataAtRisk.estimatedRecords && (
              <p style={{ fontSize: 12, color: "var(--falcon-t2)" }}>
                <span style={{ color: "var(--falcon-t3)" }}>Est. Records:</span> {data.dataAtRisk.estimatedRecords}
              </p>
            )}
            {data.dataAtRisk.regulatoryImplications && data.dataAtRisk.regulatoryImplications.length > 0 && (
              <div style={{ marginTop: 8 }}>
                <span style={{ fontSize: 10, color: "var(--falcon-t3)" }}>Regulatory:</span>
                <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 4 }}>
                  {data.dataAtRisk.regulatoryImplications.map((reg, idx) => (
                    <span key={idx} className="f-chip f-chip-med">{reg}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {data.operationalImpact && (
          <div style={{ padding: 12, borderRadius: 6, border: "1px solid var(--falcon-border)", background: "var(--falcon-panel)" }}>
            <h4 style={{ fontSize: 12, fontWeight: 600, marginBottom: 8, color: "var(--falcon-t1)" }}>Operational Impact</h4>
            {data.operationalImpact.systemsAffected !== undefined && (
              <p style={{ fontSize: 12, color: "var(--falcon-t2)" }}>
                <span style={{ color: "var(--falcon-t3)" }}>Systems Affected:</span> {data.operationalImpact.systemsAffected}
              </p>
            )}
            {data.operationalImpact.potentialDowntime && (
              <p style={{ fontSize: 12, color: "var(--falcon-t2)" }}>
                <span style={{ color: "var(--falcon-t3)" }}>Potential Downtime:</span> {data.operationalImpact.potentialDowntime}
              </p>
            )}
            {data.operationalImpact.businessProcesses && data.operationalImpact.businessProcesses.length > 0 && (
              <div style={{ marginTop: 8 }}>
                <span style={{ fontSize: 10, color: "var(--falcon-t3)" }}>Affected Processes:</span>
                <ul style={{ listStyle: "disc inside", fontSize: 12, color: "var(--falcon-t3)", margin: "4px 0 0 0", padding: 0 }}>
                  {data.operationalImpact.businessProcesses.map((proc, idx) => (
                    <li key={idx}>{proc}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {data.financialImpact && (
          <div style={{ padding: 12, borderRadius: 6, border: "1px solid var(--falcon-border)", background: "var(--falcon-panel)" }}>
            <h4 style={{ fontSize: 12, fontWeight: 600, marginBottom: 8, color: "var(--falcon-t1)" }}>Financial Impact</h4>
            {data.financialImpact.estimatedRange && (
              <p style={{ fontSize: 16, fontWeight: 700, color: "var(--falcon-red)" }}>{data.financialImpact.estimatedRange}</p>
            )}
            {data.financialImpact.factors && data.financialImpact.factors.length > 0 && (
              <div style={{ marginTop: 8 }}>
                <span style={{ fontSize: 10, color: "var(--falcon-t3)" }}>Contributing Factors:</span>
                <ul style={{ listStyle: "disc inside", fontSize: 12, color: "var(--falcon-t3)", margin: "4px 0 0 0", padding: 0 }}>
                  {data.financialImpact.factors.map((factor, idx) => (
                    <li key={idx}>{factor}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>

      {data.reputationalImpact && (
        <div style={{ padding: 12, borderRadius: 6, border: "1px solid var(--falcon-border)", background: "var(--falcon-panel)" }}>
          <h4 style={{ fontSize: 12, fontWeight: 600, marginBottom: 8, color: "var(--falcon-t1)" }}>Reputational Impact</h4>
          <p style={{ fontSize: 12, color: "var(--falcon-t3)" }}>{data.reputationalImpact}</p>
        </div>
      )}
    </div>
  );
}

function AssessmentCard({ assessment, onView, onDelete }: {
  assessment: FullAssessment;
  onView: () => void;
  onDelete: () => void;
}) {
  const isRunning = !["completed", "failed", "pending"].includes(assessment.status);

  return (
    <div className="f-panel" style={{ overflow: "visible" }}>
      <div className="f-panel-head" style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="f-panel-title" style={{ marginBottom: 2 }}>
            <span className="f-panel-dot" />
            <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{assessment.name}</span>
          </div>
          <div style={{ fontSize: 10, color: "var(--falcon-t4)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", paddingLeft: 14 }}>
            {assessment.description || "Full system security assessment"}
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {isRunning && <Loader2 style={{ width: 12, height: 12, color: "var(--falcon-blue-hi)", animation: "spin 1s linear infinite" }} />}
          <StatusChip status={assessment.status} />
        </div>
      </div>
      <div style={{ padding: "12px 16px" }}>
        {isRunning && (
          <div style={{ marginBottom: 12 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--falcon-t3)", marginBottom: 6 }}>
              <span>{assessment.currentPhase}</span>
              <span style={{ fontFamily: "var(--font-mono)" }}>{assessment.progress}%</span>
            </div>
            <div className="f-tb-track" style={{ height: 4 }}>
              <div className="f-tb-fill f-tf-b" style={{ width: `${assessment.progress}%` }} />
            </div>
          </div>
        )}

        {assessment.status === "completed" && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 12 }}>
            <div className="f-kpi" style={{ padding: 8 }}>
              <div className="f-kpi-val r" style={{ fontSize: 20 }}>
                {assessment.overallRiskScore ?? "-"}
              </div>
              <div className="f-kpi-foot">Risk Score</div>
            </div>
            <div className="f-kpi" style={{ padding: 8 }}>
              <div className="f-kpi-val" style={{ fontSize: 20, color: "#a78bfa" }}>
                {assessment.criticalPathCount ?? 0}
              </div>
              <div className="f-kpi-foot">Attack Paths</div>
            </div>
            <div className="f-kpi" style={{ padding: 8 }}>
              <div className="f-kpi-val b" style={{ fontSize: 20 }}>
                {assessment.systemsAnalyzed ?? 0}
              </div>
              <div className="f-kpi-foot">Systems</div>
            </div>
            <div className="f-kpi" style={{ padding: 8 }}>
              <div className="f-kpi-val o" style={{ fontSize: 20 }}>
                {assessment.findingsAnalyzed ?? 0}
              </div>
              <div className="f-kpi-foot">Findings</div>
            </div>
          </div>
        )}

        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          <button className="f-btn f-btn-primary" onClick={onView} data-testid={`button-view-assessment-${assessment.id}`}>
            <Eye style={{ width: 12, height: 12 }} />
            View Details
          </button>
          <button
            className="f-btn f-btn-ghost"
            onClick={onDelete}
            data-testid={`button-delete-assessment-${assessment.id}`}
          >
            <Trash2 style={{ width: 12, height: 12 }} />
          </button>
        </div>

        <div style={{ marginTop: 10, fontSize: 10, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>
          Started: {assessment.startedAt ? new Date(assessment.startedAt).toLocaleString() : "Not started"}
          {assessment.durationMs && (
            <span style={{ marginLeft: 8 }}>Duration: {Math.round(assessment.durationMs / 1000)}s</span>
          )}
        </div>
      </div>
    </div>
  );
}

function RunDebugPanel({ evaluationId }: { evaluationId: string }) {
  const { data, isLoading } = useQuery<{
    runs: Array<{
      id: string; runType: string; executionMode: string; stopReason: string | null;
      failureCode: string | null; exploitable: boolean | null; overallConfidence: number | null;
      totalTurns: number | null; totalToolCalls: number | null; durationMs: number | null;
      startedAt: string | null; completedAt: string | null; errorMessage: string | null;
    }>;
    toolCalls: Array<{
      id: string; runId: string; turn: number; toolName: string;
      vulnerable: boolean | null; confidence: number | null; executionTimeMs: number | null;
      resultSummary: string | null; failureCode: string | null;
    }>;
    llmTurns: Array<{
      id: string; runId: string; turn: number; model: string;
      hadToolCalls: boolean | null; toolCallCount: number | null; durationMs: number | null;
    }>;
    failures: Array<{
      id: string; runId: string; failureCode: string; context: string | null;
      message: string | null; occurredAt: string | null;
    }>;
  }>({
    queryKey: [`/api/aev/runs/${evaluationId}`],
    enabled: Boolean(evaluationId),
  });

  if (isLoading) return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: 16 }}>
      <Loader2 style={{ width: 14, height: 14, color: "var(--falcon-t3)", animation: "spin 1s linear infinite" }} />
      <span style={{ fontSize: 12, color: "var(--falcon-t3)" }}>Loading telemetry...</span>
    </div>
  );
  if (!data || data.runs.length === 0) return (
    <div className="f-panel">
      <div style={{ padding: "24px 16px", textAlign: "center" }}>
        <p style={{ fontSize: 12, color: "var(--falcon-t3)" }}>No telemetry data recorded for this assessment.</p>
      </div>
    </div>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {data.runs.map((run) => {
        const runToolCalls = data.toolCalls.filter(tc => tc.runId === run.id);
        const runLlmTurns = data.llmTurns.filter(lt => lt.runId === run.id);
        const runFailures = data.failures.filter(f => f.runId === run.id);

        return (
          <div className="f-panel" key={run.id}>
            <div className="f-panel-head" style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div className="f-panel-title">
                <span className="f-panel-dot" />
                {run.runType === "exploit_agent" ? "Exploit Agent Run" : run.runType === "chain_playbook" ? "Chain Playbook" : run.runType}
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span className={
                  run.stopReason === "completed" ? "f-chip f-chip-ok" :
                  run.stopReason === "error" ? "f-chip f-chip-crit" :
                  "f-chip f-chip-gray"
                }>
                  {run.stopReason || "unknown"}
                </span>
                {run.exploitable && <span className="f-chip f-chip-crit">Exploitable</span>}
                {run.durationMs != null && <span style={{ fontSize: 10, color: "var(--falcon-t3)", fontFamily: "var(--font-mono)" }}>{(run.durationMs / 1000).toFixed(1)}s</span>}
              </div>
            </div>
            <div style={{ padding: "8px 16px", fontSize: 10, color: "var(--falcon-t3)", fontFamily: "var(--font-mono)", borderBottom: "1px solid var(--falcon-border)" }}>
              Mode: {run.executionMode} | Turns: {run.totalTurns ?? 0} | Tool calls: {run.totalToolCalls ?? 0}
              {run.overallConfidence != null && ` | Confidence: ${run.overallConfidence}%`}
              {run.failureCode && run.failureCode !== "none" && <span style={{ color: "var(--falcon-red)", marginLeft: 8 }}>Failure: {run.failureCode}</span>}
            </div>
            <div style={{ padding: "12px 16px", display: "flex", flexDirection: "column", gap: 10 }}>
              {runFailures.length > 0 && (
                <div style={{ background: "var(--falcon-red-dim)", border: "1px solid var(--falcon-red-border)", borderRadius: 4, padding: 8, display: "flex", flexDirection: "column", gap: 4 }}>
                  {runFailures.map(f => (
                    <div key={f.id} style={{ fontSize: 10, color: "var(--falcon-red)" }}>
                      <span style={{ fontFamily: "var(--font-mono)" }}>{f.failureCode}</span> in {f.context}: {f.message}
                    </div>
                  ))}
                </div>
              )}
              {run.errorMessage && (
                <div style={{ background: "var(--falcon-red-dim)", border: "1px solid var(--falcon-red-border)", borderRadius: 4, padding: 8, fontSize: 10, color: "var(--falcon-red)", fontFamily: "var(--font-mono)" }}>{run.errorMessage}</div>
              )}

              {/* LLM turn timeline */}
              {runLlmTurns.length > 0 && (
                <div>
                  <p style={{ fontSize: 10, fontWeight: 600, color: "var(--falcon-t3)", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.05em" }}>LLM Turns</p>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {runLlmTurns.sort((a, b) => a.turn - b.turn).map(lt => (
                      <div key={lt.id} style={{ fontSize: 9.5, background: "var(--falcon-panel-2)", borderRadius: 3, padding: "2px 6px", color: "var(--falcon-t2)", fontFamily: "var(--font-mono)" }} title={`Model: ${lt.model}, Duration: ${lt.durationMs}ms`}>
                        T{lt.turn}: {lt.model?.split("/").pop()?.slice(0, 15)} ({lt.durationMs}ms){lt.hadToolCalls ? ` → ${lt.toolCallCount} calls` : " → final"}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Tool call badges */}
              {runToolCalls.length > 0 && (
                <div>
                  <p style={{ fontSize: 10, fontWeight: 600, color: "var(--falcon-t3)", marginBottom: 4, textTransform: "uppercase", letterSpacing: "0.05em" }}>Tool Calls</p>
                  <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                    {runToolCalls.sort((a, b) => a.turn - b.turn).map(tc => (
                      <div key={tc.id} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10 }}>
                        <span style={{ fontSize: 9.5, color: "var(--falcon-t4)", width: 24, fontFamily: "var(--font-mono)" }}>T{tc.turn}</span>
                        <span className="f-chip f-chip-gray" style={{ fontSize: 9.5 }}>{tc.toolName}</span>
                        {tc.vulnerable ? (
                          <span className="f-chip f-chip-crit" style={{ fontSize: 9.5 }}>vuln ({tc.confidence}%)</span>
                        ) : (
                          <span style={{ color: "var(--falcon-t4)", fontSize: 9.5 }}>clean</span>
                        )}
                        {tc.executionTimeMs != null && <span style={{ fontSize: 9.5, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>{tc.executionTimeMs}ms</span>}
                        {tc.failureCode && tc.failureCode !== "none" && (
                          <span className="f-chip f-chip-crit" style={{ fontSize: 9.5 }}>{tc.failureCode}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function AssessmentDetail({ assessment }: { assessment: FullAssessment }) {
  const attackGraph = assessment.unifiedAttackGraph;
  const recommendations = assessment.recommendations || [];

  const [detailTab, setDetailTab] = useState("summary");

  return (
    <div>
      <div className="f-tab-bar">
        <button className={`f-tab ${detailTab === "summary" ? "active" : ""}`} onClick={() => setDetailTab("summary")}>Summary</button>
        {(assessment as any).webAppRecon && (
          <button className={`f-tab ${detailTab === "web-recon" ? "active" : ""}`} onClick={() => setDetailTab("web-recon")}>Web Recon</button>
        )}
        {(assessment as any).validatedFindings?.length > 0 && (
          <button className={`f-tab ${detailTab === "validated-findings" ? "active" : ""}`} onClick={() => setDetailTab("validated-findings")}>Validated Findings</button>
        )}
        <button className={`f-tab ${detailTab === "attack-graph" ? "active" : ""}`} onClick={() => setDetailTab("attack-graph")}>Attack Graph</button>
        <button className={`f-tab ${detailTab === "recommendations" ? "active" : ""}`} onClick={() => setDetailTab("recommendations")}>Recommendations</button>
        <button className={`f-tab ${detailTab === "lateral" ? "active" : ""}`} onClick={() => setDetailTab("lateral")}>Lateral Movement</button>
        <button className={`f-tab ${detailTab === "impact" ? "active" : ""}`} onClick={() => setDetailTab("impact")}>Business Impact</button>
        <button className={`f-tab ${detailTab === "run-debug" ? "active" : ""}`} onClick={() => setDetailTab("run-debug")}>Run Debug</button>
      </div>

      {detailTab === "summary" && <div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 16 }}>
          <div className="f-kpi">
            <div className="f-kpi-lbl"><span className="f-kpi-dot r" />Risk Score</div>
            <RiskGauge score={assessment.overallRiskScore ?? 0} />
          </div>
          <div className="f-kpi">
            <div className="f-kpi-lbl"><span className="f-kpi-dot" style={{ background: "#a78bfa" }} />Critical Paths</div>
            <div className="f-kpi-val" style={{ color: "#a78bfa" }}>
              {assessment.criticalPathCount ?? 0}
            </div>
            <div className="f-kpi-foot">attack paths identified</div>
          </div>
          <div className="f-kpi">
            <div className="f-kpi-lbl"><span className="f-kpi-dot b" />Systems</div>
            <div className="f-kpi-val b">
              {assessment.systemsAnalyzed ?? 0}
            </div>
            <div className="f-kpi-foot">systems analyzed</div>
          </div>
          <div className="f-kpi">
            <div className="f-kpi-lbl"><span className="f-kpi-dot o" />Findings</div>
            <div className="f-kpi-val o">
              {assessment.findingsAnalyzed ?? 0}
            </div>
            <div className="f-kpi-foot">findings analyzed</div>
          </div>
        </div>

        {assessment.executiveSummary && (
          <div className="f-panel">
            <div className="f-panel-head">
              <div className="f-panel-title">
                <span className="f-panel-dot b" />
                <FileText style={{ width: 12, height: 12 }} />
                Executive Summary
              </div>
            </div>
            <div style={{ padding: "12px 16px" }}>
              <div style={{ fontSize: 12, color: "var(--falcon-t2)", whiteSpace: "pre-wrap", lineHeight: 1.6 }}>
                {assessment.executiveSummary}
              </div>
            </div>
          </div>
        )}
      </div>}

      {/* Web App Reconnaissance Results */}
      {detailTab === "web-recon" && (assessment as any).webAppRecon && (
        <div>
          <div className="f-panel">
            <div className="f-panel-head">
              <div className="f-panel-title">
                <span className="f-panel-dot b" />
                <Globe style={{ width: 12, height: 12 }} />
                Web Application Reconnaissance
              </div>
              <span style={{ fontSize: 10, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>
                Target: {(assessment as any).webAppRecon.targetUrl}
              </span>
            </div>
            <div style={{ padding: "12px 16px", display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
                <div className="f-kpi" style={{ padding: 10 }}>
                  <div className="f-kpi-val b" style={{ fontSize: 22 }}>
                    {(assessment as any).webAppRecon.attackSurface?.totalEndpoints || 0}
                  </div>
                  <div className="f-kpi-foot">Endpoints</div>
                </div>
                <div className="f-kpi" style={{ padding: 10 }}>
                  <div className="f-kpi-val" style={{ fontSize: 22, color: "#a78bfa" }}>
                    {(assessment as any).webAppRecon.attackSurface?.inputParameters || 0}
                  </div>
                  <div className="f-kpi-foot">Parameters</div>
                </div>
                <div className="f-kpi" style={{ padding: 10 }}>
                  <div className="f-kpi-val b" style={{ fontSize: 22 }}>
                    {(assessment as any).webAppRecon.attackSurface?.formCount || 0}
                  </div>
                  <div className="f-kpi-foot">Forms</div>
                </div>
                <div className="f-kpi" style={{ padding: 10 }}>
                  <div className="f-kpi-val o" style={{ fontSize: 22 }}>
                    {(((assessment as any).webAppRecon.scanDurationMs || 0) / 1000).toFixed(1)}s
                  </div>
                  <div className="f-kpi-foot">Scan Time</div>
                </div>
              </div>

              {(assessment as any).webAppRecon.applicationInfo && (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  <h4 style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Application Info</h4>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    {(assessment as any).webAppRecon.applicationInfo.technologies?.map((tech: string, idx: number) => (
                      <span key={idx} className="f-chip f-chip-gray">{tech}</span>
                    ))}
                    {(assessment as any).webAppRecon.applicationInfo.frameworks?.map((fw: string, idx: number) => (
                      <span key={idx} className="f-chip f-chip-low">{fw}</span>
                    ))}
                  </div>
                  {(assessment as any).webAppRecon.applicationInfo.missingSecurityHeaders?.length > 0 && (
                    <div style={{ marginTop: 4 }}>
                      <span style={{ fontSize: 10, color: "var(--falcon-t3)" }}>Missing Security Headers:</span>
                      <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 4 }}>
                        {(assessment as any).webAppRecon.applicationInfo.missingSecurityHeaders.map((h: string, idx: number) => (
                          <span key={idx} className="f-chip f-chip-crit">{h}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {(assessment as any).webAppRecon.endpoints?.length > 0 && (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  <h4 style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Discovered Endpoints ({(assessment as any).webAppRecon.endpoints.length})</h4>
                  <div style={{ maxHeight: 300, overflowY: "auto" }}>
                    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      {(assessment as any).webAppRecon.endpoints.slice(0, 50).map((ep: any, idx: number) => (
                        <div key={idx} style={{ padding: "6px 10px", borderRadius: 4, border: "1px solid var(--falcon-border)", fontSize: 12, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, background: "var(--falcon-panel)" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
                            <span className="f-chip f-chip-gray" style={{ flexShrink: 0, fontSize: 10 }}>{ep.method}</span>
                            <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--falcon-t3)", fontFamily: "var(--font-mono)", fontSize: 11 }}>{ep.path}</span>
                          </div>
                          <span className={
                            ep.priority === 'high' ? "f-chip f-chip-crit" :
                            ep.priority === 'medium' ? "f-chip f-chip-med" :
                            "f-chip f-chip-gray"
                          } style={{ flexShrink: 0, fontSize: 10 }}>
                            {ep.priority}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Validated Findings from Parallel Agents */}
      {detailTab === "validated-findings" && (assessment as any).validatedFindings?.length > 0 && (
        <div>
          <div className="f-panel">
            <div className="f-panel-head">
              <div className="f-panel-title">
                <span className="f-panel-dot" style={{ background: "var(--falcon-green)" }} />
                <Shield style={{ width: 12, height: 12 }} />
                Validated Security Findings
              </div>
              <span style={{ fontSize: 10, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>
                {(assessment as any).validatedFindings.length} vulnerabilities confirmed by parallel security agents
              </span>
            </div>
            <div style={{ padding: "12px 16px", display: "flex", flexDirection: "column", gap: 16 }}>
              {(assessment as any).agentDispatchStats && (
                <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
                  <div className="f-kpi" style={{ padding: 10 }}>
                    <div className="f-kpi-val b" style={{ fontSize: 22 }}>
                      {(assessment as any).agentDispatchStats.completedTasks}
                    </div>
                    <div className="f-kpi-foot">Tasks Completed</div>
                  </div>
                  <div className="f-kpi" style={{ padding: 10 }}>
                    <div className="f-kpi-val g" style={{ fontSize: 22 }}>
                      {(assessment as any).validatedFindings.length}
                    </div>
                    <div className="f-kpi-foot">Confirmed</div>
                  </div>
                  <div className="f-kpi" style={{ padding: 10 }}>
                    <div className="f-kpi-val o" style={{ fontSize: 22 }}>
                      {(assessment as any).agentDispatchStats.falsePositivesFiltered}
                    </div>
                    <div className="f-kpi-foot">False Positives Filtered</div>
                  </div>
                  <div className="f-kpi" style={{ padding: 10 }}>
                    <div className="f-kpi-val" style={{ fontSize: 22 }}>
                      {(((assessment as any).agentDispatchStats.executionTimeMs || 0) / 1000).toFixed(1)}s
                    </div>
                    <div className="f-kpi-foot">Execution Time</div>
                  </div>
                </div>
              )}

              <div style={{ maxHeight: 400, overflowY: "auto" }}>
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {(assessment as any).validatedFindings.map((finding: any, idx: number) => (
                    <div key={finding.id || idx} style={{ padding: 12, borderRadius: 6, border: "1px solid var(--falcon-border)", background: "var(--falcon-panel)" }}>
                      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                          <span className={sevChip(finding.severity)}>
                            {finding.severity?.toUpperCase()}
                          </span>
                          <span className="f-chip f-chip-gray">{finding.vulnerabilityType}</span>
                          {finding.mitreAttackId && (
                            <span className="f-chip" style={{ color: "#a78bfa", borderColor: "rgba(167,139,250,0.3)", background: "rgba(167,139,250,0.1)", fontSize: 10 }}>{finding.mitreAttackId}</span>
                          )}
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                          {finding.cvssEstimate && (
                            <span className="f-chip f-chip-gray">CVSS: {finding.cvssEstimate}</span>
                          )}
                          <span className={finding.verdict === 'confirmed' ? "f-chip f-chip-crit" : "f-chip f-chip-gray"}>
                            {finding.verdict}
                          </span>
                        </div>
                      </div>
                      <div style={{ fontSize: 12, color: "var(--falcon-t3)", marginBottom: 8 }}>
                        <span style={{ fontWeight: 600, color: "var(--falcon-t1)" }}>{finding.endpointPath}</span>
                        {finding.parameter && <span> ({finding.parameter})</span>}
                      </div>
                      {finding.evidence && finding.evidence.length > 0 && (
                        <div style={{ fontSize: 10, color: "var(--falcon-t3)", background: "var(--falcon-panel-2)", padding: 8, borderRadius: 4, marginBottom: 8, overflowX: "auto", fontFamily: "var(--font-mono)" }}>
                          <code>{Array.isArray(finding.evidence)
                            ? finding.evidence[0]?.slice(0, 200) + (finding.evidence[0]?.length > 200 ? '...' : '')
                            : String(finding.evidence).slice(0, 200)
                          }</code>
                        </div>
                      )}
                      {finding.recommendations?.length > 0 && (
                        <div style={{ fontSize: 10, color: "var(--falcon-t2)" }}>
                          <span style={{ color: "var(--falcon-t3)" }}>Recommendations: </span>
                          {finding.recommendations.slice(0, 2).join('; ')}
                        </div>
                      )}
                      {finding.llmValidation && (
                        <div style={{ fontSize: 10, color: "var(--falcon-t3)", marginTop: 4, display: "flex", alignItems: "center", gap: 4 }}>
                          <CheckCircle2 style={{ width: 11, height: 11, color: "var(--falcon-green)" }} />
                          LLM Validated: {finding.llmValidation.confidence}% confidence
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {detailTab === "attack-graph" && <div>
        <div className="f-panel">
          <div className="f-panel-head">
            <div className="f-panel-title">
              <span className="f-panel-dot" style={{ background: "#a78bfa" }} />
              <Network style={{ width: 12, height: 12 }} />
              Unified Attack Graph
            </div>
            <span style={{ fontSize: 10, color: "var(--falcon-t4)", fontFamily: "var(--font-mono)" }}>
              cross-system attack paths showing how vulnerabilities chain together
            </span>
          </div>
          <div style={{ padding: "12px 16px" }}>
            {attackGraph?.criticalPaths && attackGraph.criticalPaths.length > 0 ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                <h4 style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Critical Attack Paths</h4>
                {attackGraph.criticalPaths.map((path, idx) => (
                  <div key={path.pathId || idx} style={{ padding: 12, borderRadius: 6, border: "1px solid var(--falcon-border)", background: "var(--falcon-panel-2)" }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
                      <span style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>Path {idx + 1}</span>
                      <span className={path.riskScore >= 70 ? "f-chip f-chip-crit" : "f-chip f-chip-gray"}>
                        Risk: {path.riskScore}
                      </span>
                    </div>
                    <p style={{ fontSize: 12, color: "var(--falcon-t3)" }}>{path.description}</p>
                    <div style={{ display: "flex", gap: 4, marginTop: 8, flexWrap: "wrap" }}>
                      {path.nodes.map((node, nodeIdx) => (
                        <span key={nodeIdx} className="f-chip f-chip-gray" style={{ fontSize: 10 }}>
                          {node}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}

                {attackGraph.nodes && attackGraph.nodes.length > 0 && (
                  <div style={{ marginTop: 12 }}>
                    <h4 style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 8 }}>Attack Graph Nodes</h4>
                    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                      {attackGraph.nodes.slice(0, 20).map((node, idx) => (
                        <span
                          key={node.id || idx}
                          className="f-chip"
                          style={
                            node.type === "vulnerability" ? { color: "var(--falcon-red)", background: "var(--falcon-red-dim)", borderColor: "var(--falcon-red-border)" } :
                            node.type === "technique" ? { color: "#a78bfa", background: "rgba(167,139,250,0.1)", borderColor: "rgba(167,139,250,0.3)" } :
                            node.type === "impact" ? { color: "var(--falcon-orange)", background: "var(--falcon-orange-dim)", borderColor: "rgba(242,140,40,0.3)" } :
                            { color: "var(--falcon-t3)", background: "rgba(255,255,255,0.03)", borderColor: "var(--falcon-border)" }
                          }
                        >
                          {node.label}
                        </span>
                      ))}
                      {attackGraph.nodes.length > 20 && (
                        <span style={{ fontSize: 10, color: "var(--falcon-t4)", alignSelf: "center" }}>
                          +{attackGraph.nodes.length - 20} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <p style={{ fontSize: 12, color: "var(--falcon-t3)" }}>No attack graph data available</p>
            )}
          </div>
        </div>
      </div>}

      {detailTab === "recommendations" && <div>
        <div className="f-panel">
          <div className="f-panel-head">
            <div className="f-panel-title">
              <span className="f-panel-dot" style={{ background: "var(--falcon-green)" }} />
              <Shield style={{ width: 12, height: 12 }} />
              Prioritized Recommendations
            </div>
          </div>
          <div style={{ padding: "12px 16px" }}>
            {recommendations.length > 0 ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {recommendations.map((rec, idx) => (
                  <div key={rec.id || idx} style={{ padding: 12, borderRadius: 6, border: "1px solid var(--falcon-border)", background: "var(--falcon-panel)" }}>
                    <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                          <span className={
                            rec.priority === "critical" ? "f-chip f-chip-crit" :
                            rec.priority === "high" ? "f-chip f-chip-high" :
                            rec.priority === "medium" ? "f-chip f-chip-med" :
                            "f-chip f-chip-gray"
                          }>
                            {rec.priority}
                          </span>
                          <span style={{ fontSize: 12, fontWeight: 600, color: "var(--falcon-t1)" }}>{rec.title}</span>
                        </div>
                        <p style={{ fontSize: 12, color: "var(--falcon-t3)" }}>{rec.description}</p>
                        {rec.affectedSystems && rec.affectedSystems.length > 0 && (
                          <div style={{ display: "flex", gap: 4, marginTop: 8, flexWrap: "wrap", alignItems: "center" }}>
                            <span style={{ fontSize: 10, color: "var(--falcon-t4)" }}>Affected:</span>
                            {rec.affectedSystems.map((sys, sIdx) => (
                              <span key={sIdx} className="f-chip f-chip-gray" style={{ fontSize: 10 }}>
                                {sys}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                      <div style={{ textAlign: "right", fontSize: 10, color: "var(--falcon-t4)" }}>
                        <div>Effort: {rec.effort}</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ fontSize: 12, color: "var(--falcon-t3)" }}>No recommendations available</p>
            )}
          </div>
        </div>
      </div>}

      {detailTab === "lateral" && <div>
        <div className="f-panel">
          <div className="f-panel-head">
            <div className="f-panel-title">
              <span className="f-panel-dot o" />
              <TrendingUp style={{ width: 12, height: 12 }} />
              Lateral Movement Analysis
            </div>
          </div>
          <div style={{ padding: "12px 16px" }}>
            {assessment.lateralMovementPaths ? (
              <LateralMovementDisplay data={assessment.lateralMovementPaths as any} />
            ) : (
              <p style={{ fontSize: 12, color: "var(--falcon-t3)" }}>No lateral movement data available</p>
            )}
          </div>
        </div>
      </div>}

      {detailTab === "impact" && <div>
        <div className="f-panel">
          <div className="f-panel-head">
            <div className="f-panel-title">
              <span className="f-panel-dot r" />
              <AlertCircle style={{ width: 12, height: 12 }} />
              Business Impact Analysis
            </div>
          </div>
          <div style={{ padding: "12px 16px" }}>
            {assessment.businessImpactAnalysis ? (
              <BusinessImpactDisplay data={assessment.businessImpactAnalysis as any} />
            ) : (
              <p style={{ fontSize: 12, color: "var(--falcon-t3)" }}>No business impact data available</p>
            )}
          </div>
        </div>
      </div>}

      {detailTab === "run-debug" && <div>
        <RunDebugPanel evaluationId={assessment.id} />
      </div>}
    </div>
  );
}

export default function FullAssessmentPage() {
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const [selectedAssessment, setSelectedAssessment] = useState<FullAssessment | null>(null);
  const [pageTab, setPageTab] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get("tab") || "assessments";
  });

  const { data: assessments = [], isLoading, refetch } = useQuery<FullAssessment[]>({
    queryKey: ["/api/full-assessments"],
    refetchInterval: 5000,
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      return apiRequest("DELETE", `/api/full-assessments/${id}`);
    },
    onSuccess: () => {
      toast({ title: "Deleted", description: "Assessment removed" });
      setSelectedAssessment(null);
      queryClient.invalidateQueries({ queryKey: ["/api/full-assessments"] });
    },
  });

  return (
    <div data-testid="text-page-title">
      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, flexWrap: "wrap", marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 18, fontWeight: 700, color: "var(--falcon-t1)", margin: 0 }}>Full Security Assessment</h1>
          <p style={{ fontSize: 11, color: "var(--falcon-t3)", marginTop: 4, fontFamily: "var(--font-mono)" }}>
            // multi-system penetration testing
          </p>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          <button className="f-btn f-btn-ghost" onClick={() => refetch()} data-testid="button-refresh-assessments">
            <RefreshCw style={{ width: 12, height: 12 }} />
            Refresh
          </button>
          <button className="f-btn f-btn-primary" onClick={() => navigate("/assess")} data-testid="button-start-full-assessment">
            <Play style={{ width: 12, height: 12 }} />
            New Assessment
          </button>
        </div>
      </div>

      <div className="f-tab-bar">
        <button className={`f-tab ${pageTab === "assessments" ? "active" : ""}`} onClick={() => setPageTab("assessments")}>Assessments</button>
        <button className={`f-tab ${pageTab === "live-recon" ? "active" : ""}`} onClick={() => setPageTab("live-recon")}>Live Recon</button>
        <button className={`f-tab ${pageTab === "approvals" ? "active" : ""}`} onClick={() => setPageTab("approvals")}>Approvals</button>
        <button className={`f-tab ${pageTab === "sandbox" ? "active" : ""}`} onClick={() => setPageTab("sandbox")}>Sandbox</button>
      </div>

      {pageTab === "assessments" && <div>
      {selectedAssessment ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div>
            <button
              className="f-btn f-btn-ghost"
              onClick={() => setSelectedAssessment(null)}
              data-testid="button-back-to-list"
            >
              Back to List
            </button>
          </div>
          <div className="f-panel">
            <div className="f-panel-head" style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8, flexWrap: "wrap" }}>
              <div>
                <div className="f-panel-title">
                  <span className="f-panel-dot" />
                  {selectedAssessment.name}
                </div>
                <div style={{ fontSize: 10, color: "var(--falcon-t4)", paddingLeft: 14, marginTop: 2 }}>
                  {selectedAssessment.description || "Full security assessment"}
                </div>
              </div>
              <StatusChip status={selectedAssessment.status} />
            </div>
            <div style={{ padding: "12px 16px" }}>
              <AssessmentDetail assessment={selectedAssessment} />
            </div>
          </div>
        </div>
      ) : (
        <>
          {isLoading ? (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "48px 0" }}>
              <Loader2 style={{ width: 24, height: 24, color: "var(--falcon-t3)", animation: "spin 1s linear infinite" }} />
            </div>
          ) : assessments.length === 0 ? (
            <div className="f-panel">
              <div style={{ padding: "48px 16px", textAlign: "center" }}>
                <Target style={{ width: 40, height: 40, margin: "0 auto 16px", color: "var(--falcon-t4)" }} />
                <h3 style={{ fontSize: 14, fontWeight: 600, color: "var(--falcon-t1)", marginBottom: 4 }}>No Assessments Yet</h3>
                <p style={{ fontSize: 12, color: "var(--falcon-t3)", marginBottom: 16 }}>
                  Start a full security assessment to analyze all your systems
                </p>
                <button
                  className="f-btn f-btn-primary"
                  onClick={() => navigate("/assess")}
                  data-testid="button-start-first-assessment"
                >
                  <Play style={{ width: 12, height: 12 }} />
                  Start Your First Assessment
                </button>
              </div>
            </div>
          ) : (
            <div style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))" }}>
              {assessments.map((assessment) => (
                <AssessmentCard
                  key={assessment.id}
                  assessment={assessment}
                  onView={() => setSelectedAssessment(assessment)}
                  onDelete={() => deleteMutation.mutate(assessment.id)}
                />
              ))}
            </div>
          )}
        </>
      )}
        </div>}

      {pageTab === "live-recon" && (
        <Suspense fallback={<div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 256 }}><Loader2 style={{ width: 24, height: 24, color: "var(--falcon-t3)", animation: "spin 1s linear infinite" }} /></div>}>
          <ExternalReconPanel />
        </Suspense>
      )}

      {pageTab === "approvals" && (
        <Suspense fallback={<div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 256 }}><Loader2 style={{ width: 24, height: 24, color: "var(--falcon-t3)", animation: "spin 1s linear infinite" }} /></div>}>
          <ApprovalsPanel />
        </Suspense>
      )}

      {pageTab === "sandbox" && (
        <Suspense fallback={<div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: 256 }}><Loader2 style={{ width: 24, height: 24, color: "var(--falcon-t3)", animation: "spin 1s linear infinite" }} /></div>}>
          <SandboxPanel />
        </Suspense>
      )}
    </div>
  );
}
