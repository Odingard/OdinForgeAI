import { useEffect, useRef } from "react";
import type { AttackGraph } from "@shared/schema";
import { Download, X, Image } from "lucide-react";

// ============================================================================
// TYPES
// ============================================================================

interface BreachChainExportProps {
  chain: any;           // the full breach chain object
  graph: AttackGraph | null;
  narrative?: any;      // ChainNarrative if available
  onClose: () => void;
}

// ============================================================================
// HELPERS
// ============================================================================

function formatDate(d?: string | Date | null): string {
  if (!d) return new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
  return new Date(d).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
}

function sevColor(sev: string): string {
  if (sev === "critical") return "#ef4444";
  if (sev === "high") return "#f97316";
  if (sev === "medium") return "#eab308";
  return "#22c55e";
}

function nodeRemColor(status?: string): string {
  if (status === "verified_fixed") return "#22c55e";
  if (status === "in_progress") return "#eab308";
  if (status === "accepted_risk") return "#6b7280";
  return "#ef4444";
}

function nodeRemLabel(status?: string): string {
  if (status === "verified_fixed") return "Fixed";
  if (status === "in_progress") return "In Progress";
  if (status === "accepted_risk") return "Accepted Risk";
  return "Open";
}

// ============================================================================
// COMPONENT
// ============================================================================

export function BreachChainExport({ chain, graph, narrative, onClose }: BreachChainExportProps) {
  const exportRef = useRef<HTMLDivElement>(null);
  const canvasExportRef = useRef<HTMLCanvasElement | null>(null);

  // Build ordered narrative steps from attack graph critical path
  const criticalNodes = (() => {
    if (!graph?.nodes?.length) return [];
    const nodeMap = new Map(graph.nodes.map(n => [n.id, n]));
    return (graph.criticalPath || [])
      .map(id => nodeMap.get(id))
      .filter((n): n is NonNullable<typeof n> => !!n);
  })();

  // Key metrics
  const totalSteps = criticalNodes.length;
  const systemsAtRisk = chain.totalAssetsCompromised ?? 0;
  const maxPrivilege = chain.maxPrivilegeAchieved || "none";
  const ttc = graph?.timeToCompromise;
  const ttcStr = ttc ? `${ttc.expected} ${ttc.unit}` : "Unknown";

  // Narrative fallback
  const headline = narrative?.headline ?? `Breach chain "${chain.name}" demonstrates ${totalSteps}-step attack path`;
  const riskSentence = narrative?.riskSentence ?? (
    chain.overallRiskScore >= 80
      ? "This represents a critical risk to your organization requiring immediate remediation."
      : chain.overallRiskScore >= 50
        ? "This represents a high risk that should be addressed in the next sprint."
        : "This represents a medium risk to be addressed in your next security cycle."
  );
  const attackerProfile = narrative?.attackerProfile ?? "External attacker with no prior credentials";

  // Remediation summary
  const allNodes = graph?.nodes || [];
  const remStats = {
    total: allNodes.length,
    fixed: allNodes.filter(n => n.remediationStatus === "verified_fixed").length,
    inProgress: allNodes.filter(n => n.remediationStatus === "in_progress").length,
    open: allNodes.filter(n => !n.remediationStatus || n.remediationStatus === "open").length,
  };

  const handlePrint = () => {
    window.print();
  };

  const handleCopyPng = async () => {
    // Find the existing canvas element in the DOM
    const existingCanvas = document.querySelector("canvas") as HTMLCanvasElement | null;
    if (!existingCanvas) {
      // Fallback: just print
      window.print();
      return;
    }
    try {
      existingCanvas.toBlob(async (blob) => {
        if (!blob) return;
        await navigator.clipboard.write([
          new ClipboardItem({ "image/png": blob }),
        ]);
      });
    } catch {
      // Clipboard API not available — silently skip
    }
  };

  // Inject print styles
  useEffect(() => {
    const styleId = "odinforge-print-style";
    if (document.getElementById(styleId)) return;
    const style = document.createElement("style");
    style.id = styleId;
    style.textContent = `
      @media print {
        body > * { display: none !important; }
        #odinforge-export-content { display: block !important; }
        @page { margin: 16mm; size: A4 portrait; }
      }
    `;
    document.head.appendChild(style);
    return () => {
      const el = document.getElementById(styleId);
      if (el) document.head.removeChild(el);
    };
  }, []);

  return (
    <>
      {/* Modal overlay */}
      <div
        className="f-modal-overlay"
        onClick={onClose}
        style={{ zIndex: 1000 }}
      >
        <div
          className="f-modal f-modal-lg"
          onClick={e => e.stopPropagation()}
          style={{ maxHeight: "90vh", overflowY: "auto", width: "min(780px, 95vw)" }}
        >
          {/* Modal header */}
          <div className="f-modal-head">
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <h2 className="f-modal-title" style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Download style={{ width: 16, height: 16, color: "var(--falcon-blue-hi)" }} />
                Export Board Report
              </h2>
              <button
                style={{ background: "none", border: "none", cursor: "pointer", color: "var(--falcon-t4)", padding: 4 }}
                onClick={onClose}
              >
                <X style={{ width: 16, height: 16 }} />
              </button>
            </div>
            <p className="f-modal-desc">
              Preview below. Click "Download PDF" to print as PDF, or "Copy PNG" to copy the attack graph image.
            </p>
          </div>

          {/* Action buttons */}
          <div style={{ display: "flex", gap: 8, padding: "0 20px 16px" }}>
            <button className="f-btn f-btn-primary" onClick={handlePrint}>
              <Download style={{ width: 13, height: 13, marginRight: 6 }} />
              Download PDF
            </button>
            <button className="f-btn f-btn-secondary" onClick={handleCopyPng}>
              <Image style={{ width: 13, height: 13, marginRight: 6 }} />
              Copy PNG
            </button>
            <button className="f-btn f-btn-ghost" onClick={onClose} style={{ marginLeft: "auto" }}>
              Cancel
            </button>
          </div>

          {/* Preview wrapper */}
          <div
            style={{
              margin: "0 20px 20px",
              border: "1px solid var(--falcon-border)",
              borderRadius: 6,
              overflow: "auto",
              maxHeight: 560,
              background: "#fff",
            }}
          >
            <ExportContent
              chain={chain}
              criticalNodes={criticalNodes}
              allNodes={allNodes}
              headline={headline}
              riskSentence={riskSentence}
              attackerProfile={attackerProfile}
              totalSteps={totalSteps}
              ttcStr={ttcStr}
              systemsAtRisk={systemsAtRisk}
              maxPrivilege={maxPrivilege}
              remStats={remStats}
              isPreview={true}
            />
          </div>
        </div>
      </div>

      {/* Hidden print-only content */}
      <ExportContent
        chain={chain}
        criticalNodes={criticalNodes}
        allNodes={allNodes}
        headline={headline}
        riskSentence={riskSentence}
        attackerProfile={attackerProfile}
        totalSteps={totalSteps}
        ttcStr={ttcStr}
        systemsAtRisk={systemsAtRisk}
        maxPrivilege={maxPrivilege}
        remStats={remStats}
        isPreview={false}
      />
    </>
  );
}

// ============================================================================
// Export Content — rendered both in preview and hidden for print
// ============================================================================

interface ExportContentProps {
  chain: any;
  criticalNodes: any[];
  allNodes: any[];
  headline: string;
  riskSentence: string;
  attackerProfile: string;
  totalSteps: number;
  ttcStr: string;
  systemsAtRisk: number;
  maxPrivilege: string;
  remStats: { total: number; fixed: number; inProgress: number; open: number };
  isPreview: boolean;
}

function ExportContent({
  chain,
  criticalNodes,
  allNodes,
  headline,
  riskSentence,
  attackerProfile,
  totalSteps,
  ttcStr,
  systemsAtRisk,
  maxPrivilege,
  remStats,
  isPreview,
}: ExportContentProps) {
  const containerStyle: React.CSSProperties = isPreview
    ? {
        padding: "32px 40px",
        background: "#ffffff",
        color: "#111827",
        fontFamily: "Georgia, 'Times New Roman', Times, serif",
        fontSize: 13,
        lineHeight: 1.6,
        minWidth: 600,
      }
    : {
        display: "none",
        padding: "32px 40px",
        background: "#ffffff",
        color: "#111827",
        fontFamily: "Georgia, 'Times New Roman', Times, serif",
        fontSize: 13,
        lineHeight: 1.6,
      };

  return (
    <div
      id={isPreview ? undefined : "odinforge-export-content"}
      style={containerStyle}
    >
      {/* Cover */}
      <div style={{ borderBottom: "3px solid #111827", paddingBottom: 20, marginBottom: 28 }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 12 }}>
          <div>
            <div style={{ fontSize: 22, fontWeight: 900, letterSpacing: -0.5, color: "#111827", fontFamily: "system-ui, sans-serif" }}>
              ODIN<span style={{ color: "#1d4ed8" }}>FORGE</span>
              <span style={{ fontSize: 11, fontWeight: 400, color: "#6b7280", marginLeft: 10, fontFamily: "monospace" }}>AI Security Intelligence</span>
            </div>
          </div>
          <div style={{
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: 1,
            color: "#fff",
            background: "#dc2626",
            padding: "4px 10px",
            borderRadius: 4,
            fontFamily: "system-ui, sans-serif",
          }}>
            CONFIDENTIAL — BOARD REPORT
          </div>
        </div>
        <h1 style={{ fontSize: 26, fontWeight: 700, margin: "0 0 6px 0", color: "#111827", fontFamily: "system-ui, sans-serif" }}>
          {chain.name}
        </h1>
        <div style={{ fontSize: 12, color: "#6b7280", fontFamily: "system-ui, sans-serif" }}>
          Generated: {formatDate(chain.completedAt || chain.startedAt)} &nbsp;·&nbsp;
          Chain ID: {chain.id}
        </div>
      </div>

      {/* Executive Summary */}
      <div style={{
        background: "#fef2f2",
        border: "1px solid #fca5a5",
        borderRadius: 6,
        padding: "16px 20px",
        marginBottom: 28,
      }}>
        <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: 1, color: "#dc2626", fontFamily: "system-ui, sans-serif", marginBottom: 8 }}>
          EXECUTIVE SUMMARY
        </div>
        <p style={{ margin: "0 0 8px 0", fontWeight: 600, fontSize: 14, color: "#111827" }}>
          {headline}
        </p>
        <p style={{ margin: "0 0 8px 0", color: "#374151" }}>
          {riskSentence}
        </p>
        <p style={{ margin: 0, color: "#6b7280", fontSize: 12 }}>
          Attacker profile: {attackerProfile}
        </p>
      </div>

      {/* Key Metrics */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(4, 1fr)",
        gap: 12,
        marginBottom: 28,
      }}>
        {[
          { label: "Total Steps", value: String(totalSteps), color: "#1d4ed8" },
          { label: "Time to Breach", value: ttcStr, color: "#b45309" },
          { label: "Systems at Risk", value: String(systemsAtRisk), color: "#dc2626" },
          { label: "Max Privilege", value: maxPrivilege, color: "#7c3aed" },
        ].map(m => (
          <div key={m.label} style={{
            padding: "14px 16px",
            border: "1px solid #e5e7eb",
            borderRadius: 6,
            textAlign: "center",
          }}>
            <div style={{
              fontSize: 26,
              fontWeight: 800,
              color: m.color,
              fontFamily: "system-ui, sans-serif",
              lineHeight: 1,
              marginBottom: 4,
            }}>
              {m.value}
            </div>
            <div style={{ fontSize: 11, color: "#6b7280", fontFamily: "system-ui, sans-serif" }}>
              {m.label}
            </div>
          </div>
        ))}
      </div>

      {/* Attack Path */}
      {criticalNodes.length > 0 && (
        <div style={{ marginBottom: 28 }}>
          <h2 style={{ fontSize: 16, fontWeight: 700, margin: "0 0 14px 0", color: "#111827", fontFamily: "system-ui, sans-serif", borderBottom: "1px solid #e5e7eb", paddingBottom: 8 }}>
            Attack Path
          </h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {criticalNodes.map((node, idx) => {
              const sev = node.compromiseLevel === "admin" || node.compromiseLevel === "system"
                ? "critical"
                : node.compromiseLevel === "user"
                  ? "high"
                  : node.compromiseLevel === "limited"
                    ? "medium"
                    : "low";
              const sc = sevColor(sev);
              return (
                <div key={node.id} style={{
                  display: "flex",
                  gap: 14,
                  padding: "12px 14px",
                  border: "1px solid #e5e7eb",
                  borderLeft: `4px solid ${sc}`,
                  borderRadius: 4,
                }}>
                  <div style={{
                    width: 28,
                    height: 28,
                    borderRadius: "50%",
                    background: `${sc}22`,
                    border: `2px solid ${sc}`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                    fontSize: 12,
                    fontWeight: 700,
                    color: sc,
                    fontFamily: "system-ui, sans-serif",
                  }}>
                    {idx + 1}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 13, fontWeight: 700, color: "#111827", fontFamily: "system-ui, sans-serif" }}>
                        {node.label}
                      </span>
                      <span style={{
                        fontSize: 10,
                        fontWeight: 700,
                        padding: "2px 6px",
                        borderRadius: 4,
                        color: "#fff",
                        background: sc,
                        fontFamily: "system-ui, sans-serif",
                        textTransform: "uppercase",
                      }}>
                        {sev}
                      </span>
                      {node.tactic && (
                        <span style={{
                          fontSize: 10,
                          padding: "2px 6px",
                          borderRadius: 4,
                          color: "#6b7280",
                          background: "#f3f4f6",
                          fontFamily: "monospace",
                        }}>
                          {node.tactic.replace(/-/g, " ")}
                        </span>
                      )}
                    </div>
                    <p style={{ margin: 0, fontSize: 12, color: "#374151" }}>
                      {node.description || "No description available."}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Remediation Status */}
      {allNodes.length > 0 && (
        <div style={{ marginBottom: 28 }}>
          <h2 style={{ fontSize: 16, fontWeight: 700, margin: "0 0 14px 0", color: "#111827", fontFamily: "system-ui, sans-serif", borderBottom: "1px solid #e5e7eb", paddingBottom: 8 }}>
            Remediation Status
          </h2>

          {/* Progress bar */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: "#6b7280", fontFamily: "system-ui, sans-serif", marginBottom: 6 }}>
              <span>{remStats.fixed} of {remStats.total} nodes remediated</span>
              <span>{Math.round((remStats.fixed / Math.max(remStats.total, 1)) * 100)}%</span>
            </div>
            <div style={{ height: 8, background: "#e5e7eb", borderRadius: 4, overflow: "hidden" }}>
              <div style={{
                width: `${(remStats.fixed / Math.max(remStats.total, 1)) * 100}%`,
                height: "100%",
                background: "#22c55e",
                borderRadius: 4,
                transition: "width 0.3s ease",
              }} />
            </div>
          </div>

          {/* Table */}
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, fontFamily: "system-ui, sans-serif" }}>
            <thead>
              <tr style={{ background: "#f9fafb" }}>
                <th style={{ padding: "8px 10px", textAlign: "left", fontWeight: 600, color: "#374151", border: "1px solid #e5e7eb" }}>Node</th>
                <th style={{ padding: "8px 10px", textAlign: "left", fontWeight: 600, color: "#374151", border: "1px solid #e5e7eb" }}>Type</th>
                <th style={{ padding: "8px 10px", textAlign: "left", fontWeight: 600, color: "#374151", border: "1px solid #e5e7eb" }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {allNodes.map((node: any, idx: number) => {
                const rc = nodeRemColor(node.remediationStatus);
                return (
                  <tr key={node.id} style={{ background: idx % 2 === 0 ? "#fff" : "#f9fafb" }}>
                    <td style={{ padding: "7px 10px", color: "#111827", border: "1px solid #e5e7eb" }}>{node.label}</td>
                    <td style={{ padding: "7px 10px", color: "#6b7280", border: "1px solid #e5e7eb", fontFamily: "monospace" }}>{node.nodeType}</td>
                    <td style={{ padding: "7px 10px", border: "1px solid #e5e7eb" }}>
                      <span style={{
                        fontSize: 10,
                        fontWeight: 700,
                        padding: "2px 7px",
                        borderRadius: 4,
                        color: "#fff",
                        background: rc,
                      }}>
                        {nodeRemLabel(node.remediationStatus)}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Footer */}
      <div style={{
        borderTop: "1px solid #e5e7eb",
        paddingTop: 14,
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        fontSize: 11,
        color: "#9ca3af",
        fontFamily: "system-ui, sans-serif",
      }}>
        <span>Generated by OdinForge AI &nbsp;·&nbsp; Confidential</span>
        <span>{formatDate(null)}</span>
      </div>
    </div>
  );
}
