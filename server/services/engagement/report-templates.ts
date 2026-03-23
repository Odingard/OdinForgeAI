/**
 * Report Templates — HTML section generators for the HTML→PDF report engine
 *
 * Each function returns an HTML string for a specific report section.
 * Used by html-report-renderer.ts to compose the full document.
 */

import type { ReportConfig, ColorScheme } from "./report-config";
import { getColorScheme } from "./report-config";
import type { CISOReport } from "./ciso-report";
import type { EngineerReport, EngineerFindingDetail } from "./engineer-report";
import type { PackageAttackPath, RemediationPlan } from "./engagement-package";

// ── Shared Types ─────────────────────────────────────────────────────────────

export interface ReportData {
  cisoReport: CISOReport;
  engineerReport: EngineerReport;
  primaryPath: PackageAttackPath | null;
  supportingPaths: PackageAttackPath[];
  remediation: RemediationPlan | null;
  sealStatus: "sealed" | "unsealed";
  componentHashes?: Record<string, string>;
}

// ── Utility ──────────────────────────────────────────────────────────────────

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function gradeColor(grade: string, cs: ColorScheme): string {
  const map: Record<string, string> = {
    A: cs.gradeA, B: cs.gradeB, C: cs.gradeC,
    D: cs.gradeD, E: cs.gradeE, F: cs.gradeF,
  };
  return map[grade] || cs.muted;
}

function sevColor(sev: string, cs: ColorScheme): string {
  const map: Record<string, string> = {
    critical: cs.sevCritical, high: cs.sevHigh,
    medium: cs.sevMedium, low: cs.sevLow,
  };
  return map[sev] || cs.muted;
}

function classificationColor(classification: string): string {
  const map: Record<string, string> = {
    CONFIDENTIAL: "#dc2626",
    RESTRICTED: "#d97706",
    "CLIENT CONFIDENTIAL": "#ea580c",
    PUBLIC: "#16a34a",
  };
  return map[classification] || "#64748b";
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
}

// ── Styles ───────────────────────────────────────────────────────────────────

export function renderStyles(config: ReportConfig): string {
  const cs = getColorScheme(config);
  const isLight = config.colorScheme !== "executive";
  const pageW = config.pageSize === "A4" ? "210mm" : "8.5in";
  const pageH = config.pageSize === "A4" ? "297mm" : "11in";

  return `
    @page {
      size: ${pageW} ${pageH};
      margin: 20mm 18mm 25mm 18mm;

      @bottom-left {
        content: "${config.classification} — Odingard Security — Engagement ${escapeHtml(config.engagementId)}";
        font-family: "Segoe UI", Helvetica, Arial, sans-serif;
        font-size: 7pt;
        color: ${cs.muted};
      }
      @bottom-right {
        content: "Page " counter(page);
        font-family: "Segoe UI", Helvetica, Arial, sans-serif;
        font-size: 7pt;
        color: ${cs.muted};
      }
    }

    @page cover {
      margin: 0;
      @bottom-left { content: none; }
      @bottom-right { content: none; }
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: "Segoe UI", Helvetica, Arial, sans-serif;
      font-size: 10pt;
      color: ${isLight ? cs.body : cs.body};
      background: ${cs.background};
      line-height: 1.5;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }

    .cover-page {
      page: cover;
      width: 100vw;
      height: 100vh;
      background: ${cs.coverBg};
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      text-align: center;
      color: ${cs.coverText};
      page-break-after: always;
      position: relative;
      overflow: hidden;
    }

    .cover-page::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: radial-gradient(ellipse at 30% 20%, rgba(${config.colorScheme === "minimal" ? "29,78,216" : config.colorScheme === "executive" ? "183,28,28" : "44,62,80"},.12) 0%, transparent 60%);
    }

    .cover-logo { width: 160px; margin-bottom: 32px; position: relative; z-index: 1; }
    .cover-company { font-size: 18pt; font-weight: 700; letter-spacing: 6px; text-transform: uppercase; margin-bottom: 4px; position: relative; z-index: 1; }
    .cover-tagline { font-size: 9pt; color: ${cs.muted}; margin-bottom: 48px; position: relative; z-index: 1; }
    .cover-title { font-size: 28pt; font-weight: 700; margin-bottom: 8px; position: relative; z-index: 1; line-height: 1.2; max-width: 80%; }
    .cover-client { font-size: 14pt; color: ${cs.muted}; margin-bottom: 24px; position: relative; z-index: 1; }
    .cover-meta { font-size: 9pt; color: ${cs.muted}; margin-bottom: 8px; position: relative; z-index: 1; }
    .cover-classification {
      display: inline-block;
      padding: 4px 16px;
      font-size: 8pt;
      font-weight: 700;
      letter-spacing: 2px;
      border: 2px solid;
      margin-top: 32px;
      position: relative;
      z-index: 1;
    }
    .cover-assessor { font-size: 9pt; color: ${cs.muted}; margin-top: 16px; position: relative; z-index: 1; }

    .toc-page { page-break-after: always; padding-top: 24px; }
    .toc-title { font-size: 18pt; font-weight: 700; color: ${cs.heading}; margin-bottom: 24px; border-bottom: 2px solid ${cs.accent}; padding-bottom: 8px; }
    .toc-entry {
      display: flex;
      align-items: baseline;
      padding: 6px 0;
      border-bottom: 1px dotted ${cs.border};
    }
    .toc-entry-name { font-size: 10pt; color: ${cs.heading}; font-weight: 500; }
    .toc-entry-leader { flex: 1; border-bottom: 1px dotted ${cs.border}; margin: 0 8px; min-width: 40px; }
    .toc-entry-page { font-size: 10pt; color: ${cs.muted}; font-weight: 500; }

    .section-break { page-break-before: always; }
    .section-title {
      font-size: 16pt;
      font-weight: 700;
      color: ${cs.heading};
      border-bottom: 2px solid ${cs.accent};
      padding-bottom: 6px;
      margin-bottom: 16px;
      margin-top: 8px;
    }
    .sub-title { font-size: 12pt; font-weight: 700; color: ${cs.heading}; margin: 16px 0 8px 0; }
    .sub-title-sm { font-size: 10pt; font-weight: 700; color: ${cs.heading}; margin: 12px 0 6px 0; }

    .text-body { font-size: 10pt; color: ${isLight ? cs.body : cs.body}; line-height: 1.6; margin-bottom: 12px; }
    .text-muted { font-size: 9pt; color: ${cs.muted}; }

    /* Risk Grade Badge */
    .grade-badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 64px;
      height: 64px;
      font-size: 36pt;
      font-weight: 800;
      border: 3px solid;
      border-radius: 8px;
      margin-right: 20px;
      flex-shrink: 0;
    }

    /* Metrics row */
    .metrics-row {
      display: flex;
      gap: 12px;
      margin: 16px 0;
    }
    .metric-card {
      flex: 1;
      padding: 12px;
      border: 1px solid ${cs.border};
      background: ${isLight ? cs.panel : cs.panel};
      text-align: center;
    }
    .metric-val { font-size: 20pt; font-weight: 700; color: ${cs.heading}; }
    .metric-label { font-size: 8pt; color: ${cs.muted}; text-transform: uppercase; letter-spacing: 1px; margin-top: 2px; }

    /* Business Impact Box */
    .impact-box {
      border-left: 4px solid ${cs.accent};
      padding: 12px 16px;
      background: ${isLight ? "#fef2f2" : "rgba(220,38,38,.06)"};
      margin: 16px 0;
    }
    .impact-box-title { font-size: 10pt; font-weight: 700; color: ${cs.accent}; margin-bottom: 4px; }

    /* Attack Chain Flow */
    .chain-flow {
      display: flex;
      align-items: center;
      gap: 0;
      margin: 16px 0;
      overflow-x: auto;
      padding: 8px 0;
    }
    .chain-step {
      flex-shrink: 0;
      min-width: 120px;
      max-width: 160px;
      padding: 10px 12px;
      border: 1px solid ${cs.border};
      background: ${isLight ? cs.panel : cs.panel};
      text-align: center;
      position: relative;
    }
    .chain-step-num {
      font-size: 7pt;
      color: ${cs.muted};
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 4px;
    }
    .chain-step-name { font-size: 9pt; font-weight: 600; color: ${cs.heading}; margin-bottom: 2px; word-break: break-word; }
    .chain-step-mitre { font-size: 7pt; color: ${cs.muted}; }
    .chain-arrow {
      flex-shrink: 0;
      width: 24px;
      text-align: center;
      font-size: 14pt;
      color: ${cs.accent};
      font-weight: 700;
    }

    /* Finding Cards */
    .finding-card {
      border: 1px solid ${cs.border};
      margin-bottom: 16px;
      page-break-inside: avoid;
    }
    .finding-header {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 14px;
      border-bottom: 1px solid ${cs.border};
      background: ${isLight ? cs.panel : cs.panel};
    }
    .sev-badge {
      display: inline-block;
      padding: 2px 8px;
      font-size: 7pt;
      font-weight: 700;
      letter-spacing: 1px;
      text-transform: uppercase;
      color: #fff;
      flex-shrink: 0;
    }
    .finding-title { font-size: 10pt; font-weight: 600; color: ${cs.heading}; flex: 1; }
    .finding-mitre { font-size: 8pt; color: ${cs.muted}; flex-shrink: 0; }
    .finding-body { padding: 12px 14px; }
    .finding-desc { font-size: 9pt; color: ${isLight ? cs.body : cs.body}; line-height: 1.5; margin-bottom: 8px; }
    .finding-meta-row {
      display: flex;
      gap: 16px;
      font-size: 8pt;
      color: ${cs.muted};
      margin-bottom: 8px;
    }
    .finding-meta-item { display: flex; gap: 4px; }
    .finding-meta-label { font-weight: 600; }
    .evidence-badge {
      display: inline-block;
      padding: 1px 6px;
      font-size: 7pt;
      font-weight: 700;
      letter-spacing: .5px;
      border: 1px solid;
    }

    /* Code blocks */
    .code-block {
      background: ${isLight ? "#f8fafc" : "#0f172a"};
      border: 1px solid ${cs.border};
      padding: 10px 12px;
      font-family: "Cascadia Code", "Fira Code", "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 8pt;
      color: ${isLight ? "#334155" : "#e2e8f0"};
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      margin: 8px 0;
      line-height: 1.5;
    }
    .code-label { font-size: 7pt; color: ${cs.muted}; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }

    /* Remediation */
    .remediation-section { margin-bottom: 16px; }
    .remediation-category {
      font-size: 10pt;
      font-weight: 700;
      color: ${cs.heading};
      padding: 6px 12px;
      background: ${isLight ? cs.panel : cs.panel};
      border-left: 3px solid ${cs.accent};
      margin-bottom: 8px;
    }
    .remediation-list { padding-left: 20px; margin-bottom: 12px; }
    .remediation-list li {
      font-size: 9pt;
      color: ${isLight ? cs.body : cs.body};
      line-height: 1.6;
      margin-bottom: 4px;
    }

    /* Methodology */
    .methodology-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin: 16px 0;
    }
    .methodology-card {
      border: 1px solid ${cs.border};
      padding: 12px;
      background: ${isLight ? cs.panel : cs.panel};
    }
    .methodology-card-title { font-size: 9pt; font-weight: 700; color: ${cs.heading}; margin-bottom: 4px; }
    .methodology-card-body { font-size: 8pt; color: ${cs.muted}; line-height: 1.5; }

    /* Appendix */
    .hash-table { width: 100%; border-collapse: collapse; margin: 12px 0; }
    .hash-table th {
      text-align: left;
      padding: 6px 10px;
      font-size: 8pt;
      font-weight: 700;
      color: ${cs.white};
      background: ${isLight ? cs.dark : cs.dark};
      text-transform: uppercase;
      letter-spacing: .5px;
    }
    .hash-table td {
      padding: 6px 10px;
      font-size: 8pt;
      color: ${isLight ? cs.body : cs.body};
      border-bottom: 1px solid ${cs.border};
      font-family: "SF Mono", Consolas, monospace;
    }

    /* Evidence Integrity Guide */
    .integrity-guide {
      border: 1px solid ${cs.accent};
      border-left: 4px solid ${cs.accent};
      padding: 16px 20px;
      margin: 20px 0;
      background: ${isLight ? "#f0f9ff" : "rgba(59,130,246,.06)"};
      page-break-inside: avoid;
    }
    .integrity-guide-title {
      font-size: 11pt;
      font-weight: 700;
      color: ${cs.accent};
      letter-spacing: 1px;
      margin-bottom: 10px;
    }
  `;
}

// ── Cover Page ───────────────────────────────────────────────────────────────

export function renderCoverPage(data: ReportData, config: ReportConfig, logoBase64: string | null): string {
  if (!config.sections.coverPage) return "";
  const clsColor = classificationColor(config.classification);
  const dateStr = formatDate(data.cisoReport.generatedAt);

  return `
    <div class="cover-page">
      ${logoBase64 ? `<img src="${logoBase64}" class="cover-logo" alt="Odingard Security" />` : ""}
      <div class="cover-company">ODINGARD SECURITY</div>
      <div class="cover-tagline">by Six Sense Enterprise Services</div>
      <div class="cover-title">${escapeHtml(config.reportTitle)}</div>
      ${config.clientName ? `<div class="cover-client">Prepared for: ${escapeHtml(config.clientName)}</div>` : ""}
      <div class="cover-meta">Engagement: ${escapeHtml(config.engagementId)}</div>
      <div class="cover-meta">${dateStr}</div>
      ${config.assessorName ? `<div class="cover-assessor">Assessor: ${escapeHtml(config.assessorName)}${config.assessorCredentials ? ` (${escapeHtml(config.assessorCredentials)})` : ""}</div>` : ""}
      <div class="cover-classification" style="color: ${clsColor}; border-color: ${clsColor};">
        ${escapeHtml(config.classification)}
      </div>
    </div>
  `;
}

// ── Table of Contents ────────────────────────────────────────────────────────

export function renderTableOfContents(data: ReportData, config: ReportConfig): string {
  if (!config.sections.tableOfContents) return "";

  const sections: { name: string; enabled: boolean }[] = [
    { name: "Executive Summary", enabled: config.sections.executiveSummary },
    { name: "Attack Chain Visualization", enabled: config.sections.attackChainVisualization },
    { name: "Detailed Findings", enabled: config.sections.detailedFindings },
    { name: "Remediation Plan", enabled: config.sections.remediationPlan },
    { name: "Methodology", enabled: config.sections.methodology },
    { name: "Appendix", enabled: config.sections.appendix },
    { name: "Evidence Appendix", enabled: config.sections.evidenceAppendix },
  ];

  const entries = sections
    .filter(s => s.enabled)
    .map(s => `
      <div class="toc-entry">
        <span class="toc-entry-name">${escapeHtml(s.name)}</span>
        <span class="toc-entry-leader"></span>
      </div>
    `)
    .join("");

  return `
    <div class="toc-page">
      <div class="toc-title">Table of Contents</div>
      ${entries}
    </div>
  `;
}

// ── Executive Summary ────────────────────────────────────────────────────────

export function renderExecutiveSummary(data: ReportData, config: ReportConfig): string {
  if (!config.sections.executiveSummary) return "";

  const cs = getColorScheme(config);
  const ciso = data.cisoReport;
  const gc = gradeColor(ciso.riskGrade, cs);

  const metrics = ciso.keyMetrics;
  const duration = metrics.chainDurationMs > 0
    ? `${Math.round(metrics.chainDurationMs / 1000)}s`
    : "N/A";

  return `
    <div class="section-break">
      <div class="section-title">Executive Summary</div>

      <div style="display: flex; align-items: flex-start; margin-bottom: 16px;">
        <div class="grade-badge" style="color: ${gc}; border-color: ${gc};">
          ${escapeHtml(ciso.riskGrade)}
        </div>
        <div style="flex: 1;">
          <div style="font-size: 12pt; font-weight: 700; color: ${cs.heading}; margin-bottom: 4px;">
            Risk Score: ${ciso.overallRiskScore}/100
          </div>
          <div class="text-body">${escapeHtml(ciso.riskGradeRationale)}</div>
        </div>
      </div>

      ${data.primaryPath ? `
        <div class="sub-title">Primary Breach Path</div>
        <div style="display: flex; gap: 16px; margin-bottom: 8px;">
          <span style="font-size: 9pt; color: ${cs.heading}; font-weight: 600;">${escapeHtml(data.primaryPath.name)}</span>
          <span style="font-size: 9pt; color: ${cs.accent}; font-weight: 700; text-transform: uppercase;">${escapeHtml(data.primaryPath.confidence)}</span>
        </div>
        <div class="text-body">${escapeHtml(data.primaryPath.narrative)}</div>
      ` : ""}

      <div class="impact-box">
        <div class="impact-box-title">Business Impact</div>
        <div class="text-body" style="margin-bottom: 0;">${escapeHtml(ciso.businessImpact.summary)}</div>
      </div>

      <div class="sub-title">Key Metrics</div>
      <div class="metrics-row">
        <div class="metric-card">
          <div class="metric-val">${metrics.totalFindings}</div>
          <div class="metric-label">Total Findings</div>
        </div>
        <div class="metric-card">
          <div class="metric-val" style="color: ${cs.sevCritical};">${metrics.criticalFindings}</div>
          <div class="metric-label">Critical</div>
        </div>
        <div class="metric-card">
          <div class="metric-val">${metrics.customerFindings}</div>
          <div class="metric-label">Customer Findings</div>
        </div>
        <div class="metric-card">
          <div class="metric-val">${duration}</div>
          <div class="metric-label">Duration</div>
        </div>
        <div class="metric-card">
          <div class="metric-val">${metrics.phasesCompleted}/${metrics.totalPhases}</div>
          <div class="metric-label">Phases</div>
        </div>
      </div>

      <div class="text-body">${escapeHtml(ciso.breachChainNarrative.replace(/### /g, "").replace(/\n/g, " "))}</div>
    </div>
  `;
}

// ── Attack Chain Visualization ───────────────────────────────────────────────

export function renderAttackChain(data: ReportData, config: ReportConfig): string {
  if (!config.sections.attackChainVisualization) return "";
  if (!data.primaryPath) return "";

  const cs = getColorScheme(config);
  const steps = data.primaryPath.steps || [];

  const stepsHtml = steps.map((step, i) => {
    const arrow = i < steps.length - 1 ? `<div class="chain-arrow">&rarr;</div>` : "";
    const sColor = sevColorForStep(step, cs);
    return `
      <div class="chain-step" style="border-top: 3px solid ${sColor};">
        <div class="chain-step-num">Step ${step.order}</div>
        <div class="chain-step-name">${escapeHtml(truncate(step.action.replace("[VALIDATED] ", ""), 60))}</div>
        <div class="chain-step-mitre">${escapeHtml(step.mitreId || "")}</div>
      </div>
      ${arrow}
    `;
  }).join("");

  const supportingHtml = data.supportingPaths.length > 0
    ? `
      <div class="sub-title" style="margin-top: 24px;">Supporting Paths</div>
      ${data.supportingPaths.map(p => `
        <div style="padding: 8px 12px; border: 1px solid ${cs.border}; margin-bottom: 8px;">
          <span style="font-size: 9pt; font-weight: 600; color: ${cs.heading};">${escapeHtml(p.name)}</span>
          <span style="font-size: 8pt; color: ${cs.muted}; margin-left: 8px;">Confidence: ${escapeHtml(p.confidence)} | Score: ${p.score}/100</span>
          <div style="font-size: 8pt; color: ${cs.muted}; margin-top: 4px;">${escapeHtml(p.narrative)}</div>
        </div>
      `).join("")}
    `
    : "";

  return `
    <div class="section-break">
      <div class="section-title">Attack Chain Visualization</div>
      <div class="sub-title">Primary Path: ${escapeHtml(data.primaryPath.name)}</div>
      <div style="font-size: 9pt; color: ${cs.muted}; margin-bottom: 12px;">
        Confidence: <strong style="color: ${cs.accent};">${escapeHtml(data.primaryPath.confidence.toUpperCase())}</strong>
        &nbsp;&nbsp;|&nbsp;&nbsp;Path Score: <strong>${data.primaryPath.score}/100</strong>
      </div>
      <div class="chain-flow">${stepsHtml}</div>
      <div class="text-body" style="margin-top: 12px;">${escapeHtml(data.primaryPath.narrative)}</div>
      ${supportingHtml}
    </div>
  `;
}

function sevColorForStep(step: { technique?: string }, cs: ColorScheme): string {
  // Color based on technique keywords
  const t = (step.technique || "").toLowerCase();
  if (t.includes("admin") || t.includes("rce") || t.includes("inject")) return cs.sevCritical;
  if (t.includes("auth") || t.includes("cred") || t.includes("escalat")) return cs.sevHigh;
  return cs.accent;
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 3) + "..." : s;
}

// ── Detailed Findings ────────────────────────────────────────────────────────

export function renderDetailedFindings(data: ReportData, config: ReportConfig): string {
  if (!config.sections.detailedFindings) return "";

  const cs = getColorScheme(config);
  const findings = data.engineerReport.findingDetails;

  if (findings.length === 0) {
    return `
      <div class="section-break">
        <div class="section-title">Detailed Findings</div>
        <div class="text-body">No findings met the evidence quality threshold for inclusion in this report.</div>
      </div>
    `;
  }

  const cards = findings.map(f => renderFindingCard(f, config, cs)).join("");

  return `
    <div class="section-break">
      <div class="section-title">Detailed Findings</div>
      <div class="text-body" style="margin-bottom: 16px;">
        ${findings.length} finding(s) included. Only PROVEN and CORROBORATED findings appear in customer deliverables.
      </div>
      ${cards}
    </div>
  `;
}

function renderFindingCard(finding: EngineerFindingDetail, config: ReportConfig, cs: ColorScheme): string {
  const sc = sevColor(finding.severity, cs);
  const eq = (finding.evidenceQuality || "unknown").toUpperCase();
  const eqColor = eq === "PROVEN" ? cs.gradeA : eq === "CORROBORATED" ? cs.gradeB : cs.muted;

  let evidenceHtml = "";

  if (config.includeRawEvidence || config.includeCurlCommands) {
    const curlCmd = (finding as any).curlCommand;
    if (curlCmd && config.includeCurlCommands) {
      evidenceHtml += `
        <div class="code-label">Reproduction Command</div>
        <div class="code-block">${escapeHtml(curlCmd)}</div>
      `;
    }
  }

  if (config.includeResponseBodies && finding.httpEvidence) {
    const preview = finding.httpEvidence.responseBodyPreview || "";
    if (preview) {
      const truncated = preview.slice(0, config.maxResponseBodyLength);
      evidenceHtml += `
        <div class="code-label">Response Body (HTTP ${finding.httpEvidence.statusCode})</div>
        <div class="code-block">${escapeHtml(truncated)}${preview.length > config.maxResponseBodyLength ? "\n... [truncated]" : ""}</div>
      `;
    }
  }

  return `
    <div class="finding-card">
      <div class="finding-header">
        <span class="sev-badge" style="background: ${sc};">${escapeHtml(finding.severity.toUpperCase())}</span>
        <span class="finding-title">${escapeHtml(finding.title.replace("[VALIDATED] ", ""))}</span>
        ${finding.mitreId ? `<span class="finding-mitre">${escapeHtml(finding.mitreId)}</span>` : ""}
      </div>
      <div class="finding-body">
        <div class="finding-desc">${escapeHtml(finding.description)}</div>
        <div class="finding-meta-row">
          <div class="finding-meta-item">
            <span class="finding-meta-label">Evidence:</span>
            <span class="evidence-badge" style="color: ${eqColor}; border-color: ${eqColor};">${eq}</span>
          </div>
          ${finding.technique ? `<div class="finding-meta-item"><span class="finding-meta-label">Technique:</span> ${escapeHtml(finding.technique)}</div>` : ""}
          ${finding.httpEvidence ? `<div class="finding-meta-item"><span class="finding-meta-label">HTTP:</span> ${finding.httpEvidence.statusCode}</div>` : ""}
          ${finding.source ? `<div class="finding-meta-item"><span class="finding-meta-label">Source:</span> ${escapeHtml(finding.source)}</div>` : ""}
        </div>
        ${evidenceHtml}
      </div>
    </div>
  `;
}

// ── Remediation Plan ─────────────────────────────────────────────────────────

export function renderRemediationPlan(data: ReportData, config: ReportConfig): string {
  if (!config.sections.remediationPlan) return "";
  if (!data.remediation) return "";

  const categories: { title: string; items: string[] }[] = [
    { title: "Immediate Actions", items: data.remediation.immediate || [] },
    { title: "Pivot Disruption", items: data.remediation.pivotDisruption || [] },
    { title: "Artifact Protection", items: data.remediation.artifactProtection || [] },
    { title: "Privilege Boundary", items: data.remediation.privilegeBoundary || [] },
    { title: "Monitoring & Detection", items: data.remediation.monitoring || [] },
  ];

  const categoriesHtml = categories
    .filter(c => c.items.length > 0)
    .map(c => `
      <div class="remediation-section">
        <div class="remediation-category">${escapeHtml(c.title)}</div>
        <ul class="remediation-list">
          ${c.items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}
        </ul>
      </div>
    `)
    .join("");

  return `
    <div class="section-break">
      <div class="section-title">Remediation Plan</div>
      <div class="text-body">
        Remediation recommendations are organized by priority category, derived from validated attack paths and confirmed findings.
      </div>
      ${categoriesHtml}
    </div>
  `;
}

// ── Methodology ──────────────────────────────────────────────────────────────

export function renderMethodology(config: ReportConfig): string {
  if (!config.sections.methodology) return "";

  return `
    <div class="section-break">
      <div class="section-title">Methodology</div>
      <div class="text-body">
        This assessment was conducted using the OdinForge Adversarial Exposure Validation (AEV) platform.
        The methodology employs a multi-phase breach chain approach to systematically discover, validate,
        and exploit security weaknesses across the target environment.
      </div>

      <div class="sub-title">Assessment Phases</div>
      <div class="methodology-grid">
        <div class="methodology-card">
          <div class="methodology-card-title">Phase 1: Application Compromise</div>
          <div class="methodology-card-body">
            Automated vulnerability discovery and exploitation of web application flaws including injection,
            authentication bypass, SSRF, and configuration exposure.
          </div>
        </div>
        <div class="methodology-card">
          <div class="methodology-card-title">Phase 2: Credential Extraction</div>
          <div class="methodology-card-body">
            Harvesting of exposed credentials, tokens, and secrets from application responses,
            configuration files, and error messages.
          </div>
        </div>
        <div class="methodology-card">
          <div class="methodology-card-title">Phase 3: Cloud IAM Escalation</div>
          <div class="methodology-card-body">
            Privilege escalation through cloud IAM misconfigurations, service account abuse,
            and cross-account access chains.
          </div>
        </div>
        <div class="methodology-card">
          <div class="methodology-card-title">Phase 4: Container/K8s Breakout</div>
          <div class="methodology-card-body">
            Container escape and Kubernetes cluster compromise through API server exposure,
            RBAC misconfigurations, and secrets access.
          </div>
        </div>
        <div class="methodology-card">
          <div class="methodology-card-title">Phase 5: Lateral Movement</div>
          <div class="methodology-card-body">
            Network traversal and pivoting using harvested credentials to access additional
            systems and expand the breach footprint.
          </div>
        </div>
        <div class="methodology-card">
          <div class="methodology-card-title">Phase 6: Impact Assessment</div>
          <div class="methodology-card-body">
            Evaluation of total business impact including data exposure, privilege achieved,
            compliance implications, and blast radius estimation.
          </div>
        </div>
      </div>

      <div class="sub-title">Evidence Quality Gate</div>
      <div class="text-body">
        All findings are classified by the OdinForge Evidence Quality Gate (ADR-001):
      </div>
      <div class="methodology-grid">
        <div class="methodology-card">
          <div class="methodology-card-title" style="color: #059669;">PROVEN</div>
          <div class="methodology-card-body">Direct HTTP evidence with reproducible curl command and confirming response.</div>
        </div>
        <div class="methodology-card">
          <div class="methodology-card-title" style="color: #16a34a;">CORROBORATED</div>
          <div class="methodology-card-body">Multiple independent signals confirm the vulnerability exists.</div>
        </div>
        <div class="methodology-card">
          <div class="methodology-card-title" style="color: #d97706;">INFERRED</div>
          <div class="methodology-card-body">Indirect evidence suggests vulnerability presence. Excluded from customer reports.</div>
        </div>
        <div class="methodology-card">
          <div class="methodology-card-title" style="color: #dc2626;">UNVERIFIABLE</div>
          <div class="methodology-card-body">Insufficient evidence to confirm. Excluded from customer reports.</div>
        </div>
      </div>

      <div class="sub-title">Evidence Integrity</div>
      <div class="text-body">
        Every finding produced by OdinForge is backed by real exploitation &mdash; not simulation,
        not inference. When a vulnerability is confirmed, the platform captures the full HTTP request
        and response at the moment of exploitation and immediately computes a SHA-256 cryptographic hash
        of this evidence. This hash is embedded alongside each finding and cannot be retroactively altered
        without detection.
      </div>
      <div class="text-body">
        Once all assessment phases are complete, the engagement package &mdash; containing executive
        and technical reports, attack chain replays, and the raw evidence &mdash; is sealed with a
        master SHA-256 hash that covers every component. This seal confirms that the entire deliverable
        is intact and has not been modified after the assessment concluded.
      </div>

      <div class="sub-title">Deterministic Scoring</div>
      <div class="text-body">
        OdinForge Deterministic Scoring v3.0 computes risk scores from three weighted components:
        EPSS (45%), CVSS (35%), and Agent Exploitability (20%). Findings on the CISA KEV list
        receive a minimum score override of 85.
      </div>

      ${config.customDisclaimer ? `
        <div class="sub-title">Disclaimer</div>
        <div class="text-body">${escapeHtml(config.customDisclaimer)}</div>
      ` : ""}

      ${config.customLegalText ? `
        <div class="sub-title">Legal Notice</div>
        <div class="text-body">${escapeHtml(config.customLegalText)}</div>
      ` : ""}
    </div>
  `;
}

// ── Appendix ─────────────────────────────────────────────────────────────────

export function renderAppendix(data: ReportData, config: ReportConfig): string {
  if (!config.sections.appendix) return "";

  const cs = getColorScheme(config);
  const eng = data.engineerReport;

  // Endpoint list from findings
  const endpoints = eng.findingDetails
    .filter(f => f.httpEvidence)
    .map(f => `${f.title} (HTTP ${f.httpEvidence?.statusCode ?? "N/A"})`);

  // Integrity hashes
  const hashes = data.componentHashes || {};
  const hashRows = Object.entries(hashes).map(([component, hash]) =>
    `<tr><td style="font-weight: 600; font-family: inherit;">${escapeHtml(component)}</td><td>${escapeHtml(hash)}</td></tr>`
  ).join("");

  return `
    <div class="section-break">
      <div class="section-title">Appendix</div>

      ${endpoints.length > 0 ? `
        <div class="sub-title">Validated Endpoints</div>
        <ul class="remediation-list">
          ${endpoints.map(ep => `<li>${escapeHtml(ep)}</li>`).join("")}
        </ul>
      ` : ""}

      ${hashRows ? `
        <div class="sub-title">Evidence Integrity &mdash; SHA-256 Hashes</div>
        <table class="hash-table">
          <thead><tr><th>Component</th><th>SHA-256</th></tr></thead>
          <tbody>${hashRows}</tbody>
        </table>

        <div class="integrity-guide">
          <div class="integrity-guide-title">EVIDENCE INTEGRITY VERIFICATION</div>
          <div class="text-body">
            Each finding in this report includes a SHA-256 cryptographic hash computed at the moment
            of discovery. These hashes prove that the evidence has not been modified since the
            assessment was conducted.
          </div>

          <div class="sub-title-sm">How to Verify</div>
          <ol class="remediation-list">
            <li>The engagement package includes a sealed evidence manifest containing all component hashes.</li>
            <li>Each finding&rsquo;s hash was computed from the full HTTP request, HTTP response, and timestamp captured at exploitation time.</li>
            <li>To verify: recompute the SHA-256 hash of the same inputs and compare it with the value shown above.</li>
            <li>Matching hashes confirm the evidence is authentic and has not been modified.</li>
          </ol>

          <div class="sub-title-sm">Why This Matters</div>
          <ul class="remediation-list">
            <li>Proves that findings are real and were not fabricated.</li>
            <li>Confirms that evidence has not been tampered with after discovery.</li>
            <li>Provides an auditable chain of evidence for compliance and regulatory purposes.</li>
            <li>Can be independently verified by any party with access to the raw evidence data.</li>
          </ul>

          <div class="sub-title-sm">Package Seal</div>
          <div class="text-body">
            The complete engagement package is sealed with a master SHA-256 hash that covers all
            components listed above. A <strong>SEALED</strong> status confirms the entire deliverable
            &mdash; executive report, technical report, attack chain replay, and raw evidence &mdash;
            is intact and unmodified.
          </div>
        </div>
      ` : ""}

      <div class="sub-title">Engagement Status</div>
      <div class="text-body">
        Seal Status: <strong style="color: ${data.sealStatus === "sealed" ? cs.gradeA : cs.muted};">${data.sealStatus.toUpperCase()}</strong>
      </div>

      <div class="sub-title">Evidence Integrity Summary</div>
      <div class="metrics-row">
        <div class="metric-card">
          <div class="metric-val" style="color: ${cs.gradeA};">${data.cisoReport.evidenceIntegritySummary.proven}</div>
          <div class="metric-label">Proven</div>
        </div>
        <div class="metric-card">
          <div class="metric-val" style="color: ${cs.gradeB};">${data.cisoReport.evidenceIntegritySummary.corroborated}</div>
          <div class="metric-label">Corroborated</div>
        </div>
        <div class="metric-card">
          <div class="metric-val" style="color: ${cs.sevMedium};">${data.cisoReport.evidenceIntegritySummary.inferred}</div>
          <div class="metric-label">Inferred (Suppressed)</div>
        </div>
        <div class="metric-card">
          <div class="metric-val">${Math.round(data.cisoReport.evidenceIntegritySummary.filterPassRate * 100)}%</div>
          <div class="metric-label">Pass Rate</div>
        </div>
      </div>
    </div>
  `;
}
