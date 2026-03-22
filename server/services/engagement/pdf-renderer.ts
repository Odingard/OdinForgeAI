/**
 * PDF Renderer — Generates branded PDF reports from engagement data
 *
 * Uses pdfmake to produce professional CISO and Engineer reports
 * with Odingard Security branding.
 */

import * as fs from "fs";
import * as path from "path";
import type { CISOReport } from "./ciso-report";
import type { EngineerReport } from "./engineer-report";
import type { PackageAttackPath, RemediationPlan } from "./engagement-package";

// ── Logo Loading ─────────────────────────────────────────────────────────────

let logoBase64: string | null = null;

function getLogoBase64(): string | null {
  if (logoBase64) return logoBase64;
  try {
    const logoPath = path.join(process.cwd(), "public", "odingard-logo.png");
    const buffer = fs.readFileSync(logoPath);
    logoBase64 = `data:image/png;base64,${buffer.toString("base64")}`;
    return logoBase64;
  } catch {
    console.warn("[PDF] Logo file not found at public/odingard-logo.png");
    return null;
  }
}

// ── Color Palette ────────────────────────────────────────────────────────────

const COLORS = {
  primary: "#1a1a2e",       // dark navy
  accent: "#dc2626",        // red
  accentLight: "#fecaca",
  heading: "#1e293b",
  body: "#334155",
  muted: "#64748b",
  border: "#e2e8f0",
  white: "#ffffff",
  gradeF: "#dc2626",
  gradeE: "#ea580c",
  gradeD: "#d97706",
  gradeC: "#ca8a04",
  gradeB: "#16a34a",
  gradeA: "#059669",
};

function gradeColor(grade: string): string {
  const map: Record<string, string> = { F: COLORS.gradeF, E: COLORS.gradeE, D: COLORS.gradeD, C: COLORS.gradeC, B: COLORS.gradeB, A: COLORS.gradeA };
  return map[grade] || COLORS.muted;
}

// ── CISO Report PDF ──────────────────────────────────────────────────────────

export function buildCISOReportPDF(
  report: CISOReport,
  primaryPath?: PackageAttackPath | null,
  remediation?: RemediationPlan | null
): any {
  const logo = getLogoBase64();
  const now = new Date(report.generatedAt).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

  const content: any[] = [];

  // ── Header with branding ───────────────────────────────────────────
  if (logo) {
    content.push({
      columns: [
        { image: logo, width: 140, margin: [0, 0, 0, 0] },
        {
          text: [
            { text: "Odingard Security\n", style: "companyName" },
            { text: "by Six Sense Enterprise Services", style: "companyTagline" },
          ],
          alignment: "right",
          margin: [0, 10, 0, 0],
        },
      ],
      margin: [0, 0, 0, 20],
    });
  } else {
    content.push({
      text: [
        { text: "ODINGARD SECURITY\n", style: "companyName" },
        { text: "by Six Sense Enterprise Services", style: "companyTagline" },
      ],
      margin: [0, 0, 0, 20],
    });
  }

  // ── Report Title ───────────────────────────────────────────────────
  content.push({ canvas: [{ type: "line", x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 2, lineColor: COLORS.accent }] });
  content.push({ text: "ADVERSARIAL EXPOSURE VALIDATION", style: "reportType", margin: [0, 15, 0, 2] });
  content.push({ text: "Executive Risk Assessment", style: "reportTitle", margin: [0, 0, 0, 5] });
  content.push({ text: `Engagement: ${report.engagementId} | Generated: ${now}`, style: "reportMeta" });
  content.push({ text: "", margin: [0, 0, 0, 15] });

  // ── Risk Grade ─────────────────────────────────────────────────────
  content.push({
    columns: [
      {
        width: 80,
        stack: [
          { text: "RISK GRADE", style: "label", alignment: "center" },
          { text: report.riskGrade, fontSize: 48, bold: true, color: gradeColor(report.riskGrade), alignment: "center", margin: [0, 5, 0, 5] },
          { text: `${report.overallRiskScore}/100`, style: "sublabel", alignment: "center" },
        ],
        margin: [0, 0, 20, 0],
      },
      {
        width: "*",
        stack: [
          { text: report.riskGradeRationale, style: "body", margin: [0, 5, 0, 10] },
        ],
      },
    ],
    margin: [0, 0, 0, 20],
  });

  // ── Primary Breach Path ────────────────────────────────────────────
  if (primaryPath) {
    content.push({ text: "PRIMARY BREACH PATH", style: "sectionHeader" });
    content.push({ canvas: [{ type: "line", x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 1, lineColor: COLORS.border }] });
    content.push({ text: "", margin: [0, 0, 0, 8] });

    content.push({
      columns: [
        { width: "*", text: [{ text: "Path: ", style: "label" }, { text: primaryPath.name, style: "bodyBold" }] },
        { width: 120, text: [{ text: "Confidence: ", style: "label" }, { text: primaryPath.confidence.toUpperCase(), style: "bodyBold", color: COLORS.accent }] },
        { width: 80, text: [{ text: "Score: ", style: "label" }, { text: `${primaryPath.score}/100`, style: "bodyBold" }] },
      ],
      margin: [0, 0, 0, 10],
    });

    content.push({ text: primaryPath.narrative, style: "body", margin: [0, 0, 0, 10] });

    // Steps table
    content.push({ text: "Validated Attack Steps", style: "subHeader", margin: [0, 5, 0, 5] });
    const stepRows = primaryPath.steps.map((s: any) => [
      { text: `${s.order}`, style: "tableCell", alignment: "center" },
      { text: s.action.replace("[VALIDATED] ", ""), style: "tableCell" },
      { text: s.mitreId || "", style: "tableCellMuted" },
    ]);

    content.push({
      table: {
        headerRows: 1,
        widths: [30, "*", 60],
        body: [
          [
            { text: "#", style: "tableHeader", alignment: "center" },
            { text: "Step", style: "tableHeader" },
            { text: "MITRE", style: "tableHeader" },
          ],
          ...stepRows,
        ],
      },
      layout: {
        hLineColor: () => COLORS.border,
        vLineColor: () => COLORS.border,
        fillColor: (rowIndex: number) => rowIndex === 0 ? COLORS.primary : null,
      },
      margin: [0, 0, 0, 15],
    });

    // Business Impact
    content.push({ text: "BUSINESS IMPACT", style: "sectionHeader" });
    content.push({ canvas: [{ type: "line", x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 1, lineColor: COLORS.border }] });
    content.push({ text: primaryPath.businessImpact, style: "body", margin: [0, 8, 0, 15] });
  }

  // ── Executive Narrative ────────────────────────────────────────────
  content.push({ text: "ASSESSMENT NARRATIVE", style: "sectionHeader" });
  content.push({ canvas: [{ type: "line", x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 1, lineColor: COLORS.border }] });
  content.push({ text: report.breachChainNarrative.replace(/### /g, "").replace(/\n- /g, "\n• "), style: "body", margin: [0, 8, 0, 15] });

  // ── Key Metrics ────────────────────────────────────────────────────
  content.push({ text: "KEY METRICS", style: "sectionHeader" });
  content.push({ canvas: [{ type: "line", x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 1, lineColor: COLORS.border }] });
  content.push({
    columns: [
      { width: "*", text: [{ text: "Total Findings: ", style: "label" }, { text: `${report.keyMetrics.totalFindings}`, style: "bodyBold" }] },
      { width: "*", text: [{ text: "Customer Findings: ", style: "label" }, { text: `${report.keyMetrics.customerFindings}`, style: "bodyBold" }] },
      { width: "*", text: [{ text: "Critical: ", style: "label" }, { text: `${report.keyMetrics.criticalFindings}`, style: "bodyBold", color: COLORS.accent }] },
      { width: "*", text: [{ text: "Duration: ", style: "label" }, { text: `${Math.round(report.keyMetrics.chainDurationMs / 1000)}s`, style: "bodyBold" }] },
    ],
    margin: [0, 8, 0, 15],
  });

  // ── Remediation ────────────────────────────────────────────────────
  if (remediation) {
    content.push({ text: "REMEDIATION PLAN", style: "sectionHeader" });
    content.push({ canvas: [{ type: "line", x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 1, lineColor: COLORS.border }] });
    content.push({ text: "", margin: [0, 0, 0, 8] });

    const sections = [
      { title: "Immediate Actions", items: remediation.immediate },
      { title: "Pivot Disruption", items: remediation.pivotDisruption },
      { title: "Artifact Protection", items: remediation.artifactProtection },
      { title: "Privilege Boundary", items: remediation.privilegeBoundary },
      { title: "Monitoring & Detection", items: remediation.monitoring },
    ];

    for (const section of sections) {
      if (section.items.length === 0) continue;
      content.push({ text: section.title, style: "subHeader", margin: [0, 5, 0, 3] });
      content.push({
        ul: section.items.map((item: string) => ({ text: item, style: "body" })),
        margin: [10, 0, 0, 8],
      });
    }
  }

  // ── Evidence Integrity ─────────────────────────────────────────────
  content.push({ text: "EVIDENCE INTEGRITY", style: "sectionHeader", margin: [0, 10, 0, 0] });
  content.push({ canvas: [{ type: "line", x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 1, lineColor: COLORS.border }] });
  content.push({
    columns: [
      { width: "*", text: [{ text: "PROVEN: ", style: "label" }, { text: `${report.evidenceIntegritySummary.proven}`, style: "bodyBold" }] },
      { width: "*", text: [{ text: "CORROBORATED: ", style: "label" }, { text: `${report.evidenceIntegritySummary.corroborated}`, style: "bodyBold" }] },
      { width: "*", text: [{ text: "Suppressed: ", style: "label" }, { text: `${report.evidenceIntegritySummary.inferred + report.evidenceIntegritySummary.unverifiable}`, style: "bodyBold" }] },
      { width: "*", text: [{ text: "Pass Rate: ", style: "label" }, { text: `${(report.evidenceIntegritySummary.filterPassRate * 100).toFixed(0)}%`, style: "bodyBold" }] },
    ],
    margin: [0, 8, 0, 15],
  });

  // ── Footer ─────────────────────────────────────────────────────────
  content.push({ canvas: [{ type: "line", x1: 0, y1: 0, x2: 515, y2: 0, lineWidth: 2, lineColor: COLORS.accent }] });
  content.push({
    text: "This report was generated by OdinForge AEV. All findings are backed by the OdinForge EvidenceContract — only PROVEN and CORROBORATED findings are included in customer deliverables.",
    style: "footer",
    margin: [0, 10, 0, 5],
  });
  content.push({ text: "CONFIDENTIAL — Odingard Security | Six Sense Enterprise Services", style: "footer", alignment: "center" });

  // ── Document Definition ────────────────────────────────────────────
  return {
    content,
    defaultStyle: { font: "Helvetica" },
    styles: {
      companyName: { fontSize: 16, bold: true, color: COLORS.heading },
      companyTagline: { fontSize: 9, color: COLORS.muted },
      reportType: { fontSize: 10, color: COLORS.accent, bold: true, letterSpacing: 2 },
      reportTitle: { fontSize: 22, bold: true, color: COLORS.heading },
      reportMeta: { fontSize: 9, color: COLORS.muted },
      sectionHeader: { fontSize: 12, bold: true, color: COLORS.heading, margin: [0, 15, 0, 3] as any },
      subHeader: { fontSize: 10, bold: true, color: COLORS.heading },
      label: { fontSize: 9, color: COLORS.muted },
      sublabel: { fontSize: 10, color: COLORS.muted },
      body: { fontSize: 10, color: COLORS.body, lineHeight: 1.4 },
      bodyBold: { fontSize: 10, color: COLORS.heading, bold: true },
      tableHeader: { fontSize: 9, bold: true, color: COLORS.white, margin: [4, 4, 4, 4] as any },
      tableCell: { fontSize: 9, color: COLORS.body, margin: [4, 3, 4, 3] as any },
      tableCellMuted: { fontSize: 8, color: COLORS.muted, margin: [4, 3, 4, 3] as any },
      footer: { fontSize: 8, color: COLORS.muted, italics: true },
    },
    pageSize: "LETTER",
    pageMargins: [40, 40, 40, 40],
  };
}
