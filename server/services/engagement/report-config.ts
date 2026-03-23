/**
 * Report Configuration Schema — Per-engagement PDF customization
 *
 * Operators can customize report appearance, content sections, and
 * branding per engagement before generating the final PDF deliverable.
 */

// ── Report Configuration Interface ───────────────────────────────────────────

export interface ReportConfig {
  // Client info
  clientName: string;
  clientLogo?: string; // base64 data URI or URL
  engagementId: string;
  assessorName?: string;
  assessorCredentials?: string;

  // Branding
  reportTitle: string;
  classification: "CONFIDENTIAL" | "RESTRICTED" | "CLIENT CONFIDENTIAL" | "PUBLIC";
  colorScheme: "odingard" | "neutral" | "dark";

  // Sections to include
  sections: {
    coverPage: boolean;
    tableOfContents: boolean;
    executiveSummary: boolean;
    attackChainVisualization: boolean;
    detailedFindings: boolean;
    remediationPlan: boolean;
    methodology: boolean;
    appendix: boolean;
    evidenceAppendix: boolean;
  };

  // Content options
  includeRawEvidence: boolean;
  includeCurlCommands: boolean;
  includeResponseBodies: boolean;
  maxResponseBodyLength: number;
  customDisclaimer?: string;
  customLegalText?: string;

  // Output
  pageSize: "A4" | "Letter";
  orientation: "portrait" | "landscape";
}

// ── Default Configuration ────────────────────────────────────────────────────

export const DEFAULT_REPORT_CONFIG: ReportConfig = {
  clientName: "",
  engagementId: "",
  reportTitle: "Adversarial Exposure Assessment",
  classification: "CONFIDENTIAL",
  colorScheme: "odingard",
  sections: {
    coverPage: true,
    tableOfContents: true,
    executiveSummary: true,
    attackChainVisualization: true,
    detailedFindings: true,
    remediationPlan: true,
    methodology: true,
    appendix: true,
    evidenceAppendix: true,
  },
  includeRawEvidence: true,
  includeCurlCommands: true,
  includeResponseBodies: true,
  maxResponseBodyLength: 2000,
  pageSize: "A4",
  orientation: "portrait",
};

// ── Color Schemes ────────────────────────────────────────────────────────────

export interface ColorScheme {
  accent: string;
  accentLight: string;
  dark: string;
  panel: string;
  panelBorder: string;
  heading: string;
  body: string;
  muted: string;
  border: string;
  white: string;
  background: string;
  coverBg: string;
  coverText: string;
  gradeA: string;
  gradeB: string;
  gradeC: string;
  gradeD: string;
  gradeE: string;
  gradeF: string;
  sevCritical: string;
  sevHigh: string;
  sevMedium: string;
  sevLow: string;
}

export const COLOR_SCHEMES: Record<string, ColorScheme> = {
  odingard: {
    accent: "#dc2626",
    accentLight: "#fecaca",
    dark: "#0a0e17",
    panel: "#1e293b",
    panelBorder: "#334155",
    heading: "#f8fafc",
    body: "#cbd5e1",
    muted: "#64748b",
    border: "#334155",
    white: "#ffffff",
    background: "#0f172a",
    coverBg: "#0a0e17",
    coverText: "#f8fafc",
    gradeA: "#059669",
    gradeB: "#16a34a",
    gradeC: "#ca8a04",
    gradeD: "#d97706",
    gradeE: "#ea580c",
    gradeF: "#dc2626",
    sevCritical: "#dc2626",
    sevHigh: "#ea580c",
    sevMedium: "#d97706",
    sevLow: "#16a34a",
  },
  neutral: {
    accent: "#1d4ed8",
    accentLight: "#bfdbfe",
    dark: "#1e293b",
    panel: "#f1f5f9",
    panelBorder: "#e2e8f0",
    heading: "#0f172a",
    body: "#334155",
    muted: "#64748b",
    border: "#e2e8f0",
    white: "#ffffff",
    background: "#ffffff",
    coverBg: "#1e3a5f",
    coverText: "#ffffff",
    gradeA: "#059669",
    gradeB: "#16a34a",
    gradeC: "#ca8a04",
    gradeD: "#d97706",
    gradeE: "#ea580c",
    gradeF: "#dc2626",
    sevCritical: "#dc2626",
    sevHigh: "#ea580c",
    sevMedium: "#d97706",
    sevLow: "#16a34a",
  },
  dark: {
    accent: "#6366f1",
    accentLight: "#c7d2fe",
    dark: "#0f172a",
    panel: "#1e293b",
    panelBorder: "#334155",
    heading: "#e2e8f0",
    body: "#94a3b8",
    muted: "#64748b",
    border: "#334155",
    white: "#ffffff",
    background: "#0f172a",
    coverBg: "#0f172a",
    coverText: "#e2e8f0",
    gradeA: "#059669",
    gradeB: "#16a34a",
    gradeC: "#ca8a04",
    gradeD: "#d97706",
    gradeE: "#ea580c",
    gradeF: "#dc2626",
    sevCritical: "#dc2626",
    sevHigh: "#ea580c",
    sevMedium: "#d97706",
    sevLow: "#16a34a",
  },
};

// ── Helpers ──────────────────────────────────────────────────────────────────

export function getColorScheme(config: ReportConfig): ColorScheme {
  return COLOR_SCHEMES[config.colorScheme] || COLOR_SCHEMES.odingard;
}

export function mergeWithDefaults(partial: Partial<ReportConfig>): ReportConfig {
  return {
    ...DEFAULT_REPORT_CONFIG,
    ...partial,
    sections: {
      ...DEFAULT_REPORT_CONFIG.sections,
      ...(partial.sections ?? {}),
    },
  };
}

/**
 * In-memory store for per-engagement report configs.
 * In production this would be persisted to the database.
 */
const configStore = new Map<string, ReportConfig>();

export function saveReportConfig(engagementId: string, config: ReportConfig): void {
  configStore.set(engagementId, config);
}

export function loadReportConfig(engagementId: string): ReportConfig | null {
  return configStore.get(engagementId) ?? null;
}
