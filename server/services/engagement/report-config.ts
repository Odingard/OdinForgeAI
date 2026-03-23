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
  colorScheme: "corporate" | "executive" | "minimal";

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
  colorScheme: "corporate",
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
  corporate: {
    accent: "#2c3e50",
    accentLight: "#eaf0f6",
    dark: "#1a1a2e",
    panel: "#f8f9fa",
    panelBorder: "#dee2e6",
    heading: "#1a1a2e",
    body: "#2d3436",
    muted: "#6c757d",
    border: "#dee2e6",
    white: "#ffffff",
    background: "#ffffff",
    coverBg: "#1a1a2e",
    coverText: "#ffffff",
    gradeA: "#27ae60",
    gradeB: "#2ecc71",
    gradeC: "#f39c12",
    gradeD: "#e67e22",
    gradeE: "#e74c3c",
    gradeF: "#c0392b",
    sevCritical: "#c0392b",
    sevHigh: "#e67e22",
    sevMedium: "#f39c12",
    sevLow: "#27ae60",
  },
  executive: {
    accent: "#b71c1c",
    accentLight: "#fce8e8",
    dark: "#1a1a2e",
    panel: "#fafafa",
    panelBorder: "#e0e0e0",
    heading: "#212529",
    body: "#37474f",
    muted: "#78909c",
    border: "#e0e0e0",
    white: "#ffffff",
    background: "#ffffff",
    coverBg: "#1a1a2e",
    coverText: "#ffffff",
    gradeA: "#27ae60",
    gradeB: "#2ecc71",
    gradeC: "#f39c12",
    gradeD: "#e67e22",
    gradeE: "#e74c3c",
    gradeF: "#c0392b",
    sevCritical: "#c0392b",
    sevHigh: "#e67e22",
    sevMedium: "#f39c12",
    sevLow: "#27ae60",
  },
  minimal: {
    accent: "#1565c0",
    accentLight: "#e3f2fd",
    dark: "#1a1a2e",
    panel: "#f5f7fa",
    panelBorder: "#e8ecf1",
    heading: "#333333",
    body: "#4a4a4a",
    muted: "#90a4ae",
    border: "#e8ecf1",
    white: "#ffffff",
    background: "#ffffff",
    coverBg: "#ffffff",
    coverText: "#333333",
    gradeA: "#27ae60",
    gradeB: "#2ecc71",
    gradeC: "#f39c12",
    gradeD: "#e67e22",
    gradeE: "#e74c3c",
    gradeF: "#c0392b",
    sevCritical: "#c0392b",
    sevHigh: "#e67e22",
    sevMedium: "#f39c12",
    sevLow: "#27ae60",
  },
};

// ── Helpers ──────────────────────────────────────────────────────────────────

export function getColorScheme(config: ReportConfig): ColorScheme {
  return COLOR_SCHEMES[config.colorScheme] || COLOR_SCHEMES.corporate;
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
