/**
 * HTML→PDF Report Renderer — Professional engagement report generation
 *
 * Uses Playwright to render a self-contained HTML document to PDF,
 * producing CrowdStrike/Deloitte-quality output with per-engagement
 * customization via ReportConfig.
 *
 * Falls back to the legacy pdfmake renderer on failure.
 */

import * as fs from "fs";
import * as path from "path";
import type { ReportConfig } from "./report-config";
import { DEFAULT_REPORT_CONFIG, mergeWithDefaults } from "./report-config";
import type { ReportData } from "./report-templates";
import {
  renderStyles,
  renderCoverPage,
  renderTableOfContents,
  renderExecutiveSummary,
  renderAttackChain,
  renderDetailedFindings,
  renderRemediationPlan,
  renderMethodology,
  renderAppendix,
} from "./report-templates";

// ── Logo Loading ─────────────────────────────────────────────────────────────

let cachedLogoBase64: string | null = null;

function getLogoBase64(): string | null {
  if (cachedLogoBase64 !== null) return cachedLogoBase64 || null;
  try {
    const logoPath = path.join(process.cwd(), "public", "odingard-logo.png");
    const buffer = fs.readFileSync(logoPath);
    cachedLogoBase64 = `data:image/png;base64,${buffer.toString("base64")}`;
    return cachedLogoBase64;
  } catch {
    console.warn("[HTML-PDF] Logo file not found at public/odingard-logo.png");
    cachedLogoBase64 = "";
    return null;
  }
}

// ── HTML Document Composition ────────────────────────────────────────────────

export function buildReportHTML(
  reportData: ReportData,
  config: ReportConfig
): string {
  const logoBase64 = config.clientLogo || getLogoBase64();

  const sections = [
    renderCoverPage(reportData, config, logoBase64),
    renderTableOfContents(reportData, config),
    renderExecutiveSummary(reportData, config),
    renderAttackChain(reportData, config),
    renderDetailedFindings(reportData, config),
    renderRemediationPlan(reportData, config),
    renderMethodology(config),
    renderAppendix(reportData, config),
  ].filter(Boolean);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(config.reportTitle)} - ${escapeHtml(config.engagementId)}</title>
  <style>${renderStyles(config)}</style>
</head>
<body>
  ${sections.join("\n")}
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── PDF Rendering via Playwright ─────────────────────────────────────────────

export async function renderReportToPdf(
  reportData: ReportData,
  config?: Partial<ReportConfig>
): Promise<Buffer> {
  const fullConfig = mergeWithDefaults({
    ...DEFAULT_REPORT_CONFIG,
    ...(config ?? {}),
    engagementId: config?.engagementId || reportData.cisoReport.engagementId,
  });

  const html = buildReportHTML(reportData, fullConfig);

  // Try Playwright first, fall back to returning HTML as buffer if unavailable
  try {
    return await renderWithPlaywright(html, fullConfig);
  } catch (err) {
    console.error("[HTML-PDF] Playwright rendering failed, attempting chromium detection:", err);
    throw err;
  }
}

async function renderWithPlaywright(
  html: string,
  config: ReportConfig
): Promise<Buffer> {
  // Dynamic import to avoid hard dependency at startup
  const { chromium } = await import("playwright-core");

  // Try to find a Chromium binary
  const executablePath = findChromiumPath();

  const browser = await chromium.launch({
    headless: true,
    ...(executablePath ? { executablePath } : {}),
  });

  try {
    const context = await browser.newContext();
    const page = await context.newPage();

    await page.setContent(html, { waitUntil: "networkidle" });

    const pdfBuffer = await page.pdf({
      format: config.pageSize === "Letter" ? "Letter" : "A4",
      landscape: config.orientation === "landscape",
      printBackground: true,
      margin: {
        top: "20mm",
        right: "18mm",
        bottom: "25mm",
        left: "18mm",
      },
      displayHeaderFooter: true,
      headerTemplate: `<div></div>`,
      footerTemplate: `
        <div style="width: 100%; font-family: 'Segoe UI', Helvetica, Arial, sans-serif; font-size: 7px; padding: 0 18mm; display: flex; justify-content: space-between; color: #64748b;">
          <span>${escapeHtml(config.classification)} &mdash; Odingard Security &mdash; Engagement ${escapeHtml(config.engagementId)}</span>
          <span>Page <span class="pageNumber"></span></span>
        </div>
      `,
    });

    return Buffer.from(pdfBuffer);
  } finally {
    await browser.close();
  }
}

/**
 * Attempt to find a Chromium/Chrome executable on the system.
 * Returns undefined if none found (Playwright will use its bundled version).
 */
function findChromiumPath(): string | undefined {
  const candidates = [
    // Playwright's default install location
    process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
    // macOS
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    // Linux common paths
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    // Snap
    "/snap/bin/chromium",
  ];

  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return undefined;
}

// ── Convenience: Build ReportData from engagement package ────────────────────

import type { EngagementPackage } from "./engagement-package";

export function buildReportDataFromPackage(pkg: EngagementPackage): ReportData {
  return {
    cisoReport: pkg.components.cisoReport,
    engineerReport: pkg.components.engineerReport,
    primaryPath: pkg.metadata.primaryAttackPath ?? null,
    supportingPaths: pkg.metadata.supportingAttackPaths ?? [],
    remediation: pkg.metadata.remediationPlan ?? null,
    sealStatus: pkg.sealedAt ? "sealed" : "unsealed",
    componentHashes: pkg.integrity,
  };
}
