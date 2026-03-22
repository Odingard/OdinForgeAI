/**
 * OdinForge Core V2 — Forensic Trace
 *
 * Runs the core exploit loop against a live target and captures
 * every stage: crawl, payloads, evidence, quality gate, findings.
 *
 * Usage: npx tsx core-v2-baseline/forensic-trace.ts [target-url]
 */

import { runActiveExploitEngine, type ActiveExploitResult } from "../server/services/active-exploit-engine";
import { evidenceQualityGate } from "../server/services/evidence-quality-gate";
import { reportIntegrityFilter } from "../server/services/report-integrity-filter";

const target = process.argv[2] || "https://brokencrystals.com";
const startTime = Date.now();

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║       ODINFORGE CORE V2 — FORENSIC TRACE                   ║");
console.log("╚══════════════════════════════════════════════════════════════╝");
console.log(`Target: ${target}`);
console.log(`Started: ${new Date().toISOString()}`);
console.log("");

// ── STAGE 1: Active Exploit Engine ──────────────────────────────────────────

console.log("═══ STAGE 1: ACTIVE EXPLOIT ENGINE ═══");
console.log("");

let result: ActiveExploitResult;

try {
  result = await runActiveExploitEngine(
    {
      baseUrl: target,
      assetId: target,
      scope: {
        exposureTypes: ["sqli", "xss", "ssrf", "command_injection", "path_traversal", "auth_bypass", "idor", "jwt_abuse", "api_abuse"],
        maxEndpoints: 200,
      },
      timeout: 10000,
      maxRequests: 500,
      crawlDepth: 3,
    },
    (phase, progress, detail) => {
      console.log(`  [${phase}] ${progress}% — ${detail}`);
    },
    (kind, label, detail) => {
      console.log(`  [SURFACE] ${kind}: ${label} — ${detail}`);
    }
  );
} catch (err: any) {
  console.error(`\n✗ EXPLOIT ENGINE FAILED: ${err.message}`);
  console.log(`\nDuration: ${Date.now() - startTime}ms`);
  process.exit(1);
}

console.log("");
console.log("── Crawl Results ──");
console.log(`  Endpoints discovered: ${result.crawl.endpoints.length}`);
console.log(`  Technologies: ${Array.from(result.crawl.technologies).join(", ") || "(none)"}`);
console.log(`  Sitemap found: ${result.crawl.sitemapFound}`);
console.log(`  Robots.txt found: ${result.crawl.robotsFound}`);
console.log(`  API spec found: ${result.crawl.apiSpecFound}`);

console.log("");
console.log("── Exploit Summary ──");
console.log(`  Total attempts: ${result.summary.totalAttempts}`);
console.log(`  Total validated: ${result.summary.totalValidated}`);
console.log(`  Total credentials: ${result.summary.totalCredentials}`);
console.log(`  Attack paths found: ${result.summary.attackPathsFound}`);
console.log(`  Duration: ${result.durationMs}ms`);

if (result.crawl.endpoints.length > 0) {
  console.log("");
  console.log("── Endpoints (first 20) ──");
  for (const ep of result.crawl.endpoints.slice(0, 20)) {
    console.log(`  ${ep.method} ${ep.url} [${ep.parameters.length} params] ${ep.technology?.join(",") || ""}`);
  }
}

if (result.validated.length > 0) {
  console.log("");
  console.log("── Validated Exploits ──");
  for (const v of result.validated) {
    console.log(`  ✓ ${v.payload.type} @ ${v.request.url}`);
    console.log(`    Payload: ${v.payload.name}`);
    console.log(`    Status: HTTP ${v.response.statusCode}`);
    console.log(`    Confidence: ${v.confidence}`);
    console.log(`    Evidence: ${v.evidence.description.slice(0, 120)}`);
    console.log(`    Response (first 200): ${v.response.body.slice(0, 200)}`);
    console.log("");
  }
} else {
  console.log("");
  console.log("  ✗ No validated exploits found.");
}

if (result.credentials.length > 0) {
  console.log("");
  console.log("── Harvested Credentials ──");
  for (const c of result.credentials) {
    console.log(`  ${c.type}: ${JSON.stringify(c).slice(0, 120)}`);
  }
}

// ── STAGE 2: Evidence Quality Gate ──────────────────────────────────────────

console.log("");
console.log("═══ STAGE 2: EVIDENCE QUALITY GATE ═══");
console.log("");

const findings = result.validated.map((v, i) => ({
  id: `trace-${i}`,
  severity: v.payload.severity as "critical" | "high" | "medium" | "low",
  title: `${v.payload.type}: ${v.payload.name}`,
  description: v.evidence.description,
  technique: v.payload.name,
  source: "active_exploit_engine" as const,
  evidenceQuality: "proven" as const,
  statusCode: v.response.statusCode,
  responseBody: v.response.body.slice(0, 500),
}));

if (findings.length === 0) {
  console.log("  No findings to evaluate (0 validated exploits).");
  console.log("  Quality gate: SKIPPED");
} else {
  const verdict = evidenceQualityGate.evaluateBatch(findings);
  console.log(`  Total findings: ${verdict.summary.total}`);
  console.log(`  PROVEN: ${verdict.summary.proven}`);
  console.log(`  CORROBORATED: ${verdict.summary.corroborated}`);
  console.log(`  INFERRED: ${verdict.summary.inferred}`);
  console.log(`  UNVERIFIABLE: ${verdict.summary.unverifiable}`);
  console.log(`  Pass rate: ${(verdict.summary.passRate * 100).toFixed(1)}%`);

  console.log("");
  console.log("── Per-Finding Verdicts ──");
  for (const v of [...verdict.passed, ...verdict.failed]) {
    const icon = v.passed ? "✓" : "✗";
    console.log(`  ${icon} [${v.quality}] ${v.finding.title} — ${v.reason}`);
  }

  // ── STAGE 3: Report Integrity Filter ────────────────────────────────────

  console.log("");
  console.log("═══ STAGE 3: REPORT INTEGRITY FILTER ═══");
  console.log("");

  const filtered = reportIntegrityFilter.filter(findings);
  console.log(`  Customer findings: ${filtered.customerFindings.length}`);
  console.log(`  Internal only: ${filtered.internalFindings.length}`);
  console.log(`  Audit: ${JSON.stringify(filtered.audit)}`);
}

// ── SUMMARY ─────────────────────────────────────────────────────────────────

const elapsed = Date.now() - startTime;
console.log("");
console.log("═══ FORENSIC TRACE COMPLETE ═══");
console.log(`  Target: ${target}`);
console.log(`  Duration: ${elapsed}ms`);
console.log(`  Endpoints crawled: ${result.crawl.endpoints.length}`);
console.log(`  Payloads fired: ${result.summary.totalAttempts}`);
console.log(`  Validated findings: ${result.summary.totalValidated}`);
console.log(`  Credentials harvested: ${result.summary.totalCredentials}`);
console.log(`  Verdict: ${result.summary.totalValidated > 0 ? "FINDINGS CONFIRMED" : "NO FINDINGS"}`);
console.log("");

// Write results to JSON
const traceOutput = {
  target,
  timestamp: new Date().toISOString(),
  durationMs: elapsed,
  crawl: {
    endpoints: result.crawl.endpoints.length,
    technologies: Array.from(result.crawl.technologies),
    sitemapFound: result.crawl.sitemapFound,
    robotsFound: result.crawl.robotsFound,
    apiSpecFound: result.crawl.apiSpecFound,
  },
  exploits: {
    attempts: result.summary.totalAttempts,
    validated: result.summary.totalValidated,
    credentials: result.summary.totalCredentials,
    attackPaths: result.summary.attackPathsFound,
  },
  findings: findings.map(f => ({
    id: f.id,
    severity: f.severity,
    title: f.title,
    source: f.source,
    evidenceQuality: f.evidenceQuality,
    statusCode: f.statusCode,
  })),
  verdict: result.summary.totalValidated > 0 ? "FINDINGS_CONFIRMED" : "NO_FINDINGS",
};

const fs = await import("fs");
fs.writeFileSync("core-v2-baseline/forensic-trace-result.json", JSON.stringify(traceOutput, null, 2));
console.log("Results saved to core-v2-baseline/forensic-trace-result.json");
