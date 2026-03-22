/**
 * Package Audit — capture executive summary, primary path, and remediation
 * from a sealed engagement package.
 */
import { runActiveExploitEngine } from "../server/services/active-exploit-engine";

const target = process.argv[2] || "https://brokencrystals.com";

// Run the engine
const result = await runActiveExploitEngine({
  baseUrl: target,
  assetId: target,
  scope: {
    exposureTypes: ["sqli", "xss", "ssrf", "command_injection", "path_traversal", "auth_bypass", "idor", "jwt_abuse", "api_abuse"],
    maxEndpoints: 200,
  },
  timeout: 10000,
  maxRequests: 500,
  crawlDepth: 4,
});

// Build a mock chain object from engine results to pass to package generator
const mockChain: any = {
  id: "audit-chain",
  organizationId: "default",
  assetIds: [target],
  config: { executionMode: "live", enabledPhases: ["application_compromise"] },
  status: "completed",
  phaseResults: [{
    phaseName: "application_compromise",
    status: "completed",
    findings: result.validated.map(v => ({
      id: v.payload.id,
      severity: v.payload.severity,
      title: `[VALIDATED] ${v.payload.name}`,
      description: v.evidence.description,
      technique: `${v.endpoint.url} → ${v.payload.name}`,
      source: "active_exploit_engine",
      evidenceQuality: "proven",
      statusCode: v.response.statusCode,
      responseBody: v.response.body.slice(0, 500),
      mitreId: v.payload.mitreId,
    })),
    startedAt: result.startTime,
    completedAt: result.endTime,
    durationMs: result.durationMs,
    outputContext: { credentials: [], compromisedAssets: [], attackPathSteps: [], evidenceArtifacts: [], currentPrivilegeLevel: "none", domainsCompromised: [] },
    inputContext: {},
  }],
  unifiedAttackGraph: { nodes: result.attackPaths.flatMap(p => p.steps.map(s => ({ id: s.mitreId, label: s.action, tactic: "initial-access", nodeType: "pivot", description: s.technique }))), edges: [] },
  overallRiskScore: 75,
  domainsBreached: ["application"],
  maxPrivilegeAchieved: "user",
  totalCredentialsHarvested: result.credentials.length,
  totalAssetsCompromised: 1,
  durationMs: result.durationMs,
  executiveSummary: null,
  currentContext: null,
};

// Generate the reports
const { generateCISOReport } = await import("../server/services/engagement/ciso-report");
const { extractAttackPaths, generatePathRemediation } = await import("../server/services/engagement/engagement-package") as any;

// Extract paths
let primaryPath: any = null;
let remediationPlan: any = null;

try {
  // Use the package's internal extraction
  const { sealEngagementPackage } = await import("../server/services/engagement/engagement-package");
  const pkg = sealEngagementPackage(mockChain, "audit");
  primaryPath = pkg.metadata.primaryAttackPath;
  remediationPlan = pkg.metadata.remediationPlan;

  // Generate CISO report with path
  const cisoReport = generateCISOReport(mockChain, primaryPath);

  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║  1. EXECUTIVE SUMMARY (CISO REPORT)                        ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
  console.log(`\nRisk Grade: ${cisoReport.riskGrade}`);
  console.log(`Risk Score: ${cisoReport.overallRiskScore}/100`);
  console.log(`\nNarrative:\n${cisoReport.breachChainNarrative}`);
  console.log(`\nBusiness Impact:\n${cisoReport.businessImpact.summary}`);

  console.log("\n╔══════════════════════════════════════════════════════════════╗");
  console.log("║  2. PRIMARY ATTACK PATH                                    ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
  if (primaryPath) {
    console.log(`\nName: ${primaryPath.name}`);
    console.log(`Confidence: ${primaryPath.confidence}`);
    console.log(`Score: ${primaryPath.score}`);
    console.log(`\nNarrative: ${primaryPath.narrative}`);
    console.log(`\nFinal Impact: ${primaryPath.finalImpact}`);
    console.log(`Business Impact: ${primaryPath.businessImpact}`);
    console.log(`\nSteps:`);
    for (const step of primaryPath.steps) {
      console.log(`  ${step.order}. ${step.action}`);
      console.log(`     Technique: ${step.technique} (${step.mitreId})`);
    }
    console.log(`\nArtifacts: ${primaryPath.artifacts.join(', ') || 'none'}`);
  } else {
    console.log("\n  (no primary path extracted)");
  }

  console.log("\n╔══════════════════════════════════════════════════════════════╗");
  console.log("║  3. REMEDIATION PLAN                                       ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
  if (remediationPlan) {
    console.log(`\nImmediate:`);
    for (const r of remediationPlan.immediate) console.log(`  • ${r}`);
    console.log(`\nPivot Disruption:`);
    for (const r of remediationPlan.pivotDisruption) console.log(`  • ${r}`);
    console.log(`\nArtifact Protection:`);
    for (const r of remediationPlan.artifactProtection) console.log(`  • ${r}`);
    console.log(`\nPrivilege Boundary:`);
    for (const r of remediationPlan.privilegeBoundary) console.log(`  • ${r}`);
    console.log(`\nMonitoring:`);
    for (const r of remediationPlan.monitoring) console.log(`  • ${r}`);
  } else {
    console.log("\n  (no remediation plan generated)");
  }
} catch (err: any) {
  console.error("Package audit failed:", err.message);
  console.error(err.stack);
}
