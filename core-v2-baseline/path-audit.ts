/**
 * Path Audit — extract primary path, supporting paths, and scoring breakdown
 */
import { runActiveExploitEngine } from "../server/services/active-exploit-engine";

const target = process.argv[2] || "https://brokencrystals.com";

const result = await runActiveExploitEngine(
  {
    baseUrl: target,
    assetId: target,
    scope: {
      exposureTypes: ["sqli", "xss", "ssrf", "command_injection", "path_traversal", "auth_bypass", "idor", "jwt_abuse", "api_abuse"],
      maxEndpoints: 200,
    },
    timeout: 10000,
    maxRequests: 500,
    crawlDepth: 4,
  },
);

const paths = result.attackPaths as Array<any>;
const primary = paths.find((p: any) => p.isPrimary);
const supporting = paths.filter((p: any) => !p.isPrimary).slice(0, 2);

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║       PRIMARY ATTACK PATH                                  ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

if (primary) {
  console.log(`\n  Name: ${primary.name}`);
  console.log(`  Score: ${primary.score}`);
  console.log(`  Confidence: ${primary.confidence}`);
  console.log(`  Steps:`);
  for (const step of primary.steps) {
    console.log(`    ${step.order}. ${step.action}`);
    console.log(`       Technique: ${step.technique} (${step.mitreId})`);
    if (step.credentialsGained?.length) console.log(`       Gained: ${step.credentialsGained.join(', ')}`);
    if (step.credentialsUsed?.length) console.log(`       Used: ${step.credentialsUsed.join(', ')}`);
  }
  console.log(`\n  Final Impact: ${primary.finalImpact}`);
  console.log(`  Business Impact: ${primary.businessImpact}`);
  console.log(`\n  Narrative: ${primary.narrative}`);

  console.log(`\n  ── Scoring Breakdown ──`);
  console.log(`  Replay used: ${primary.steps.some((s: any) => /replay|post-exploit|pivot|extract/i.test(s.action || s.technique)) ? 'YES' : 'NO'}`);
  console.log(`  Artifact used: ${primary.steps.some((s: any) => s.credentialsGained?.length || s.credentialsUsed?.length) ? 'YES' : 'NO'}`);
} else {
  console.log("  (no primary path)");
}

console.log("\n╔══════════════════════════════════════════════════════════════╗");
console.log("║       SUPPORTING PATHS                                     ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

for (const sp of supporting) {
  console.log(`\n  ${sp.name} (score: ${sp.score}, confidence: ${sp.confidence})`);
  console.log(`  Steps: ${sp.steps.length} | Impact: ${sp.finalImpact.slice(0, 100)}`);
  console.log(`  Why lower: ${sp.score < (primary?.score || 0) ? `Score ${sp.score} vs primary ${primary?.score}` : 'Similar score'}`);
}

console.log("\n╔══════════════════════════════════════════════════════════════╗");
console.log("║       FINDINGS vs PROMOTED                                 ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

const totalFindings = result.validated.length;
const findingsInPaths = new Set<string>();
for (const path of paths) {
  for (const step of (path as any).steps) {
    // Match finding by technique name in step
    for (const v of result.validated) {
      if (step.technique === v.payload.name || step.action.includes(v.payload.type)) {
        findingsInPaths.add(v.payload.id);
      }
    }
  }
}
console.log(`\n  Total PROVEN findings: ${totalFindings}`);
console.log(`  Findings contributing to paths: ${findingsInPaths.size}`);
console.log(`  Total paths: ${paths.length}`);
console.log(`  Primary path: ${primary?.name || 'none'}`);
