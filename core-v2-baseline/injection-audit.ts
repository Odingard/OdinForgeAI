/**
 * Injection Precision Audit
 *
 * Captures actual request shapes OdinForge sends vs what each endpoint type expects.
 * Picks 4 representative endpoints and logs every attempt against them.
 */

import { ActiveExploitEngine, type ActiveExploitResult, type ExploitAttempt } from "../server/services/active-exploit-engine";

const target = process.argv[2] || "https://brokencrystals.com";

console.log("╔══════════════════════════════════════════════════════════╗");
console.log("║     INJECTION PRECISION AUDIT                          ║");
console.log("╚══════════════════════════════════════════════════════════╝");
console.log(`Target: ${target}\n`);

const engine = new ActiveExploitEngine(
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
  (phase, progress, detail) => {
    // quiet — only log crawl summary
    if (phase.includes("complete") || phase.includes("crawl") && progress > 20) {
      console.log(`  [${phase}] ${progress}% — ${detail}`);
    }
  }
);

const result: ActiveExploitResult = await engine.run();

console.log(`\nCrawl: ${result.crawl.endpoints.length} endpoints`);
console.log(`Attempts: ${result.attempts.length}`);
console.log(`Validated: ${result.validated.length}\n`);

// Pick 4 representative endpoint types
const graphqlEp = result.crawl.endpoints.find(e => e.url.includes("graphql") && !e.url.includes("console") && !e.url.includes("playground"));
const jsonApiEp = result.crawl.endpoints.find(e => e.url.includes("/api/") && e.parameters.some(p => p.location === "body"));
const formEp = result.crawl.endpoints.find(e => e.method === "POST" && e.contentType?.includes("form"));
const authEp = result.crawl.endpoints.find(e => e.url.includes("auth") || e.url.includes("login") || e.url.includes("oauth"));
const configEp = result.crawl.endpoints.find(e => e.url.includes(".env") || e.url.includes("config") || e.url.includes("actuator"));

const auditTargets = [
  { label: "GRAPHQL", ep: graphqlEp },
  { label: "JSON API", ep: jsonApiEp },
  { label: "FORM", ep: formEp },
  { label: "AUTH", ep: authEp },
  { label: "CONFIG", ep: configEp },
];

for (const { label, ep } of auditTargets) {
  console.log(`\n${"═".repeat(60)}`);
  console.log(`ENDPOINT TYPE: ${label}`);
  console.log(`${"═".repeat(60)}`);

  if (!ep) {
    console.log("  NOT FOUND in crawl results");
    continue;
  }

  console.log(`  URL: ${ep.url}`);
  console.log(`  Method: ${ep.method}`);
  console.log(`  Content-Type: ${ep.contentType || "(none)"}`);
  console.log(`  Parameters: ${ep.parameters.length}`);
  for (const p of ep.parameters.slice(0, 10)) {
    console.log(`    - ${p.name} [${p.location}] type=${p.type} sample=${p.sampleValue?.slice(0, 60) || "(none)"}`);
  }
  console.log(`  Authenticated: ${ep.authenticated}`);

  // Find all attempts against this endpoint
  const attempts = result.attempts.filter(a => a.endpoint.url === ep.url);
  console.log(`\n  ATTEMPTS: ${attempts.length}`);

  if (attempts.length === 0) {
    console.log("  (no payloads fired at this endpoint)");
    continue;
  }

  // Group by vuln class
  const byClass = new Map<string, ExploitAttempt[]>();
  for (const a of attempts) {
    const cls = a.payload.type;
    if (!byClass.has(cls)) byClass.set(cls, []);
    byClass.get(cls)!.push(a);
  }

  for (const [cls, clsAttempts] of byClass) {
    const validated = clsAttempts.filter(a => a.validated);
    console.log(`\n  [${cls}] ${clsAttempts.length} attempts, ${validated.length} validated`);

    // Show first attempt's request shape
    const sample = clsAttempts[0];
    console.log(`    Request: ${sample.request.method} ${sample.request.url.slice(0, 100)}`);
    console.log(`    Content-Type: ${sample.request.headers?.['Content-Type'] || sample.request.headers?.['content-type'] || "(none)"}`);
    console.log(`    Body: ${sample.request.body?.slice(0, 150) || "(none)"}`);
    console.log(`    Payload param: ${sample.payload.parameter} [${sample.payload.location}]`);
    console.log(`    Payload value: ${sample.payload.payload.slice(0, 80)}`);
    console.log(`    Response: HTTP ${sample.response.statusCode} (${sample.response.size} bytes, ${sample.durationMs}ms)`);
    console.log(`    Confidence: ${(sample.confidence * 100).toFixed(0)}%`);
    console.log(`    Evidence: ${sample.evidence.description.slice(0, 120)}`);

    if (validated.length > 0) {
      console.log(`    ✓ VALIDATED: ${validated[0].evidence.description.slice(0, 120)}`);
    }
  }
}

// Summary of all failed attempts — what went wrong?
console.log(`\n${"═".repeat(60)}`);
console.log("FAILURE ANALYSIS — Why did ${result.attempts.length - result.validated.length} attempts fail?");
console.log(`${"═".repeat(60)}`);

const failed = result.attempts.filter(a => !a.validated);

// Group failures by reason
const failReasons = new Map<string, number>();
for (const a of failed) {
  const reason = a.confidence === 0
    ? "zero_confidence_no_pattern_match"
    : a.confidence < 0.6
      ? `low_confidence_${(a.confidence * 100).toFixed(0)}pct`
      : "threshold_met_but_no_hard_evidence";
  failReasons.set(reason, (failReasons.get(reason) || 0) + 1);
}

for (const [reason, count] of Array.from(failReasons.entries()).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${count}x ${reason}`);
}

// Injection location distribution
const locationDist = new Map<string, number>();
for (const a of result.attempts) {
  locationDist.set(a.payload.location, (locationDist.get(a.payload.location) || 0) + 1);
}
console.log(`\n  Injection locations:`);
for (const [loc, count] of Array.from(locationDist.entries()).sort((a, b) => b[1] - a[1])) {
  console.log(`    ${loc}: ${count}`);
}

// Content-type distribution
const ctDist = new Map<string, number>();
for (const a of result.attempts) {
  const ct = a.request.headers?.['Content-Type'] || a.request.headers?.['content-type'] || "(none)";
  ctDist.set(ct, (ctDist.get(ct) || 0) + 1);
}
console.log(`\n  Content-Types sent:`);
for (const [ct, count] of Array.from(ctDist.entries()).sort((a, b) => b[1] - a[1])) {
  console.log(`    ${ct}: ${count}`);
}
