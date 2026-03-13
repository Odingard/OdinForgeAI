#!/usr/bin/env npx tsx
/**
 * False Positive Benchmark
 *
 * Runs the validation engine against a known-clean target to verify
 * OdinForge does not generate false positives. A clean target should
 * produce zero confirmed/likely findings.
 *
 * Usage:
 *   npx tsx server/benchmark/false-positive-benchmark.ts <clean-target-url> [mode]
 *
 * Example:
 *   npx tsx server/benchmark/false-positive-benchmark.ts http://localhost:8080 live
 *
 * The target should be a simple web server with NO vulnerabilities
 * (e.g., a static file server, nginx default page, or httpbin).
 */

import { ValidationEngine, type VulnerabilityType, type UnifiedValidationResult } from "../services/validation/validation-engine";
import { writeFileSync } from "fs";

const VULN_TYPES: VulnerabilityType[] = [
  "sqli",
  "xss",
  "auth_bypass",
  "command_injection",
  "path_traversal",
  "ssrf",
  "bfla",
];

interface FpBenchmarkResult {
  target: string;
  mode: string;
  timestamp: string;
  totalTests: number;
  falsePositives: number;
  falsePositiveRate: number;
  results: {
    endpoint: string;
    parameter: string;
    vulnType: VulnerabilityType;
    vulnerable: boolean;
    confidence: number;
    verdict: string;
    evidence: string[];
  }[];
}

// Common endpoints to probe on the clean target
const PROBE_ENDPOINTS = [
  { path: "/", param: "q", method: "GET" as const, location: "url_param" as const },
  { path: "/search", param: "query", method: "GET" as const, location: "url_param" as const },
  { path: "/api/data", param: "id", method: "GET" as const, location: "url_param" as const },
  { path: "/login", param: "username", method: "POST" as const, location: "body_param" as const },
  { path: "/api/users", param: "email", method: "POST" as const, location: "body_param" as const },
];

async function runFalsePositiveBenchmark(targetUrl: string, mode: string): Promise<FpBenchmarkResult> {
  const timestamp = new Date().toISOString();
  const results: FpBenchmarkResult["results"] = [];
  let totalTests = 0;
  let falsePositives = 0;

  console.log("═══════════════════════════════════════════════════════════");
  console.log("  OdinForge AI — False Positive Benchmark");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`  Target:    ${targetUrl}`);
  console.log(`  Mode:      ${mode}`);
  console.log(`  Tests:     ${PROBE_ENDPOINTS.length} endpoints × ${VULN_TYPES.length} vuln types`);
  console.log(`  Time:      ${timestamp}`);
  console.log("───────────────────────────────────────────────────────────");

  // Verify target is reachable
  try {
    const res = await fetch(targetUrl, { signal: AbortSignal.timeout(5000) });
    console.log(`\n  Target reachable: ${res.status} ${res.statusText}\n`);
  } catch (err: any) {
    console.error(`\n  ❌ Target unreachable: ${err.message}`);
    process.exit(1);
  }

  const engine = new ValidationEngine({
    executionMode: mode as any,
    maxPayloadsPerTest: 12,
    timeoutMs: 10000,
    tenantId: "fp-benchmark",
  });

  for (const endpoint of PROBE_ENDPOINTS) {
    const url = `${targetUrl}${endpoint.path}`;

    // Check if endpoint exists (skip 404s)
    try {
      const check = await fetch(url, { signal: AbortSignal.timeout(3000) });
      if (check.status === 404) {
        console.log(`  ⏭ Skipping ${endpoint.path} (404)`);
        continue;
      }
    } catch {
      console.log(`  ⏭ Skipping ${endpoint.path} (unreachable)`);
      continue;
    }

    for (const vulnType of VULN_TYPES) {
      totalTests++;

      try {
        const result: UnifiedValidationResult = await engine.validateTarget({
          url,
          method: endpoint.method,
          parameterName: endpoint.param,
          parameterLocation: endpoint.location,
          vulnerabilityTypes: [vulnType],
        });

        const isFalsePositive = result.vulnerable && result.overallConfidence >= 40;
        if (isFalsePositive) {
          falsePositives++;
          console.log(`  ❌ FALSE POSITIVE: ${vulnType} on ${endpoint.path}?${endpoint.param} (${result.overallConfidence}% confidence)`);
        }

        results.push({
          endpoint: url,
          parameter: endpoint.param,
          vulnType,
          vulnerable: result.vulnerable,
          confidence: result.overallConfidence,
          verdict: result.overallVerdict,
          evidence: result.evidence,
        });
      } catch (err: any) {
        console.error(`  ⚠ Error testing ${vulnType} on ${endpoint.path}: ${err.message}`);
      }
    }

    console.log(`  ✓ Tested ${endpoint.path} against ${VULN_TYPES.length} vuln types`);
  }

  const fpRate = totalTests > 0 ? (falsePositives / totalTests) * 100 : 0;

  console.log("\n═══════════════════════════════════════════════════════════");
  console.log("  FALSE POSITIVE RESULTS");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`  Total Tests:       ${totalTests}`);
  console.log(`  False Positives:   ${falsePositives}`);
  console.log(`  FP Rate:           ${fpRate.toFixed(1)}%`);

  if (falsePositives === 0) {
    console.log(`\n  ✅ PASS: Zero false positives on clean target`);
  } else {
    console.log(`\n  ❌ FAIL: ${falsePositives} false positive(s) detected`);
    console.log("  False positive details:");
    for (const r of results.filter((r) => r.vulnerable && r.confidence >= 40)) {
      console.log(`    - ${r.vulnType} on ${r.endpoint} (${r.confidence}%): ${r.evidence[0] || "no evidence"}`);
    }
  }

  console.log("═══════════════════════════════════════════════════════════\n");

  return {
    target: targetUrl,
    mode,
    timestamp,
    totalTests,
    falsePositives,
    falsePositiveRate: fpRate,
    results,
  };
}

// ─── CLI ─────────────────────────────────────────────────────────────

const [targetUrl, mode = "live"] = process.argv.slice(2);

if (!targetUrl) {
  console.error("Usage: npx tsx server/benchmark/false-positive-benchmark.ts <clean-target-url> [mode]");
  console.error("Example: npx tsx server/benchmark/false-positive-benchmark.ts http://localhost:8080 live");
  process.exit(1);
}

runFalsePositiveBenchmark(targetUrl, mode)
  .then((result) => {
    const outputPath = process.argv.find((a) => a.startsWith("--output="))?.split("=")[1]
      || "/tmp/false-positive-benchmark-results.json";
    writeFileSync(outputPath, JSON.stringify(result, null, 2));
    console.log(`Report written to ${outputPath}`);

    if (result.falsePositives > 0) {
      process.exit(1);
    }
  })
  .catch((err) => {
    console.error("Benchmark failed:", err);
    process.exit(1);
  });
