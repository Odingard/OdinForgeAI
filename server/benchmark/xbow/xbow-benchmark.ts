#!/usr/bin/env npx tsx
/**
 * OdinForge AI — XBOW CTF Benchmark
 *
 * Runs OdinForge's exploit agent against the XBOW 104-challenge benchmark
 * in black-box mode (no source code access).
 *
 * Usage:
 *   npx tsx server/benchmark/xbow/xbow-benchmark.ts <xbow-repo-path> [mode] [options]
 *
 * Options:
 *   --output <path>       Write JSON report to file
 *   --category <cat>      Filter to one category (sqli, xss, idor, etc.)
 *   --challenge <id>      Run single challenge (e.g. XBEN-001-24)
 *   --limit <n>           Run first N challenges only
 *   --offset <n>          Skip first N challenges (for chunked CI runs)
 *   --timeout <ms>        Per-challenge timeout (default: 180000)
 *
 * Examples:
 *   npx tsx server/benchmark/xbow/xbow-benchmark.ts ./xbow-repo simulation --limit 5
 *   npx tsx server/benchmark/xbow/xbow-benchmark.ts ./xbow-repo simulation --category sqli
 *   npx tsx server/benchmark/xbow/xbow-benchmark.ts ./xbow-repo simulation --challenge XBEN-001-24
 */

import { writeFileSync, mkdirSync } from "fs";
import { dirname } from "path";
import { loadChallenges, filterChallenges } from "./challenge-loader";
import { runChallengeWithRetry, checkDockerPreflight } from "./challenge-runner";
import type { XBOWChallengeResult, XBOWReport, XBOWCategoryStats } from "./xbow-types";

// ─── CLI Parsing ──────────────────────────────────────────────────────

const args = process.argv.slice(2);

function getArg(name: string): string | undefined {
  const idx = args.indexOf(`--${name}`);
  return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : undefined;
}

const XBOW_REPO = args.find((a) => !a.startsWith("--") && a !== getArg("output") && a !== getArg("category") && a !== getArg("challenge") && a !== getArg("limit") && a !== getArg("timeout"));
const EXECUTION_MODE = args.find((a) => ["safe", "simulation", "live"].includes(a)) || "simulation";
const OUTPUT_PATH = getArg("output");
const CATEGORY_FILTER = getArg("category");
const CHALLENGE_FILTER = getArg("challenge");
const LIMIT = getArg("limit") ? parseInt(getArg("limit")!, 10) : undefined;
const OFFSET = getArg("offset") ? parseInt(getArg("offset")!, 10) : 0;
const TIMEOUT = getArg("timeout") ? parseInt(getArg("timeout")!, 10) : 180_000;
const CHAIN_LOOP_MAX_ITERS = process.env.CHAIN_LOOP_MAX_ITERS
  ? parseInt(process.env.CHAIN_LOOP_MAX_ITERS, 10)
  : 3;

if (!XBOW_REPO) {
  console.error("Usage: npx tsx server/benchmark/xbow/xbow-benchmark.ts <xbow-repo-path> [mode] [options]");
  console.error("");
  console.error("Options:");
  console.error("  --output <path>     Write JSON report to file");
  console.error("  --category <cat>    Filter to one category");
  console.error("  --challenge <id>    Run single challenge");
  console.error("  --limit <n>         Run first N challenges only");
  console.error("  --offset <n>        Skip first N challenges (for chunked CI)");
  console.error("  --timeout <ms>      Per-challenge timeout (default: 180000)");
  process.exit(1);
}

// ─── Main ─────────────────────────────────────────────────────────────

async function main() {
  console.log("═══════════════════════════════════════════════════════════");
  console.log("  OdinForge AI — XBOW CTF Benchmark");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`  Repo:      ${XBOW_REPO}`);
  console.log(`  Mode:      ${EXECUTION_MODE} (black-box)`);
  console.log(`  ChainIter: ${CHAIN_LOOP_MAX_ITERS}`);

  // Docker pre-flight
  checkDockerPreflight();
  console.log("  Docker:    OK");

  // Load challenges
  const allChallenges = loadChallenges(XBOW_REPO!);
  console.log(`  Loaded:    ${allChallenges.length} challenges`);

  const challenges = filterChallenges(allChallenges, {
    category: CATEGORY_FILTER,
    challengeId: CHALLENGE_FILTER,
    limit: LIMIT,
    offset: OFFSET,
  });
  console.log(`  Running:   ${challenges.length} challenges`);
  console.log(`  Time:      ${new Date().toISOString()}`);
  console.log("───────────────────────────────────────────────────────────\n");

  if (challenges.length === 0) {
    console.error("No challenges matched the filter criteria.");
    process.exit(1);
  }

  // Run challenges
  const results: XBOWChallengeResult[] = [];
  let solved = 0;
  let vulnDetected = 0;

  for (let i = 0; i < challenges.length; i++) {
    const challenge = challenges[i];
    console.log(`▶ [${i + 1}/${challenges.length}] ${challenge.name}`);
    console.log(`  Category: ${challenge.category} | Difficulty: ${challenge.difficulty}`);

    const result = await runChallengeWithRetry(challenge, {
      executionMode: EXECUTION_MODE,
      timeoutMs: TIMEOUT,
    });

    results.push(result);

    if (result.success) {
      solved++;
      console.log(`  Result: ✅ SOLVED (flag in ${result.flagFoundIn}) — ${(result.processingTimeMs / 1000).toFixed(1)}s`);
    } else if (result.vulnDetected) {
      vulnDetected++;
      console.log(`  Result: 🔶 VULN FOUND (no flag) — ${(result.processingTimeMs / 1000).toFixed(1)}s`);
    } else if (result.error) {
      console.log(`  Result: ❌ ERROR: ${result.error}`);
    } else {
      console.log(`  Result: ❌ MISSED — ${(result.processingTimeMs / 1000).toFixed(1)}s`);
    }
    console.log("");
  }

  // Build report
  const report = buildReport(results);

  // Print summary
  console.log("═══════════════════════════════════════════════════════════");
  console.log("  RESULTS SUMMARY");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`  Solved:          ${report.overall.solved}/${report.overall.total} (${report.overall.percentage})`);
  console.log(`  Vulns Detected:  ${vulnDetected} additional (found vuln but no flag)`);
  console.log("");
  console.log("  By Category:");
  for (const [cat, stats] of Object.entries(report.byCategory)) {
    console.log(`    ${cat.padEnd(25)} ${stats.solved}/${stats.total} (${stats.rate})`);
  }
  console.log("");
  console.log("  By Difficulty:");
  for (const [diff, stats] of Object.entries(report.byDifficulty)) {
    console.log(`    Level ${diff.padEnd(20)} ${stats.solved}/${stats.total} (${stats.rate})`);
  }
  console.log("");
  console.log("  Comparison:");
  console.log(`    OdinForge (black-box):  ${report.overall.percentage}`);
  console.log(`    Shannon (white-box):    ${report.overall.shannonRate}`);
  console.log(`    XBOW official (bb):     ${report.overall.xbowRate}`);
  if (report.telemetry) {
    console.log("");
    console.log("  Telemetry:");
    console.log(`    Avg agent run:   ${(report.telemetry.avgAgentRunMs / 1000).toFixed(1)}s`);
    console.log(`    Median run:      ${(report.telemetry.medianAgentRunMs / 1000).toFixed(1)}s`);
    console.log(`    Avg tool calls:  ${report.telemetry.avgToolCalls}`);
    console.log(`    Docker build:    ${(report.telemetry.totalDockerBuildMs / 1000).toFixed(1)}s total`);
    console.log(`    Docker start:    ${(report.telemetry.totalDockerStartMs / 1000).toFixed(1)}s total`);
    console.log(`    Retries:         ${report.telemetry.totalRetries}`);
    if (Object.keys(report.telemetry.failureCodeCounts).length > 0) {
      console.log("    Failure codes:");
      for (const [code, count] of Object.entries(report.telemetry.failureCodeCounts)) {
        console.log(`      ${code}: ${count}`);
      }
    }
  }
  console.log("═══════════════════════════════════════════════════════════");

  if (report.failures.length > 0) {
    console.log("\n  Failures:");
    for (const f of report.failures) {
      console.log(`    ${f.challengeId}: ${f.reason}`);
    }
  }

  // Write report
  if (OUTPUT_PATH) {
    const dir = dirname(OUTPUT_PATH);
    if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
    writeFileSync(OUTPUT_PATH, JSON.stringify(report, null, 2));
    console.log(`\nReport written to ${OUTPUT_PATH}`);
  }

  // Always exit 0 — XBOW is informational, not gated.
  // Solve rate is tracked in the report, not via exit code.
  process.exit(0);
}

// ─── Report Builder ───────────────────────────────────────────────────

function buildReport(results: XBOWChallengeResult[]): XBOWReport {
  const solved = results.filter((r) => r.success).length;
  const total = results.length;
  const percentage = total > 0 ? ((solved / total) * 100).toFixed(2) + "%" : "0%";

  // By category
  const byCategory: Record<string, XBOWCategoryStats> = {};
  for (const r of results) {
    if (!byCategory[r.category]) {
      byCategory[r.category] = { solved: 0, total: 0, rate: "" };
    }
    byCategory[r.category].total++;
    if (r.success) byCategory[r.category].solved++;
  }
  for (const stats of Object.values(byCategory)) {
    stats.rate = stats.total > 0 ? ((stats.solved / stats.total) * 100).toFixed(1) + "%" : "0%";
  }

  // By difficulty
  const byDifficulty: Record<string, XBOWCategoryStats> = {};
  for (const r of results) {
    const d = String(r.difficulty);
    if (!byDifficulty[d]) {
      byDifficulty[d] = { solved: 0, total: 0, rate: "" };
    }
    byDifficulty[d].total++;
    if (r.success) byDifficulty[d].solved++;
  }
  for (const stats of Object.values(byDifficulty)) {
    stats.rate = stats.total > 0 ? ((stats.solved / stats.total) * 100).toFixed(1) + "%" : "0%";
  }

  // Failures
  const failures = results
    .filter((r) => !r.success)
    .map((r) => ({
      challengeId: r.challengeId,
      reason: r.error || (r.vulnDetected ? "Vuln found but flag not extracted" : "No vulnerability detected"),
      agentSummary: r.vulnDetected
        ? `Detected vuln (${r.toolCalls} tool calls, ${(r.processingTimeMs / 1000).toFixed(1)}s)`
        : `No detection (${r.toolCalls} tool calls, ${(r.processingTimeMs / 1000).toFixed(1)}s)`,
    }));

  // Aggregate telemetry
  const agentRunTimes = results.map(r => r.agentRunMs).filter((t): t is number => t != null && t > 0);
  const toolCallCounts = results.map(r => r.toolCalls);
  const sortedTimes = [...agentRunTimes].sort((a, b) => a - b);

  const stopReasonCounts: Record<string, number> = {};
  const failureCodeCounts: Record<string, number> = {};
  let totalRetries = 0;

  for (const r of results) {
    if (r.stopReason) stopReasonCounts[r.stopReason] = (stopReasonCounts[r.stopReason] || 0) + 1;
    if (r.failureCode) failureCodeCounts[r.failureCode] = (failureCodeCounts[r.failureCode] || 0) + 1;
    totalRetries += r.retryCount || 0;
  }

  const telemetry = {
    avgAgentRunMs: agentRunTimes.length > 0 ? Math.round(agentRunTimes.reduce((a, b) => a + b, 0) / agentRunTimes.length) : 0,
    avgToolCalls: total > 0 ? Math.round(toolCallCounts.reduce((a, b) => a + b, 0) / total) : 0,
    medianAgentRunMs: sortedTimes.length > 0 ? sortedTimes[Math.floor(sortedTimes.length / 2)] : 0,
    stopReasonCounts,
    failureCodeCounts,
    totalDockerBuildMs: results.reduce((sum, r) => sum + (r.dockerBuildMs || 0), 0),
    totalDockerStartMs: results.reduce((sum, r) => sum + (r.dockerStartMs || 0), 0),
    totalRetries,
  };

  return {
    meta: {
      timestamp: new Date().toISOString(),
      totalChallenges: total,
      executionMode: EXECUTION_MODE,
      modelRouter: process.env.EXPLOIT_AGENT_ALLOY === "true" ? "alloy" : "single",
      odinforgeMode: "black-box",
      chainLoopMaxIters: CHAIN_LOOP_MAX_ITERS,
      aevExecutionMode: process.env.AEV_EXECUTION_MODE || undefined,
    },
    overall: {
      solved,
      total,
      percentage,
      shannonRate: "96.15%",
      shannonMode: "white-box",
      xbowRate: "85%",
      xbowMode: "black-box",
    },
    byCategory,
    byDifficulty,
    results,
    failures,
    telemetry,
  };
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
