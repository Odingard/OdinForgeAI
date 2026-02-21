#!/usr/bin/env npx tsx
/**
 * OdinForge AI — AEV Breach Chain Benchmark
 *
 * Tests multi-phase attack chain capabilities using the chain orchestrator
 * and existing playbooks against vulnerable targets.
 *
 * Usage:
 *   npx tsx server/benchmark/breach-chain/breach-chain-benchmark.ts <target-url> [mode] [options]
 *
 * Options:
 *   --target <name>         juice-shop | dvwa | webgoat
 *   --output <path>         Write JSON report to file
 *   --scenario <id>         Run single scenario
 *   --threshold-score <n>   Min composite score for CI pass (default: 30)
 *
 * Examples:
 *   npx tsx server/benchmark/breach-chain/breach-chain-benchmark.ts http://localhost:3001 simulation --target juice-shop
 *   npx tsx server/benchmark/breach-chain/breach-chain-benchmark.ts http://localhost:3002 simulation --target dvwa --scenario dvwa-sqli-chain
 */

import { writeFileSync } from "fs";
import { ChainOrchestrator } from "../../services/aev/chain-orchestrator";
import { getPlaybook } from "../../services/aev/playbooks/index";
import { executionModeEnforcer } from "../../services/validation/execution-modes";
import { sandboxExecutor } from "../../services/validation/sandbox-executor";
import { getScenariosForTarget, getScenarioById, getAllScenarios } from "./scenarios";
import { scoreChainResult, buildCompetitorComparison } from "./breach-chain-scorer";
import type { BreachChainScenario, BreachChainBenchmarkResult, BreachChainReport } from "./breach-chain-types";

// ─── CLI Parsing ──────────────────────────────────────────────────────

const args = process.argv.slice(2);

function getArg(name: string): string | undefined {
  const idx = args.indexOf(`--${name}`);
  return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : undefined;
}

const TARGET_URL = args.find((a) => a.startsWith("http"));
const EXECUTION_MODE = args.find((a) => ["safe", "simulation", "live"].includes(a)) || "simulation";
const TARGET_NAME = getArg("target") || "juice-shop";
const OUTPUT_PATH = getArg("output");
const SCENARIO_FILTER = getArg("scenario");
const THRESHOLD_SCORE = getArg("threshold-score") ? parseInt(getArg("threshold-score")!, 10) : 30;

if (!TARGET_URL) {
  console.error("Usage: npx tsx server/benchmark/breach-chain/breach-chain-benchmark.ts <target-url> [mode] [options]");
  console.error("");
  console.error("Options:");
  console.error("  --target <name>         juice-shop | dvwa | webgoat");
  console.error("  --output <path>         Write JSON report to file");
  console.error("  --scenario <id>         Run single scenario");
  console.error("  --threshold-score <n>   Min avg composite score for CI (default: 30)");
  process.exit(1);
}

// ─── Main ─────────────────────────────────────────────────────────────

async function main() {
  console.log("═══════════════════════════════════════════════════════════");
  console.log("  OdinForge AI — AEV Breach Chain Benchmark");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`  Target:    ${TARGET_NAME} @ ${TARGET_URL}`);
  console.log(`  Mode:      ${EXECUTION_MODE}`);

  // Load scenarios
  let scenarios: BreachChainScenario[];
  if (SCENARIO_FILTER) {
    const s = getScenarioById(SCENARIO_FILTER);
    scenarios = s ? [s] : [];
  } else {
    scenarios = getScenariosForTarget(TARGET_NAME);
  }

  console.log(`  Scenarios: ${scenarios.length}`);
  console.log(`  Threshold: ${THRESHOLD_SCORE} composite score`);
  console.log(`  Time:      ${new Date().toISOString()}`);
  console.log("───────────────────────────────────────────────────────────\n");

  if (scenarios.length === 0) {
    console.error(`No scenarios found for target "${TARGET_NAME}".`);
    console.error("Available targets: juice-shop, dvwa, webgoat");
    process.exit(1);
  }

  // Verify target is reachable
  try {
    const resp = await fetch(TARGET_URL!);
    console.log(`  Target reachable: ${resp.status} ${resp.statusText}\n`);
  } catch (err: any) {
    console.error(`  ERROR: Cannot reach ${TARGET_URL}: ${err.message}`);
    process.exit(1);
  }

  // Set execution mode to match CLI arg (playbooks require simulation or live)
  executionModeEnforcer.setMode(EXECUTION_MODE as "safe" | "simulation" | "live");

  // Configure sandbox for benchmark: allow localhost targets and all operation types
  sandboxExecutor.setTenantConfig("benchmark", {
    blockedTargetPatterns: [],  // Allow localhost for benchmarking
    allowedOperations: [
      "protocol_probe", "vulnerability_scan", "credential_test",
      "network_scan", "port_scan", "payload_injection",
      "exploit_execution", "data_exfiltration",
    ],
    requireApprovalForLiveMode: false,
  });

  // Initialize chain orchestrator
  const orchestrator = new ChainOrchestrator({
    defaultTimeout: 60_000,
    confidenceThreshold: 30,
    collectAllEvidence: true,
    redactSensitiveData: false,
  });

  // Run scenarios
  const results: BreachChainBenchmarkResult[] = [];

  for (let i = 0; i < scenarios.length; i++) {
    const scenario = scenarios[i];
    console.log(`▶ [${i + 1}/${scenarios.length}] ${scenario.name}`);
    console.log(`  Playbook: ${scenario.playbookId}`);

    const playbook = getPlaybook(scenario.playbookId);
    if (!playbook) {
      console.log(`  ❌ Playbook "${scenario.playbookId}" not found — skipping`);
      results.push({
        scenarioId: scenario.id,
        scenarioName: scenario.name,
        target: scenario.target,
        playbookId: scenario.playbookId,
        status: "failed",
        stepsExecuted: 0,
        stepsSucceeded: 0,
        stepsFailed: 0,
        stepsSkipped: 0,
        overallConfidence: 0,
        criticalFindings: [],
        proofArtifacts: 0,
        totalDurationMs: 0,
        chainDepthScore: 0,
        confidenceScore: 0,
        evidenceScore: 0,
        findingScore: 0,
        compositeScore: 0,
        success: false,
        error: `Playbook "${scenario.playbookId}" not found`,
      });
      continue;
    }

    try {
      const fullTarget = `${TARGET_URL}${scenario.targetEndpoint}`;
      console.log(`  Target endpoint: ${fullTarget}`);

      const chainResult = await orchestrator.executePlaybook(
        playbook,
        fullTarget,
        {
          tenantId: "benchmark",
          organizationId: "benchmark",
        },
        (stepId, status, progress) => {
          process.stdout.write(`  [${scenario.id}] Step ${stepId}: ${status} (${progress}%)\r`);
        }
      );

      const scored = scoreChainResult(scenario, chainResult);
      results.push(scored);

      const statusIcon = scored.success ? "✅" : "🔶";
      console.log(`  ${statusIcon} ${scored.status} — ${scored.stepsSucceeded}/${scored.stepsExecuted} steps | ` +
        `confidence: ${scored.overallConfidence}% | score: ${scored.compositeScore}/100 | ` +
        `${(scored.totalDurationMs / 1000).toFixed(1)}s`);
    } catch (error: any) {
      console.log(`  ❌ ERROR: ${error.message}`);
      results.push({
        scenarioId: scenario.id,
        scenarioName: scenario.name,
        target: scenario.target,
        playbookId: scenario.playbookId,
        status: "failed",
        stepsExecuted: 0,
        stepsSucceeded: 0,
        stepsFailed: 0,
        stepsSkipped: 0,
        overallConfidence: 0,
        criticalFindings: [],
        proofArtifacts: 0,
        totalDurationMs: 0,
        chainDepthScore: 0,
        confidenceScore: 0,
        evidenceScore: 0,
        findingScore: 0,
        compositeScore: 0,
        success: false,
        error: error.message,
      });
    }
    console.log("");
  }

  // Build report
  const report = buildReport(results);

  // Print summary
  console.log("═══════════════════════════════════════════════════════════");
  console.log("  BREACH CHAIN RESULTS");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`  Scenarios:     ${report.overall.scenariosSucceeded}/${report.overall.scenariosRun} passed`);
  console.log(`  Avg Score:     ${report.overall.avgCompositeScore}/100`);
  console.log(`  Avg Depth:     ${report.overall.avgChainDepth} steps`);
  console.log(`  Avg Confidence:${report.overall.avgConfidence}%`);
  console.log("");
  console.log("  Competitor Capability Matrix:");
  console.log("  ┌──────────────────────────────────┬───────────┬─────────┬──────┐");
  console.log("  │ Capability                       │ OdinForge │ Shannon │ XBOW │");
  console.log("  ├──────────────────────────────────┼───────────┼─────────┼──────┤");
  for (const row of report.competitorComparison) {
    const cap = row.capability.padEnd(34);
    const of_ = row.odinforge.padEnd(9);
    const sh = row.shannon.padEnd(7);
    const xb = row.xbow.padEnd(4);
    console.log(`  │ ${cap}│ ${of_} │ ${sh} │ ${xb} │`);
  }
  console.log("  └──────────────────────────────────┴───────────┴─────────┴──────┘");
  console.log("═══════════════════════════════════════════════════════════");

  // Write report
  if (OUTPUT_PATH) {
    writeFileSync(OUTPUT_PATH, JSON.stringify(report, null, 2));
    console.log(`\nReport written to ${OUTPUT_PATH}`);
  }

  // CI threshold check
  const avgScore = report.overall.avgCompositeScore;
  if (avgScore < THRESHOLD_SCORE) {
    console.error(`\n  FAIL: Average composite score ${avgScore} < threshold ${THRESHOLD_SCORE}`);
    process.exit(1);
  }

  process.exit(0);
}

// ─── Report Builder ───────────────────────────────────────────────────

function buildReport(results: BreachChainBenchmarkResult[]): BreachChainReport {
  const succeeded = results.filter((r) => r.success).length;
  const total = results.length;

  const avgCompositeScore = total > 0
    ? Math.round(results.reduce((sum, r) => sum + r.compositeScore, 0) / total)
    : 0;

  const avgChainDepth = total > 0
    ? Math.round((results.reduce((sum, r) => sum + r.stepsSucceeded, 0) / total) * 10) / 10
    : 0;

  const avgConfidence = total > 0
    ? Math.round(results.reduce((sum, r) => sum + r.overallConfidence, 0) / total)
    : 0;

  // By target
  const byTarget: Record<string, { scenarios: number; succeeded: number; avgScore: number }> = {};
  for (const r of results) {
    if (!byTarget[r.target]) {
      byTarget[r.target] = { scenarios: 0, succeeded: 0, avgScore: 0 };
    }
    byTarget[r.target].scenarios++;
    if (r.success) byTarget[r.target].succeeded++;
  }
  for (const [target, stats] of Object.entries(byTarget)) {
    const targetResults = results.filter((r) => r.target === target);
    stats.avgScore = Math.round(
      targetResults.reduce((sum, r) => sum + r.compositeScore, 0) / targetResults.length
    );
  }

  return {
    meta: {
      timestamp: new Date().toISOString(),
      targets: Array.from(new Set(results.map((r) => r.target))),
      executionMode: EXECUTION_MODE,
    },
    overall: {
      scenariosRun: total,
      scenariosSucceeded: succeeded,
      avgCompositeScore,
      avgChainDepth,
      avgConfidence,
    },
    byTarget,
    results,
    competitorComparison: buildCompetitorComparison() as any,
  };
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
