/**
 * OdinForge AI — Benchmark Social Proof Export
 *
 * Reads a benchmark JSON report and generates social media copy
 * in three formats: Twitter/X thread, LinkedIn post, HN comment.
 *
 * Usage:
 *   npx tsx scripts/benchmark-social.ts <path-to-benchmark-report.json>
 */

import { readFileSync } from "fs";

interface BenchmarkReport {
  meta: {
    target: string;
    targetName?: string;
    targetDisplayName?: string;
    targetVersion?: string;
    executionMode: string;
    timestamp: string;
    scenarioCount: number;
    passRate: string;
    detectionRate: string;
    totalToolCalls: number;
    totalTimeMs: number;
  };
  results: Array<{
    scenarioId: string;
    scenarioName: string;
    success: boolean;
    matchedExpected: string[];
    missedExpected: string[];
  }>;
}

function loadReport(path: string): BenchmarkReport {
  const raw = readFileSync(path, "utf-8");
  return JSON.parse(raw);
}

function getTargetLabel(report: BenchmarkReport): string {
  return report.meta.targetDisplayName || report.meta.targetName || "OWASP Juice Shop";
}

function getMissedVulns(report: BenchmarkReport): string[] {
  const missed: string[] = [];
  for (const r of report.results) {
    missed.push(...r.missedExpected);
  }
  return [...new Set(missed)];
}

// ─── Twitter/X Thread ────────────────────────────────────────────────

function generateTwitterThread(report: BenchmarkReport): string {
  const target = getTargetLabel(report);
  const { passRate, detectionRate, totalToolCalls, totalTimeMs, scenarioCount } = report.meta;
  const timeSeconds = (totalTimeMs / 1000).toFixed(0);
  const missed = getMissedVulns(report);

  const tweets: string[] = [];

  tweets.push(
    `We just benchmarked OdinForge's exploit agent against ${target}.\n\n` +
    `${passRate} scenarios passed\n` +
    `${detectionRate} detection rate\n` +
    `${totalToolCalls} tool calls in ${timeSeconds}s\n\n` +
    `Full results are public. Here's the thread.`
  );

  tweets.push(
    `The benchmark runs ${scenarioCount} scenarios covering SQLi, XSS, auth bypass, path traversal, and more.\n\n` +
    `Each scenario feeds a target description to our agentic exploit agent, which autonomously uses HTTP tools to find and validate vulnerabilities.`
  );

  if (missed.length > 0) {
    tweets.push(
      `Transparency: we missed ${missed.length} expected vuln type(s): ${missed.join(", ")}.\n\n` +
      `We publish what we miss, not just what we find. That's the point of open benchmarks.`
    );
  } else {
    tweets.push(
      `100% of expected vulnerability types detected. Zero misses.\n\n` +
      `We publish everything — hits and misses. That's the point of open benchmarks.`
    );
  }

  tweets.push(
    `Reproduce it yourself:\n\n` +
    `docker run -d -p 3001:3000 bkimminich/juice-shop:v17.1.1\n` +
    `npx tsx server/benchmark/exploit-benchmark.ts http://localhost:3001 simulation\n\n` +
    `Full results: odinforge.ai/benchmark`
  );

  return tweets.map((t, i) => `--- Tweet ${i + 1} ---\n${t}`).join("\n\n");
}

// ─── LinkedIn Post ───────────────────────────────────────────────────

function generateLinkedIn(report: BenchmarkReport): string {
  const target = getTargetLabel(report);
  const { passRate, detectionRate, totalToolCalls, totalTimeMs } = report.meta;
  const timeSeconds = (totalTimeMs / 1000).toFixed(0);
  const missed = getMissedVulns(report);

  let post = `OdinForge Benchmark Results: ${target}\n\n`;

  post += `We run our AI exploit agent against known-vulnerable targets and publish the results — no cherry-picking.\n\n`;

  post += `Latest run:\n`;
  post += `  ${passRate} scenarios passed\n`;
  post += `  ${detectionRate} vulnerability detection rate\n`;
  post += `  ${totalToolCalls} autonomous tool calls\n`;
  post += `  ${timeSeconds}s total execution time\n\n`;

  if (missed.length > 0) {
    post += `What we missed: ${missed.join(", ")}. We're working on improving detection for these categories.\n\n`;
  }

  post += `Why publish benchmarks?\n\n`;
  post += `Most AI security tools make claims without reproducible evidence. `;
  post += `We think the industry needs transparent, verifiable results. `;
  post += `Our benchmark harness runs in CI on every push, with threshold gating that fails the build if detection drops.\n\n`;

  post += `The methodology is open. The results are public. Anyone can reproduce them.\n\n`;

  post += `Full results: odinforge.ai/benchmark\n`;
  post += `Reproduce: docs/BENCHMARKS.md in our repo\n\n`;

  post += `#cybersecurity #aisecurity #pentesting #benchmarks #transparency`;

  return post;
}

// ─── Hacker News Comment ─────────────────────────────────────────────

function generateHN(report: BenchmarkReport): string {
  const target = getTargetLabel(report);
  const { passRate, detectionRate, totalToolCalls, totalTimeMs } = report.meta;
  const timeSeconds = (totalTimeMs / 1000).toFixed(0);
  const missed = getMissedVulns(report);

  let comment = `We've been running our exploit agent against ${target} and publishing the results.\n\n`;

  comment += `Latest numbers: ${passRate} scenarios passed, ${detectionRate} detection rate, ${totalToolCalls} tool calls, ${timeSeconds}s total.\n\n`;

  comment += `The agent runs a multi-turn tool-calling loop with 6 security tools (HTTP fingerprinting, port scanning, fuzzing, SSL/TLS checks, protocol probing, vulnerability validation). `;
  comment += `It operates in simulation mode — safe payloads that prove exploitability without causing damage.\n\n`;

  if (missed.length > 0) {
    comment += `We missed: ${missed.join(", ")}. Publishing misses alongside hits is the whole point — if we only showed wins, you'd rightfully be skeptical.\n\n`;
  }

  comment += `Reproduce it:\n\n`;
  comment += `  docker run -d -p 3001:3000 bkimminich/juice-shop:v17.1.1\n`;
  comment += `  npx tsx server/benchmark/exploit-benchmark.ts http://localhost:3001 simulation\n\n`;

  comment += `Results page: odinforge.ai/benchmark`;

  return comment;
}

// ─── Main ────────────────────────────────────────────────────────────

function main() {
  const reportPath = process.argv[2];

  if (!reportPath) {
    console.error("Usage: npx tsx scripts/benchmark-social.ts <path-to-benchmark-report.json>");
    process.exit(1);
  }

  const report = loadReport(reportPath);

  console.log("=".repeat(60));
  console.log("  TWITTER/X THREAD");
  console.log("=".repeat(60));
  console.log();
  console.log(generateTwitterThread(report));
  console.log();

  console.log("=".repeat(60));
  console.log("  LINKEDIN POST");
  console.log("=".repeat(60));
  console.log();
  console.log(generateLinkedIn(report));
  console.log();

  console.log("=".repeat(60));
  console.log("  HACKER NEWS COMMENT");
  console.log("=".repeat(60));
  console.log();
  console.log(generateHN(report));
  console.log();
}

main();
