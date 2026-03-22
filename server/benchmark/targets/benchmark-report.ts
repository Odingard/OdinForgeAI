import fs from "fs";
import path from "path";
import { BENCHMARK_TARGETS } from "./benchmark-targets";
import type { BenchmarkResult } from "./run-benchmark";

const RESULTS_DIR = path.join(__dirname, "results");

function loadAllResults(): BenchmarkResult[] {
  if (!fs.existsSync(RESULTS_DIR)) return [];
  const files = fs.readdirSync(RESULTS_DIR).filter((f) => f.endsWith(".json"));
  const results: BenchmarkResult[] = [];

  for (const file of files) {
    try {
      const data = fs.readFileSync(path.join(RESULTS_DIR, file), "utf-8");
      results.push(JSON.parse(data));
    } catch {
      // skip
    }
  }

  return results.sort((a, b) => a.runDate.localeCompare(b.runDate));
}

function generateReport(): string {
  const results = loadAllResults();
  const lines: string[] = [];

  lines.push("# OdinForge Benchmark Report");
  lines.push("");
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push(`Total targets: ${BENCHMARK_TARGETS.length}`);
  lines.push(`Targets with results: ${new Set(results.map((r) => r.targetId)).size}`);
  lines.push("");

  // Summary table
  lines.push("## Summary");
  lines.push("");
  lines.push("| Target | Category | Support | Priority | Runs | Last Findings | Last Verdict | Last Run |");
  lines.push("|--------|----------|---------|----------|------|---------------|--------------|----------|");

  for (const target of BENCHMARK_TARGETS) {
    const targetResults = results.filter((r) => r.targetId === target.id);
    const latest = targetResults[targetResults.length - 1];

    const runs = targetResults.length;
    const findings = latest ? String(latest.validatedFindings) : "-";
    const verdict = latest?.verdict || "-";
    const lastRun = latest ? latest.runDate.split("T")[0] : "never";

    lines.push(
      `| ${target.name} | ${target.category} | ${target.odinforgeSupport} | ${target.priority} | ${runs} | ${findings} | ${verdict} | ${lastRun} |`
    );
  }

  lines.push("");

  // Trend data per target
  const targetsWithMultipleRuns = BENCHMARK_TARGETS.filter(
    (t) => results.filter((r) => r.targetId === t.id).length > 1
  );

  if (targetsWithMultipleRuns.length > 0) {
    lines.push("## Trend Data");
    lines.push("");

    for (const target of targetsWithMultipleRuns) {
      const targetResults = results.filter((r) => r.targetId === target.id);
      lines.push(`### ${target.name}`);
      lines.push("");
      lines.push("| Date | Endpoints | Findings | Paths | Duration | Verdict |");
      lines.push("|------|-----------|----------|-------|----------|---------|");

      for (const r of targetResults) {
        lines.push(
          `| ${r.runDate.split("T")[0]} | ${r.endpoints} | ${r.validatedFindings} | ${r.attackPaths} | ${(r.durationMs / 1000).toFixed(1)}s | ${r.verdict || "-"} |`
        );
      }

      lines.push("");
    }
  }

  // Coverage matrix
  lines.push("## Vuln Class Coverage");
  lines.push("");

  const allClasses = new Set<string>();
  for (const t of BENCHMARK_TARGETS) {
    for (const vc of t.vulnClasses) allClasses.add(vc);
  }

  const sorted = Array.from(allClasses).sort();
  lines.push(`| Vuln Class | Targets | Tested | Findings |`);
  lines.push(`|------------|---------|--------|----------|`);

  for (const vc of sorted) {
    const targets = BENCHMARK_TARGETS.filter((t) => t.vulnClasses.includes(vc));
    const tested = targets.filter((t) => results.some((r) => r.targetId === t.id));
    const findings = results
      .filter((r) => targets.some((t) => t.id === r.targetId))
      .reduce((sum, r) => sum + r.validatedFindings, 0);

    lines.push(`| ${vc} | ${targets.length} | ${tested.length} | ${findings} |`);
  }

  lines.push("");

  // Not yet tested
  const untestedCritical = BENCHMARK_TARGETS.filter(
    (t) => t.priority === "critical" && !results.some((r) => r.targetId === t.id)
  );

  if (untestedCritical.length > 0) {
    lines.push("## Untested Critical Targets");
    lines.push("");
    for (const t of untestedCritical) {
      lines.push(`- **${t.name}** (${t.category}) — ${t.description}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

// CLI entry
const report = generateReport();
console.log(report);

// Also write to file
const outputPath = path.join(__dirname, "BENCHMARK_REPORT.md");
fs.writeFileSync(outputPath, report);
console.log(`\nReport written to: ${outputPath}`);

export { generateReport, loadAllResults };
