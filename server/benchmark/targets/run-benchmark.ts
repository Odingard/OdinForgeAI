import fs from "fs";
import path from "path";
import { getTargetById, type BenchmarkTarget } from "./benchmark-targets";

interface BenchmarkResult {
  targetId: string;
  targetName: string;
  runDate: string;
  durationMs: number;
  endpoints: number;
  attempts: number;
  validatedFindings: number;
  attackPaths: number;
  replayAttempted: number;
  replaySucceeded: number;
  llmTime: number;
  verdict?: "GO" | "HOLD" | "NO_GO";
  findings: Array<{
    id: string;
    title: string;
    severity: string;
    evidenceQuality: string;
    technique: string;
  }>;
  errors: string[];
}

const RESULTS_DIR = path.join(__dirname, "results");

function ensureResultsDir(): void {
  if (!fs.existsSync(RESULTS_DIR)) {
    fs.mkdirSync(RESULTS_DIR, { recursive: true });
  }
}

function saveResult(result: BenchmarkResult): string {
  ensureResultsDir();
  const date = new Date().toISOString().split("T")[0];
  const filename = `${result.targetId}-${date}.json`;
  const filepath = path.join(RESULTS_DIR, filename);
  fs.writeFileSync(filepath, JSON.stringify(result, null, 2));
  return filepath;
}

function loadResults(targetId?: string): BenchmarkResult[] {
  ensureResultsDir();
  const files = fs.readdirSync(RESULTS_DIR).filter((f) => f.endsWith(".json"));
  const results: BenchmarkResult[] = [];

  for (const file of files) {
    if (targetId && !file.startsWith(targetId)) continue;
    try {
      const data = fs.readFileSync(path.join(RESULTS_DIR, file), "utf-8");
      results.push(JSON.parse(data));
    } catch {
      // skip malformed files
    }
  }

  return results.sort((a, b) => a.runDate.localeCompare(b.runDate));
}

async function runBenchmark(targetId: string): Promise<BenchmarkResult> {
  const target = getTargetById(targetId);
  if (!target) {
    throw new Error(`Unknown target: ${targetId}. Available: juice-shop, dvwa, broken-crystals, webgoat, zero-bank, etc.`);
  }

  if (!target.url && target.hosting === "online") {
    throw new Error(`Target ${targetId} has no URL configured`);
  }

  if (target.hosting === "local" && !target.url) {
    throw new Error(
      `Target ${targetId} is local-only. Start it first (e.g., docker run -p 3000:3000 ${target.dockerImage || "IMAGE"}) then set url in benchmark-targets.ts`
    );
  }

  const startTime = Date.now();
  const errors: string[] = [];

  console.log(`\n=== BENCHMARK: ${target.name} ===`);
  console.log(`Target: ${target.url}`);
  console.log(`Category: ${target.category}`);
  console.log(`Vuln classes: ${target.vulnClasses.join(", ")}`);
  console.log(`Starting...\n`);

  // Use the public run() entry point which handles auth, crawl, exploit, replay, paths, and launch readiness
  const { runActiveExploitEngine } = await import("../../services/active-exploit-engine");

  let result: any;
  try {
    result = await runActiveExploitEngine(
      { baseUrl: target.url! } as any
    );
  } catch (e) {
    errors.push(`Engine failed: ${e instanceof Error ? e.message : String(e)}`);
    result = { crawl: { endpoints: [] }, attempts: [], validated: [], attackPaths: [], durationMs: Date.now() - startTime, summary: {} };
  }

  const benchmarkResult: BenchmarkResult = {
    targetId: target.id,
    targetName: target.name,
    runDate: new Date().toISOString(),
    durationMs: result.durationMs ?? (Date.now() - startTime),
    endpoints: result.crawl?.endpoints?.length ?? 0,
    attempts: result.attempts?.length ?? 0,
    validatedFindings: result.validated?.length ?? 0,
    attackPaths: result.attackPaths?.length ?? 0,
    replayAttempted: 0,
    replaySucceeded: 0,
    llmTime: 0,
    verdict: result.launchReadiness?.finalVerdict,
    findings: (result.validated ?? []).map((v: any) => ({
      id: v.payload?.id || "unknown",
      title: v.payload?.name || "unknown",
      severity: v.payload?.severity || "unknown",
      evidenceQuality: v.validated ? "proven" : "unconfirmed",
      technique: `${v.endpoint?.url || "?"} → ${v.payload?.name || "?"}`,
    })),
    errors,
  };

  const filepath = saveResult(benchmarkResult);

  console.log(`\n=== RESULTS: ${target.name} ===`);
  console.log(`Duration: ${benchmarkResult.durationMs}ms`);
  console.log(`Endpoints: ${benchmarkResult.endpoints}`);
  console.log(`Validated: ${benchmarkResult.validatedFindings}`);
  console.log(`Paths: ${benchmarkResult.attackPaths}`);
  console.log(`Verdict: ${benchmarkResult.verdict || "N/A"}`);
  console.log(`Saved: ${filepath}`);
  if (errors.length) console.log(`Errors: ${errors.join(", ")}`);

  return benchmarkResult;
}

// CLI entry point
const targetId = process.argv[2];
if (!targetId) {
  console.log("Usage: npx tsx server/benchmark/targets/run-benchmark.ts <target-id>");
  console.log("\nAvailable targets:");
  const { BENCHMARK_TARGETS } = require("./benchmark-targets");
  for (const t of BENCHMARK_TARGETS) {
    const supported = t.odinforgeSupport === "full" || t.odinforgeSupport === "partial";
    console.log(`  ${t.id.padEnd(20)} ${t.name.padEnd(40)} ${supported ? "✓" : "○"} ${t.priority}`);
  }
  process.exit(0);
}

runBenchmark(targetId)
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });

export { runBenchmark, loadResults, saveResult, type BenchmarkResult };
