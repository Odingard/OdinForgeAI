#!/usr/bin/env node
/**
 * Automated benchmark runner for vuln-bank
 * Requires OdinForge to be running (npm run dev)
 * 
 * Usage:
 *   npm run benchmark-vuln-bank
 *   or: node scripts/benchmark-vuln-bank.ts
 */

import axios from "axios";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

// Configuration
const ODINFORGE_API_BASE = process.env.ODINFORGE_API_URL || "http://localhost:5000";
const VULN_BANK_URL = process.env.VULN_BANK_URL || "http://localhost:5000";
const JWT_TOKEN = process.env.ODINFORGE_JWT_TOKEN || "";
const RESULTS_DIR = join(process.cwd(), "results");

// Create results directory
mkdirSync(RESULTS_DIR, { recursive: true });

const TIMESTAMP = new Date().toISOString().replace(/[:.]/g, "-");
const RESULTS_FILE = join(RESULTS_DIR, `vuln-bank-benchmark-${TIMESTAMP}.json`);

interface BenchmarkResult {
  timestamp: string;
  targetUrl: string;
  evaluationId: string;
  phases: Record<string, unknown>;
  summary: {
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    discoveryTimeMs: number;
    exploitationTimeMs: number;
  };
}

const result: BenchmarkResult = {
  timestamp: TIMESTAMP,
  targetUrl: VULN_BANK_URL,
  evaluationId: "",
  phases: {},
  summary: {
    totalFindings: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    discoveryTimeMs: 0,
    exploitationTimeMs: 0,
  },
};

async function checkOdinForgeHealth(): Promise<boolean> {
  try {
    const response = await axios.get(`${ODINFORGE_API_BASE}/api/health`, {
      timeout: 5000,
    });
    return response.status === 200;
  } catch {
    console.error(
      "❌ OdinForge is not running. Start it with: npm run dev"
    );
    return false;
  }
}

async function checkVulnBankHealth(): Promise<boolean> {
  try {
    const response = await axios.get(VULN_BANK_URL, {
      timeout: 5000,
    });
    return response.status === 200;
  } catch {
    console.error(
      "❌ vuln-bank is not running. Start it with: ./scripts/benchmark-vuln-bank.sh"
    );
    return false;
  }
}

async function createEvaluation(): Promise<string> {
  try {
    console.log("📝 Creating evaluation...");

    const response = await axios.post(
      `${ODINFORGE_API_BASE}/api/evaluations`,
      {
        assetId: `vuln-bank-benchmark-${TIMESTAMP}`,
        assetType: "web_application",
        targetUrl: VULN_BANK_URL,
        targetDescription: "Deliberately vulnerable banking application",
        executionMode: "safe",
        scanType: "full_recon",
      },
      {
        headers: JWT_TOKEN
          ? { Authorization: `Bearer ${JWT_TOKEN}` }
          : undefined,
        timeout: 30000,
      }
    );

    const evaluationId = response.data.id || response.data.evaluationId;
    console.log(`✅ Evaluation created: ${evaluationId}`);
    return evaluationId;
  } catch (error: any) {
    if (error.response?.status === 401) {
      console.error(
        "❌ Unauthorized. Set ODINFORGE_JWT_TOKEN environment variable"
      );
    } else {
      console.error(`❌ Failed to create evaluation: ${error.message}`);
    }
    throw error;
  }
}

async function pollEvaluationProgress(
  evaluationId: string,
  maxWaitMs: number = 600000
): Promise<void> {
  const startTime = Date.now();
  let lastStatus = "";

  while (Date.now() - startTime < maxWaitMs) {
    try {
      const response = await axios.get(
        `${ODINFORGE_API_BASE}/api/evaluations/${evaluationId}`,
        {
          headers: JWT_TOKEN
            ? { Authorization: `Bearer ${JWT_TOKEN}` }
            : undefined,
        }
      );

      const { status, phases } = response.data;

      if (status !== lastStatus) {
        console.log(`⏳ Status: ${status}`);
        lastStatus = status;
      }

      if (phases) {
        result.phases = phases;
      }

      if (status === "completed" || status === "failed") {
        console.log(`✅ Evaluation ${status}`);
        break;
      }

      // Wait before next poll
      await new Promise((resolve) => setTimeout(resolve, 5000));
    } catch (error: any) {
      console.error(`Error polling evaluation: ${error.message}`);
      await new Promise((resolve) => setTimeout(resolve, 5000));
    }
  }

  if (Date.now() - startTime >= maxWaitMs) {
    console.warn("⚠️  Evaluation timeout (10 minutes)");
  }
}

async function getEvaluationResults(evaluationId: string): Promise<void> {
  try {
    console.log("📊 Fetching detailed results...");

    const response = await axios.get(
      `${ODINFORGE_API_BASE}/api/evaluations/${evaluationId}`,
      {
        headers: JWT_TOKEN
          ? { Authorization: `Bearer ${JWT_TOKEN}` }
          : undefined,
      }
    );

    const findings = response.data.findings || [];

    result.evaluationId = evaluationId;
    result.summary.totalFindings = findings.length;
    result.summary.criticalCount = findings.filter(
      (f: any) => f.severity === "critical"
    ).length;
    result.summary.highCount = findings.filter(
      (f: any) => f.severity === "high"
    ).length;
    result.summary.mediumCount = findings.filter(
      (f: any) => f.severity === "medium"
    ).length;
    result.summary.lowCount = findings.filter(
      (f: any) => f.severity === "low"
    ).length;

    console.log(
      `📈 Found ${result.summary.totalFindings} vulnerabilities:`
    );
    console.log(
      `   🔴 Critical: ${result.summary.criticalCount}`
    );
    console.log(`   🟠 High: ${result.summary.highCount}`);
    console.log(`   🟡 Medium: ${result.summary.mediumCount}`);
    console.log(`   🔵 Low: ${result.summary.lowCount}`);
  } catch (error: any) {
    console.error(`Error fetching results: ${error.message}`);
  }
}

async function main(): Promise<void> {
  console.log("🚀 OdinForge vuln-bank Benchmark Runner\n");

  // Health checks
  console.log("🔍 Checking service health...");
  const odinforgeReady = await checkOdinForgeHealth();
  const vulnBankReady = await checkVulnBankHealth();

  if (!odinforgeReady || !vulnBankReady) {
    process.exit(1);
  }
  console.log("✅ All services ready\n");

  try {
    // Create evaluation
    const evaluationId = await createEvaluation();

    // Poll for results
    console.log("⏳ Waiting for evaluation to complete (max 10 minutes)...\n");
    await pollEvaluationProgress(evaluationId);

    // Fetch final results
    await getEvaluationResults(evaluationId);

    // Save results to file
    writeFileSync(RESULTS_FILE, JSON.stringify(result, null, 2));
    console.log(`\n📄 Results saved to: ${RESULTS_FILE}`);

    // Summary
    console.log("\n" + "=".repeat(50));
    console.log("BENCHMARK SUMMARY");
    console.log("=".repeat(50));
    console.log(`Target: ${result.targetUrl}`);
    console.log(`Evaluation ID: ${result.evaluationId}`);
    console.log(`Total Findings: ${result.summary.totalFindings}`);
    console.log(`Critical: ${result.summary.criticalCount}`);
    console.log(`High: ${result.summary.highCount}`);
    console.log(`Medium: ${result.summary.mediumCount}`);
    console.log(`Low: ${result.summary.lowCount}`);
    console.log("=".repeat(50) + "\n");

    process.exit(0);
  } catch (error: any) {
    console.error(`\n❌ Benchmark failed: ${error.message}`);
    process.exit(1);
  }
}

main().catch(console.error);
