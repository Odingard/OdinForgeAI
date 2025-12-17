#!/usr/bin/env npx tsx

interface LoadTestConfig {
  baseUrl: string;
  concurrency: number;
  totalRequests: number;
  testDurationMs: number;
}

interface TestResult {
  endpoint: string;
  totalRequests: number;
  successCount: number;
  errorCount: number;
  rateLimitedCount: number;
  avgLatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  minLatencyMs: number;
  maxLatencyMs: number;
  requestsPerSecond: number;
}

interface RequestResult {
  success: boolean;
  latencyMs: number;
  statusCode: number;
  rateLimited: boolean;
}

async function makeRequest(url: string, options: RequestInit = {}): Promise<RequestResult> {
  const start = Date.now();
  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });
    const latencyMs = Date.now() - start;
    return {
      success: response.ok,
      latencyMs,
      statusCode: response.status,
      rateLimited: response.status === 429,
    };
  } catch (error) {
    return {
      success: false,
      latencyMs: Date.now() - start,
      statusCode: 0,
      rateLimited: false,
    };
  }
}

function calculatePercentile(values: number[], percentile: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.ceil((percentile / 100) * sorted.length) - 1;
  return sorted[Math.max(0, index)];
}

async function runConcurrentRequests(
  endpoint: string,
  method: string,
  body: unknown | null,
  concurrency: number,
  totalRequests: number
): Promise<TestResult> {
  const results: RequestResult[] = [];
  const startTime = Date.now();
  
  let completed = 0;
  const pending: Promise<void>[] = [];
  
  const url = `http://localhost:5000${endpoint}`;
  
  async function executeRequest() {
    const result = await makeRequest(url, {
      method,
      body: body ? JSON.stringify(body) : undefined,
    });
    results.push(result);
    completed++;
    
    const progress = Math.round((completed / totalRequests) * 100);
    if (completed % Math.ceil(totalRequests / 10) === 0) {
      process.stdout.write(`\r  Progress: ${progress}% (${completed}/${totalRequests})`);
    }
  }
  
  for (let i = 0; i < totalRequests; i++) {
    if (pending.length >= concurrency) {
      await Promise.race(pending);
      pending.splice(0, pending.findIndex(p => p === undefined) + 1);
    }
    
    const promise = executeRequest().then(() => {
      const idx = pending.indexOf(promise);
      if (idx > -1) pending.splice(idx, 1);
    });
    pending.push(promise);
  }
  
  await Promise.all(pending);
  console.log();
  
  const duration = Date.now() - startTime;
  const latencies = results.map(r => r.latencyMs);
  
  return {
    endpoint,
    totalRequests: results.length,
    successCount: results.filter(r => r.success).length,
    errorCount: results.filter(r => !r.success && !r.rateLimited).length,
    rateLimitedCount: results.filter(r => r.rateLimited).length,
    avgLatencyMs: latencies.reduce((a, b) => a + b, 0) / latencies.length,
    p95LatencyMs: calculatePercentile(latencies, 95),
    p99LatencyMs: calculatePercentile(latencies, 99),
    minLatencyMs: Math.min(...latencies),
    maxLatencyMs: Math.max(...latencies),
    requestsPerSecond: (results.length / duration) * 1000,
  };
}

function printResult(result: TestResult) {
  console.log(`\n  ${result.endpoint}:`);
  console.log(`    Total Requests:     ${result.totalRequests}`);
  console.log(`    Successful:         ${result.successCount} (${((result.successCount / result.totalRequests) * 100).toFixed(1)}%)`);
  console.log(`    Errors:             ${result.errorCount}`);
  console.log(`    Rate Limited:       ${result.rateLimitedCount}`);
  console.log(`    Avg Latency:        ${result.avgLatencyMs.toFixed(2)}ms`);
  console.log(`    P95 Latency:        ${result.p95LatencyMs.toFixed(2)}ms`);
  console.log(`    P99 Latency:        ${result.p99LatencyMs.toFixed(2)}ms`);
  console.log(`    Min/Max Latency:    ${result.minLatencyMs}ms / ${result.maxLatencyMs}ms`);
  console.log(`    Requests/sec:       ${result.requestsPerSecond.toFixed(2)}`);
}

async function testEvaluationsEndpoint(concurrency: number, requests: number): Promise<TestResult> {
  console.log(`\nTesting GET /api/aev/evaluations (${concurrency} concurrent, ${requests} total)`);
  return runConcurrentRequests("/api/aev/evaluations", "GET", null, concurrency, requests);
}

async function testEvaluationCreate(concurrency: number, requests: number): Promise<TestResult> {
  console.log(`\nTesting POST /api/aev/evaluate (${concurrency} concurrent, ${requests} total)`);
  
  const testEvaluation = {
    assetId: `load-test-asset-${Date.now()}`,
    exposureType: "cve",
    description: "Load test evaluation - CVE-2024-TEST",
    priority: "medium",
  };
  
  return runConcurrentRequests("/api/aev/evaluate", "POST", testEvaluation, concurrency, requests);
}

async function testBatchJobsRead(concurrency: number, requests: number): Promise<TestResult> {
  console.log(`\nTesting GET /api/batch-jobs (${concurrency} concurrent, ${requests} total)`);
  return runConcurrentRequests("/api/batch-jobs", "GET", null, concurrency, requests);
}

async function testReportsRead(concurrency: number, requests: number): Promise<TestResult> {
  console.log(`\nTesting GET /api/reports (${concurrency} concurrent, ${requests} total)`);
  return runConcurrentRequests("/api/reports", "GET", null, concurrency, requests);
}

async function testSimulationsRead(concurrency: number, requests: number): Promise<TestResult> {
  console.log(`\nTesting GET /api/simulations (${concurrency} concurrent, ${requests} total)`);
  return runConcurrentRequests("/api/simulations", "GET", null, concurrency, requests);
}

async function testAgentsRead(concurrency: number, requests: number): Promise<TestResult> {
  console.log(`\nTesting GET /api/agents (${concurrency} concurrent, ${requests} total)`);
  return runConcurrentRequests("/api/agents", "GET", null, concurrency, requests);
}

async function runLoadTests() {
  console.log("╔════════════════════════════════════════════════════════════════╗");
  console.log("║           OdinForge Platform Load Testing Suite               ║");
  console.log("╚════════════════════════════════════════════════════════════════╝");
  
  const args = process.argv.slice(2);
  const concurrency = parseInt(args[0]) || 10;
  const requests = parseInt(args[1]) || 100;
  
  console.log(`\nConfiguration:`);
  console.log(`  Concurrency:    ${concurrency} parallel requests`);
  console.log(`  Total Requests: ${requests} per endpoint`);
  console.log(`  Base URL:       http://localhost:5000`);
  
  const results: TestResult[] = [];
  
  try {
    const healthCheck = await makeRequest("http://localhost:5000/api/aev/evaluations");
    if (!healthCheck.success) {
      console.error("\nServer not responding. Make sure the application is running on port 5000.");
      process.exit(1);
    }
    console.log("\nServer health check passed!");
  } catch (error) {
    console.error("\nFailed to connect to server:", error);
    process.exit(1);
  }
  
  console.log("\n════════════════════════════════════════════════════════════════");
  console.log("  READ ENDPOINTS (High Throughput)");
  console.log("════════════════════════════════════════════════════════════════");
  
  results.push(await testEvaluationsEndpoint(concurrency, requests));
  results.push(await testBatchJobsRead(concurrency, requests));
  results.push(await testReportsRead(concurrency, requests));
  results.push(await testSimulationsRead(concurrency, requests));
  results.push(await testAgentsRead(concurrency, requests));
  
  console.log("\n════════════════════════════════════════════════════════════════");
  console.log("  WRITE ENDPOINTS (Rate Limited)");
  console.log("════════════════════════════════════════════════════════════════");
  
  results.push(await testEvaluationCreate(Math.min(concurrency, 5), Math.min(requests, 50)));
  
  console.log("\n════════════════════════════════════════════════════════════════");
  console.log("  LOAD TEST RESULTS SUMMARY");
  console.log("════════════════════════════════════════════════════════════════");
  
  results.forEach(printResult);
  
  console.log("\n════════════════════════════════════════════════════════════════");
  console.log("  OVERALL METRICS");
  console.log("════════════════════════════════════════════════════════════════");
  
  const totalSuccess = results.reduce((sum, r) => sum + r.successCount, 0);
  const totalRequests = results.reduce((sum, r) => sum + r.totalRequests, 0);
  const totalRateLimited = results.reduce((sum, r) => sum + r.rateLimitedCount, 0);
  const avgLatency = results.reduce((sum, r) => sum + r.avgLatencyMs, 0) / results.length;
  const avgRps = results.reduce((sum, r) => sum + r.requestsPerSecond, 0) / results.length;
  
  console.log(`\n  Total Requests:       ${totalRequests}`);
  console.log(`  Total Successful:     ${totalSuccess} (${((totalSuccess / totalRequests) * 100).toFixed(1)}%)`);
  console.log(`  Total Rate Limited:   ${totalRateLimited}`);
  console.log(`  Avg Latency:          ${avgLatency.toFixed(2)}ms`);
  console.log(`  Avg Requests/sec:     ${avgRps.toFixed(2)}`);
  
  const hasHighLatency = results.some(r => r.p95LatencyMs > 500);
  const hasHighErrors = results.some(r => r.errorCount / r.totalRequests > 0.05);
  
  console.log("\n  Status: " + (hasHighLatency || hasHighErrors 
    ? "NEEDS ATTENTION - Check latency or error rates"
    : "HEALTHY - All endpoints performing well"));
  
  console.log("\n════════════════════════════════════════════════════════════════");
}

runLoadTests().catch(console.error);
