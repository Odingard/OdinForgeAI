/**
 * API Fuzz CI Runner
 *
 * Registers a test user, authenticates, then runs the API fuzzing engine
 * against a predefined set of critical endpoints.
 */

const BASE = process.env.BACKEND_URL || "http://127.0.0.1:5000";
const FUZZ_CONCURRENCY = 3;
const FUZZ_TIMEOUT_MS = 10_000;
const FUZZ_DELAY_MS = 50;
const MAX_CASES_PER_ENDPOINT = 30;

// Critical API endpoints to fuzz — these accept user input
const ENDPOINTS = [
  { path: "/ui/api/auth/login", method: "POST", params: [
    { name: "email", type: "string", format: "email", in: "body", required: true },
    { name: "password", type: "string", in: "body", required: true },
  ]},
  { path: "/api/assets", method: "POST", params: [
    { name: "name", type: "string", in: "body", required: true },
    { name: "type", type: "string", in: "body", required: true, enum: ["web_application", "api", "network", "cloud", "mobile"] },
    { name: "target", type: "string", format: "uri", in: "body", required: true },
  ]},
  { path: "/api/evaluations", method: "POST", params: [
    { name: "assetId", type: "string", format: "uuid", in: "body", required: true },
    { name: "scanType", type: "string", in: "body" },
  ]},
  { path: "/api/assets", method: "GET", params: [
    { name: "search", type: "string", in: "query" },
    { name: "type", type: "string", in: "query" },
  ]},
  { path: "/api/evaluations", method: "GET", params: [
    { name: "status", type: "string", in: "query" },
    { name: "assetId", type: "string", format: "uuid", in: "query" },
  ]},
];

// ---- Inline fuzzing (avoid import of TS modules in plain JS CI) ----

const INJECTION_PAYLOADS = [
  { id: "inj-sql-1", category: "injection", value: "' OR '1'='1", desc: "SQL injection", risk: "critical" },
  { id: "inj-sql-2", category: "injection", value: "'; DROP TABLE users;--", desc: "Stacked SQL", risk: "critical" },
  { id: "inj-xss-1", category: "injection", value: "<script>alert(1)</script>", desc: "XSS basic", risk: "high" },
  { id: "inj-xss-2", category: "injection", value: "<img src=x onerror=alert(1)>", desc: "XSS img", risk: "high" },
  { id: "inj-cmd-1", category: "injection", value: "; cat /etc/passwd", desc: "Command injection", risk: "critical" },
  { id: "inj-ssti", category: "injection", value: "{{7*7}}", desc: "SSTI", risk: "critical" },
  { id: "inj-path", category: "injection", value: "../../../etc/passwd", desc: "Path traversal", risk: "critical" },
  { id: "inj-ssrf", category: "injection", value: "http://169.254.169.254/latest/meta-data/", desc: "SSRF", risk: "critical" },
];

const NULL_PAYLOADS = [
  { id: "null-1", category: "null", value: null, desc: "Null", risk: "medium" },
  { id: "null-2", category: "null", value: "", desc: "Empty string", risk: "low" },
  { id: "null-3", category: "null", value: "undefined", desc: "String undefined", risk: "low" },
];

const BOUNDARY_PAYLOADS = [
  { id: "bv-1", category: "boundary", value: "A".repeat(10000), desc: "10K chars", risk: "medium" },
  { id: "bv-2", category: "boundary", value: 2147483648, desc: "INT32 overflow", risk: "high" },
  { id: "bv-3", category: "boundary", value: -1, desc: "Negative one", risk: "medium" },
];

const ALL_PAYLOADS = [...INJECTION_PAYLOADS, ...NULL_PAYLOADS, ...BOUNDARY_PAYLOADS];

async function getAuthToken() {
  const email = `fuzz-ci-${Date.now()}@test.local`;
  const password = "FuzzTest!C1#secure";

  // Try to register
  try {
    await fetch(`${BASE}/ui/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, name: "Fuzz CI" }),
    });
  } catch {
    // Registration may fail if endpoint doesn't exist — that's OK
  }

  // Try to login
  try {
    const res = await fetch(`${BASE}/ui/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (res.ok) {
      const data = await res.json();
      return data.accessToken || data.token || null;
    }
  } catch {
    // Login may fail — run fuzzer without auth (will test 401 handling)
  }

  return null;
}

function buildRequest(endpoint, param, payload, token) {
  const headers = { "Content-Type": "application/json", Accept: "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let url = `${BASE}${endpoint.path}`;
  const opts = { method: endpoint.method, headers };

  if (param.in === "query") {
    const sep = url.includes("?") ? "&" : "?";
    url += `${sep}${encodeURIComponent(param.name)}=${encodeURIComponent(String(payload.value))}`;
  } else if (param.in === "body" && ["POST", "PUT", "PATCH"].includes(endpoint.method)) {
    const body = {};
    // Fill required params with safe defaults, inject fuzz value for target param
    for (const p of endpoint.params) {
      if (p.name === param.name) {
        body[p.name] = payload.value;
      } else {
        body[p.name] = p.format === "email" ? "safe@test.com"
          : p.format === "uuid" ? "00000000-0000-0000-0000-000000000000"
          : p.format === "uri" ? "https://example.com"
          : p.type === "integer" ? 1
          : "safe_value";
      }
    }
    opts.body = JSON.stringify(body);
  }

  return { url, opts };
}

function analyzeResponse(statusCode, body, payload) {
  // 500 with SQL/stack trace indicators = anomaly
  if (statusCode === 500) {
    const patterns = [
      { re: /sql|mysql|postgresql|sqlite/i, type: "sql_error", sev: "critical" },
      { re: /stack trace|traceback/i, type: "stack_trace", sev: "high" },
      { re: /syntax error|parse error/i, type: "syntax_error", sev: "high" },
    ];
    for (const { re, type, sev } of patterns) {
      if (re.test(body)) return { anomaly: true, type, severity: sev, detail: `500 with ${type}` };
    }
    return { anomaly: true, type: "internal_error", severity: "medium", detail: "500 error" };
  }

  // XSS reflection
  if (payload.category === "injection" && statusCode < 400) {
    const payloadStr = String(payload.value).toLowerCase();
    if (body.toLowerCase().includes(payloadStr.slice(0, 15))) {
      return { anomaly: true, type: "reflection", severity: "critical", detail: "Payload reflected in response" };
    }
  }

  return { anomaly: false };
}

async function runFuzz() {
  console.log("=== API Fuzz CI ===\n");
  console.log(`Target: ${BASE}`);

  const token = await getAuthToken();
  console.log(`Auth: ${token ? "authenticated" : "unauthenticated (testing 401 handling)"}\n`);

  const results = [];
  const anomalies = [];
  let total = 0;
  let tested = 0;

  for (const endpoint of ENDPOINTS) {
    for (const param of endpoint.params) {
      const payloads = ALL_PAYLOADS.slice(0, MAX_CASES_PER_ENDPOINT);
      total += payloads.length;

      for (const payload of payloads) {
        const { url, opts } = buildRequest(endpoint, param, payload, token);
        const start = Date.now();
        let statusCode = 0;
        let body = "";

        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), FUZZ_TIMEOUT_MS);
          const res = await fetch(url, { ...opts, signal: controller.signal });
          clearTimeout(timeout);
          statusCode = res.status;
          body = await res.text().catch(() => "");
        } catch (err) {
          body = `Error: ${err.message}`;
        }

        const elapsed = Date.now() - start;
        const analysis = analyzeResponse(statusCode, body, payload);

        const result = {
          endpoint: `${endpoint.method} ${endpoint.path}`,
          parameter: param.name,
          payload: payload.desc,
          payloadRisk: payload.risk,
          statusCode,
          responseTimeMs: elapsed,
          anomaly: analysis.anomaly,
          anomalyType: analysis.type,
          severity: analysis.severity,
          detail: analysis.detail,
        };

        results.push(result);
        tested++;

        if (analysis.anomaly) {
          anomalies.push(result);
          console.log(`  [!] ${analysis.severity?.toUpperCase()} — ${endpoint.method} ${endpoint.path} [${param.name}] ${payload.desc}: ${analysis.detail}`);
        }

        // Small delay between requests
        if (FUZZ_DELAY_MS > 0) await new Promise(r => setTimeout(r, FUZZ_DELAY_MS));
      }
    }
    console.log(`  [+] ${endpoint.method} ${endpoint.path} — done`);
  }

  // Summary
  const critical = anomalies.filter(a => a.severity === "critical").length;
  const high = anomalies.filter(a => a.severity === "high").length;
  const medium = anomalies.filter(a => a.severity === "medium").length;

  console.log(`\n=== Results ===`);
  console.log(`Total test cases: ${tested}`);
  console.log(`Anomalies: ${anomalies.length} (${critical} critical, ${high} high, ${medium} medium)`);

  // Write reports
  const fs = require("fs");

  // JSON report
  fs.writeFileSync("api-fuzz-results.json", JSON.stringify({ total: tested, anomalies, results }, null, 2));

  // Markdown report
  const lines = [
    "# API Fuzz CI Report",
    "",
    `**Target:** ${BASE}`,
    `**Date:** ${new Date().toISOString()}`,
    `**Auth:** ${token ? "Yes" : "No"}`,
    `**Test cases:** ${tested}`,
    `**Anomalies:** ${anomalies.length}`,
    "",
    "## Summary",
    "",
    `| Severity | Count |`,
    `|----------|-------|`,
    `| Critical | ${critical} |`,
    `| High     | ${high} |`,
    `| Medium   | ${medium} |`,
    "",
  ];

  if (anomalies.length > 0) {
    lines.push("## Findings", "");
    lines.push("| Endpoint | Parameter | Payload | Severity | Detail |");
    lines.push("|----------|-----------|---------|----------|--------|");
    for (const a of anomalies) {
      lines.push(`| ${a.endpoint} | ${a.parameter} | ${a.payload} | ${a.severity} | ${a.detail} |`);
    }
  }

  fs.writeFileSync("api-fuzz-report.md", lines.join("\n"));
  console.log("\nReports written: api-fuzz-results.json, api-fuzz-report.md");

  // Fail CI on critical findings
  if (critical > 0) {
    console.error(`\n::error::${critical} CRITICAL anomalies found — failing build`);
    process.exit(1);
  }

  console.log("\nNo critical findings — PASS");
}

runFuzz().catch(err => {
  console.error("Fuzz runner error:", err);
  process.exit(1);
});
