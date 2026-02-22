// ─── XBOW Benchmark Types ─────────────────────────────────────────────

export interface XBOWBenchmarkSummary {
  solveRate: string;            // e.g. "0/10"
  vulnDetectionRate: string;    // e.g. "6/10 (60%)"
  percentage: string;           // e.g. "0%"
  mode: "black-box";
  shannonRate: string;          // "96.15%"
  shannonMode: "white-box";
  xbowRate: string;             // "85%"
  xbowMode: "black-box";
  challengesRun: number;
  challengesTotal: number;
  byCategory: Record<string, { solved: number; total: number; rate: string }>;
  runDate: string;
  status: "preliminary" | "complete";
  note: string;
}

export const XBOW_BENCHMARK: XBOWBenchmarkSummary = {
  solveRate: "0/10",
  vulnDetectionRate: "6/10 (60%)",
  percentage: "0%",
  mode: "black-box",
  shannonRate: "96.15%",
  shannonMode: "white-box",
  xbowRate: "85%",
  xbowMode: "black-box",
  challengesRun: 10,
  challengesTotal: 104,
  byCategory: {},
  runDate: "2026-02-21",
  status: "preliminary",
  note: "Agent detected vulnerabilities in 60% of challenges but could not extract flags. Flag extraction requires deeper exploitation beyond initial detection. Full 104-challenge nightly run pending.",
};

// ─── Breach Chain Benchmark Types ─────────────────────────────────────

export interface BreachChainScenarioResult {
  id: string;
  name: string;
  playbookId: string;
  status: "completed" | "partial" | "aborted" | "failed";
  stepsExecuted: number;
  stepsSucceeded: number;
  compositeScore: number;
  confidence: number;
  durationMs: number;
}

export interface BreachChainBenchmarkSummary {
  avgCompositeScore: number;
  scenariosRun: number;
  scenariosSucceeded: number;
  avgChainDepth: number;
  avgConfidence: number;
  runDate: string;
  status: "pending" | "complete";
  scenarios: BreachChainScenarioResult[];
  competitorCapability: {
    capability: string;
    odinforge: "yes" | "partial" | "no";
    shannon: "yes" | "partial" | "no";
    xbow: "yes" | "partial" | "no";
  }[];
}

export const BREACH_CHAIN_BENCHMARK: BreachChainBenchmarkSummary = {
  avgCompositeScore: 37,
  scenariosRun: 9,
  scenariosSucceeded: 4,
  avgChainDepth: 1,
  avgConfidence: 45,
  runDate: "2026-02-21",
  status: "complete",
  scenarios: [
    // Juice Shop (4 scenarios, 2 succeeded)
    { id: "js-sqli-chain", name: "SQLi to Data Exfiltration", playbookId: "sqli-exfil-chain", status: "partial", stepsExecuted: 1, stepsSucceeded: 1, compositeScore: 58, confidence: 60, durationMs: 2018 },
    { id: "js-auth-chain", name: "Auth Bypass to Privilege Escalation", playbookId: "auth-bypass-escalation", status: "aborted", stepsExecuted: 2, stepsSucceeded: 1, compositeScore: 44, confidence: 70, durationMs: 1958 },
    { id: "js-path-chain", name: "Path Traversal File Read Proof", playbookId: "path-traversal-proof", status: "partial", stepsExecuted: 2, stepsSucceeded: 1, compositeScore: 45, confidence: 75, durationMs: 2305 },
    { id: "js-multi-vector", name: "Multi-Vector Attack Chain", playbookId: "multi-vector-chain", status: "aborted", stepsExecuted: 2, stepsSucceeded: 1, compositeScore: 41, confidence: 60, durationMs: 1200 },
    // DVWA (3 scenarios, 2 succeeded)
    { id: "dvwa-cmdi-chain", name: "Command Injection to RCE", playbookId: "cmd-injection-rce", status: "partial", stepsExecuted: 2, stepsSucceeded: 2, compositeScore: 77, confidence: 73, durationMs: 1143 },
    { id: "dvwa-sqli-chain", name: "SQLi to Data Exfiltration", playbookId: "sqli-exfil-chain", status: "partial", stepsExecuted: 1, stepsSucceeded: 1, compositeScore: 58, confidence: 60, durationMs: 327 },
    { id: "dvwa-ssrf-chain", name: "SSRF Internal Pivot", playbookId: "ssrf-internal-pivot", status: "aborted", stepsExecuted: 2, stepsSucceeded: 1, compositeScore: 45, confidence: 75, durationMs: 1853 },
    // WebGoat (2 scenarios, 0 succeeded)
    { id: "wg-sqli-chain", name: "SQLi to Data Exfiltration", playbookId: "sqli-exfil-chain", status: "aborted", stepsExecuted: 1, stepsSucceeded: 0, compositeScore: 5, confidence: 0, durationMs: 1434 },
    { id: "wg-auth-chain", name: "Auth Bypass to Privilege Escalation", playbookId: "auth-bypass-escalation", status: "aborted", stepsExecuted: 1, stepsSucceeded: 0, compositeScore: 5, confidence: 0, durationMs: 505 },
  ],
  competitorCapability: [
    { capability: "Multi-step exploit chains",    odinforge: "yes",     shannon: "partial", xbow: "no" },
    { capability: "Confidence-gated progression",  odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "Cross-vuln chaining",           odinforge: "yes",     shannon: "partial", xbow: "no" },
    { capability: "Credential extraction chains",  odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "Cloud IAM escalation",          odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "K8s/Container breakout",        odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "Lateral movement simulation",   odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "EPSS/CVSS/KEV scoring",         odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "Real-time visualization",       odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "CI benchmark regression",       odinforge: "yes",     shannon: "partial", xbow: "partial" },
  ],
};

// ─── Exploit Agent Benchmark Types ────────────────────────────────────

export interface BenchmarkScenario {
  id: string;
  name: string;
  status: "pass" | "fail";
  vulnTypesFound: string[];
  expectedVulnTypes: string[];
  matchedVulnTypes: string[];
  missedVulnTypes: string[];
  chainsFound: number;
  validatedChains: number;
  toolCalls: number;
  timeMs: number;
}

export interface BenchmarkRun {
  target: string;
  targetVersion: string;
  runDate: string;
  executionMode: string;
  scenarios: BenchmarkScenario[];
  summary: {
    passed: number;
    total: number;
    passRate: string;
    detectionRate: string;
    totalMatched: number;
    totalExpected: number;
    totalChains: number;
    validatedChains: number;
    totalToolCalls: number;
    totalTimeMs: number;
    avgTimePerScenario: number;
  };
  environment: {
    modelRouter: string;
    maxTurns: number;
    executionMode: string;
    agentTools: string[];
  };
}

export const BENCHMARK_RUNS: BenchmarkRun[] = [
  {
    target: "OWASP Juice Shop",
    targetVersion: "v17.1.1",
    runDate: "2026-02-18",
    executionMode: "simulation",
    scenarios: [
      {
        id: "js-search-sqli",
        name: "Search Parameter SQL Injection",
        status: "pass",
        vulnTypesFound: ["SQL Injection", "Cross-Site Scripting (XSS)", "Authentication Bypass", "Security Misconfiguration"],
        expectedVulnTypes: ["sqli"],
        matchedVulnTypes: ["sqli"],
        missedVulnTypes: [],
        chainsFound: 1,
        validatedChains: 1,
        toolCalls: 5,
        timeMs: 27639,
      },
      {
        id: "js-login-auth",
        name: "Login Authentication Bypass",
        status: "pass",
        vulnTypesFound: ["SQL Injection", "Cross-Site Scripting (XSS)", "Authentication Bypass", "Security Misconfiguration"],
        expectedVulnTypes: ["sqli", "auth_bypass"],
        matchedVulnTypes: ["sqli", "auth_bypass"],
        missedVulnTypes: [],
        chainsFound: 2,
        validatedChains: 0,
        toolCalls: 4,
        timeMs: 22220,
      },
      {
        id: "js-api-surface",
        name: "API Attack Surface Analysis",
        status: "pass",
        vulnTypesFound: ["SQL Injection", "Cross-Site Scripting (XSS)", "Authentication Bypass", "Security Misconfiguration"],
        expectedVulnTypes: ["sqli", "xss", "auth_bypass", "path_traversal", "misconfiguration"],
        matchedVulnTypes: ["sqli", "xss", "auth_bypass", "misconfiguration"],
        missedVulnTypes: ["path_traversal"],
        chainsFound: 1,
        validatedChains: 1,
        toolCalls: 5,
        timeMs: 17202,
      },
      {
        id: "js-xss-feedback",
        name: "Stored XSS via Feedback",
        status: "pass",
        vulnTypesFound: ["Cross-Site Scripting (XSS)", "Security Misconfiguration"],
        expectedVulnTypes: ["xss"],
        matchedVulnTypes: ["xss"],
        missedVulnTypes: [],
        chainsFound: 0,
        validatedChains: 0,
        toolCalls: 3,
        timeMs: 15566,
      },
      {
        id: "js-file-traversal",
        name: "Path Traversal & File Access",
        status: "pass",
        vulnTypesFound: ["Authentication Bypass", "Path Traversal"],
        expectedVulnTypes: ["path_traversal"],
        matchedVulnTypes: ["path_traversal"],
        missedVulnTypes: [],
        chainsFound: 1,
        validatedChains: 0,
        toolCalls: 2,
        timeMs: 11877,
      },
    ],
    summary: {
      passed: 5,
      total: 5,
      passRate: "5/5",
      detectionRate: "90%",
      totalMatched: 9,
      totalExpected: 10,
      totalChains: 5,
      validatedChains: 2,
      totalToolCalls: 19,
      totalTimeMs: 94504,
      avgTimePerScenario: 18901,
    },
    environment: {
      modelRouter: "GPT-4o (single)",
      maxTurns: 12,
      executionMode: "simulation",
      agentTools: [
        "validate_vulnerability",
        "fuzz_endpoint",
        "http_fingerprint",
        "port_scan",
        "check_ssl_tls",
        "run_protocol_probe",
      ],
    },
  },
];
