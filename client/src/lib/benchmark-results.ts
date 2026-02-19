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
