/**
 * AEV Breach Chain Benchmark Scenarios
 *
 * Maps existing playbooks from server/services/aev/playbooks/ to
 * benchmark targets. Each scenario tests a multi-step attack chain.
 */

import type { BreachChainScenario } from "./breach-chain-types";

// ─── Juice Shop Scenarios ─────────────────────────────────────────────

const juiceShopScenarios: BreachChainScenario[] = [
  {
    id: "js-sqli-chain",
    name: "SQLi to Data Exfiltration",
    target: "juice-shop",
    playbookId: "sqli-exfil-chain",
    targetEndpoint: "/rest/products/search?q=test",
    parameters: {},
    expectedOutcome: {
      minStepsCompleted: 2,
      minConfidence: 40,
      shouldDetectVuln: true,
    },
  },
  {
    id: "js-auth-chain",
    name: "Auth Bypass to Privilege Escalation",
    target: "juice-shop",
    playbookId: "auth-bypass-escalation",
    targetEndpoint: "/rest/user/login",
    parameters: {},
    expectedOutcome: {
      minStepsCompleted: 1,
      minConfidence: 40,
      shouldDetectVuln: true,
    },
  },
  {
    id: "js-path-chain",
    name: "Path Traversal File Read Proof",
    target: "juice-shop",
    playbookId: "path-traversal-proof",
    targetEndpoint: "/ftp/eastere.gg%2500.md",
    parameters: {
      parameter: "file",
      parameterLocation: "path",
    },
    expectedOutcome: {
      minStepsCompleted: 1,
      minConfidence: 30,
      shouldDetectVuln: true,
    },
  },
  {
    id: "js-multi-vector",
    name: "Multi-Vector Attack Chain",
    target: "juice-shop",
    playbookId: "multi-vector-chain",
    targetEndpoint: "/rest/products/search?q=test",
    parameters: {},
    expectedOutcome: {
      minStepsCompleted: 2,
      minConfidence: 30,
      shouldDetectVuln: true,
    },
  },
];

// ─── DVWA Scenarios ───────────────────────────────────────────────────

const dvwaScenarios: BreachChainScenario[] = [
  {
    id: "dvwa-cmdi-chain",
    name: "Command Injection to RCE",
    target: "dvwa",
    playbookId: "cmd-injection-rce",
    targetEndpoint: "/vulnerabilities/exec/",
    parameters: {},
    expectedOutcome: {
      minStepsCompleted: 1,
      minConfidence: 40,
      shouldDetectVuln: true,
    },
  },
  {
    id: "dvwa-sqli-chain",
    name: "SQLi to Data Exfiltration",
    target: "dvwa",
    playbookId: "sqli-exfil-chain",
    targetEndpoint: "/vulnerabilities/sqli/",
    parameters: {},
    expectedOutcome: {
      minStepsCompleted: 2,
      minConfidence: 50,
      shouldDetectVuln: true,
    },
  },
  {
    id: "dvwa-ssrf-chain",
    name: "SSRF Internal Pivot",
    target: "dvwa",
    playbookId: "ssrf-internal-pivot",
    targetEndpoint: "/vulnerabilities/fi/",
    parameters: {},
    expectedOutcome: {
      minStepsCompleted: 1,
      minConfidence: 30,
      shouldDetectVuln: true,
    },
  },
];

// ─── WebGoat Scenarios ────────────────────────────────────────────────

const webgoatScenarios: BreachChainScenario[] = [
  {
    id: "wg-sqli-chain",
    name: "SQLi to Data Exfiltration",
    target: "webgoat",
    playbookId: "sqli-exfil-chain",
    targetEndpoint: "/WebGoat/SqlInjection/attack",
    parameters: {},
    expectedOutcome: {
      minStepsCompleted: 1,
      minConfidence: 40,
      shouldDetectVuln: true,
    },
  },
  {
    id: "wg-auth-chain",
    name: "Auth Bypass to Privilege Escalation",
    target: "webgoat",
    playbookId: "auth-bypass-escalation",
    targetEndpoint: "/WebGoat/JWT/",
    parameters: {},
    expectedOutcome: {
      minStepsCompleted: 1,
      minConfidence: 30,
      shouldDetectVuln: true,
    },
  },
];

// ─── BrokenCrystals Scenarios ────────────────────────────────────────

const brokenCrystalsScenarios: BreachChainScenario[] = [
  {
    id: "bc-cmdi-chain",
    name: "Command Injection to RCE via Spawn",
    target: "broken-crystals",
    playbookId: "cmd-injection-rce",
    targetEndpoint: "/api/spawn",
    parameters: {
      parameter: "command",
      parameterLocation: "url_param",
      method: "GET",
      injectionPayload: "id",
    },
    expectedOutcome: {
      minStepsCompleted: 1,
      minConfidence: 40,
      shouldDetectVuln: true,
    },
  },
  {
    id: "bc-ssrf-chain",
    name: "SSRF to Internal Network Pivot via File Endpoint",
    target: "broken-crystals",
    playbookId: "ssrf-internal-pivot",
    targetEndpoint: "/api/file",
    parameters: {
      parameter: "path",
      parameterLocation: "url_param",
      method: "GET",
      value: "http://example.com",
    },
    expectedOutcome: {
      minStepsCompleted: 1,
      minConfidence: 30,
      shouldDetectVuln: true,
    },
  },
  {
    id: "bc-auth-chain",
    name: "JWT Bypass to Privilege Escalation",
    target: "broken-crystals",
    playbookId: "auth-bypass-escalation",
    targetEndpoint: "/api/auth/login",
    parameters: {
      parameter: "user",
      parameterLocation: "body_param",
      method: "POST",
      analyzeJwt: true,
    },
    expectedOutcome: {
      minStepsCompleted: 1,
      minConfidence: 30,
      shouldDetectVuln: true,
    },
  },
  {
    id: "bc-path-chain",
    name: "Path Traversal File Read via LFI",
    target: "broken-crystals",
    playbookId: "path-traversal-proof",
    targetEndpoint: "/api/file",
    parameters: {
      parameter: "path",
      parameterLocation: "url_param",
      method: "GET",
      value: "test.txt",
    },
    expectedOutcome: {
      minStepsCompleted: 1,
      minConfidence: 30,
      shouldDetectVuln: true,
    },
  },
  {
    id: "bc-multi-vector",
    name: "Multi-Vector Attack Chain (SSTI + CMDi + SSRF)",
    target: "broken-crystals",
    playbookId: "multi-vector-chain",
    targetEndpoint: "/api/testimonials/count",
    parameters: {
      parameter: "query",
      parameterLocation: "url_param",
      method: "GET",
    },
    expectedOutcome: {
      minStepsCompleted: 2,
      minConfidence: 30,
      shouldDetectVuln: true,
    },
  },
];

// ─── Registry ─────────────────────────────────────────────────────────

const allScenarios: BreachChainScenario[] = [
  ...juiceShopScenarios,
  ...dvwaScenarios,
  ...webgoatScenarios,
  ...brokenCrystalsScenarios,
];

export function getScenariosForTarget(target: string): BreachChainScenario[] {
  return allScenarios.filter((s) => s.target === target);
}

export function getScenarioById(id: string): BreachChainScenario | undefined {
  return allScenarios.find((s) => s.id === id);
}

export function getAllScenarios(): BreachChainScenario[] {
  return allScenarios;
}
