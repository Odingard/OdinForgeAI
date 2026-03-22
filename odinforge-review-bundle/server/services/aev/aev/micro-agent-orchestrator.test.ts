import { describe, it, expect } from "vitest";
import {
  MicroAgentOrchestrator,
  mergeMicroResults,
  type MicroAgentResult,
  type MicroAgentFinding,
} from "./micro-agent-orchestrator";
import type { DiscoveredEndpoint, ExposureType } from "../active-exploit-engine";
import { makeRealHttpEvidence } from "../../lib/real-evidence";

function makeEndpoint(overrides: Partial<DiscoveredEndpoint> = {}): DiscoveredEndpoint {
  return {
    url: "https://example.com/api/users",
    method: "POST",
    parameters: [
      { name: "id", location: "query", type: "string", required: false },
    ],
    headers: {},
    authenticated: false,
    ...overrides,
  };
}

function makeFinding(overrides: Partial<MicroAgentFinding> = {}): MicroAgentFinding {
  return {
    id: "f-1",
    title: "SQLI confirmed @ https://example.com/api/users",
    description: "Test finding",
    severity: "critical",
    technique: "sqli",
    mitreId: "T1190",
    cwe: "CWE-89",
    evidenceType: "real_http_response",
    source: "active_exploit_engine",
    statusCode: 200,
    responseBody: "SQL error",
    success: true,
    confidence: 80,
    endpoint: "https://example.com/api/users",
    parameter: "id",
    payload: "' OR 1=1--",
    reproductionCurl: "curl ...",
    ...overrides,
  };
}

describe("MicroAgentOrchestrator", () => {
  const orchestrator = new MicroAgentOrchestrator({ maxConcurrent: 5 });

  describe("buildAgentSpecs", () => {
    it("creates specs for each applicable endpoint × vulnClass", () => {
      const endpoints = [
        makeEndpoint({ url: "https://example.com/api/users" }),
        makeEndpoint({ url: "https://example.com/api/items" }),
      ];
      const scope: ExposureType[] = ["sqli", "xss"];
      const specs = orchestrator.buildAgentSpecs(endpoints, scope, "chain-1", "https://example.com");

      expect(specs.length).toBe(4); // 2 endpoints × 2 vulnClasses
      expect(specs[0].vulnClass).toBe("sqli");
      expect(specs[0].endpoint.url).toBe("https://example.com/api/users");
    });

    it("filters out static file endpoints", () => {
      const endpoints = [
        makeEndpoint({ url: "https://example.com/styles.css" }),
        makeEndpoint({ url: "https://example.com/logo.png" }),
        makeEndpoint({ url: "https://example.com/api/data" }),
      ];
      const specs = orchestrator.buildAgentSpecs(endpoints, ["sqli"], "chain-1", "https://example.com");
      expect(specs.length).toBe(1); // only /api/data
    });

    it("skips auth_bypass on unauthenticated endpoints", () => {
      const endpoints = [
        makeEndpoint({ authenticated: false }),
      ];
      const specs = orchestrator.buildAgentSpecs(endpoints, ["auth_bypass"], "chain-1", "https://example.com");
      expect(specs.length).toBe(0);
    });

    it("includes auth_bypass on authenticated endpoints", () => {
      const endpoints = [
        makeEndpoint({ authenticated: true }),
      ];
      const specs = orchestrator.buildAgentSpecs(endpoints, ["auth_bypass"], "chain-1", "https://example.com");
      expect(specs.length).toBe(1);
    });

    it("skips sqli on endpoints with no parameters", () => {
      const endpoints = [
        makeEndpoint({ parameters: [] }),
      ];
      const specs = orchestrator.buildAgentSpecs(endpoints, ["sqli"], "chain-1", "https://example.com");
      expect(specs.length).toBe(0);
    });
  });
});

describe("mergeMicroResults", () => {
  it("merges findings from results with evidence", () => {
    const evidence = makeRealHttpEvidence({
      requestPayload: "' OR 1=1--",
      targetUrl: "https://example.com/api/users",
      method: "POST",
      statusCode: 200,
      rawResponseBody: "SQL syntax error",
      durationMs: 100,
    });

    const results: MicroAgentResult[] = [
      {
        spec: { endpoint: makeEndpoint(), vulnClass: "sqli", depth: 0, chainId: "c1", targetUrl: "https://example.com" },
        agentId: "micro-sqli-abc",
        durationMs: 100,
        evidence: [evidence],
        finding: makeFinding(),
        credentials: [],
      },
    ];

    const merged = mergeMicroResults(results);
    expect(merged.findings).toHaveLength(1);
    expect(merged.agentDispatchSummary.totalFindings).toBe(1);
    expect(merged.agentDispatchSummary.discardedFindings).toBe(0);
  });

  it("DISCARDS finding with no evidence (LLM Boundary hard gate)", () => {
    const results: MicroAgentResult[] = [
      {
        spec: { endpoint: makeEndpoint(), vulnClass: "sqli", depth: 0, chainId: "c1", targetUrl: "https://example.com" },
        agentId: "micro-sqli-abc",
        durationMs: 100,
        evidence: [], // NO evidence — finding must be discarded
        finding: makeFinding({ title: "Fabricated finding" }),
        credentials: [],
      },
    ];

    const merged = mergeMicroResults(results);
    expect(merged.findings).toHaveLength(0);
    expect(merged.agentDispatchSummary.discardedFindings).toBe(1);
  });

  it("passes through credentials regardless of findings", () => {
    const results: MicroAgentResult[] = [
      {
        spec: { endpoint: makeEndpoint(), vulnClass: "sqli", depth: 0, chainId: "c1", targetUrl: "https://example.com" },
        agentId: "micro-sqli-abc",
        durationMs: 100,
        evidence: [],
        finding: null,
        credentials: [{ type: "api_key", value: "sk-test-key", context: "response body" }],
      },
    ];

    const merged = mergeMicroResults(results);
    expect(merged.credentials).toHaveLength(1);
  });

  it("aggregates summary stats correctly", () => {
    const evidence = makeRealHttpEvidence({
      requestPayload: "test",
      targetUrl: "https://example.com",
      method: "GET",
      statusCode: 200,
      rawResponseBody: "ok",
      durationMs: 50,
    });

    const results: MicroAgentResult[] = [
      { spec: { endpoint: makeEndpoint(), vulnClass: "sqli", depth: 0, chainId: "c1", targetUrl: "x" }, agentId: "a1", durationMs: 100, evidence: [evidence], finding: makeFinding(), credentials: [] },
      { spec: { endpoint: makeEndpoint(), vulnClass: "xss", depth: 0, chainId: "c1", targetUrl: "x" }, agentId: "a2", durationMs: 200, evidence: [], finding: null, credentials: [] },
      { spec: { endpoint: makeEndpoint(), vulnClass: "ssrf", depth: 0, chainId: "c1", targetUrl: "x" }, agentId: "a3", durationMs: 150, evidence: [], finding: makeFinding({ title: "bad" }), credentials: [] },
    ];

    const merged = mergeMicroResults(results);
    expect(merged.agentDispatchSummary.totalAgents).toBe(3);
    expect(merged.agentDispatchSummary.totalFindings).toBe(1);
    expect(merged.agentDispatchSummary.discardedFindings).toBe(1);
    expect(merged.agentDispatchSummary.totalEvidence).toBe(1);
  });
});
