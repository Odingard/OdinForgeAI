import { describe, it, expect } from "vitest";
import { generateSarifReport } from "./sarif-exporter";

function makeEvaluation(overrides: Record<string, any> = {}) {
  return {
    id: "eval-1",
    organizationId: "org-1",
    exposureType: "cve",
    targetUrl: "http://example.com",
    status: "completed",
    createdAt: new Date("2025-01-01"),
    ...overrides,
  } as any;
}

function makeResult(overrides: Record<string, any> = {}) {
  return {
    evaluationId: "eval-1",
    exploitable: true,
    confidence: 85,
    severity: "high",
    completedAt: new Date("2025-01-01"),
    attackPath: [],
    ...overrides,
  } as any;
}

describe("generateSarifReport", () => {
  it("returns valid SARIF 2.1.0 schema and version", () => {
    const sarif = generateSarifReport([makeEvaluation()], [makeResult()], "org-1");
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-schema-2.1.0");
    expect(sarif.runs).toHaveLength(1);
  });

  it("maps evaluations to SARIF rules and results", () => {
    const sarif = generateSarifReport([makeEvaluation()], [makeResult()], "org-1");
    const run = sarif.runs[0];
    expect(run.tool.driver.rules.length).toBeGreaterThanOrEqual(1);
    expect(run.results.length).toBe(1);
  });

  it("empty input produces valid SARIF with 0 results", () => {
    const sarif = generateSarifReport([], [], "org-1");
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
  });

  it("tool driver has correct name", () => {
    const sarif = generateSarifReport([makeEvaluation()], [makeResult()], "org-1");
    expect(sarif.runs[0].tool.driver.name).toBe("OdinForge AEV");
  });

  it("includes invocation with organizationId", () => {
    const sarif = generateSarifReport([makeEvaluation()], [makeResult()], "org-test");
    const inv = sarif.runs[0].invocations[0];
    expect(inv.executionSuccessful).toBe(true);
    expect(inv.properties.organizationId).toBe("org-test");
  });
});
