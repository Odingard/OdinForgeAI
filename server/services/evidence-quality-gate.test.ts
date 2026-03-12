import { describe, it, expect } from "vitest";
import {
  EvidenceQualityGate,
  EvidenceQuality,
  EvaluatedFinding,
} from "./evidence-quality-gate";

function makeFinding(overrides: Partial<EvaluatedFinding> = {}): EvaluatedFinding {
  return {
    id: "f-001",
    severity: "high",
    title: "Test Finding",
    description: "A test finding",
    ...overrides,
  };
}

describe("EvidenceQualityGate", () => {
  const gate = new EvidenceQualityGate();

  it("classifies real HTTP evidence with statusCode as PROVEN", () => {
    const finding = makeFinding({
      statusCode: 200,
      responseBody: "<html>admin panel</html>",
    });
    const verdict = gate.evaluate(finding);
    expect(verdict.quality).toBe(EvidenceQuality.PROVEN);
    expect(verdict.passed).toBe(true);
    expect(verdict.requiresManualReview).toBe(false);
  });

  it("classifies real protocol auth success as PROVEN", () => {
    const finding = makeFinding({
      evidenceType: "real_smb_auth",
      success: true,
    });
    const verdict = gate.evaluate(finding);
    expect(verdict.quality).toBe(EvidenceQuality.PROVEN);
    expect(verdict.passed).toBe(true);
  });

  it("classifies real attempt failure as CORROBORATED", () => {
    const finding = makeFinding({
      evidenceType: "real_smb_auth",
      success: false,
      error: { code: "ACCESS_DENIED" },
    });
    const verdict = gate.evaluate(finding);
    expect(verdict.quality).toBe(EvidenceQuality.CORROBORATED);
    expect(verdict.passed).toBe(true);
  });

  it("classifies active exploit engine source as CORROBORATED", () => {
    const finding = makeFinding({
      source: "active_exploit_engine",
    });
    const verdict = gate.evaluate(finding);
    expect(verdict.quality).toBe(EvidenceQuality.CORROBORATED);
    expect(verdict.passed).toBe(true);
  });

  it("classifies LLM inference source as INFERRED", () => {
    const finding = makeFinding({
      source: "llm_inference_xyz",
    });
    const verdict = gate.evaluate(finding);
    expect(verdict.quality).toBe(EvidenceQuality.INFERRED);
    expect(verdict.passed).toBe(false);
    expect(verdict.requiresManualReview).toBe(true);
  });

  it("classifies title containing [LLM Inferred] as INFERRED", () => {
    const finding = makeFinding({
      title: "Possible XSS [LLM Inferred]",
    });
    const verdict = gate.evaluate(finding);
    expect(verdict.quality).toBe(EvidenceQuality.INFERRED);
    expect(verdict.passed).toBe(false);
  });

  it("classifies heuristic source as INFERRED", () => {
    const finding = makeFinding({
      source: "heuristic_pattern_match",
    });
    const verdict = gate.evaluate(finding);
    expect(verdict.quality).toBe(EvidenceQuality.INFERRED);
    expect(verdict.passed).toBe(false);
  });

  it("classifies finding with no evidence fields as UNVERIFIABLE", () => {
    const finding = makeFinding();
    const verdict = gate.evaluate(finding);
    expect(verdict.quality).toBe(EvidenceQuality.UNVERIFIABLE);
    expect(verdict.passed).toBe(false);
    expect(verdict.requiresManualReview).toBe(true);
  });

  it("evaluates a batch with correct summary counts and pass/fail split", () => {
    const findings: EvaluatedFinding[] = [
      makeFinding({ id: "f-1", statusCode: 200, responseBody: "ok" }),        // PROVEN
      makeFinding({ id: "f-2", source: "active_exploit_engine" }),             // CORROBORATED
      makeFinding({ id: "f-3", source: "llm_inference_v2" }),                  // INFERRED
      makeFinding({ id: "f-4" }),                                              // UNVERIFIABLE
    ];

    const batch = gate.evaluateBatch(findings);

    expect(batch.summary.proven).toBe(1);
    expect(batch.summary.corroborated).toBe(1);
    expect(batch.summary.inferred).toBe(1);
    expect(batch.summary.unverifiable).toBe(1);
    expect(batch.summary.total).toBe(4);
    expect(batch.summary.passRate).toBe(50);
    expect(batch.passed).toHaveLength(2);
    expect(batch.failed).toHaveLength(2);
  });

  it("evaluates an empty batch with zero counts and 0 passRate", () => {
    const batch = gate.evaluateBatch([]);
    expect(batch.summary.total).toBe(0);
    expect(batch.summary.passRate).toBe(0);
    expect(batch.summary.proven).toBe(0);
    expect(batch.summary.corroborated).toBe(0);
    expect(batch.summary.inferred).toBe(0);
    expect(batch.summary.unverifiable).toBe(0);
    expect(batch.passed).toHaveLength(0);
    expect(batch.failed).toHaveLength(0);
  });
});
