/**
 * Report V2 End-to-End Tests
 * 
 * Tests the complete V2 report generation flow including:
 * - Feature flag behavior (enabled/disabled)
 * - Anti-template linting
 * - Fixture validation
 * - Mock data factory
 * 
 * Run with: npx tsx server/src/reportsV2/tests/reportV2.e2e.test.ts
 */

import { isFeatureEnabled, setTenantFeatureOverride, removeTenantFeatureOverride } from "../../../feature-flags";
import { lintReportSection } from "../antiTemplateLint";
import {
  iamAbuseFixture,
  paymentBypassFixture,
  multiVectorFixture,
  complianceGapFixture,
} from "./fixtures";
import {
  createTestEvaluation,
  createTestResult,
  createRichEvaluation,
  createEvaluationBatch,
  createAttackPath,
  createRecommendations,
  createEvidenceArtifacts,
} from "./mock-data-factory";

interface TestResult {
  name: string;
  passed: boolean;
  error?: string;
}

const results: TestResult[] = [];

function test(name: string, fn: () => void | Promise<void>): void {
  try {
    const result = fn();
    if (result instanceof Promise) {
      result.then(() => {
        results.push({ name, passed: true });
      }).catch((e: Error) => {
        results.push({ name, passed: false, error: e.message });
      });
    } else {
      results.push({ name, passed: true });
    }
  } catch (e: any) {
    results.push({ name, passed: false, error: e.message });
  }
}

function expect(value: any) {
  return {
    toBe(expected: any) {
      if (value !== expected) {
        throw new Error(`Expected ${JSON.stringify(expected)}, got ${JSON.stringify(value)}`);
      }
    },
    toEqual(expected: any) {
      if (JSON.stringify(value) !== JSON.stringify(expected)) {
        throw new Error(`Expected ${JSON.stringify(expected)}, got ${JSON.stringify(value)}`);
      }
    },
    toBeDefined() {
      if (value === undefined) {
        throw new Error(`Expected value to be defined, got undefined`);
      }
    },
    toBeGreaterThan(expected: number) {
      if (!(value > expected)) {
        throw new Error(`Expected ${value} to be greater than ${expected}`);
      }
    },
    toHaveLength(expected: number) {
      if (value?.length !== expected) {
        throw new Error(`Expected length ${expected}, got ${value?.length}`);
      }
    },
    toContain(expected: any) {
      if (!value?.includes?.(expected)) {
        throw new Error(`Expected array to contain ${expected}`);
      }
    },
  };
}

// Feature Flag Tests
console.log("\n=== Feature Flag Behavior Tests ===\n");

test("should return feature enabled when set via tenant override", () => {
  // Set override and test
  setTenantFeatureOverride("test-org-v2-enabled", "REPORTS_V2_NARRATIVE", true);
  const enabled = isFeatureEnabled("REPORTS_V2_NARRATIVE", "test-org-v2-enabled");
  // Clean up
  removeTenantFeatureOverride("test-org-v2-enabled", "REPORTS_V2_NARRATIVE");
  expect(enabled).toBe(true);
});

test("should return feature disabled by default for unknown org", () => {
  expect(isFeatureEnabled("REPORTS_V2_NARRATIVE", "unknown-org-never-set")).toBe(false);
});

test("should respect tenant override removal", () => {
  setTenantFeatureOverride("test-org-temp", "REPORTS_V2_NARRATIVE", true);
  expect(isFeatureEnabled("REPORTS_V2_NARRATIVE", "test-org-temp")).toBe(true);
  removeTenantFeatureOverride("test-org-temp", "REPORTS_V2_NARRATIVE");
  expect(isFeatureEnabled("REPORTS_V2_NARRATIVE", "test-org-temp")).toBe(false);
});

// Anti-Template Linting Tests
console.log("\n=== Anti-Template Linting Tests ===\n");

test("should pass valid narrative text with lintReportSection", () => {
  const validNarrative = `During our assessment of the payment processing infrastructure, 
    we discovered a critical SQL injection vulnerability in the customer search endpoint. 
    This finding represents a significant risk to the organization's data integrity 
    and customer privacy. The vulnerability allows an authenticated attacker to extract 
    sensitive cardholder data from the database without proper authorization controls.`;

  const result = lintReportSection(validNarrative, "Executive Summary");
  expect(result.passed).toBe(true);
  expect(result.score).toBeGreaterThan(80);
});

test("should flag templated phrases in report sections", () => {
  const templatedText = `This section provides an overview of our findings. 
    It is recommended that the organization should consider implementing best practices.
    Based on our assessment, industry standards recommend a holistic approach.`;

  const result = lintReportSection(templatedText, "Summary");
  expect(result.warnings.length).toBeGreaterThan(0);
  expect(result.score).toBeGreaterThan(0); // Should still have a score
});

test("should flag narratives that are too short", () => {
  const shortText = "Critical vulnerability found.";
  const result = lintReportSection(shortText, "Executive Summary");
  expect(result.passed).toBe(false);
  expect(result.errors.length).toBeGreaterThan(0);
});

test("should pass long narrative content", () => {
  const longContent = `During our comprehensive security assessment of the organization's 
    cloud infrastructure, our team identified several critical vulnerabilities that pose 
    immediate risk to business operations and customer data. The assessment covered web 
    applications, API endpoints, cloud configurations, and network segmentation controls. 
    Our findings indicate significant gaps in the security posture that require urgent 
    remediation efforts. The most concerning discovery was a SQL injection vulnerability 
    in the customer portal that could allow unauthorized access to sensitive data.`;

  const result = lintReportSection(longContent, "Technical Summary");
  expect(result.passed).toBe(true);
});

// Fixture Validation Tests
console.log("\n=== Fixture Validation Tests ===\n");

test("should have valid IAM abuse fixture", () => {
  expect(iamAbuseFixture.evaluation.id).toBeDefined();
  expect(iamAbuseFixture.result.attackPath).toBeDefined();
  expect(iamAbuseFixture.result.attackPath!.length).toBeGreaterThan(0);
  expect(iamAbuseFixture.expectedNarrativeElements).toContain("privilege escalation");
});

test("should have valid payment bypass fixture", () => {
  expect(paymentBypassFixture.evaluation.exposureType).toBe("business_logic_flaw");
  expect(paymentBypassFixture.result.recommendations).toBeDefined();
  expect(paymentBypassFixture.result.recommendations!.length).toBeGreaterThan(0);
  expect(paymentBypassFixture.expectedNarrativeElements).toContain("payment bypass");
});

test("should have valid multi-vector fixture with chain", () => {
  expect(multiVectorFixture.result.attackPath!.length).toBeGreaterThan(3);
  expect(multiVectorFixture.expectedNarrativeElements).toContain("SQL injection");
  expect(multiVectorFixture.expectedNarrativeElements).toContain("lateral movement");
});

test("should have valid compliance gap fixture with framework references", () => {
  expect(complianceGapFixture.complianceFrameworks).toContain("PCI-DSS 4.0");
  expect(complianceGapFixture.affectedRequirements).toContain("3.4");
  expect(complianceGapFixture.expectedNarrativeElements).toContain("PCI-DSS");
});

test("should have consistent evaluation-result linking in fixtures", () => {
  expect(iamAbuseFixture.result.evaluationId).toBe(iamAbuseFixture.evaluation.id);
  expect(paymentBypassFixture.result.evaluationId).toBe(paymentBypassFixture.evaluation.id);
  expect(multiVectorFixture.result.evaluationId).toBe(multiVectorFixture.evaluation.id);
  expect(complianceGapFixture.result.evaluationId).toBe(complianceGapFixture.evaluation.id);
});

// Mock Data Factory Tests
console.log("\n=== Mock Data Factory Tests ===\n");

test("should create valid test evaluations", () => {
  const evaluation = createTestEvaluation();
  
  expect(evaluation.id).toBeDefined();
  expect(evaluation.assetId).toBeDefined();
  expect(evaluation.status).toBe("completed");
});

test("should allow overriding evaluation fields", () => {
  const evaluation = createTestEvaluation({
    priority: "critical",
    exposureType: "rce",
  });

  expect(evaluation.priority).toBe("critical");
  expect(evaluation.exposureType).toBe("rce");
});

test("should create matching result for evaluation", () => {
  const evaluation = createTestEvaluation();
  const result = createTestResult(evaluation.id);

  expect(result.evaluationId).toBe(evaluation.id);
  expect(result.exploitable).toBe(true);
  expect(result.attackPath).toBeDefined();
});

test("should create rich evaluation with complete data", () => {
  const { evaluation, result } = createRichEvaluation("sql_injection");

  expect(result.attackPath!.length).toBe(5);
  expect(result.recommendations!.length).toBe(5);
  expect(result.evidenceArtifacts!.length).toBe(4);
  expect(result.confidence).toBe(95);
});

test("should create batch of evaluations for date range testing", () => {
  const { evaluations, results } = createEvaluationBatch(10);

  expect(evaluations).toHaveLength(10);
  expect(results).toHaveLength(10);
});

test("should create attack paths with specified steps", () => {
  const attackPath = createAttackPath(4);
  expect(attackPath).toHaveLength(4);
  expect(attackPath[0].order).toBe(1);
  expect(attackPath[3].order).toBe(4);
});

test("should create recommendations with correct types", () => {
  const recommendations = createRecommendations(3);
  expect(recommendations).toHaveLength(3);
  expect(recommendations[0].id).toBeDefined();
  expect(recommendations[0].type).toBeDefined();
});

test("should create evidence artifacts", () => {
  const evidence = createEvidenceArtifacts(2);
  expect(evidence).toHaveLength(2);
  expect(evidence[0].id).toBeDefined();
  expect(evidence[0].content).toBeDefined();
});

// Print Results
setTimeout(() => {
  console.log("\n" + "=".repeat(50));
  console.log("TEST RESULTS");
  console.log("=".repeat(50) + "\n");

  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;

  results.forEach(r => {
    const status = r.passed ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m";
    console.log(`${status} ${r.name}`);
    if (r.error) {
      console.log(`      Error: ${r.error}`);
    }
  });

  console.log("\n" + "-".repeat(50));
  console.log(`Total: ${results.length} | Passed: ${passed} | Failed: ${failed}`);
  console.log("-".repeat(50) + "\n");

  if (failed > 0) {
    process.exit(1);
  }
}, 100);
