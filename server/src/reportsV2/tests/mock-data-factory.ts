/**
 * Mock Data Factory
 * 
 * Generates test evaluations and results for Report V2 testing.
 * Provides utilities for creating various test scenarios.
 */

import type { TestEvaluation, TestResult, TestRecommendation, TestEvidence, TestAttackPathStep } from "./fixtures/test-data.types";
import { randomUUID } from "crypto";

export type ExposureType = 
  | "sql_injection"
  | "iam_misconfiguration"
  | "business_logic_flaw"
  | "compliance_violation"
  | "rce"
  | "ssrf"
  | "authentication_bypass"
  | "xss";

export type Priority = "critical" | "high" | "medium" | "low";

/**
 * Generate a random ID with prefix
 */
function generateId(prefix: string): string {
  return `${prefix}-${randomUUID().slice(0, 8)}`;
}

/**
 * Create a test evaluation with sensible defaults
 */
export function createTestEvaluation(overrides: Partial<TestEvaluation> = {}): TestEvaluation {
  return {
    id: generateId("eval"),
    assetId: generateId("asset"),
    assetName: "test-asset.example.com",
    assetType: "web_application",
    exposureType: "sql_injection",
    description: "Test vulnerability for evaluation",
    priority: "high",
    status: "completed",
    organizationId: "test-org",
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

/**
 * Create a test result with sensible defaults
 */
export function createTestResult(evaluationId: string, overrides: Partial<TestResult> = {}): TestResult {
  return {
    id: generateId("result"),
    evaluationId,
    exploitable: true,
    confidence: 85,
    score: 80,
    attackPath: [
      {
        id: 1,
        title: "Initial Access",
        description: "Exploit vulnerability to gain initial foothold",
        technique: "T1190",
        severity: "high",
        order: 1,
      },
      {
        id: 2,
        title: "Privilege Escalation",
        description: "Escalate privileges to admin level",
        technique: "T1068",
        severity: "critical",
        order: 2,
      },
    ],
    impact: "Significant security impact with potential data exposure",
    recommendations: [
      {
        id: generateId("rec"),
        title: "Apply security patch",
        description: "Update affected component to latest patched version",
        priority: "critical",
        type: "remediation",
        effort: "medium",
        timeline: "48 hours",
      },
      {
        id: generateId("rec"),
        title: "Enable additional monitoring",
        description: "Configure alerts for suspicious activity patterns",
        priority: "high",
        type: "compensating",
        effort: "low",
        timeline: "24 hours",
      },
    ],
    evidenceArtifacts: [
      {
        id: generateId("ev"),
        type: "http_request",
        title: "Exploit Request",
        description: "HTTP request demonstrating the vulnerability",
        content: "GET /api/vulnerable?param=exploit HTTP/1.1",
      },
    ],
    completedAt: new Date(),
    ...overrides,
  };
}

/**
 * Create a minimal evaluation for quick tests
 */
export function createMinimalEvaluation(): TestEvaluation {
  return createTestEvaluation({
    description: "Minimal test case",
    priority: "low",
  });
}

/**
 * Create a critical-priority evaluation
 */
export function createCriticalEvaluation(exposureType: ExposureType = "rce"): TestEvaluation {
  return createTestEvaluation({
    exposureType,
    priority: "critical",
    description: `Critical ${exposureType} vulnerability requiring immediate attention`,
  });
}

/**
 * Create a batch of evaluations for date range testing
 */
export function createEvaluationBatch(count: number, options: {
  organizationId?: string;
  exposureTypes?: ExposureType[];
  priorities?: Priority[];
  startDate?: Date;
  endDate?: Date;
} = {}): { evaluations: TestEvaluation[]; results: TestResult[] } {
  const {
    organizationId = "test-org",
    exposureTypes = ["sql_injection", "rce", "xss", "ssrf"],
    priorities = ["critical", "high", "medium", "low"],
    startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // 7 days ago
    endDate = new Date(),
  } = options;

  const evaluations: TestEvaluation[] = [];
  const results: TestResult[] = [];

  const timeRange = endDate.getTime() - startDate.getTime();

  for (let i = 0; i < count; i++) {
    const createdAt = new Date(startDate.getTime() + (timeRange * i / count));
    const exposureType = exposureTypes[i % exposureTypes.length];
    const priority = priorities[i % priorities.length];

    const evaluation = createTestEvaluation({
      id: `eval-batch-${i.toString().padStart(3, "0")}`,
      assetId: `asset-batch-${i.toString().padStart(3, "0")}`,
      assetName: `batch-asset-${i}.example.com`,
      exposureType,
      priority,
      organizationId,
      description: `Batch evaluation ${i + 1} of ${count} - ${exposureType} vulnerability`,
      createdAt,
      updatedAt: new Date(createdAt.getTime() + 3600000), // 1 hour later
    });

    const result = createTestResult(evaluation.id, {
      id: `result-batch-${i.toString().padStart(3, "0")}`,
      confidence: 60 + Math.floor(Math.random() * 40), // 60-100
      score: 50 + Math.floor(Math.random() * 50), // 50-100
      completedAt: new Date(createdAt.getTime() + 3600000),
    });

    evaluations.push(evaluation);
    results.push(result);
  }

  return { evaluations, results };
}

/**
 * Create attack path steps for testing
 */
export function createAttackPath(steps: number = 3): TestAttackPathStep[] {
  const techniques = [
    { id: "T1190", name: "Exploit Public-Facing Application" },
    { id: "T1068", name: "Exploitation for Privilege Escalation" },
    { id: "T1078", name: "Valid Accounts" },
    { id: "T1021", name: "Remote Services" },
    { id: "T1041", name: "Exfiltration Over C2 Channel" },
  ];

  const severities: Priority[] = ["high", "critical", "high", "medium", "critical"];

  return Array.from({ length: steps }, (_, i) => ({
    id: i + 1,
    title: `Attack Step ${i + 1}`,
    description: `Description of attack step ${i + 1}`,
    technique: techniques[i % techniques.length].id,
    severity: severities[i % severities.length],
    order: i + 1,
    targetAsset: `target-asset-${i + 1}`,
    tools: ["tool1", "tool2"],
  }));
}

/**
 * Create recommendations for testing
 */
export function createRecommendations(count: number = 3): TestRecommendation[] {
  const types: ("remediation" | "compensating" | "preventive")[] = ["remediation", "compensating", "preventive"];
  const priorities: Priority[] = ["critical", "high", "medium", "low"];

  return Array.from({ length: count }, (_, i) => ({
    id: generateId("rec"),
    title: `Recommendation ${i + 1}`,
    description: `Detailed description of recommendation ${i + 1}`,
    priority: priorities[i % priorities.length],
    type: types[i % types.length],
    effort: (["low", "medium", "high"] as const)[i % 3],
    timeline: `${i + 1} weeks`,
  }));
}

/**
 * Create evidence artifacts for testing
 */
export function createEvidenceArtifacts(count: number = 2): TestEvidence[] {
  const types = ["http_request", "http_response", "log_sample", "configuration", "screenshot"];

  return Array.from({ length: count }, (_, i) => ({
    id: generateId("ev"),
    type: types[i % types.length],
    title: `Evidence ${i + 1}`,
    description: `Description of evidence artifact ${i + 1}`,
    content: `Sample content for evidence ${i + 1}\nLine 2\nLine 3`,
    timestamp: new Date(),
  }));
}

/**
 * Create a complete evaluation with rich data for narrative testing
 */
export function createRichEvaluation(exposureType: ExposureType): {
  evaluation: TestEvaluation;
  result: TestResult;
} {
  const evaluation = createTestEvaluation({
    exposureType,
    priority: "critical",
    description: `Comprehensive ${exposureType} vulnerability with full evidence chain and multiple attack paths. Discovered during automated security scanning and validated through manual testing. Requires immediate remediation.`,
  });

  const result = createTestResult(evaluation.id, {
    confidence: 95,
    score: 92,
    attackPath: createAttackPath(5),
    recommendations: createRecommendations(5),
    evidenceArtifacts: createEvidenceArtifacts(4),
    impact: `Critical security impact from ${exposureType}. Full system compromise possible with significant data exposure risk. Business continuity threatened. Regulatory notification may be required.`,
  });

  return { evaluation, result };
}
