/**
 * Test Data Types for Report V2 Fixtures
 * 
 * These types mirror the essential fields used by the report input builder
 * without requiring exact schema compliance for test data generation.
 */

export interface TestEvaluation {
  id: string;
  assetName?: string;
  assetId: string;
  assetType?: string;
  exposureType: string;
  description: string;
  priority: "critical" | "high" | "medium" | "low";
  status: "pending" | "in_progress" | "completed" | "failed";
  organizationId: string;
  adversaryProfile?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface TestAttackPathStep {
  id: number;
  title: string;
  description: string;
  technique?: string;
  severity: "critical" | "high" | "medium" | "low";
  order?: number;
  targetAsset?: string;
  tools?: string[];
}

export interface TestRecommendation {
  id: string;
  title: string;
  description: string;
  priority: "critical" | "high" | "medium" | "low";
  type: "remediation" | "compensating" | "preventive";
  effort?: "low" | "medium" | "high";
  timeline?: string;
}

export interface TestEvidence {
  id: string;
  type: string;
  title: string;
  description: string;
  content: string;
  timestamp?: Date;
}

export interface TestResult {
  id: string;
  evaluationId: string;
  exploitable: boolean;
  confidence: number;
  score: number;
  attackPath?: TestAttackPathStep[];
  impact?: string;
  recommendations?: TestRecommendation[];
  evidenceArtifacts?: TestEvidence[];
  completedAt?: Date;
}

export interface TestFixture {
  evaluation: TestEvaluation;
  result: TestResult;
  expectedNarrativeElements: string[];
  complianceFrameworks?: string[];
  affectedRequirements?: string[];
}
