/**
 * Test Fixtures Index
 * 
 * Exports all test fixtures for Report V2 E2E testing.
 */

export { iamAbuseFixture, iamAbuseEvaluation, iamAbuseResult } from "./iam-abuse.fixture";
export { paymentBypassFixture, paymentBypassEvaluation, paymentBypassResult } from "./payment-bypass.fixture";
export { multiVectorFixture, multiVectorEvaluation, multiVectorResult } from "./multi-vector.fixture";
export { complianceGapFixture, complianceGapEvaluation, complianceGapResult } from "./compliance-gap.fixture";
export type { TestEvaluation, TestResult, TestFixture, TestRecommendation, TestEvidence, TestAttackPathStep } from "./test-data.types";

export const allFixtures = {
  iamAbuse: "iam-abuse",
  paymentBypass: "payment-bypass", 
  multiVector: "multi-vector",
  complianceGap: "compliance-gap",
} as const;

export type FixtureName = typeof allFixtures[keyof typeof allFixtures];
