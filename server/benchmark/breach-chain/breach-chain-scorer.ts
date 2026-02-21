/**
 * AEV Breach Chain Scorer
 *
 * Multi-dimensional scoring for breach chain benchmark results.
 * Produces a composite score (0-100) from chain depth, confidence,
 * evidence quality, and critical findings.
 */

import type { ChainExecutionResult } from "../../services/aev/chain-orchestrator";
import type { BreachChainScenario, BreachChainBenchmarkResult } from "./breach-chain-types";

const WEIGHTS = {
  chainDepth:  0.35,
  confidence:  0.30,
  evidence:    0.20,
  findings:    0.15,
};

/**
 * Score a chain execution result against its scenario expectations.
 */
export function scoreChainResult(
  scenario: BreachChainScenario,
  result: ChainExecutionResult
): BreachChainBenchmarkResult {
  // Chain depth: stepsSucceeded / total steps attempted
  const chainDepthScore = result.stepsExecuted > 0
    ? Math.round((result.stepsSucceeded / result.stepsExecuted) * 100)
    : 0;

  // Confidence: direct from chain orchestrator (0-100)
  const confidenceScore = Math.round(result.overallConfidence);

  // Evidence: proof artifacts collected (25 pts each, max 100)
  const evidenceScore = Math.min(100, (result.proofArtifacts?.length || 0) * 25);

  // Findings: critical findings (50 pts each, max 100)
  const findingScore = Math.min(100, (result.criticalFindings?.length || 0) * 50);

  // Composite weighted score
  const compositeScore = Math.round(
    chainDepthScore * WEIGHTS.chainDepth +
    confidenceScore * WEIGHTS.confidence +
    evidenceScore * WEIGHTS.evidence +
    findingScore * WEIGHTS.findings
  );

  // Pass/fail based on expected outcome
  const success =
    result.stepsSucceeded >= scenario.expectedOutcome.minStepsCompleted &&
    result.overallConfidence >= scenario.expectedOutcome.minConfidence;

  return {
    scenarioId: scenario.id,
    scenarioName: scenario.name,
    target: scenario.target,
    playbookId: scenario.playbookId,
    status: result.status,
    stepsExecuted: result.stepsExecuted,
    stepsSucceeded: result.stepsSucceeded,
    stepsFailed: result.stepsFailed,
    stepsSkipped: result.stepsSkipped,
    overallConfidence: result.overallConfidence,
    criticalFindings: result.criticalFindings || [],
    proofArtifacts: result.proofArtifacts?.length || 0,
    totalDurationMs: result.totalDurationMs,
    chainDepthScore,
    confidenceScore,
    evidenceScore,
    findingScore,
    compositeScore,
    success,
  };
}

/**
 * Build the competitor comparison matrix.
 */
export function buildCompetitorComparison(): BreachChainBenchmarkResult["compositeScore"] extends number ? {
  capability: string;
  odinforge: "yes" | "partial" | "no";
  shannon: "yes" | "partial" | "no";
  xbow: "yes" | "partial" | "no";
}[] : never {
  return [
    { capability: "Multi-step exploit chains",    odinforge: "yes",     shannon: "partial", xbow: "no" },
    { capability: "Confidence-gated progression",  odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "Cross-vuln chaining",           odinforge: "yes",     shannon: "partial", xbow: "no" },
    { capability: "Evidence collection per step",  odinforge: "yes",     shannon: "yes",     xbow: "partial" },
    { capability: "Playbook-based execution",      odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "Credential extraction chains",  odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "Cloud IAM escalation",          odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "K8s/Container breakout",        odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "Lateral movement simulation",   odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "EPSS/CVSS/KEV scoring",         odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "Real-time visualization",       odinforge: "yes",     shannon: "no",      xbow: "no" },
    { capability: "CI benchmark regression",       odinforge: "yes",     shannon: "partial", xbow: "partial" },
  ] as any;
}
