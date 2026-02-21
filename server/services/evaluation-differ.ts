import { storage } from "../storage";
import type { DriftResult, Evaluation, Result, AttackPathStep } from "@shared/schema";
import { randomUUID } from "crypto";

/**
 * Evaluation Differ — Continuous Validation Drift Detection
 *
 * Compares current evaluation results against the most recent previous result
 * for the same asset, producing a DriftResult that tracks:
 * - Score changes (positive = worse, negative = better)
 * - Exploitability state transitions
 * - New and resolved findings
 * - Overall risk trend (improving / stable / degrading)
 */

export interface DiffInput {
  currentEvaluation: Evaluation;
  currentResult: Result;
  assetId: string;
}

/**
 * Compute the diff between the current evaluation result and the most recent
 * historical snapshot for the same asset.
 * Returns null if no previous snapshot exists (first evaluation for asset).
 */
export async function computeEvaluationDiff(input: DiffInput): Promise<DriftResult | null> {
  const previousSnapshot = await storage.getLatestEvaluationHistoryForAsset(input.assetId);
  if (!previousSnapshot?.snapshot) return null;

  const prev = previousSnapshot.snapshot;
  const currFindings = extractFindingSummary(input.currentResult);

  const scoreChange = (input.currentResult.score ?? 0) - (prev.score ?? 0);
  const exploitabilityChange: DriftResult["changes"]["exploitabilityChange"] =
    !prev.exploitable && input.currentResult.exploitable ? "became_exploitable" :
    prev.exploitable && !input.currentResult.exploitable ? "became_safe" : "unchanged";

  const prevFindingSet = new Set(prev.findingSummary || []);
  const currFindingSet = new Set(currFindings);
  const newFindings = currFindings.filter(f => !prevFindingSet.has(f));
  const resolvedFindings = (prev.findingSummary || []).filter(f => !currFindingSet.has(f));

  const riskTrend: DriftResult["riskTrend"] =
    scoreChange > 5 ? "degrading" :
    scoreChange < -5 ? "improving" : "stable";

  return {
    comparisonId: `diff-${randomUUID().slice(0, 8)}`,
    baselineEvaluationId: previousSnapshot.evaluationId,
    currentEvaluationId: input.currentEvaluation.id,
    assetId: input.assetId,
    comparedAt: new Date().toISOString(),
    changes: {
      scoreChange,
      exploitabilityChange,
      newFindings,
      resolvedFindings,
      severityChanges: [],
    },
    summary: generateDiffSummary(scoreChange, exploitabilityChange, newFindings.length, resolvedFindings.length),
    riskTrend,
  };
}

/**
 * Record the current evaluation result as a snapshot for future diffing.
 */
export async function recordEvaluationSnapshot(
  evaluation: Evaluation,
  result: Result,
  scheduledScanId?: string
): Promise<void> {
  await storage.createEvaluationHistoryEntry({
    assetId: evaluation.assetId,
    evaluationId: evaluation.id,
    batchJobId: null,
    scheduledScanId: scheduledScanId || null,
    snapshot: {
      exploitable: result.exploitable,
      score: result.score,
      confidence: result.confidence,
      findingSummary: extractFindingSummary(result),
    },
  });
}

function extractFindingSummary(result: Result): string[] {
  const summaries: string[] = [];
  const attackPath = result.attackPath as AttackPathStep[] | null;
  if (attackPath) {
    for (const step of attackPath) {
      const label = step.technique || step.title;
      if (label) summaries.push(label);
    }
  }
  return summaries;
}

function generateDiffSummary(
  scoreChange: number,
  exploitabilityChange: string,
  newCount: number,
  resolvedCount: number
): string {
  const parts: string[] = [];
  if (scoreChange > 0) parts.push(`Risk score increased by ${scoreChange} points`);
  else if (scoreChange < 0) parts.push(`Risk score decreased by ${Math.abs(scoreChange)} points`);
  else parts.push("Risk score unchanged");

  if (exploitabilityChange === "became_exploitable") parts.push("Asset became exploitable");
  else if (exploitabilityChange === "became_safe") parts.push("Asset is no longer exploitable");

  if (newCount > 0) parts.push(`${newCount} new finding(s) identified`);
  if (resolvedCount > 0) parts.push(`${resolvedCount} finding(s) resolved`);

  return parts.join(". ") + ".";
}
