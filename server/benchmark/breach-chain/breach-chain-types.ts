/**
 * AEV Breach Chain Benchmark Types
 *
 * Types for testing OdinForge's multi-phase breach chain capabilities
 * against vulnerable targets. Measures chain depth, confidence, evidence,
 * and scoring — capabilities competitors cannot match.
 */

import type { ChainExecutionResult } from "../../services/aev/chain-orchestrator";

export interface BreachChainScenario {
  id: string;
  name: string;
  target: string;              // "juice-shop" | "dvwa" | "webgoat"
  playbookId: string;          // Reference to playbook in registry
  targetEndpoint: string;      // URL path appended to target base URL
  parameters: Record<string, string | boolean | number>;
  expectedOutcome: {
    minStepsCompleted: number;
    minConfidence: number;
    shouldDetectVuln: boolean;
  };
}

export interface BreachChainBenchmarkResult {
  scenarioId: string;
  scenarioName: string;
  target: string;
  playbookId: string;
  // From ChainExecutionResult
  status: string;
  stepsExecuted: number;
  stepsSucceeded: number;
  stepsFailed: number;
  stepsSkipped: number;
  overallConfidence: number;
  criticalFindings: string[];
  proofArtifacts: number;
  totalDurationMs: number;
  // Scoring
  chainDepthScore: number;
  confidenceScore: number;
  evidenceScore: number;
  findingScore: number;
  compositeScore: number;
  // Pass/fail
  success: boolean;
  error?: string;
}

export interface BreachChainReport {
  meta: {
    timestamp: string;
    targets: string[];
    executionMode: string;
  };
  overall: {
    scenariosRun: number;
    scenariosSucceeded: number;
    avgCompositeScore: number;
    avgChainDepth: number;
    avgConfidence: number;
  };
  byTarget: Record<string, {
    scenarios: number;
    succeeded: number;
    avgScore: number;
  }>;
  results: BreachChainBenchmarkResult[];
  competitorComparison: {
    capability: string;
    odinforge: "yes" | "partial" | "no";
    shannon: "yes" | "partial" | "no";
    xbow: "yes" | "partial" | "no";
  }[];
}
