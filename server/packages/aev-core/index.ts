/**
 * @aev-core — Orchestration, exploit agent, scoring, evidence collection
 *
 * The central AEV pipeline: plan → exploit → validate → score → report.
 */

// Orchestrator
export { runAgentOrchestrator, runChainLoop } from "../../services/agents/orchestrator";
export type { OrchestratorOptions, ChainLoopResult } from "../../services/agents/orchestrator";

// Exploit agent
export { runExploitAgent } from "../../services/agents/exploit";
export type { ExploitAgentOptions } from "../../services/agents/exploit";

// Scoring engine
export { generateDeterministicScore, generateFallbackScore, calculateFixPriority } from "../../services/agents/scoring-engine";
export type { ScoringContext } from "../../services/agents/scoring-engine";

// Evidence collection
export { EvidenceCollector, generateEvidenceFromAnalysis } from "../../services/agents/evidence-collector";
export type { EvidenceContext } from "../../services/agents/evidence-collector";

// Core types
export type {
  AgentMemory,
  AgentContext,
  AgentResult,
  ExploitFindings,
  ReconFindings,
  LateralFindings,
  ImpactFindings,
  PlanFindings,
  OrchestratorResult,
  ProgressCallback,
  SafetyDecision,
  PolicyDecision,
  ExploitState,
} from "../../services/agents/types";
