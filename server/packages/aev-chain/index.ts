/**
 * @aev-chain — Playbook-based breach chain orchestration
 *
 * Multi-step attack chains with confidence gating and evidence collection.
 */

// Chain orchestrator
export { ChainOrchestrator, chainOrchestrator } from "../../services/aev/chain-orchestrator";
export type {
  Playbook,
  PlaybookStep,
  StepResult,
  StepEvidence,
  ChainExecutionResult,
  ChainOrchestratorConfig,
  ExploitCategory,
  StepType,
  StepHandler,
} from "../../services/aev/chain-orchestrator";

// Playbook registry
export {
  playbookRegistry,
  getPlaybook,
  listPlaybooks,
  getPlaybooksByCategory,
  getPlaybooksByRiskLevel,
} from "../../services/aev/playbooks";
