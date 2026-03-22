export { runAgentOrchestrator } from "./orchestrator";
export { runDefenderAgent } from "./defender";
export type {
  AgentContext,
  AgentMemory,
  OrchestratorResult,
  ProgressCallback,
  ReconFindings,
  ExploitFindings,
  LateralFindings,
  LateralShadowAdminIndicator,
  BusinessLogicFindings,
  EnhancedBusinessLogicFindings,
  MultiVectorFindings,
  ImpactFindings,
} from "./types";
export type {
  DefenderFindings,
  DetectedAttack,
  DefensiveControl,
  MitigationAction,
  BlockedPath,
  Alert,
} from "./defender";
// core-v2: ai-simulation, business-logic, multi-vector exports removed
