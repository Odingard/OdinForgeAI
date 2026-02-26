/**
 * @aev-recon — External reconnaissance and AEV mapping
 *
 * Phase 1 recon modules, verification agents, finding extraction, attack graph mapping.
 */

// Recon agent (LLM-based)
export { runReconAgent } from "../../services/agents/recon";

// AEV mapper (recon → AttackGraph)
export { mapReconToAttackGraph, mapReconToBreachContext, buildIncrementalGraph } from "../../services/recon/aev-mapper";

// Recon modules (FullReconResult is the canonical output type)
export type { FullReconResult } from "../../services/recon/index";
