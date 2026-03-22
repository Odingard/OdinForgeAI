/**
 * Lateral Movement Coordination Module
 *
 * PivotExecutor and AgentMeshClient remain for protocol-level work.
 * LateralMovementCoordinator has been removed — it contained hardcoded
 * credentials and fake discovery results. Use PivotQueue (pivot-queue.ts)
 * for multi-hop lateral movement orchestration.
 */

export { PivotExecutor } from "./pivot-executor";
export { AgentMeshClient } from "./agent-mesh-client";
