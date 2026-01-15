/**
 * Lateral Movement Coordination Module
 * 
 * Coordinates multi-agent attack chains across network segments.
 * Uses the endpoint agent mesh for distributed execution.
 */

export { LateralMovementCoordinator } from "./coordinator";
export { PivotExecutor } from "./pivot-executor";
export { AgentMeshClient } from "./agent-mesh-client";
export type { 
  LateralMovementPlan,
  MovementStep,
  PivotResult,
  MeshStatus 
} from "./coordinator";
