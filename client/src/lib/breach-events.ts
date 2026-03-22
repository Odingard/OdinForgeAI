/**
 * Client-side breach event types.
 * Mirrors server/lib/breach-event-emitter.ts — no server imports.
 */

export type BreachNodeKind =
  | "phase_spine" | "finding" | "credential"
  | "iam_path" | "k8s_escape" | "pivot_hop"
  | "data_store" | "dead_end";

export type BreachNodeSeverity = "critical" | "high" | "medium" | "low" | "info";

export type BreachPhaseId =
  | "application_compromise" | "credential_extraction"
  | "cloud_iam_escalation" | "container_k8s_breakout"
  | "lateral_movement" | "impact_assessment";

export type SurfaceSignalKind =
  | "stack" | "endpoint" | "cloud" | "secret" | "port" | "domain";

export interface BreachNodeAddedEvent {
  type: "breach_node_added";
  chainId: string;
  nodeId: string;
  kind: BreachNodeKind;
  phase: BreachPhaseId;
  phaseIndex: number;
  label: string;
  detail: string;
  severity: BreachNodeSeverity;
  technique?: string;
  evidenceRef?: string;
  curlCommand?: string;
  targetUrl?: string;
  statusCode?: number;
  responseSnippet?: string;
  timestamp: string;
}

export interface BreachEdgeAddedEvent {
  type: "breach_edge_added";
  chainId: string;
  edgeId: string;
  fromNodeId: string;
  toNodeId: string;
  label?: string;
  confirmed: boolean;
  timestamp: string;
}

export interface BreachSurfaceSignalEvent {
  type: "breach_surface_signal";
  chainId: string;
  signalId: string;
  kind: SurfaceSignalKind;
  label: string;
  detail: string;
  confidence: "confirmed" | "probable" | "detected";
  timestamp: string;
}

export interface BreachReasoningEvent {
  type: "breach_reasoning";
  chainId: string;
  phase: BreachPhaseId;
  agentId: string;
  decision: string;
  rationale: string;
  techniqueTried?: string;
  outcome: "confirmed" | "failed" | "pivoting" | "investigating";
  linkedNodeId?: string;
  timestamp: string;
}

export interface BreachPhaseTransitionEvent {
  type: "breach_phase_transition";
  chainId: string;
  fromPhase: BreachPhaseId | null;
  toPhase: BreachPhaseId;
  phaseIndex: number;
  findingCount: number;
  credentialCount: number;
  summary: string;
  timestamp: string;
}
