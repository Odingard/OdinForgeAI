/**
 * BreachEventEmitter
 *
 * Single typed emitter for all granular breach chain events.
 * Every phase executor calls this — never wsService directly.
 * Events fire at the moment of confirmation, not phase completion.
 * The frontend consumes these additively to build the live graph.
 */

import { wsService } from "../services/websocket";

// ─── Types ────────────────────────────────────────────────────────────────────

export type BreachNodeKind =
  | "phase_spine"   // Phase 1–6 spine node
  | "finding"       // Confirmed exploit finding
  | "credential"    // Harvested credential
  | "iam_path"      // IAM escalation path confirmed
  | "k8s_escape"    // Container escape confirmed
  | "pivot_hop"     // Lateral movement hop confirmed
  | "data_store"    // Reachable data store (Phase 6)
  | "dead_end";     // Attempted, failed — shown grayed

export type BreachNodeSeverity = "critical" | "high" | "medium" | "low" | "info";

export type BreachPhaseId =
  | "application_compromise"
  | "credential_extraction"
  | "cloud_iam_escalation"
  | "container_k8s_breakout"
  | "lateral_movement"
  | "impact_assessment";

export type SurfaceSignalKind =
  | "stack" | "endpoint" | "cloud" | "secret" | "port" | "domain";

// ─── Event interfaces ─────────────────────────────────────────────────────────

export interface BreachNodeAddedEvent {
  type: "breach_node_added";
  chainId: string;
  nodeId: string;
  kind: BreachNodeKind;
  phase: BreachPhaseId;
  phaseIndex: number;        // 0–5
  label: string;             // Short label e.g. "SQLi", "AWS Key"
  detail: string;            // Full description for drill-down panel
  severity: BreachNodeSeverity;
  technique?: string;        // MITRE ATT&CK ID e.g. T1190
  evidenceRef?: string;      // UUID of HTTP evidence object
  curlCommand?: string;      // Reproducible PoC
  targetUrl?: string;
  statusCode?: number;
  responseSnippet?: string;  // First 200 chars of confirming response
  timestamp: string;
}

export interface BreachEdgeAddedEvent {
  type: "breach_edge_added";
  chainId: string;
  edgeId: string;
  fromNodeId: string;
  toNodeId: string;
  label?: string;            // Protocol, technique, or pivot method
  confirmed: boolean;        // false = attempted, true = confirmed
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
  decision: string;           // What the AI decided to do next
  rationale: string;          // Why
  techniqueTried?: string;
  outcome: "confirmed" | "failed" | "pivoting" | "investigating";
  linkedNodeId?: string;      // Node that triggered this reasoning step
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

export type BreachEvent =
  | BreachNodeAddedEvent
  | BreachEdgeAddedEvent
  | BreachSurfaceSignalEvent
  | BreachReasoningEvent
  | BreachPhaseTransitionEvent;

// ─── Emitter class ────────────────────────────────────────────────────────────

export class BreachEventEmitter {
  private chainId: string;
  private nodeIndex = 0;
  private edgeIndex = 0;
  private signalIndex = 0;

  constructor(chainId: string) {
    this.chainId = chainId;
  }

  /** Surface discovery — fires during crawl before any payload */
  surfaceSignal(
    kind: SurfaceSignalKind,
    label: string,
    detail: string,
    confidence: BreachSurfaceSignalEvent["confidence"] = "confirmed"
  ): string {
    const signalId = `sig-${this.signalIndex++}-${Date.now()}`;
    const event: BreachSurfaceSignalEvent = {
      type: "breach_surface_signal",
      chainId: this.chainId,
      signalId,
      kind,
      label,
      detail,
      confidence,
      timestamp: new Date().toISOString(),
    };
    wsService.broadcastBreachEvent(this.chainId, event);
    return signalId;
  }

  /** Confirmed node — fires the moment evidence is sealed */
  nodeAdded(params: Omit<BreachNodeAddedEvent,
    "type" | "chainId" | "nodeId" | "timestamp">
  ): string {
    const nodeId = `node-${this.nodeIndex++}-${Date.now()}`;
    const event: BreachNodeAddedEvent = {
      type: "breach_node_added",
      chainId: this.chainId,
      nodeId,
      timestamp: new Date().toISOString(),
      ...params,
    };
    wsService.broadcastBreachEvent(this.chainId, event);
    return nodeId;
  }

  /** Confirmed edge — fires when a connection between nodes is proven */
  edgeAdded(
    fromNodeId: string,
    toNodeId: string,
    confirmed: boolean,
    label?: string
  ): string {
    const edgeId = `edge-${this.edgeIndex++}-${Date.now()}`;
    const event: BreachEdgeAddedEvent = {
      type: "breach_edge_added",
      chainId: this.chainId,
      edgeId,
      fromNodeId,
      toNodeId,
      label,
      confirmed,
      timestamp: new Date().toISOString(),
    };
    wsService.broadcastBreachEvent(this.chainId, event);
    return edgeId;
  }

  /** AI reasoning — fires at each pivot decision */
  reasoning(
    phase: BreachPhaseId,
    agentId: string,
    decision: string,
    rationale: string,
    outcome: BreachReasoningEvent["outcome"],
    opts?: { techniqueTried?: string; linkedNodeId?: string }
  ): void {
    const event: BreachReasoningEvent = {
      type: "breach_reasoning",
      chainId: this.chainId,
      phase,
      agentId,
      decision,
      rationale,
      outcome,
      techniqueTried: opts?.techniqueTried,
      linkedNodeId: opts?.linkedNodeId,
      timestamp: new Date().toISOString(),
    };
    wsService.broadcastBreachEvent(this.chainId, event);
  }

  /** Phase transition — fires when moving between phases */
  phaseTransition(
    fromPhase: BreachPhaseId | null,
    toPhase: BreachPhaseId,
    phaseIndex: number,
    findingCount: number,
    credentialCount: number,
    summary: string
  ): void {
    const event: BreachPhaseTransitionEvent = {
      type: "breach_phase_transition",
      chainId: this.chainId,
      fromPhase,
      toPhase,
      phaseIndex,
      findingCount,
      credentialCount,
      summary,
      timestamp: new Date().toISOString(),
    };
    wsService.broadcastBreachEvent(this.chainId, event);
  }
}

/** Factory — one emitter per engagement */
export function createBreachEventEmitter(chainId: string): BreachEventEmitter {
  return new BreachEventEmitter(chainId);
}

// ─── Cognitive Events ────────────────────────────────────────────────────────
// Lightweight diagnostic events for the exploit engine and orchestrator.
// These fire alongside the existing granular breach events — they provide
// human-readable "what is the engine thinking" signals for debugging
// and for future UI rendering (reasoning panel, live feed).

export type CognitiveEventType =
  | "exploration.started"
  | "exploration.failed"
  | "exploration.succeeded"
  | "intelligence.strategy"
  | "intelligence.hypothesis"
  | "adaptation.pivot";

export interface CognitiveEvent {
  type: CognitiveEventType;
  chainId: string;
  target?: string;
  summary: string;
  detail?: string;
  timestamp: string;
}

/**
 * Emit a cognitive event via the existing WebSocket service.
 * Falls back to console.log if wsService is unavailable (e.g. in tests).
 */
export function emitCognitiveEvent(event: CognitiveEvent): void {
  try {
    const { type: _eventType, chainId: _chainId, ...rest } = event;
    wsService.broadcastBreachEvent(event.chainId, {
      type: "breach_cognitive_event",
      chainId: event.chainId,
      cognitiveType: event.type,
      ...rest,
    } as unknown as BreachEvent);
  } catch {
    // wsService not initialized (test/CLI context) — log instead
    console.log(`[COGNITIVE] ${event.type} | ${event.summary}${event.detail ? ` | ${event.detail}` : ""}`);
  }
}
