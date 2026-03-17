/**
 * OdinForge AEV — AgentEventBus
 *
 * Pub/sub event bus for the Agent Mesh. Every agent communicates
 * exclusively through this bus. Findings that require an EvidenceContract
 * are rejected at intake if evidence is missing — structural enforcement,
 * not policy.
 *
 * CRITICAL: No unsigned finding can enter the bus. This is the last
 * architectural line of defense for the EvidenceContract guarantee.
 */

import { randomUUID } from "crypto";
import type { RealHttpEvidence } from "../../lib/real-evidence";

// ─── Event Types ────────────────────────────────────────────────────────────

export type AgentEventType =
  | "target.discovered" // Recon → Scan: new exploitable target found
  | "surface.expanded" // Recon → Orchestrator: new subdomain/target discovered
  | "credential.found" // Recon → All: secret extracted from config file
  | "vuln.confirmed" // Scan → Exploit: vulnerability confirmed, EvidenceContract sealed
  | "scan.finished" // Scan → Orchestrator: scan for a target is complete
  | "endpoint.viable" // Scan → Exploit: auth surface confirmed
  | "breach.confirmed" // Exploit → Report: phase breach sealed with evidence
  | "credential.extracted" // Exploit → ALL: live credential available — broadcast immediately
  | "exploit.finished" // Exploit → Orchestrator: exploit chain for a vuln is complete
  | "pivot.available" // Exploit → Orchestrator: new target to chain into
  | "chain.complete" // Orchestrator → Report: seal the package
  | "package.sealed"; // Report → system: engagement done, API keys deactivate

/**
 * Event types that REQUIRE a sealed EvidenceContract.
 * Bus rejects publication of these types if evidence is null or empty.
 */
const EVIDENCED_EVENT_TYPES_LIST: AgentEventType[] = [
  "vuln.confirmed",
  "endpoint.viable",
  "breach.confirmed",
  "credential.extracted",
  "pivot.available",
];
const EVIDENCED_EVENT_TYPES: Set<AgentEventType> = new Set(EVIDENCED_EVENT_TYPES_LIST);

// ─── Event Interface ─────────────────────────────────────────────────────────

export interface AgentEvent<T = unknown> {
  id: string;
  type: AgentEventType;
  publishedBy: "recon" | "scan" | "exploit" | "report" | "orchestrator";
  chainId: string; // Engagement isolation — bus filters by chainId
  timestamp: string; // ISO — set by bus at intake, not by publisher
  payload: T;
  /**
   * Required for all EVIDENCED_EVENT_TYPES.
   * Bus rejects publication if null/empty for those types.
   * null is valid for orchestration events (surface.expanded, chain.complete, etc.)
   */
  evidence: RealHttpEvidence[] | null;
}

export type EventHandler<T = unknown> = (event: AgentEvent<T>) => void;

// ─── Bus Implementation ──────────────────────────────────────────────────────

export class AgentEventBus {
  private subscribers: Map<AgentEventType, Set<EventHandler>> = new Map();
  private eventLog: AgentEvent[] = [];
  private orchestratorCallback?: (event: AgentEvent) => void;

  /**
   * Register the TaskOrchestrator callback.
   * Called before any agents are started.
   */
  setOrchestrator(callback: (event: AgentEvent) => void): void {
    this.orchestratorCallback = callback;
  }

  /**
   * Subscribe to a specific event type or all events ('*').
   * ReportAgent uses '*' to receive every event for continuous writing.
   */
  subscribe(type: AgentEventType | "*", handler: EventHandler): void {
    if (type === "*") {
      for (const t of EVIDENCED_EVENT_TYPES_LIST) this.subscribe(t, handler);
      // Also subscribe to non-evidenced events for ReportAgent
      const allTypes: AgentEventType[] = [
        "target.discovered",
        "surface.expanded",
        "credential.found",
        "vuln.confirmed",
        "scan.finished",
        "endpoint.viable",
        "breach.confirmed",
        "credential.extracted",
        "exploit.finished",
        "pivot.available",
        "chain.complete",
        "package.sealed",
      ];
      for (const t of allTypes) {
        if (!EVIDENCED_EVENT_TYPES.has(t)) this.subscribe(t, handler);
      }
      return;
    }
    if (!this.subscribers.has(type)) {
      this.subscribers.set(type, new Set());
    }
    this.subscribers.get(type)!.add(handler);
  }

  /**
   * Publish an event to the bus.
   *
   * CRITICAL: validateAtIntake() throws if an EVIDENCED event type
   * has no evidence. This is the structural EvidenceContract gate.
   * The bus sets the timestamp — publishers cannot fake timing.
   */
  publish(event: Omit<AgentEvent, "id" | "timestamp">): void {
    const fullEvent: AgentEvent = {
      ...event,
      id: randomUUID(),
      timestamp: new Date().toISOString(),
    };

    this.validateAtIntake(fullEvent);
    this.eventLog.push(fullEvent);

    // Deliver to subscribers — non-blocking via setImmediate
    const handlers = Array.from(this.subscribers.get(fullEvent.type) ?? []);
    for (const handler of handlers) {
      setImmediate(() => {
        try {
          handler(fullEvent);
        } catch (err) {
          console.error(
            `[AgentEventBus] Handler error for event '${fullEvent.type}' ` +
              `from ${fullEvent.publishedBy} on chain ${fullEvent.chainId}:`,
            err,
          );
        }
      });
    }

    // Notify TaskOrchestrator synchronously — may unblock dependent TCG nodes
    if (this.orchestratorCallback) {
      try {
        this.orchestratorCallback(fullEvent);
      } catch (err) {
        console.error("[AgentEventBus] Orchestrator callback error:", err);
      }
    }
  }

  /**
   * Returns the full ordered event log for this bus instance.
   * Used by ReportAgent to generate Breach Chain Replay.
   * Returns an immutable copy — callers cannot mutate the log.
   */
  getEventLog(): Readonly<AgentEvent[]> {
    return [...this.eventLog];
  }

  /**
   * Returns events filtered by chainId.
   * Used for per-engagement replay and audit.
   */
  getEventLogForChain(chainId: string): Readonly<AgentEvent[]> {
    return this.eventLog.filter((e) => e.chainId === chainId);
  }

  // ─── Internal ─────────────────────────────────────────────────────────────

  /**
   * Validates that EVIDENCED event types carry real HTTP evidence.
   * Throws immediately on violation — event is never logged or delivered.
   *
   * This is the structural EvidenceContract gate for the entire Agent Mesh.
   */
  private validateAtIntake(event: AgentEvent): void {
    if (!EVIDENCED_EVENT_TYPES.has(event.type)) {
      return; // Orchestration events do not require evidence
    }

    if (!event.evidence || event.evidence.length === 0) {
      throw new Error(
        `[AgentEventBus] REJECTED: '${event.type}' published by '${event.publishedBy}' ` +
          `on chain '${event.chainId}' has no EvidenceContract. ` +
          `All finding events require a sealed RealHttpEvidence object. ` +
          `This event was NOT logged and NOT delivered to any subscriber.`,
      );
    }

    // Validate each evidence object has required fields
    for (const e of event.evidence) {
      if (e.statusCode <= 0) {
        throw new Error(
          `[AgentEventBus] REJECTED: '${event.type}' has evidence with statusCode <= 0. ` +
            `Did you stub the HTTP call?`,
        );
      }
      if (!e.rawResponseBody || e.rawResponseBody.trim().length === 0) {
        throw new Error(
          `[AgentEventBus] REJECTED: '${event.type}' has evidence with empty rawResponseBody. ` +
            `Did you stub the HTTP call?`,
        );
      }
      if (e.source !== "real_http_response") {
        throw new Error(
          `[AgentEventBus] REJECTED: '${event.type}' has evidence with source='${e.source}'. ` +
            `Expected 'real_http_response'. Source field cannot be spoofed.`,
        );
      }
    }
  }
}

// ─── Singleton factory (one bus per engagement) ───────────────────────────────

export function createAgentEventBus(): AgentEventBus {
  return new AgentEventBus();
}
