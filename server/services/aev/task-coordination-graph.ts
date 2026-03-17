/**
 * OdinForge AEV — Task Coordination Graph (TCG)
 *
 * Directed acyclic graph where every node is a task and every edge is
 * a dependency. TaskOrchestrator dispatches a node the moment all its
 * dependencies are satisfied — not when a phase timer fires or the entire
 * prior phase completes.
 *
 * KEY CAPABILITY: Dynamic node spawning. When ReconAgent discovers a new
 * attack surface (surface.expanded event), TaskOrchestrator adds new Scan
 * and Exploit nodes to the graph at runtime. The chain adapts as it executes.
 */

import { randomUUID } from "crypto";
import type { AgentEvent, AgentEventBus, AgentEventType } from "./agent-event-bus";

// ─── Node Types ──────────────────────────────────────────────────────────────

export type TCGNodeType =
  | "RECON_SUBDOMAIN"
  | "RECON_PORT_SCAN"
  | "RECON_SECRET_EXTRACT"
  | "SCAN_ENDPOINT"
  | "SCAN_JWT"
  | "SCAN_CLOUD"
  | "EXPLOIT_APPSEC"
  | "EXPLOIT_IAM"
  | "EXPLOIT_K8S"
  | "EXPLOIT_LATERAL"
  | "REPORT_CONTINUOUS"
  | "REPORT_SEAL"
  | "DYNAMIC_SCAN"
  | "DYNAMIC_EXPLOIT";

export type TCGNodeStatus = "pending" | "ready" | "running" | "complete" | "failed";

export interface TCGNode {
  id: string;
  type: TCGNodeType;
  assignedAgent: "recon" | "scan" | "exploit" | "report";
  dependencies: string[]; // node IDs that must complete before this fires
  triggerEvent?: AgentEventType; // bus event type that unblocks this node
  triggerPayload?: unknown; // payload from the triggering event
  status: TCGNodeStatus;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  dynamicSource?: string; // set if this node was spawned from surface.expanded
}

// ─── Dispatch callback type ───────────────────────────────────────────────────

export type DispatchCallback = (node: TCGNode, triggerEvent: AgentEvent) => void;

// ─── TaskOrchestrator ────────────────────────────────────────────────────────

export class TaskOrchestrator {
  private graph: Map<string, TCGNode> = new Map();
  private dispatchCallback?: DispatchCallback;
  private chainId: string;
  private chainCompletePublished = false;
  private activeScans = 0; // tracks target.discovered minus scan.finished
  private activeExploits = 0; // tracks vuln.confirmed minus exploit.finished

  constructor(
    chainId: string,
    private bus: AgentEventBus,
  ) {
    this.chainId = chainId;
    bus.setOrchestrator(this.onEvent.bind(this));
  }

  /**
   * Register the function that actually runs a task node.
   * AgentMeshOrchestrator sets this to route nodes to the correct agent.
   */
  onDispatch(callback: DispatchCallback): void {
    this.dispatchCallback = callback;
  }

  /**
   * Initialize the default graph for a new engagement.
   * Recon and Report nodes start immediately (no dependencies).
   * Scan, Exploit nodes wait for triggering events.
   */
  initializeGraph(targetUrl: string): void {
    // Recon nodes — fire immediately, no dependencies
    this.addNode({ type: "RECON_SUBDOMAIN", assignedAgent: "recon", dependencies: [], status: "ready" });
    this.addNode({ type: "RECON_PORT_SCAN", assignedAgent: "recon", dependencies: [], status: "ready" });
    this.addNode({ type: "RECON_SECRET_EXTRACT", assignedAgent: "recon", dependencies: [], status: "ready" });

    // Report node — runs entire engagement duration
    this.addNode({ type: "REPORT_CONTINUOUS", assignedAgent: "report", dependencies: [], status: "ready" });

    // Report seal — waits for chain.complete
    this.addNode({
      type: "REPORT_SEAL",
      assignedAgent: "report",
      dependencies: [],
      triggerEvent: "chain.complete",
      status: "pending",
    });

    // Dispatch all 'ready' nodes immediately
    for (const node of Array.from(this.graph.values())) {
      if (node.status === "ready") {
        this.dispatch(node, {
          type: "chain.start",
          chainId: this.chainId,
          payload: { targetUrl },
        } as unknown as AgentEvent);
      }
    }
  }

  /**
   * Called by AgentEventBus on every published event.
   * Finds nodes whose triggerEvent matches, checks dependencies,
   * and dispatches newly unblocked nodes.
   */
  onEvent(event: AgentEvent): void {
    if (event.chainId !== this.chainId) return; // Isolation — ignore other chains

    // Track active scans and exploits for completion detection
    if (event.type === "target.discovered") {
      this.activeScans++;
    } else if (event.type === "scan.finished") {
      this.activeScans = Math.max(0, this.activeScans - 1);
    } else if (event.type === "vuln.confirmed") {
      this.activeExploits++;
    } else if (event.type === "exploit.finished") {
      this.activeExploits = Math.max(0, this.activeExploits - 1);
    }

    // Find all pending nodes whose triggerEvent matches this event
    const unblocked = Array.from(this.graph.values()).filter(
      (node) =>
        node.status === "pending" && node.triggerEvent === event.type && this.dependenciesSatisfied(node),
    );

    for (const node of unblocked) {
      node.status = "ready";
      node.triggerPayload = event.payload;
      this.dispatch(node, event);
    }

    // Dynamic node spawning — new attack surface discovered
    if (event.type === "surface.expanded") {
      this.spawnSubGraph(event);
    }

    // Lateral movement — spawn new exploit node for pivot target
    if (event.type === "pivot.available") {
      this.spawnLateralNode(event);
    }

    if (!this.chainCompletePublished && this.isChainComplete()) {
      this.chainCompletePublished = true;
      console.info(
        `[TCG] Chain complete — ${this.graph.size} nodes, ` +
          `activeScans=${this.activeScans}, activeExploits=${this.activeExploits}`,
      );
      this.bus.publish({
        type: "chain.complete",
        publishedBy: "orchestrator",
        chainId: this.chainId,
        payload: { nodeCount: this.graph.size, completedAt: new Date().toISOString() },
        evidence: null,
      });
    }
  }

  /**
   * Mark a node as complete. Called by agents when their task finishes.
   */
  completeNode(nodeId: string): void {
    const node = this.graph.get(nodeId);
    if (!node) return;
    node.status = "complete";
    node.completedAt = new Date().toISOString();
  }

  failNode(nodeId: string, error: Error): void {
    const node = this.graph.get(nodeId);
    if (!node) return;
    node.status = "failed";
    console.error(`[TCG] Node ${node.type} (${nodeId}) failed:`, error.message);
  }

  getNode(nodeId: string): TCGNode | undefined {
    return this.graph.get(nodeId);
  }

  get nodeCount(): number {
    return this.graph.size;
  }

  getGraphSnapshot(): TCGNode[] {
    return Array.from(this.graph.values());
  }

  // ─── Internal ─────────────────────────────────────────────────────────────

  private addNode(partial: Omit<TCGNode, "id" | "createdAt">): TCGNode {
    const node: TCGNode = {
      ...partial,
      id: randomUUID(),
      createdAt: new Date().toISOString(),
    };
    this.graph.set(node.id, node);
    return node;
  }

  private dispatch(node: TCGNode, triggerEvent: AgentEvent): void {
    if (!this.dispatchCallback) {
      console.error("[TCG] No dispatch callback registered — did you call onDispatch()?");
      return;
    }
    node.status = "running";
    node.startedAt = new Date().toISOString();
    try {
      this.dispatchCallback(node, triggerEvent);
    } catch (err) {
      this.failNode(node.id, err as Error);
    }
  }

  private dependenciesSatisfied(node: TCGNode): boolean {
    return node.dependencies.every((depId) => {
      const dep = this.graph.get(depId);
      return dep?.status === "complete";
    });
  }

  /**
   * Dynamic sub-graph spawning.
   * When ReconAgent discovers a new subdomain/target, immediately
   * add a Scan node (fires right away) and an Exploit node (waits for Scan).
   */
  private spawnSubGraph(event: AgentEvent): void {
    const payload = event.payload as { newTarget: string };

    const scanNode = this.addNode({
      type: "DYNAMIC_SCAN",
      assignedAgent: "scan",
      dependencies: [], // no deps — fires immediately
      status: "ready",
      triggerPayload: payload,
      dynamicSource: event.id,
    });

    this.addNode({
      type: "DYNAMIC_EXPLOIT",
      assignedAgent: "exploit",
      dependencies: [scanNode.id], // waits for this specific scan
      triggerEvent: "vuln.confirmed",
      status: "pending",
      dynamicSource: event.id,
    });

    console.info(
      `[TCG] Dynamic sub-graph spawned for '${payload.newTarget}': ` +
        `SCAN(${scanNode.id.slice(0, 8)}) → EXPLOIT`,
    );

    // Dispatch the scan node immediately
    this.dispatch(scanNode, event);
  }

  private spawnLateralNode(event: AgentEvent): void {
    const pivot = event.payload as { targetHost: string; technique: string };

    const lateralNode = this.addNode({
      type: "EXPLOIT_LATERAL",
      assignedAgent: "exploit",
      dependencies: [],
      status: "ready",
      triggerPayload: pivot,
      dynamicSource: event.id,
    });

    this.dispatch(lateralNode, event);
  }

  private isChainComplete(): boolean {
    // Scans or exploits still in progress — not done yet
    if (this.activeScans > 0 || this.activeExploits > 0) return false;

    const pendingOrRunning = Array.from(this.graph.values()).filter(
      (n) => n.status === "pending" || n.status === "running",
    );
    // Exclude report nodes (REPORT_SEAL waits for chain.complete, REPORT_CONTINUOUS runs forever)
    const nonReportPending = pendingOrRunning.filter(
      (n) => n.type !== "REPORT_SEAL" && n.type !== "REPORT_CONTINUOUS",
    );
    // Exploit nodes whose scan dependency already completed are skippable —
    // the scan ran and found no vulns, so the exploit trigger (vuln.confirmed) will never fire
    const blocking = nonReportPending.filter((n) => {
      if (n.status === "pending" && n.triggerEvent === "vuln.confirmed" && n.dependencies.length > 0) {
        const allDepsComplete = n.dependencies.every((depId) => {
          const dep = this.graph.get(depId);
          return dep?.status === "complete";
        });
        if (allDepsComplete) return false; // skippable — scan done, no vulns
      }
      return true;
    });
    return blocking.length === 0;
  }
}
