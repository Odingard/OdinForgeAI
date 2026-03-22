/**
 * OdinForge AEV — AgentMeshOrchestrator
 *
 * Top-level entry point for the Agent Mesh. Feature-flagged behind AGENT_MESH.
 * When enabled, replaces the sequential phase pipeline in breach-orchestrator.ts
 * with four simultaneous agents coordinated by the Task Coordination Graph.
 *
 * Sprint 4 (S4-01): Wire this into breach-orchestrator.ts behind feature flag.
 */

import { createAgentEventBus, AgentEventBus, AgentEvent } from "./agent-event-bus";
import { TaskOrchestrator, TCGNode } from "./task-coordination-graph";
import { ReconAgent, ScanAgent, ExploitAgent, ReportAgent } from "./agents";

export interface AgentMeshConfig {
  chainId: string;
  engagementId: string;
  targetUrl: string;
  timeout?: number; // ms, default 120_000
}

export class AgentMeshOrchestrator {
  private bus: AgentEventBus;
  private orchestrator: TaskOrchestrator;
  private reconAgent: ReconAgent;
  private scanAgent: ScanAgent;
  private exploitAgent: ExploitAgent;
  private reportAgent: ReportAgent;
  private startedAt?: number;

  constructor(private config: AgentMeshConfig) {
    this.bus = createAgentEventBus();
    this.orchestrator = new TaskOrchestrator(config.chainId, this.bus);

    // Initialize four agents
    this.reconAgent = new ReconAgent(this.bus, config.chainId, config.targetUrl);
    this.scanAgent = new ScanAgent(this.bus, config.chainId);
    this.exploitAgent = new ExploitAgent(this.bus, config.chainId);
    this.reportAgent = new ReportAgent(this.bus, config.chainId, config.engagementId);

    // Route TCG node dispatches to the correct agent
    this.orchestrator.onDispatch(this.routeToAgent.bind(this));
  }

  /**
   * Start the Agent Mesh. Returns when chain.complete or package.sealed fires,
   * or when the timeout is reached.
   */
  async run(): Promise<AgentMeshResult> {
    this.startedAt = Date.now();
    const timeout = this.config.timeout ?? 120_000;

    console.info(
      `[AgentMesh] Starting mesh for chain ${this.config.chainId} ` +
        `target=${this.config.targetUrl} timeout=${timeout}ms`,
    );

    return new Promise<AgentMeshResult>((resolve) => {
      let resolved = false;

      // Listen for package.sealed to know when we're done
      this.bus.subscribe("package.sealed", (event: AgentEvent) => {
        if (resolved) return;
        resolved = true;

        const result = this.buildResult("completed", event);
        console.info(
          `[AgentMesh] Chain ${this.config.chainId} completed in ${result.durationMs}ms ` +
            `— ${result.totalEvents} events, ${result.findingCount} findings`,
        );
        resolve(result);
      });

      // Timeout fallback
      const timer = setTimeout(() => {
        if (resolved) return;
        resolved = true;
        console.warn(`[AgentMesh] Chain ${this.config.chainId} timed out after ${timeout}ms`);
        resolve(this.buildResult("timeout"));
      }, timeout);

      // Cleanup timer on resolution
      const origResolve = resolve;
      resolve = (val) => {
        clearTimeout(timer);
        origResolve(val);
      };

      // Initialize the graph — fires recon + report nodes immediately
      this.orchestrator.initializeGraph(this.config.targetUrl);
    });
  }

  /**
   * Routes a TCG node dispatch to the correct agent method.
   */
  private routeToAgent(node: TCGNode, triggerEvent: AgentEvent): void {
    const complete = () => this.orchestrator.completeNode(node.id);
    const fail = (err: Error) => this.orchestrator.failNode(node.id, err);

    switch (node.type) {
      case "RECON_SUBDOMAIN":
        this.reconAgent.runSubdomainDiscovery(node).then(complete).catch(fail);
        break;
      case "RECON_PORT_SCAN":
        // Port scan runs as part of subdomain discovery in current pipeline
        complete();
        break;
      case "RECON_SECRET_EXTRACT":
        this.reconAgent.runSecretExtraction(node).then(complete).catch(fail);
        break;
      case "REPORT_CONTINUOUS":
        // Report agent runs continuously via bus subscriptions — mark ready
        break;
      case "REPORT_SEAL":
        // Triggered by chain.complete — report agent handles via onAnyEvent
        complete();
        break;
      case "DYNAMIC_SCAN":
      case "SCAN_ENDPOINT":
      case "SCAN_JWT":
      case "SCAN_CLOUD":
        // ScanAgent handles these via target.discovered subscription
        complete();
        break;
      case "DYNAMIC_EXPLOIT":
      case "EXPLOIT_APPSEC":
      case "EXPLOIT_IAM":
      case "EXPLOIT_K8S":
      case "EXPLOIT_LATERAL":
        // ExploitAgent handles these via vuln.confirmed subscription
        complete();
        break;
      default:
        console.warn(`[AgentMesh] Unknown node type: ${node.type}`);
        complete();
    }
  }

  private buildResult(
    status: "completed" | "timeout" | "failed",
    sealEvent?: AgentEvent,
  ): AgentMeshResult {
    const eventLog = this.bus.getEventLog();
    const sealPayload = sealEvent?.payload as Record<string, unknown> | undefined;

    return {
      status,
      chainId: this.config.chainId,
      durationMs: Date.now() - (this.startedAt ?? Date.now()),
      totalEvents: eventLog.length,
      findingCount: (sealPayload?.findingCount as number) ?? 0,
      sigmaRuleCount: (sealPayload?.sigmaRuleCount as number) ?? 0,
      replayFrameCount: (sealPayload?.replayFrameCount as number) ?? 0,
      graphSnapshot: this.orchestrator.getGraphSnapshot(),
      eventLog,
      packageState: this.reportAgent.getPackageState(),
    };
  }

  /** Expose bus for testing */
  getBus(): AgentEventBus {
    return this.bus;
  }
}

export interface AgentMeshResult {
  status: "completed" | "timeout" | "failed";
  chainId: string;
  durationMs: number;
  totalEvents: number;
  findingCount: number;
  sigmaRuleCount: number;
  replayFrameCount: number;
  graphSnapshot: TCGNode[];
  eventLog: Readonly<AgentEvent[]>;
  packageState: Readonly<Record<string, unknown>>;
}
