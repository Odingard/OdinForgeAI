/**
 * SubAgentManager — recursive sub-agent spawning engine (spec v1.0 §4.3)
 *
 * For every new finding at any node in any phase:
 *   1. Spawn a dedicated sub-agent with full ATT&CK context
 *   2. Sub-agent executes the next logical TTP against the target
 *   3. Findings reported back to breach chain in real time
 *   4. New findings spawn further sub-agents (recursive, depth-controlled)
 *   5. Dead ends are retired; credentials broadcast to all active sub-agents
 *
 * Constraints (spec §9):
 *   - Async + non-blocking
 *   - Rate-limited (respects blast radius config)
 *   - Error-bounded (sub-agent failure never crashes pipeline)
 *   - Feature-flagged (BREACH_CHAIN_SUB_AGENT_ENGINE)
 */

import { EventEmitter } from "events";
import { nanoid } from "nanoid";
import type { AttackNode } from "../../../shared/schema";
import { BREACH_ENHANCEMENT_FLAGS, isBreachFlagEnabled } from "../../../shared/schema";

// ── Types ──────────────────────────────────────────────────────────────────

export interface SubAgentContext {
  engagementId: string;
  parentNodeId: string;
  depth: number;
  target: string;            // hostname or IP to attack
  tactic: string;            // ATT&CK tactic to pursue
  techniqueId?: string;      // specific ATT&CK technique hint
  compromiseLevel: string;   // current privilege level at parent node
  credentials: SubAgentCredential[];
  scope: EngagementScope;
}

export interface SubAgentCredential {
  username: string;
  password?: string;
  hash?: string;
  privilegeTier: "domain_admin" | "local_admin" | "service_account" | "standard_user";
  sourceSystem: string;
}

export interface EngagementScope {
  allowedTargets: string[];  // IPs / CIDR / hostnames
  maxDepth: number;          // recursion limit (default 5)
  maxConcurrent: number;     // parallel sub-agents allowed (default 5)
  executionMode: "safe" | "simulation" | "live";
  blastRadiusMax: number;    // max assets to touch
}

export interface SubAgentFinding {
  subAgentId: string;
  parentNodeId: string;
  engagementId: string;
  depth: number;
  timestamp: string;
  nodeArtifacts: AttackNode["artifacts"];
  nodeType: "pivot" | "objective" | "dead-end";
  label: string;
  description: string;
  tactic: string;
  compromiseLevel: "none" | "limited" | "user" | "admin" | "system";
  credentials: SubAgentCredential[];  // newly discovered at this node
  childTargets: string[];             // targets to recurse into
}

export type SubAgentStatus = "queued" | "running" | "complete" | "dead-end" | "error";

interface SubAgentRecord {
  id: string;
  context: SubAgentContext;
  status: SubAgentStatus;
  startedAt?: Date;
  completedAt?: Date;
  finding?: SubAgentFinding;
  error?: string;
}

// ── SubAgentManager ────────────────────────────────────────────────────────

export class SubAgentManager extends EventEmitter {
  private agents = new Map<string, SubAgentRecord>();
  private queue: SubAgentContext[] = [];
  private running = 0;
  private touchedAssets = new Set<string>();

  // Injected executor — replaced per-engagement with real ATT&CK engine
  private executor: SubAgentExecutor;

  constructor(executor: SubAgentExecutor) {
    super();
    this.executor = executor;
  }

  // ── Public API ────────────────────────────────────────────────────────────

  /**
   * Enqueue a new sub-agent for a discovered finding.
   * Returns the sub-agent ID immediately (non-blocking).
   */
  spawn(ctx: SubAgentContext): string {
    if (!isBreachFlagEnabled(BREACH_ENHANCEMENT_FLAGS.SUB_AGENT_ENGINE)) {
      return "flag-disabled";
    }

    // Depth limit
    if (ctx.depth > (ctx.scope.maxDepth ?? 5)) {
      this.emit("dead_end", { parentNodeId: ctx.parentNodeId, reason: "max_depth_reached" });
      return "depth-exceeded";
    }

    // Blast radius check
    if (this.touchedAssets.size >= (ctx.scope.blastRadiusMax ?? 50)) {
      this.emit("blast_radius_exceeded", { engagementId: ctx.engagementId });
      return "blast-radius-exceeded";
    }

    // Target scope check
    if (!this.isTargetInScope(ctx.target, ctx.scope.allowedTargets)) {
      return "out-of-scope";
    }

    const id = `sa-${nanoid(8)}`;
    const record: SubAgentRecord = { id, context: ctx, status: "queued" };
    this.agents.set(id, record);
    this.queue.push(ctx);

    this.emit("agent_queued", { agentId: id, parentNodeId: ctx.parentNodeId, depth: ctx.depth });
    this.drain();
    return id;
  }

  /**
   * Broadcast a newly discovered credential to all active sub-agents.
   * Sub-agents will attempt credential reuse on their targets.
   * Spec §5.1 — must deliver within 500ms.
   */
  broadcastCredential(cred: SubAgentCredential, engagementId: string): void {
    if (!isBreachFlagEnabled(BREACH_ENHANCEMENT_FLAGS.CREDENTIAL_BUS)) return;

    for (const [, record] of Array.from(this.agents)) {
      if (record.context.engagementId !== engagementId) continue;
      if (record.status === "running" || record.status === "queued") {
        record.context.credentials.push(cred);
        this.emit("credential_broadcast", { agentId: record.id, cred });
      }
    }
  }

  getStatus(agentId: string): SubAgentRecord | undefined {
    return this.agents.get(agentId);
  }

  getActiveCount(engagementId: string): number {
    let count = 0;
    for (const [, r] of Array.from(this.agents)) {
      if (r.context.engagementId === engagementId && r.status === "running") count++;
    }
    return count;
  }

  getAllForEngagement(engagementId: string): SubAgentRecord[] {
    return Array.from(this.agents.values()).filter(r => r.context.engagementId === engagementId);
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  private drain(): void {
    while (this.queue.length > 0 && this.running < (this.queue[0]?.scope.maxConcurrent ?? 5)) {
      const ctx = this.queue.shift();
      if (!ctx) break;
      this.running++;
      this.run(ctx).finally(() => {
        this.running--;
        this.drain(); // pick up next queued agent
      });
    }
  }

  private async run(ctx: SubAgentContext): Promise<void> {
    // Find the record for this context
    const record = Array.from(this.agents.values()).find(
      r => r.context.engagementId === ctx.engagementId
        && r.context.parentNodeId === ctx.parentNodeId
        && r.status === "queued"
        && r.context.depth === ctx.depth
    );
    if (!record) return;

    record.status = "running";
    record.startedAt = new Date();
    this.touchedAssets.add(ctx.target);

    this.emit("agent_started", {
      agentId: record.id,
      target: ctx.target,
      tactic: ctx.tactic,
      depth: ctx.depth,
    });

    try {
      const finding = await this.executor.execute(record.id, ctx);
      record.status = finding.nodeType === "dead-end" ? "dead-end" : "complete";
      record.finding = finding;
      record.completedAt = new Date();

      this.emit("agent_finding", { agentId: record.id, finding });

      // Broadcast any credentials discovered
      for (const cred of finding.credentials) {
        this.broadcastCredential(cred, ctx.engagementId);
      }

      // Recurse into child targets (non-dead-end only)
      if (finding.nodeType !== "dead-end") {
        for (const childTarget of finding.childTargets) {
          this.spawn({
            ...ctx,
            parentNodeId: record.id,
            depth: ctx.depth + 1,
            target: childTarget,
            credentials: [...ctx.credentials, ...finding.credentials],
          });
        }
      }

    } catch (err) {
      record.status = "error";
      record.error = String(err);
      record.completedAt = new Date();
      this.emit("agent_error", { agentId: record.id, error: record.error });
      // Error is contained — does NOT propagate up
    }
  }

  private isTargetInScope(target: string, allowed: string[]): boolean {
    if (!allowed || allowed.length === 0) return true; // open scope
    return allowed.some(scope => {
      if (scope === "*") return true;
      if (scope === target) return true;
      // Simple CIDR prefix check (production: use cidr library)
      if (scope.includes("/")) {
        const [base] = scope.split("/");
        const prefix = base.split(".").slice(0, 3).join(".");
        return target.startsWith(prefix + ".");
      }
      // Wildcard domain: *.example.com
      if (scope.startsWith("*.")) {
        const domain = scope.slice(2);
        return target.endsWith("." + domain) || target === domain;
      }
      return false;
    });
  }
}

// ── SubAgentExecutor interface ─────────────────────────────────────────────
// Implemented by the ATT&CK engine (Step 6). Default: passive/simulation stub.

export interface SubAgentExecutor {
  execute(agentId: string, ctx: SubAgentContext): Promise<SubAgentFinding>;
}

/**
 * SimulationExecutor — safe stub used when executionMode != "live".
 * Performs passive checks only: port probes, HTTP HEAD, no exploitation.
 */
export class SimulationExecutor implements SubAgentExecutor {
  async execute(agentId: string, ctx: SubAgentContext): Promise<SubAgentFinding> {
    const timestamp = new Date().toISOString();

    // Passive: TCP connect probe only
    const reachable = await this.probeReachability(ctx.target);

    if (!reachable) {
      return {
        subAgentId: agentId,
        parentNodeId: ctx.parentNodeId,
        engagementId: ctx.engagementId,
        depth: ctx.depth,
        timestamp,
        nodeArtifacts: {
          hostname: ctx.target,
          subAgentId: agentId,
          subAgentStatus: "dead-end",
          discoveredAt: timestamp,
        },
        nodeType: "dead-end",
        label: `Unreachable: ${ctx.target}`,
        description: "Target did not respond to passive probe",
        tactic: ctx.tactic,
        compromiseLevel: "none",
        credentials: [],
        childTargets: [],
      };
    }

    return {
      subAgentId: agentId,
      parentNodeId: ctx.parentNodeId,
      engagementId: ctx.engagementId,
      depth: ctx.depth,
      timestamp,
      nodeArtifacts: {
        hostname: ctx.target,
        subAgentId: agentId,
        subAgentStatus: "active",
        discoveredAt: timestamp,
        attackTechniqueId: ctx.techniqueId,
      },
      nodeType: "pivot",
      label: `Reachable Host: ${ctx.target}`,
      description: `[Simulation] Target responded. Passive probe only — no exploitation in simulation mode.`,
      tactic: ctx.tactic,
      compromiseLevel: "limited",
      credentials: [],
      childTargets: [],
    };
  }

  private probeReachability(host: string): Promise<boolean> {
    return new Promise((resolve) => {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const net = require("net") as typeof import("net");
      const socket = net.createConnection({ host, port: 80, timeout: 3000 });
      const timer = setTimeout(() => { socket.destroy(); resolve(false); }, 3000);
      socket.on("connect", () => { clearTimeout(timer); socket.destroy(); resolve(true); });
      socket.on("error", () => { clearTimeout(timer); resolve(false); });
    });
  }
}

// Singleton factory — one manager per engagement
const managers = new Map<string, SubAgentManager>();

export function getSubAgentManager(engagementId: string, executor?: SubAgentExecutor): SubAgentManager {
  if (!managers.has(engagementId)) {
    managers.set(engagementId, new SubAgentManager(executor ?? new SimulationExecutor()));
  }
  return managers.get(engagementId)!;
}

export function destroySubAgentManager(engagementId: string): void {
  managers.delete(engagementId);
}
