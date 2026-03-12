/**
 * PivotQueue — Multi-hop lateral movement orchestrator
 *
 * Replaces the dead LateralMovementCoordinator.
 *
 * Architecture:
 *   1. Seed with Phase 1 compromised hosts + Phase 2 credentials
 *   2. Drain: each item runs a LateralMovementSubAgent against its host
 *   3. Agent returns { newCredentials, discoveredHosts, evidence }
 *   4. New credentials are added to the shared store (available to all future hops)
 *   5. New hosts are enqueued at depth + 1 (up to maxDepth)
 *   6. visited set prevents any host being tested twice in one engagement
 *
 * Result: a real multi-hop breach chain where credentials harvested at hop 2
 * are available to agents working hop 3, and so on.
 */

import { lateralMovementService } from "../lateral-movement";
import type { HarvestedCredential } from "../credential-store";
import type { BreachCredential } from "@shared/schema";
import { randomUUID } from "crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PivotQueueItem {
  host: string;
  depth: number;
  /** Credential snapshot at discovery time — what the agent actually has to work with */
  credentialSnapshot: HarvestedCredential[];
  discoveredBy: string;
  timestamp: Date;
}

export interface PivotNodeResult {
  host: string;
  depth: number;
  discoveredBy: string;
  /** New credentials harvested at this node */
  newCredentials: HarvestedCredential[];
  /** New hosts discovered reachable from this node */
  discoveredHosts: string[];
  /** Findings from auth attempts at this node */
  findings: PivotFinding[];
  durationMs: number;
}

export interface PivotFinding {
  id: string;
  host: string;
  depth: number;
  technique: string;
  mitreId: string;
  severity: "critical" | "high" | "medium" | "low";
  /** What actually happened — auth result, access level, captured output */
  evidence: string;
  authResult: "success" | "invalid_credential" | "account_restricted" | "unreachable" | "error" | "no_credential";
  accessLevel: "none" | "read" | "user" | "admin" | "smb_read";
  capturedOutput?: string;
  credentialUsed?: string; // displayValue only
}

// ─── PivotQueue ───────────────────────────────────────────────────────────────

export class PivotQueue {
  private queue: PivotQueueItem[] = [];
  private visited: Set<string> = new Set();
  private credentialStore: HarvestedCredential[] = [];
  private maxDepth: number;
  private allResults: PivotNodeResult[] = [];

  constructor(maxDepth = 5) {
    this.maxDepth = maxDepth;
  }

  /** Add a host to test — deduped by visited set */
  enqueue(host: string, depth: number, discoveredBy: string): void {
    if (!host || this.visited.has(host)) return;
    if (depth > this.maxDepth) return;
    this.visited.add(host);
    this.queue.push({
      host,
      depth,
      discoveredBy,
      timestamp: new Date(),
      credentialSnapshot: [...this.credentialStore], // snapshot at discovery time
    });
  }

  /** Add a credential to the shared store — available to all future hop agents */
  addCredential(cred: HarvestedCredential): void {
    const exists = this.credentialStore.find(c => c.hash === cred.hash);
    if (!exists) {
      this.credentialStore.push(cred);
    }
  }

  /** Add multiple credentials */
  addCredentials(creds: HarvestedCredential[]): void {
    creds.forEach(c => this.addCredential(c));
  }

  /**
   * Drain the queue — process each item with the worker function.
   * Worker returns { newCredentials, discoveredHosts, findings }.
   * New credentials are added to the shared store before the next hop.
   * New hosts are enqueued at depth + 1.
   */
  async drain(
    worker: (item: PivotQueueItem) => Promise<PivotNodeResult>,
    onProgress?: (msg: string, depth: number) => void
  ): Promise<PivotNodeResult[]> {
    while (this.queue.length > 0) {
      const item = this.queue.shift()!;
      onProgress?.(`Testing ${item.host} (depth ${item.depth}, ${this.credentialStore.length} creds available)`, item.depth);

      const result = await worker(item);
      this.allResults.push(result);

      // Add new credentials to shared store before processing next item
      // so agents at the next depth have access to them
      result.newCredentials.forEach(c => this.addCredential(c));

      // Enqueue newly discovered hosts at the next depth
      result.discoveredHosts.forEach(h =>
        this.enqueue(h, item.depth + 1, item.host)
      );
    }

    return this.allResults;
  }

  getResults(): PivotNodeResult[] { return this.allResults; }
  getVisited(): string[] { return Array.from(this.visited); }
  getCredentialCount(): number { return this.credentialStore.length; }
}

// ─── LateralMovementSubAgent ──────────────────────────────────────────────────

export class LateralMovementSubAgent {
  private target: string;
  private credentials: HarvestedCredential[];
  private depth: number;

  constructor(params: {
    target: string;
    credentials: HarvestedCredential[];
    depth: number;
  }) {
    this.target = params.target;
    this.credentials = params.credentials;
    this.depth = params.depth;
  }

  async execute(): Promise<PivotNodeResult> {
    const startTime = Date.now();
    const findings: PivotFinding[] = [];
    const discoveredHosts: string[] = [];
    const newCredentials: HarvestedCredential[] = [];

    // 1. Discover pivot surface on this host
    let pivotHost = this.target;
    try {
      if (this.target.startsWith("http")) {
        pivotHost = new URL(this.target).hostname;
      }
    } catch { /* use as-is */ }

    const pivotResult = await lateralMovementService.discoverPivotPoints({
      startingHost: pivotHost,
      scanDepth: 1,
      techniques: ["credential_reuse", "ssh_pivot", "smb_relay", "rdp_pivot"],
    });

    // Newly discovered hosts from pivot point scan
    for (const pivot of pivotResult.pivotPoints) {
      if (pivot.hostname && pivot.hostname !== pivotHost) {
        discoveredHosts.push(pivot.hostname);
      }
    }

    // 2. Test credential reuse against this host with all available credentials
    const TECHNIQUES = ["credential_reuse", "ssh_pivot"];
    for (const cred of this.credentials) {
      const reuseResult = await lateralMovementService.testCredentialReuse({
        credentialType: cred.type,
        username: cred.username || "unknown",
        domain: cred.domain,
        credentialValue: cred.authValue, // encrypted — decrypted inside service at auth time
        targetHosts: [pivotHost],
        techniques: TECHNIQUES,
      });

      for (const finding of reuseResult.findings) {
        const lmFinding = finding as any;
        const authResult: PivotFinding["authResult"] =
          lmFinding.success ? "success"
          : (lmFinding.accessLevel === "none" ? "invalid_credential" : "error");

        findings.push({
          id: `pf-${randomUUID().slice(0, 8)}`,
          host: pivotHost,
          depth: this.depth,
          technique: lmFinding.technique || "credential_reuse",
          mitreId: lmFinding.mitreAttackId || "T1078",
          severity: lmFinding.success ? (lmFinding.accessLevel === "admin" ? "critical" : "high") : "low",
          evidence: lmFinding.businessImpact || lmFinding.evidence?.technique || `Auth attempt against ${pivotHost}`,
          authResult,
          accessLevel: lmFinding.accessLevel || "none",
          capturedOutput: lmFinding.evidence?.outputCaptured || undefined,
          credentialUsed: cred.displayValue,
        });

        // If auth succeeded, this host is a credential validated target
        if (lmFinding.success && cred.accessLevel !== "unknown") {
          // Treat any newly discovered credentials from this host as phase output
          for (const newCred of (pivotResult.credentialsDiscovered as any[] || [])) {
            if (newCred.authValue) {
              newCredentials.push(newCred as HarvestedCredential);
            }
          }
        }
      }
    }

    return {
      host: pivotHost,
      depth: this.depth,
      discoveredBy: "pivot-queue",
      newCredentials,
      discoveredHosts,
      findings,
      durationMs: Date.now() - startTime,
    };
  }
}

/**
 * Convert a BreachCredential (schema type) to HarvestedCredential for the queue.
 * BreachCredentials from prior phases have valueHash; we reconstruct a minimal
 * HarvestedCredential so the queue can pass them to auth attempts.
 */
export function breachCredToHarvested(bc: BreachCredential): HarvestedCredential {
  return {
    id: bc.id,
    type: (bc.type as HarvestedCredential["type"]) || "password",
    username: bc.username || undefined,
    domain: bc.domain || undefined,
    displayValue: bc.valueHash?.substring(0, 8) + "***" || "***",
    // authValue IS the valueHash field — if it's an encrypted ciphertext (IV:cipher:tag)
    // it will decrypt correctly; if it's a plain hash it will fail gracefully at auth time
    authValue: bc.authValue || bc.valueHash || "",
    source: bc.source || "unknown",
    context: `Carried from phase: ${bc.source}`,
    timestamp: new Date(bc.discoveredAt || Date.now()),
    usedBy: [],
    hash: bc.valueHash || bc.id,
    accessLevel: (bc.accessLevel === "cloud_admin" ? "admin" : bc.accessLevel || "unknown") as HarvestedCredential["accessLevel"],
  };
}
