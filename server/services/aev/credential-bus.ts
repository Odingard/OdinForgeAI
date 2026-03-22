/**
 * CredentialBus — cross-phase credential sharing (spec v1.0 §5.1)
 *
 * Every credential discovered at ANY phase is immediately broadcast to all
 * active sub-agents. Successful credential reuse spawns a new node and
 * a new sub-agent for the unlocked target.
 *
 * Delivery SLA: < 500ms (in-process event emission; Redis for multi-process)
 * Feature flag: BREACH_CHAIN_CREDENTIAL_BUS
 */

import { EventEmitter } from "events";
import { BREACH_ENHANCEMENT_FLAGS, isBreachFlagEnabled } from "../../../shared/schema";
// core-v2: sub-agent-manager removed — inline the type
type SubAgentCredential = { username: string; password?: string; hash?: string; privilegeTier: string; sourceSystem: string };

// ── Types ──────────────────────────────────────────────────────────────────

export type PrivilegeTier = "domain_admin" | "local_admin" | "service_account" | "standard_user";

export interface HarvestedCredential {
  id: string;
  engagementId: string;
  username: string;
  hash?: string;
  cleartext?: string;
  privilegeTier: PrivilegeTier;
  sourceSystem: string;
  sourceNodeId: string;
  sourceTactic: string;
  discoveredAt: string;
  reusedOn: ReusedEntry[];
  unlocked: string[];  // node IDs or target strings that this credential unlocked
}

export interface ReusedEntry {
  target: string;
  nodeId?: string;
  timestamp: string;
  success: boolean;
}

export type CredentialBusHandler = (cred: HarvestedCredential) => void | Promise<void>;

// ── CredentialBus ──────────────────────────────────────────────────────────

export class CredentialBus extends EventEmitter {
  private store = new Map<string, HarvestedCredential[]>(); // engagementId → creds
  private handlers = new Map<string, CredentialBusHandler[]>(); // engagementId → subscribers

  // ── Publish ───────────────────────────────────────────────────────────────

  /**
   * Publish a newly discovered credential from any phase.
   * Immediately dispatches to all subscribers for this engagement.
   */
  publish(engagementId: string, cred: Omit<HarvestedCredential, "reusedOn" | "unlocked">): void {
    if (!isBreachFlagEnabled(BREACH_ENHANCEMENT_FLAGS.CREDENTIAL_BUS)) return;

    const full: HarvestedCredential = { ...cred, reusedOn: [], unlocked: [] };

    if (!this.store.has(engagementId)) this.store.set(engagementId, []);
    this.store.get(engagementId)!.push(full);

    this.emit("credential", engagementId, full);
    this.emit(`credential:${engagementId}`, full);

    // Dispatch to registered handlers within this tick
    const handlers = this.handlers.get(engagementId) || [];
    for (const handler of handlers) {
      Promise.resolve(handler(full)).catch((err) => {
        // Handler errors are contained — never crash the bus
        console.error("[CredentialBus] handler error:", err);
      });
    }
  }

  // ── Subscribe ─────────────────────────────────────────────────────────────

  /**
   * Subscribe to credentials for an engagement.
   * Handler is called for every NEW credential, including credentials
   * published before the subscription if catchUp = true.
   */
  subscribe(engagementId: string, handler: CredentialBusHandler, catchUp = false): () => void {
    if (!this.handlers.has(engagementId)) this.handlers.set(engagementId, []);
    this.handlers.get(engagementId)!.push(handler);

    if (catchUp) {
      const existing = this.store.get(engagementId) || [];
      for (const cred of existing) {
        Promise.resolve(handler(cred)).catch(() => {});
      }
    }

    return () => {
      const arr = this.handlers.get(engagementId);
      if (arr) {
        const idx = arr.indexOf(handler);
        if (idx !== -1) arr.splice(idx, 1);
      }
    };
  }

  // ── Reuse Tracking ────────────────────────────────────────────────────────

  recordReuse(
    engagementId: string,
    credentialUsername: string,
    entry: ReusedEntry,
    unlockedTarget?: string
  ): void {
    const creds = this.store.get(engagementId) || [];
    const cred = creds.find(c => c.username === credentialUsername);
    if (!cred) return;

    cred.reusedOn.push(entry);
    if (unlockedTarget && entry.success) {
      cred.unlocked.push(unlockedTarget);
    }

    this.emit("reuse_recorded", engagementId, cred, entry);
  }

  // ── Query ─────────────────────────────────────────────────────────────────

  getAll(engagementId: string): HarvestedCredential[] {
    return this.store.get(engagementId) || [];
  }

  getByTier(engagementId: string, tier: PrivilegeTier): HarvestedCredential[] {
    return this.getAll(engagementId).filter(c => c.privilegeTier === tier);
  }

  /** Returns a SubAgentCredential-compatible view for injection into sub-agent contexts */
  toSubAgentCredentials(engagementId: string): SubAgentCredential[] {
    return this.getAll(engagementId).map(c => ({
      username: c.username,
      password: c.cleartext,
      hash: c.hash,
      privilegeTier: c.privilegeTier,
      sourceSystem: c.sourceSystem,
    }));
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  clear(engagementId: string): void {
    this.store.delete(engagementId);
    this.handlers.delete(engagementId);
  }

  /**
   * Returns credential web data for visualization (spec §8.2).
   * Each credential node + its source system, reuse targets, unlocked targets.
   */
  getCredentialWebData(engagementId: string): CredentialWebNode[] {
    return this.getAll(engagementId).map(c => ({
      id: c.id,
      username: c.username,
      privilegeTier: c.privilegeTier,
      sourceSystem: c.sourceSystem,
      discoveredAt: c.discoveredAt,
      reusedOn: c.reusedOn,
      unlocked: c.unlocked,
      hasHash: !!c.hash,
      hasCleartext: !!c.cleartext,
    }));
  }
}

export interface CredentialWebNode {
  id: string;
  username: string;
  privilegeTier: PrivilegeTier;
  sourceSystem: string;
  discoveredAt: string;
  reusedOn: ReusedEntry[];
  unlocked: string[];
  hasHash: boolean;
  hasCleartext: boolean;
}

// ── Singleton ──────────────────────────────────────────────────────────────

let _bus: CredentialBus | null = null;

export function getCredentialBus(): CredentialBus {
  if (!_bus) _bus = new CredentialBus();
  return _bus;
}
