/**
 * LLM Memory — Two-layer memory for OdinForge core-v2 LLM agents.
 *
 * Layer 1: RunMemory (per-run, cleared on new run)
 *   Tracks discovered endpoints, trust zones, artifacts, replay outcomes,
 *   failed shapes, and path promotions for the current breach chain run.
 *
 * Layer 2: HeuristicsMemory (singleton, persists across runs in-process)
 *   Learns patterns across runs: what request shapes work by endpoint type,
 *   common auth flow patterns, GraphQL templates that validate, replay ordering.
 *
 * CORE PRINCIPLE:
 *   Heuristics are retrieval hints, not truth. They inform LLM planning
 *   but never bypass the deterministic engine or quality gate.
 */

// Standalone logger
const serviceLogger = (_name: string) => ({
  info: (msg: string, ...args: any[]) => console.log(`[LLM-MEMORY] ${msg}`, ...args),
  warn: (msg: string, ...args: any[]) => console.warn(`[LLM-MEMORY] ${msg}`, ...args),
});

const log = serviceLogger("llm-memory");

// ─── Run Memory (per-run, ephemeral) ────────────────────────────────────────

export interface DiscoveredEndpoint {
  url: string;
  method: string;
  type?: string; // REST, GraphQL, WebSocket, gRPC
  trustZone?: string;
  authRequired?: boolean;
  discoveredAt: number;
}

export interface ReplayOutcome {
  endpointUrl: string;
  technique: string;
  success: boolean;
  statusCode?: number;
  timestamp: number;
}

export interface FailedShape {
  endpointUrl: string;
  shape: string; // description of the request shape that failed
  reason: string;
  timestamp: number;
}

export interface PathPromotion {
  from: string; // endpoint or phase
  to: string;
  reason: string;
  timestamp: number;
}

export class RunMemory {
  readonly runId: string;
  readonly startedAt: number;

  private endpoints: Map<string, DiscoveredEndpoint> = new Map();
  private trustZones: Map<string, string[]> = new Map(); // zone → endpoint URLs
  private artifacts: Map<string, string> = new Map(); // id → artifact description
  private replayOutcomes: ReplayOutcome[] = [];
  private failedShapes: FailedShape[] = [];
  private pathPromotions: PathPromotion[] = [];

  constructor(runId: string) {
    this.runId = runId;
    this.startedAt = Date.now();
    log.debug({ runId }, "RunMemory created for run %s", runId);
  }

  // ── Endpoints ──

  addEndpoint(endpoint: DiscoveredEndpoint): void {
    const key = `${endpoint.method}:${endpoint.url}`;
    this.endpoints.set(key, endpoint);
  }

  getEndpoints(): DiscoveredEndpoint[] {
    return Array.from(this.endpoints.values());
  }

  getEndpointsByType(type: string): DiscoveredEndpoint[] {
    return Array.from(this.endpoints.values()).filter(
      (e) => e.type === type,
    );
  }

  // ── Trust Zones ──

  setTrustZone(zone: string, endpointUrls: string[]): void {
    this.trustZones.set(zone, endpointUrls);
  }

  getTrustZones(): Map<string, string[]> {
    return new Map(this.trustZones);
  }

  // ── Artifacts ──

  addArtifact(id: string, description: string): void {
    this.artifacts.set(id, description);
  }

  getArtifacts(): Map<string, string> {
    return new Map(this.artifacts);
  }

  // ── Replay Outcomes ──

  addReplayOutcome(outcome: ReplayOutcome): void {
    this.replayOutcomes.push(outcome);
  }

  getReplayOutcomes(): ReplayOutcome[] {
    return [...this.replayOutcomes];
  }

  getReplayOutcomesForEndpoint(endpointUrl: string): ReplayOutcome[] {
    return this.replayOutcomes.filter((o) => o.endpointUrl === endpointUrl);
  }

  // ── Failed Shapes ──

  addFailedShape(shape: FailedShape): void {
    this.failedShapes.push(shape);
  }

  getFailedShapes(): FailedShape[] {
    return [...this.failedShapes];
  }

  getFailedShapesForEndpoint(endpointUrl: string): FailedShape[] {
    return this.failedShapes.filter((s) => s.endpointUrl === endpointUrl);
  }

  // ── Path Promotions ──

  addPathPromotion(promotion: PathPromotion): void {
    this.pathPromotions.push(promotion);
  }

  getPathPromotions(): PathPromotion[] {
    return [...this.pathPromotions];
  }

  // ── Summary ──

  getSummary(): {
    runId: string;
    durationMs: number;
    endpointCount: number;
    trustZoneCount: number;
    artifactCount: number;
    replayCount: number;
    failedShapeCount: number;
    promotionCount: number;
  } {
    return {
      runId: this.runId,
      durationMs: Date.now() - this.startedAt,
      endpointCount: this.endpoints.size,
      trustZoneCount: this.trustZones.size,
      artifactCount: this.artifacts.size,
      replayCount: this.replayOutcomes.length,
      failedShapeCount: this.failedShapes.length,
      promotionCount: this.pathPromotions.length,
    };
  }

  // ── Clear ──

  clear(): void {
    this.endpoints.clear();
    this.trustZones.clear();
    this.artifacts.clear();
    this.replayOutcomes.length = 0;
    this.failedShapes.length = 0;
    this.pathPromotions.length = 0;
    log.debug({ runId: this.runId }, "RunMemory cleared for run %s", this.runId);
  }
}

// ─── Heuristics Memory (global, persists across runs in-process) ────────────

export type HeuristicCategory =
  | "request_shape"
  | "auth_pattern"
  | "graphql_template"
  | "replay_ordering"
  | "endpoint_pattern"
  | "technique_success";

interface HeuristicEntry {
  value: string;
  hitCount: number;
  lastUsed: number;
  createdAt: number;
}

/**
 * HeuristicsMemory is a singleton that persists in-process across breach runs.
 * It stores retrieval hints — patterns that have worked before — to inform
 * LLM planning decisions.
 *
 * These are NOT truth. They are frequency-weighted hints that the planner
 * can consider when prioritizing exploration paths.
 */
export class HeuristicsMemory {
  private static instance: HeuristicsMemory | null = null;

  private store: Map<string, HeuristicEntry> = new Map();
  private maxEntries = 10_000;

  private constructor() {
    log.debug("HeuristicsMemory singleton initialized");
  }

  static getInstance(): HeuristicsMemory {
    if (!HeuristicsMemory.instance) {
      HeuristicsMemory.instance = new HeuristicsMemory();
    }
    return HeuristicsMemory.instance;
  }

  /**
   * For testing: reset the singleton.
   */
  static resetInstance(): void {
    HeuristicsMemory.instance = null;
  }

  // ── Core Operations ──

  /**
   * Record a heuristic learning.
   *
   * If the key already exists for this category, increments hit count.
   * If at capacity, evicts least-recently-used entry.
   */
  recordHeuristic(category: HeuristicCategory, key: string, value: string): void {
    const compositeKey = `${category}::${key}`;
    const existing = this.store.get(compositeKey);

    if (existing) {
      existing.value = value;
      existing.hitCount += 1;
      existing.lastUsed = Date.now();
    } else {
      // Evict LRU if at capacity
      if (this.store.size >= this.maxEntries) {
        this.evictLRU();
      }

      this.store.set(compositeKey, {
        value,
        hitCount: 1,
        lastUsed: Date.now(),
        createdAt: Date.now(),
      });
    }
  }

  /**
   * Retrieve a heuristic hint.
   *
   * Returns the stored value if found, or undefined.
   * Updates lastUsed timestamp on access.
   */
  getHeuristic(category: HeuristicCategory, key: string): string | undefined {
    const compositeKey = `${category}::${key}`;
    const entry = this.store.get(compositeKey);

    if (entry) {
      entry.lastUsed = Date.now();
      return entry.value;
    }

    return undefined;
  }

  /**
   * Get all heuristics in a category, sorted by hit count (most used first).
   */
  getByCategory(category: HeuristicCategory): Array<{ key: string; value: string; hitCount: number }> {
    const results: Array<{ key: string; value: string; hitCount: number }> = [];
    const prefix = `${category}::`;

    for (const [compositeKey, entry] of Array.from(this.store.entries())) {
      if (compositeKey.startsWith(prefix)) {
        results.push({
          key: compositeKey.slice(prefix.length),
          value: entry.value,
          hitCount: entry.hitCount,
        });
      }
    }

    return results.sort((a, b) => b.hitCount - a.hitCount);
  }

  /**
   * Get the top N most-used heuristics across all categories.
   */
  getTopHeuristics(n: number): Array<{ category: string; key: string; value: string; hitCount: number }> {
    const all: Array<{ category: string; key: string; value: string; hitCount: number }> = [];

    for (const [compositeKey, entry] of Array.from(this.store.entries())) {
      const sepIdx = compositeKey.indexOf("::");
      if (sepIdx !== -1) {
        all.push({
          category: compositeKey.slice(0, sepIdx),
          key: compositeKey.slice(sepIdx + 2),
          value: entry.value,
          hitCount: entry.hitCount,
        });
      }
    }

    return all.sort((a, b) => b.hitCount - a.hitCount).slice(0, n);
  }

  // ── Diagnostics ──

  getStats(): { totalEntries: number; maxEntries: number; categories: Record<string, number> } {
    const categories: Record<string, number> = {};

    for (const compositeKey of Array.from(this.store.keys())) {
      const sepIdx = compositeKey.indexOf("::");
      if (sepIdx !== -1) {
        const cat = compositeKey.slice(0, sepIdx);
        categories[cat] = (categories[cat] ?? 0) + 1;
      }
    }

    return {
      totalEntries: this.store.size,
      maxEntries: this.maxEntries,
      categories,
    };
  }

  /**
   * Clear all heuristics. Useful for testing or full reset.
   */
  clear(): void {
    this.store.clear();
    log.debug("HeuristicsMemory cleared");
  }

  // ── Internal ──

  private evictLRU(): void {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;

    for (const [key, entry] of Array.from(this.store.entries())) {
      if (entry.lastUsed < oldestTime) {
        oldestTime = entry.lastUsed;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.store.delete(oldestKey);
      log.debug({ evictedKey: oldestKey }, "HeuristicsMemory evicted LRU entry");
    }
  }
}
