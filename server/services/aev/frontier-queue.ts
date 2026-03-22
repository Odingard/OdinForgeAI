/**
 * Frontier Queue — Recursive Bounded Exploration
 *
 * Run-local queue that holds "next meaningful things to explore."
 * Every validated finding, artifact, or new discovery can seed
 * follow-on exploration. The queue is bounded, prioritized,
 * and converges when meaningful exploration is exhausted.
 *
 * This is NOT a new subsystem. It's a run-local helper inside
 * the existing exploit engine.
 */

// ── Types ────────────────────────────────────────────────────────────────────

export type FrontierItemType =
  | 'endpoint'
  | 'neighbor'
  | 'artifact_replay'
  | 'identifier_replay'
  | 'graphql_probe'
  | 'auth_family'
  | 'admin_family'
  | 'config_family';

export interface FrontierItem {
  id: string;
  type: FrontierItemType;
  url: string;
  method: string;
  priority: number;          // 0-100, higher = explore first
  depth: number;             // how deep in the recursion tree
  source: string;            // what created this item
  reason: string;            // why this was enqueued
  parent: string | null;     // parent frontier item ID
  discoverySource: string;   // crawl, headless, js_extract, frontier_expansion, finding_pivot, artifact_replay
  processed: boolean;
  result?: 'discovered' | 'dead_end' | 'already_seen' | 'skipped';
  /** LLM planner advisory hint — informational only */
  plannerHint?: string;
  /** LLM planner priority boost (capped at +15, never exceeds hard priority classes) */
  plannerPriorityBoost?: number;
}

export interface FrontierConfig {
  maxDepth: number;              // max recursion depth per branch
  maxTotalItems: number;         // max items processed per run
  maxSiblingsPerSeed: number;    // max neighbor expansion per endpoint
  maxReplayPerArtifact: number;  // max replay-derived items per artifact
  maxGraphQLProbes: number;      // max new GraphQL probes per schema insight
  staleThreshold: number;        // stop after N expansions with no new discoveries
}

const DEFAULT_CONFIG: FrontierConfig = {
  maxDepth: 6,
  maxTotalItems: 150,
  maxSiblingsPerSeed: 5,
  maxReplayPerArtifact: 5,
  maxGraphQLProbes: 3,
  staleThreshold: 10,
};

// ── Neighbor Maps ────────────────────────────────────────────────────────────

const ADMIN_NEIGHBORS = ['/admin/api', '/admin/users', '/admin/config', '/management', '/console', '/debug', '/config', '/internal'];
const AUTH_NEIGHBORS = ['/api/auth/login', '/api/auth/register', '/api/auth/token', '/api/auth/refresh', '/me', '/account', '/profile', '/api/user', '/api/me', '/api/account'];
const GRAPHQL_NEIGHBORS = ['/graphql/console', '/graphiql', '/playground', '/altair', '/api/graphql'];
const CONFIG_NEIGHBORS = ['/.env', '/.env.local', '/api/config', '/actuator', '/actuator/env', '/debug', '/.git/config'];

const USER_ID_NEIGHBORS = (base: string, id: string) => {
  const numId = parseInt(id);
  if (!isNaN(numId)) {
    return [
      base.replace(id, String(numId + 1)),
      base.replace(id, String(numId - 1)),
      base.replace(/\/\d+$/, 's'), // /api/user/1 → /api/users
      base.replace(/\/\d+$/, ''),  // /api/user/1 → /api/user
    ];
  }
  return [base.replace(/\/[^/]+$/, 's')]; // /api/user/abc → /api/users
};

// ── Frontier Queue Class ─────────────────────────────────────────────────────

export class FrontierQueue {
  private queue: FrontierItem[] = [];
  private processedUrls = new Set<string>();
  private config: FrontierConfig;
  private itemCounter = 0;
  private processedCount = 0;
  private staleCounter = 0;
  private lastMeaningfulDiscovery = 0;
  private converged = false;

  constructor(config: Partial<FrontierConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  // ── Core Queue Operations ──────────────────────────────────────────

  enqueue(item: Omit<FrontierItem, 'id' | 'processed' | 'result'>): string | null {
    // Bounds check
    if (this.queue.length >= this.config.maxTotalItems) return null;
    if (item.depth > this.config.maxDepth) return null;
    if (this.processedUrls.has(item.url)) return null;
    if (this.converged) return null;

    const id = `frontier-${this.itemCounter++}`;
    this.queue.push({ ...item, id, processed: false });

    // Sort by effective priority (base + capped planner boost), highest first
    this.queue.sort((a, b) => {
      const aBoost = Math.min(a.plannerPriorityBoost ?? 0, 15);
      const bBoost = Math.min(b.plannerPriorityBoost ?? 0, 15);
      const aEff = Math.min(a.priority + aBoost, 100);
      const bEff = Math.min(b.priority + bBoost, 100);
      return bEff - aEff;
    });

    return id;
  }

  dequeue(): FrontierItem | null {
    if (this.converged) return null;
    if (this.processedCount >= this.config.maxTotalItems) {
      this.converged = true;
      return null;
    }

    const item = this.queue.find(i => !i.processed);
    if (!item) {
      this.converged = true;
      return null;
    }

    item.processed = true;
    this.processedCount++;
    this.processedUrls.add(item.url);
    return item;
  }

  markResult(id: string, result: FrontierItem['result'], foundNew: boolean): void {
    const item = this.queue.find(i => i.id === id);
    if (item) item.result = result;

    if (foundNew) {
      this.staleCounter = 0;
      this.lastMeaningfulDiscovery = this.processedCount;
    } else {
      this.staleCounter++;
      if (this.staleCounter >= this.config.staleThreshold) {
        this.converged = true;
      }
    }
  }

  isConverged(): boolean { return this.converged; }
  pendingCount(): number { return this.queue.filter(i => !i.processed).length; }
  totalProcessed(): number { return this.processedCount; }

  getStats(): { total: number; processed: number; pending: number; converged: boolean; stale: number } {
    return {
      total: this.queue.length,
      processed: this.processedCount,
      pending: this.pendingCount(),
      converged: this.converged,
      stale: this.staleCounter,
    };
  }

  /** Reprioritize pending items based on session role change */
  reprioritizeForRole(role: 'anonymous' | 'user' | 'admin'): number {
    let adjusted = 0;
    for (const item of this.queue) {
      if (item.processed) continue;
      const lower = item.url.toLowerCase();

      if (role === 'admin') {
        // Admin: boost privileged surfaces, deprioritize login/register
        if (/admin|config|management|debug|internal/i.test(lower)) {
          item.priority = Math.min(100, item.priority + 20);
          adjusted++;
        }
        if (/login|register|signup/i.test(lower)) {
          item.priority = Math.max(10, item.priority - 15);
        }
      } else if (role === 'user') {
        // User: boost authenticated surfaces
        if (/account|profile|me|user|dashboard/i.test(lower)) {
          item.priority = Math.min(100, item.priority + 15);
          adjusted++;
        }
        if (item.type === 'auth_family') {
          item.priority = Math.min(100, item.priority + 10);
        }
      }
      // anonymous: no changes — default priorities are already anonymous-biased
    }

    // Re-sort after adjustments (including planner boosts)
    if (adjusted > 0) {
      this.queue.sort((a, b) => {
        const aBoost = Math.min(a.plannerPriorityBoost ?? 0, 15);
        const bBoost = Math.min(b.plannerPriorityBoost ?? 0, 15);
        const aEff = Math.min(a.priority + aBoost, 100);
        const bEff = Math.min(b.priority + bBoost, 100);
        return bEff - aEff;
      });
    }

    return adjusted;
  }

  // ── Seeding ────────────────────────────────────────────────────────

  /** Seed from discovered high-value endpoints */
  seedFromDiscovery(endpoints: Array<{
    url: string; method?: string; trustZone?: string; sensitivity?: string;
    chainRole?: string; discoverySource?: string; discoveryConfidence?: number;
  }>): number {
    let seeded = 0;

    for (const ep of endpoints) {
      let priority = 30; // base

      // Boost high-value targets
      if (ep.trustZone === 'privileged') priority += 30;
      if (ep.trustZone === 'internal_like') priority += 25;
      if (ep.trustZone === 'authenticated') priority += 10;
      if (ep.sensitivity === 'admin') priority += 25;
      if (ep.sensitivity === 'config') priority += 20;
      if (ep.sensitivity === 'auth') priority += 15;
      if (ep.chainRole === 'target') priority += 15;
      if (ep.chainRole === 'pivot') priority += 10;

      // Discovery source quality boost — XHR-observed outranks common-path probes
      if (ep.discoverySource === 'headless') priority += 15;
      if (ep.discoverySource === 'js_extract') priority += 10;
      if (ep.discoverySource === 'common_path') priority += 0; // no boost

      // Discovery confidence boost — high-confidence routes get priority
      if (ep.discoveryConfidence && ep.discoveryConfidence > 0.8) priority += 15;
      else if (ep.discoveryConfidence && ep.discoveryConfidence > 0.6) priority += 8;

      // Determine type from URL patterns
      let type: FrontierItemType = 'endpoint';
      const lower = ep.url.toLowerCase();
      if (lower.includes('graphql')) type = 'graphql_probe';
      else if (/auth|login|token|session|oauth/i.test(lower)) type = 'auth_family';
      else if (/admin|manage|config|debug/i.test(lower)) type = 'admin_family';
      else if (/\.env|config|secret|actuator/i.test(lower)) type = 'config_family';

      if (priority >= 50) { // only seed meaningful targets
        this.enqueue({
          type,
          url: ep.url,
          method: ep.method || 'GET',
          priority: Math.min(100, priority),
          depth: 0,
          source: 'seed',
          reason: `High-value ${ep.trustZone || 'unknown'} ${ep.sensitivity || 'generic'} endpoint`,
          parent: null,
          discoverySource: ep.discoverySource || 'crawl',
        });
        seeded++;
      }
    }

    return seeded;
  }

  // ── Finding-Driven Pivot Seeds ─────────────────────────────────────

  /** Generate frontier items from a validated finding */
  seedFromFinding(finding: {
    type: string;
    url: string;
    technique?: string;
    artifacts?: string[];
  }, parentId: string | null = null): number {
    let seeded = 0;
    const depth = parentId ? 1 : 0;

    switch (finding.type) {
      case 'xss':
        // XSS → replay targets, admin surfaces
        for (const url of ['/admin', '/api/admin', '/dashboard', ...AUTH_NEIGHBORS.slice(0, 3)]) {
          if (this.enqueue({ type: 'artifact_replay', url, method: 'GET', priority: 70, depth: depth + 1, source: 'xss_finding', reason: 'XSS session replay target', parent: parentId, discoverySource: 'finding_pivot' })) seeded++;
        }
        break;

      case 'auth_bypass':
      case 'jwt_abuse':
        // Auth bypass → all auth-family endpoints
        for (const url of AUTH_NEIGHBORS) {
          if (this.enqueue({ type: 'auth_family', url, method: 'GET', priority: 80, depth: depth + 1, source: 'auth_finding', reason: 'Auth bypass replay target', parent: parentId, discoverySource: 'finding_pivot' })) seeded++;
        }
        break;

      case 'api_abuse':
        // GraphQL/API abuse → deeper probing
        for (const url of GRAPHQL_NEIGHBORS) {
          if (this.enqueue({ type: 'graphql_probe', url, method: 'POST', priority: 75, depth: depth + 1, source: 'api_finding', reason: 'API abuse follow-on', parent: parentId, discoverySource: 'finding_pivot' })) seeded++;
        }
        break;

      case 'sqli':
        // SQLi → neighbor endpoints on same path family
        const base = finding.url.replace(/\/[^/]*$/, '');
        for (const suffix of ['/1', '/2', '/me', '/admin', 's']) {
          if (this.enqueue({ type: 'neighbor', url: `${base}${suffix}`, method: 'GET', priority: 65, depth: depth + 1, source: 'sqli_finding', reason: 'SQLi neighbor exploration', parent: parentId, discoverySource: 'finding_pivot' })) seeded++;
        }
        break;

      case 'idor':
        // IDOR → sibling IDs
        const idMatch = finding.url.match(/\/(\d+)(?:\/|$)/);
        if (idMatch) {
          for (const neighbor of USER_ID_NEIGHBORS(finding.url, idMatch[1])) {
            if (this.enqueue({ type: 'identifier_replay', url: neighbor, method: 'GET', priority: 70, depth: depth + 1, source: 'idor_finding', reason: 'IDOR sibling enumeration', parent: parentId, discoverySource: 'finding_pivot' })) seeded++;
          }
        }
        break;

      case 'path_traversal':
      case 'ssrf':
      case 'command_injection':
        // Config/system access → config family exploration
        for (const url of CONFIG_NEIGHBORS.slice(0, 4)) {
          if (this.enqueue({ type: 'config_family', url, method: 'GET', priority: 60, depth: depth + 1, source: `${finding.type}_finding`, reason: 'Config/system access follow-on', parent: parentId, discoverySource: 'finding_pivot' })) seeded++;
        }
        break;
    }

    return seeded;
  }

  // ── Neighbor Expansion ─────────────────────────────────────────────

  /** Expand neighbors around a discovered endpoint */
  expandNeighbors(url: string, parentId: string, depth: number): number {
    let expanded = 0;
    const lower = url.toLowerCase();

    let neighbors: string[] = [];

    if (/admin/i.test(lower)) {
      neighbors = ADMIN_NEIGHBORS;
    } else if (/auth|login|token/i.test(lower)) {
      neighbors = AUTH_NEIGHBORS;
    } else if (/graphql/i.test(lower)) {
      neighbors = GRAPHQL_NEIGHBORS;
    } else if (/config|env|debug|actuator/i.test(lower)) {
      neighbors = CONFIG_NEIGHBORS;
    } else if (/api\//i.test(lower)) {
      // Generic API — try common siblings
      const base = url.replace(/\/[^/]*$/, '');
      neighbors = [`${base}s`, `${base}/1`, `${base}/me`, `${base}/admin`];
    }

    for (const neighbor of neighbors.slice(0, this.config.maxSiblingsPerSeed)) {
      if (this.enqueue({
        type: 'neighbor',
        url: neighbor,
        method: 'GET',
        priority: 45,
        depth: depth + 1,
        source: 'neighbor_expansion',
        reason: `Neighbor of ${url}`,
        parent: parentId,
        discoverySource: 'frontier_expansion',
      })) expanded++;
    }

    return expanded;
  }

  // ── Artifact-Driven Expansion ──────────────────────────────────────

  /** Expand exploration based on a gained artifact */
  seedFromArtifact(artifactType: string, sourceUrl: string, parentId: string | null, depth: number): number {
    let seeded = 0;
    const targets = /token|jwt|session|cookie|bearer/i.test(artifactType)
      ? ['/me', '/account', '/profile', '/admin', '/api/user', '/api/account', '/graphql', '/dashboard']
      : /id|userId|accountId/i.test(artifactType)
        ? ['/api/user/1', '/api/user/2', '/api/account/1', '/api/users']
        : /schema|graphql/i.test(artifactType)
          ? ['/graphql', '/api/graphql', '/graphiql']
          : ['/api/config', '/admin'];

    for (const url of targets.slice(0, this.config.maxReplayPerArtifact)) {
      if (this.enqueue({
        type: 'artifact_replay',
        url,
        method: 'GET',
        priority: 75,
        depth: depth + 1,
        source: 'artifact_expansion',
        reason: `Replay ${artifactType} from ${sourceUrl}`,
        parent: parentId,
        discoverySource: 'artifact_replay',
      })) seeded++;
    }

    return seeded;
  }
}
