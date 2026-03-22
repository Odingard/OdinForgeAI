/**
 * Portfolio Orchestrator — Multi-Target Run Management
 *
 * Tracks multiple concurrent breach chain runs, provides target ranking,
 * portfolio summaries, and cross-run safety controls.
 *
 * Runtime-only state — not persisted to database.
 */

// ── Run Lifecycle States ─────────────────────────────────────────────────────

export type RunLifecycleState =
  | 'queued'
  | 'discovering'
  | 'exploiting'
  | 'validating'
  | 'replaying'
  | 'summarizing'
  | 'completed'
  | 'failed';

// ── Run Registry Entry ───────────────────────────────────────────────────────

export interface RunEntry {
  runId: string;
  chainId: string;
  target: string;
  status: RunLifecycleState;
  startedAt: string;
  updatedAt: string;
  completedAt?: string;
  findingsCount: number;
  pathsCount: number;
  replaySuccesses: number;
  primaryPath: string | null;
  highestTrustZone: string;
  highestSensitivity: string;
  primaryPathConfidence: string;
  primaryPathScore: number;
  durationMs?: number;
}

// ── Portfolio Summary ────────────────────────────────────────────────────────

export interface PortfolioSummary {
  activeRuns: number;
  completedRuns: number;
  failedRuns: number;
  totalFindings: number;
  totalReplaySuccesses: number;
  mostExposedTarget: string | null;
  mostReplayCapableTarget: string | null;
  highestPrivilegePath: string | null;
  highestConfidencePath: string | null;
  topTargets: Array<{ target: string; score: number; reason: string }>;
}

// ── Orchestration Controls ───────────────────────────────────────────────────

export interface OrchestratorConfig {
  maxConcurrentRuns: number;
  perRunEventBufferLimit: number;
  replayConcurrencyCap: number;
  portfolioUpdateThrottleMs: number;
}

const DEFAULT_CONFIG: OrchestratorConfig = {
  maxConcurrentRuns: 5,
  perRunEventBufferLimit: 250,
  replayConcurrencyCap: 3,
  portfolioUpdateThrottleMs: 2000,
};

// ── Portfolio Orchestrator Class ─────────────────────────────────────────────

export class PortfolioOrchestrator {
  private runs = new Map<string, RunEntry>();
  private config: OrchestratorConfig;
  private lastPortfolioUpdate = 0;

  constructor(config: Partial<OrchestratorConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  // ── Run Lifecycle ────────────────────────────────────────────────────

  canStartRun(): { allowed: boolean; reason?: string } {
    const active = this.getActiveRuns().length;
    if (active >= this.config.maxConcurrentRuns) {
      return { allowed: false, reason: `Max concurrent runs (${this.config.maxConcurrentRuns}) reached` };
    }
    return { allowed: true };
  }

  registerRun(runId: string, chainId: string, target: string): RunEntry {
    const entry: RunEntry = {
      runId,
      chainId,
      target,
      status: 'queued',
      startedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      findingsCount: 0,
      pathsCount: 0,
      replaySuccesses: 0,
      primaryPath: null,
      highestTrustZone: 'unknown',
      highestSensitivity: 'generic',
      primaryPathConfidence: 'low',
      primaryPathScore: 0,
    };
    this.runs.set(runId, entry);
    return entry;
  }

  updateRunState(runId: string, state: RunLifecycleState): void {
    const entry = this.runs.get(runId);
    if (!entry) return;
    entry.status = state;
    entry.updatedAt = new Date().toISOString();
    if (state === 'completed' || state === 'failed') {
      entry.completedAt = new Date().toISOString();
      entry.durationMs = Date.now() - new Date(entry.startedAt).getTime();
    }
  }

  updateRunStats(runId: string, stats: Partial<Pick<RunEntry,
    'findingsCount' | 'pathsCount' | 'replaySuccesses' | 'primaryPath' |
    'highestTrustZone' | 'highestSensitivity' | 'primaryPathConfidence' | 'primaryPathScore'
  >>): void {
    const entry = this.runs.get(runId);
    if (!entry) return;
    Object.assign(entry, stats);
    entry.updatedAt = new Date().toISOString();
  }

  // ── Queries ──────────────────────────────────────────────────────────

  getRun(runId: string): RunEntry | undefined {
    return this.runs.get(runId);
  }

  getActiveRuns(): RunEntry[] {
    return Array.from(this.runs.values()).filter(r =>
      r.status !== 'completed' && r.status !== 'failed'
    );
  }

  getAllRuns(): RunEntry[] {
    return Array.from(this.runs.values());
  }

  // ── Target Ranking ───────────────────────────────────────────────────

  rankTargets(): Array<{ target: string; score: number; reason: string }> {
    const runs = Array.from(this.runs.values()).filter(r => r.status === 'completed');
    if (runs.length === 0) return [];

    return runs.map(r => {
      let score = 0;
      const reasons: string[] = [];

      // Trust zone reached
      if (r.highestTrustZone === 'privileged') { score += 40; reasons.push('privileged zone'); }
      else if (r.highestTrustZone === 'internal_like') { score += 35; reasons.push('internal zone'); }
      else if (r.highestTrustZone === 'authenticated') { score += 15; reasons.push('auth zone'); }

      // Sensitivity reached
      if (r.highestSensitivity === 'admin') { score += 30; reasons.push('admin sensitivity'); }
      else if (r.highestSensitivity === 'config') { score += 20; reasons.push('config sensitivity'); }
      else if (r.highestSensitivity === 'auth') { score += 15; reasons.push('auth sensitivity'); }

      // Replay success
      if (r.replaySuccesses > 0) { score += 25; reasons.push(`${r.replaySuccesses} replay(s)`); }

      // Path confidence
      if (r.primaryPathConfidence === 'critical') { score += 30; reasons.push('critical path'); }
      else if (r.primaryPathConfidence === 'strong') { score += 20; reasons.push('strong path'); }

      // Findings
      score += Math.min(20, r.findingsCount * 3);
      if (r.findingsCount > 0) reasons.push(`${r.findingsCount} findings`);

      // Path score
      score += Math.min(15, r.primaryPathScore / 10);

      return { target: r.target, score, reason: reasons.join(', ') };
    }).sort((a, b) => b.score - a.score);
  }

  // ── Portfolio Summary ────────────────────────────────────────────────

  getPortfolioSummary(): PortfolioSummary {
    const all = Array.from(this.runs.values());
    const active = all.filter(r => r.status !== 'completed' && r.status !== 'failed');
    const completed = all.filter(r => r.status === 'completed');
    const failed = all.filter(r => r.status === 'failed');

    const ranked = this.rankTargets();
    const topTargets = ranked.slice(0, 3);

    // Find superlatives
    const byReplay = [...completed].sort((a, b) => b.replaySuccesses - a.replaySuccesses);
    const byPrivilege = [...completed].sort((a, b) => {
      const zoneOrder: Record<string, number> = { internal_like: 4, privileged: 3, authenticated: 2, public: 1, unknown: 0 };
      return (zoneOrder[b.highestTrustZone] || 0) - (zoneOrder[a.highestTrustZone] || 0);
    });
    const byConfidence = [...completed].sort((a, b) => {
      const confOrder: Record<string, number> = { critical: 4, strong: 3, moderate: 2, low: 1 };
      return (confOrder[b.primaryPathConfidence] || 0) - (confOrder[a.primaryPathConfidence] || 0);
    });

    return {
      activeRuns: active.length,
      completedRuns: completed.length,
      failedRuns: failed.length,
      totalFindings: all.reduce((s, r) => s + r.findingsCount, 0),
      totalReplaySuccesses: all.reduce((s, r) => s + r.replaySuccesses, 0),
      mostExposedTarget: topTargets[0]?.target || null,
      mostReplayCapableTarget: byReplay[0]?.target || null,
      highestPrivilegePath: byPrivilege[0]?.primaryPath || null,
      highestConfidencePath: byConfidence[0]?.primaryPath || null,
      topTargets,
    };
  }

  // ── Throttled Portfolio Update Check ─────────────────────────────────

  shouldUpdatePortfolio(): boolean {
    const now = Date.now();
    if (now - this.lastPortfolioUpdate < this.config.portfolioUpdateThrottleMs) {
      return false;
    }
    this.lastPortfolioUpdate = now;
    return true;
  }
}

// ── Singleton ────────────────────────────────────────────────────────────────

let _portfolioInstance: PortfolioOrchestrator | null = null;

export function getPortfolioOrchestrator(config?: Partial<OrchestratorConfig>): PortfolioOrchestrator {
  if (!_portfolioInstance) {
    _portfolioInstance = new PortfolioOrchestrator(config);
  }
  return _portfolioInstance;
}
