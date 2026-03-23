/**
 * OdinForge Reasoning Engine
 *
 * Real-time intelligence expression layer. Emits deterministic reasoning
 * events, canvas state changes, and operator summaries during a run.
 *
 * This layer does NOT confirm findings or change exploit truth.
 * It expresses what the engine is doing and why.
 *
 * All events are broadcast through the existing WebSocket channel
 * so the frontend receives them in real time.
 */

import { wsService } from '../websocket';
import { LlmRouter } from '../../../src/llm/router';

// ── Intent Classes ───────────────────────────────────────────────────────────

export type ReasoningIntent =
  | 'explore'     // discovering surface
  | 'exploit'     // attempting exploitation
  | 'validate'    // confirming or rejecting evidence
  | 'pivot'       // using a finding to reach deeper
  | 'escalate'    // moving to higher-privilege surface
  | 'replay'      // replaying artifact against new target
  | 'summarize';  // synthesizing state

export interface ReasoningEvent {
  timestamp: string;
  chainId: string;
  intent: ReasoningIntent;
  target?: string;
  message: string;
  detail?: string;           // Enriched one-liner for live feed (technique + what was found)
  technique?: string;        // e.g. "JWT none algorithm", "SQLi union-based"
  credentialType?: string;   // e.g. "password", "api_key", "session_cookie" (no raw values)
  context?: {
    artifact?: string;
    zone?: string;
    sensitivity?: string;
    role?: string;
    pathId?: string;
    confidence?: string;
  };
}

// ── Credential Masking ────────────────────────────────────────────────────────
// Show first 4 chars then mask the rest. Never expose full credentials in the live feed.

export function maskCredential(raw: string): string {
  if (!raw || raw.length <= 4) return '****';
  return raw.slice(0, 4) + '***';
}

// ── Canvas Events ────────────────────────────────────────────────────────────

export type CanvasEventType =
  | 'node_discovered'
  | 'node_classified'
  | 'edge_inferred'
  | 'edge_confirmed'
  | 'node_promoted'
  | 'artifact_gained'
  | 'replay_started'
  | 'replay_succeeded'
  | 'replay_failed'
  | 'path_promoted'
  | 'primary_path_changed';

export interface CanvasEvent {
  timestamp: string;
  chainId: string;
  type: CanvasEventType;
  source?: string;
  target?: string;
  zone?: string;
  sensitivity?: string;
  confirmed: boolean;
  detail?: string;
  technique?: string;        // Short technique label for node subtitle
  severity?: string;         // For node coloring on discovery
  label?: string;            // Short display label
  credentialType?: string;   // Indicator that creds were found at this node
  statusCode?: number;       // HTTP status code for evidence
  confidence?: string;       // e.g. "85%"
}

// ── Operator Summary ─────────────────────────────────────────────────────────

export interface OperatorSummary {
  currentObjective: string;
  currentPrimarySurface: string;
  activeArtifact: string | null;
  currentPrimaryPath: string | null;
  currentTrustZone: string;
  currentSensitivity: string;
  lastMeaningfulChange: string;
  findingsCount: number;
  pathsCount: number;
  replaySuccesses: number;
}

// ── Run-Local Memory ─────────────────────────────────────────────────────────

export interface RunMemory {
  surfaces: {
    highValue: string[];
    failed: string[];
    classified: Map<string, { zone: string; sensitivity: string; role: string }>;
  };
  artifacts: {
    tokens: string[];
    identifiers: string[];
    schemaHints: string[];
    credentials: string[];
  };
  paths: {
    primaryId: string | null;
    primaryScore: number;
    totalPaths: number;
  };
  failures: {
    unreachable: string[];
    rejected: string[];
    noEvidence: string[];
  };
  stats: {
    reasoningEvents: number;
    canvasEvents: number;
    replaySuccesses: number;
  };
}

// ── Reasoning Engine Class ───────────────────────────────────────────────────

export class ReasoningEngine {
  private chainId: string;
  private events: ReasoningEvent[] = [];
  private canvasEvents: CanvasEvent[] = [];
  private memory: RunMemory;
  private operatorSummary: OperatorSummary;
  private lastPrimaryPathId: string | null = null;

  // ── Stability guards (Phase 12A) ──────────────────────────────────
  private recentReasoningKeys = new Set<string>();  // dedup window
  private recentCanvasKeys = new Set<string>();
  private lastPrimaryScore = 0;
  private readonly PRIMARY_PATH_THRESHOLD = 10;     // min score diff to switch primary
  private readonly REASONING_DEDUP_WINDOW_MS = 2000; // suppress same message within 2s
  private lastReasoningTimestamps = new Map<string, number>();
  private lastSummaryJson = '';                      // suppress unchanged summary broadcasts

  // ── LLM reasoning removed from engine hot path ────────────────────
  // LLM reasoning adds zero operational value during engine execution.
  // Deterministic reasoning is always used. LLM will be reintroduced
  // in the report/UI/Jarvis layer, not the engine hot path.
  private llmRouter: LlmRouter;
  private reasoningLlmCalls = 0;
  private readonly MAX_REASONING_LLM_CALLS = 0;

  constructor(chainId: string) {
    this.chainId = chainId;
    this.llmRouter = new LlmRouter();
    this.memory = {
      surfaces: { highValue: [], failed: [], classified: new Map() },
      artifacts: { tokens: [], identifiers: [], schemaHints: [], credentials: [] },
      paths: { primaryId: null, primaryScore: 0, totalPaths: 0 },
      failures: { unreachable: [], rejected: [], noEvidence: [] },
      stats: { reasoningEvents: 0, canvasEvents: 0, replaySuccesses: 0 },
    };
    this.operatorSummary = {
      currentObjective: 'Initializing surface discovery',
      currentPrimarySurface: '',
      activeArtifact: null,
      currentPrimaryPath: null,
      currentTrustZone: 'unknown',
      currentSensitivity: 'generic',
      lastMeaningfulChange: 'Engine started',
      findingsCount: 0,
      pathsCount: 0,
      replaySuccesses: 0,
    };
  }

  // ── Reasoning Emission ───────────────────────────────────────────────

  reason(
    intent: ReasoningIntent,
    target: string,
    message: string,
    context?: ReasoningEvent['context'],
    enrichment?: { detail?: string; technique?: string; credentialType?: string },
  ): void {
    // Spam suppression: skip identical message within dedup window
    const dedupKey = `${intent}:${target}:${message}`;
    const now = Date.now();
    const lastSeen = this.lastReasoningTimestamps.get(dedupKey);
    if (lastSeen && now - lastSeen < this.REASONING_DEDUP_WINDOW_MS) {
      return; // suppress duplicate
    }
    this.lastReasoningTimestamps.set(dedupKey, now);

    // LLM reasoning removed from engine hot path — deterministic only.

    const event: ReasoningEvent = {
      timestamp: new Date().toISOString(),
      chainId: this.chainId,
      intent,
      target,
      message,
      detail: enrichment?.detail,
      technique: enrichment?.technique,
      credentialType: enrichment?.credentialType,
      context,
    };

    // Bounded buffer: keep last 100 events
    this.events.push(event);
    if (this.events.length > 100) this.events = this.events.slice(-100);

    this.memory.stats.reasoningEvents++;
    console.log(`[REASON:${intent}] ${message}${target ? ` → ${target}` : ''}`);

    // Broadcast through existing WebSocket channel
    try {
      const { intent: _t, chainId: _c, ...rest } = event;
      wsService.broadcastToChannel(`breach_chain:${this.chainId}`, {
        type: 'reasoning_event',
        chainId: this.chainId,
        reasoningIntent: event.intent,
        ...rest,
      } as any);
    } catch { /* wsService not initialized (test/CLI context) */ }
  }

  // ── Canvas Emission ──────────────────────────────────────────────────

  canvas(type: CanvasEventType, opts: Partial<Omit<CanvasEvent, 'timestamp' | 'chainId' | 'type'>> = {}): void {
    // Canvas dedup: skip identical source+type within same run
    const canvasKey = `${type}:${opts.source || ''}:${opts.target || ''}:${opts.detail || ''}`;
    if (this.recentCanvasKeys.has(canvasKey) && type !== 'primary_path_changed') {
      return; // suppress duplicate canvas event
    }
    this.recentCanvasKeys.add(canvasKey);

    const event: CanvasEvent = {
      timestamp: new Date().toISOString(),
      chainId: this.chainId,
      type,
      confirmed: false,
      ...opts,
    };

    // Bounded buffer: keep last 250 canvas events
    this.canvasEvents.push(event);
    if (this.canvasEvents.length > 250) this.canvasEvents = this.canvasEvents.slice(-250);

    this.memory.stats.canvasEvents++;

    // Broadcast through existing WebSocket channel
    try {
      const { type: _ct, chainId: _cc, ...canvasRest } = event;
      wsService.broadcastToChannel(`breach_chain:${this.chainId}`, {
        type: 'canvas_event',
        chainId: this.chainId,
        canvasType: event.type,
        ...canvasRest,
      } as any);
    } catch { /* wsService not initialized (test/CLI context) */ }
  }

  /** Broadcast current operator summary to frontend — only if changed */
  broadcastSummary(): void {
    const currentJson = JSON.stringify(this.operatorSummary);
    if (currentJson === this.lastSummaryJson) return; // no change — suppress
    this.lastSummaryJson = currentJson;
    try {
      wsService.broadcastToChannel(`breach_chain:${this.chainId}`, {
        type: 'operator_summary',
        chainId: this.chainId,
        ...this.operatorSummary,
      } as any);
    } catch { /* wsService not initialized */ }
  }

  // ── LLM-Assisted Reasoning ─────────────────────────────────────────

  /**
   * LLM reasoning removed from engine hot path.
   * Always returns null — deterministic messages are used instead.
   * Kept as a stub so the method signature survives for post-run summary reintroduction.
   */
  async generateReasoningLine(_intent: ReasoningIntent, _target: string, _context: string): Promise<string | null> {
    return null;
  }

  // ── LLM Reasoning Qualification (removed from hot path) ─────────────
  // qualifiesForLlmReasoning() removed — LLM reasoning is no longer
  // called during engine execution. Will be reintroduced in the
  // report/UI/Jarvis layer.

  // ── Surface Intelligence Hooks ───────────────────────────────────────

  onEndpointDiscovered(url: string, zone: string, sensitivity: string, role: string): void {
    const shortUrl = url.replace(/^https?:\/\/[^/]+/, '');
    this.memory.surfaces.classified.set(url, { zone, sensitivity, role });
    this.canvas('node_discovered', { source: url, zone, sensitivity, confirmed: true, label: shortUrl });

    if (role === 'target' || zone === 'privileged') {
      this.memory.surfaces.highValue.push(url);
      this.canvas('node_classified', {
        source: url, zone, sensitivity, confirmed: true,
        detail: `High-value ${role}`, severity: 'high', label: shortUrl,
      });
      this.reason('explore', url,
        `${zone} ${sensitivity} surface ${shortUrl} identified as ${role}`, { zone, sensitivity, role }, {
          detail: `High-value target: ${shortUrl} (${zone}/${sensitivity})`,
        },
      );
    }
  }

  onSurfaceModelBuilt(entryPoints: string[], targets: string[], highValue: string[]): void {
    this.operatorSummary.currentObjective = 'Surface mapped — beginning exploit phase';
    this.operatorSummary.currentPrimarySurface = highValue[0] || entryPoints[0] || '';
    this.reason('summarize', '', `Surface mapped: ${entryPoints.length} entries, ${targets.length} targets, ${highValue.length} high-value`, {
      zone: 'mixed',
    });
    this.broadcastSummary();
  }

  // ── Exploit Hooks ────────────────────────────────────────────────────

  onExploitAttempt(target: string, vulnClass: string, zone?: string, sensitivity?: string): void {
    const shortTarget = target.replace(/^https?:\/\/[^/]+/, '');
    this.operatorSummary.currentObjective = `Testing ${vulnClass} on ${shortTarget}`;
    this.reason('exploit', target, `${vulnClass} probe on ${shortTarget}`, { zone, sensitivity }, {
      detail: `Testing ${vulnClass} against ${shortTarget}${zone ? ` (${zone} zone)` : ''}`,
      technique: vulnClass,
    });
  }

  onExploitValidated(
    target: string,
    vulnClass: string,
    confidence: string,
    opts?: { matchedPatterns?: string[]; extractedData?: string[]; statusCode?: number; payloadName?: string },
  ): void {
    const shortTarget = target.replace(/^https?:\/\/[^/]+/, '');
    const pName = opts?.payloadName || vulnClass;
    const patternCount = opts?.matchedPatterns?.length || 0;
    const extractCount = opts?.extractedData?.length || 0;
    const httpNote = opts?.statusCode ? ` HTTP ${opts.statusCode}` : '';

    // Build rich detail line
    let detail = `${pName} confirmed on ${shortTarget}${httpNote}`;
    if (patternCount > 0) detail += ` — ${patternCount} pattern match${patternCount > 1 ? 'es' : ''}`;
    if (extractCount > 0) detail += `, ${extractCount} data item${extractCount > 1 ? 's' : ''} extracted`;

    this.operatorSummary.lastMeaningfulChange = detail;
    this.operatorSummary.findingsCount++;
    this.canvas('edge_confirmed', {
      source: target,
      detail: pName,
      confirmed: true,
      technique: vulnClass,
      severity: 'high',
      confidence,
      statusCode: opts?.statusCode,
    });
    this.reason('validate', target, detail, { confidence }, {
      detail,
      technique: vulnClass,
    });
  }

  onExploitRejected(target: string, vulnClass: string, reason: string): void {
    this.memory.failures.noEvidence.push(`${vulnClass}@${target}`);
  }

  onExploitGated(target: string, vulnClass: string, reason: string): void {
    // Silent — don't emit for gated skips (too noisy)
  }

  // ── Artifact Hooks ───────────────────────────────────────────────────

  onArtifactGained(type: string, source: string, detail: string): void {
    const shortSource = source.replace(/^https?:\/\/[^/]+/, '');
    const masked = maskCredential(detail);

    if (/token|jwt|session|cookie|bearer/i.test(type)) {
      this.memory.artifacts.tokens.push(detail);
      this.operatorSummary.activeArtifact = detail;
      this.canvas('artifact_gained', { source, detail: `${type}: ${masked}`, confirmed: true, credentialType: type });
      this.reason('pivot', source,
        `${type} harvested from ${shortSource} — replaying against authenticated zones`, {
          artifact: masked,
        }, {
          detail: `${type} harvested: ${masked} from ${shortSource} — replay candidates narrowed`,
          technique: 'credential harvest',
          credentialType: type,
        },
      );
    } else if (/id|userId|accountId|identifier/i.test(type)) {
      this.memory.artifacts.identifiers.push(detail);
      this.reason('pivot', source,
        `Identifier extracted from ${shortSource}: ${masked} — prioritizing related endpoints`, {
          artifact: masked,
        }, {
          detail: `${type} identifier: ${masked} from ${shortSource}`,
          credentialType: type,
        },
      );
    } else if (/schema|graphql|mutation/i.test(type)) {
      this.memory.artifacts.schemaHints.push(detail);
      this.reason('escalate', source,
        `Schema hints from ${shortSource} — deeper mutation/field probing now viable`, undefined, {
          detail: `Schema discovery at ${shortSource}: ${detail.slice(0, 60)}`,
          technique: 'schema introspection',
        },
      );
    } else {
      this.memory.artifacts.credentials.push(detail);
      this.canvas('artifact_gained', { source, detail: `${type}: ${masked}`, confirmed: true, credentialType: type });
      this.reason('pivot', source,
        `Credential extracted from ${shortSource}: ${type} ${masked}`, {
          artifact: masked,
        }, {
          detail: `Credential: ${type} ${masked} from ${shortSource}`,
          technique: 'credential extraction',
          credentialType: type,
        },
      );
    }
  }

  // ── Replay Hooks ─────────────────────────────────────────────────────

  onReplayStarted(target: string, artifact: string, reason: string): void {
    const shortTarget = target.replace(/^https?:\/\/[^/]+/, '');
    this.operatorSummary.currentObjective = `Replaying against ${shortTarget}`;
    this.canvas('replay_started', { target, detail: reason, confirmed: false });
    this.reason('replay', target,
      `Replaying ${maskCredential(artifact)} against ${shortTarget} — ${reason}`, undefined, {
        detail: `Session replay: ${maskCredential(artifact)} on ${shortTarget} — ${reason}`,
        technique: 'session replay',
      },
    );
  }

  onReplaySucceeded(target: string, artifact: string, result: string): void {
    const shortTarget = target.replace(/^https?:\/\/[^/]+/, '');
    this.memory.stats.replaySuccesses++;
    this.operatorSummary.replaySuccesses++;
    this.operatorSummary.lastMeaningfulChange = `Replay accepted on ${shortTarget} — ${result}`;
    this.canvas('replay_succeeded', { target, detail: result, confirmed: true, technique: 'session replay' });
    this.reason('escalate', target,
      `Replay ACCEPTED on ${shortTarget} — ${result}`, {
        artifact: maskCredential(artifact), role: 'replay-success',
      }, {
        detail: `Replay accepted: ${maskCredential(artifact)} on ${shortTarget} — ${result}`,
        technique: 'session replay',
      },
    );
  }

  onReplayFailed(target: string, reason: string): void {
    const shortTarget = target.replace(/^https?:\/\/[^/]+/, '');
    this.canvas('replay_failed', { target, detail: reason, confirmed: false });
    // Emit reasoning for replay failures on high-value targets so LLM can provide insight
    const surfaceInfo = this.memory.surfaces.classified.get(target);
    if (surfaceInfo && (surfaceInfo.zone === 'privileged' || surfaceInfo.sensitivity === 'admin' || surfaceInfo.sensitivity === 'config')) {
      this.reason('replay', target,
        `Replay REJECTED on ${shortTarget} — ${reason}`, {
          zone: surfaceInfo.zone,
          sensitivity: surfaceInfo.sensitivity,
        }, {
          detail: `Replay rejected on high-value ${shortTarget}: ${reason}`,
          technique: 'session replay',
        },
      );
    } else if (this.memory.surfaces.highValue.includes(target)) {
      this.reason('replay', target,
        `Replay REJECTED on ${shortTarget} — ${reason}`, {
          zone: 'privileged',
        }, {
          detail: `Replay rejected on high-value ${shortTarget}: ${reason}`,
          technique: 'session replay',
        },
      );
    }
  }

  // ── Path Hooks ───────────────────────────────────────────────────────

  onPathBuilt(pathId: string, name: string, score: number, confidence: string): void {
    this.memory.paths.totalPaths++;
    this.operatorSummary.pathsCount++;
    this.canvas('path_promoted', { source: pathId, detail: `${name} (${score})`, confirmed: true });
  }

  onPrimaryPathChanged(pathId: string, name: string, score: number, reason: string): void {
    const prev = this.lastPrimaryPathId;
    if (prev === pathId) return; // no change
    // Flicker prevention: only switch if score diff exceeds threshold
    if (prev && Math.abs(score - this.lastPrimaryScore) < this.PRIMARY_PATH_THRESHOLD) {
      return; // suppress small score oscillations
    }
    this.lastPrimaryPathId = pathId;
    this.lastPrimaryScore = score;
    this.memory.paths.primaryId = pathId;
    this.memory.paths.primaryScore = score;
    this.operatorSummary.currentPrimaryPath = name;
    this.operatorSummary.lastMeaningfulChange = `Primary path: ${name}`;
    this.canvas('primary_path_changed', { source: pathId, detail: reason, confirmed: true });
    this.reason('summarize', '', `${name} promoted to primary path — ${reason}`, { pathId, confidence: String(score) });
    this.broadcastSummary();
  }

  // ── Output ───────────────────────────────────────────────────────────

  getReasoningStream(): ReasoningEvent[] { return this.events; }
  getCanvasEvents(): CanvasEvent[] { return this.canvasEvents; }
  getMemory(): RunMemory { return this.memory; }
  getOperatorSummary(): OperatorSummary { return this.operatorSummary; }

  /** Compact summary for logging */
  summarize(): string {
    const s = this.operatorSummary;
    return `[OPERATOR] Objective: ${s.currentObjective} | Primary: ${s.currentPrimaryPath || 'none'} | ` +
      `Findings: ${s.findingsCount} | Paths: ${s.pathsCount} | Replays: ${s.replaySuccesses} | ` +
      `Last: ${s.lastMeaningfulChange}`;
  }
}
