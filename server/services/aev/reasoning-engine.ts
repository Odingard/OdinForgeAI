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
import { isLlmConfigured } from '../../../src/llm/config';
import { quickSafetyCheck } from '../../../src/llm/safety-boundary';
import { recordLlmFailure } from '../../../src/llm/router-health';

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
  context?: {
    artifact?: string;
    zone?: string;
    sensitivity?: string;
    role?: string;
    pathId?: string;
    confidence?: string;
  };
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

  // ── LLM-assisted reasoning (demoted: target 3-5 calls per run) ────
  private llmRouter: LlmRouter;
  private reasoningLlmCalls = 0;
  private readonly MAX_REASONING_LLM_CALLS = 5;
  // Only high-signal intents qualify for LLM reasoning
  private readonly MEANINGFUL_INTENTS = new Set<ReasoningIntent>(['escalate', 'replay', 'summarize']);

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

  reason(intent: ReasoningIntent, target: string, message: string, context?: ReasoningEvent['context']): void {
    // Spam suppression: skip identical message within dedup window
    const dedupKey = `${intent}:${target}:${message}`;
    const now = Date.now();
    const lastSeen = this.lastReasoningTimestamps.get(dedupKey);
    if (lastSeen && now - lastSeen < this.REASONING_DEDUP_WINDOW_MS) {
      return; // suppress duplicate
    }
    this.lastReasoningTimestamps.set(dedupKey, now);

    // For meaningful intents with qualifying context, try LLM-assisted reasoning (fire-and-forget).
    // The deterministic message is always emitted immediately; LLM result
    // supplements it as a follow-on event if it returns in time.
    // Target: 3-5 LLM reasoning lines per run.
    const shouldCallLlm = this.MEANINGFUL_INTENTS.has(intent) && this.qualifiesForLlmReasoning(intent, target, message, context);
    if (shouldCallLlm && isLlmConfigured() && this.reasoningLlmCalls < this.MAX_REASONING_LLM_CALLS) {
      const contextSummary = context ? Object.entries(context).map(([k, v]) => `${k}=${v}`).join(', ') : '';
      this.generateReasoningLine(intent, target, `${message} | ${contextSummary}`).then(llmLine => {
        if (llmLine) {
          // Emit a supplementary LLM-enhanced reasoning event
          const llmEvent: ReasoningEvent = {
            timestamp: new Date().toISOString(),
            chainId: this.chainId,
            intent,
            target,
            message: llmLine,
            context: { ...context, role: 'llm-enhanced' },
          };
          this.events.push(llmEvent);
          if (this.events.length > 100) this.events = this.events.slice(-100);
          try {
            const { intent: _lt, chainId: _lc, ...llmRest } = llmEvent;
            wsService.broadcastToChannel(`breach_chain:${this.chainId}`, {
              type: 'reasoning_event',
              chainId: this.chainId,
              reasoningIntent: llmEvent.intent,
              ...llmRest,
            } as any);
          } catch { /* wsService not initialized */ }
        }
      }).catch(() => { /* LLM failure — deterministic message already emitted */ });
    }

    const event: ReasoningEvent = {
      timestamp: new Date().toISOString(),
      chainId: this.chainId,
      intent,
      target,
      message,
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
   * Generate a concise reasoning line via LLM. Falls back to null on failure.
   * Only called for meaningful intents, never for spam-suppressed events.
   */
  async generateReasoningLine(intent: ReasoningIntent, target: string, context: string): Promise<string | null> {
    if (!isLlmConfigured()) return null;
    if (this.reasoningLlmCalls >= this.MAX_REASONING_LLM_CALLS) return null;

    try {
      this.reasoningLlmCalls++;
      const resp = await this.llmRouter.reasoningStream([
        {
          role: 'system',
          content: 'Produce exactly one concise operator-facing reasoning line. Maximum 18 words. Deterministic, no fluff, no speculation, no unsupported adjectives.',
        },
        {
          role: 'user',
          content: `Intent: ${intent}\nTarget: ${target}\nContext: ${context}`,
        },
      ]);

      const text = resp.text.trim();
      if (!text || !quickSafetyCheck(text)) return null;
      // Truncate to reasonable single-line length
      return text.slice(0, 300);
    } catch (err) {
      recordLlmFailure('reasoning_stream', 'router', 'auto', err instanceof Error ? err.message : String(err));
      return null;
    }
  }

  // ── LLM Reasoning Qualification ──────────────────────────────────────

  /**
   * Determines if this reasoning event qualifies for an LLM call.
   * Demoted: target 3-5 LLM reasoning lines per run, not 0 and not 20.
   *
   * Only returns true for:
   * - Primary path promoted or demoted
   * - Replay succeeded
   * - Replay failed on high-value target
   * - Convergence summary
   * - Final operator summary
   */
  private qualifiesForLlmReasoning(intent: ReasoningIntent, target: string, message: string, context?: ReasoningEvent['context']): boolean {
    // Avoid recursion from LLM-enhanced events
    if (context?.role === 'llm-enhanced') return false;

    // Combine target + message for keyword matching (target is often '' for summarize calls)
    const text = `${target || ''} ${message || ''}`;

    switch (intent) {
      case 'escalate':
        // Replay succeeded (onReplaySucceeded emits escalate with artifact + role='replay-success')
        if (context?.role === 'replay-success') {
          console.log(`[LLM:reasoning] Qualified: ${intent} → replay succeeded on ${target}`);
          return true;
        }
        // Primary path promotion/demotion (role change with pathId)
        if (context?.pathId) {
          console.log(`[LLM:reasoning] Qualified: ${intent} → path promotion ${context.pathId}`);
          return true;
        }
        // Only log skip for replay-like escalations (have artifact), not for schema hints etc.
        if (context?.artifact) {
          console.log(`[LLM:reasoning] Skipped: ${intent} — artifact present but no replay-success role`);
        }
        return false;

      case 'replay':
        // Replay succeeded (keyword match)
        if (/ACCEPTED|succeeded/i.test(text)) {
          console.log(`[LLM:reasoning] Qualified: ${intent} → replay succeeded on ${target}`);
          return true;
        }
        // Replay failed on high-value target
        if (context?.zone === 'privileged' || context?.sensitivity === 'admin' || context?.sensitivity === 'config') {
          console.log(`[LLM:reasoning] Qualified: ${intent} → replay failed on high-value ${target}`);
          return true;
        }
        return false;

      case 'summarize':
        // Primary path change (onPrimaryPathChanged passes pathId in context)
        if (context?.pathId) {
          console.log(`[LLM:reasoning] Qualified: ${intent} → primary path promoted ${context.pathId}`);
          return true;
        }
        // Convergence summary or final operator summary (keywords in message, not just target)
        if (/converge|final|complete|OPERATOR/i.test(text)) {
          console.log(`[LLM:reasoning] Qualified: ${intent} → convergence/final summary`);
          return true;
        }
        console.log(`[LLM:reasoning] Skipped: ${intent} — no pathId or convergence/final keywords`);
        return false;

      default:
        // explore, validate, exploit, pivot — no LLM reasoning
        return false;
    }
  }

  // ── Surface Intelligence Hooks ───────────────────────────────────────

  onEndpointDiscovered(url: string, zone: string, sensitivity: string, role: string): void {
    this.memory.surfaces.classified.set(url, { zone, sensitivity, role });
    this.canvas('node_discovered', { source: url, zone, sensitivity, confirmed: true });

    if (role === 'target' || zone === 'privileged') {
      this.memory.surfaces.highValue.push(url);
      this.canvas('node_classified', { source: url, zone, sensitivity, confirmed: true, detail: `High-value ${role}` });
      this.reason('explore', url, `${zone} ${sensitivity} surface identified as ${role}`, { zone, sensitivity, role });
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
    this.operatorSummary.currentObjective = `Testing ${vulnClass} on ${target}`;
    this.reason('exploit', target, `Attempting ${vulnClass}`, { zone, sensitivity });
  }

  onExploitValidated(target: string, vulnClass: string, confidence: string): void {
    this.operatorSummary.lastMeaningfulChange = `${vulnClass} confirmed on ${target}`;
    this.operatorSummary.findingsCount++;
    this.canvas('edge_confirmed', { source: target, detail: vulnClass, confirmed: true });
    this.reason('validate', target, `${vulnClass} CONFIRMED (${confidence})`, { confidence });
  }

  onExploitRejected(target: string, vulnClass: string, reason: string): void {
    this.memory.failures.noEvidence.push(`${vulnClass}@${target}`);
  }

  onExploitGated(target: string, vulnClass: string, reason: string): void {
    // Silent — don't emit for gated skips (too noisy)
  }

  // ── Artifact Hooks ───────────────────────────────────────────────────

  onArtifactGained(type: string, source: string, detail: string): void {
    if (/token|jwt|session|cookie|bearer/i.test(type)) {
      this.memory.artifacts.tokens.push(detail);
      this.operatorSummary.activeArtifact = detail;
      this.canvas('artifact_gained', { source, detail: `${type}: ${detail.slice(0, 40)}`, confirmed: true });
      this.reason('pivot', source, `${type} harvested — replay candidates narrowed to authenticated and privileged zones`, {
        artifact: detail.slice(0, 40),
      });
    } else if (/id|userId|accountId|identifier/i.test(type)) {
      this.memory.artifacts.identifiers.push(detail);
      this.reason('pivot', source, `Identifier extracted — prioritizing related resource family endpoints`, {
        artifact: detail.slice(0, 40),
      });
    } else if (/schema|graphql|mutation/i.test(type)) {
      this.memory.artifacts.schemaHints.push(detail);
      this.reason('escalate', source, `Schema hints expanded — deeper mutation/field probing now viable`);
    } else {
      this.memory.artifacts.credentials.push(detail);
      this.canvas('artifact_gained', { source, detail: `${type}: ${detail.slice(0, 40)}`, confirmed: true });
      this.reason('pivot', source, `Credential extracted: ${type}`, { artifact: detail.slice(0, 40) });
    }
  }

  // ── Replay Hooks ─────────────────────────────────────────────────────

  onReplayStarted(target: string, artifact: string, reason: string): void {
    this.operatorSummary.currentObjective = `Replaying against ${target}`;
    this.canvas('replay_started', { target, detail: reason, confirmed: false });
    this.reason('replay', target, `Replaying ${artifact.slice(0, 30)} — ${reason}`);
  }

  onReplaySucceeded(target: string, artifact: string, result: string): void {
    this.memory.stats.replaySuccesses++;
    this.operatorSummary.replaySuccesses++;
    this.operatorSummary.lastMeaningfulChange = `Replay succeeded against ${target}`;
    this.canvas('replay_succeeded', { target, detail: result, confirmed: true });
    this.reason('escalate', target, `Replay ACCEPTED — ${result}`, { artifact: artifact.slice(0, 30), role: 'replay-success' });
  }

  onReplayFailed(target: string, reason: string): void {
    this.canvas('replay_failed', { target, detail: reason, confirmed: false });
    // Emit reasoning for replay failures on high-value targets so LLM can provide insight
    const surfaceInfo = this.memory.surfaces.classified.get(target);
    if (surfaceInfo && (surfaceInfo.zone === 'privileged' || surfaceInfo.sensitivity === 'admin' || surfaceInfo.sensitivity === 'config')) {
      this.reason('replay', target, `Replay REJECTED on high-value target — ${reason}`, {
        zone: surfaceInfo.zone,
        sensitivity: surfaceInfo.sensitivity,
      });
    } else if (this.memory.surfaces.highValue.includes(target)) {
      this.reason('replay', target, `Replay REJECTED on high-value target — ${reason}`, {
        zone: 'privileged',
      });
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
