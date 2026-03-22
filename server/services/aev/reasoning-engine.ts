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

  constructor(chainId: string) {
    this.chainId = chainId;
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
    const event: ReasoningEvent = {
      timestamp: new Date().toISOString(),
      chainId: this.chainId,
      intent,
      target,
      message,
      context,
    };
    this.events.push(event);
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
    const event: CanvasEvent = {
      timestamp: new Date().toISOString(),
      chainId: this.chainId,
      type,
      confirmed: false,
      ...opts,
    };
    this.canvasEvents.push(event);
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

  /** Broadcast current operator summary to frontend */
  broadcastSummary(): void {
    try {
      wsService.broadcastToChannel(`breach_chain:${this.chainId}`, {
        type: 'operator_summary',
        chainId: this.chainId,
        ...this.operatorSummary,
      } as any);
    } catch { /* wsService not initialized */ }
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
    this.reason('escalate', target, `Replay ACCEPTED — ${result}`, { artifact: artifact.slice(0, 30) });
  }

  onReplayFailed(target: string, reason: string): void {
    this.canvas('replay_failed', { target, detail: reason, confirmed: false });
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
    this.lastPrimaryPathId = pathId;
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
