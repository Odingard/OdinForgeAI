# OdinForge AEV — Live Graph Upgrade

All changes from the live graph rebuild session. Apply in order.

---

## 1. Fix dev server startup (pre-existing bug)

**File:** `server/static.ts`

Replace the entire file:

```ts
import express, { type Express } from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function serveStatic(app: Express) {
  const distPath = path.resolve(__dirname, "public");
  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`,
    );
  }

  app.use(express.static(distPath));

  app.use("*", (_req, res) => {
    res.sendFile(path.resolve(distPath, "index.html"));
  });
}
```

---

## 2. New file — client-side breach event types

**Create:** `client/src/lib/breach-events.ts`

```ts
/**
 * Client-side breach event types.
 * Mirrors server/lib/breach-event-emitter.ts — no server imports.
 */

export type BreachNodeKind =
  | "phase_spine" | "finding" | "credential"
  | "iam_path" | "k8s_escape" | "pivot_hop"
  | "data_store" | "dead_end";

export type BreachNodeSeverity = "critical" | "high" | "medium" | "low" | "info";

export type BreachPhaseId =
  | "application_compromise" | "credential_extraction"
  | "cloud_iam_escalation" | "container_k8s_breakout"
  | "lateral_movement" | "impact_assessment";

export type SurfaceSignalKind =
  | "stack" | "endpoint" | "cloud" | "secret" | "port" | "domain";

export interface BreachNodeAddedEvent {
  type: "breach_node_added";
  chainId: string;
  nodeId: string;
  kind: BreachNodeKind;
  phase: BreachPhaseId;
  phaseIndex: number;
  label: string;
  detail: string;
  severity: BreachNodeSeverity;
  technique?: string;
  evidenceRef?: string;
  curlCommand?: string;
  targetUrl?: string;
  statusCode?: number;
  responseSnippet?: string;
  timestamp: string;
}

export interface BreachEdgeAddedEvent {
  type: "breach_edge_added";
  chainId: string;
  edgeId: string;
  fromNodeId: string;
  toNodeId: string;
  label?: string;
  confirmed: boolean;
  timestamp: string;
}

export interface BreachSurfaceSignalEvent {
  type: "breach_surface_signal";
  chainId: string;
  signalId: string;
  kind: SurfaceSignalKind;
  label: string;
  detail: string;
  confidence: "confirmed" | "probable" | "detected";
  timestamp: string;
}

export interface BreachReasoningEvent {
  type: "breach_reasoning";
  chainId: string;
  phase: BreachPhaseId;
  agentId: string;
  decision: string;
  rationale: string;
  techniqueTried?: string;
  outcome: "confirmed" | "failed" | "pivoting" | "investigating";
  linkedNodeId?: string;
  timestamp: string;
}

export interface BreachPhaseTransitionEvent {
  type: "breach_phase_transition";
  chainId: string;
  fromPhase: BreachPhaseId | null;
  toPhase: BreachPhaseId;
  phaseIndex: number;
  findingCount: number;
  credentialCount: number;
  summary: string;
  timestamp: string;
}
```

---

## 3. New file — server-side breach event emitter

**Create:** `server/lib/breach-event-emitter.ts`

```ts
import { wsService } from "../services/websocket";

export type BreachNodeKind =
  | "phase_spine" | "finding" | "credential"
  | "iam_path" | "k8s_escape" | "pivot_hop"
  | "data_store" | "dead_end";

export type BreachNodeSeverity = "critical" | "high" | "medium" | "low" | "info";

export type BreachPhaseId =
  | "application_compromise" | "credential_extraction"
  | "cloud_iam_escalation" | "container_k8s_breakout"
  | "lateral_movement" | "impact_assessment";

export type SurfaceSignalKind =
  | "stack" | "endpoint" | "cloud" | "secret" | "port" | "domain";

export interface BreachNodeAddedEvent {
  type: "breach_node_added";
  chainId: string;
  nodeId: string;
  kind: BreachNodeKind;
  phase: BreachPhaseId;
  phaseIndex: number;
  label: string;
  detail: string;
  severity: BreachNodeSeverity;
  technique?: string;
  evidenceRef?: string;
  curlCommand?: string;
  targetUrl?: string;
  statusCode?: number;
  responseSnippet?: string;
  timestamp: string;
}

export interface BreachEdgeAddedEvent {
  type: "breach_edge_added";
  chainId: string;
  edgeId: string;
  fromNodeId: string;
  toNodeId: string;
  label?: string;
  confirmed: boolean;
  timestamp: string;
}

export interface BreachSurfaceSignalEvent {
  type: "breach_surface_signal";
  chainId: string;
  signalId: string;
  kind: SurfaceSignalKind;
  label: string;
  detail: string;
  confidence: "confirmed" | "probable" | "detected";
  timestamp: string;
}

export interface BreachReasoningEvent {
  type: "breach_reasoning";
  chainId: string;
  phase: BreachPhaseId;
  agentId: string;
  decision: string;
  rationale: string;
  techniqueTried?: string;
  outcome: "confirmed" | "failed" | "pivoting" | "investigating";
  linkedNodeId?: string;
  timestamp: string;
}

export interface BreachPhaseTransitionEvent {
  type: "breach_phase_transition";
  chainId: string;
  fromPhase: BreachPhaseId | null;
  toPhase: BreachPhaseId;
  phaseIndex: number;
  findingCount: number;
  credentialCount: number;
  summary: string;
  timestamp: string;
}

export type BreachEvent =
  | BreachNodeAddedEvent
  | BreachEdgeAddedEvent
  | BreachSurfaceSignalEvent
  | BreachReasoningEvent
  | BreachPhaseTransitionEvent;

export class BreachEventEmitter {
  private chainId: string;
  private nodeIndex = 0;
  private edgeIndex = 0;
  private signalIndex = 0;

  constructor(chainId: string) {
    this.chainId = chainId;
  }

  surfaceSignal(
    kind: SurfaceSignalKind,
    label: string,
    detail: string,
    confidence: BreachSurfaceSignalEvent["confidence"] = "confirmed"
  ): string {
    const signalId = `sig-${this.signalIndex++}-${Date.now()}`;
    wsService.broadcastBreachEvent(this.chainId, {
      type: "breach_surface_signal",
      chainId: this.chainId, signalId, kind, label, detail, confidence,
      timestamp: new Date().toISOString(),
    });
    return signalId;
  }

  nodeAdded(params: Omit<BreachNodeAddedEvent, "type"|"chainId"|"nodeId"|"timestamp">): string {
    const nodeId = `node-${this.nodeIndex++}-${Date.now()}`;
    wsService.broadcastBreachEvent(this.chainId, {
      type: "breach_node_added",
      chainId: this.chainId, nodeId,
      timestamp: new Date().toISOString(), ...params,
    });
    return nodeId;
  }

  edgeAdded(fromNodeId: string, toNodeId: string, confirmed: boolean, label?: string): string {
    const edgeId = `edge-${this.edgeIndex++}-${Date.now()}`;
    wsService.broadcastBreachEvent(this.chainId, {
      type: "breach_edge_added",
      chainId: this.chainId, edgeId, fromNodeId, toNodeId, label, confirmed,
      timestamp: new Date().toISOString(),
    });
    return edgeId;
  }

  reasoning(
    phase: BreachPhaseId, agentId: string, decision: string, rationale: string,
    outcome: BreachReasoningEvent["outcome"],
    opts?: { techniqueTried?: string; linkedNodeId?: string }
  ): void {
    wsService.broadcastBreachEvent(this.chainId, {
      type: "breach_reasoning",
      chainId: this.chainId, phase, agentId, decision, rationale, outcome,
      techniqueTried: opts?.techniqueTried, linkedNodeId: opts?.linkedNodeId,
      timestamp: new Date().toISOString(),
    });
  }

  phaseTransition(
    fromPhase: BreachPhaseId | null, toPhase: BreachPhaseId, phaseIndex: number,
    findingCount: number, credentialCount: number, summary: string
  ): void {
    wsService.broadcastBreachEvent(this.chainId, {
      type: "breach_phase_transition",
      chainId: this.chainId, fromPhase, toPhase, phaseIndex,
      findingCount, credentialCount, summary,
      timestamp: new Date().toISOString(),
    });
  }
}

export function createBreachEventEmitter(chainId: string): BreachEventEmitter {
  return new BreachEventEmitter(chainId);
}
```

---

## 4. Edit — websocket.ts

**File:** `server/services/websocket.ts`

**Change A** — find this line:
```ts
type WebSocketEvent = AEVProgressEvent | AEVCompleteEvent | SimulationProgressEvent | ReconProgressEvent | HeartbeatEvent | ScanProgressEvent | SafetyBlockEvent | ReasoningTraceEvent | SharedMemoryUpdateEvent | HITLApprovalEvent | BreachChainGraphUpdateEvent | BreachChainLiveEvent;
```

Replace with:
```ts
import type { BreachEvent } from "../lib/breach-event-emitter";
type WebSocketEvent = AEVProgressEvent | AEVCompleteEvent | SimulationProgressEvent | ReconProgressEvent | HeartbeatEvent | ScanProgressEvent | SafetyBlockEvent | ReasoningTraceEvent | SharedMemoryUpdateEvent | HITLApprovalEvent | BreachChainGraphUpdateEvent | BreachChainLiveEvent | BreachEvent;
```

**Change B** — find `getStats(): {` and insert this block BEFORE it:

```ts
  broadcastBreachEvent(chainId: string, event: BreachEvent): void {
    this.broadcastToChannel(`breach_chain:${chainId}`, event as unknown as WebSocketEvent);
  }

```

---

## 5. Edit — breach-orchestrator.ts

**File:** `server/services/breach-orchestrator.ts`

**Change A** — find:
```ts
import { ReplayRecorder, type EngagementReplayManifest } from "./replay-recorder";
```
Replace with:
```ts
import { ReplayRecorder, type EngagementReplayManifest } from "./replay-recorder";
import { createBreachEventEmitter, type BreachEventEmitter } from "../lib/breach-event-emitter";
```

**Change B** — find:
```ts
const phase1AEvidenceStore = new Map<string, ExploitAttempt[]>();
```
Replace with:
```ts
const phase1AEvidenceStore = new Map<string, ExploitAttempt[]>();

import type { BreachEventEmitter } from "../lib/breach-event-emitter";
const chainEmitterStore = new Map<string, BreachEventEmitter>();
```

**Change C** — find this block (around line 440):
```ts
  const replayRecorder = new ReplayRecorder(chainId);
  const defendersMirror = new DefendersMirror();
  const reachabilityBuilder = new ReachabilityChainBuilder();

  // ── GTM v1.0: Prometheus metrics — engagement start ──────────────────
  recordEngagementStart();
```
Replace with:
```ts
  const replayRecorder = new ReplayRecorder(chainId);
  const defendersMirror = new DefendersMirror();
  const reachabilityBuilder = new ReachabilityChainBuilder();

  const breachEmitter = createBreachEventEmitter(chainId);
  chainEmitterStore.set(chainId, breachEmitter);

  const PHASE_IDS = [
    "application_compromise", "credential_extraction", "cloud_iam_escalation",
    "container_k8s_breakout", "lateral_movement", "impact_assessment",
  ] as const;
  const spineNodeIds: Record<string, string> = {};
  PHASE_IDS.forEach((phaseId, idx) => {
    const nodeId = breachEmitter.nodeAdded({
      kind: "phase_spine", phase: phaseId, phaseIndex: idx,
      label: PHASE_DEFINITIONS[phaseId]?.displayName ?? phaseId,
      detail: `Phase ${idx + 1} — awaiting execution`, severity: "info",
    });
    spineNodeIds[phaseId] = nodeId;
    if (idx > 0) {
      breachEmitter.edgeAdded(spineNodeIds[PHASE_IDS[idx - 1]], nodeId, false);
    }
  });

  // ── GTM v1.0: Prometheus metrics — engagement start ──────────────────
  recordEngagementStart();
```

**Change D** — in the phase loop, find the block that starts:
```ts
      // ── GTM v1.0: Evidence Quality Gate — classify all findings ──────────
```
After the `evidenceQualityGate.evaluateBatch` call and after `defendersMirror.generateBatch`, find:
```ts
      // Record each finding as a replay event with quality + mirror refs
      for (let i = 0; i < phaseResult.findings.length; i++) {
```
Insert BEFORE that line:
```ts
      const phaseIdx = enabledPhases.indexOf(phaseName);
      const prevPhase = phaseIdx > 0 ? (enabledPhases[phaseIdx - 1] as import("../lib/breach-event-emitter").BreachPhaseId) : null;
      breachEmitter.phaseTransition(
        prevPhase,
        phaseName as import("../lib/breach-event-emitter").BreachPhaseId,
        phaseIdx, phaseResult.findings.length,
        phaseResult.outputContext?.credentials?.length ?? 0,
        `${PHASE_DEFINITIONS[phaseName]?.displayName} complete — ${qualityVerdict.summary.proven} proven`,
      );
      const spineNodeId = spineNodeIds[phaseName];

```

**Change E** — inside the finding loop, find:
```ts
        replayRecorder.record({
          eventType: f.severity === "critical" ? "exploit_success" : "exploit_attempt",
```
Insert BEFORE that line:
```ts
        const isReal = verdict?.quality === "PROVEN" || verdict?.quality === "CORROBORATED";
        if (isReal && spineNodeId) {
          const findingNodeId = breachEmitter.nodeAdded({
            kind: "finding",
            phase: phaseName as import("../lib/breach-event-emitter").BreachPhaseId,
            phaseIndex: phaseIdx,
            label: f.title?.split(" ")[0] ?? "Finding",
            detail: f.description ?? f.title,
            severity: (f.severity ?? "medium") as import("../lib/breach-event-emitter").BreachNodeSeverity,
            technique: f.mitreId,
          });
          breachEmitter.edgeAdded(spineNodeId, findingNodeId, true, f.technique ?? phaseName);
        }

```

**Change F** — after the finding loop closes (`}`), find:
```ts
      // Build incremental attack graph from all completed results so far
```
Insert BEFORE that line:
```ts
      for (const cred of phaseResult.outputContext?.credentials ?? []) {
        const credNodeId = breachEmitter.nodeAdded({
          kind: "credential",
          phase: phaseName as import("../lib/breach-event-emitter").BreachPhaseId,
          phaseIndex: phaseIdx,
          label: cred.type ?? "Credential",
          detail: `${cred.type} — access: ${cred.accessLevel}`,
          severity: cred.accessLevel === "admin" ? "critical" : "high",
        });
        if (spineNodeId) breachEmitter.edgeAdded(spineNodeId, credNodeId, true, "extracted");
      }

```

**Change G** — find the Prometheus metrics cleanup block near chain completion:
```ts
    // Record quality distribution
    for (const quality of ["proven", "corroborated", "inferred", "unverifiable"] as const) {
      const count = finalQualityVerdict.summary[quality] || 0;
      for (let i = 0; i < count; i++) recordFindingQuality(quality);
    }
```
Add after it:
```ts
    phase1AEvidenceStore.delete(chainId);
    chainEmitterStore.delete(chainId);
```

---

## 6. Edit — active-exploit-engine.ts

**File:** `server/services/active-exploit-engine.ts`

**Change A** — find the class constructor:
```ts
  constructor(target: ActiveExploitTarget, onProgress?: ExploitProgressCallback) {
    this.target = target;
    this.onProgress = onProgress;
```
Replace with:
```ts
  private onSurfaceSignal?: (kind: string, label: string, detail: string) => void;

  constructor(
    target: ActiveExploitTarget,
    onProgress?: ExploitProgressCallback,
    onSurfaceSignal?: (kind: string, label: string, detail: string) => void,
  ) {
    this.target = target;
    this.onProgress = onProgress;
    this.onSurfaceSignal = onSurfaceSignal;
```

**Change B** — find `private detectTechnologies` method and replace the entire method:
```ts
  private detectTechnologies(resp: AxiosResponse, techs: Set<string>): void {
    const headers = resp.headers;
    const addTech = (name: string) => {
      if (!techs.has(name)) {
        techs.add(name);
        this.onSurfaceSignal?.('stack', name, `Detected via response headers/body`);
      }
    };
    if (headers['x-powered-by']) addTech(headers['x-powered-by']);
    if (headers['server']) addTech(headers['server']);
    if (headers['x-aspnet-version']) addTech('ASP.NET');
    if (headers['x-drupal-cache']) addTech('Drupal');
    const body = typeof resp.data === 'string' ? resp.data : '';
    if (body.includes('wp-content')) addTech('WordPress');
    if (body.includes('__next')) addTech('Next.js');
    if (body.includes('_nuxt')) addTech('Nuxt.js');
    if (body.includes('csrfmiddlewaretoken')) addTech('Django');
    if (headers['x-request-id'] && body.includes('express')) addTech('Express.js');
    if (headers['x-amz-request-id'] || headers['x-amz-id-2']) addTech('AWS');
    if (headers['x-ms-request-id']) addTech('Azure');
    if (headers['x-goog-request-id']) addTech('GCP');
    if (headers['x-kubernetes-pf-flowschema-uid']) addTech('Kubernetes');
  }
```

**Change C** — find where endpoint is built in the crawl loop:
```ts
          const endpoint = this.buildEndpointFromResponse(path, 'GET', resp);
          if (endpoint) endpoints.push(endpoint);
```
Replace with:
```ts
          const endpoint = this.buildEndpointFromResponse(path, 'GET', resp);
          if (endpoint) {
            endpoints.push(endpoint);
            this.onSurfaceSignal?.('endpoint', endpoint.url, `${endpoint.method} ${endpoint.url} — HTTP ${resp.status}`);
          }
```

**Change D** — find the exported `runActiveExploitEngine` function at the bottom:
```ts
export async function runActiveExploitEngine(
  target: ActiveExploitTarget,
  onProgress?: ExploitProgressCallback
): Promise<ActiveExploitResult> {
  const engine = new ActiveExploitEngine(target, onProgress);
  return engine.run();
}
```
Replace with:
```ts
export async function runActiveExploitEngine(
  target: ActiveExploitTarget,
  onProgress?: ExploitProgressCallback,
  onSurfaceSignal?: (kind: string, label: string, detail: string) => void,
): Promise<ActiveExploitResult> {
  const engine = new ActiveExploitEngine(target, onProgress, onSurfaceSignal);
  return engine.run();
}
```

---

## 7. Wire surface signal in breach-orchestrator.ts Phase 1

**File:** `server/services/breach-orchestrator.ts`

Find the `runActiveExploitEngine` call inside `executeApplicationCompromise`:
```ts
        activeExploitResult = await runActiveExploitEngine(
          exploitTarget,
          (phase, progress, detail) => {
            onProgress(chain.id, "application_compromise",
              5 + Math.round(Math.max(0, progress) * 0.4),
              `[Active Exploit] ${detail}`);
          }
        );
```
Replace with:
```ts
        activeExploitResult = await runActiveExploitEngine(
          exploitTarget,
          (phase, progress, detail) => {
            onProgress(chain.id, "application_compromise",
              5 + Math.round(Math.max(0, progress) * 0.4),
              `[Active Exploit] ${detail}`);
          },
          (kind, label, detail) => {
            const emitter = chainEmitterStore.get(chain.id);
            if (emitter) {
              emitter.surfaceSignal(
                kind as import("../lib/breach-event-emitter").SurfaceSignalKind,
                label, detail,
              );
            }
          }
        );
```

Then find the findings loop inside `executeApplicationCompromise`:
```ts
        for (const finding of mapped.findings) {
          findings.push({
            id: `bf-${randomUUID().slice(0, 8)}`,
            severity: finding.severity as "critical" | "high" | "medium" | "low",
            title: finding.title,
            description: finding.description,
            technique: finding.exploitChain,
            source: "active_exploit_engine",
            evidenceQuality: "proven",
          });
        }
```
Replace with:
```ts
        const phase1Emitter = chainEmitterStore.get(chain.id);
        for (const finding of mapped.findings) {
          findings.push({
            id: `bf-${randomUUID().slice(0, 8)}`,
            severity: finding.severity as "critical" | "high" | "medium" | "low",
            title: finding.title,
            description: finding.description,
            technique: finding.exploitChain,
            source: "active_exploit_engine",
            evidenceQuality: "proven",
          });
          if (phase1Emitter) {
            phase1Emitter.reasoning(
              "application_compromise", "exploit-agent-p1a",
              `Confirmed: ${finding.title}`, finding.description,
              "confirmed", { techniqueTried: finding.exploitChain },
            );
          }
        }
```

---

## 8. Replace — useBreachChainUpdates.ts

**File:** `client/src/hooks/useBreachChainUpdates.ts`

Replace the entire file with:

```ts
import { useEffect, useState, useRef } from "react";
import { useWebSocket } from "./useWebSocket";
import { queryClient } from "@/lib/queryClient";
import type { AttackGraph } from "@shared/schema";
import type {
  BreachNodeAddedEvent, BreachEdgeAddedEvent,
  BreachSurfaceSignalEvent, BreachReasoningEvent,
  BreachPhaseTransitionEvent,
} from "../lib/breach-events";

export type { BreachNodeAddedEvent, BreachEdgeAddedEvent, BreachSurfaceSignalEvent, BreachReasoningEvent };

export interface BreachChainUpdateMessage {
  type: "breach_chain_progress" | "breach_chain_complete" | "breach_chain_graph_update";
  chainId: string; phase?: string; progress?: number; message?: string;
  status?: string; graph?: AttackGraph; phaseIndex?: number;
  totalPhases?: number; timestamp?: string;
}

export interface LiveEvent {
  id: string;
  eventKind: "scanning" | "exploit_attempt" | "credential_extracted" | "vuln_confirmed";
  target: string; detail: string; phase: string;
  timestamp: string; expiresAt: number;
}

export interface UseBreachChainUpdatesOptions {
  enabled?: boolean; chainId?: string;
  onProgress?: (data: BreachChainUpdateMessage) => void;
  onComplete?: (data: BreachChainUpdateMessage) => void;
  onGraphUpdate?: (data: BreachChainUpdateMessage) => void;
}

let _liveEventCounter = 0;

export function useBreachChainUpdates({
  enabled = true, chainId, onProgress, onComplete, onGraphUpdate,
}: UseBreachChainUpdatesOptions = {}) {
  const [latestGraph, setLatestGraph] = useState<AttackGraph | null>(null);
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);
  const [nodes, setNodes] = useState<BreachNodeAddedEvent[]>([]);
  const [edges, setEdges] = useState<BreachEdgeAddedEvent[]>([]);
  const [surfaceSignals, setSurfaceSignals] = useState<BreachSurfaceSignalEvent[]>([]);
  const [reasoningEvents, setReasoningEvents] = useState<BreachReasoningEvent[]>([]);
  const [phaseTransitions, setPhaseTransitions] = useState<BreachPhaseTransitionEvent[]>([]);
  const cleanupRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    cleanupRef.current = setInterval(() => {
      const now = Date.now();
      setLiveEvents(prev => {
        const f = prev.filter(e => e.expiresAt > now);
        return f.length === prev.length ? prev : f;
      });
    }, 1000);
    return () => { if (cleanupRef.current) clearInterval(cleanupRef.current); };
  }, []);

  useEffect(() => {
    setNodes([]); setEdges([]); setSurfaceSignals([]);
    setReasoningEvents([]); setPhaseTransitions([]);
    setLatestGraph(null); setLiveEvents([]);
  }, [chainId]);

  const { isConnected, subscribe, unsubscribe } = useWebSocket({
    enabled,
    onMessage: (data: any) => {
      if (chainId && data.chainId && data.chainId !== chainId) return;
      switch (data.type) {
        case "breach_node_added":
          setNodes(prev => [...prev, data as BreachNodeAddedEvent]); break;
        case "breach_edge_added":
          setEdges(prev => [...prev, data as BreachEdgeAddedEvent]); break;
        case "breach_surface_signal":
          setSurfaceSignals(prev => {
            const n = [...prev, data as BreachSurfaceSignalEvent];
            return n.length > 500 ? n.slice(-500) : n;
          }); break;
        case "breach_reasoning":
          setReasoningEvents(prev => {
            const n = [...prev, data as BreachReasoningEvent];
            return n.length > 200 ? n.slice(-200) : n;
          }); break;
        case "breach_phase_transition":
          setPhaseTransitions(prev => [...prev, data as BreachPhaseTransitionEvent]); break;
        case "breach_chain_progress":
          queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
          if (data.chainId) queryClient.invalidateQueries({ queryKey: [`/api/breach-chains/${data.chainId}`] });
          onProgress?.(data as BreachChainUpdateMessage); break;
        case "breach_chain_complete":
          queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
          if (data.chainId) queryClient.invalidateQueries({ queryKey: [`/api/breach-chains/${data.chainId}`] });
          onComplete?.(data as BreachChainUpdateMessage); break;
        case "breach_chain_graph_update":
          if (data.graph) setLatestGraph(data.graph as AttackGraph);
          onGraphUpdate?.(data as BreachChainUpdateMessage); break;
        case "breach_chain_live_event": {
          const event: LiveEvent = {
            id: `live-${++_liveEventCounter}`, eventKind: data.eventKind,
            target: data.target, detail: data.detail, phase: data.phase,
            timestamp: data.timestamp, expiresAt: Date.now() + 3000,
          };
          setLiveEvents(prev => { const n = [...prev, event]; return n.length > 5 ? n.slice(-5) : n; });
          break;
        }
      }
    },
  });

  useEffect(() => {
    if (isConnected && enabled) {
      if (chainId) subscribe(`breach_chain:${chainId}`);
      subscribe("breach_chain_progress");
      subscribe("breach_chain_complete");
      subscribe("breach_chain_graph_update");
      return () => {
        if (chainId) unsubscribe(`breach_chain:${chainId}`);
        unsubscribe("breach_chain_progress");
        unsubscribe("breach_chain_complete");
        unsubscribe("breach_chain_graph_update");
      };
    }
  }, [isConnected, enabled, chainId, subscribe, unsubscribe]);

  return {
    isConnected, nodes, edges, surfaceSignals, reasoningEvents, phaseTransitions,
    latestGraph, liveEvents,
  };
}
```

---

## 9. Edit — LiveBreachChainGraph.tsx

**File:** `client/src/components/LiveBreachChainGraph.tsx`

**Change A** — find the first two import lines:
```ts
import { useEffect, useRef, useState, useCallback } from "react";
import type { AttackGraph, AttackNode, AttackEdge } from "@shared/schema";
```
Replace with:
```ts
import { useEffect, useRef, useState, useCallback } from "react";
import type { AttackGraph, AttackNode, AttackEdge } from "@shared/schema";
import type {
  BreachNodeAddedEvent, BreachEdgeAddedEvent,
  BreachSurfaceSignalEvent, BreachReasoningEvent,
} from "../lib/breach-events";
```

**Change B** — find `interface LiveBreachChainGraphProps {` and replace the entire interface:
```ts
interface LiveBreachChainGraphProps {
  graph?: AttackGraph | null;
  riskScore?: number;
  assetsCompromised?: number;
  credentialsHarvested?: number;
  currentPhase?: string;
  isRunning?: boolean;
  liveEvents?: LiveEventData[];
  nodes?: BreachNodeAddedEvent[];
  edges?: BreachEdgeAddedEvent[];
  surfaceSignals?: BreachSurfaceSignalEvent[];
  reasoningEvents?: BreachReasoningEvent[];
}
```

**Change C** — find the function destructure:
```ts
export function LiveBreachChainGraph({
  graph,
  riskScore,
  assetsCompromised,
  credentialsHarvested,
  currentPhase,
  isRunning,
  liveEvents = [],
}: LiveBreachChainGraphProps) {
```
Replace with:
```ts
export function LiveBreachChainGraph({
  graph,
  riskScore,
  assetsCompromised,
  credentialsHarvested,
  currentPhase,
  isRunning,
  liveEvents = [],
  nodes: liveNodes = [],
  edges: liveEdges = [],
  surfaceSignals = [],
  reasoningEvents = [],
}: LiveBreachChainGraphProps) {
```

**Change D** — find `// Re-layout when graph changes` and insert this entire block BEFORE it:

```ts
  useEffect(() => {
    if (liveNodes.length === 0) return;
    const PHASE_ORDER = [
      "application_compromise","credential_extraction","cloud_iam_escalation",
      "container_k8s_breakout","lateral_movement","impact_assessment",
    ];
    const KIND_RADIUS: Record<string, number> = {
      phase_spine:22, finding:14, credential:14, iam_path:14,
      k8s_escape:14, pivot_hop:12, data_store:12, dead_end:10,
    };
    const centerX = dims.w / 2;
    const usableH = dims.h - 90;
    const spineNodes = liveNodes.filter(n => n.kind === "phase_spine");
    const totalSpine = Math.max(spineNodes.length, 1);
    const spineYStep = usableH / (totalSpine + 1);
    const spineYMap = new Map<string, number>();
    spineNodes.forEach((n, i) => spineYMap.set(n.nodeId, spineYStep * (i + 1)));
    const satellitesByPhase = new Map<string, BreachNodeAddedEvent[]>();
    liveNodes.filter(n => n.kind !== "phase_spine").forEach(n => {
      if (!satellitesByPhase.has(n.phase)) satellitesByPhase.set(n.phase, []);
      satellitesByPhase.get(n.phase)!.push(n);
    });
    const newLayoutNodes: LayoutNode[] = [];
    spineNodes.forEach(n => {
      const y = spineYMap.get(n.nodeId) ?? 0;
      newLayoutNodes.push({
        id: n.nodeId, label: n.label, tactic: n.phase, nodeType: "spine",
        x: centerX, y, targetX: centerX, targetY: y, opacity: 1,
        description: n.detail, compromiseLevel: n.severity,
        assets: [], isSpine: true, isSatellite: false,
        collapsedCount: 0, radius: KIND_RADIUS.phase_spine,
      });
    });
    satellitesByPhase.forEach((sats, phase) => {
      const spineNode = spineNodes.find(n => n.phase === phase);
      if (!spineNode) return;
      const spineY = spineYMap.get(spineNode.nodeId) ?? 0;
      const ARM = 110; const V_GAP = 32;
      sats.forEach((n, i) => {
        const side = i % 2 === 0 ? 1 : -1;
        const row = Math.floor(i / 2);
        const x = centerX + side * ARM;
        const y = spineY + (row - Math.floor(sats.length / 4)) * V_GAP;
        newLayoutNodes.push({
          id: n.nodeId, label: n.label, tactic: n.phase, nodeType: n.kind,
          x, y, targetX: x, targetY: y, opacity: 1,
          description: n.detail, compromiseLevel: n.severity,
          assets: [], isSpine: false, isSatellite: true,
          collapsedCount: 0, radius: KIND_RADIUS[n.kind] ?? 12,
        });
      });
    });
    const newLayoutEdges: LayoutEdge[] = liveEdges.map(e => ({
      from: e.fromNodeId, to: e.toNodeId,
      technique: e.label ?? "", probability: e.confirmed ? 1 : 0.3,
      edgeType: e.confirmed ? "confirmed" : "attempted", description: e.label ?? "",
    }));
    const newIds = new Set(newLayoutNodes.map(n => n.id));
    for (const node of newLayoutNodes) {
      if (!prevNodeIdsRef.current.has(node.id)) nodeOpacitiesRef.current.set(node.id, 0);
    }
    prevNodeIdsRef.current = newIds;
    layoutRef.current = { layoutNodes: newLayoutNodes, layoutEdges: newLayoutEdges };
  }, [liveNodes, liveEdges, dims.w, dims.h]);

```

**Change E** — find the first line of `// Re-layout when graph changes` useEffect:
```ts
  // Re-layout when graph changes
  useEffect(() => {
    if (!graph || !graph.nodes?.length) {
```
Replace with:
```ts
  // Re-layout when graph changes (legacy — only if no live nodes)
  useEffect(() => {
    if (liveNodes.length > 0) return;
    if (!graph || !graph.nodes?.length) {
```

---

## 10. Edit — BreachChains.tsx

**File:** `client/src/pages/BreachChains.tsx`

**Change A** — find:
```ts
  const { latestGraph, liveEvents } = useBreachChainUpdates({
    enabled: chain.status === "running" || chain.status === "paused",
    chainId: chain.id,
  });
```
Replace with:
```ts
  const {
    latestGraph, liveEvents,
    nodes, edges, surfaceSignals, reasoningEvents,
  } = useBreachChainUpdates({
    enabled: chain.status === "running" || chain.status === "paused",
    chainId: chain.id,
  });
```

**Change B** — find the `<LiveBreachChainGraph` JSX block and replace it:
```tsx
          <LiveBreachChainGraph
            graph={displayGraph}
            nodes={nodes}
            edges={edges}
            surfaceSignals={surfaceSignals}
            reasoningEvents={reasoningEvents}
            riskScore={chain.overallRiskScore ?? undefined}
            assetsCompromised={chain.totalAssetsCompromised ?? undefined}
            credentialsHarvested={chain.totalCredentialsHarvested ?? undefined}
            currentPhase={chain.currentPhase ?? undefined}
            isRunning={chain.status === "running"}
            liveEvents={liveEvents}
          />
```

---

## 11. Start the app

```bash
cd /Users/dre/prod/OdinForge-AI
npm run dev
```

Open: `http://localhost:5000`

Go to **Breach Chains** → create a new chain → watch the graph build live.

---

## What you will see

1. **Surface Map** — before payloads fire, technologies and endpoints stream in as the crawler discovers them
2. **Live Breach Chain** — 6 spine nodes appear immediately, finding/credential nodes pop in as they're confirmed with animated fade-in
3. **AI Reasoning feed** — every exploit confirmation narrates why the AI moved to the next technique
4. **Layout toggle** — switch between graph-only, split, or full three-panel view at any time

---

## TypeScript check (should be clean)

```bash
npx tsc --noEmit
```
