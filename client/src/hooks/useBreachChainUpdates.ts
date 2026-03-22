/**
 * useBreachChainUpdates
 *
 * Additive live graph model — replaces the snapshot replacement approach.
 * Instead of receiving a full AttackGraph and replacing state, this hook
 * maintains additive arrays of nodes, edges, surface signals, and reasoning
 * events that grow as the engagement progresses.
 *
 * The graph only ever grows — never resets mid-engagement.
 * LiveBreachChainGraph reads from these arrays directly.
 */

import { useEffect, useState, useRef, useCallback } from "react";
import { useWebSocket } from "./useWebSocket";
import { queryClient } from "@/lib/queryClient";
import type { AttackGraph } from "@shared/schema";
import type {
  BreachNodeAddedEvent,
  BreachEdgeAddedEvent,
  BreachSurfaceSignalEvent,
  BreachReasoningEvent,
  BreachPhaseTransitionEvent,
} from "../lib/breach-events";

// ─── Re-exported types for consumers ─────────────────────────────────────────

export type { BreachNodeAddedEvent, BreachEdgeAddedEvent, BreachSurfaceSignalEvent, BreachReasoningEvent };

export interface BreachChainUpdateMessage {
  type: "breach_chain_progress" | "breach_chain_complete" | "breach_chain_graph_update";
  chainId: string;
  phase?: string;
  progress?: number;
  message?: string;
  status?: string;
  graph?: AttackGraph;
  phaseIndex?: number;
  totalPhases?: number;
  timestamp?: string;
}

export interface LiveEvent {
  id: string;
  eventKind: "scanning" | "exploit_attempt" | "credential_extracted" | "vuln_confirmed";
  target: string;
  detail: string;
  phase: string;
  timestamp: string;
  expiresAt: number;
}

export interface UseBreachChainUpdatesOptions {
  enabled?: boolean;
  chainId?: string;
  onProgress?: (data: BreachChainUpdateMessage) => void;
  onComplete?: (data: BreachChainUpdateMessage) => void;
  onGraphUpdate?: (data: BreachChainUpdateMessage) => void;
}

let _liveEventCounter = 0;
const MAX_REASONING_EVENTS = 200;
const MAX_SURFACE_SIGNALS = 500;

export function useBreachChainUpdates({
  enabled = true,
  chainId,
  onProgress,
  onComplete,
  onGraphUpdate,
}: UseBreachChainUpdatesOptions = {}) {
  // Legacy — kept for backward compat with pages that read latestGraph
  const [latestGraph, setLatestGraph] = useState<AttackGraph | null>(null);
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);

  // ── Additive graph state ─────────────────────────────────────────────
  const [nodes, setNodes] = useState<BreachNodeAddedEvent[]>([]);
  const [edges, setEdges] = useState<BreachEdgeAddedEvent[]>([]);
  const [surfaceSignals, setSurfaceSignals] = useState<BreachSurfaceSignalEvent[]>([]);
  const [reasoningEvents, setReasoningEvents] = useState<BreachReasoningEvent[]>([]);
  const [phaseTransitions, setPhaseTransitions] = useState<BreachPhaseTransitionEvent[]>([]);

  // ── Phase 11: Reasoning / Canvas / Operator state ───────────────────
  const [reasoningStream, setReasoningStream] = useState<any[]>([]);
  const [canvasEvents, setCanvasEvents] = useState<any[]>([]);
  const [operatorSummary, setOperatorSummary] = useState<any>(null);

  const cleanupRef = useRef<NodeJS.Timeout | null>(null);

  // Expire old live events
  useEffect(() => {
    cleanupRef.current = setInterval(() => {
      const now = Date.now();
      setLiveEvents(prev => {
        const filtered = prev.filter(e => e.expiresAt > now);
        return filtered.length === prev.length ? prev : filtered;
      });
    }, 1000);
    return () => { if (cleanupRef.current) clearInterval(cleanupRef.current); };
  }, []);

  // Reset additive state when chainId changes
  useEffect(() => {
    setNodes([]);
    setEdges([]);
    setSurfaceSignals([]);
    setReasoningEvents([]);
    setPhaseTransitions([]);
    setReasoningStream([]);
    setCanvasEvents([]);
    setOperatorSummary(null);
    setLatestGraph(null);
    setLiveEvents([]);
  }, [chainId]);

  const { isConnected, subscribe, unsubscribe } = useWebSocket({
    enabled,
    onMessage: (data: any) => {
      // Guard: filter by chainId when provided
      if (chainId && data.chainId && data.chainId !== chainId) return;

      switch (data.type) {

        // ── Granular additive events ───────────────────────────────────
        case "breach_node_added":
          setNodes(prev => [...prev, data as BreachNodeAddedEvent]);
          break;

        case "breach_edge_added":
          setEdges(prev => [...prev, data as BreachEdgeAddedEvent]);
          break;

        case "breach_surface_signal":
          setSurfaceSignals(prev => {
            const next = [...prev, data as BreachSurfaceSignalEvent];
            return next.length > MAX_SURFACE_SIGNALS ? next.slice(-MAX_SURFACE_SIGNALS) : next;
          });
          break;

        case "breach_reasoning":
          setReasoningEvents(prev => {
            const next = [...prev, data as BreachReasoningEvent];
            return next.length > MAX_REASONING_EVENTS ? next.slice(-MAX_REASONING_EVENTS) : next;
          });
          break;

        case "breach_phase_transition":
          setPhaseTransitions(prev => [...prev, data as BreachPhaseTransitionEvent]);
          break;

        // ── Legacy events — kept for backward compat ──────────────────
        case "breach_chain_progress":
          queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
          if (data.chainId) queryClient.invalidateQueries({ queryKey: [`/api/breach-chains/${data.chainId}`] });
          onProgress?.(data as BreachChainUpdateMessage);
          break;

        case "breach_chain_complete":
          queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
          if (data.chainId) queryClient.invalidateQueries({ queryKey: [`/api/breach-chains/${data.chainId}`] });
          onComplete?.(data as BreachChainUpdateMessage);
          break;

        case "breach_chain_graph_update":
          if (data.graph) setLatestGraph(data.graph as AttackGraph);
          onGraphUpdate?.(data as BreachChainUpdateMessage);
          break;

        // ── Phase 11: Reasoning / Canvas / Operator events ──────────────
        case "reasoning_event":
          setReasoningStream(prev => {
            const next = [...prev, data];
            return next.length > MAX_REASONING_EVENTS ? next.slice(-MAX_REASONING_EVENTS) : next;
          });
          break;

        case "canvas_event":
          setCanvasEvents(prev => {
            const next = [...prev, data];
            return next.length > MAX_SURFACE_SIGNALS ? next.slice(-MAX_SURFACE_SIGNALS) : next;
          });
          break;

        case "operator_summary":
          setOperatorSummary(data);
          break;

        case "breach_chain_live_event": {
          const event: LiveEvent = {
            id: `live-${++_liveEventCounter}`,
            eventKind: data.eventKind,
            target: data.target,
            detail: data.detail,
            phase: data.phase,
            timestamp: data.timestamp,
            expiresAt: Date.now() + 3000,
          };
          setLiveEvents(prev => {
            const next = [...prev, event];
            return next.length > 5 ? next.slice(-5) : next;
          });
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
    isConnected,
    // Additive graph state (primary)
    nodes,
    edges,
    surfaceSignals,
    reasoningEvents,
    phaseTransitions,
    // Phase 11: Reasoning / Canvas / Operator
    reasoningStream,
    canvasEvents,
    operatorSummary,
    // Legacy (backward compat)
    latestGraph,
    liveEvents,
  };
}
