import { useEffect, useState, useRef, useCallback } from "react";
import { useWebSocket } from "./useWebSocket";
import { queryClient } from "@/lib/queryClient";
import type { AttackGraph } from "@shared/schema";

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
  expiresAt: number; // Date.now() + TTL
}

export interface UseBreachChainUpdatesOptions {
  enabled?: boolean;
  chainId?: string;
  onProgress?: (data: BreachChainUpdateMessage) => void;
  onComplete?: (data: BreachChainUpdateMessage) => void;
  onGraphUpdate?: (data: BreachChainUpdateMessage) => void;
}

let _liveEventCounter = 0;

export function useBreachChainUpdates({
  enabled = true,
  chainId,
  onProgress,
  onComplete,
  onGraphUpdate,
}: UseBreachChainUpdatesOptions = {}) {
  const [latestGraph, setLatestGraph] = useState<AttackGraph | null>(null);
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);
  const cleanupRef = useRef<NodeJS.Timeout | null>(null);

  // Expire old live events every second
  useEffect(() => {
    cleanupRef.current = setInterval(() => {
      const now = Date.now();
      setLiveEvents(prev => {
        const filtered = prev.filter(e => e.expiresAt > now);
        if (filtered.length === prev.length) return prev; // no change, skip re-render
        return filtered;
      });
    }, 1000);
    return () => {
      if (cleanupRef.current) clearInterval(cleanupRef.current);
    };
  }, []);

  const { isConnected, subscribe, unsubscribe } = useWebSocket({
    enabled,
    onMessage: (data) => {
      if (data.type === "breach_chain_progress") {
        if (chainId && data.chainId !== chainId) return;

        queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
        if (data.chainId) {
          queryClient.invalidateQueries({
            queryKey: [`/api/breach-chains/${data.chainId}`],
          });
        }

        onProgress?.(data as BreachChainUpdateMessage);
      } else if (data.type === "breach_chain_complete") {
        if (chainId && data.chainId !== chainId) return;

        queryClient.invalidateQueries({ queryKey: ["/api/breach-chains"] });
        if (data.chainId) {
          queryClient.invalidateQueries({
            queryKey: [`/api/breach-chains/${data.chainId}`],
          });
        }

        onComplete?.(data as BreachChainUpdateMessage);
      } else if (data.type === "breach_chain_graph_update") {
        if (chainId && data.chainId !== chainId) return;

        if (data.graph) {
          setLatestGraph(data.graph as AttackGraph);
        }

        onGraphUpdate?.(data as BreachChainUpdateMessage);
      } else if (data.type === "breach_chain_live_event") {
        if (chainId && data.chainId !== chainId) return;

        const event: LiveEvent = {
          id: `live-${++_liveEventCounter}`,
          eventKind: data.eventKind,
          target: data.target,
          detail: data.detail,
          phase: data.phase,
          timestamp: data.timestamp,
          expiresAt: Date.now() + 3000, // 3s TTL
        };

        setLiveEvents(prev => {
          const next = [...prev, event];
          // Ring buffer of last 5
          return next.length > 5 ? next.slice(-5) : next;
        });
      }
    },
  });

  useEffect(() => {
    if (isConnected && enabled) {
      // Subscribe to chain-specific channel (server broadcasts to breach_chain:{chainId})
      if (chainId) {
        subscribe(`breach_chain:${chainId}`);
      }
      // Also subscribe to generic channels for list-level updates
      subscribe("breach_chain_progress");
      subscribe("breach_chain_complete");
      subscribe("breach_chain_graph_update");

      return () => {
        if (chainId) {
          unsubscribe(`breach_chain:${chainId}`);
        }
        unsubscribe("breach_chain_progress");
        unsubscribe("breach_chain_complete");
        unsubscribe("breach_chain_graph_update");
      };
    }
  }, [isConnected, enabled, chainId, subscribe, unsubscribe]);

  return {
    isConnected,
    latestGraph,
    liveEvents,
  };
}
