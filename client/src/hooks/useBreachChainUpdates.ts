import { useEffect, useState } from "react";
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

export interface UseBreachChainUpdatesOptions {
  enabled?: boolean;
  chainId?: string;
  onProgress?: (data: BreachChainUpdateMessage) => void;
  onComplete?: (data: BreachChainUpdateMessage) => void;
  onGraphUpdate?: (data: BreachChainUpdateMessage) => void;
}

export function useBreachChainUpdates({
  enabled = true,
  chainId,
  onProgress,
  onComplete,
  onGraphUpdate,
}: UseBreachChainUpdatesOptions = {}) {
  const [latestGraph, setLatestGraph] = useState<AttackGraph | null>(null);

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
      }
    },
  });

  useEffect(() => {
    if (isConnected && enabled) {
      subscribe("breach_chain_progress");
      subscribe("breach_chain_complete");
      subscribe("breach_chain_graph_update");

      return () => {
        unsubscribe("breach_chain_progress");
        unsubscribe("breach_chain_complete");
        unsubscribe("breach_chain_graph_update");
      };
    }
  }, [isConnected, enabled, subscribe, unsubscribe]);

  return {
    isConnected,
    latestGraph,
  };
}
