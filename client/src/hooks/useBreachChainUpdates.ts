import { useEffect } from "react";
import { useWebSocket } from "./useWebSocket";
import { queryClient } from "@/lib/queryClient";

export interface BreachChainUpdateMessage {
  type: "breach_chain_progress" | "breach_chain_complete";
  chainId: string;
  phase?: string;
  progress?: number;
  message?: string;
  status?: string;
  timestamp?: string;
}

export interface UseBreachChainUpdatesOptions {
  enabled?: boolean;
  chainId?: string;
  onProgress?: (data: BreachChainUpdateMessage) => void;
  onComplete?: (data: BreachChainUpdateMessage) => void;
}

export function useBreachChainUpdates({
  enabled = true,
  chainId,
  onProgress,
  onComplete,
}: UseBreachChainUpdatesOptions = {}) {
  const { isConnected, subscribe, unsubscribe } = useWebSocket({
    enabled,
    onMessage: (data) => {
      if (data.type === "breach_chain_progress") {
        // If filtering by chainId, only process matching events
        if (chainId && data.chainId !== chainId) return;

        // Invalidate breach chain queries for live updates
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
      }
    },
  });

  useEffect(() => {
    if (isConnected && enabled) {
      subscribe("breach_chain_progress");
      subscribe("breach_chain_complete");

      return () => {
        unsubscribe("breach_chain_progress");
        unsubscribe("breach_chain_complete");
      };
    }
  }, [isConnected, enabled, subscribe, unsubscribe]);

  return {
    isConnected,
  };
}
