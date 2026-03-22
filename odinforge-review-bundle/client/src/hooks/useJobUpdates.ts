import { useEffect } from "react";
import { useWebSocket } from "./useWebSocket";
import { queryClient } from "@/lib/queryClient";

export interface JobUpdateMessage {
  type: "job_status_changed" | "job_progress";
  jobId: string;
  status?: "pending" | "running" | "completed" | "failed" | "cancelled";
  progress?: number;
  result?: any;
  error?: string;
}

export interface UseJobUpdatesOptions {
  enabled?: boolean;
  onJobStatusChange?: (data: JobUpdateMessage) => void;
  onJobProgress?: (data: JobUpdateMessage) => void;
}

export function useJobUpdates({
  enabled = true,
  onJobStatusChange,
  onJobProgress,
}: UseJobUpdatesOptions = {}) {
  const { isConnected, subscribe, unsubscribe } = useWebSocket({
    enabled,
    onMessage: (data) => {
      if (data.type === "job_status_changed") {
        // Invalidate jobs queries when status changes
        queryClient.invalidateQueries({ queryKey: ["/api/jobs"] });
        queryClient.invalidateQueries({ queryKey: ["/api/jobs/stats"] });

        // Call custom callback if provided
        onJobStatusChange?.(data as JobUpdateMessage);
      } else if (data.type === "job_progress") {
        // Only invalidate specific job query for progress updates
        if (data.jobId) {
          queryClient.invalidateQueries({ queryKey: [`/api/jobs/${data.jobId}`] });
        }

        // Call custom callback if provided
        onJobProgress?.(data as JobUpdateMessage);
      }
    },
  });

  useEffect(() => {
    if (isConnected && enabled) {
      // Subscribe to job status changes
      subscribe("job_status_changed");
      subscribe("job_progress");

      return () => {
        unsubscribe("job_status_changed");
        unsubscribe("job_progress");
      };
    }
  }, [isConnected, enabled, subscribe, unsubscribe]);

  return {
    isConnected,
  };
}
