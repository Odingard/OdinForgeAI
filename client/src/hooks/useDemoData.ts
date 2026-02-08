import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export interface DemoDataStatus {
  hasDemoData: boolean;
  counts: {
    agents: number;
    evaluations: number;
  };
}

export interface DemoDataResults {
  success: boolean;
  message: string;
  agents: number;
  findings: number;
  telemetry: number;
  evaluations: number;
  jobs: number;
  scans: number;
  sessions: number;
  auditLogs: number;
  assets: number;
}

/**
 * Check if demo data is loaded
 */
export function useDemoDataStatus() {
  return useQuery<DemoDataStatus>({
    queryKey: ["/api/demo-data/status"],
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}

/**
 * Load demo data
 */
export function useLoadDemoData() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/demo-data/load");

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Failed to load demo data");
      }

      return response.json() as Promise<DemoDataResults>;
    },
    onSuccess: (data) => {
      toast({
        title: "Demo Data Loaded",
        description: `Successfully loaded ${data.agents} agents, ${data.evaluations} evaluations, and more!`,
      });

      // Invalidate all queries to refresh data
      queryClient.invalidateQueries();
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to Load Demo Data",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

/**
 * Clear all demo data
 */
export function useClearDemoData() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/demo-data/clear");

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || "Failed to clear demo data");
      }

      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Demo Data Cleared",
        description: "All demo data has been removed from the system.",
      });

      // Invalidate all queries to refresh data
      queryClient.invalidateQueries();
    },
    onError: (error: Error) => {
      toast({
        title: "Failed to Clear Demo Data",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}
