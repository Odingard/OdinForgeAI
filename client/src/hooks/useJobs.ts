import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export interface Job {
  id: string;
  type: "evaluation" | "network_scan" | "external_recon" | "report" | "ai_simulation" | "breach_chain" | "full_assessment" | "cloud_discovery" | "agent_deployment";
  status: "pending" | "running" | "completed" | "failed" | "cancelled";
  tenantId: string;
  organizationId: string;
  userId?: string;
  data: any;
  result?: any;
  error?: string;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
}

export interface JobStats {
  total: number;
  pending: number;
  running: number;
  completed: number;
  failed: number;
  cancelled: number;
}

export function useJobs(filters?: {
  status?: string;
  type?: string;
  limit?: number;
}) {
  const queryKey = filters
    ? [`/api/jobs?${new URLSearchParams(filters as any).toString()}`]
    : ["/api/jobs"];

  return useQuery<Job[]>({
    queryKey,
    refetchInterval: 5000, // Refresh every 5 seconds for real-time updates
    select: (data: any) => {
      if (Array.isArray(data)) return data;
      if (data?.jobs && Array.isArray(data.jobs)) return data.jobs;
      return [];
    },
  });
}

export function useJob(jobId: string | null) {
  return useQuery<Job>({
    queryKey: [`/api/jobs/${jobId}`],
    enabled: !!jobId,
    refetchInterval: 5000,
  });
}

export function useJobStats() {
  return useQuery<JobStats>({
    queryKey: ["/api/jobs/stats"],
    refetchInterval: 10000, // Refresh every 10 seconds
    select: (data: any) => ({
      total: (data?.waiting || 0) + (data?.active || 0) + (data?.completed || 0) + (data?.failed || 0) + (data?.delayed || 0),
      pending: data?.waiting || 0,
      running: data?.active || 0,
      completed: data?.completed || 0,
      failed: data?.failed || 0,
      cancelled: data?.delayed || 0,
    }),
  });
}

export function useCancelJob() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (jobId: string) => {
      await apiRequest("POST", `/api/jobs/${jobId}/cancel`);
    },
    onSuccess: () => {
      toast({
        title: "Job Cancelled",
        description: "The job has been cancelled successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/jobs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/jobs/stats"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Cancel Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useRetryJob() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (jobId: string) => {
      await apiRequest("POST", `/api/jobs/${jobId}/retry`);
    },
    onSuccess: () => {
      toast({
        title: "Job Queued",
        description: "The job has been queued for retry",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/jobs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/jobs/stats"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Retry Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useDeleteJob() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (jobId: string) => {
      await apiRequest("DELETE", `/api/jobs/${jobId}`);
    },
    onSuccess: () => {
      toast({
        title: "Job Deleted",
        description: "The job has been removed",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/jobs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/jobs/stats"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Delete Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}
