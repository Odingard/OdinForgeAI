import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export interface ScheduledScan {
  id: string;
  name: string;
  description?: string;
  scanType: "vulnerability" | "compliance" | "reconnaissance" | "penetration";
  targetIds: string[];
  schedule: string; // cron expression
  nextRun?: string;
  lastRun?: string;
  enabled: boolean;
  createdAt: string;
  createdBy: string;
  parameters?: any;
}

export interface ScanRun {
  id: string;
  scheduledScanId: string;
  startTime: string;
  endTime?: string;
  status: "pending" | "running" | "completed" | "failed" | "cancelled";
  findingsCount?: number;
  error?: string;
}

export interface ScheduledScanStats {
  totalSchedules: number;
  enabledSchedules: number;
  upcomingRuns: number;
  lastRunsToday: number;
}

export function useScheduledScans(filters?: {
  enabled?: boolean;
  scanType?: string;
}) {
  const queryKey = filters
    ? [`/api/scheduled-scans?${new URLSearchParams(filters as any).toString()}`]
    : ["/api/scheduled-scans"];

  return useQuery<ScheduledScan[]>({
    queryKey,
    refetchInterval: 30000,
  });
}

export function useScheduledScanById(scanId: string | null) {
  return useQuery<ScheduledScan>({
    queryKey: [`/api/scheduled-scans/${scanId}`],
    enabled: !!scanId,
  });
}

export function useScheduledScanRuns(scanId: string | null) {
  return useQuery<ScanRun[]>({
    queryKey: [`/api/scheduled-scans/${scanId}/runs`],
    enabled: !!scanId,
    refetchInterval: 30000,
  });
}

export function useScheduledScanStats() {
  return useQuery<ScheduledScanStats>({
    queryKey: ["/api/scheduled-scans/stats"],
    refetchInterval: 60000,
  });
}

export function useCreateScheduledScan() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: {
      name: string;
      description?: string;
      scanType: string;
      targetIds: string[];
      schedule: string;
      parameters?: any;
    }) => {
      const response = await apiRequest("POST", "/api/scheduled-scans", data);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Schedule Created",
        description: "Scan has been scheduled successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-scans"] });
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-scans/stats"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Creation Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useUpdateScheduledScan() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: {
      id: string;
      name?: string;
      description?: string;
      scanType?: string;
      targetIds?: string[];
      schedule?: string;
      enabled?: boolean;
      parameters?: any;
    }) => {
      const { id, ...updateData } = data;
      const response = await apiRequest("PUT", `/api/scheduled-scans/${id}`, updateData);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Schedule Updated",
        description: "Scan schedule has been updated",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-scans"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Update Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useDeleteScheduledScan() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (scanId: string) => {
      await apiRequest("DELETE", `/api/scheduled-scans/${scanId}`);
    },
    onSuccess: () => {
      toast({
        title: "Schedule Deleted",
        description: "Scan schedule has been removed",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-scans"] });
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-scans/stats"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Deletion Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useRunScheduledScanNow() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (scanId: string) => {
      const response = await apiRequest("POST", `/api/scheduled-scans/${scanId}/run`);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Scan Started",
        description: "Scheduled scan is now running",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-scans"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Scan Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useToggleScheduledScan() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: { scanId: string; enabled: boolean }) => {
      const response = await apiRequest("PUT", `/api/scheduled-scans/${data.scanId}`, {
        enabled: data.enabled,
      });
      return response.json();
    },
    onSuccess: (_, variables) => {
      toast({
        title: variables.enabled ? "Schedule Enabled" : "Schedule Disabled",
        description: `Scan schedule has been ${variables.enabled ? "enabled" : "disabled"}`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-scans"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Toggle Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}
