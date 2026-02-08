import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";

export interface SandboxSubmission {
  id: string;
  fileName?: string;
  url?: string;
  submissionType: "file" | "url";
  type?: "file" | "url";
  status: "queued" | "analyzing" | "completed" | "failed";
  verdict?: "malicious" | "suspicious" | "clean";
  score?: number;
  submittedAt: string;
  completedAt?: string;
  fileHash?: string;
  fileSize?: number;
}

export interface SandboxBehavior {
  submissionId: string;
  networkActivity: Array<{
    id: string;
    destination: string;
    port: number;
    protocol: string;
    timestamp: string;
    type: string;
    sourceIp?: string;
    sourcePort?: number;
    destIp?: string;
    destPort?: number;
    domain?: string;
    suspicious?: boolean;
  }>;
  fileActivity: Array<{
    id: string;
    path: string;
    action: string;
    timestamp: string;
    suspicious?: boolean;
  }>;
  registryActivity: Array<{
    id: string;
    path: string;
    action: string;
    key?: string;
    timestamp: string;
    suspicious?: boolean;
  }>;
  processActivity: {
    processes: Array<{
      name: string;
      pid: number;
      commandLine: string;
      timestamp: string;
    }>;
  };
  mitreAttackTechniques: Array<{
    id: string;
    techniqueId: string;
    name: string;
    tactic: string;
    confidence?: string;
  }>;
  iocs: Array<{
    type: string;
    value: string;
    malicious?: boolean;
    context?: string;
  }>;
}

export interface SandboxStats {
  totalSubmissions: number;
  queuedSubmissions: number;
  analyzingSubmissions: number;
  activeAnalyses: number;
  completedSubmissions: number;
  maliciousCount: number;
  suspiciousCount: number;
  cleanCount: number;
}

export function useSandboxSubmissions() {
  return useQuery<SandboxSubmission[]>({
    queryKey: ["/api/sandbox/submissions"],
    queryFn: async () => {
      return [];
    },
  });
}

export function useSandboxBehavior(submissionId: string | null) {
  return useQuery<SandboxBehavior | null>({
    queryKey: ["/api/sandbox/behavior", submissionId],
    queryFn: async () => {
      if (!submissionId) return null;
      return null;
    },
    enabled: !!submissionId,
  });
}

export function useSandboxStats() {
  return useQuery<SandboxStats>({
    queryKey: ["/api/sandbox/stats"],
    queryFn: async () => {
      return {
        totalSubmissions: 0,
        queuedSubmissions: 0,
        analyzingSubmissions: 0,
        activeAnalyses: 0,
        completedSubmissions: 0,
        maliciousCount: 0,
        suspiciousCount: 0,
        cleanCount: 0,
      };
    },
  });
}

export function useSubmitFile() {
  return useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData();
      formData.append("file", file);
      return {
        id: `submission-${Date.now()}`,
        fileName: file.name,
        submissionType: "file" as const,
        status: "queued" as const,
        submittedAt: new Date().toISOString(),
      };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/submissions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/stats"] });
    },
  });
}

export function useSubmitUrl() {
  return useMutation({
    mutationFn: async (url: string) => {
      return {
        id: `submission-${Date.now()}`,
        url,
        submissionType: "url" as const,
        status: "queued" as const,
        submittedAt: new Date().toISOString(),
      };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/submissions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/stats"] });
    },
  });
}

export function useDeleteSandboxSubmission() {
  return useMutation({
    mutationFn: async (submissionId: string) => {
      return { success: true };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/submissions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/stats"] });
    },
  });
}

export function useReanalyzeSubmission() {
  return useMutation({
    mutationFn: async (submissionId: string) => {
      return {
        id: submissionId,
        status: "queued" as const,
      };
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/submissions"] });
    },
  });
}

export function useDownloadSandboxReport() {
  return useMutation({
    mutationFn: async (submissionId: string) => {
      const blob = new Blob(
        [JSON.stringify({ submissionId, report: "Mock report data" }, null, 2)],
        { type: "application/json" }
      );
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sandbox-report-${submissionId}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      return { success: true };
    },
  });
}
