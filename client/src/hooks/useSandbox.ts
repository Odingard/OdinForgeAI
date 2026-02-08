import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export interface SandboxSubmission {
  id: string;
  type: "file" | "url";
  fileName?: string;
  fileSize?: number;
  fileHash?: string;
  url?: string;
  status: "queued" | "analyzing" | "completed" | "failed";
  verdict?: "clean" | "suspicious" | "malicious";
  score?: number;
  submittedAt: string;
  completedAt?: string;
  error?: string;
}

export interface SandboxBehavior {
  submissionId: string;
  networkActivity: NetworkActivity[];
  fileActivity: FileActivity[];
  registryActivity: RegistryActivity[];
  processActivity: ProcessActivity[];
  mitreAttackTechniques: MitreAttackTechnique[];
  iocs: IOC[];
}

export interface NetworkActivity {
  id: string;
  timestamp: string;
  protocol: string;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  domain?: string;
  bytesTransferred?: number;
  suspicious: boolean;
}

export interface FileActivity {
  id: string;
  timestamp: string;
  action: "create" | "modify" | "delete" | "read";
  path: string;
  hash?: string;
  size?: number;
  suspicious: boolean;
}

export interface RegistryActivity {
  id: string;
  timestamp: string;
  action: "create" | "modify" | "delete" | "read";
  key: string;
  value?: string;
  data?: string;
  suspicious: boolean;
}

export interface ProcessActivity {
  id: string;
  timestamp: string;
  action: "create" | "terminate";
  name: string;
  pid: number;
  parentPid?: number;
  commandLine?: string;
  suspicious: boolean;
}

export interface MitreAttackTechnique {
  id: string;
  techniqueId: string;
  name: string;
  tactic: string;
  description: string;
  confidence: number;
}

export interface IOC {
  type: "ip" | "domain" | "url" | "hash" | "email";
  value: string;
  context?: string;
  malicious: boolean;
}

export interface SandboxStats {
  totalSubmissions: number;
  activeAnalyses: number;
  maliciousCount: number;
  suspiciousCount: number;
  cleanCount: number;
}

export function useSandboxSubmissions(filters?: {
  status?: string;
  verdict?: string;
}) {
  const queryKey = filters
    ? [`/api/sandbox/submissions?${new URLSearchParams(filters as any).toString()}`]
    : ["/api/sandbox/submissions"];

  return useQuery<SandboxSubmission[]>({
    queryKey,
    refetchInterval: 10000,
  });
}

export function useSandboxSubmissionById(submissionId: string | null) {
  return useQuery<SandboxSubmission>({
    queryKey: [`/api/sandbox/submissions/${submissionId}`],
    enabled: !!submissionId,
  });
}

export function useSandboxBehavior(submissionId: string | null) {
  return useQuery<SandboxBehavior>({
    queryKey: [`/api/sandbox/${submissionId}/behavior`],
    enabled: !!submissionId,
    refetchInterval: 15000,
  });
}

export function useSandboxStats() {
  return useQuery<SandboxStats>({
    queryKey: ["/api/sandbox/stats"],
    refetchInterval: 60000,
  });
}

export function useSubmitFile() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: { file: File }) => {
      const formData = new FormData();
      formData.append("file", data.file);

      const response = await fetch("/api/sandbox/submit", {
        method: "POST",
        body: formData,
        credentials: "include",
      });

      if (!response.ok) throw new Error(await response.text());
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "File Submitted",
        description: "File has been queued for sandbox analysis",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/submissions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/stats"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Submission Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useSubmitUrl() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: { url: string }) => {
      const response = await apiRequest("POST", "/api/sandbox/submit", data);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "URL Submitted",
        description: "URL has been queued for sandbox analysis",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/submissions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/stats"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Submission Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useDeleteSandboxSubmission() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (submissionId: string) => {
      await apiRequest("DELETE", `/api/sandbox/submissions/${submissionId}`);
    },
    onSuccess: () => {
      toast({
        title: "Submission Deleted",
        description: "Sandbox submission has been removed",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/submissions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/stats"] });
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

export function useReanalyzeSubmission() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (submissionId: string) => {
      const response = await apiRequest("POST", `/api/sandbox/submissions/${submissionId}/reanalyze`);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Reanalysis Started",
        description: "Submission is being reanalyzed",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/submissions"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Reanalysis Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useDownloadSandboxReport() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: {
      submissionId: string;
      format: "json" | "pdf";
    }) => {
      const response = await fetch(`/api/sandbox/submissions/${data.submissionId}/report?format=${data.format}`, {
        method: "GET",
        credentials: "include",
      });

      if (!response.ok) throw new Error(await response.text());

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const filename = `sandbox-report-${data.submissionId}.${data.format}`;

      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);

      return { success: true };
    },
    onSuccess: () => {
      toast({
        title: "Report Downloaded",
        description: "Sandbox report has been downloaded",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Download Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}
