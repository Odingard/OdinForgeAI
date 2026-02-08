import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export interface Evidence {
  id: string;
  evaluationId: string;
  type: "screenshot" | "log" | "network_capture" | "file" | "report";
  description?: string;
  data: any;
  fileName?: string;
  fileSize?: number;
  hash?: string;
  verified?: boolean;
  createdAt: string;
}

export interface EvidenceSummary {
  total: number;
  unverified: number;
  storageUsedMB: number;
  byType: Record<string, number>;
}

export function useEvidence(filters?: {
  evaluationId?: string;
  type?: string;
  verified?: boolean;
}) {
  const queryKey = filters
    ? [`/api/evidence?${new URLSearchParams(filters as any).toString()}`]
    : ["/api/evidence"];

  return useQuery<Evidence[]>({
    queryKey,
    refetchInterval: 30000,
  });
}

export function useEvidenceById(evidenceId: string | null) {
  return useQuery<Evidence>({
    queryKey: [`/api/evidence/${evidenceId}`],
    enabled: !!evidenceId,
  });
}

export function useEvidenceSummary() {
  return useQuery<EvidenceSummary>({
    queryKey: ["/api/evidence/summary"],
    refetchInterval: 60000,
  });
}

export function useEvidenceByEvaluation(evaluationId: string | null) {
  return useQuery<Evidence[]>({
    queryKey: [`/api/evaluations/${evaluationId}/evidence`],
    enabled: !!evaluationId,
    refetchInterval: 30000,
  });
}

export function useUploadEvidence() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: {
      evaluationId: string;
      type: string;
      file: File;
      description?: string;
    }) => {
      const formData = new FormData();
      formData.append("evaluationId", data.evaluationId);
      formData.append("type", data.type);
      formData.append("file", data.file);
      if (data.description) formData.append("description", data.description);

      const response = await fetch("/api/evidence", {
        method: "POST",
        body: formData,
        credentials: "include",
      });

      if (!response.ok) throw new Error(await response.text());
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Evidence Uploaded",
        description: "Evidence has been uploaded successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence"] });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence/summary"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Upload Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useDeleteEvidence() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (evidenceId: string) => {
      await apiRequest("DELETE", `/api/evidence/${evidenceId}`);
    },
    onSuccess: () => {
      toast({
        title: "Evidence Deleted",
        description: "Evidence has been removed",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence"] });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence/summary"] });
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

export function useVerifyEvidence() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (evidenceId: string) => {
      const response = await apiRequest("POST", `/api/evidence/${evidenceId}/verify`);
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: data.verified ? "Evidence Verified" : "Verification Failed",
        description: data.message,
        variant: data.verified ? "default" : "destructive",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Verification Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useCleanupEvidence() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (maxAgeHours: number = 720) => {
      const response = await apiRequest("POST", "/api/evidence/cleanup", { maxAgeHours });
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Cleanup Complete",
        description: `Removed ${data.deletedCount} old evidence items`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence"] });
      queryClient.invalidateQueries({ queryKey: ["/api/evidence/summary"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Cleanup Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}
