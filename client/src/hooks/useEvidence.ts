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

/**
 * Map server ValidationEvidenceArtifact to frontend Evidence interface.
 * Server fields: id, evaluationId, findingId, scanId, organizationId, verdict,
 *   artifactSizeBytes, capturedAt, httpResponse, httpRequest, rawDataBase64,
 *   confidenceScore, artifactType, description
 */
function mapServerEvidence(a: any): Evidence {
  const verdict = a.verdict || "theoretical";
  return {
    id: a.id,
    evaluationId: a.evaluationId || a.findingId || "",
    type: a.artifactType || a.type || "file",
    description: a.description || a.findingId || undefined,
    data: a.httpResponse || a.rawDataBase64 || a.data || null,
    fileName: a.fileName || (a.httpRequest?.url ? new URL(a.httpRequest.url, "http://localhost").pathname.split("/").pop() : undefined),
    fileSize: a.artifactSizeBytes ?? a.fileSize,
    hash: a.hash || a.contentHash || undefined,
    verified: a.verified ?? (verdict === "confirmed" || verdict === "likely"),
    createdAt: a.capturedAt
      ? new Date(a.capturedAt).toISOString()
      : a.createdAt
        ? new Date(a.createdAt).toISOString()
        : new Date().toISOString(),
  };
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
    select: (data: any) => {
      const arr = Array.isArray(data) ? data : data?.evidence || data?.artifacts || [];
      return arr.map(mapServerEvidence);
    },
  });
}

export function useEvidenceById(evidenceId: string | null) {
  return useQuery<Evidence>({
    queryKey: [`/api/evidence/${evidenceId}`],
    enabled: !!evidenceId,
    select: (data: any) => mapServerEvidence(data),
  });
}

export function useEvidenceSummary() {
  return useQuery<EvidenceSummary>({
    queryKey: ["/api/evidence/summary"],
    refetchInterval: 60000,
    select: (data: any) => ({
      total: data.totalArtifacts ?? data.total ?? 0,
      unverified: data.unverified ?? (
        (data.totalArtifacts ?? 0) - (data.confirmedCount ?? 0) - (data.likelyCount ?? 0)
      ),
      storageUsedMB: data.storageUsedMB ?? (
        (data.totalSizeBytes ?? 0) / (1024 * 1024)
      ),
      byType: data.byType ?? {},
    }),
  });
}

export function useEvidenceByEvaluation(evaluationId: string | null) {
  return useQuery<Evidence[]>({
    queryKey: [`/api/evaluations/${evaluationId}/evidence`],
    enabled: !!evaluationId,
    refetchInterval: 30000,
    select: (data: any) => {
      const arr = Array.isArray(data) ? data : data?.evidence || data?.artifacts || [];
      return arr.map(mapServerEvidence);
    },
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
      // Convert file to base64 for JSON upload (no multipart parser on server)
      const arrayBuffer = await data.file.arrayBuffer();
      const base64 = btoa(
        new Uint8Array(arrayBuffer).reduce((s, b) => s + String.fromCharCode(b), "")
      );

      const response = await apiRequest("POST", "/api/evidence", {
        evaluationId: data.evaluationId,
        evidenceType: data.type,
        fileName: data.file.name,
        fileSize: data.file.size,
        mimeType: data.file.type,
        content: base64,
        description: data.description,
      });

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
