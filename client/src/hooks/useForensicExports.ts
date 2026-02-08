import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export interface ForensicExport {
  id: string;
  format: "pdf" | "json" | "xml" | "csv" | "zip";
  status: "pending" | "processing" | "completed" | "failed";
  evaluationIds: string[];
  evidenceIds: string[];
  reportIds: string[];
  encrypted: boolean;
  hash?: string;
  fileSize?: number;
  downloadUrl?: string;
  expiresAt?: string;
  createdAt: string;
  completedAt?: string;
  error?: string;
}

export interface ExportStats {
  total: number;
  pending: number;
  processing: number;
  completed: number;
  failed: number;
  totalSizeMB: number;
}

export function useForensicExports() {
  return useQuery<ForensicExport[]>({
    queryKey: ["/api/forensic-exports"],
    refetchInterval: 10000,
  });
}

export function useForensicExportById(exportId: string | null) {
  return useQuery<ForensicExport>({
    queryKey: [`/api/forensic-exports/${exportId}`],
    enabled: !!exportId,
    refetchInterval: 5000,
  });
}

export function useForensicExportStats() {
  return useQuery<ExportStats>({
    queryKey: ["/api/forensic-exports/stats"],
    refetchInterval: 30000,
  });
}

export function useCreateForensicExport() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: {
      format: "pdf" | "json" | "xml" | "csv" | "zip";
      evaluationIds?: string[];
      evidenceIds?: string[];
      reportIds?: string[];
      encrypted?: boolean;
      password?: string;
      startDate?: string;
      endDate?: string;
    }) => {
      const response = await apiRequest("POST", "/api/forensic-exports", data);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Export Created",
        description: "Forensic export package is being generated",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/forensic-exports"] });
      queryClient.invalidateQueries({ queryKey: ["/api/forensic-exports/stats"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Export Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useDeleteForensicExport() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (exportId: string) => {
      await apiRequest("DELETE", `/api/forensic-exports/${exportId}`);
    },
    onSuccess: () => {
      toast({
        title: "Export Deleted",
        description: "Forensic export has been removed",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/forensic-exports"] });
      queryClient.invalidateQueries({ queryKey: ["/api/forensic-exports/stats"] });
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

export function useDownloadForensicExport() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (exportId: string) => {
      const response = await fetch(`/api/forensic-exports/${exportId}/download`, {
        method: "GET",
        credentials: "include",
      });

      if (!response.ok) throw new Error(await response.text());

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const contentDisposition = response.headers.get("Content-Disposition");
      const filename = contentDisposition
        ? contentDisposition.split("filename=")[1]?.replace(/"/g, "")
        : `forensic-export-${exportId}.zip`;

      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);

      return { success: true };
    },
    onSuccess: () => {
      toast({
        title: "Download Started",
        description: "Forensic export package is downloading",
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
