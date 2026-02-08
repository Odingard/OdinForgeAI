import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export interface Session {
  id: string;
  userId: string;
  username: string;
  startTime: string;
  endTime?: string;
  duration?: number;
  eventCount: number;
  riskScore: number;
  riskLevel: "low" | "medium" | "high" | "critical";
  suspicious: boolean;
  ipAddress?: string;
  userAgent?: string;
  location?: string;
}

export interface SessionEvent {
  id: string;
  sessionId: string;
  timestamp: string;
  type: string;
  action: string;
  resource?: string;
  details: any;
  riskScore?: number;
}

export interface SessionStats {
  totalSessions: number;
  activeSessions: number;
  suspiciousSessions: number;
  averageDuration: number;
  averageRiskScore: number;
}

export function useSessions(filters?: {
  userId?: string;
  riskLevel?: string;
  suspicious?: boolean;
  startDate?: string;
  endDate?: string;
}) {
  const queryKey = filters
    ? [`/api/sessions?${new URLSearchParams(filters as any).toString()}`]
    : ["/api/sessions"];

  return useQuery<Session[]>({
    queryKey,
    refetchInterval: 30000,
  });
}

export function useSessionById(sessionId: string | null) {
  return useQuery<Session>({
    queryKey: [`/api/sessions/${sessionId}`],
    enabled: !!sessionId,
  });
}

export function useSessionEvents(sessionId: string | null) {
  return useQuery<SessionEvent[]>({
    queryKey: [`/api/sessions/${sessionId}/events`],
    enabled: !!sessionId,
    refetchInterval: 10000,
  });
}

export function useSessionStats() {
  return useQuery<SessionStats>({
    queryKey: ["/api/sessions/stats"],
    refetchInterval: 60000,
  });
}

export function useTerminateSession() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (sessionId: string) => {
      const response = await apiRequest("POST", `/api/sessions/${sessionId}/terminate`);
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Session Terminated",
        description: "User session has been terminated",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/sessions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/sessions/stats"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Termination Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useFlagSession() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: { sessionId: string; reason: string }) => {
      const response = await apiRequest("POST", `/api/sessions/${data.sessionId}/flag`, {
        reason: data.reason,
      });
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Session Flagged",
        description: "Session has been marked for review",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/sessions"] });
    },
    onError: (error: Error) => {
      toast({
        title: "Flagging Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });
}

export function useExportSession() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (data: {
      sessionId: string;
      format: "json" | "csv" | "pdf";
    }) => {
      const response = await fetch(`/api/sessions/${data.sessionId}/export?format=${data.format}`, {
        method: "GET",
        credentials: "include",
      });

      if (!response.ok) throw new Error(await response.text());

      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const contentDisposition = response.headers.get("Content-Disposition");
      const filename = contentDisposition
        ? contentDisposition.split("filename=")[1]?.replace(/"/g, "")
        : `session-${data.sessionId}.${data.format}`;

      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);

      return { success: true };
    },
    onSuccess: () => {
      toast({
        title: "Export Complete",
        description: "Session data has been exported",
      });
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
