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

function mapServerSession(s: any): Session {
  const startTime = s.startTime ? new Date(s.startTime).toISOString() : new Date().toISOString();
  const endTime = s.endTime ? new Date(s.endTime).toISOString() : undefined;
  const durationSec = s.endTime
    ? (new Date(s.endTime).getTime() - new Date(s.startTime).getTime()) / 1000
    : undefined;
  const eventCount = s.eventCount ?? s.events?.length ?? 0;
  const riskScore = s.riskScore ?? (s.findings?.length ? Math.min(10, s.findings.length * 2) : 0);
  const riskLevel: Session["riskLevel"] =
    riskScore >= 8 ? "critical" : riskScore >= 5 ? "high" : riskScore >= 3 ? "medium" : "low";

  return {
    id: s.id,
    userId: s.userId || s.metadata?.assessor || "system",
    username: s.username || s.metadata?.assessor || s.name || "Unknown",
    startTime,
    endTime,
    duration: durationSec,
    eventCount,
    riskScore,
    riskLevel,
    suspicious: s.suspicious ?? riskScore >= 7,
    ipAddress: s.ipAddress || s.target,
    userAgent: s.userAgent,
    location: s.location,
  };
}

function mapServerEvent(e: any, sessionId: string): SessionEvent {
  return {
    id: e.id,
    sessionId,
    timestamp: e.timestamp ? new Date(e.timestamp).toISOString() : new Date().toISOString(),
    type: e.type || "action",
    action: e.description || e.action || "",
    resource: e.source || e.resource,
    details: e.data || e.details || {},
    riskScore: e.riskScore,
  };
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
    select: (data: any) => {
      const arr = Array.isArray(data) ? data : data?.sessions || [];
      return arr.map(mapServerSession);
    },
  });
}

export function useSessionById(sessionId: string | null) {
  return useQuery<Session>({
    queryKey: [`/api/sessions/${sessionId}`],
    enabled: !!sessionId,
    select: (data: any) => mapServerSession(data),
  });
}

export function useSessionEvents(sessionId: string | null) {
  // Events are embedded in the session object, so fetch the session and extract events
  return useQuery<SessionEvent[]>({
    queryKey: [`/api/sessions/${sessionId}`],
    enabled: !!sessionId,
    refetchInterval: 10000,
    select: (data: any) => {
      const events = data?.events || [];
      return events.map((e: any) => mapServerEvent(e, sessionId || ""));
    },
  });
}

export function useSessionStats() {
  // Derive stats from the sessions list since no dedicated stats endpoint exists
  return useQuery<SessionStats>({
    queryKey: ["/api/sessions"],
    refetchInterval: 60000,
    select: (data: any) => {
      const arr = Array.isArray(data) ? data : data?.sessions || [];
      const sessions = arr.map(mapServerSession);
      const activeSessions = sessions.filter((s: Session) => !s.endTime).length;
      const suspiciousSessions = sessions.filter((s: Session) => s.suspicious).length;
      const durations = sessions.filter((s: Session) => s.duration).map((s: Session) => s.duration!);
      const avgDuration = durations.length > 0 ? durations.reduce((a: number, b: number) => a + b, 0) / durations.length : 0;
      const avgRisk = sessions.length > 0
        ? sessions.reduce((a: number, s: Session) => a + s.riskScore, 0) / sessions.length
        : 0;
      return {
        totalSessions: sessions.length,
        activeSessions,
        suspiciousSessions,
        averageDuration: avgDuration,
        averageRiskScore: avgRisk,
      };
    },
  });
}

export function useTerminateSession() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (sessionId: string) => {
      const response = await apiRequest("POST", `/api/sessions/${sessionId}/stop`);
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
      const accessToken = localStorage.getItem("odinforge_access_token");
      const headers: Record<string, string> = {};
      if (accessToken) headers["Authorization"] = `Bearer ${accessToken}`;
      const response = await fetch(`/api/sessions/${data.sessionId}/export?format=${data.format}`, {
        method: "GET",
        headers,
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
