import { useQuery } from "@tanstack/react-query";

export interface AuditLog {
  id: string;
  evaluationId?: string;
  action: string;
  actorId?: string;
  actorType: "user" | "agent" | "system";
  targetResource: string;
  changes?: Record<string, any>;
  ipAddress?: string;
  timestamp: string;
  severity?: "info" | "warning" | "error" | "critical";
  category?: string;
}

export interface AuditLogStats {
  total: number;
  today: number;
  critical: number;
  uniqueUsers: number;
}

export function useAuditLogs(filters?: {
  evaluationId?: string;
  actorType?: string;
  severity?: string;
  startDate?: string;
  endDate?: string;
  limit?: number;
}) {
  const queryKey = filters
    ? [`/api/aev/audit-logs?${new URLSearchParams(filters as any).toString()}`]
    : ["/api/aev/audit-logs"];

  return useQuery<AuditLog[]>({
    queryKey,
    refetchInterval: 30000, // Refresh every 30 seconds
  });
}

export function useAuditLogsByEvaluation(evaluationId: string | null) {
  return useQuery<AuditLog[]>({
    queryKey: [`/api/audit-logs/evaluation/${evaluationId}`],
    enabled: !!evaluationId,
    refetchInterval: 30000,
  });
}

export function useAuditLogStats() {
  return useQuery<AuditLogStats>({
    queryKey: ["/api/aev/audit-logs/stats"],
    refetchInterval: 60000, // Refresh every minute
  });
}

export function useAuditLogVerification() {
  return useQuery<{
    verified: boolean;
    totalLogs: number;
    hashChainValid: boolean;
    message: string;
  }>({
    queryKey: ["/api/aev/audit-logs/verify"],
    refetchInterval: false, // Only fetch on demand
  });
}
