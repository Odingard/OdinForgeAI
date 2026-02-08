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

/**
 * Map server SandboxSession to frontend SandboxSubmission.
 * Server fields: id, name, status, targetUrl, targetHost, executionMode,
 *   createdAt, closedAt, totalExecutions, successfulExecutions, failedExecutions
 */
function mapSessionToSubmission(s: any): SandboxSubmission {
  const status = s.status === "active"
    ? "analyzing"
    : s.status === "closed" || s.status === "completed"
      ? "completed"
      : s.status === "failed"
        ? "failed"
        : "queued";

  // Derive verdict from execution results
  const totalExec = s.totalExecutions || s.executionCount || 0;
  const failedExec = s.failedExecutions || 0;
  const successExec = s.successfulExecutions || 0;
  let verdict: SandboxSubmission["verdict"] = undefined;
  if (status === "completed" && totalExec > 0) {
    if (successExec > totalExec * 0.5) verdict = "malicious";
    else if (successExec > 0) verdict = "suspicious";
    else verdict = "clean";
  }

  return {
    id: s.id,
    fileName: undefined,
    url: s.targetUrl || s.targetHost || s.target,
    submissionType: "url",
    type: "url",
    status,
    verdict,
    score: totalExec > 0 ? Math.round((successExec / totalExec) * 10) : undefined,
    submittedAt: s.createdAt ? new Date(s.createdAt).toISOString() : new Date().toISOString(),
    completedAt: s.closedAt ? new Date(s.closedAt).toISOString() : undefined,
  };
}

/**
 * Map server execution results to frontend SandboxBehavior.
 */
function mapExecutionsToBehavior(sessionId: string, session: any, executions: any[]): SandboxBehavior {
  const networkActivity = executions
    .filter((e: any) => e.evidence?.request)
    .map((e: any, i: number) => ({
      id: e.id || `net-${i}`,
      destination: e.evidence?.request?.url || session?.targetUrl || "",
      port: 443,
      protocol: "HTTPS",
      timestamp: e.executedAt ? new Date(e.executedAt).toISOString() : new Date().toISOString(),
      type: e.evidence?.request?.method || "GET",
      destIp: session?.targetHost,
      domain: session?.targetUrl ? (() => { try { return new URL(session.targetUrl).hostname; } catch { return undefined; } })() : undefined,
      suspicious: e.success === true,
    }));

  const mitreAttackTechniques = executions
    .filter((e: any) => e.mitreAttackId)
    .map((e: any, i: number) => ({
      id: `mitre-${i}`,
      techniqueId: e.mitreAttackId || "",
      name: e.payloadName || e.payloadCategory || "Unknown",
      tactic: e.mitreTactic || "unknown",
      confidence: e.success ? "high" : "low",
    }));

  const iocs = executions
    .filter((e: any) => e.evidence?.indicators?.length)
    .flatMap((e: any) =>
      (e.evidence.indicators as string[]).map((indicator: string, i: number) => ({
        type: "indicator",
        value: indicator,
        malicious: e.success === true,
        context: e.payloadCategory || "sandbox execution",
      }))
    );

  return {
    submissionId: sessionId,
    networkActivity,
    fileActivity: [],
    registryActivity: [],
    processActivity: { processes: [] },
    mitreAttackTechniques,
    iocs,
  };
}

export function useSandboxSubmissions() {
  return useQuery<SandboxSubmission[]>({
    queryKey: ["/api/sandbox/sessions"],
    refetchInterval: 10000,
    select: (data: any) => {
      const sessions = Array.isArray(data) ? data : data?.sessions || [];
      return sessions.map(mapSessionToSubmission);
    },
  });
}

export function useSandboxBehavior(submissionId: string | null) {
  return useQuery<SandboxBehavior | null>({
    queryKey: [`/api/sandbox/sessions/${submissionId}/executions`],
    enabled: !!submissionId,
    refetchInterval: 5000,
    select: (data: any) => {
      if (!data) return null;
      const executions = Array.isArray(data) ? data : data?.executions || [];
      return mapExecutionsToBehavior(submissionId || "", null, executions);
    },
  });
}

export function useSandboxStats() {
  return useQuery<SandboxStats>({
    queryKey: ["/api/sandbox/sessions"],
    refetchInterval: 30000,
    select: (data: any) => {
      const sessions = Array.isArray(data) ? data : data?.sessions || [];
      const submissions = sessions.map(mapSessionToSubmission);
      return {
        totalSubmissions: submissions.length,
        queuedSubmissions: submissions.filter((s: SandboxSubmission) => s.status === "queued").length,
        analyzingSubmissions: submissions.filter((s: SandboxSubmission) => s.status === "analyzing").length,
        activeAnalyses: submissions.filter((s: SandboxSubmission) => s.status === "analyzing").length,
        completedSubmissions: submissions.filter((s: SandboxSubmission) => s.status === "completed").length,
        maliciousCount: submissions.filter((s: SandboxSubmission) => s.verdict === "malicious").length,
        suspiciousCount: submissions.filter((s: SandboxSubmission) => s.verdict === "suspicious").length,
        cleanCount: submissions.filter((s: SandboxSubmission) => s.verdict === "clean").length,
      };
    },
  });
}

export function useSubmitFile() {
  return useMutation({
    mutationFn: async (file: File) => {
      // Convert file to base64 and create a sandbox session
      const arrayBuffer = await file.arrayBuffer();
      const base64 = btoa(
        new Uint8Array(arrayBuffer).reduce((s, b) => s + String.fromCharCode(b), "")
      );

      const response = await apiRequest("POST", "/api/sandbox/sessions", {
        name: `File Analysis: ${file.name}`,
        description: `Sandbox analysis of uploaded file: ${file.name}`,
        executionMode: "safe",
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/sessions"] });
    },
  });
}

export function useSubmitUrl() {
  return useMutation({
    mutationFn: async (url: string) => {
      const response = await apiRequest("POST", "/api/sandbox/sessions", {
        name: `URL Analysis: ${url}`,
        description: `Sandbox analysis of URL target`,
        targetUrl: url,
        executionMode: "safe",
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/sessions"] });
    },
  });
}

export function useDeleteSandboxSubmission() {
  return useMutation({
    mutationFn: async (submissionId: string) => {
      const response = await apiRequest("POST", `/api/sandbox/sessions/${submissionId}/close`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/sessions"] });
    },
  });
}

export function useReanalyzeSubmission() {
  return useMutation({
    mutationFn: async (submissionId: string) => {
      // Re-execute with a basic probe payload
      const response = await apiRequest("POST", `/api/sandbox/sessions/${submissionId}/execute`, {
        payloadName: "Reanalysis Probe",
        payloadCategory: "reconnaissance",
        payloadContent: "GET / HTTP/1.1",
        targetEndpoint: "/",
        targetMethod: "GET",
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/sandbox/sessions"] });
    },
  });
}

export function useDownloadSandboxReport() {
  return useMutation({
    mutationFn: async (submissionId: string) => {
      const response = await apiRequest("GET", `/api/sandbox/sessions/${submissionId}`);
      const sessionData = await response.json();

      const execResponse = await apiRequest("GET", `/api/sandbox/sessions/${submissionId}/executions`);
      const execData = await execResponse.json();

      const report = {
        session: sessionData.session || sessionData,
        executions: execData.executions || execData,
        exportedAt: new Date().toISOString(),
      };

      const blob = new Blob(
        [JSON.stringify(report, null, 2)],
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
