import { randomUUID } from "crypto";

export type SandboxedOperationType = 
  | "protocol_probe"
  | "vulnerability_scan"
  | "credential_test"
  | "payload_injection"
  | "network_scan"
  | "port_scan"
  | "exploit_execution"
  | "data_exfiltration";

export interface ResourceLimits {
  maxExecutionTimeMs: number;
  maxConcurrentOperations: number;
  maxMemoryMB: number;
  maxRequestsPerMinute: number;
  maxPayloadSizeBytes: number;
  maxTargetsPerOperation: number;
}

export interface SandboxConfig {
  enabled: boolean;
  limits: ResourceLimits;
  allowedOperations: SandboxedOperationType[];
  blockedTargetPatterns: string[];
  requireApprovalForLiveMode: boolean;
}

export interface SandboxedOperation {
  id: string;
  operationType: SandboxedOperationType;
  target: string;
  startedAt: Date;
  timeoutMs: number;
  abortController: AbortController;
  status: "running" | "completed" | "aborted" | "timeout" | "error";
  result?: any;
  error?: string;
  tenantId: string;
  organizationId: string;
  executionMode: "safe" | "simulation" | "live";
}

export interface KillSwitchState {
  engaged: boolean;
  engagedAt?: Date;
  engagedBy?: string;
  reason?: string;
  scope: "global" | "tenant" | "operation";
  affectedTenants?: string[];
  affectedOperations?: string[];
}

const DEFAULT_LIMITS: ResourceLimits = {
  maxExecutionTimeMs: 30000,
  maxConcurrentOperations: 10,
  maxMemoryMB: 512,
  maxRequestsPerMinute: 100,
  maxPayloadSizeBytes: 1024 * 1024,
  maxTargetsPerOperation: 50,
};

const DEFAULT_CONFIG: SandboxConfig = {
  enabled: true,
  limits: DEFAULT_LIMITS,
  allowedOperations: [
    "protocol_probe",
    "vulnerability_scan",
    "credential_test",
    "network_scan",
    "port_scan",
    "payload_injection",
    "exploit_execution",
  ],
  blockedTargetPatterns: [
    "localhost",
    "127\\.0\\.0\\.",
    "::1",
    "0\\.0\\.0\\.0",
    "10\\.",
    "172\\.(1[6-9]|2[0-9]|3[01])\\.",
    "192\\.168\\.",
    "\\.gov$",
    "\\.mil$",
  ],
  requireApprovalForLiveMode: true,
};

class SandboxExecutor {
  private config: SandboxConfig = DEFAULT_CONFIG;
  private activeOperations: Map<string, SandboxedOperation> = new Map();
  private killSwitch: KillSwitchState = { engaged: false, scope: "global" };
  private requestCounts: Map<string, { count: number; resetAt: number }> = new Map();
  private tenantConfigs: Map<string, Partial<SandboxConfig>> = new Map();

  getConfig(): SandboxConfig {
    return { ...this.config };
  }

  setConfig(config: Partial<SandboxConfig>): void {
    this.config = { ...this.config, ...config };
  }

  setTenantConfig(tenantId: string, config: Partial<SandboxConfig>): void {
    this.tenantConfigs.set(tenantId, config);
  }

  getTenantConfig(tenantId: string): SandboxConfig {
    const tenantConfig = this.tenantConfigs.get(tenantId);
    if (tenantConfig) {
      return {
        ...this.config,
        ...tenantConfig,
        limits: { ...this.config.limits, ...tenantConfig.limits },
      };
    }
    return this.config;
  }

  isKillSwitchEngaged(tenantId?: string, operationType?: SandboxedOperationType): boolean {
    if (!this.killSwitch.engaged) return false;
    
    switch (this.killSwitch.scope) {
      case "global":
        return true;
      case "tenant":
        return tenantId ? this.killSwitch.affectedTenants?.includes(tenantId) || false : false;
      case "operation":
        return operationType ? this.killSwitch.affectedOperations?.includes(operationType) || false : false;
      default:
        return false;
    }
  }

  engageKillSwitch(options: {
    scope: "global" | "tenant" | "operation";
    reason: string;
    engagedBy: string;
    affectedTenants?: string[];
    affectedOperations?: string[];
  }): KillSwitchState {
    this.killSwitch = {
      engaged: true,
      engagedAt: new Date(),
      engagedBy: options.engagedBy,
      reason: options.reason,
      scope: options.scope,
      affectedTenants: options.affectedTenants,
      affectedOperations: options.affectedOperations,
    };

    this.abortAffectedOperations();
    
    console.log(`[Sandbox] KILL SWITCH ENGAGED: ${options.reason} by ${options.engagedBy}, scope: ${options.scope}`);
    
    return { ...this.killSwitch };
  }

  disengageKillSwitch(disengagedBy: string): KillSwitchState {
    if (this.killSwitch.engaged) {
      console.log(`[Sandbox] Kill switch disengaged by ${disengagedBy}`);
    }
    
    this.killSwitch = { engaged: false, scope: "global" };
    return { ...this.killSwitch };
  }

  getKillSwitchState(): KillSwitchState {
    return { ...this.killSwitch };
  }

  private abortAffectedOperations(): void {
    Array.from(this.activeOperations.entries()).forEach(([id, op]) => {
      const shouldAbort = this.isKillSwitchEngaged(op.tenantId, op.operationType);
      if (shouldAbort && op.status === "running") {
        op.abortController.abort();
        op.status = "aborted";
        op.error = "Operation aborted by kill switch";
        console.log(`[Sandbox] Aborted operation ${id} due to kill switch`);
      }
    });
  }

  validateTarget(target: string, tenantId: string = "default"): { valid: boolean; reason?: string } {
    const config = this.getTenantConfig(tenantId);
    
    for (const pattern of config.blockedTargetPatterns) {
      const regex = new RegExp(pattern, "i");
      if (regex.test(target)) {
        return { valid: false, reason: `Target matches blocked pattern: ${pattern}` };
      }
    }
    
    return { valid: true };
  }

  checkRateLimits(tenantId: string): { allowed: boolean; resetIn?: number; remaining?: number } {
    const config = this.getTenantConfig(tenantId);
    const now = Date.now();
    const key = `rate:${tenantId}`;
    
    let rateInfo = this.requestCounts.get(key);
    
    if (!rateInfo || now > rateInfo.resetAt) {
      rateInfo = { count: 0, resetAt: now + 60000 };
      this.requestCounts.set(key, rateInfo);
    }
    
    const remaining = config.limits.maxRequestsPerMinute - rateInfo.count;
    const resetIn = Math.max(0, rateInfo.resetAt - now);
    
    if (rateInfo.count >= config.limits.maxRequestsPerMinute) {
      return { allowed: false, resetIn, remaining: 0 };
    }
    
    rateInfo.count++;
    return { allowed: true, resetIn, remaining: remaining - 1 };
  }

  checkConcurrencyLimits(tenantId: string): { allowed: boolean; current: number; max: number } {
    const config = this.getTenantConfig(tenantId);
    const current = Array.from(this.activeOperations.values()).filter(
      op => op.tenantId === tenantId && op.status === "running"
    ).length;
    
    return {
      allowed: current < config.limits.maxConcurrentOperations,
      current,
      max: config.limits.maxConcurrentOperations,
    };
  }

  checkPayloadSize(payloadSizeBytes: number, tenantId: string): { allowed: boolean; reason?: string } {
    const config = this.getTenantConfig(tenantId);
    if (payloadSizeBytes > config.limits.maxPayloadSizeBytes) {
      return { 
        allowed: false, 
        reason: `Payload size ${payloadSizeBytes} bytes exceeds limit of ${config.limits.maxPayloadSizeBytes} bytes` 
      };
    }
    return { allowed: true };
  }

  checkTargetsCount(targetsCount: number, tenantId: string): { allowed: boolean; reason?: string } {
    const config = this.getTenantConfig(tenantId);
    if (targetsCount > config.limits.maxTargetsPerOperation) {
      return { 
        allowed: false, 
        reason: `Targets count ${targetsCount} exceeds limit of ${config.limits.maxTargetsPerOperation}` 
      };
    }
    return { allowed: true };
  }

  checkLiveModeApproval(executionMode: "safe" | "simulation" | "live", approvalId?: string): { allowed: boolean; reason?: string } {
    if (executionMode === "live" && this.config.requireApprovalForLiveMode && !approvalId) {
      return { 
        allowed: false, 
        reason: "Live mode operations require prior approval. Please obtain approval before executing." 
      };
    }
    return { allowed: true };
  }

  async execute<T>(
    operationType: SandboxedOperationType,
    target: string,
    operation: (signal: AbortSignal) => Promise<T>,
    options: {
      tenantId?: string;
      organizationId?: string;
      executionMode?: "safe" | "simulation" | "live";
      timeoutMs?: number;
      payloadSizeBytes?: number;
      targetsCount?: number;
      approvalId?: string;
    } = {}
  ): Promise<{ success: boolean; result?: T; error?: string; operationId: string; executionTimeMs: number }> {
    const tenantId = options.tenantId || "default";
    const organizationId = options.organizationId || "default";
    const executionMode = options.executionMode || "safe";
    const config = this.getTenantConfig(tenantId);
    const timeoutMs = options.timeoutMs || config.limits.maxExecutionTimeMs;
    
    const operationId = `sandbox-${randomUUID().slice(0, 12)}`;
    const startTime = Date.now();

    if (!config.enabled) {
      return { success: false, error: "Sandbox execution is disabled", operationId, executionTimeMs: 0 };
    }

    if (this.isKillSwitchEngaged(tenantId, operationType)) {
      return { 
        success: false, 
        error: `Kill switch is engaged: ${this.killSwitch.reason}`, 
        operationId, 
        executionTimeMs: 0 
      };
    }

    if (!config.allowedOperations.includes(operationType)) {
      return { 
        success: false, 
        error: `Operation type '${operationType}' is not allowed`, 
        operationId, 
        executionTimeMs: 0 
      };
    }

    const targetValidation = this.validateTarget(target, tenantId);
    if (!targetValidation.valid) {
      return { 
        success: false, 
        error: targetValidation.reason, 
        operationId, 
        executionTimeMs: 0 
      };
    }

    const rateCheck = this.checkRateLimits(tenantId);
    if (!rateCheck.allowed) {
      return { 
        success: false, 
        error: `Rate limit exceeded. Retry in ${Math.ceil(rateCheck.resetIn! / 1000)}s`, 
        operationId, 
        executionTimeMs: 0 
      };
    }

    const concurrencyCheck = this.checkConcurrencyLimits(tenantId);
    if (!concurrencyCheck.allowed) {
      return { 
        success: false, 
        error: `Concurrency limit reached (${concurrencyCheck.current}/${concurrencyCheck.max})`, 
        operationId, 
        executionTimeMs: 0 
      };
    }

    if (options.payloadSizeBytes !== undefined) {
      const payloadCheck = this.checkPayloadSize(options.payloadSizeBytes, tenantId);
      if (!payloadCheck.allowed) {
        return { 
          success: false, 
          error: payloadCheck.reason, 
          operationId, 
          executionTimeMs: 0 
        };
      }
    }

    if (options.targetsCount !== undefined) {
      const targetsCheck = this.checkTargetsCount(options.targetsCount, tenantId);
      if (!targetsCheck.allowed) {
        return { 
          success: false, 
          error: targetsCheck.reason, 
          operationId, 
          executionTimeMs: 0 
        };
      }
    }

    const liveModeCheck = this.checkLiveModeApproval(executionMode, options.approvalId);
    if (!liveModeCheck.allowed) {
      return { 
        success: false, 
        error: liveModeCheck.reason, 
        operationId, 
        executionTimeMs: 0 
      };
    }

    const abortController = new AbortController();
    const sandboxedOp: SandboxedOperation = {
      id: operationId,
      operationType,
      target,
      startedAt: new Date(),
      timeoutMs,
      abortController,
      status: "running",
      tenantId,
      organizationId,
      executionMode,
    };

    this.activeOperations.set(operationId, sandboxedOp);

    const timeoutId = setTimeout(() => {
      if (sandboxedOp.status === "running") {
        abortController.abort();
        sandboxedOp.status = "timeout";
        sandboxedOp.error = `Operation timed out after ${timeoutMs}ms`;
        console.log(`[Sandbox] Operation ${operationId} timed out`);
      }
    }, timeoutMs);

    try {
      const result = await operation(abortController.signal);
      
      sandboxedOp.status = "completed";
      sandboxedOp.result = result;
      
      return {
        success: true,
        result,
        operationId,
        executionTimeMs: Date.now() - startTime,
      };
    } catch (error: any) {
      if (error.name === "AbortError" || abortController.signal.aborted) {
        sandboxedOp.status = sandboxedOp.status === "timeout" ? "timeout" : "aborted";
        return {
          success: false,
          error: sandboxedOp.error || "Operation was aborted",
          operationId,
          executionTimeMs: Date.now() - startTime,
        };
      }
      
      sandboxedOp.status = "error";
      sandboxedOp.error = error.message;
      
      return {
        success: false,
        error: error.message,
        operationId,
        executionTimeMs: Date.now() - startTime,
      };
    } finally {
      clearTimeout(timeoutId);
      
      setTimeout(() => {
        this.activeOperations.delete(operationId);
      }, 60000);
    }
  }

  abortOperation(operationId: string, reason: string = "Manually aborted"): boolean {
    const op = this.activeOperations.get(operationId);
    if (!op || op.status !== "running") {
      return false;
    }
    
    op.abortController.abort();
    op.status = "aborted";
    op.error = reason;
    
    console.log(`[Sandbox] Operation ${operationId} aborted: ${reason}`);
    return true;
  }

  abortAllOperations(tenantId?: string, reason: string = "All operations aborted"): number {
    let aborted = 0;
    
    Array.from(this.activeOperations.entries()).forEach(([id, op]) => {
      if (op.status === "running" && (!tenantId || op.tenantId === tenantId)) {
        this.abortOperation(id, reason);
        aborted++;
      }
    });
    
    console.log(`[Sandbox] Aborted ${aborted} operations${tenantId ? ` for tenant ${tenantId}` : ""}`);
    return aborted;
  }

  getActiveOperations(tenantId?: string): SandboxedOperation[] {
    return Array.from(this.activeOperations.values())
      .filter(op => !tenantId || op.tenantId === tenantId)
      .map(op => ({
        ...op,
        abortController: undefined as any,
      }));
  }

  getStats(tenantId?: string): {
    activeOperations: number;
    completedOperations: number;
    abortedOperations: number;
    timedOutOperations: number;
    erroredOperations: number;
    killSwitchEngaged: boolean;
  } {
    const ops = tenantId 
      ? Array.from(this.activeOperations.values()).filter(op => op.tenantId === tenantId)
      : Array.from(this.activeOperations.values());
    
    return {
      activeOperations: ops.filter(op => op.status === "running").length,
      completedOperations: ops.filter(op => op.status === "completed").length,
      abortedOperations: ops.filter(op => op.status === "aborted").length,
      timedOutOperations: ops.filter(op => op.status === "timeout").length,
      erroredOperations: ops.filter(op => op.status === "error").length,
      killSwitchEngaged: this.isKillSwitchEngaged(tenantId),
    };
  }
}

export const sandboxExecutor = new SandboxExecutor();

export async function executeSandboxed<T>(
  operationType: SandboxedOperationType,
  target: string,
  operation: (signal: AbortSignal) => Promise<T>,
  options?: {
    tenantId?: string;
    organizationId?: string;
    executionMode?: "safe" | "simulation" | "live";
    timeoutMs?: number;
    payloadSizeBytes?: number;
    targetsCount?: number;
    approvalId?: string;
  }
): Promise<{ success: boolean; result?: T; error?: string; operationId: string; executionTimeMs: number }> {
  return sandboxExecutor.execute(operationType, target, operation, options);
}
