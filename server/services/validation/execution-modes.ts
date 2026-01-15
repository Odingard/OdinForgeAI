export type ExecutionMode = "safe" | "simulation" | "live";

export interface ExecutionModeConfig {
  mode: ExecutionMode;
  allowedOperations: {
    bannerGrabbing: boolean;
    versionDetection: boolean;
    portScanning: boolean;
    credentialTesting: boolean;
    payloadInjection: boolean;
    exploitExecution: boolean;
    dataExfiltration: boolean;
  };
  restrictions: {
    maxConcurrentProbes: number;
    maxPayloadSize: number;
    timeoutMs: number;
    requiresApproval: boolean;
    allowedTargetPatterns: string[];
    blockedTargetPatterns: string[];
  };
  auditLevel: "minimal" | "standard" | "comprehensive";
}

const MODE_CONFIGS: Record<ExecutionMode, ExecutionModeConfig> = {
  safe: {
    mode: "safe",
    allowedOperations: {
      bannerGrabbing: true,
      versionDetection: true,
      portScanning: true,
      credentialTesting: false,
      payloadInjection: false,
      exploitExecution: false,
      dataExfiltration: false,
    },
    restrictions: {
      maxConcurrentProbes: 5,
      maxPayloadSize: 0,
      timeoutMs: 10000,
      requiresApproval: false,
      allowedTargetPatterns: ["*"],
      blockedTargetPatterns: [],
    },
    auditLevel: "minimal",
  },
  simulation: {
    mode: "simulation",
    allowedOperations: {
      bannerGrabbing: true,
      versionDetection: true,
      portScanning: true,
      credentialTesting: true,
      payloadInjection: true,
      exploitExecution: false,
      dataExfiltration: false,
    },
    restrictions: {
      maxConcurrentProbes: 10,
      maxPayloadSize: 1024,
      timeoutMs: 30000,
      requiresApproval: false,
      allowedTargetPatterns: ["*"],
      blockedTargetPatterns: ["*.gov", "*.mil", "*.edu"],
    },
    auditLevel: "standard",
  },
  live: {
    mode: "live",
    allowedOperations: {
      bannerGrabbing: true,
      versionDetection: true,
      portScanning: true,
      credentialTesting: true,
      payloadInjection: true,
      exploitExecution: true,
      dataExfiltration: true,
    },
    restrictions: {
      maxConcurrentProbes: 20,
      maxPayloadSize: 65536,
      timeoutMs: 120000,
      requiresApproval: true,
      allowedTargetPatterns: [],
      blockedTargetPatterns: ["*.gov", "*.mil", "*.edu", "localhost", "127.0.0.1", "10.*", "172.16.*", "192.168.*"],
    },
    auditLevel: "comprehensive",
  },
};

export function getExecutionModeConfig(mode: ExecutionMode): ExecutionModeConfig {
  return MODE_CONFIGS[mode];
}

export interface OperationValidationResult {
  allowed: boolean;
  requiresApproval?: boolean;
  reason?: string;
  requiredApprovalLevel?: "manager" | "security_lead" | "ciso";
}

export function validateOperation(
  mode: ExecutionMode,
  operation: keyof ExecutionModeConfig["allowedOperations"],
  target?: string
): OperationValidationResult {
  const config = getExecutionModeConfig(mode);
  
  if (!config.allowedOperations[operation]) {
    return {
      allowed: false,
      reason: `Operation '${operation}' is not allowed in '${mode}' mode`,
    };
  }
  
  if (target) {
    const blocked = config.restrictions.blockedTargetPatterns.some(pattern => 
      matchPattern(target, pattern)
    );
    if (blocked) {
      return {
        allowed: false,
        reason: `Target '${target}' matches a blocked pattern in '${mode}' mode`,
      };
    }
    
    if (config.restrictions.allowedTargetPatterns.length > 0 && 
        !config.restrictions.allowedTargetPatterns.includes("*")) {
      const allowed = config.restrictions.allowedTargetPatterns.some(pattern =>
        matchPattern(target, pattern)
      );
      if (!allowed) {
        return {
          allowed: false,
          reason: `Target '${target}' is not in the allowed target list for '${mode}' mode`,
        };
      }
    }
  }
  
  if (config.restrictions.requiresApproval) {
    return {
      allowed: false,
      requiresApproval: true,
      reason: "Operation requires approval before execution in live mode",
      requiredApprovalLevel: operation === "exploitExecution" ? "ciso" : 
                            operation === "dataExfiltration" ? "security_lead" : "manager",
    };
  }
  
  return { allowed: true, requiresApproval: false };
}

function matchPattern(target: string, pattern: string): boolean {
  if (pattern === "*") return true;
  
  const regex = new RegExp(
    "^" + pattern
      .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
    + "$",
    "i"
  );
  
  return regex.test(target);
}

export interface ModeTransitionRequest {
  fromMode: ExecutionMode;
  toMode: ExecutionMode;
  requestedBy: string;
  reason: string;
  targetScope: string[];
  duration: number;
}

export interface ModeTransitionResult {
  allowed: boolean;
  requiresApproval: boolean;
  approvalLevel?: "manager" | "security_lead" | "ciso";
  reason?: string;
}

export function validateModeTransition(request: ModeTransitionRequest): ModeTransitionResult {
  const modeOrder = { safe: 0, simulation: 1, live: 2 };
  
  if (modeOrder[request.toMode] <= modeOrder[request.fromMode]) {
    return {
      allowed: true,
      requiresApproval: false,
      reason: "Downgrading or maintaining mode level is always allowed",
    };
  }
  
  if (request.toMode === "simulation") {
    return {
      allowed: true,
      requiresApproval: true,
      approvalLevel: "manager",
      reason: "Upgrading to simulation mode requires manager approval",
    };
  }
  
  if (request.toMode === "live") {
    return {
      allowed: true,
      requiresApproval: true,
      approvalLevel: "ciso",
      reason: "Upgrading to live mode requires CISO approval and creates full audit trail",
    };
  }
  
  return {
    allowed: false,
    requiresApproval: false,
    reason: "Invalid mode transition",
  };
}

export class ExecutionModeEnforcer {
  private currentMode: ExecutionMode = "safe";
  private modeOverrides: Map<string, { mode: ExecutionMode; expiresAt: Date }> = new Map();
  
  constructor(defaultMode: ExecutionMode = "safe") {
    this.currentMode = defaultMode;
  }
  
  getMode(tenantId?: string): ExecutionMode {
    if (tenantId) {
      const override = this.modeOverrides.get(tenantId);
      if (override && override.expiresAt > new Date()) {
        return override.mode;
      }
      this.modeOverrides.delete(tenantId);
    }
    return this.currentMode;
  }
  
  setMode(mode: ExecutionMode): void {
    this.currentMode = mode;
  }
  
  setTenantOverride(tenantId: string, mode: ExecutionMode, durationMinutes: number): void {
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + durationMinutes);
    this.modeOverrides.set(tenantId, { mode, expiresAt });
  }
  
  clearTenantOverride(tenantId: string): void {
    this.modeOverrides.delete(tenantId);
  }
  
  validateAndEnforce<T>(
    operation: keyof ExecutionModeConfig["allowedOperations"],
    target: string,
    tenantId: string,
    executor: () => T,
    approvalId?: string
  ): { result?: T; error?: string; requiresApproval?: boolean; approvalLevel?: string } {
    const mode = this.getMode(tenantId);
    const validation = validateOperation(mode, operation, target);
    
    if (validation.requiresApproval && validation.requiredApprovalLevel) {
      if (!approvalId) {
        return {
          requiresApproval: true,
          approvalLevel: validation.requiredApprovalLevel,
          error: validation.reason,
        };
      }
    }
    
    if (!validation.allowed && !validation.requiresApproval) {
      return { error: validation.reason };
    }
    
    try {
      const result = executor();
      return { result };
    } catch (error) {
      return { error: error instanceof Error ? error.message : "Execution failed" };
    }
  }
  
  async validateAndEnforceAsync<T>(
    operation: keyof ExecutionModeConfig["allowedOperations"],
    target: string,
    tenantId: string,
    executor: () => Promise<T>,
    approvalId?: string
  ): Promise<{ result?: T; error?: string; requiresApproval?: boolean; approvalLevel?: string }> {
    const mode = this.getMode(tenantId);
    const validation = validateOperation(mode, operation, target);
    
    if (validation.requiresApproval && validation.requiredApprovalLevel) {
      if (!approvalId) {
        return {
          requiresApproval: true,
          approvalLevel: validation.requiredApprovalLevel,
          error: validation.reason,
        };
      }
    }
    
    if (!validation.allowed && !validation.requiresApproval) {
      return { error: validation.reason };
    }
    
    try {
      const result = await executor();
      return { result };
    } catch (error) {
      return { error: error instanceof Error ? error.message : "Execution failed" };
    }
  }
}

export const executionModeEnforcer = new ExecutionModeEnforcer("safe");

export function getExecutionModeSummary(mode: ExecutionMode): {
  mode: ExecutionMode;
  description: string;
  allowedOperations: string[];
  blockedOperations: string[];
  requiresApproval: boolean;
} {
  const config = getExecutionModeConfig(mode);
  const allowed: string[] = [];
  const blocked: string[] = [];
  
  for (const [op, isAllowed] of Object.entries(config.allowedOperations)) {
    if (isAllowed) {
      allowed.push(op);
    } else {
      blocked.push(op);
    }
  }
  
  const descriptions: Record<ExecutionMode, string> = {
    safe: "Read-only reconnaissance and version detection. No active exploitation.",
    simulation: "Safe payload testing to demonstrate exploitability without real impact.",
    live: "Full exploitation capabilities. Requires explicit approval and creates audit trail.",
  };
  
  return {
    mode,
    description: descriptions[mode],
    allowedOperations: allowed,
    blockedOperations: blocked,
    requiresApproval: config.restrictions.requiresApproval,
  };
}
