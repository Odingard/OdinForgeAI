import { storage } from "../../storage";
import type { OrganizationGovernance, ScopeRule, InsertAuthorizationLog } from "@shared/schema";
import { 
  type ExecutionMode, 
  getExecutionModeConfig, 
  validateOperation,
  type ExecutionModeConfig
} from "../validation/execution-modes";

export interface GovernanceCheckResult {
  allowed: boolean;
  reason?: string;
  blockedBy?: "kill_switch" | "scope_rule" | "execution_mode" | "rate_limit";
  ruleId?: string;
  requiresApproval?: boolean;
  approvalLevel?: "manager" | "security_lead" | "ciso";
}

export interface TargetValidationRequest {
  target: string;
  targetType: "ip" | "hostname" | "cidr" | "url";
  operation: "evaluation" | "network_scan" | "cloud_discovery" | "external_recon" | "ai_simulation" | "exploit_validation" | "api_scan" | "auth_scan" | "full_assessment";
  userId?: string;
  tenantId?: string;
}

export interface OperationContext {
  operationType: keyof ExecutionModeConfig["allowedOperations"];
  target?: string;
  organizationId: string;
  userId?: string;
  requestId?: string;
}

export class GovernanceEnforcementService {
  private static instance: GovernanceEnforcementService;
  private governanceCache: Map<string, { governance: OrganizationGovernance; cachedAt: number }> = new Map();
  private scopeRulesCache: Map<string, { rules: ScopeRule[]; cachedAt: number }> = new Map();
  private readonly CACHE_TTL_MS = 30000;

  static getInstance(): GovernanceEnforcementService {
    if (!GovernanceEnforcementService.instance) {
      GovernanceEnforcementService.instance = new GovernanceEnforcementService();
    }
    return GovernanceEnforcementService.instance;
  }

  async checkKillSwitch(organizationId: string): Promise<GovernanceCheckResult> {
    const governance = await this.getGovernance(organizationId);
    
    if (!governance) {
      return { allowed: true };
    }
    
    if (governance.killSwitchActive) {
      return {
        allowed: false,
        reason: `Kill switch is active. Activated by ${governance.killSwitchActivatedBy || "system"} at ${governance.killSwitchActivatedAt?.toISOString() || "unknown time"}. All security testing operations are halted.`,
        blockedBy: "kill_switch",
      };
    }
    
    return { allowed: true };
  }

  async checkScopeRules(organizationId: string, target: string, targetType: string): Promise<GovernanceCheckResult> {
    const rules = await this.getScopeRules(organizationId);
    
    if (!rules || rules.length === 0) {
      return { allowed: true };
    }

    const sortedRules = [...rules].sort((a, b) => (b.priority || 0) - (a.priority || 0));
    
    for (const rule of sortedRules) {
      if (!rule.enabled) continue;
      
      if (rule.targetType !== targetType && rule.targetType !== "pattern") {
        continue;
      }
      
      const matches = this.matchTarget(target, rule.targetValue, rule.targetType);
      
      if (matches) {
        if (rule.ruleType === "block") {
          return {
            allowed: false,
            reason: `Target "${target}" blocked by scope rule "${rule.name}": ${rule.targetValue}`,
            blockedBy: "scope_rule",
            ruleId: rule.id,
          };
        } else if (rule.ruleType === "allow") {
          return { allowed: true };
        }
      }
    }
    
    return { allowed: true };
  }

  async checkExecutionMode(
    organizationId: string, 
    operation: keyof ExecutionModeConfig["allowedOperations"],
    target?: string
  ): Promise<GovernanceCheckResult> {
    const governance = await this.getGovernance(organizationId);
    
    if (!governance) {
      return { allowed: true };
    }
    
    const mode = (governance.executionMode || "safe") as ExecutionMode;
    const validation = validateOperation(mode, operation, target);
    
    if (!validation.allowed) {
      if (validation.requiresApproval) {
        return {
          allowed: false,
          reason: validation.reason || `Operation "${operation}" requires approval in "${mode}" mode`,
          blockedBy: "execution_mode",
          requiresApproval: true,
          approvalLevel: validation.requiredApprovalLevel,
        };
      }
      
      return {
        allowed: false,
        reason: validation.reason || `Operation "${operation}" is not allowed in "${mode}" mode`,
        blockedBy: "execution_mode",
      };
    }
    
    return { allowed: true };
  }

  async validateOperationStart(request: TargetValidationRequest): Promise<GovernanceCheckResult> {
    const organizationId = request.tenantId || "default";
    
    const killSwitchCheck = await this.checkKillSwitch(organizationId);
    if (!killSwitchCheck.allowed) {
      await this.logBlockedOperation(organizationId, request, killSwitchCheck);
      return killSwitchCheck;
    }
    
    const normalizedTarget = this.normalizeTarget(request.target);
    const scopeCheck = await this.checkScopeRules(organizationId, normalizedTarget, request.targetType);
    if (!scopeCheck.allowed) {
      await this.logBlockedOperation(organizationId, request, scopeCheck);
      return scopeCheck;
    }
    
    const operationMapping: Record<string, keyof ExecutionModeConfig["allowedOperations"]> = {
      "evaluation": "versionDetection",
      "network_scan": "portScanning",
      "cloud_discovery": "versionDetection",
      "external_recon": "bannerGrabbing",
      "ai_simulation": "credentialTesting",
      "exploit_validation": "payloadInjection",
      "api_scan": "payloadInjection",
      "auth_scan": "credentialTesting",
      "full_assessment": "payloadInjection",
      "breach_chain": "exploitExecution",
    };
    
    const executionOperation = operationMapping[request.operation] || "versionDetection";
    const modeCheck = await this.checkExecutionMode(organizationId, executionOperation, normalizedTarget);
    if (!modeCheck.allowed) {
      await this.logBlockedOperation(organizationId, request, modeCheck);
      return modeCheck;
    }
    
    return { allowed: true };
  }

  async canStartOperation(
    organizationId: string,
    operationType: string,
    target?: string
  ): Promise<{ canStart: boolean; reason?: string }> {
    const request: TargetValidationRequest = {
      target: target || "unknown",
      targetType: this.inferTargetType(target || ""),
      operation: operationType as TargetValidationRequest["operation"],
      tenantId: organizationId,
    };
    
    const result = await this.validateOperationStart(request);
    
    return {
      canStart: result.allowed,
      reason: result.reason,
    };
  }

  private async logBlockedOperation(
    organizationId: string,
    request: TargetValidationRequest,
    result: GovernanceCheckResult
  ): Promise<void> {
    try {
      const logEntry = {
        organizationId,
        action: "unauthorized_target_blocked",
        targetAsset: request.target,
        outcome: "blocked",
        details: {
          operation: request.operation,
          targetType: request.targetType,
          blockedBy: result.blockedBy || "",
          reason: result.reason || "",
          ruleId: result.ruleId || "",
          userId: request.userId || "",
        } as Record<string, any>,
        performedBy: request.userId || "system",
      } as InsertAuthorizationLog;
      
      await storage.createAuthorizationLog(logEntry);
    } catch (error) {
      console.error("[GovernanceEnforcement] Failed to log blocked operation:", error);
    }
  }

  async logOperationStarted(
    organizationId: string,
    operation: string,
    target: string,
    userId?: string,
    details?: Record<string, unknown>
  ): Promise<void> {
    try {
      await storage.createAuthorizationLog({
        organizationId,
        action: `${operation}_started`,
        targetAsset: target,
        outcome: "allowed",
        details: (details || {}) as Record<string, any>,
        performedBy: userId || "system",
      } as InsertAuthorizationLog);
    } catch (error) {
      console.error("[GovernanceEnforcement] Failed to log operation start:", error);
    }
  }

  private async getGovernance(organizationId: string): Promise<OrganizationGovernance | undefined> {
    const cached = this.governanceCache.get(organizationId);
    if (cached && Date.now() - cached.cachedAt < this.CACHE_TTL_MS) {
      return cached.governance;
    }
    
    try {
      const governance = await storage.getOrganizationGovernance(organizationId);
      if (governance) {
        this.governanceCache.set(organizationId, { governance, cachedAt: Date.now() });
      }
      return governance;
    } catch (error) {
      console.error("[GovernanceEnforcement] Failed to get governance:", error);
      return undefined;
    }
  }

  private async getScopeRules(organizationId: string): Promise<ScopeRule[]> {
    const cached = this.scopeRulesCache.get(organizationId);
    if (cached && Date.now() - cached.cachedAt < this.CACHE_TTL_MS) {
      return cached.rules;
    }
    
    try {
      const rules = await storage.getScopeRules(organizationId);
      this.scopeRulesCache.set(organizationId, { rules, cachedAt: Date.now() });
      return rules;
    } catch (error) {
      console.error("[GovernanceEnforcement] Failed to get scope rules:", error);
      return [];
    }
  }

  clearCache(organizationId?: string): void {
    if (organizationId) {
      this.governanceCache.delete(organizationId);
      this.scopeRulesCache.delete(organizationId);
    } else {
      this.governanceCache.clear();
      this.scopeRulesCache.clear();
    }
  }

  private matchTarget(target: string, pattern: string, patternType: string): boolean {
    const normalizedTarget = target.toLowerCase();
    const normalizedPattern = pattern.toLowerCase();
    
    switch (patternType) {
      case "ip":
        return normalizedTarget === normalizedPattern || 
               this.extractHostFromUrl(normalizedTarget) === normalizedPattern;
      
      case "hostname":
        const targetHost = this.extractHostFromUrl(normalizedTarget);
        return targetHost === normalizedPattern || 
               targetHost.endsWith(`.${normalizedPattern}`);
      
      case "cidr":
        return this.matchCidr(this.extractHostFromUrl(normalizedTarget), pattern);
      
      case "pattern":
        try {
          const regex = new RegExp(
            "^" + normalizedPattern
              .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
              .replace(/\*/g, ".*")
            + "$",
            "i"
          );
          return regex.test(normalizedTarget) || regex.test(this.extractHostFromUrl(normalizedTarget));
        } catch {
          return normalizedTarget.includes(normalizedPattern);
        }
      
      default:
        return normalizedTarget.includes(normalizedPattern);
    }
  }

  private extractHostFromUrl(input: string): string {
    try {
      if (input.startsWith("http://") || input.startsWith("https://")) {
        const url = new URL(input);
        return url.hostname;
      }
    } catch {}
    
    const hostMatch = input.match(/^([^:/]+)/);
    return hostMatch ? hostMatch[1] : input;
  }

  private matchCidr(ip: string, cidr: string): boolean {
    const ipParts = ip.split(".").map(Number);
    if (ipParts.length !== 4 || ipParts.some(p => isNaN(p) || p < 0 || p > 255)) {
      return false;
    }
    
    const [cidrIp, cidrMaskStr] = cidr.split("/");
    const cidrParts = cidrIp.split(".").map(Number);
    const cidrMask = parseInt(cidrMaskStr, 10);
    
    if (cidrParts.length !== 4 || isNaN(cidrMask) || cidrMask < 0 || cidrMask > 32) {
      return false;
    }
    
    const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
    const cidrNum = (cidrParts[0] << 24) | (cidrParts[1] << 16) | (cidrParts[2] << 8) | cidrParts[3];
    const mask = ~((1 << (32 - cidrMask)) - 1);
    
    return (ipNum & mask) === (cidrNum & mask);
  }

  private normalizeTarget(target: string): string {
    return target.trim().toLowerCase();
  }

  private inferTargetType(target: string): "ip" | "hostname" | "cidr" | "url" {
    if (target.startsWith("http://") || target.startsWith("https://")) {
      return "url";
    }
    
    if (target.includes("/") && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(target)) {
      return "cidr";
    }
    
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target)) {
      return "ip";
    }
    
    return "hostname";
  }

  async getGovernanceStatus(organizationId: string): Promise<{
    killSwitchActive: boolean;
    executionMode: string;
    activeRulesCount: number;
    blockedTargetsCount: number;
  }> {
    const governance = await this.getGovernance(organizationId);
    const rules = await this.getScopeRules(organizationId);
    
    const activeRules = rules.filter(r => r.enabled);
    const blockedRules = activeRules.filter(r => r.ruleType === "block");
    
    return {
      killSwitchActive: governance?.killSwitchActive || false,
      executionMode: governance?.executionMode || "safe",
      activeRulesCount: activeRules.length,
      blockedTargetsCount: blockedRules.length,
    };
  }
}

export const governanceEnforcement = GovernanceEnforcementService.getInstance();
