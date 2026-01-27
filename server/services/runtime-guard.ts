import { db } from "../db";
import { hitlApprovalRequests, type HitlApprovalRequest, type HitlRiskLevel } from "@shared/schema";
import { eq, and, lt } from "drizzle-orm";
import { searchPolicies, type PolicySearchResult } from "./rag/policy-search";
import { wsService } from "./websocket";
import { createHmac, randomBytes } from "crypto";

const APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;

function getHitlSecret(): string {
  const secret = process.env.HITL_SIGNING_SECRET;
  if (!secret) {
    const isProduction = process.env.REPLIT_DEPLOYMENT === "1";
    if (isProduction) {
      console.error("[RuntimeGuard] CRITICAL: HITL_SIGNING_SECRET must be configured in production!");
      throw new Error("HITL_SIGNING_SECRET environment variable is required in production");
    }
    console.warn("[RuntimeGuard] WARNING: Using default HITL secret - configure HITL_SIGNING_SECRET for production");
    return "odinforge-hitl-dev-secret-" + (process.env.REPL_ID || "local");
  }
  return secret;
}

const HITL_SECRET = getHitlSecret();

const FORBIDDEN_COMMAND_PATTERNS = [
  /\brm\s+-rf\b/i,
  /\brm\s+--no-preserve-root\b/i,
  /\bdrop\s+table\b/i,
  /\bdrop\s+database\b/i,
  /\btruncate\s+table\b/i,
  /\bdelete\s+from\s+\w+\s*;?\s*$/i,
  /\bformat\s+[a-z]:/i,
  /\bmkfs\b/i,
  /\bdd\s+if=.*of=\/dev\//i,
  />\s*\/dev\/sd[a-z]/i,
  /\bshutdown\b/i,
  /\breboot\b/i,
  /\bhalt\b/i,
  /\binit\s+0\b/i,
  /\bkill\s+-9\s+-1\b/i,
  /\bchmod\s+777\s+\/\b/i,
  /\bchown\s+-R\s+.*\s+\/\b/i,
];

export interface RuntimeGuardContext {
  evaluationId: string;
  executionId: string;
  organizationId: string;
  agentName: string;
  tenantId?: string;
}

export interface RuntimeGuardResult {
  allowed: boolean;
  requiresApproval: boolean;
  approvalId?: string;
  riskLevel?: HitlRiskLevel;
  riskReason?: string;
  matchedPolicies?: PolicySearchResult[];
  blockedReason?: string;
}

interface PendingApproval {
  resolve: (approved: boolean) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
}

class RuntimeGuard {
  private pendingApprovals: Map<string, PendingApproval> = new Map();

  async validateCommand(
    command: string,
    target: string | undefined,
    context: RuntimeGuardContext
  ): Promise<RuntimeGuardResult> {
    console.log(`[RuntimeGuard] Validating command from ${context.agentName}: "${command.substring(0, 80)}..."`);

    const patternMatch = this.checkForbiddenPatterns(command);
    if (patternMatch) {
      console.log(`[RuntimeGuard] Forbidden pattern detected: ${patternMatch}`);
      return this.createApprovalRequest(command, target, context, "critical", 
        `Forbidden command pattern detected: ${patternMatch}`, []);
    }

    const blacklistResults = await this.checkBlacklistedTargets(target, context.organizationId);
    if (blacklistResults.length > 0) {
      const highSimilarity = blacklistResults.filter(p => p.similarity > 0.75);
      if (highSimilarity.length > 0) {
        console.log(`[RuntimeGuard] Blacklisted target detected: ${target}`);
        return this.createApprovalRequest(command, target, context, "critical",
          `Target matches blacklisted asset: ${highSimilarity[0].content.substring(0, 100)}`,
          highSimilarity);
      }
    }

    const forbiddenCmdResults = await this.checkForbiddenCommands(command, context.organizationId);
    if (forbiddenCmdResults.length > 0) {
      const highSimilarity = forbiddenCmdResults.filter(p => p.similarity > 0.7);
      if (highSimilarity.length > 0) {
        const riskLevel = highSimilarity[0].similarity > 0.85 ? "critical" : "high";
        console.log(`[RuntimeGuard] Policy-forbidden command detected (${riskLevel})`);
        return this.createApprovalRequest(command, target, context, riskLevel,
          `Command matches forbidden policy: ${highSimilarity[0].content.substring(0, 100)}`,
          highSimilarity);
      }
    }

    console.log(`[RuntimeGuard] Command approved automatically`);
    return { allowed: true, requiresApproval: false };
  }

  private checkForbiddenPatterns(command: string): string | null {
    for (const pattern of FORBIDDEN_COMMAND_PATTERNS) {
      if (pattern.test(command)) {
        return pattern.toString();
      }
    }
    return null;
  }

  private async checkBlacklistedTargets(
    target: string | undefined,
    organizationId: string
  ): Promise<PolicySearchResult[]> {
    if (!target) return [];

    try {
      const results = await searchPolicies(
        `blacklisted target ${target} forbidden asset do not scan`,
        { organizationId, limit: 5, minSimilarity: 0.6 }
      );
      return results.filter(p => 
        p.metadata.policyType === "blacklist" || 
        p.content.toLowerCase().includes("blacklist") ||
        p.content.toLowerCase().includes("forbidden") ||
        p.content.toLowerCase().includes("do not scan")
      );
    } catch (error) {
      console.warn(`[RuntimeGuard] Failed to search blacklisted targets:`, error);
      return [];
    }
  }

  private async checkForbiddenCommands(
    command: string,
    organizationId: string
  ): Promise<PolicySearchResult[]> {
    try {
      const results = await searchPolicies(
        `forbidden command ${command} dangerous destructive prohibited`,
        { organizationId, limit: 5, minSimilarity: 0.6 }
      );
      return results.filter(p =>
        p.metadata.policyType === "forbidden_commands" ||
        p.content.toLowerCase().includes("forbidden") ||
        p.content.toLowerCase().includes("prohibited") ||
        p.content.toLowerCase().includes("dangerous")
      );
    } catch (error) {
      console.warn(`[RuntimeGuard] Failed to search forbidden commands:`, error);
      return [];
    }
  }

  private async createApprovalRequest(
    command: string,
    target: string | undefined,
    context: RuntimeGuardContext,
    riskLevel: HitlRiskLevel,
    riskReason: string,
    matchedPolicies: PolicySearchResult[]
  ): Promise<RuntimeGuardResult> {
    const approvalId = `hitl-${Date.now()}-${randomBytes(8).toString("hex")}`;
    const expiresAt = new Date(Date.now() + APPROVAL_TIMEOUT_MS);

    await db.insert(hitlApprovalRequests).values({
      id: approvalId,
      evaluationId: context.evaluationId,
      executionId: context.executionId,
      organizationId: context.organizationId,
      agentName: context.agentName,
      command,
      target,
      riskLevel,
      riskReason,
      matchedPolicies: matchedPolicies.map(p => ({
        policyId: p.id,
        policyType: p.metadata.policyType || "general",
        matchedContent: p.content.substring(0, 200),
        similarity: p.similarity,
      })),
      status: "pending",
      expiresAt,
    });

    this.sendApprovalNotification(approvalId, context, command, target, riskLevel, riskReason);

    return {
      allowed: false,
      requiresApproval: true,
      approvalId,
      riskLevel,
      riskReason,
      matchedPolicies,
    };
  }

  private sendApprovalNotification(
    approvalId: string,
    context: RuntimeGuardContext,
    command: string,
    target: string | undefined,
    riskLevel: HitlRiskLevel,
    riskReason: string
  ): void {
    const channel = `evaluation:${context.evaluationId}`;
    
    wsService.broadcastToChannel(channel, {
      type: "hitl_approval_required",
      approvalId,
      evaluationId: context.evaluationId,
      executionId: context.executionId,
      agentName: context.agentName,
      command: command.substring(0, 500),
      target,
      riskLevel,
      riskReason,
      expiresAt: new Date(Date.now() + APPROVAL_TIMEOUT_MS).toISOString(),
    });

    console.log(`[RuntimeGuard] Sent HITL approval notification: ${approvalId}`);
  }

  async waitForApproval(approvalId: string, timeoutMs: number = APPROVAL_TIMEOUT_MS): Promise<boolean> {
    console.log(`[RuntimeGuard] Waiting for approval: ${approvalId}`);

    return new Promise<boolean>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingApprovals.delete(approvalId);
        this.expireApprovalRequest(approvalId);
        reject(new Error(`Approval request ${approvalId} timed out`));
      }, timeoutMs);

      this.pendingApprovals.set(approvalId, { resolve, reject, timeout });
    });
  }

  async processApprovalResponse(
    approvalId: string,
    approved: boolean,
    respondedBy: string,
    signature: string,
    nonce: string,
    rejectionReason?: string
  ): Promise<{ success: boolean; error?: string }> {
    const [request] = await db.select()
      .from(hitlApprovalRequests)
      .where(eq(hitlApprovalRequests.id, approvalId));

    if (!request) {
      return { success: false, error: "Approval request not found" };
    }

    if (request.status !== "pending") {
      return { success: false, error: `Request already ${request.status}` };
    }

    if (new Date() > request.expiresAt) {
      await this.expireApprovalRequest(approvalId);
      return { success: false, error: "Approval request has expired" };
    }

    const expectedSignature = this.generateSignature(approvalId, approved, nonce);
    if (signature !== expectedSignature) {
      console.warn(`[RuntimeGuard] Invalid signature for approval ${approvalId}`);
      return { success: false, error: "Invalid approval signature" };
    }

    await db.update(hitlApprovalRequests)
      .set({
        status: approved ? "approved" : "rejected",
        respondedAt: new Date(),
        respondedBy,
        responseSignature: signature,
        responseNonce: nonce,
        rejectionReason: rejectionReason || null,
      })
      .where(eq(hitlApprovalRequests.id, approvalId));

    const pending = this.pendingApprovals.get(approvalId);
    if (pending) {
      clearTimeout(pending.timeout);
      pending.resolve(approved);
      this.pendingApprovals.delete(approvalId);
    }

    const [updatedRequest] = await db.select()
      .from(hitlApprovalRequests)
      .where(eq(hitlApprovalRequests.id, approvalId));

    if (updatedRequest) {
      wsService.broadcastToChannel(`evaluation:${updatedRequest.evaluationId}`, {
        type: "hitl_approval_response",
        approvalId,
        approved,
        respondedBy,
        rejectionReason,
      });
    }

    console.log(`[RuntimeGuard] Approval ${approvalId} ${approved ? "approved" : "rejected"} by ${respondedBy}`);
    return { success: true };
  }

  private async expireApprovalRequest(approvalId: string): Promise<void> {
    await db.update(hitlApprovalRequests)
      .set({ status: "expired" })
      .where(and(
        eq(hitlApprovalRequests.id, approvalId),
        eq(hitlApprovalRequests.status, "pending")
      ));
  }

  generateSignature(approvalId: string, approved: boolean, nonce: string): string {
    const payload = `${approvalId}:${approved}:${nonce}`;
    return createHmac("sha256", HITL_SECRET).update(payload).digest("hex");
  }

  generateNonce(): string {
    return randomBytes(16).toString("hex");
  }

  async getPendingApprovals(organizationId: string): Promise<HitlApprovalRequest[]> {
    return db.select()
      .from(hitlApprovalRequests)
      .where(and(
        eq(hitlApprovalRequests.organizationId, organizationId),
        eq(hitlApprovalRequests.status, "pending")
      ));
  }

  async getApprovalHistory(evaluationId: string): Promise<HitlApprovalRequest[]> {
    return db.select()
      .from(hitlApprovalRequests)
      .where(eq(hitlApprovalRequests.evaluationId, evaluationId));
  }

  async cancelPendingApprovals(evaluationId: string): Promise<number> {
    const result = await db.update(hitlApprovalRequests)
      .set({ status: "cancelled" })
      .where(and(
        eq(hitlApprovalRequests.evaluationId, evaluationId),
        eq(hitlApprovalRequests.status, "pending")
      ));

    this.pendingApprovals.forEach((pending, id) => {
      if (id.includes(evaluationId)) {
        clearTimeout(pending.timeout);
        pending.reject(new Error("Evaluation cancelled"));
        this.pendingApprovals.delete(id);
      }
    });

    return 0;
  }
}

export const runtimeGuard = new RuntimeGuard();
