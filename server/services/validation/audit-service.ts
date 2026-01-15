import { createHash } from "crypto";
import { storage } from "../../storage";
import type { 
  ValidationAuditLogAction, 
  InsertValidationAuditLog,
  ValidationAuditLog,
  InsertApprovalRequest,
  ApprovalRequest,
  ApprovalLevel,
  ApprovalStatus 
} from "@shared/schema";
import type { ExecutionMode } from "./execution-modes";

interface AuditContext {
  organizationId: string;
  tenantId: string;
  evaluationId?: string;
  agentId?: string;
  requestedBy?: string;
  ipAddress?: string;
  userAgent?: string;
}

interface ProbeAuditDetails {
  targetHost: string;
  targetPort?: number;
  probeType?: string;
  vulnerabilityType?: string;
  payloadUsed?: string;
  resultStatus: "success" | "failure" | "blocked" | "timeout";
  confidenceScore?: number;
  verdict?: "confirmed" | "likely" | "theoretical" | "false_positive";
  evidence?: string;
  executionDurationMs?: number;
  metadata?: Record<string, any>;
}

class ValidationAuditService {
  async logValidationAction(
    action: ValidationAuditLogAction,
    executionMode: ExecutionMode,
    context: AuditContext,
    details?: ProbeAuditDetails,
    approvalId?: string
  ): Promise<string> {
    const id = `vlog-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    
    const payloadHash = details?.payloadUsed 
      ? this.hashContent(details.payloadUsed) 
      : undefined;
    
    const evidenceHash = details?.evidence 
      ? this.hashContent(details.evidence) 
      : undefined;
    
    const riskLevel = this.calculateRiskLevel(action, executionMode, details);
    
    const previousRecordHash = await this.getLastRecordHash(context.organizationId);
    
    const record: InsertValidationAuditLog = {
      organizationId: context.organizationId,
      tenantId: context.tenantId,
      evaluationId: context.evaluationId,
      agentId: context.agentId,
      action,
      executionMode,
      targetHost: details?.targetHost,
      targetPort: details?.targetPort,
      probeType: details?.probeType,
      vulnerabilityType: details?.vulnerabilityType,
      payloadUsed: details?.payloadUsed,
      payloadHash,
      resultStatus: details?.resultStatus,
      confidenceScore: details?.confidenceScore,
      verdict: details?.verdict,
      evidence: details?.evidence,
      evidenceHash,
      requestedBy: context.requestedBy,
      approvalId,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      riskLevel,
      executionDurationMs: details?.executionDurationMs,
      metadata: details?.metadata,
      previousRecordHash: previousRecordHash || undefined,
    };
    
    const checksum = this.calculateChecksum(id, record);
    
    try {
      await storage.createValidationAuditLog({ ...record, checksum }, id);
      
      console.log(`[AuditService] Logged ${action} for ${details?.targetHost || context.tenantId}`);
      return id;
    } catch (error) {
      console.error("[AuditService] Failed to create audit log:", error);
      throw error;
    }
  }
  
  private async getLastRecordHash(organizationId: string): Promise<string | null> {
    try {
      const logs = await storage.getValidationAuditLogs(organizationId, { limit: 1 });
      if (logs.length > 0 && logs[0].checksum) {
        return logs[0].checksum;
      }
      return null;
    } catch (error) {
      console.error("[AuditService] Failed to get last record hash:", error);
      return null;
    }
  }
  
  async logProbeExecution(
    executionMode: ExecutionMode,
    context: AuditContext,
    details: ProbeAuditDetails
  ): Promise<string> {
    return this.logValidationAction("probe_executed", executionMode, context, details);
  }
  
  async logVulnerabilityConfirmed(
    executionMode: ExecutionMode,
    context: AuditContext,
    details: ProbeAuditDetails
  ): Promise<string> {
    return this.logValidationAction("vulnerability_confirmed", executionMode, context, details);
  }
  
  async logExecutionBlocked(
    executionMode: ExecutionMode,
    context: AuditContext,
    reason: string,
    targetHost: string
  ): Promise<string> {
    return this.logValidationAction("execution_blocked", executionMode, context, {
      targetHost,
      resultStatus: "blocked",
      evidence: reason,
    });
  }
  
  async logModeEscalation(
    fromMode: ExecutionMode,
    toMode: ExecutionMode,
    context: AuditContext,
    approvalId?: string
  ): Promise<string> {
    return this.logValidationAction("mode_escalated", toMode, context, {
      targetHost: context.tenantId,
      resultStatus: "success",
      metadata: { fromMode, toMode },
    }, approvalId);
  }
  
  async getAuditLogs(
    organizationId: string,
    options?: {
      limit?: number;
      offset?: number;
      action?: ValidationAuditLogAction;
      executionMode?: ExecutionMode;
      startDate?: Date;
      endDate?: Date;
    }
  ): Promise<ValidationAuditLog[]> {
    return storage.getValidationAuditLogs(organizationId, options);
  }
  
  async verifyAuditIntegrity(organizationId: string): Promise<{
    valid: boolean;
    totalRecords: number;
    invalidRecords: string[];
    chainBroken: boolean;
  }> {
    const logs = await storage.getValidationAuditLogs(organizationId, { limit: 10000 });
    const invalidRecords: string[] = [];
    let chainBroken = false;
    let previousHash: string | null = null;
    
    for (const log of logs) {
      const expectedChecksum = this.calculateChecksum(log.id, log as any);
      if (log.checksum !== expectedChecksum) {
        invalidRecords.push(log.id);
      }
      
      if (previousHash && log.previousRecordHash !== previousHash) {
        chainBroken = true;
      }
      previousHash = log.checksum || null;
    }
    
    return {
      valid: invalidRecords.length === 0 && !chainBroken,
      totalRecords: logs.length,
      invalidRecords,
      chainBroken,
    };
  }
  
  private calculateChecksum(id: string, record: InsertValidationAuditLog): string {
    const content = JSON.stringify({
      id,
      organizationId: record.organizationId,
      tenantId: record.tenantId,
      action: record.action,
      executionMode: record.executionMode,
      targetHost: record.targetHost,
      payloadHash: record.payloadHash,
      evidenceHash: record.evidenceHash,
      previousRecordHash: record.previousRecordHash,
    });
    return this.hashContent(content);
  }
  
  private hashContent(content: string): string {
    return createHash("sha256").update(content).digest("hex");
  }
  
  private calculateRiskLevel(
    action: ValidationAuditLogAction,
    mode: ExecutionMode,
    details?: ProbeAuditDetails
  ): string {
    if (mode === "live") {
      if (action === "exploit_attempted" || action === "data_retrieved") {
        return "critical";
      }
      return "high";
    }
    
    if (mode === "simulation") {
      if (details?.verdict === "confirmed") {
        return "medium";
      }
      return "low";
    }
    
    return "low";
  }
}

class ApprovalWorkflowService {
  async createApprovalRequest(
    requestType: "mode_change" | "live_execution" | "scope_expansion",
    requiredLevel: ApprovalLevel,
    context: AuditContext & {
      requestedByName?: string;
      targetHost?: string;
      targetScope?: string[];
      executionMode?: ExecutionMode;
      operationType?: string;
      justification: string;
      riskAssessment?: string;
      estimatedImpact?: "minimal" | "moderate" | "significant" | "severe";
      durationMinutes?: number;
    }
  ): Promise<ApprovalRequest> {
    const id = `apr-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);
    
    const request: InsertApprovalRequest = {
      organizationId: context.organizationId,
      tenantId: context.tenantId,
      requestType,
      requestedBy: context.requestedBy || "unknown",
      requestedByName: context.requestedByName,
      requiredLevel,
      status: "pending",
      targetHost: context.targetHost,
      targetScope: context.targetScope,
      executionMode: context.executionMode,
      operationType: context.operationType,
      justification: context.justification,
      riskAssessment: context.riskAssessment,
      estimatedImpact: context.estimatedImpact,
      durationMinutes: context.durationMinutes,
      expiresAt,
    };
    
    const created = await storage.createApprovalRequest(request, id);
    
    await auditService.logValidationAction(
      "approval_requested",
      (context.executionMode as ExecutionMode) || "safe",
      context,
      {
        targetHost: context.targetHost || context.tenantId,
        resultStatus: "success",
        metadata: { requestType, requiredLevel, approvalId: id },
      }
    );
    
    console.log(`[ApprovalWorkflow] Created approval request ${id} requiring ${requiredLevel} approval`);
    return created;
  }
  
  async approveRequest(
    requestId: string,
    approverId: string,
    approverName: string,
    notes?: string
  ): Promise<ApprovalRequest> {
    const request = await storage.getApprovalRequest(requestId);
    if (!request) {
      throw new Error("Approval request not found");
    }
    
    if (request.status !== "pending") {
      throw new Error(`Request already ${request.status}`);
    }
    
    if (request.expiresAt && new Date(request.expiresAt) < new Date()) {
      await storage.updateApprovalRequest(requestId, { status: "expired" });
      throw new Error("Approval request has expired");
    }
    
    const updated = await storage.updateApprovalRequest(requestId, {
      status: "approved",
      approvedBy: approverId,
      approvedByName: approverName,
      approvalNotes: notes,
      approvedAt: new Date(),
    });
    
    await auditService.logValidationAction(
      "approval_granted",
      (request.executionMode as ExecutionMode) || "safe",
      {
        organizationId: request.organizationId,
        tenantId: request.tenantId,
        requestedBy: approverId,
      },
      {
        targetHost: request.targetHost || request.tenantId,
        resultStatus: "success",
        metadata: { 
          approvalId: requestId, 
          requestType: request.requestType,
          approvedBy: approverName,
        },
      },
      requestId
    );
    
    console.log(`[ApprovalWorkflow] Request ${requestId} approved by ${approverName}`);
    return updated;
  }
  
  async denyRequest(
    requestId: string,
    denierId: string,
    denierName: string,
    reason: string
  ): Promise<ApprovalRequest> {
    const request = await storage.getApprovalRequest(requestId);
    if (!request) {
      throw new Error("Approval request not found");
    }
    
    if (request.status !== "pending") {
      throw new Error(`Request already ${request.status}`);
    }
    
    const updated = await storage.updateApprovalRequest(requestId, {
      status: "denied",
      denialReason: reason,
      deniedAt: new Date(),
    });
    
    await auditService.logValidationAction(
      "approval_denied",
      (request.executionMode as ExecutionMode) || "safe",
      {
        organizationId: request.organizationId,
        tenantId: request.tenantId,
        requestedBy: denierId,
      },
      {
        targetHost: request.targetHost || request.tenantId,
        resultStatus: "blocked",
        evidence: reason,
        metadata: { 
          approvalId: requestId, 
          requestType: request.requestType,
          deniedBy: denierName,
        },
      },
      requestId
    );
    
    console.log(`[ApprovalWorkflow] Request ${requestId} denied by ${denierName}: ${reason}`);
    return updated;
  }
  
  async getPendingApprovals(
    organizationId: string,
    requiredLevel?: ApprovalLevel
  ): Promise<ApprovalRequest[]> {
    return storage.getPendingApprovalRequests(organizationId, requiredLevel);
  }
  
  async getApprovalRequest(requestId: string): Promise<ApprovalRequest | undefined> {
    return storage.getApprovalRequest(requestId);
  }
  
  async cancelRequest(requestId: string, cancelledBy: string): Promise<ApprovalRequest> {
    const request = await storage.getApprovalRequest(requestId);
    if (!request) {
      throw new Error("Approval request not found");
    }
    
    if (request.status !== "pending") {
      throw new Error(`Request already ${request.status}`);
    }
    
    return storage.updateApprovalRequest(requestId, {
      status: "cancelled",
      metadata: { ...request.metadata, cancelledBy, cancelledAt: new Date().toISOString() },
    });
  }
  
  async expireOldRequests(): Promise<number> {
    return storage.expireOldApprovalRequests();
  }
}

export const auditService = new ValidationAuditService();
export const approvalWorkflowService = new ApprovalWorkflowService();
