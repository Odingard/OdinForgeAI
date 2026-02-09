import { db } from "../db";
import { auditLogs, type AuditLogType, type InsertAuditLog } from "@shared/schema";
import { createHash } from "crypto";
import { eq, and, asc } from "drizzle-orm";

export interface AuditLogContext {
  executionId: string;
  evaluationId: string;
  organizationId: string;
}

export class AuditLogger {
  private sequenceCounter = 0;
  private context: AuditLogContext;

  constructor(context: AuditLogContext) {
    this.context = context;
  }

  private generateId(): string {
    return `audit-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private computeChecksum(data: Record<string, unknown>): string {
    const content = JSON.stringify(data);
    return createHash("sha256").update(content).digest("hex").substring(0, 16);
  }

  private async createLog(log: Omit<InsertAuditLog, "executionId" | "evaluationId" | "organizationId" | "sequenceNumber" | "checksum">): Promise<string> {
    const id = this.generateId();
    this.sequenceCounter++;

    const logData = {
      ...log,
      executionId: this.context.executionId,
      evaluationId: this.context.evaluationId,
      organizationId: this.context.organizationId,
      sequenceNumber: this.sequenceCounter,
    };

    const checksum = this.computeChecksum(logData as unknown as Record<string, unknown>);

    await db.insert(auditLogs).values({
      id,
      ...logData,
      checksum,
    } as any);

    return id;
  }

  async logAgentDecision(
    agentName: string,
    decision: string,
    reason: string,
    metadata?: Record<string, unknown>
  ): Promise<string> {
    return this.createLog({
      agentName,
      logType: "agent_decision" as AuditLogType,
      decision,
      decisionReason: reason,
      content: `${agentName} decided: ${decision}`,
      metadata,
    });
  }

  async logLLMPrompt(
    agentName: string,
    prompt: string,
    modelUsed: string,
    metadata?: Record<string, unknown>
  ): Promise<string> {
    return this.createLog({
      agentName,
      logType: "llm_prompt" as AuditLogType,
      prompt,
      modelUsed,
      content: `LLM prompt sent to ${modelUsed}`,
      metadata,
    });
  }

  async logLLMResponse(
    agentName: string,
    response: string,
    modelUsed: string,
    tokenCount?: number,
    durationMs?: number,
    parentLogId?: string,
    metadata?: Record<string, unknown>
  ): Promise<string> {
    return this.createLog({
      agentName,
      logType: "llm_response" as AuditLogType,
      response,
      modelUsed,
      tokenCount,
      durationMs,
      parentLogId,
      content: `LLM response from ${modelUsed}`,
      metadata,
    });
  }

  async logCommandOutput(
    agentName: string,
    commandInput: string,
    commandOutput: string,
    durationMs?: number,
    metadata?: Record<string, unknown>
  ): Promise<string> {
    return this.createLog({
      agentName,
      logType: "command_output" as AuditLogType,
      commandInput,
      commandOutput,
      durationMs,
      content: `Command executed: ${commandInput.substring(0, 100)}`,
      metadata,
    });
  }

  async logPolicyCheck(
    agentName: string,
    policyName: string,
    decision: "ALLOW" | "DENY" | "MODIFY",
    reason: string,
    metadata?: Record<string, unknown>
  ): Promise<string> {
    return this.createLog({
      agentName,
      logType: "policy_check" as AuditLogType,
      decision,
      decisionReason: reason,
      content: `Policy "${policyName}" check: ${decision}`,
      metadata: { ...metadata, policyName },
    });
  }

  async logScreenshot(
    agentName: string,
    objectStorageKey: string,
    fileSize: number,
    description: string,
    metadata?: Record<string, unknown>
  ): Promise<string> {
    return this.createLog({
      agentName,
      logType: "screenshot" as AuditLogType,
      objectStorageKey,
      objectStorageType: "image/png",
      objectStorageSize: fileSize,
      content: description,
      metadata,
    });
  }

  async logNetworkCapture(
    agentName: string,
    objectStorageKey: string,
    fileSize: number,
    description: string,
    metadata?: Record<string, unknown>
  ): Promise<string> {
    return this.createLog({
      agentName,
      logType: "network_capture" as AuditLogType,
      objectStorageKey,
      objectStorageType: "application/vnd.tcpdump.pcap",
      objectStorageSize: fileSize,
      content: description,
      metadata,
    });
  }

  async logEvidenceArtifact(
    agentName: string,
    artifactType: string,
    content: string,
    metadata?: Record<string, unknown>
  ): Promise<string> {
    return this.createLog({
      agentName,
      logType: "evidence_artifact" as AuditLogType,
      content,
      metadata: { ...metadata, artifactType },
    });
  }

  static async getLogsForExecution(executionId: string): Promise<typeof auditLogs.$inferSelect[]> {
    return db.select()
      .from(auditLogs)
      .where(eq(auditLogs.executionId, executionId))
      .orderBy(asc(auditLogs.sequenceNumber));
  }

  static async getLogsForEvaluation(evaluationId: string): Promise<typeof auditLogs.$inferSelect[]> {
    return db.select()
      .from(auditLogs)
      .where(eq(auditLogs.evaluationId, evaluationId))
      .orderBy(asc(auditLogs.sequenceNumber));
  }
}

export function createAuditLogger(context: AuditLogContext): AuditLogger {
  return new AuditLogger(context);
}
