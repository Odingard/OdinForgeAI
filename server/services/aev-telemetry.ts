/**
 * AEV Telemetry Recorder
 *
 * Captures structured telemetry for every exploit agent run and chain execution.
 * All DB writes are wrapped in try/catch with silent=true (default) so telemetry
 * never crashes the main AEV pipeline.
 */

import { randomUUID } from "crypto";
import { db } from "../db";
import { aevRuns, aevToolCalls, aevLlmTurns, aevFailures } from "@shared/schema";
import { eq } from "drizzle-orm";
import type { AevRunStopReason, AevFailureCode } from "@shared/schema";

export interface TelemetryRunInit {
  evaluationId?: string;
  organizationId: string;
  runType: "exploit_agent" | "chain_playbook" | "xbow_challenge";
  playbookId?: string;
  challengeId?: string;
  executionMode: string;
}

export class AevTelemetryRecorder {
  private runId: string;
  private startedAt: number;
  private silent: boolean;

  constructor(private init: TelemetryRunInit, silent = true) {
    this.runId = `run-${randomUUID()}`;
    this.startedAt = Date.now();
    this.silent = silent;
  }

  get id(): string {
    return this.runId;
  }

  async start(): Promise<void> {
    try {
      await db.insert(aevRuns).values({
        id: this.runId,
        evaluationId: this.init.evaluationId,
        organizationId: this.init.organizationId,
        runType: this.init.runType,
        playbookId: this.init.playbookId,
        challengeId: this.init.challengeId,
        executionMode: this.init.executionMode,
        startedAt: new Date(),
      });
    } catch (e) {
      if (!this.silent) throw e;
      console.warn("[AevTelemetry] Failed to record run start:", (e as Error).message);
    }
  }

  async recordToolCall(data: {
    turn: number;
    toolName: string;
    arguments: Record<string, unknown>;
    resultSummary: string;
    vulnerable: boolean;
    confidence: number;
    executionTimeMs: number;
    failureCode?: AevFailureCode;
  }): Promise<void> {
    try {
      await db.insert(aevToolCalls).values({
        id: `tc-${randomUUID()}`,
        runId: this.runId,
        evaluationId: this.init.evaluationId,
        turn: data.turn,
        toolName: data.toolName,
        arguments: data.arguments,
        resultSummary: data.resultSummary,
        vulnerable: data.vulnerable,
        confidence: data.confidence,
        executionTimeMs: data.executionTimeMs,
        failureCode: data.failureCode ?? "none",
        calledAt: new Date(),
      });
    } catch (e) {
      if (!this.silent) throw e;
    }
  }

  async recordLlmTurn(data: {
    turn: number;
    model: string;
    hadToolCalls: boolean;
    toolCallCount: number;
    durationMs: number;
    failureCode?: AevFailureCode;
  }): Promise<void> {
    try {
      await db.insert(aevLlmTurns).values({
        id: `lt-${randomUUID()}`,
        runId: this.runId,
        turn: data.turn,
        model: data.model,
        hadToolCalls: data.hadToolCalls,
        toolCallCount: data.toolCallCount,
        durationMs: data.durationMs,
        failureCode: data.failureCode ?? "none",
        calledAt: new Date(),
      });
    } catch (e) {
      if (!this.silent) throw e;
    }
  }

  async recordFailure(failureCode: AevFailureCode, context: string, message: string): Promise<void> {
    try {
      await db.insert(aevFailures).values({
        id: `fail-${randomUUID()}`,
        runId: this.runId,
        evaluationId: this.init.evaluationId,
        failureCode,
        context,
        message,
        occurredAt: new Date(),
      });
    } catch (e) {
      if (!this.silent) throw e;
    }
  }

  async finish(data: {
    stopReason: AevRunStopReason;
    exploitable?: boolean;
    overallConfidence?: number;
    findingCount?: number;
    failureCode?: AevFailureCode;
    errorMessage?: string;
    totalTurns: number;
    totalToolCalls: number;
    exploitState?: Record<string, unknown>;
  }): Promise<void> {
    const durationMs = Date.now() - this.startedAt;
    try {
      await db.update(aevRuns)
        .set({
          completedAt: new Date(),
          durationMs,
          stopReason: data.stopReason,
          exploitable: data.exploitable,
          overallConfidence: data.overallConfidence,
          findingCount: data.findingCount ?? 0,
          failureCode: data.failureCode ?? "none",
          errorMessage: data.errorMessage,
          totalTurns: data.totalTurns,
          totalToolCalls: data.totalToolCalls,
          exploitState: data.exploitState,
        })
        .where(eq(aevRuns.id, this.runId));
    } catch (e) {
      if (!this.silent) throw e;
      console.warn("[AevTelemetry] Failed to record run finish:", (e as Error).message);
    }
  }
}
