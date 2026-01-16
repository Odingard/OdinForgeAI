import { Job } from "bullmq";
import { randomUUID } from "crypto";
import { storage } from "../../../storage";
import { runAgentOrchestrator } from "../../agents/orchestrator";
import { governanceEnforcement } from "../../governance/governance-enforcement";
import {
  EvaluationJobData,
  JobResult,
  JobProgress,
} from "../job-types";

interface EvaluationJob {
  id?: string;
  data: EvaluationJobData;
  updateProgress?: (progress: number | object) => Promise<void>;
}

function emitEvaluationProgress(
  tenantId: string,
  organizationId: string,
  evaluationId: string,
  event: Record<string, any>
): void {
  const type = event.type;
  
  if (type === "evaluation_started") {
    console.log(`[Evaluation] ${evaluationId}: Started evaluation in ${event.mode} mode`);
  } else if (type === "evaluation_progress") {
    console.log(`[Evaluation] ${evaluationId}: ${event.agent} - ${event.message}`);
  } else if (type === "evaluation_completed") {
    console.log(`[Evaluation] ${evaluationId}: Completed with score ${event.score}`);
  } else if (type === "evaluation_failed") {
    console.log(`[Evaluation] ${evaluationId}: Failed - ${event.error}`);
  }

  try {
    const { wsService } = require("../../websocket");
    if (!wsService) return;
    
    const channel = `evaluation:${tenantId}:${organizationId}:${evaluationId}`;
    wsService.broadcastToChannel(channel, {
      type: "evaluation_progress",
      evaluationId,
      phase: event.phase || event.agent || "processing",
      progress: event.progress || 0,
      message: event.message,
    });
  } catch {
  }
}

export async function handleEvaluationJob(
  job: Job<EvaluationJobData> | EvaluationJob
): Promise<JobResult> {
  const startTime = Date.now();
  const { evaluationId, executionMode, assetId, exposureData, tenantId, organizationId } = job.data;
  const jobId = job.id || evaluationId;

  console.log(`[Evaluation] Starting evaluation ${evaluationId} in ${executionMode} mode`);

  const governanceCheck = await governanceEnforcement.canStartOperation(
    organizationId,
    "evaluation",
    assetId
  );
  
  if (!governanceCheck.canStart) {
    console.log(`[Evaluation] Blocked by governance: ${governanceCheck.reason}`);
    await storage.updateEvaluationStatus(evaluationId, "failed", executionMode);
    
    emitEvaluationProgress(tenantId, organizationId, evaluationId, {
      type: "evaluation_failed",
      error: `Operation blocked by governance controls: ${governanceCheck.reason}`,
    });
    
    return {
      success: false,
      error: governanceCheck.reason,
      metadata: {
        blockedByGovernance: true,
        reason: governanceCheck.reason,
      },
    };
  }

  await governanceEnforcement.logOperationStarted(organizationId, "evaluation", assetId || evaluationId);

  emitEvaluationProgress(tenantId, organizationId, evaluationId, {
    type: "evaluation_started",
    mode: executionMode,
  });

  try {
    const evaluation = await storage.getEvaluation(evaluationId);
    
    if (!evaluation) {
      throw new Error(`Evaluation not found: ${evaluationId}`);
    }

    await storage.updateEvaluationStatus(evaluationId, "running", executionMode);

    await job.updateProgress?.({
      percent: 10,
      stage: "initializing",
      message: "Initializing AI agents...",
    } as JobProgress);

    emitEvaluationProgress(tenantId, organizationId, evaluationId, {
      type: "evaluation_progress",
      agent: "orchestrator",
      progress: 10,
      message: "Initializing AI agents",
    });

    const targetAssetId = assetId || evaluation.assetId;
    const exposureType = exposureData?.exposureType || evaluation.exposureType || "unknown";
    const priority = evaluation.priority || "medium";
    const description = evaluation.description || `Security evaluation for ${targetAssetId}`;

    const onProgress = (agentName: string, stage: string, progress: number, message: string) => {
      const scaledProgress = Math.min(10 + Math.floor(progress * 0.85), 95);
      
      job.updateProgress?.({
        percent: scaledProgress,
        stage: agentName,
        message: `${agentName}: ${message}`,
      } as JobProgress);

      emitEvaluationProgress(tenantId, organizationId, evaluationId, {
        type: "evaluation_progress",
        agent: agentName,
        phase: stage,
        progress: scaledProgress,
        message,
      });
    };

    const result = await runAgentOrchestrator(
      targetAssetId,
      exposureType,
      priority,
      description,
      evaluationId,
      onProgress
    );

    await storage.updateEvaluationStatus(evaluationId, "completed");

    await storage.createResult({
      id: randomUUID(),
      evaluationId,
      exploitable: result.exploitable,
      confidence: result.confidence,
      score: result.score,
      attackPath: result.attackPath,
      attackGraph: result.attackGraph,
      businessLogicFindings: result.businessLogicFindings,
      multiVectorFindings: result.multiVectorFindings,
      workflowAnalysis: result.workflowAnalysis,
      impact: result.impact,
      recommendations: result.recommendations,
      evidenceArtifacts: result.evidenceArtifacts,
      intelligentScore: result.intelligentScore,
      remediationGuidance: result.remediationGuidance,
      llmValidation: result.llmValidation,
      llmValidationVerdict: result.llmValidationVerdict,
      duration: Date.now() - startTime,
    });

    await job.updateProgress?.({
      percent: 100,
      stage: "complete",
      message: "Evaluation complete",
    } as JobProgress);

    emitEvaluationProgress(tenantId, organizationId, evaluationId, {
      type: "evaluation_completed",
      exploitable: result.exploitable,
      score: result.score,
      attackPathLength: result.attackPath?.length || 0,
      recommendationCount: result.recommendations?.length || 0,
    });

    return {
      success: true,
      data: {
        evaluationId,
        exploitable: result.exploitable,
        score: result.score,
        attackPathSteps: result.attackPath?.length || 0,
        recommendations: result.recommendations?.length || 0,
      },
      duration: Date.now() - startTime,
    };

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error(`[Evaluation] Evaluation failed:`, errorMessage);

    await storage.updateEvaluationStatus(evaluationId, "failed").catch(() => {});

    emitEvaluationProgress(tenantId, organizationId, evaluationId, {
      type: "evaluation_failed",
      error: errorMessage,
    });

    return {
      success: false,
      error: errorMessage,
      duration: Date.now() - startTime,
    };
  }
}
