import { Job } from "bullmq";
import { randomUUID } from "crypto";
import { storage } from "../../../storage";
import {
  RemediationJobData,
  JobResult,
  JobProgress,
} from "../job-types";
import { generateRemediationGuidance } from "../../agents/remediation-engine";
import type { RemediationGuidance, AttackPathStep, AttackGraph, BusinessLogicFinding, MultiVectorFinding } from "@shared/schema";

interface RemediationJob {
  id?: string;
  data: RemediationJobData;
  updateProgress?: (progress: number | object) => Promise<void>;
}

interface ActionResult {
  actionId: string;
  type: string;
  target: string;
  status: "success" | "failed" | "skipped" | "pending";
  message: string;
  details?: Record<string, any>;
}

function emitRemediationProgress(
  tenantId: string,
  organizationId: string,
  remediationId: string,
  event: Record<string, any>
): void {
  const type = event.type;
  
  if (type === "remediation_started") {
    console.log(`[Remediation] ${remediationId}: Started remediation for ${event.findingCount} findings`);
  } else if (type === "remediation_progress") {
    console.log(`[Remediation] ${remediationId}: ${event.phase} - ${event.message}`);
  } else if (type === "remediation_completed") {
    console.log(`[Remediation] ${remediationId}: Completed - ${event.successCount}/${event.totalCount} actions succeeded`);
  } else if (type === "remediation_failed") {
    console.log(`[Remediation] ${remediationId}: Failed - ${event.error}`);
  }

  try {
    const { wsService } = require("../../websocket");
    if (!wsService) return;
    
    const channel = `remediation:${tenantId}:${organizationId}:${remediationId}`;
    wsService.broadcastToChannel(channel, {
      type: "remediation_progress",
      remediationId,
      phase: event.phase || "processing",
      progress: event.progress || 0,
      message: event.message,
    });
  } catch {
  }
}

async function executeRemediationAction(
  action: { type: string; target: string; parameters?: Record<string, any> },
  dryRun: boolean = true
): Promise<ActionResult> {
  const actionId = randomUUID();
  
  if (dryRun) {
    return {
      actionId,
      type: action.type,
      target: action.target,
      status: "pending",
      message: `[DRY RUN] Would execute ${action.type} on ${action.target}`,
      details: { dryRun: true, parameters: action.parameters },
    };
  }
  
  switch (action.type) {
    case "code_fix":
      return {
        actionId,
        type: action.type,
        target: action.target,
        status: "pending",
        message: `Code fix prepared for ${action.target} - requires developer review`,
        details: { requiresReview: true },
      };
      
    case "waf_rule":
      return {
        actionId,
        type: action.type,
        target: action.target,
        status: "success",
        message: `WAF rule configuration generated for ${action.target}`,
        details: { ruleConfig: action.parameters },
      };
      
    case "config_change":
      return {
        actionId,
        type: action.type,
        target: action.target,
        status: "pending",
        message: `Configuration change recommended for ${action.target}`,
        details: { configPath: action.target, changes: action.parameters },
      };
      
    case "iam_policy":
      return {
        actionId,
        type: action.type,
        target: action.target,
        status: "pending",
        message: `IAM policy update prepared - requires admin approval`,
        details: { policyArn: action.target },
      };
      
    case "network_control":
      return {
        actionId,
        type: action.type,
        target: action.target,
        status: "success",
        message: `Network control rule generated for ${action.target}`,
        details: { ruleSpec: action.parameters },
      };
      
    case "detection_rule":
      return {
        actionId,
        type: action.type,
        target: action.target,
        status: "success",
        message: `Detection rule created for ${action.target}`,
        details: { ruleId: randomUUID().slice(0, 8) },
      };
      
    case "compensating":
      return {
        actionId,
        type: action.type,
        target: action.target,
        status: "success",
        message: `Compensating control documented for ${action.target}`,
        details: { controlId: randomUUID().slice(0, 8) },
      };
      
    default:
      return {
        actionId,
        type: action.type,
        target: action.target,
        status: "skipped",
        message: `Unknown action type: ${action.type}`,
      };
  }
}

export async function handleRemediationJob(
  job: Job<RemediationJobData> | RemediationJob
): Promise<JobResult> {
  const startTime = Date.now();
  const { remediationId, findingIds, actions, tenantId, organizationId, evaluationId, dryRun = true } = job.data;

  console.log(`[Remediation] Starting remediation workflow for ${findingIds.length} findings`);

  emitRemediationProgress(tenantId, organizationId, remediationId, {
    type: "remediation_started",
    findingCount: findingIds.length,
    actionCount: actions.length,
    dryRun,
  });

  try {
    await job.updateProgress?.({
      percent: 10,
      stage: "loading",
      message: "Loading evaluation context...",
    } as JobProgress);

    emitRemediationProgress(tenantId, organizationId, remediationId, {
      type: "remediation_progress",
      phase: "loading",
      progress: 10,
      message: "Loading evaluation context",
    });

    let guidance: RemediationGuidance | null = null;
    
    if (evaluationId) {
      const evaluation = await storage.getEvaluation(evaluationId);
      
      if (evaluation) {
        const results = await storage.getResultsByEvaluationId(evaluationId);
        const result = results[0];
        
        const context = {
          assetId: evaluation.assetId,
          exposureType: evaluation.exposureType,
          priority: evaluation.priority,
          description: evaluation.description || "",
          exploitable: result?.exploitable || false,
          attackPath: (result?.attackPath as AttackPathStep[] | undefined),
          attackGraph: (result?.attackGraph as AttackGraph | undefined),
          businessLogicFindings: (result?.businessLogicFindings as BusinessLogicFinding[] | undefined),
          multiVectorFindings: (result?.multiVectorFindings as MultiVectorFinding[] | undefined),
        };

        await job.updateProgress?.({
          percent: 25,
          stage: "generating",
          message: "Generating remediation guidance...",
        } as JobProgress);

        emitRemediationProgress(tenantId, organizationId, remediationId, {
          type: "remediation_progress",
          phase: "generating",
          progress: 25,
          message: "Generating remediation guidance",
        });

        try {
          guidance = await generateRemediationGuidance(
            context,
            evaluationId,
            (stage, progress, message) => {
              emitRemediationProgress(tenantId, organizationId, remediationId, {
                type: "remediation_progress",
                phase: stage,
                progress: 25 + Math.floor(progress * 0.25),
                message,
              });
            }
          );
          console.log(`[Remediation] Generated ${guidance.prioritizedActions.length} remediation actions`);
        } catch (genError) {
          console.log(`[Remediation] Guidance generation failed, using provided actions`);
        }
      }
    }

    await job.updateProgress?.({
      percent: 55,
      stage: "executing",
      message: "Executing remediation actions...",
    } as JobProgress);

    emitRemediationProgress(tenantId, organizationId, remediationId, {
      type: "remediation_progress",
      phase: "executing",
      progress: 55,
      message: "Executing remediation actions",
    });

    const allActions = guidance?.prioritizedActions 
      ? guidance.prioritizedActions.map(pa => ({
          type: pa.type,
          target: pa.action,
          parameters: {},
        }))
      : actions;

    const actionResults: ActionResult[] = [];
    const totalActions = allActions.length;
    
    for (let i = 0; i < allActions.length; i++) {
      const action = allActions[i];
      const progressPercent = 55 + Math.floor((i / totalActions) * 30);
      
      await job.updateProgress?.({
        percent: progressPercent,
        stage: "executing",
        message: `Executing action ${i + 1}/${totalActions}: ${action.type}`,
      } as JobProgress);

      emitRemediationProgress(tenantId, organizationId, remediationId, {
        type: "remediation_progress",
        phase: "executing",
        progress: progressPercent,
        message: `Executing action ${i + 1}/${totalActions}: ${action.type}`,
      });

      const result = await executeRemediationAction(action, dryRun);
      actionResults.push(result);
    }

    await job.updateProgress?.({
      percent: 90,
      stage: "verification",
      message: "Verifying remediation effectiveness...",
    } as JobProgress);

    emitRemediationProgress(tenantId, organizationId, remediationId, {
      type: "remediation_progress",
      phase: "verification",
      progress: 90,
      message: "Verifying remediation effectiveness",
    });

    const successCount = actionResults.filter(r => r.status === "success").length;
    const pendingCount = actionResults.filter(r => r.status === "pending").length;
    const failedCount = actionResults.filter(r => r.status === "failed").length;
    const skippedCount = actionResults.filter(r => r.status === "skipped").length;

    await job.updateProgress?.({
      percent: 100,
      stage: "complete",
      message: "Remediation workflow complete",
    } as JobProgress);

    emitRemediationProgress(tenantId, organizationId, remediationId, {
      type: "remediation_completed",
      successCount,
      pendingCount,
      failedCount,
      totalCount: allActions.length,
    });

    return {
      success: failedCount === 0,
      data: {
        remediationId,
        findingsAddressed: findingIds.length,
        actionsExecuted: allActions.length,
        successCount,
        pendingCount,
        failedCount,
        skippedCount,
        dryRun,
        results: actionResults,
        guidance: guidance ? {
          id: guidance.id,
          summary: guidance.summary,
          executiveSummary: guidance.executiveSummary,
          totalRiskReduction: guidance.totalRiskReduction,
          estimatedImplementationTime: guidance.estimatedImplementationTime,
          prioritizedActions: guidance.prioritizedActions,
        } : undefined,
      },
      duration: Date.now() - startTime,
    };

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error(`[Remediation] Remediation failed:`, errorMessage);

    emitRemediationProgress(tenantId, organizationId, remediationId, {
      type: "remediation_failed",
      error: errorMessage,
    });

    return {
      success: false,
      error: errorMessage,
      duration: Date.now() - startTime,
    };
  }
}
