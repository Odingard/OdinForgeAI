import { Job } from "bullmq";
import { storage } from "../../../storage";
import { runFullAssessment } from "../../full-assessment";
import { governanceEnforcement } from "../../governance/governance-enforcement";
import {
  FullAssessmentJobData,
  JobResult,
  JobProgress,
} from "../job-types";

interface FullAssessmentJob {
  id?: string;
  data: FullAssessmentJobData;
  updateProgress?: (progress: number | object) => Promise<void>;
}

function emitAssessmentProgress(
  tenantId: string,
  organizationId: string,
  assessmentId: string,
  event: Record<string, any>
): void {
  const type = event.type;
  
  if (type === "assessment_started") {
    console.log(`[FullAssessment] ${assessmentId}: Started with ${event.systemCount} target systems`);
  } else if (type === "assessment_progress") {
    console.log(`[FullAssessment] ${assessmentId}: Phase ${event.phase} - ${event.message}`);
  } else if (type === "assessment_completed") {
    console.log(`[FullAssessment] ${assessmentId}: Completed - ${event.findingsCount} findings`);
  } else if (type === "assessment_failed") {
    console.log(`[FullAssessment] ${assessmentId}: Failed - ${event.error}`);
  }

  try {
    const { wsService } = require("../../websocket");
    if (!wsService) return;
    
    const channel = `assessment:${tenantId}:${organizationId}:${assessmentId}`;
    wsService.broadcastToChannel(channel, {
      type: "assessment_progress",
      assessmentId,
      phase: event.phase || "processing",
      progress: event.progress || 0,
      message: event.message,
    });
  } catch {
  }
}

export async function handleFullAssessmentJob(
  job: Job<FullAssessmentJobData> | FullAssessmentJob
): Promise<JobResult> {
  const startTime = Date.now();
  const { assessmentId, targetSystems, phases, tenantId, organizationId } = job.data;
  const jobId = job.id || assessmentId;

  console.log(`[FullAssessment] Starting full assessment ${assessmentId} for ${targetSystems.length} systems`);

  const governanceCheck = await governanceEnforcement.canStartOperation(
    organizationId,
    "full_assessment",
    targetSystems[0]
  );
  
  if (!governanceCheck.canStart) {
    console.log(`[FullAssessment] Blocked by governance: ${governanceCheck.reason}`);
    
    emitAssessmentProgress(tenantId, organizationId, assessmentId, {
      type: "assessment_failed",
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

  await governanceEnforcement.logOperationStarted(organizationId, "full_assessment", targetSystems.join(", "));

  emitAssessmentProgress(tenantId, organizationId, assessmentId, {
    type: "assessment_started",
    systemCount: targetSystems.length,
    phases: phases || ["reconnaissance", "vulnerability", "attack", "lateral", "impact"],
  });

  try {
    await job.updateProgress?.({
      percent: 5,
      stage: "initializing",
      message: "Initializing full assessment...",
    } as JobProgress);

    const onProgress = (
      id: string,
      phase: string,
      progress: number,
      message: string
    ) => {
      job.updateProgress?.({
        percent: Math.min(progress, 99),
        stage: phase,
        message,
      } as JobProgress);

      emitAssessmentProgress(tenantId, organizationId, assessmentId, {
        type: "assessment_progress",
        phase,
        progress,
        message,
      });
    };

    await runFullAssessment(assessmentId, onProgress);

    const assessment = await storage.getFullAssessment(assessmentId);

    await job.updateProgress?.({
      percent: 100,
      stage: "complete",
      message: "Full assessment complete",
    } as JobProgress);

    const findingsCount = assessment?.findingsAnalyzed || 0;
    const attackPathCount = assessment?.criticalPathCount || 0;

    emitAssessmentProgress(tenantId, organizationId, assessmentId, {
      type: "assessment_completed",
      findingsCount,
      attackPathCount,
      systemsAssessed: targetSystems.length,
    });

    return {
      success: true,
      data: {
        assessmentId,
        targetSystems: targetSystems.length,
        findingsCount,
        attackPathCount,
      },
      duration: Date.now() - startTime,
    };

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error(`[FullAssessment] Assessment failed:`, errorMessage);

    emitAssessmentProgress(tenantId, organizationId, assessmentId, {
      type: "assessment_failed",
      error: errorMessage,
    });

    return {
      success: false,
      error: errorMessage,
      duration: Date.now() - startTime,
    };
  }
}
