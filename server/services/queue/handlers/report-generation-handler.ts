import { Job } from "bullmq";
import { storage } from "../../../storage";
import { reportGenerator } from "../../report-generator";
import { setTenantContext, clearTenantContext } from "../../rls-setup";
import {
  ReportGenerationJobData,
  JobResult,
  JobProgress,
} from "../job-types";

interface ReportGenerationJob {
  id?: string;
  data: ReportGenerationJobData;
  updateProgress?: (progress: number | object) => Promise<void>;
}

function emitReportProgress(
  tenantId: string,
  organizationId: string,
  reportId: string,
  event: Record<string, any>
): void {
  const type = event.type;
  
  if (type === "report_generation_started") {
    console.log(`[ReportGeneration] ${reportId}: Started generating ${event.reportType} report`);
  } else if (type === "report_generation_progress") {
    console.log(`[ReportGeneration] ${reportId}: ${event.phase} - ${event.message}`);
  } else if (type === "report_generation_completed") {
    console.log(`[ReportGeneration] ${reportId}: Completed - ${event.format} report generated`);
  } else if (type === "report_generation_failed") {
    console.log(`[ReportGeneration] ${reportId}: Failed - ${event.error}`);
  }

  try {
    const { broadcastToChannel } = require("../../ws-bridge");
    const channel = `report:${tenantId}:${organizationId}:${reportId}`;
    broadcastToChannel(channel, {
      type: "recon_progress",
      scanId: reportId,
      phase: event.phase === "complete" ? "complete" : event.phase === "error" ? "error" : "http",
      progress: event.progress || 0,
      message: event.message,
    });
  } catch {
  }
}

export async function handleReportGenerationJob(
  job: Job<ReportGenerationJobData> | ReportGenerationJob
): Promise<JobResult> {
  const startTime = Date.now();
  const { reportId, evaluationIds, format = "pdf", reportType = "executive", tenantId, organizationId } = job.data;
  const jobId = job.id || reportId;

  console.log(`[ReportGeneration] Starting ${reportType} report generation for ${evaluationIds.length} evaluation(s)`);

  await setTenantContext(organizationId);

  emitReportProgress(tenantId, organizationId, reportId, {
    type: "report_generation_started",
    reportType,
    format,
    evaluationCount: evaluationIds.length,
  });

  try {
    await job.updateProgress?.({
      percent: 10,
      stage: "gathering",
      message: "Gathering evaluation data...",
    } as JobProgress);

    emitReportProgress(tenantId, organizationId, reportId, {
      type: "report_generation_progress",
      phase: "gathering",
      progress: 10,
      message: "Gathering evaluation data",
    });

    const evaluations = await Promise.all(
      evaluationIds.map(id => storage.getEvaluation(id))
    );

    const validEvaluations = evaluations.filter(e => e !== undefined);
    
    if (validEvaluations.length === 0) {
      throw new Error("No valid evaluations found for report generation");
    }

    await job.updateProgress?.({
      percent: 30,
      stage: "analyzing",
      message: "Analyzing evaluation results...",
    } as JobProgress);

    emitReportProgress(tenantId, organizationId, reportId, {
      type: "report_generation_progress",
      phase: "analyzing",
      progress: 30,
      message: "Analyzing evaluation results",
    });

    const results = await Promise.all(
      evaluationIds.map(id => storage.getResultByEvaluationId(id))
    );
    const allResults = results.filter(r => r !== undefined);

    await job.updateProgress?.({
      percent: 50,
      stage: "generating",
      message: `Generating ${reportType} report...`,
    } as JobProgress);

    emitReportProgress(tenantId, organizationId, reportId, {
      type: "report_generation_progress",
      phase: "generating",
      progress: 50,
      message: `Generating ${reportType} report`,
    });

    let reportContent: any;
    const now = new Date();
    
    const earliestEval = validEvaluations.reduce((earliest, e) => {
      const evalDate = e.createdAt ? new Date(e.createdAt) : now;
      return evalDate < earliest ? evalDate : earliest;
    }, now);
    const dateRangeFrom = earliestEval;
    const dateRangeTo = now;
    
    if (reportType === "technical" && evaluationIds.length === 1) {
      reportContent = await reportGenerator.generateSingleEvaluationTechnicalReport(evaluationIds[0]);
    } else if (reportType === "technical") {
      reportContent = await reportGenerator.generateTechnicalReport(dateRangeFrom, dateRangeTo, organizationId);
    } else if (reportType === "compliance" && evaluationIds.length === 1) {
      reportContent = await reportGenerator.generateSingleEvaluationComplianceReport(evaluationIds[0], "pci_dss");
    } else if (reportType === "compliance") {
      reportContent = await reportGenerator.generateComplianceReport("pci_dss", dateRangeFrom, dateRangeTo, organizationId);
    } else {
      reportContent = {
        title: `Executive Security Assessment Report`,
        generatedAt: new Date().toISOString(),
        evaluationCount: validEvaluations.length,
        findings: allResults.length,
        type: reportType,
        summary: `Security assessment covering ${validEvaluations.length} evaluation(s) with ${allResults.length} finding(s).`,
      };
    }

    await job.updateProgress?.({
      percent: 80,
      stage: "formatting",
      message: `Formatting as ${format}...`,
    } as JobProgress);

    emitReportProgress(tenantId, organizationId, reportId, {
      type: "report_generation_progress",
      phase: "formatting",
      progress: 80,
      message: `Formatting as ${format}`,
    });

    await storage.createReport({
      organizationId,
      evaluationIds,
      reportType: reportType as any,
      title: `${reportType.charAt(0).toUpperCase() + reportType.slice(1)} Report`,
      dateRangeFrom,
      dateRangeTo,
      status: "completed",
      reportVersion: "v1_template",
      content: { ...reportContent, format },
    } as any);

    await job.updateProgress?.({
      percent: 100,
      stage: "complete",
      message: "Report generation complete",
    } as JobProgress);

    emitReportProgress(tenantId, organizationId, reportId, {
      type: "report_generation_completed",
      phase: "complete",
      format,
      reportType,
      evaluationCount: validEvaluations.length,
      findingsCount: allResults.length,
    });

    return {
      success: true,
      data: {
        reportId,
        reportType,
        format,
        evaluationCount: validEvaluations.length,
        findingsCount: allResults.length,
      },
      duration: Date.now() - startTime,
    };

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error(`[ReportGeneration] Report generation failed:`, errorMessage);

    emitReportProgress(tenantId, organizationId, reportId, {
      type: "report_generation_failed",
      phase: "error",
      error: errorMessage,
    });

    return {
      success: false,
      error: errorMessage,
      duration: Date.now() - startTime,
    };
  } finally {
    await clearTenantContext().catch((err) => console.error("[RLS] Failed to clear context:", err));
  }
}
