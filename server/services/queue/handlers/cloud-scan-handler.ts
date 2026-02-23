import type { Job } from "bullmq";
import type { AnyJobData, JobResult } from "../job-types";
import { handleCloudScanJob } from "../../cloud/cloudScanOrchestrator";

export async function handleCloudScanJobHandler(job: Job<AnyJobData>): Promise<JobResult> {
  const startTime = Date.now();

  const result = await handleCloudScanJob({
    data: job.data as any,
    updateProgress: async (progress: number) => {
      await job.updateProgress(progress);
    },
    log: (msg: string) => {
      console.log(`[cloud-scan:${job.id}]`, msg);
    },
  });

  return {
    success: true,
    data: {
      provider:   result.provider,
      findings:   result.findings.length,
      errors:     result.errors.length,
      checksRun:  result.checksRun,
    },
    duration: Date.now() - startTime,
    metrics: {
      findings:  result.findings.length,
      errors:    result.errors.length,
      checksRun: result.checksRun,
    },
  };
}
