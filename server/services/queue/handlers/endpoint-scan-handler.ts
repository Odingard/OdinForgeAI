import type { Job } from "bullmq";
import type { AnyJobData, JobResult } from "../job-types";
import { handleEndpointScanJob } from "../../endpoint/endpointAgentOrchestrator";

export async function handleEndpointScanJobHandler(job: Job<AnyJobData>): Promise<JobResult> {
  const startTime = Date.now();

  const result = await handleEndpointScanJob({
    data: job.data as any,
    updateProgress: async (p: number) => {
      await job.updateProgress(p);
    },
    log: (msg: string) => {
      console.log(`[endpoint-scan:${job.id}]`, msg);
    },
  });

  return {
    success: true,
    data: {
      os:        result.os,
      hostname:  result.hostname,
      findings:  result.findings.length,
      errors:    result.errors.length,
      checksRun: result.checksRun,
    },
    duration: Date.now() - startTime,
    metrics: {
      findings:  result.findings.length,
      errors:    result.errors.length,
      checksRun: result.checksRun,
    },
  };
}
