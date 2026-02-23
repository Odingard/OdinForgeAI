// =============================================================================
// Task 06 — Cloud Scan Orchestrator
// server/services/cloud/cloudScanOrchestrator.ts
//
// Entry point for cloud scans. Provides:
//   - Scanner factory (returns correct scanner for provider)
//   - BullMQ job handler (integrates with OdinForge job queue)
//   - Credential validation endpoint helper
//   - Scan result persistence to entity graph
// =============================================================================

import { EntityGraphWriter } from "../entityGraph/entityGraphWriter";
import { db } from "../../db";
import { AwsScanner }   from "./AwsScanner";
import { AzureScanner } from "./AzureScanner";
import { GcpScanner }   from "./GcpScanner";
import { K8sScanner }   from "./K8sScanner";
import type { CloudScanner, CloudCredentials, CloudScanResult } from "./base/CloudScanner";

// —— Scanner factory ——————————————————————————————————————————————
export function createCloudScanner(opts: {
  provider:       string;
  organizationId: string;
  evaluationId:   string;
  entityWriter:   EntityGraphWriter;
}): CloudScanner {
  const base = { ...opts };
  switch (opts.provider) {
    case "aws":   return new AwsScanner(base);
    case "azure": return new AzureScanner(base);
    case "gcp":   return new GcpScanner(base);
    case "k8s":   return new K8sScanner(base);
    default:
      throw new Error(`Unknown cloud provider: ${opts.provider}. Supported: aws, azure, gcp, k8s`);
  }
}

// —— BullMQ job handler ———————————————————————————————————————————

export interface CloudScanJobData {
  organizationId: string;
  evaluationId:   string;
  provider:       string;
  credentials:    CloudCredentials;   // Decrypted at job dispatch time
}

export async function handleCloudScanJob(job: {
  data: CloudScanJobData;
  updateProgress: (progress: number) => Promise<void>;
  log: (msg: string) => void;
}): Promise<CloudScanResult> {
  const { organizationId, evaluationId, provider, credentials } = job.data;

  job.log(`Starting ${provider} cloud scan for eval ${evaluationId}`);
  await job.updateProgress(5);

  const entityWriter = new EntityGraphWriter(db, organizationId);

  const scanner = createCloudScanner({
    provider,
    organizationId,
    evaluationId,
    entityWriter,
  });

  await job.updateProgress(10);

  let result: CloudScanResult;
  try {
    result = await scanner.run(credentials);
    await job.updateProgress(90);
  } catch (err: unknown) {
    const e = err as Error;
    job.log(`Cloud scan failed: ${e.message}`);
    throw e; // BullMQ will mark job as failed
  }

  // Summary log
  job.log(
    `Cloud scan complete — provider=${provider} findings=${result.findings.length} ` +
    `errors=${result.errors.length} checksRun=${result.checksRun} ` +
    `duration=${result.finishedAt.getTime() - result.startedAt.getTime()}ms`
  );

  await job.updateProgress(100);
  return result;
}

// —— Credential validation helper (used by API before queuing scan) ————
export async function validateCloudCredentials(
  provider:    string,
  credentials: CloudCredentials
): Promise<{ valid: boolean; error?: string }> {
  try {
    const entityWriter = new EntityGraphWriter(db, "validate-only");
    const scanner = createCloudScanner({
      provider,
      organizationId: "validate-only",
      evaluationId:   "validate-only",
      entityWriter,
    });
    await (scanner as unknown as { validateCredentials: (c: CloudCredentials) => Promise<void> })
      .validateCredentials(credentials);
    return { valid: true };
  } catch (err: unknown) {
    return { valid: false, error: (err as Error).message };
  }
}

// —— Cloud scan queue helper ——————————————————————————————————————
export async function queueCloudScan(opts: {
  evaluationId:   string;
  organizationId: string;
  provider:       string;
  credentials:    CloudCredentials;
  queueService:   { addJob: (type: string, data: unknown) => Promise<void> };
}): Promise<void> {
  // Validate credentials before spending queue slot
  const validation = await validateCloudCredentials(opts.provider, opts.credentials);
  if (!validation.valid) {
    throw new Error(validation.error ?? "Invalid cloud credentials");
  }

  await opts.queueService.addJob("cloud_scan", {
    organizationId: opts.organizationId,
    evaluationId:   opts.evaluationId,
    provider:       opts.provider,
    credentials:    opts.credentials,
  } satisfies CloudScanJobData);
}
