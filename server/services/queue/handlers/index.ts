import { queueService, JobHandler } from "../queue-service";
import { AEV_ONLY_MODE } from "../../../feature-flags";
import { handleReportGenerationJob } from "./report-generation-handler";
import { handleEvaluationJob } from "./evaluation-handler";
import { handleExploitValidationJob } from "./exploit-validation-handler";
import { handleAuthScanJob } from "./auth-scan-handler";
import { handleProtocolProbeJob } from "./protocol-probe-handler";
import { handleMimirTriggeredEvaluation } from "./mimir-triggered-evaluation-handler";

// core-v2: Non-core handlers removed (network-scan, cloud-discovery, external-recon,
// ai-simulation, full-assessment, api-scan, remediation, agent-deployment, recon,
// cloud-scan, endpoint-scan)

export function registerJobHandlers(): void {
  console.log(`[Queue] Registering job handlers (AEV_ONLY=${AEV_ONLY_MODE})...`);

  // Core handlers — always registered
  queueService.registerHandler("evaluation", handleEvaluationJob as JobHandler);
  queueService.registerHandler("exploit_validation", handleExploitValidationJob as JobHandler);
  queueService.registerHandler("report_generation", handleReportGenerationJob as JobHandler);
  queueService.registerHandler("auth_scan", handleAuthScanJob as JobHandler);
  queueService.registerHandler("protocol_probe", handleProtocolProbeJob as JobHandler);
  queueService.registerHandler("mimir_triggered_evaluation", handleMimirTriggeredEvaluation as JobHandler);

  const count = 6;
  console.log(`[Queue] ${count} job handlers registered`);

  // Start the shared worker after all handlers are registered
  queueService.startWorker();
}

export {
  handleReportGenerationJob,
  handleEvaluationJob,
  handleExploitValidationJob,
  handleAuthScanJob,
  handleProtocolProbeJob,
  handleMimirTriggeredEvaluation,
};
