import { queueService, JobHandler } from "../queue-service";
import { AEV_ONLY_MODE } from "../../../feature-flags";
import { handleNetworkScanJob } from "./network-scan-handler";
import { handleCloudDiscoveryJob } from "./cloud-discovery-handler";
import { handleExternalReconJob } from "./external-recon-handler";
import { handleReportGenerationJob } from "./report-generation-handler";
import { handleAISimulationJob } from "./ai-simulation-handler";
import { handleEvaluationJob } from "./evaluation-handler";
import { handleFullAssessmentJob } from "./full-assessment-handler";
import { handleExploitValidationJob } from "./exploit-validation-handler";
import { handleApiScanJob } from "./api-scan-handler";
import { handleAuthScanJob } from "./auth-scan-handler";
import { handleRemediationJob } from "./remediation-handler";
import { handleAgentDeploymentJob } from "./agent-deployment-handler";
import { handleProtocolProbeJob } from "./protocol-probe-handler";
import { handleReconScanJob } from "./recon-handler";
import { handleMimirTriggeredEvaluation } from "./mimir-triggered-evaluation-handler";
import { handleCloudScanJobHandler } from "./cloud-scan-handler";
import { handleEndpointScanJobHandler } from "./endpoint-scan-handler";

export function registerJobHandlers(): void {
  console.log(`[Queue] Registering job handlers (AEV_ONLY=${AEV_ONLY_MODE})...`);

  // AEV-core handlers — always registered
  queueService.registerHandler("evaluation", handleEvaluationJob as JobHandler);
  queueService.registerHandler("exploit_validation", handleExploitValidationJob as JobHandler);
  queueService.registerHandler("recon_scan", handleReconScanJob as JobHandler);
  queueService.registerHandler("report_generation", handleReportGenerationJob as JobHandler);
  queueService.registerHandler("external_recon", handleExternalReconJob as JobHandler);
  queueService.registerHandler("full_assessment", handleFullAssessmentJob as JobHandler);
  queueService.registerHandler("api_scan", handleApiScanJob as JobHandler);
  queueService.registerHandler("auth_scan", handleAuthScanJob as JobHandler);
  queueService.registerHandler("protocol_probe", handleProtocolProbeJob as JobHandler);
  queueService.registerHandler("remediation", handleRemediationJob as JobHandler);
  queueService.registerHandler("mimir_triggered_evaluation", handleMimirTriggeredEvaluation as JobHandler);

  if (!AEV_ONLY_MODE) {
    // Non-AEV handlers — skipped in AEV_ONLY mode
    queueService.registerHandler("network_scan", handleNetworkScanJob as JobHandler);
    queueService.registerHandler("cloud_discovery", handleCloudDiscoveryJob as JobHandler);
    queueService.registerHandler("ai_simulation", handleAISimulationJob as JobHandler);
    queueService.registerHandler("agent_deployment", handleAgentDeploymentJob as JobHandler);
    queueService.registerHandler("cloud_scan", handleCloudScanJobHandler as JobHandler);
    queueService.registerHandler("endpoint_scan", handleEndpointScanJobHandler as JobHandler);
  }

  const count = AEV_ONLY_MODE ? 11 : 17;
  console.log(`[Queue] ${count} job handlers registered`);

  // Start the shared worker after all handlers are registered
  queueService.startWorker();
}

export {
  handleNetworkScanJob,
  handleCloudDiscoveryJob,
  handleExternalReconJob,
  handleReportGenerationJob,
  handleAISimulationJob,
  handleEvaluationJob,
  handleFullAssessmentJob,
  handleExploitValidationJob,
  handleApiScanJob,
  handleAuthScanJob,
  handleRemediationJob,
  handleAgentDeploymentJob,
  handleProtocolProbeJob,
  handleReconScanJob,
  handleMimirTriggeredEvaluation,
  handleCloudScanJobHandler,
  handleEndpointScanJobHandler,
};
