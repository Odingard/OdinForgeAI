import { queueService, JobHandler } from "../queue-service";
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

export function registerJobHandlers(): void {
  console.log("[Queue] Registering job handlers...");
  
  queueService.registerHandler("network_scan", handleNetworkScanJob as JobHandler);
  queueService.registerHandler("cloud_discovery", handleCloudDiscoveryJob as JobHandler);
  queueService.registerHandler("external_recon", handleExternalReconJob as JobHandler);
  queueService.registerHandler("report_generation", handleReportGenerationJob as JobHandler);
  queueService.registerHandler("ai_simulation", handleAISimulationJob as JobHandler);
  queueService.registerHandler("evaluation", handleEvaluationJob as JobHandler);
  queueService.registerHandler("full_assessment", handleFullAssessmentJob as JobHandler);
  queueService.registerHandler("exploit_validation", handleExploitValidationJob as JobHandler);
  queueService.registerHandler("api_scan", handleApiScanJob as JobHandler);
  queueService.registerHandler("auth_scan", handleAuthScanJob as JobHandler);
  queueService.registerHandler("remediation", handleRemediationJob as JobHandler);
  queueService.registerHandler("agent_deployment", handleAgentDeploymentJob as JobHandler);
  queueService.registerHandler("protocol_probe", handleProtocolProbeJob as JobHandler);
  
  console.log("[Queue] Job handlers registered (13 total): network_scan, cloud_discovery, external_recon, report_generation, ai_simulation, evaluation, full_assessment, exploit_validation, api_scan, auth_scan, remediation, agent_deployment, protocol_probe");
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
};
