import { queueService, JobHandler } from "../queue-service";
import { handleNetworkScanJob } from "./network-scan-handler";
import { handleCloudDiscoveryJob } from "./cloud-discovery-handler";
import { handleExternalReconJob } from "./external-recon-handler";
import { handleReportGenerationJob } from "./report-generation-handler";
import { handleAISimulationJob } from "./ai-simulation-handler";
import { handleEvaluationJob } from "./evaluation-handler";
import { handleFullAssessmentJob } from "./full-assessment-handler";

export function registerJobHandlers(): void {
  console.log("[Queue] Registering job handlers...");
  
  queueService.registerHandler("network_scan", handleNetworkScanJob as JobHandler);
  queueService.registerHandler("cloud_discovery", handleCloudDiscoveryJob as JobHandler);
  queueService.registerHandler("external_recon", handleExternalReconJob as JobHandler);
  queueService.registerHandler("report_generation", handleReportGenerationJob as JobHandler);
  queueService.registerHandler("ai_simulation", handleAISimulationJob as JobHandler);
  queueService.registerHandler("evaluation", handleEvaluationJob as JobHandler);
  queueService.registerHandler("full_assessment", handleFullAssessmentJob as JobHandler);
  
  console.log("[Queue] Job handlers registered: network_scan, cloud_discovery, external_recon, report_generation, ai_simulation, evaluation, full_assessment");
}

export { 
  handleNetworkScanJob, 
  handleCloudDiscoveryJob, 
  handleExternalReconJob,
  handleReportGenerationJob,
  handleAISimulationJob,
  handleEvaluationJob,
  handleFullAssessmentJob,
};
