import { Job } from "bullmq";
import { storage } from "../../../storage";
import { fullRecon, reconToExposures, ReconResult } from "../../external-recon";
import { governanceEnforcement } from "../../governance/governance-enforcement";
import {
  ExternalReconJobData,
  JobResult,
  JobProgress,
} from "../job-types";

interface ExternalReconJob {
  id?: string;
  data: ExternalReconJobData;
  updateProgress?: (progress: number | object) => Promise<void>;
}

function emitReconProgress(
  tenantId: string,
  organizationId: string,
  reconId: string,
  event: Record<string, any>
): void {
  const type = event.type;
  
  if (type === "external_recon_started") {
    console.log(`[ExternalRecon] ${reconId}: Started scanning ${event.target}`);
  } else if (type === "external_recon_progress") {
    console.log(`[ExternalRecon] ${reconId}: ${event.phase} - ${event.message}`);
  } else if (type === "external_recon_completed") {
    console.log(`[ExternalRecon] ${reconId}: Completed - ${event.exposuresFound} exposures found`);
  } else if (type === "external_recon_failed") {
    console.log(`[ExternalRecon] ${reconId}: Failed - ${event.error}`);
  }
  
  try {
    const { wsService } = require("../../websocket");
    if (!wsService) return;
    
    const channel = `external-recon:${tenantId}:${organizationId}:${reconId}`;
    
    const phaseMap: Record<string, "dns" | "ports" | "ssl" | "http" | "complete" | "error"> = {
      dns: "dns",
      ports: "ports",
      ssl: "ssl",
      http: "http",
      complete: "complete",
      error: "error",
    };
    
    if (type === "external_recon_progress") {
      wsService.broadcastToChannel(channel, {
        type: "recon_progress",
        scanId: reconId,
        phase: phaseMap[event.phase] || "ports",
        progress: event.progress || 0,
        message: event.message,
        portsFound: event.portsFound || 0,
        vulnerabilitiesFound: event.exposuresFound || 0,
      });
    } else if (type === "external_recon_completed") {
      wsService.broadcastToChannel(channel, {
        type: "recon_progress",
        scanId: reconId,
        phase: "complete",
        progress: 100,
        message: `Scan complete: ${event.exposuresFound} exposures identified`,
        portsFound: event.openPorts || 0,
        vulnerabilitiesFound: event.exposuresFound || 0,
      });
    } else if (type === "external_recon_failed") {
      wsService.broadcastToChannel(channel, {
        type: "recon_progress",
        scanId: reconId,
        phase: "error",
        progress: 0,
        message: `Scan failed: ${event.error}`,
        portsFound: 0,
        vulnerabilitiesFound: 0,
      });
    }
  } catch {
  }
}

export async function handleExternalReconJob(
  job: Job<ExternalReconJobData> | ExternalReconJob
): Promise<JobResult> {
  const startTime = Date.now();
  const { reconId, target, modules, tenantId, organizationId } = job.data;
  const jobId = job.id || reconId;

  console.log(`[ExternalRecon] Starting reconnaissance for target: ${target}`);

  const governanceCheck = await governanceEnforcement.canStartOperation(
    organizationId,
    "external_recon",
    target
  );
  
  if (!governanceCheck.canStart) {
    console.log(`[ExternalRecon] Blocked by governance: ${governanceCheck.reason}`);
    
    emitReconProgress(tenantId, organizationId, reconId, {
      type: "external_recon_failed",
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

  await governanceEnforcement.logOperationStarted(organizationId, "external_recon", target);

  emitReconProgress(tenantId, organizationId, reconId, {
    type: "external_recon_started",
    target,
    modules,
  });

  try {
    const reconModules = modules || ["dns", "ports", "ssl", "http"];
    const totalSteps = reconModules.length;
    let completedSteps = 0;

    const updateProgress = async (phase: string, message: string) => {
      completedSteps++;
      const progress = Math.round((completedSteps / totalSteps) * 100);
      
      await job.updateProgress?.({
        percent: Math.min(99, progress),
        stage: phase,
        message,
      } as JobProgress);

      emitReconProgress(tenantId, organizationId, reconId, {
        type: "external_recon_progress",
        phase,
        progress,
        message,
      });
    };

    await updateProgress("dns", `Starting DNS enumeration for ${target}`);

    const result: ReconResult = await fullRecon(target, {
      portScan: reconModules.includes("ports"),
      sslCheck: reconModules.includes("ssl"),
      httpFingerprint: reconModules.includes("http"),
      dnsEnum: reconModules.includes("dns"),
      authSurface: true,
      generateSummary: true,
    });

    await updateProgress("ports", `Port scanning complete`);
    
    if (reconModules.includes("ssl")) {
      await updateProgress("ssl", `SSL/TLS analysis complete`);
    }
    
    if (reconModules.includes("http")) {
      await updateProgress("http", `HTTP fingerprinting complete`);
    }

    const exposures = reconToExposures(result);
    const openPorts = result.portScan?.filter(p => p.state === "open").length || 0;

    await storage.createReconScan({
      id: reconId,
      organizationId,
      target,
      status: "completed",
      scanTime: new Date(),
      portScan: result.portScan || [],
      networkExposure: result.networkExposure || null,
      sslCheck: result.sslCheck || null,
      transportSecurity: result.transportSecurity || null,
      httpFingerprint: result.httpFingerprint || null,
      applicationIdentity: result.applicationIdentity || null,
      authenticationSurface: result.authenticationSurface || null,
      dnsEnum: result.dnsEnum || null,
      infrastructure: result.infrastructure || null,
      attackReadiness: result.attackReadiness || null,
      errors: result.errors || [],
    });

    console.log(`[ExternalRecon] ${reconId}: Found ${openPorts} open ports, ${exposures.length} exposures for ${target}`);

    await job.updateProgress?.({
      percent: 100,
      stage: "complete",
      message: `Reconnaissance complete: ${exposures.length} exposures identified`,
    } as JobProgress);

    emitReconProgress(tenantId, organizationId, reconId, {
      type: "external_recon_completed",
      target,
      openPorts,
      exposuresFound: exposures.length,
      sslValid: result.sslCheck?.valid,
      technologies: result.httpFingerprint?.technologies || [],
    });

    return {
      success: true,
      data: {
        reconId,
        target,
        openPorts,
        exposuresFound: exposures.length,
        exposures: exposures.map(e => ({
          type: e.type,
          severity: e.severity,
          description: e.description,
        })),
        sslValid: result.sslCheck?.valid,
        technologies: result.httpFingerprint?.technologies || [],
        dnsRecords: result.dnsEnum,
      },
      duration: Date.now() - startTime,
    };

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error(`[ExternalRecon] Reconnaissance failed for ${target}:`, errorMessage);

    emitReconProgress(tenantId, organizationId, reconId, {
      type: "external_recon_failed",
      target,
      error: errorMessage,
    });

    return {
      success: false,
      error: errorMessage,
      duration: Date.now() - startTime,
    };
  }
}
