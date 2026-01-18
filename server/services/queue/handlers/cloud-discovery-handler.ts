import { Job } from "bullmq";
import { storage } from "../../../storage";
import { cloudIntegrationService } from "../../cloud";
import { governanceEnforcement } from "../../governance/governance-enforcement";
import {
  CloudDiscoveryJobData,
  JobResult,
  JobProgress,
} from "../job-types";

interface CloudDiscoveryJob {
  id?: string;
  data: CloudDiscoveryJobData;
  updateProgress?: (progress: number | object) => Promise<void>;
}

function emitDiscoveryProgress(
  tenantId: string,
  organizationId: string,
  jobId: string,
  event: Record<string, any>
): void {
  const type = event.type;
  
  if (type === "cloud_discovery_started") {
    console.log(`[CloudDiscovery] ${jobId}: Started for provider ${event.provider}`);
  } else if (type === "cloud_discovery_progress") {
    console.log(`[CloudDiscovery] ${jobId}: ${event.completedRegions}/${event.totalRegions} regions, ${event.assetsFound} assets`);
  } else if (type === "cloud_discovery_completed") {
    console.log(`[CloudDiscovery] ${jobId}: Completed - ${event.newAssets} new, ${event.updatedAssets} updated`);
  } else if (type === "cloud_discovery_failed") {
    console.log(`[CloudDiscovery] ${jobId}: Failed - ${event.error}`);
  }
  
  try {
    const { wsService } = require("../../websocket");
    if (!wsService) return;
    
    const channel = `cloud-discovery:${tenantId}:${organizationId}:${jobId}`;
    
    if (type === "cloud_discovery_progress") {
      wsService.broadcastToChannel(channel, {
        type: "recon_progress",
        scanId: jobId,
        phase: "ports",
        progress: event.progress || 0,
        message: `Discovered ${event.assetsFound} assets in ${event.completedRegions}/${event.totalRegions} regions`,
        portsFound: event.assetsFound,
        vulnerabilitiesFound: 0,
      });
    } else if (type === "cloud_discovery_completed") {
      wsService.broadcastToChannel(channel, {
        type: "recon_progress",
        scanId: jobId,
        phase: "complete",
        progress: 100,
        message: `Discovery complete: ${event.newAssets} new assets, ${event.updatedAssets} updated`,
        portsFound: event.totalAssets,
        vulnerabilitiesFound: 0,
      });
    } else if (type === "cloud_discovery_failed") {
      wsService.broadcastToChannel(channel, {
        type: "recon_progress",
        scanId: jobId,
        phase: "error",
        progress: 0,
        message: `Discovery failed: ${event.error}`,
        portsFound: 0,
        vulnerabilitiesFound: 0,
      });
    }
  } catch {
  }
}

export async function handleCloudDiscoveryJob(
  job: Job<CloudDiscoveryJobData> | CloudDiscoveryJob
): Promise<JobResult> {
  const startTime = Date.now();
  const { connectionId, provider, regions, tenantId, organizationId } = job.data;
  const jobId = job.id || connectionId;

  const governanceCheck = await governanceEnforcement.canStartOperation(
    organizationId,
    "cloud_discovery",
    provider
  );
  
  if (!governanceCheck.canStart) {
    console.log(`[CloudDiscovery] Blocked by governance: ${governanceCheck.reason}`);
    
    emitDiscoveryProgress(tenantId, organizationId, jobId, {
      type: "cloud_discovery_failed",
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

  await governanceEnforcement.logOperationStarted(organizationId, "cloud_discovery", provider);

  console.log(`[CloudDiscovery] Starting discovery for connection ${connectionId} (${provider})`);

  emitDiscoveryProgress(tenantId, organizationId, jobId, {
    type: "cloud_discovery_started",
    connectionId,
    provider,
  });

  try {
    const connection = await storage.getCloudConnection(connectionId);
    if (!connection) {
      throw new Error("Cloud connection not found");
    }

    if (connection.organizationId !== organizationId) {
      throw new Error("Connection does not belong to this organization");
    }

    const result = await cloudIntegrationService.startDiscoveryJob(
      connectionId,
      organizationId,
      { regions, triggeredBy: `job:${jobId}` }
    );

    if (result.error) {
      throw new Error(result.error);
    }

    const discoveryJobId = result.jobId;
    let lastProgress = 0;
    let attempts = 0;
    const maxAttempts = 300;

    while (attempts < maxAttempts) {
      await new Promise(resolve => setTimeout(resolve, 2000));
      attempts++;

      const discoveryJob = await storage.getCloudDiscoveryJob(discoveryJobId);
      if (!discoveryJob) {
        throw new Error("Discovery job not found");
      }

      const totalRegions = discoveryJob.totalRegions || 1;
      const completedRegions = discoveryJob.completedRegions || 0;
      const progress = totalRegions > 0
        ? Math.round((completedRegions / totalRegions) * 100)
        : 0;

      if (progress !== lastProgress) {
        lastProgress = progress;
        
        await job.updateProgress?.({
          percent: Math.min(99, progress),
          stage: "discovery",
          message: `Discovered ${discoveryJob.totalAssets || 0} assets in ${completedRegions}/${totalRegions} regions`,
        } as JobProgress);

        emitDiscoveryProgress(tenantId, organizationId, jobId, {
          type: "cloud_discovery_progress",
          completedRegions,
          totalRegions,
          assetsFound: discoveryJob.totalAssets || 0,
          progress,
        });
      }

      if (discoveryJob.status === "completed") {
        await job.updateProgress?.({
          percent: 100,
          stage: "complete",
          message: `Discovery complete: ${discoveryJob.newAssets} new, ${discoveryJob.updatedAssets} updated`,
        } as JobProgress);

        emitDiscoveryProgress(tenantId, organizationId, jobId, {
          type: "cloud_discovery_completed",
          totalAssets: discoveryJob.totalAssets || 0,
          newAssets: discoveryJob.newAssets || 0,
          updatedAssets: discoveryJob.updatedAssets || 0,
        });

        // Trigger auto-deployment for ONLY newly discovered assets if enabled
        const newAssetCount = discoveryJob.newAssets || 0;
        if (newAssetCount > 0) {
          try {
            const { triggerAutoDeployForNewAssets } = await import("../../auto-deploy-orchestrator");
            
            // Get only assets discovered in THIS job (recently created, no agent installed)
            // Filter by createdAt being within the last few minutes to ensure we only get NEW assets
            const discoveryStartTime = new Date(Date.now() - (attempts * 2000 + 60000)); // Buffer for discovery duration
            const allAssets = await storage.getCloudAssetsByConnection(connectionId);
            
            // Only include assets that:
            // 1. Don't have an agent installed
            // 2. Were discovered recently (within this discovery job's timeframe)
            // 3. Have no previous deployment attempts
            const newAssetsList = allAssets
              .filter(asset => {
                const isNewlyDiscovered = asset.createdAt && new Date(asset.createdAt) >= discoveryStartTime;
                const noAgentInstalled = !asset.agentInstalled;
                const noPreviousDeployment = !asset.agentDeploymentStatus || asset.agentDeploymentStatus === "pending";
                return noAgentInstalled && isNewlyDiscovered && noPreviousDeployment;
              })
              .slice(0, newAssetCount) // Limit to expected new asset count
              .map(asset => ({
                id: asset.id,
                assetType: asset.assetType,
                provider: asset.provider,
                region: asset.region || undefined,
                platform: asset.platform || undefined,
                tags: asset.tags as Record<string, string> | undefined,
                agentInstalled: asset.agentInstalled || false,
              }));
            
            if (newAssetsList.length > 0) {
              console.log(`[CloudDiscovery] Triggering auto-deploy for ${newAssetsList.length} newly discovered assets`);
              
              const autoDeployResult = await triggerAutoDeployForNewAssets(
                organizationId,
                tenantId,
                connectionId,
                newAssetsList
              );
              
              if (autoDeployResult.deploymentsTriggered > 0) {
                console.log(`[CloudDiscovery] Auto-deploy triggered ${autoDeployResult.deploymentsTriggered} deployments`);
              }
            } else {
              console.log(`[CloudDiscovery] No newly discovered assets eligible for auto-deploy`);
            }
          } catch (autoDeployError) {
            console.error(`[CloudDiscovery] Auto-deploy check failed:`, autoDeployError);
          }
        }

        return {
          success: true,
          data: {
            connectionId,
            provider,
            discoveryJobId,
            totalAssets: discoveryJob.totalAssets || 0,
            newAssets: discoveryJob.newAssets || 0,
            updatedAssets: discoveryJob.updatedAssets || 0,
            regionsScanned: discoveryJob.completedRegions,
          },
          duration: Date.now() - startTime,
        };
      }

      if (discoveryJob.status === "failed") {
        const errorMsg = Array.isArray(discoveryJob.errors) && discoveryJob.errors.length > 0
          ? (discoveryJob.errors[0] as any).error || "Discovery failed"
          : "Discovery failed";
        throw new Error(errorMsg);
      }
    }

    throw new Error("Discovery job timed out after 10 minutes");

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error(`[CloudDiscovery] Discovery failed for ${connectionId}:`, errorMessage);

    emitDiscoveryProgress(tenantId, organizationId, jobId, {
      type: "cloud_discovery_failed",
      error: errorMessage,
    });

    return {
      success: false,
      error: errorMessage,
      duration: Date.now() - startTime,
    };
  }
}
