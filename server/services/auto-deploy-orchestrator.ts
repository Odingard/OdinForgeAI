import { storage } from "../storage";
import { governanceEnforcement } from "./governance/governance-enforcement";
import { randomUUID } from "crypto";

function normalizePlatform(platform: string): string {
  const lower = platform.toLowerCase().trim();
  
  if (lower.includes("windows") || lower === "win32" || lower === "win64") {
    return "windows";
  }
  
  if (lower.includes("linux") || lower === "ubuntu" || lower === "debian" || lower === "centos" || lower === "rhel" || lower === "fedora") {
    return "linux";
  }
  
  if (lower.includes("darwin") || lower.includes("macos") || lower.includes("mac os") || lower === "osx") {
    return "macos";
  }
  
  if (lower.includes("container") || lower.includes("docker")) {
    return "container";
  }
  
  if (lower.includes("kubernetes") || lower.includes("k8s")) {
    return "kubernetes";
  }
  
  return lower;
}

interface AutoDeployConfig {
  enabled: boolean;
  providers: string[];
  assetTypes: string[];
  targetPlatforms: string[];
  deploymentOptions: {
    maxConcurrentDeployments: number;
    deploymentTimeoutSeconds: number;
    retryFailedDeployments: boolean;
    maxRetries: number;
    skipOfflineAssets: boolean;
  };
  filterRules?: {
    includeTags?: Record<string, string>;
    excludeTags?: Record<string, string>;
    includeRegions?: string[];
    excludeRegions?: string[];
    minInstanceSize?: string;
  } | null;
}

interface NewAsset {
  id: string;
  assetType: string;
  provider: string;
  region?: string;
  platform?: string;
  tags?: Record<string, string>;
  agentInstalled?: boolean;
}

interface AutoDeployResult {
  success: boolean;
  deploymentsTriggered: number;
  assetsProcessed: number;
  skippedAssets: number;
  errors: string[];
  deploymentJobIds: string[];
}

function emitAutoDeployProgress(
  organizationId: string,
  event: Record<string, any>
): void {
  const type = event.type;
  
  if (type === "auto_deploy_started") {
    console.log(`[AutoDeploy] ${organizationId}: Started auto-deployment for ${event.assetCount} assets`);
  } else if (type === "auto_deploy_progress") {
    console.log(`[AutoDeploy] ${organizationId}: ${event.processed}/${event.total} assets processed`);
  } else if (type === "auto_deploy_completed") {
    console.log(`[AutoDeploy] ${organizationId}: Completed - ${event.deploymentsTriggered} deployments, ${event.skipped} skipped`);
  } else if (type === "auto_deploy_blocked") {
    console.log(`[AutoDeploy] ${organizationId}: Blocked - ${event.reason}`);
  }
  
  try {
    const { wsService } = require("./websocket");
    if (!wsService) return;
    
    const channel = `auto-deploy:${organizationId}`;
    wsService.broadcastToChannel(channel, {
      type: "auto_deploy_progress",
      organizationId,
      ...event,
    });
  } catch {
  }
}

function matchesFilters(asset: NewAsset, filterRules: AutoDeployConfig["filterRules"]): boolean {
  if (!filterRules) return true;
  
  if (filterRules.includeRegions && filterRules.includeRegions.length > 0) {
    if (!asset.region || !filterRules.includeRegions.includes(asset.region)) {
      return false;
    }
  }
  
  if (filterRules.excludeRegions && filterRules.excludeRegions.length > 0) {
    if (asset.region && filterRules.excludeRegions.includes(asset.region)) {
      return false;
    }
  }
  
  if (filterRules.includeTags && Object.keys(filterRules.includeTags).length > 0) {
    if (!asset.tags) return false;
    for (const [key, value] of Object.entries(filterRules.includeTags)) {
      if (asset.tags[key] !== value) return false;
    }
  }
  
  if (filterRules.excludeTags && Object.keys(filterRules.excludeTags).length > 0) {
    if (asset.tags) {
      for (const [key, value] of Object.entries(filterRules.excludeTags)) {
        if (asset.tags[key] === value) return false;
      }
    }
  }
  
  return true;
}

export async function triggerAutoDeployForNewAssets(
  organizationId: string,
  tenantId: string,
  connectionId: string,
  newAssets: NewAsset[]
): Promise<AutoDeployResult> {
  const result: AutoDeployResult = {
    success: true,
    deploymentsTriggered: 0,
    assetsProcessed: 0,
    skippedAssets: 0,
    errors: [],
    deploymentJobIds: [],
  };
  
  if (newAssets.length === 0) {
    console.log(`[AutoDeploy] No new assets to deploy for org ${organizationId}`);
    return result;
  }
  
  const config = await storage.getAutoDeployConfig(organizationId);
  if (!config || !config.enabled) {
    console.log(`[AutoDeploy] Auto-deploy is disabled for org ${organizationId}`);
    result.skippedAssets = newAssets.length;
    return result;
  }
  
  const governanceCheck = await governanceEnforcement.canStartOperation(
    organizationId,
    "agent_deployment",
    "auto-deploy"
  );
  
  if (!governanceCheck.canStart) {
    console.log(`[AutoDeploy] Blocked by governance: ${governanceCheck.reason}`);
    
    emitAutoDeployProgress(organizationId, {
      type: "auto_deploy_blocked",
      reason: governanceCheck.reason,
    });
    
    result.success = false;
    result.errors.push(`Blocked by governance: ${governanceCheck.reason}`);
    result.skippedAssets = newAssets.length;
    return result;
  }
  
  const providers = config.providers || ["aws", "azure", "gcp"];
  const assetTypes = config.assetTypes || ["ec2", "vm", "gce"];
  const targetPlatforms = config.targetPlatforms || ["linux", "windows"];
  const deploymentOptions = config.deploymentOptions || {
    maxConcurrentDeployments: 10,
    deploymentTimeoutSeconds: 300,
    retryFailedDeployments: true,
    maxRetries: 3,
    skipOfflineAssets: true,
  };
  
  const eligibleAssets = newAssets.filter(asset => {
    if (!providers.includes(asset.provider)) {
      console.log(`[AutoDeploy] Skipping asset ${asset.id}: provider ${asset.provider} not in allowed list`);
      return false;
    }
    
    if (!assetTypes.includes(asset.assetType)) {
      console.log(`[AutoDeploy] Skipping asset ${asset.id}: type ${asset.assetType} not in allowed list`);
      return false;
    }
    
    if (asset.platform) {
      const normalizedAssetPlatform = normalizePlatform(asset.platform);
      const normalizedTargetPlatforms = targetPlatforms.map(p => normalizePlatform(p));
      if (!normalizedTargetPlatforms.includes(normalizedAssetPlatform)) {
        console.log(`[AutoDeploy] Skipping asset ${asset.id}: platform ${asset.platform} (normalized: ${normalizedAssetPlatform}) not in allowed list`);
        return false;
      }
    }
    
    if (asset.agentInstalled) {
      console.log(`[AutoDeploy] Skipping asset ${asset.id}: agent already installed`);
      return false;
    }
    
    if (!matchesFilters(asset, config.filterRules)) {
      console.log(`[AutoDeploy] Skipping asset ${asset.id}: doesn't match filter rules`);
      return false;
    }
    
    return true;
  });
  
  result.skippedAssets = newAssets.length - eligibleAssets.length;
  
  if (eligibleAssets.length === 0) {
    console.log(`[AutoDeploy] No eligible assets after filtering for org ${organizationId}`);
    return result;
  }
  
  emitAutoDeployProgress(organizationId, {
    type: "auto_deploy_started",
    assetCount: eligibleAssets.length,
  });
  
  const assetBatches: NewAsset[][] = [];
  for (let i = 0; i < eligibleAssets.length; i += deploymentOptions.maxConcurrentDeployments) {
    assetBatches.push(eligibleAssets.slice(i, i + deploymentOptions.maxConcurrentDeployments));
  }
  
  for (let batchIndex = 0; batchIndex < assetBatches.length; batchIndex++) {
    const batch = assetBatches[batchIndex];
    
    emitAutoDeployProgress(organizationId, {
      type: "auto_deploy_progress",
      processed: batchIndex * deploymentOptions.maxConcurrentDeployments,
      total: eligibleAssets.length,
      currentBatch: batchIndex + 1,
      totalBatches: assetBatches.length,
    });
    
    for (const asset of batch) {
      try {
        const deploymentJobId = randomUUID();
        
        await storage.updateCloudAsset(asset.id, {
          agentDeploymentStatus: "pending",
          agentDeploymentError: null,
        });
        
        const { cloudIntegrationService } = await import("./cloud/index");
        const deployResult = await cloudIntegrationService.deployAgentToAsset(
          asset.id,
          { initiatedBy: "auto-deploy" }
        );
        
        if (deployResult.error) {
          result.errors.push(`Failed to deploy to ${asset.id}: ${deployResult.error}`);
          await storage.updateCloudAsset(asset.id, {
            agentDeploymentStatus: "failed",
            agentDeploymentError: deployResult.error,
          });
        } else {
          result.deploymentsTriggered++;
          result.deploymentJobIds.push(deployResult.jobId || deploymentJobId);
        }
        
        result.assetsProcessed++;
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : "Unknown error";
        result.errors.push(`Error processing asset ${asset.id}: ${errorMsg}`);
        result.assetsProcessed++;
      }
    }
  }
  
  await storage.incrementAutoDeployStats(organizationId);
  
  emitAutoDeployProgress(organizationId, {
    type: "auto_deploy_completed",
    deploymentsTriggered: result.deploymentsTriggered,
    skipped: result.skippedAssets,
    errors: result.errors.length,
  });
  
  console.log(`[AutoDeploy] Completed for org ${organizationId}: ${result.deploymentsTriggered} deployments triggered, ${result.skippedAssets} skipped, ${result.errors.length} errors`);
  
  return result;
}

export async function getAutoDeployEligibleAssets(
  organizationId: string,
  assets: NewAsset[]
): Promise<{ eligible: NewAsset[]; ineligible: Array<{ asset: NewAsset; reason: string }> }> {
  const config = await storage.getAutoDeployConfig(organizationId);
  
  if (!config || !config.enabled) {
    return {
      eligible: [],
      ineligible: assets.map(asset => ({ asset, reason: "Auto-deploy is disabled" })),
    };
  }
  
  const providers = config.providers || ["aws", "azure", "gcp"];
  const assetTypes = config.assetTypes || ["ec2", "vm", "gce"];
  const targetPlatforms = config.targetPlatforms || ["linux", "windows"];
  
  const eligible: NewAsset[] = [];
  const ineligible: Array<{ asset: NewAsset; reason: string }> = [];
  
  for (const asset of assets) {
    if (!providers.includes(asset.provider)) {
      ineligible.push({ asset, reason: `Provider ${asset.provider} not allowed` });
      continue;
    }
    
    if (!assetTypes.includes(asset.assetType)) {
      ineligible.push({ asset, reason: `Asset type ${asset.assetType} not allowed` });
      continue;
    }
    
    if (asset.platform) {
      const normalizedAssetPlatform = normalizePlatform(asset.platform);
      const normalizedTargetPlatforms = targetPlatforms.map(p => normalizePlatform(p));
      if (!normalizedTargetPlatforms.includes(normalizedAssetPlatform)) {
        ineligible.push({ asset, reason: `Platform ${asset.platform} (normalized: ${normalizedAssetPlatform}) not allowed` });
        continue;
      }
    }
    
    if (asset.agentInstalled) {
      ineligible.push({ asset, reason: "Agent already installed" });
      continue;
    }
    
    if (!matchesFilters(asset, config.filterRules)) {
      ineligible.push({ asset, reason: "Does not match filter rules" });
      continue;
    }
    
    eligible.push(asset);
  }
  
  return { eligible, ineligible };
}
