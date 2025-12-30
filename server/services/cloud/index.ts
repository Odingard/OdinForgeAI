import { storage } from "../../storage";
import { secretsService } from "../secrets";
import { awsAdapter } from "./aws-adapter";
import { azureAdapter } from "./azure-adapter";
import { gcpAdapter } from "./gcp-adapter";
import type { ProviderAdapter, CloudCredentials, CloudAssetInfo, DiscoveryProgress, CloudProvider } from "./types";
import { randomUUID } from "crypto";

const adapters: Record<CloudProvider, ProviderAdapter> = {
  aws: awsAdapter,
  azure: azureAdapter,
  gcp: gcpAdapter,
  oci: awsAdapter,
  alibaba: awsAdapter,
  other: awsAdapter,
};

export class CloudIntegrationService {
  private getAdapter(provider: string): ProviderAdapter {
    const adapter = adapters[provider as CloudProvider];
    if (!adapter) {
      throw new Error(`Unsupported cloud provider: ${provider}`);
    }
    return adapter;
  }

  async validateAndStoreCredentials(
    connectionId: string,
    provider: string,
    credentials: CloudCredentials
  ): Promise<{ success: boolean; error?: string; accountInfo?: Record<string, any> }> {
    const adapter = this.getAdapter(provider);

    const validation = await adapter.validateCredentials(credentials);
    if (!validation.valid) {
      return { success: false, error: validation.error };
    }

    const { encryptedData, keyId } = secretsService.encryptCredentials(credentials);

    try {
      await storage.createCloudCredential({
        connectionId,
        encryptedData,
        encryptionKeyId: keyId,
        credentialType: this.getCredentialType(provider, credentials),
      });

      return { success: true, accountInfo: validation.accountInfo };
    } catch (error: any) {
      return { success: false, error: `Failed to store credentials: ${error.message}` };
    }
  }

  private getCredentialType(provider: string, credentials: CloudCredentials): string {
    switch (provider) {
      case "aws":
        if (credentials.aws?.roleArn) return "aws_role";
        return "aws_access_key";
      case "azure":
        if (credentials.azure?.useManagedIdentity) return "azure_managed_identity";
        if (credentials.azure?.certificatePath) return "azure_certificate";
        return "azure_sp";
      case "gcp":
        if (credentials.gcp?.useWorkloadIdentity) return "gcp_workload_identity";
        return "gcp_service_account";
      default:
        return "unknown";
    }
  }

  async getConnectionCredentials(connectionId: string): Promise<CloudCredentials | null> {
    const credential = await storage.getCloudCredentialByConnectionId(connectionId);
    if (!credential) return null;

    return secretsService.decryptCredentials(
      credential.encryptedData,
      credential.encryptionKeyId
    );
  }

  async startDiscoveryJob(
    connectionId: string,
    organizationId: string,
    options?: { regions?: string[]; triggeredBy?: string }
  ): Promise<{ jobId: string; error?: string }> {
    const connection = await storage.getCloudConnection(connectionId);
    if (!connection) {
      return { jobId: "", error: "Connection not found" };
    }

    const credentials = await this.getConnectionCredentials(connectionId);
    if (!credentials) {
      return { jobId: "", error: "Credentials not found for connection" };
    }

    const adapter = this.getAdapter(connection.provider);

    const regions = options?.regions || await adapter.listRegions(credentials);

    const job = await storage.createCloudDiscoveryJob({
      connectionId,
      organizationId,
      status: "running",
      jobType: "full",
      totalRegions: regions.length,
      completedRegions: 0,
      triggeredBy: options?.triggeredBy,
      triggerType: options?.triggeredBy ? "manual" : "scheduled",
      startedAt: new Date(),
    });

    this.runDiscovery(job.id, connection, credentials, adapter, regions).catch(console.error);

    return { jobId: job.id };
  }

  private async runDiscovery(
    jobId: string,
    connection: { id: string; organizationId: string; provider: string },
    credentials: CloudCredentials,
    adapter: ProviderAdapter,
    regions: string[]
  ): Promise<void> {
    let newAssets = 0;
    let updatedAssets = 0;

    try {
      const assets = await adapter.discoverAssets(
        credentials,
        regions,
        async (progress) => {
          await storage.updateCloudDiscoveryJob(jobId, {
            completedRegions: progress.completedRegions,
            totalAssets: progress.totalAssets,
            errors: progress.errors as any,
          });
        }
      );

      for (const assetInfo of assets) {
        const existing = await storage.getCloudAssetByProviderId(
          connection.id,
          assetInfo.providerResourceId
        );

        if (existing) {
          await storage.updateCloudAsset(existing.id, {
            ...assetInfo,
            lastSeenAt: new Date(),
            discoveryJobId: jobId,
          });
          updatedAssets++;
        } else {
          await storage.createCloudAsset({
            connectionId: connection.id,
            organizationId: connection.organizationId,
            ...assetInfo,
            discoveryJobId: jobId,
            lastSeenAt: new Date(),
          });
          newAssets++;
        }
      }

      await storage.updateCloudDiscoveryJob(jobId, {
        status: "completed",
        completedAt: new Date(),
        totalAssets: assets.length,
        newAssets,
        updatedAssets,
      });

      await storage.updateCloudConnection(connection.id, {
        status: "connected",
        lastSyncAt: new Date(),
        lastSyncStatus: "success",
        assetsDiscovered: assets.length,
        lastAssetCount: assets.length,
      });
    } catch (error: any) {
      await storage.updateCloudDiscoveryJob(jobId, {
        status: "failed",
        completedAt: new Date(),
        errors: [{ error: error.message, timestamp: new Date().toISOString() }] as any,
      });

      await storage.updateCloudConnection(connection.id, {
        status: "error",
        lastSyncAt: new Date(),
        lastSyncStatus: "failed",
        lastError: error.message,
      });
    }
  }

  async deployAgentToAsset(
    assetId: string,
    options?: { initiatedBy?: string }
  ): Promise<{ jobId: string; error?: string }> {
    const asset = await storage.getCloudAsset(assetId);
    if (!asset) {
      return { jobId: "", error: "Asset not found" };
    }

    if (!asset.agentDeployable) {
      return { jobId: "", error: "Asset does not support agent deployment" };
    }

    const connection = await storage.getCloudConnection(asset.connectionId);
    if (!connection) {
      return { jobId: "", error: "Connection not found" };
    }

    const credentials = await this.getConnectionCredentials(asset.connectionId);
    if (!credentials) {
      return { jobId: "", error: "Credentials not found" };
    }

    const job = await storage.createAgentDeploymentJob({
      cloudAssetId: assetId,
      connectionId: asset.connectionId,
      organizationId: asset.organizationId,
      deploymentMethod: asset.agentDeploymentMethod || "manual",
      status: "pending",
      scheduledAt: new Date(),
      initiatedBy: options?.initiatedBy,
    });

    this.runDeployment(job.id, asset, connection, credentials).catch(console.error);

    return { jobId: job.id };
  }

  private async runDeployment(
    jobId: string,
    asset: any,
    connection: any,
    credentials: CloudCredentials
  ): Promise<void> {
    const adapter = this.getAdapter(connection.provider);

    await storage.updateAgentDeploymentJob(jobId, {
      status: "deploying",
      startedAt: new Date(),
    });

    await storage.updateCloudAsset(asset.id, {
      agentDeploymentStatus: "deploying",
      lastAgentDeploymentAttempt: new Date(),
    });

    // Pre-register the agent in the database immediately
    // This ensures the agent shows up in the Agents list right away
    const apiKey = `ak-${randomUUID()}`;
    const assetName = asset.assetName || asset.providerResourceId || "Cloud Agent";
    
    // Determine platform from asset type/metadata
    let platform = "linux";
    if (asset.rawMetadata?.platform === "windows" || asset.rawMetadata?.osType === "Windows") {
      platform = "windows";
    } else if (connection.provider === "azure" && asset.rawMetadata?.osType === "Linux") {
      platform = "linux";
    } else if (connection.provider === "gcp" || connection.provider === "aws") {
      platform = "linux";
    }

    // Create the agent record with pending status
    let agentId = "";
    try {
      const newAgent = await storage.createEndpointAgent({
        organizationId: asset.organizationId,
        agentName: `${assetName} (${connection.provider.toUpperCase()})`,
        apiKey,
        hostname: asset.assetName || asset.providerResourceId,
        platform,
        architecture: "x86_64",
        ipAddresses: asset.privateIpAddresses || asset.publicIpAddresses || [],
        capabilities: ["telemetry", "vulnerability_scan"],
        status: "pending",
        tags: [
          `cloud:${connection.provider}`,
          `asset:${asset.id}`,
          `auto-deployed`,
          `region:${asset.region || "unknown"}`,
        ],
        environment: "production",
      });
      agentId = newAgent.id;

      console.log(`[CloudDeploy] Pre-registered agent ${agentId} for asset ${assetName}`);
    } catch (error: any) {
      console.error(`[CloudDeploy] Failed to pre-register agent:`, error.message);
      // Abort deployment if we can't create the agent record
      await storage.updateAgentDeploymentJob(jobId, {
        status: "failed",
        completedAt: new Date(),
        errorMessage: `Failed to pre-register agent: ${error.message}`,
      });
      await storage.updateCloudAsset(asset.id, {
        agentDeploymentStatus: "failed",
        agentDeploymentError: `Failed to pre-register agent: ${error.message}`,
      });
      return;
    }

    // Link the cloud asset to the pre-registered agent immediately (if created)
    if (agentId) {
      await storage.updateCloudAsset(asset.id, {
        agentId,
      });
    }

    const registrationToken = process.env.AGENT_REGISTRATION_TOKEN || "auto-deploy-token";
    // Use production domain if available (REPLIT_DOMAINS), otherwise dev domain, otherwise localhost
    let serverUrl = "http://localhost:5000";
    if (process.env.REPLIT_DOMAINS) {
      // REPLIT_DOMAINS is comma-separated, use the first one (primary domain)
      const primaryDomain = process.env.REPLIT_DOMAINS.split(",")[0].trim();
      serverUrl = `https://${primaryDomain}`;
    } else if (process.env.REPLIT_DEV_DOMAIN) {
      serverUrl = `https://${process.env.REPLIT_DEV_DOMAIN}`;
    }
    console.log(`[CloudDeploy] Using server URL: ${serverUrl}`);

    const result = await adapter.deployAgent(
      credentials,
      asset,
      {
        serverUrl,
        registrationToken,
        organizationId: asset.organizationId,
      }
    );

    if (result.success) {
      await storage.updateAgentDeploymentJob(jobId, {
        status: "success",
        completedAt: new Date(),
        resultAgentId: agentId,
      });

      await storage.updateCloudAsset(asset.id, {
        agentInstalled: true,
        agentId,
        agentDeploymentStatus: "success",
      });

      // Update agent status to offline (waiting for connection)
      await storage.updateEndpointAgent(agentId, {
        status: "offline",
      });
    } else {
      const job = await storage.getAgentDeploymentJob(jobId);
      const attempts = (job?.attempts || 0) + 1;

      if (attempts < (job?.maxAttempts || 3)) {
        await storage.updateAgentDeploymentJob(jobId, {
          status: "pending",
          attempts,
          errorMessage: result.errorMessage,
          scheduledAt: new Date(Date.now() + 60000 * attempts),
        });

        await storage.updateCloudAsset(asset.id, {
          agentDeploymentStatus: "pending",
          agentDeploymentError: result.errorMessage,
        });
      } else {
        await storage.updateAgentDeploymentJob(jobId, {
          status: "failed",
          completedAt: new Date(),
          attempts,
          errorMessage: result.errorMessage,
          errorDetails: result.errorDetails,
        });

        await storage.updateCloudAsset(asset.id, {
          agentDeploymentStatus: "failed",
          agentDeploymentError: result.errorMessage,
        });

        // Update agent status to show deployment failed
        await storage.updateEndpointAgent(agentId, {
          status: "offline",
          tags: [
            `cloud:${connection.provider}`,
            `asset:${asset.id}`,
            `auto-deployed`,
            `deployment-failed`,
          ],
        });
      }
    }
  }

  async deployAgentsToAllAssets(
    connectionId: string,
    options?: { assetTypes?: string[]; initiatedBy?: string }
  ): Promise<{ jobIds: string[]; errors: string[] }> {
    const assets = await storage.getCloudAssetsByConnection(connectionId);
    
    // Filter for assets that:
    // 1. Are deployable
    // 2. Don't already have an agent installed
    // 3. Either have no deployment status, or are stuck in pending/failed without an agent linked
    // 4. Match optional asset type filter
    const deployableAssets = assets.filter(a => 
      a.agentDeployable && 
      !a.agentInstalled &&
      (!options?.assetTypes?.length || options.assetTypes.includes(a.assetType)) &&
      // Allow deployment if: no status, status is null, stuck in pending/failed with no agent
      (!a.agentDeploymentStatus || 
       a.agentDeploymentStatus === "failed" || 
       (a.agentDeploymentStatus === "pending" && !a.agentId))
    );

    const jobIds: string[] = [];
    const errors: string[] = [];

    for (const asset of deployableAssets) {
      const result = await this.deployAgentToAsset(asset.id, options);
      if (result.jobId) {
        jobIds.push(result.jobId);
      } else if (result.error) {
        errors.push(`${asset.assetName}: ${result.error}`);
      }
    }

    return { jobIds, errors };
  }
}

export const cloudIntegrationService = new CloudIntegrationService();
