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
  // Helper to check if deployment job was cancelled before updating asset
  private async isJobCancelled(jobId: string): Promise<boolean> {
    const job = await storage.getAgentDeploymentJob(jobId);
    return job?.status === "cancelled";
  }

  // Safe asset update that respects job cancellation
  private async updateAssetIfNotCancelled(
    jobId: string,
    assetId: string,
    updates: Record<string, any>
  ): Promise<boolean> {
    if (await this.isJobCancelled(jobId)) {
      console.log(`[CloudDeploy] Job ${jobId} was cancelled, skipping asset update for ${assetId}`);
      return false;
    }
    await storage.updateCloudAsset(assetId, updates);
    return true;
  }

  // Safe job update that respects cancellation - won't overwrite cancelled status
  private async updateJobIfNotCancelled(
    jobId: string,
    updates: Record<string, any>
  ): Promise<boolean> {
    if (await this.isJobCancelled(jobId)) {
      console.log(`[CloudDeploy] Job ${jobId} was cancelled, skipping job status update`);
      return false;
    }
    await storage.updateAgentDeploymentJob(jobId, updates);
    return true;
  }

  private getAdapter(provider: string): ProviderAdapter {
    // Normalize provider to lowercase for consistent adapter lookup
    const normalizedProvider = provider.toLowerCase();
    const adapter = adapters[normalizedProvider as CloudProvider];
    if (!adapter) {
      throw new Error(`Unsupported cloud provider: ${provider}`);
    }
    return adapter;
  }

  async validateCredentials(
    provider: string,
    credentials: CloudCredentials
  ): Promise<{ valid: boolean; error?: string; accountInfo?: Record<string, any> }> {
    const adapter = this.getAdapter(provider);
    return adapter.validateCredentials(credentials);
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

      // Run IAM security scan as part of discovery
      let iamFindings: any = null;
      try {
        console.log(`[CloudDiscovery] Running IAM security scan for ${connection.provider}...`);
        const iamResult = await adapter.scanIAM(credentials);
        
        if (iamResult.findings && iamResult.findings.length > 0) {
          const criticalCount = iamResult.findings.filter((f: any) => f.severity === "critical").length;
          const highCount = iamResult.findings.filter((f: any) => f.severity === "high").length;
          const mediumCount = iamResult.findings.filter((f: any) => f.severity === "medium").length;
          const lowCount = iamResult.findings.filter((f: any) => f.severity === "low").length;
          
          iamFindings = {
            findings: iamResult.findings,
            summary: {
              ...iamResult.summary,
              criticalFindings: criticalCount,
              highFindings: highCount,
              mediumFindings: mediumCount,
              lowFindings: lowCount,
            },
            scannedAt: new Date().toISOString(),
          };
          
          console.log(`[CloudDiscovery] IAM scan complete: ${criticalCount} critical, ${highCount} high, ${mediumCount} medium, ${lowCount} low findings`);
        } else {
          iamFindings = {
            findings: [],
            summary: {
              ...iamResult.summary,
              criticalFindings: 0,
              highFindings: 0,
              mediumFindings: 0,
              lowFindings: 0,
            },
            scannedAt: new Date().toISOString(),
          };
          console.log(`[CloudDiscovery] IAM scan complete: No security issues found`);
        }
      } catch (iamError: any) {
        console.error(`[CloudDiscovery] IAM scan failed (non-blocking):`, iamError.message);
        // IAM scan failure is non-blocking - asset discovery still succeeds
      }

      await storage.updateCloudConnection(connection.id, {
        status: "connected",
        lastSyncAt: new Date(),
        lastSyncStatus: "success",
        assetsDiscovered: assets.length,
        lastAssetCount: assets.length,
        ...(iamFindings && { iamFindings }),
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
    options?: { 
      initiatedBy?: string;
      deploymentMethod?: "cloud-api" | "ssh";
      sshCredentials?: {
        host: string;
        port?: number;
        username: string;
        password?: string;
        privateKey?: string;
        useSudo?: boolean;
      };
    }
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

    // Determine deployment method - prefer explicit option, then asset config, then default
    const deploymentMethod = options?.deploymentMethod || asset.agentDeploymentMethod || "cloud-api";
    
    // For SSH deployment, validate credentials
    if (deploymentMethod === "ssh") {
      if (!options?.sshCredentials) {
        return { jobId: "", error: "SSH credentials required for SSH deployment" };
      }
      if (!options.sshCredentials.host || !options.sshCredentials.username) {
        return { jobId: "", error: "SSH host and username are required" };
      }
      if (!options.sshCredentials.password && !options.sshCredentials.privateKey) {
        return { jobId: "", error: "Either SSH password or private key is required" };
      }
    }

    // For cloud-api deployment, ensure we have cloud credentials
    let credentials: CloudCredentials | null = null;
    if (deploymentMethod === "cloud-api") {
      credentials = await this.getConnectionCredentials(asset.connectionId);
      if (!credentials) {
        return { jobId: "", error: "Cloud credentials not found" };
      }
    }

    const job = await storage.createAgentDeploymentJob({
      cloudAssetId: assetId,
      connectionId: asset.connectionId,
      organizationId: asset.organizationId,
      deploymentMethod: deploymentMethod,
      status: "pending",
      scheduledAt: new Date(),
      initiatedBy: options?.initiatedBy,
    });

    // Run deployment based on method
    if (deploymentMethod === "ssh" && options?.sshCredentials) {
      this.runSSHDeployment(job.id, asset, options.sshCredentials).catch(console.error);
    } else {
      this.runDeployment(job.id, asset, connection, credentials!).catch(console.error);
    }

    return { jobId: job.id };
  }
  
  private async runSSHDeployment(
    jobId: string,
    asset: any,
    sshCredentials: {
      host: string;
      port?: number;
      username: string;
      password?: string;
      privateKey?: string;
      useSudo?: boolean;
    }
  ): Promise<void> {
    const { sshDeploymentService } = await import("../ssh-deployment");
    
    // Check if job was cancelled before starting
    const jobNotCancelled = await this.updateJobIfNotCancelled(jobId, {
      status: "deploying",
      startedAt: new Date(),
    });
    
    if (!jobNotCancelled) {
      return; // Job was cancelled, abort deployment
    }

    // Check if job was cancelled before updating asset
    const assetNotCancelled = await this.updateAssetIfNotCancelled(jobId, asset.id, {
      agentDeploymentStatus: "deploying",
      lastAgentDeploymentAttempt: new Date(),
    });
    
    if (!assetNotCancelled) {
      return; // Job was cancelled, abort deployment
    }

    try {
      const assetName = asset.assetName || asset.providerResourceId || "Cloud Agent";
      
      // Get server URL for agent configuration
      const serverUrl = process.env.PUBLIC_ODINFORGE_URL || `https://${process.env.REPLIT_DEV_DOMAIN || "localhost:5000"}`;
      
      // Create a registration token for this deployment
      const registrationToken = `reg-${randomUUID()}`;
      
      // Pre-register the agent with pending status
      const platform = "linux";
      const apiKey = `ak-${randomUUID()}`;
      
      const newAgent = await storage.createEndpointAgent({
        organizationId: asset.organizationId,
        agentName: `${assetName} (SSH)`,
        apiKey,
        hostname: asset.assetName || asset.providerResourceId,
        platform,
        architecture: "x86_64",
        ipAddresses: [sshCredentials.host],
        capabilities: ["telemetry", "vulnerability_scan"],
        status: "pending",
        tags: [
          "ssh-deployed",
          `asset:${asset.id}`,
          "auto-deployed",
        ],
        environment: "production",
      });

      // Deploy via SSH using the deployment service
      const result = await sshDeploymentService.deployAgent(
        {
          host: sshCredentials.host,
          port: sshCredentials.port || 22,
          username: sshCredentials.username,
          password: sshCredentials.password,
          privateKey: sshCredentials.privateKey,
          useSudo: sshCredentials.useSudo !== false,
        },
        {
          serverUrl,
          registrationToken,
          organizationId: asset.organizationId,
          platform: "linux",
        }
      );

      if (result.success) {
        // Only update job if not cancelled
        await this.updateJobIfNotCancelled(jobId, {
          status: "completed",
          completedAt: new Date(),
        });

        // Only update asset if job wasn't cancelled
        await this.updateAssetIfNotCancelled(jobId, asset.id, {
          agentDeploymentStatus: "success",
          agentInstalled: true,
          agentId: result.agentId || newAgent.id,
          agentDeploymentError: null,
        });

        await storage.updateEndpointAgent(newAgent.id, {
          status: "online",
        });
      } else {
        throw new Error(result.errorMessage || "SSH deployment failed");
      }
    } catch (error: any) {
      console.error(`[SSH Deploy] Error deploying to asset ${asset.id}:`, error);
      
      // Only update job if not cancelled
      await this.updateJobIfNotCancelled(jobId, {
        status: "failed",
        completedAt: new Date(),
        errorMessage: error.message,
      });

      // Only update asset if job wasn't cancelled
      await this.updateAssetIfNotCancelled(jobId, asset.id, {
        agentDeploymentStatus: "failed",
        agentDeploymentError: error.message,
      });
    }
  }

  private async runDeployment(
    jobId: string,
    asset: any,
    connection: any,
    credentials: CloudCredentials
  ): Promise<void> {
    const adapter = this.getAdapter(connection.provider);

    // Check if job was cancelled before starting
    const jobNotCancelled = await this.updateJobIfNotCancelled(jobId, {
      status: "deploying",
      startedAt: new Date(),
    });
    
    if (!jobNotCancelled) {
      return; // Job was cancelled, abort deployment
    }

    // Check if job was cancelled before updating asset
    const assetNotCancelled = await this.updateAssetIfNotCancelled(jobId, asset.id, {
      agentDeploymentStatus: "deploying",
      lastAgentDeploymentAttempt: new Date(),
    });
    
    if (!assetNotCancelled) {
      return; // Job was cancelled, abort deployment
    }

    // Pre-register the agent in the database immediately
    // This ensures the agent shows up in the Agents list right away
    const apiKey = `ak-${randomUUID()}`;
    const assetName = asset.assetName || asset.providerResourceId || "Cloud Agent";
    
    // Determine platform from asset type/metadata
    // Normalize provider to lowercase for consistent comparison
    const normalizedProvider = connection.provider.toLowerCase();
    let platform = "linux";
    if (asset.rawMetadata?.platform === "windows" || asset.rawMetadata?.osType === "Windows") {
      platform = "windows";
    } else if (normalizedProvider === "azure" && asset.rawMetadata?.osType === "Linux") {
      platform = "linux";
    } else if (normalizedProvider === "gcp" || normalizedProvider === "aws") {
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
      // Only update job if not cancelled
      await this.updateJobIfNotCancelled(jobId, {
        status: "success",
        completedAt: new Date(),
        resultAgentId: agentId,
      });

      // Only update asset if job wasn't cancelled
      await this.updateAssetIfNotCancelled(jobId, asset.id, {
        agentInstalled: true,
        agentId,
        agentDeploymentStatus: "success",
      });

      // Update agent status to offline (waiting for connection)
      await storage.updateEndpointAgent(agentId, {
        status: "offline",
      });
    } else {
      // Check if job was cancelled before processing failure
      if (await this.isJobCancelled(jobId)) {
        console.log(`[CloudDeploy] Job ${jobId} was cancelled, skipping failure update`);
        return;
      }
      
      const job = await storage.getAgentDeploymentJob(jobId);
      const attempts = (job?.attempts || 0) + 1;

      if (attempts < (job?.maxAttempts || 3)) {
        // Only update job if not cancelled
        await this.updateJobIfNotCancelled(jobId, {
          status: "pending",
          attempts,
          errorMessage: result.errorMessage,
          scheduledAt: new Date(Date.now() + 60000 * attempts),
        });

        // Only update asset if job wasn't cancelled
        await this.updateAssetIfNotCancelled(jobId, asset.id, {
          agentDeploymentStatus: "pending",
          agentDeploymentError: result.errorMessage,
        });
      } else {
        // Only update job if not cancelled
        await this.updateJobIfNotCancelled(jobId, {
          status: "failed",
          completedAt: new Date(),
          attempts,
          errorMessage: result.errorMessage,
          errorDetails: result.errorDetails,
        });

        // Only update asset if job wasn't cancelled
        await this.updateAssetIfNotCancelled(jobId, asset.id, {
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
