import { storage } from "../../storage";
import { secretsService } from "../secrets";
import { awsAdapter } from "./aws-adapter";
import { azureAdapter } from "./azure-adapter";
import { gcpAdapter } from "./gcp-adapter";
import type { ProviderAdapter, CloudCredentials, CloudAssetInfo, DiscoveryProgress, CloudProvider, DeploymentResult } from "./types";
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

    // For cloud-based deployment (SSM, cloud-api), ensure we have cloud credentials
    let credentials: CloudCredentials | null = null;
    if (deploymentMethod !== "ssh") {
      credentials = await this.getConnectionCredentials(asset.connectionId);
      if (!credentials) {
        return { jobId: "", error: "Cloud credentials not found for connection" };
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

      // Use enterprise agent provisioning for SSH deployments
      const { agentManagementService } = await import("../agent-management");

      const provisionResult = await agentManagementService.provisionAgent({
        hostname: asset.assetName || asset.providerResourceId,
        platform: "linux",
        architecture: "x86_64",
        organizationId: asset.organizationId,
        environment: "production",
        tags: [
          "ssh-deployed",
          `asset:${asset.id}`,
          "auto-deployed",
        ],
      });

      const agentId = provisionResult.agentId;
      const apiKey = provisionResult.apiKey;
      const serverUrl = process.env.PUBLIC_ODINFORGE_URL || "http://localhost:5000";

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
          apiKey,
          agentId,
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
          agentId: result.agentId || agentId,
          agentDeploymentError: null,
        });

        await storage.updateEndpointAgent(agentId, {
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
    let adapter: ProviderAdapter;
    try {
      adapter = this.getAdapter(connection.provider);
    } catch (err: any) {
      console.error(`[CloudDeploy] Failed to get adapter for ${connection.provider}:`, err.message);
      await storage.updateAgentDeploymentJob(jobId, {
        status: "failed",
        completedAt: new Date(),
        errorMessage: `Unsupported provider: ${connection.provider}`,
      });
      await storage.updateCloudAsset(asset.id, {
        agentDeploymentStatus: "failed",
        agentDeploymentError: `Unsupported provider: ${connection.provider}`,
      });
      return;
    }

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

    // Use enterprise agent provisioning for secure, standardized agent creation
    const assetName = asset.assetName || asset.providerResourceId || "Cloud Agent";

    // Determine platform from asset type/metadata
    const normalizedProvider = connection.provider.toLowerCase();
    let platform: "linux" | "windows" | "darwin" = "linux";
    if (asset.rawMetadata?.platform === "windows" || asset.rawMetadata?.osType === "Windows") {
      platform = "windows";
    } else if (normalizedProvider === "azure" && asset.rawMetadata?.osType === "Linux") {
      platform = "linux";
    } else if (normalizedProvider === "gcp" || normalizedProvider === "aws") {
      platform = "linux";
    }

    // Provision agent using enterprise agent management service
    let agentId = "";
    let apiKey = "";
    let installCommand = "";

    try {
      const { agentManagementService } = await import("../agent-management");

      const provisionResult = await agentManagementService.provisionAgent({
        hostname: asset.assetName || asset.providerResourceId,
        platform,
        architecture: "x86_64",
        organizationId: asset.organizationId,
        environment: "production",
        tags: [
          `cloud:${connection.provider}`,
          `asset:${asset.id}`,
          `auto-deployed`,
          `region:${asset.region || "unknown"}`,
        ],
      });

      agentId = provisionResult.agentId;
      apiKey = provisionResult.apiKey;
      installCommand = provisionResult.installCommand;

      console.log(`[CloudDeploy] Provisioned enterprise agent ${agentId} for asset ${assetName}`);
    } catch (error: any) {
      console.error(`[CloudDeploy] Failed to provision agent:`, error.message);
      // Abort deployment if we can't provision the agent
      await storage.updateAgentDeploymentJob(jobId, {
        status: "failed",
        completedAt: new Date(),
        errorMessage: `Failed to provision agent: ${error.message}`,
      });
      await storage.updateCloudAsset(asset.id, {
        agentDeploymentStatus: "failed",
        agentDeploymentError: `Failed to provision agent: ${error.message}`,
      });
      return;
    }

    // Link the cloud asset to the provisioned agent
    await storage.updateCloudAsset(asset.id, {
      agentId,
    });

    // Use configured public URL or fallback to localhost
    let serverUrl = process.env.PUBLIC_ODINFORGE_URL || "http://localhost:5000";

    // Remove trailing slash if present
    serverUrl = serverUrl.replace(/\/$/, '');

    console.log(`[CloudDeploy] Using server URL: ${serverUrl}`);

    const deployOptions = {
      serverUrl,
      apiKey,
      agentId,
      organizationId: asset.organizationId,
      installCommand,
    };

    let result: DeploymentResult;

    try {
      // For AWS: SSM pre-check + SSH fallback chain
      if (connection.provider === "aws" && credentials?.aws) {
        const ssmCheck = await awsAdapter.checkSSMAvailability(
          credentials.aws,
          asset.providerResourceId,
          asset.region || "us-east-1"
        );
        console.log(`[CloudDeploy] SSM pre-check for ${asset.providerResourceId}: available=${ssmCheck.available}, status=${ssmCheck.pingStatus || "unknown"}`);

        if (ssmCheck.available) {
          // SSM is available, try it first
          result = await adapter.deployAgent(credentials, asset, deployOptions);
        } else {
          console.log(`[CloudDeploy] SSM unavailable: ${ssmCheck.error}. Skipping SSM, trying SSH fallback.`);
          result = { success: false, errorMessage: `SSM unavailable: ${ssmCheck.error}` };
        }

        // If SSM failed or was skipped, try SSH fallback
        if (!result.success) {
          console.log(`[CloudDeploy] SSM failed for ${asset.providerResourceId}. Attempting SSH fallback...`);
          try {
            // Pass connectionId so it finds connection-level SSH keys too
            const sshCred = await storage.getSshCredentialForAsset(asset.id, asset.organizationId, asset.connectionId);
            if (sshCred) {
              console.log(`[CloudDeploy] Found SSH credential ${sshCred.id} for asset, attempting SSH deployment`);
              const { sshDeploymentService } = await import("../ssh-deployment");
              const sshConfig = await sshDeploymentService.getDecryptedCredentials(sshCred.id);
              if (sshConfig) {
                // Resolve host from asset metadata if credential has placeholder or no host
                if (!sshConfig.host || sshConfig.host === "auto") {
                  const publicIp = Array.isArray(asset.publicIpAddresses) ? asset.publicIpAddresses[0] : null;
                  const privateIp = Array.isArray(asset.privateIpAddresses) ? asset.privateIpAddresses[0] : null;
                  sshConfig.host = publicIp || privateIp || "";
                  console.log(`[CloudDeploy] Resolved SSH host from asset metadata: ${sshConfig.host}`);
                }
                if (sshConfig.host) {
                  const sshResult = await sshDeploymentService.deployAgent(
                    sshConfig,
                    {
                      serverUrl,
                      apiKey,
                      agentId,
                      organizationId: asset.organizationId,
                      platform: platform,
                    }
                  );
                  if (sshResult.success) {
                    result = { success: true, agentId };
                    console.log(`[CloudDeploy] SSH fallback succeeded for ${asset.providerResourceId}`);
                  } else {
                    console.log(`[CloudDeploy] SSH fallback also failed: ${sshResult.errorMessage}`);
                    result = { success: false, errorMessage: `SSM failed, SSH fallback failed: ${sshResult.errorMessage}` };
                  }
                } else {
                  console.log(`[CloudDeploy] No host IP available for SSH fallback`);
                  result = { success: false, errorMessage: `SSM unavailable and no IP address for SSH fallback` };
                }
              } else {
                console.log(`[CloudDeploy] SSH credential decryption failed`);
              }
            } else {
              console.log(`[CloudDeploy] No SSH credentials found for asset ${asset.id} or connection ${asset.connectionId}, SSH fallback unavailable`);
            }
          } catch (sshErr: any) {
            console.log(`[CloudDeploy] SSH fallback error: ${sshErr.message}`);
          }
        }
      } else {
        // Non-AWS providers: deploy directly
        result = await adapter.deployAgent(credentials, asset, deployOptions);
      }
    } catch (deployError: any) {
      // Catch any unhandled crash during deployment execution
      console.error(`[CloudDeploy] Unhandled deployment error for asset ${asset.id}:`, deployError);
      result = { success: false, errorMessage: `Deployment crashed: ${deployError.message}` };
    }

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

      // Mark as failed immediately with the error message visible to the user
      await this.updateJobIfNotCancelled(jobId, {
        status: "failed",
        completedAt: new Date(),
        errorMessage: result.errorMessage,
        errorDetails: result.errorDetails,
      });

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
