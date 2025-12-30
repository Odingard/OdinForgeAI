import { ProviderAdapter, CloudCredentials, CloudAssetInfo, DiscoveryProgress, DeploymentResult } from "./types";

const GCP_REGIONS = [
  "us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
  "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6", "europe-north1",
  "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
  "asia-south1", "asia-southeast1", "asia-southeast2",
  "australia-southeast1", "australia-southeast2",
  "southamerica-east1", "northamerica-northeast1"
];

export class GCPAdapter implements ProviderAdapter {
  readonly provider = "gcp" as const;

  async validateCredentials(credentials: CloudCredentials): Promise<{ valid: boolean; error?: string; accountInfo?: Record<string, any> }> {
    const gcpCreds = credentials.gcp;
    if (!gcpCreds) {
      return { valid: false, error: "GCP credentials not provided" };
    }

    if (!gcpCreds.serviceAccountJson && !gcpCreds.useWorkloadIdentity) {
      return { valid: false, error: "GCP Service Account JSON or Workload Identity must be configured" };
    }

    try {
      if (gcpCreds.serviceAccountJson) {
        const serviceAccount = JSON.parse(gcpCreds.serviceAccountJson);
        
        if (!serviceAccount.client_email || !serviceAccount.private_key || !serviceAccount.project_id) {
          return { valid: false, error: "Invalid service account JSON format" };
        }

        return {
          valid: true,
          accountInfo: {
            projectId: serviceAccount.project_id,
            clientEmail: serviceAccount.client_email,
            type: serviceAccount.type,
          },
        };
      }

      return {
        valid: true,
        accountInfo: {
          workloadIdentity: true,
          projectId: gcpCreds.projectId,
        },
      };
    } catch (error: any) {
      return { valid: false, error: `GCP validation error: ${error.message}` };
    }
  }

  async listRegions(_credentials: CloudCredentials): Promise<string[]> {
    return GCP_REGIONS;
  }

  async discoverAssets(
    credentials: CloudCredentials,
    regions: string[],
    onProgress?: (progress: DiscoveryProgress) => void
  ): Promise<CloudAssetInfo[]> {
    const gcpCreds = credentials.gcp;
    if (!gcpCreds) {
      throw new Error("GCP credentials not provided");
    }

    const allAssets: CloudAssetInfo[] = [];
    const progress: DiscoveryProgress = {
      totalRegions: regions.length,
      completedRegions: 0,
      totalAssets: 0,
      errors: [],
    };

    for (const region of regions) {
      progress.currentRegion = region;
      onProgress?.(progress);

      try {
        const gceAssets = await this.discoverComputeInstances(gcpCreds, region);
        allAssets.push(...gceAssets);

        const gkeAssets = await this.discoverGKEClusters(gcpCreds, region);
        allAssets.push(...gkeAssets);

        const sqlAssets = await this.discoverCloudSQL(gcpCreds, region);
        allAssets.push(...sqlAssets);

        progress.totalAssets = allAssets.length;
      } catch (error: any) {
        progress.errors.push({ region, error: error.message });
      }

      progress.completedRegions++;
      onProgress?.(progress);
    }

    return allAssets;
  }

  private async discoverComputeInstances(creds: NonNullable<CloudCredentials["gcp"]>, region: string): Promise<CloudAssetInfo[]> {
    console.log(`[GCP] Discovering Compute Engine instances in ${region}...`);
    return [];
  }

  private async discoverGKEClusters(creds: NonNullable<CloudCredentials["gcp"]>, region: string): Promise<CloudAssetInfo[]> {
    console.log(`[GCP] Discovering GKE clusters in ${region}...`);
    return [];
  }

  private async discoverCloudSQL(creds: NonNullable<CloudCredentials["gcp"]>, region: string): Promise<CloudAssetInfo[]> {
    console.log(`[GCP] Discovering Cloud SQL instances in ${region}...`);
    return [];
  }

  async deployAgent(
    credentials: CloudCredentials,
    asset: CloudAssetInfo,
    agentConfig: {
      serverUrl: string;
      registrationToken: string;
      organizationId: string;
    }
  ): Promise<DeploymentResult> {
    const gcpCreds = credentials.gcp;
    if (!gcpCreds) {
      return { success: false, errorMessage: "GCP credentials not provided" };
    }

    if (!asset.agentDeployable) {
      return { success: false, errorMessage: "Asset does not support agent deployment" };
    }

    console.log(`[GCP] Deploying agent to ${asset.providerResourceId} via ${asset.agentDeploymentMethod || "os_config"}`);

    switch (asset.agentDeploymentMethod) {
      case "os_config":
        return this.deployViaOSConfig(gcpCreds, asset, agentConfig);
      case "startup_script":
        return this.deployViaStartupScript(gcpCreds, asset, agentConfig);
      default:
        return { success: false, errorMessage: `Deployment method ${asset.agentDeploymentMethod} not supported` };
    }
  }

  private async deployViaOSConfig(
    creds: NonNullable<CloudCredentials["gcp"]>,
    asset: CloudAssetInfo,
    config: { serverUrl: string; registrationToken: string; organizationId: string }
  ): Promise<DeploymentResult> {
    console.log(`[GCP OS Config] Would deploy to ${asset.providerResourceId}`);

    return {
      success: false,
      errorMessage: "OS Config deployment requires GCP SDK - install @google-cloud/os-config for full functionality",
    };
  }

  private async deployViaStartupScript(
    creds: NonNullable<CloudCredentials["gcp"]>,
    asset: CloudAssetInfo,
    config: { serverUrl: string; registrationToken: string; organizationId: string }
  ): Promise<DeploymentResult> {
    console.log(`[GCP Startup Script] Would deploy to ${asset.providerResourceId}`);

    return {
      success: false,
      errorMessage: "Startup script deployment not yet implemented",
    };
  }

  async checkAgentDeploymentStatus(
    _credentials: CloudCredentials,
    _asset: CloudAssetInfo,
    _deploymentId: string
  ): Promise<{ status: string; error?: string }> {
    return { status: "unknown", error: "Status check not implemented" };
  }
}

export const gcpAdapter = new GCPAdapter();
