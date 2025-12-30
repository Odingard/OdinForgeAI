import { ProjectsClient } from "@google-cloud/resource-manager";
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
      let serviceAccount: any = null;
      let projectId: string | undefined;

      if (gcpCreds.serviceAccountJson) {
        try {
          serviceAccount = JSON.parse(gcpCreds.serviceAccountJson);
        } catch {
          return { valid: false, error: "Invalid JSON format in service account key" };
        }
        
        if (!serviceAccount.client_email || !serviceAccount.private_key || !serviceAccount.project_id) {
          return { valid: false, error: "Service account JSON missing required fields (client_email, private_key, project_id)" };
        }
        
        projectId = serviceAccount.project_id;
      } else {
        projectId = gcpCreds.projectId;
      }

      const clientOptions: any = {};
      
      if (serviceAccount) {
        clientOptions.credentials = {
          client_email: serviceAccount.client_email,
          private_key: serviceAccount.private_key,
        };
        clientOptions.projectId = projectId;
      }

      const projectsClient = new ProjectsClient(clientOptions);
      
      const [project] = await projectsClient.getProject({
        name: `projects/${projectId}`,
      });

      return {
        valid: true,
        accountInfo: {
          projectId: project.projectId,
          displayName: project.displayName,
          state: project.state,
          createTime: project.createTime,
        },
      };
    } catch (error: any) {
      const errorMessage = error.message || "Unknown error";
      if (errorMessage.includes("PERMISSION_DENIED")) {
        return { valid: false, error: "Service account lacks required permissions" };
      }
      if (errorMessage.includes("UNAUTHENTICATED")) {
        return { valid: false, error: "Invalid GCP service account credentials" };
      }
      if (errorMessage.includes("NOT_FOUND")) {
        return { valid: false, error: "GCP project not found" };
      }
      return { valid: false, error: `GCP credential validation failed: ${errorMessage}` };
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
