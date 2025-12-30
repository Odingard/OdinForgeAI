import { ProjectsClient } from "@google-cloud/resource-manager";
import compute from "@google-cloud/compute";
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

    try {
      progress.currentRegion = "global";
      onProgress?.(progress);

      const gceAssets = await this.discoverAllComputeInstances(gcpCreds);
      allAssets.push(...gceAssets);
      progress.totalAssets = allAssets.length;
      progress.completedRegions = regions.length;
      onProgress?.(progress);
    } catch (error: any) {
      progress.errors.push({ region: "global", error: error.message });
    }

    return allAssets;
  }

  private getClientOptions(creds: NonNullable<CloudCredentials["gcp"]>): any {
    if (creds.serviceAccountJson) {
      const serviceAccount = JSON.parse(creds.serviceAccountJson);
      return {
        credentials: {
          client_email: serviceAccount.client_email,
          private_key: serviceAccount.private_key,
        },
        projectId: serviceAccount.project_id,
      };
    }
    return { projectId: creds.projectId };
  }

  private getProjectId(creds: NonNullable<CloudCredentials["gcp"]>): string {
    if (creds.serviceAccountJson) {
      const serviceAccount = JSON.parse(creds.serviceAccountJson);
      return serviceAccount.project_id;
    }
    return creds.projectId || "";
  }

  private async discoverAllComputeInstances(creds: NonNullable<CloudCredentials["gcp"]>): Promise<CloudAssetInfo[]> {
    console.log(`[GCP] Discovering all Compute Engine instances...`);
    const assets: CloudAssetInfo[] = [];

    try {
      const clientOptions = this.getClientOptions(creds);
      const projectId = this.getProjectId(creds);
      const instancesClient = new compute.InstancesClient(clientOptions);

      const aggListRequest = instancesClient.aggregatedListAsync({
        project: projectId,
      });

      for await (const [zone, scopedList] of aggListRequest) {
        if (!scopedList.instances) continue;
        
        for (const instance of scopedList.instances) {
          const zoneName = zone.replace("zones/", "");
          const privateIps: string[] = [];
          const publicIps: string[] = [];
          
          for (const ni of instance.networkInterfaces || []) {
            if (ni.networkIP) privateIps.push(ni.networkIP);
            for (const ac of ni.accessConfigs || []) {
              if (ac.natIP) publicIps.push(ac.natIP);
            }
          }

          assets.push({
            provider: "gcp",
            providerResourceId: `projects/${projectId}/zones/${zoneName}/instances/${instance.name}`,
            assetType: "compute_instance",
            assetName: instance.name || "Unnamed Instance",
            region: zoneName.replace(/-[a-z]$/, ""),
            instanceType: instance.machineType?.split("/").pop() || undefined,
            powerState: instance.status || undefined,
            privateIpAddresses: privateIps,
            publicIpAddresses: publicIps,
            rawMetadata: {
              zone: zoneName,
              creationTimestamp: instance.creationTimestamp,
            },
            agentDeployable: instance.status === "RUNNING",
            agentDeploymentMethod: "os_config",
          });
        }
      }
    } catch (error: any) {
      console.error(`[GCP] Compute discovery error:`, error.message);
    }

    return assets;
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
    // Use metadata-based startup script approach
    return this.deployViaStartupScript(creds, asset, config);
  }

  private async deployViaStartupScript(
    creds: NonNullable<CloudCredentials["gcp"]>,
    asset: CloudAssetInfo,
    config: { serverUrl: string; registrationToken: string; organizationId: string }
  ): Promise<DeploymentResult> {
    console.log(`[GCP Startup Script] Deploying to ${asset.providerResourceId}`);

    try {
      const clientOptions = this.getClientOptions(creds);
      
      // Parse resource ID: projects/{project}/zones/{zone}/instances/{instance}
      const parts = asset.providerResourceId.split("/");
      const projectIndex = parts.indexOf("projects");
      const zoneIndex = parts.indexOf("zones");
      const instanceIndex = parts.indexOf("instances");
      
      if (projectIndex === -1 || zoneIndex === -1 || instanceIndex === -1) {
        return { success: false, errorMessage: "Invalid GCP resource ID format" };
      }
      
      const project = parts[projectIndex + 1];
      const zone = parts[zoneIndex + 1];
      const instanceName = parts[instanceIndex + 1];

      const instancesClient = new compute.InstancesClient(clientOptions);
      
      // Create a startup script that installs the agent
      // This uses a one-time marker file to prevent re-running on every boot
      const startupScript = `#!/bin/bash
# OdinForge Agent Installation Script
MARKER_FILE="/var/run/odinforge-agent-installed"
if [ -f "$MARKER_FILE" ]; then
  echo "OdinForge agent already installed, skipping..."
  exit 0
fi

set -e
echo "Installing OdinForge agent..."
curl -fsSL "${config.serverUrl}/api/agents/download/linux-amd64" -o /tmp/odinforge-agent
chmod +x /tmp/odinforge-agent
/tmp/odinforge-agent install --server-url "${config.serverUrl}" --registration-token "${config.registrationToken}" --tenant-id "${config.organizationId}" --force

# Create marker file to prevent re-running
touch "$MARKER_FILE"
echo "OdinForge agent installed successfully"
`;

      // Get current instance to retrieve existing metadata
      const [instance] = await instancesClient.get({
        project,
        zone,
        instance: instanceName,
      });

      // Build new metadata with our startup script
      const existingItems = instance.metadata?.items || [];
      const newItems = existingItems.filter(item => item.key !== "startup-script");
      newItems.push({
        key: "startup-script",
        value: startupScript,
      });

      console.log(`[GCP] Setting startup script metadata on ${instanceName}`);
      
      // Set the metadata
      const [operation] = await instancesClient.setMetadata({
        project,
        zone,
        instance: instanceName,
        metadataResource: {
          fingerprint: instance.metadata?.fingerprint,
          items: newItems,
        },
      });

      // Wait for the operation to complete
      const operationsClient = new compute.ZoneOperationsClient(clientOptions);
      
      // Poll for operation completion (up to 2 minutes)
      let completed = false;
      const startTime = Date.now();
      while (!completed && Date.now() - startTime < 120000) {
        const [opStatus] = await operationsClient.get({
          project,
          zone,
          operation: operation.name!,
        });
        
        if (opStatus.status === "DONE") {
          completed = true;
          if (opStatus.error) {
            return {
              success: false,
              errorMessage: `Metadata update failed: ${JSON.stringify(opStatus.error)}`,
              deploymentId: operation.name,
            };
          }
        } else {
          await new Promise(resolve => setTimeout(resolve, 2000));
        }
      }

      if (!completed) {
        return {
          success: false,
          errorMessage: "Metadata update operation timed out",
          deploymentId: operation.name,
        };
      }

      // Startup script is now set - agent will install on next boot
      // We don't auto-reset to avoid disrupting running workloads
      console.log(`[GCP] Startup script configured on ${instanceName} - agent will install on next boot`);

      return {
        success: true,
        deploymentId: operation.name,
        message: `Startup script configured on ${instanceName}. The agent will install automatically when the instance next reboots. For immediate installation, manually restart the instance from the GCP Console.`,
      };
    } catch (error: any) {
      console.error(`[GCP Startup Script] Deployment error:`, error.message);
      
      let errorMessage = error.message;
      if (error.code === 403) {
        errorMessage = "Permission denied. Ensure the service account has compute.instances.setMetadata permission.";
      } else if (error.code === 404) {
        errorMessage = "Instance not found. It may have been deleted or moved.";
      }
      
      return {
        success: false,
        errorMessage,
      };
    }
  }

  async checkAgentDeploymentStatus(
    credentials: CloudCredentials,
    asset: CloudAssetInfo,
    deploymentId: string
  ): Promise<{ status: string; error?: string }> {
    // GCP uses startup script approach - the script is configured but won't run
    // until the instance is rebooted. We return a pending status to indicate
    // the agent will install on next boot.
    return { 
      status: "pending_reboot",
      error: "Agent will install when instance is rebooted. Restart the instance from GCP Console for immediate installation."
    };
  }
}

export const gcpAdapter = new GCPAdapter();
