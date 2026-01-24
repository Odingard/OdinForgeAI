import { ProjectsClient } from "@google-cloud/resource-manager";
import compute from "@google-cloud/compute";
import { ProviderAdapter, CloudCredentials, CloudAssetInfo, DiscoveryProgress, DeploymentResult, IAMFinding } from "./types";

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
    console.log(`[GCP] validateCredentials called`);
    const gcpCreds = credentials.gcp;
    if (!gcpCreds) {
      console.log(`[GCP] No GCP credentials in payload, keys received: ${Object.keys(credentials).join(', ')}`);
      return { valid: false, error: "GCP credentials not provided" };
    }
    console.log(`[GCP] GCP credentials found, keys: ${Object.keys(gcpCreds).join(', ')}`);

    // Accept both serviceAccountJson and serviceAccountKey field names
    const serviceAccountData = gcpCreds.serviceAccountJson || (gcpCreds as any).serviceAccountKey;
    console.log(`[GCP] serviceAccountData present: ${!!serviceAccountData}, useWorkloadIdentity: ${!!gcpCreds.useWorkloadIdentity}`);

    if (!serviceAccountData && !gcpCreds.useWorkloadIdentity) {
      console.log(`[GCP] No service account data or workload identity configured`);
      return { valid: false, error: "GCP Service Account JSON or Workload Identity must be configured" };
    }

    try {
      let serviceAccount: any = null;
      let projectId: string | undefined;

      if (serviceAccountData) {
        try {
          serviceAccount = JSON.parse(serviceAccountData);
          console.log(`[GCP] Parsed service account JSON successfully`);
        } catch (parseError) {
          console.log(`[GCP] Failed to parse service account JSON: ${parseError}`);
          return { valid: false, error: "Invalid JSON format in service account key" };
        }
        
        if (!serviceAccount.client_email || !serviceAccount.private_key || !serviceAccount.project_id) {
          console.log(`[GCP] Missing required fields - client_email: ${!!serviceAccount.client_email}, private_key: ${!!serviceAccount.private_key}, project_id: ${!!serviceAccount.project_id}`);
          return { valid: false, error: "Service account JSON missing required fields (client_email, private_key, project_id)" };
        }
        
        projectId = serviceAccount.project_id;
      } else {
        projectId = gcpCreds.projectId;
      }

      console.log(`[GCP] Attempting to validate credentials...`);
      const clientOptions: any = {};
      
      if (serviceAccount) {
        clientOptions.credentials = {
          client_email: serviceAccount.client_email,
          private_key: serviceAccount.private_key,
        };
        clientOptions.projectId = projectId;
      }

      console.log(`[GCP] Creating ProjectsClient...`);
      const projectsClient = new ProjectsClient(clientOptions);
      
      console.log(`[GCP] Calling GCP API to verify project access...`);
      const [project] = await projectsClient.getProject({
        name: `projects/${projectId}`,
      });

      console.log(`[GCP] Validation successful - project verified`);
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
      console.log(`[GCP] Validation error: ${errorMessage}`);
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
    // Accept both serviceAccountJson and serviceAccountKey field names
    const serviceAccountData = creds.serviceAccountJson || (creds as any).serviceAccountKey;
    if (serviceAccountData) {
      const serviceAccount = JSON.parse(serviceAccountData);
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
    // Accept both serviceAccountJson and serviceAccountKey field names
    const serviceAccountData = creds.serviceAccountJson || (creds as any).serviceAccountKey;
    if (serviceAccountData) {
      const serviceAccount = JSON.parse(serviceAccountData);
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

  async scanIAM(credentials: CloudCredentials): Promise<{ findings: IAMFinding[]; summary: Record<string, any> }> {
    const gcpCreds = credentials.gcp;
    if (!gcpCreds) {
      throw new Error("GCP credentials not provided");
    }

    const findings: IAMFinding[] = [];
    
    // Parse service account credentials
    const serviceAccountData = gcpCreds.serviceAccountJson || (gcpCreds as any).serviceAccountKey;
    if (!serviceAccountData && !gcpCreds.useWorkloadIdentity) {
      throw new Error("GCP Service Account JSON or Workload Identity required for IAM scanning");
    }

    let serviceAccount: any = null;
    let projectId: string | undefined;
    
    if (serviceAccountData) {
      try {
        serviceAccount = JSON.parse(serviceAccountData);
      } catch {
        throw new Error("Invalid JSON format in service account key");
      }
      projectId = serviceAccount.project_id;
    } else {
      projectId = gcpCreds.projectId;
    }

    if (!projectId) {
      throw new Error("GCP project ID is required");
    }

    const clientOptions: any = {};
    if (serviceAccount) {
      clientOptions.credentials = {
        client_email: serviceAccount.client_email,
        private_key: serviceAccount.private_key,
      };
      clientOptions.projectId = projectId;
    }

    // High-risk GCP IAM roles
    const dangerousRoles: Record<string, { severity: "critical" | "high"; description: string }> = {
      "roles/owner": { severity: "critical", description: "Full access to all resources in the project" },
      "roles/editor": { severity: "high", description: "Edit access to most resources in the project" },
      "roles/iam.securityAdmin": { severity: "critical", description: "Can manage IAM policies and service accounts" },
      "roles/iam.serviceAccountAdmin": { severity: "high", description: "Can manage service accounts" },
      "roles/iam.serviceAccountKeyAdmin": { severity: "high", description: "Can create and manage service account keys" },
      "roles/iam.serviceAccountTokenCreator": { severity: "high", description: "Can create OAuth2 tokens for service accounts" },
      "roles/resourcemanager.organizationAdmin": { severity: "critical", description: "Full control over organization resources" },
      "roles/resourcemanager.projectIamAdmin": { severity: "high", description: "Can manage project IAM policies" },
    };

    // Track statistics
    let totalBindings = 0;
    let totalServiceAccounts = 0;
    let totalUsers = 0;
    let totalGroups = 0;

    try {
      const projectsClient = new ProjectsClient(clientOptions);
      
      // Get project IAM policy
      const [iamPolicy] = await projectsClient.getIamPolicy({
        resource: `projects/${projectId}`,
        options: {
          requestedPolicyVersion: 3,
        },
      });

      const bindings = iamPolicy?.bindings || [];
      
      for (const binding of bindings) {
        const role = binding.role || "";
        const members = binding.members || [];
        
        totalBindings++;

        for (const member of members) {
          // Parse member type
          let memberType: "user" | "service_account" | "group" = "user";
          let memberName = member;
          
          if (member.startsWith("serviceAccount:")) {
            memberType = "service_account";
            memberName = member.replace("serviceAccount:", "");
            totalServiceAccounts++;
          } else if (member.startsWith("user:")) {
            memberType = "user";
            memberName = member.replace("user:", "");
            totalUsers++;
          } else if (member.startsWith("group:")) {
            memberType = "group";
            memberName = member.replace("group:", "");
            totalGroups++;
          } else if (member.startsWith("allUsers") || member.startsWith("allAuthenticatedUsers")) {
            // Public access - very dangerous (allUsers/allAuthenticatedUsers are special principals)
            findings.push({
              id: `gcp-public-${role.replace(/\//g, "-")}-${member}`,
              provider: "gcp",
              findingType: "user" as const,
              resourceId: projectId,
              resourceName: projectId,
              severity: "critical",
              title: "Public Access Granted at Project Level",
              description: `Role "${role}" is granted to "${member}" at the project level, allowing ${member === "allUsers" ? "unauthenticated" : "any authenticated"} users to access project resources.`,
              riskFactors: ["public_access", "project_level", "excessive_permissions"],
              recommendation: "Remove public access bindings unless explicitly required. Restrict access to specific principals.",
              metadata: {
                projectId,
                role,
                member,
                condition: binding.condition,
              },
            });
            continue;
          }

          // Check for dangerous roles
          const dangerousRole = dangerousRoles[role];
          if (dangerousRole) {
            const findingType = memberType === "service_account" ? "service_account" : 
                               memberType === "group" ? "group" : "user";
            
            findings.push({
              id: `gcp-role-${role.replace(/\//g, "-")}-${memberName.replace(/[@.]/g, "-")}`,
              provider: "gcp",
              findingType,
              resourceId: memberName,
              resourceName: memberName,
              severity: dangerousRole.severity,
              title: `${role.split("/").pop()} Role Assigned at Project Level`,
              description: `${memberType === "service_account" ? "Service account" : memberType === "group" ? "Group" : "User"} "${memberName}" has been granted the "${role}" role at project level. ${dangerousRole.description}.`,
              riskFactors: [
                "project_level",
                role.includes("owner") || role.includes("securityAdmin") || role.includes("organizationAdmin") ? "admin_access" : "elevated_privileges",
                memberType === "service_account" ? "service_account" : "identity_risk",
              ],
              recommendation: `Review if the ${role.split("/").pop()} role is necessary for ${memberName}. Consider using more specific roles with least privilege.`,
              metadata: {
                projectId,
                role,
                member,
                memberType,
                condition: binding.condition,
              },
            });
          }

          // Check for service accounts with key admin or token creator roles
          if (memberType === "service_account" && 
              (role.includes("serviceAccountKeyAdmin") || role.includes("serviceAccountTokenCreator"))) {
            findings.push({
              id: `gcp-sa-escalation-${memberName.replace(/[@.]/g, "-")}-${role.replace(/\//g, "-")}`,
              provider: "gcp",
              findingType: "service_account",
              resourceId: memberName,
              resourceName: memberName,
              severity: "high",
              title: "Service Account Privilege Escalation Risk",
              description: `Service account "${memberName}" has ${role} which allows it to create keys or tokens for other service accounts, potentially escalating privileges.`,
              riskFactors: ["privilege_escalation", "service_account", "key_management"],
              recommendation: "Review if this permission is necessary. Consider restricting which service accounts can be impersonated.",
              metadata: {
                projectId,
                role,
                serviceAccount: memberName,
              },
            });
          }
        }
      }

    } catch (err: any) {
      console.error(`[GCP IAM] Error scanning project ${projectId}:`, err.message);
      // Return partial results with error indication
      return {
        findings,
        summary: {
          projectId,
          error: err.message,
          scannedAt: new Date().toISOString(),
        },
      };
    }

    // Calculate summary
    const criticalFindings = findings.filter(f => f.severity === "critical").length;
    const highFindings = findings.filter(f => f.severity === "high").length;
    const mediumFindings = findings.filter(f => f.severity === "medium").length;

    return {
      findings,
      summary: {
        projectId,
        totalBindings,
        totalServiceAccounts,
        totalUsers,
        totalGroups,
        criticalFindings,
        highFindings,
        mediumFindings,
        scannedAt: new Date().toISOString(),
      },
    };
  }
}

export const gcpAdapter = new GCPAdapter();
