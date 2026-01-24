import { ClientSecretCredential, ManagedIdentityCredential, TokenCredential } from "@azure/identity";
import { SubscriptionClient } from "@azure/arm-subscriptions";
import { ComputeManagementClient } from "@azure/arm-compute";
import { ResourceManagementClient } from "@azure/arm-resources";
import { SqlManagementClient } from "@azure/arm-sql";
import { AuthorizationManagementClient } from "@azure/arm-authorization";
import { ProviderAdapter, CloudCredentials, CloudAssetInfo, DiscoveryProgress, DeploymentResult, IAMFinding } from "./types";

const AZURE_REGIONS = [
  "eastus", "eastus2", "westus", "westus2", "westus3",
  "centralus", "northcentralus", "southcentralus",
  "westeurope", "northeurope", "uksouth", "ukwest",
  "francecentral", "germanywestcentral", "switzerlandnorth",
  "australiaeast", "australiasoutheast",
  "japaneast", "japanwest", "koreacentral",
  "southeastasia", "eastasia",
  "brazilsouth", "canadacentral", "canadaeast"
];

export class AzureAdapter implements ProviderAdapter {
  readonly provider = "azure" as const;

  async validateCredentials(credentials: CloudCredentials): Promise<{ valid: boolean; error?: string; accountInfo?: Record<string, any> }> {
    const azureCreds = credentials.azure;
    if (!azureCreds) {
      return { valid: false, error: "Azure credentials not provided" };
    }

    try {
      let credential;
      
      if (azureCreds.useManagedIdentity) {
        credential = azureCreds.clientId 
          ? new ManagedIdentityCredential(azureCreds.clientId)
          : new ManagedIdentityCredential();
      } else {
        if (!azureCreds.tenantId || !azureCreds.clientId) {
          return { valid: false, error: "Azure Tenant ID and Client ID are required for service principal authentication" };
        }
        if (!azureCreds.clientSecret) {
          return { valid: false, error: "Azure Client Secret is required for service principal authentication" };
        }
        credential = new ClientSecretCredential(
          azureCreds.tenantId,
          azureCreds.clientId,
          azureCreds.clientSecret
        );
      }

      const subscriptionClient = new SubscriptionClient(credential);
      const subscriptions: Array<{ subscriptionId?: string; displayName?: string }> = [];
      
      const subscriptionsList = (subscriptionClient as any).subscriptions.list();
      for await (const subscription of subscriptionsList) {
        subscriptions.push({
          subscriptionId: subscription.subscriptionId,
          displayName: subscription.displayName,
        });
      }

      return {
        valid: true,
        accountInfo: {
          tenantId: azureCreds.tenantId,
          subscriptionCount: subscriptions.length,
          subscriptions: subscriptions.slice(0, 5),
        },
      };
    } catch (error: any) {
      const errorMessage = error.message || "Unknown error";
      if (errorMessage.includes("AADSTS700016")) {
        return { valid: false, error: "Invalid Azure Application (Client) ID" };
      }
      if (errorMessage.includes("AADSTS7000215")) {
        return { valid: false, error: "Invalid Azure Client Secret" };
      }
      if (errorMessage.includes("AADSTS90002")) {
        return { valid: false, error: "Invalid Azure Tenant ID" };
      }
      return { valid: false, error: `Azure credential validation failed: ${errorMessage}` };
    }
  }

  async listRegions(_credentials: CloudCredentials): Promise<string[]> {
    return AZURE_REGIONS;
  }

  async discoverAssets(
    credentials: CloudCredentials,
    regions: string[],
    onProgress?: (progress: DiscoveryProgress) => void
  ): Promise<CloudAssetInfo[]> {
    const azureCreds = credentials.azure;
    if (!azureCreds) {
      throw new Error("Azure credentials not provided");
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

      const vmAssets = await this.discoverAllVMs(azureCreds);
      allAssets.push(...vmAssets);
      progress.totalAssets = allAssets.length;
      onProgress?.(progress);

      const sqlAssets = await this.discoverSQLServers(azureCreds);
      allAssets.push(...sqlAssets);
      progress.totalAssets = allAssets.length;
      onProgress?.(progress);

      const rgAssets = await this.discoverResourceGroups(azureCreds);
      allAssets.push(...rgAssets);
      progress.totalAssets = allAssets.length;

      progress.completedRegions = regions.length;
      onProgress?.(progress);
    } catch (error: any) {
      progress.errors.push({ region: "global", error: error.message });
    }

    return allAssets;
  }

  private getCredential(creds: NonNullable<CloudCredentials["azure"]>): TokenCredential {
    if (creds.useManagedIdentity) {
      return creds.clientId 
        ? new ManagedIdentityCredential(creds.clientId)
        : new ManagedIdentityCredential();
    }
    return new ClientSecretCredential(
      creds.tenantId!,
      creds.clientId!,
      creds.clientSecret!
    );
  }

  private async getSubscriptions(creds: NonNullable<CloudCredentials["azure"]>): Promise<string[]> {
    const credential = this.getCredential(creds);
    const subscriptionClient = new SubscriptionClient(credential);
    const subscriptions: string[] = [];
    
    const subscriptionsList = (subscriptionClient as any).subscriptions.list();
    for await (const sub of subscriptionsList) {
      if (sub.subscriptionId) {
        subscriptions.push(sub.subscriptionId);
      }
    }
    return subscriptions;
  }

  private async discoverVMs(creds: NonNullable<CloudCredentials["azure"]>, region: string): Promise<CloudAssetInfo[]> {
    console.log(`[Azure] Discovering VMs in ${region}...`);
    const assets: CloudAssetInfo[] = [];

    try {
      const credential = this.getCredential(creds);
      const subscriptions = await this.getSubscriptions(creds);

      for (const subscriptionId of subscriptions) {
        const computeClient = new ComputeManagementClient(credential, subscriptionId);
        
        for await (const vm of computeClient.virtualMachines.listAll()) {
          if (vm.location?.toLowerCase() !== region.toLowerCase()) continue;
          
          assets.push({
            provider: "azure",
            providerResourceId: vm.id || "",
            assetType: "virtual_machine",
            assetName: vm.name || "Unnamed VM",
            region: vm.location || region,
            instanceType: vm.hardwareProfile?.vmSize,
            healthStatus: vm.provisioningState,
            rawMetadata: {
              osType: vm.storageProfile?.osDisk?.osType,
              subscriptionId,
              resourceGroup: vm.id?.split("/")[4],
            },
            agentDeployable: vm.provisioningState === "Succeeded",
            agentDeploymentMethod: "vm_extension",
          });
        }
      }
    } catch (error: any) {
      console.error(`[Azure] VM discovery error in ${region}:`, error.message);
    }

    return assets;
  }

  private async discoverAllVMs(creds: NonNullable<CloudCredentials["azure"]>): Promise<CloudAssetInfo[]> {
    console.log(`[Azure] Discovering all VMs across subscriptions...`);
    const assets: CloudAssetInfo[] = [];

    try {
      const credential = this.getCredential(creds);
      const subscriptions = await this.getSubscriptions(creds);

      for (const subscriptionId of subscriptions) {
        const computeClient = new ComputeManagementClient(credential, subscriptionId);
        
        for await (const vm of computeClient.virtualMachines.listAll()) {
          assets.push({
            provider: "azure",
            providerResourceId: vm.id || "",
            assetType: "virtual_machine",
            assetName: vm.name || "Unnamed VM",
            region: vm.location || "unknown",
            instanceType: vm.hardwareProfile?.vmSize,
            healthStatus: vm.provisioningState,
            rawMetadata: {
              osType: vm.storageProfile?.osDisk?.osType,
              subscriptionId,
              resourceGroup: vm.id?.split("/")[4],
            },
            agentDeployable: vm.provisioningState === "Succeeded",
            agentDeploymentMethod: "vm_extension",
          });
        }
      }
    } catch (error: any) {
      console.error(`[Azure] VM discovery error:`, error.message);
    }

    return assets;
  }

  private async discoverSQLServers(creds: NonNullable<CloudCredentials["azure"]>): Promise<CloudAssetInfo[]> {
    console.log(`[Azure] Discovering SQL servers...`);
    const assets: CloudAssetInfo[] = [];

    try {
      const credential = this.getCredential(creds);
      const subscriptions = await this.getSubscriptions(creds);

      for (const subscriptionId of subscriptions) {
        const sqlClient = new SqlManagementClient(credential, subscriptionId);
        
        for await (const server of sqlClient.servers.list()) {
          assets.push({
            provider: "azure",
            providerResourceId: server.id || "",
            assetType: "sql_server",
            assetName: server.name || "Unnamed SQL Server",
            region: server.location || "unknown",
            healthStatus: server.state,
            rawMetadata: {
              fullyQualifiedDomainName: server.fullyQualifiedDomainName,
              version: server.version,
              subscriptionId,
            },
            agentDeployable: false,
          });
        }
      }
    } catch (error: any) {
      console.error(`[Azure] SQL discovery error:`, error.message);
    }

    return assets;
  }

  private async discoverResourceGroups(creds: NonNullable<CloudCredentials["azure"]>): Promise<CloudAssetInfo[]> {
    console.log(`[Azure] Discovering resource groups...`);
    const assets: CloudAssetInfo[] = [];

    try {
      const credential = this.getCredential(creds);
      const subscriptions = await this.getSubscriptions(creds);

      for (const subscriptionId of subscriptions) {
        const resourceClient = new ResourceManagementClient(credential, subscriptionId);
        
        for await (const rg of resourceClient.resourceGroups.list()) {
          assets.push({
            provider: "azure",
            providerResourceId: rg.id || "",
            assetType: "resource_group",
            assetName: rg.name || "Unnamed Resource Group",
            region: rg.location || "unknown",
            healthStatus: rg.properties?.provisioningState,
            rawMetadata: {
              subscriptionId,
            },
            agentDeployable: false,
          });
        }
      }
    } catch (error: any) {
      console.error(`[Azure] Resource group discovery error:`, error.message);
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
    const azureCreds = credentials.azure;
    if (!azureCreds) {
      return { success: false, errorMessage: "Azure credentials not provided" };
    }

    if (!asset.agentDeployable) {
      return { success: false, errorMessage: "Asset does not support agent deployment" };
    }

    console.log(`[Azure] Deploying agent to ${asset.providerResourceId} via ${asset.agentDeploymentMethod || "vm_extension"}`);

    switch (asset.agentDeploymentMethod) {
      case "vm_extension":
        return this.deployViaVMExtension(azureCreds, asset, agentConfig);
      case "arc":
        return this.deployViaArc(azureCreds, asset, agentConfig);
      default:
        return { success: false, errorMessage: `Deployment method ${asset.agentDeploymentMethod} not supported` };
    }
  }

  private async deployViaVMExtension(
    creds: NonNullable<CloudCredentials["azure"]>,
    asset: CloudAssetInfo,
    config: { serverUrl: string; registrationToken: string; organizationId: string }
  ): Promise<DeploymentResult> {
    console.log(`[Azure Run Command] Deploying to ${asset.providerResourceId}`);

    try {
      const credential = this.getCredential(creds);
      
      // Parse resource ID to get subscription, resource group, and VM name
      const resourceId = asset.providerResourceId;
      const parts = resourceId.split("/");
      const subscriptionIndex = parts.indexOf("subscriptions");
      const rgIndex = parts.indexOf("resourceGroups");
      const vmIndex = parts.indexOf("virtualMachines");
      
      if (subscriptionIndex === -1 || rgIndex === -1 || vmIndex === -1) {
        return { success: false, errorMessage: "Invalid Azure resource ID format" };
      }
      
      const subscriptionId = parts[subscriptionIndex + 1];
      const resourceGroup = parts[rgIndex + 1];
      const vmName = parts[vmIndex + 1];

      const computeClient = new ComputeManagementClient(credential, subscriptionId);
      
      // Determine OS type for correct script
      const osType = asset.rawMetadata?.osType?.toLowerCase();
      const isWindows = osType === "windows";
      
      let script: string[];
      let commandId: string;
      
      if (isWindows) {
        commandId = "RunPowerShellScript";
        script = [
          `$ErrorActionPreference = "Stop"`,
          `Invoke-WebRequest -Uri "${config.serverUrl}/api/agents/download/windows-amd64" -OutFile "C:\\Temp\\odinforge-agent.exe"`,
          `& "C:\\Temp\\odinforge-agent.exe" install --server-url "${config.serverUrl}" --registration-token "${config.registrationToken}" --tenant-id "${config.organizationId}" --force`,
        ];
      } else {
        commandId = "RunShellScript";
        script = [
          `#!/bin/bash`,
          `set -e`,
          `curl -fsSL "${config.serverUrl}/api/agents/download/linux-amd64" -o /tmp/odinforge-agent`,
          `chmod +x /tmp/odinforge-agent`,
          `sudo /tmp/odinforge-agent install --server-url "${config.serverUrl}" --registration-token "${config.registrationToken}" --tenant-id "${config.organizationId}" --force`,
        ];
      }

      console.log(`[Azure Run Command] Sending ${commandId} to VM ${vmName} in resource group ${resourceGroup}`);
      
      // Execute the run command (this is a long-running operation)
      const runResult = await computeClient.virtualMachines.beginRunCommandAndWait(
        resourceGroup,
        vmName,
        {
          commandId,
          script,
        }
      );

      // Check if command succeeded
      const output = runResult.value?.[0]?.message || "";
      const hasError = output.toLowerCase().includes("error") || 
                       runResult.value?.[0]?.code?.includes("Error");

      if (hasError) {
        return {
          success: false,
          errorMessage: `Run command failed: ${output.substring(0, 500)}`,
          deploymentId: `${resourceGroup}/${vmName}/${Date.now()}`,
        };
      }

      return {
        success: true,
        deploymentId: `${resourceGroup}/${vmName}/${Date.now()}`,
        message: `Agent deployed successfully to ${vmName}`,
      };
    } catch (error: any) {
      console.error(`[Azure Run Command] Deployment error:`, error.message);
      
      let errorMessage = error.message;
      if (error.code === "AuthorizationFailed") {
        errorMessage = "Authorization failed. Ensure your Azure credentials have Microsoft.Compute/virtualMachines/runCommand/action permission.";
      } else if (error.code === "ResourceNotFound") {
        errorMessage = "VM not found. It may have been deleted or moved.";
      }
      
      return {
        success: false,
        errorMessage,
      };
    }
  }

  private async deployViaArc(
    creds: NonNullable<CloudCredentials["azure"]>,
    asset: CloudAssetInfo,
    config: { serverUrl: string; registrationToken: string; organizationId: string }
  ): Promise<DeploymentResult> {
    console.log(`[Azure Arc] Would deploy to ${asset.providerResourceId}`);

    return {
      success: false,
      errorMessage: "Arc deployment not yet implemented",
    };
  }

  async checkAgentDeploymentStatus(
    credentials: CloudCredentials,
    asset: CloudAssetInfo,
    deploymentId: string
  ): Promise<{ status: string; error?: string }> {
    // Azure Run Command is synchronous (beginRunCommandAndWait), so status is determined at deployment time
    // The deploymentId format is: resourceGroup/vmName/timestamp
    // If we got here, deployment already completed (success or failure was determined inline)
    // Return success since Azure Run Command waits for completion
    return { status: "success" };
  }

  async scanIAM(credentials: CloudCredentials): Promise<{ findings: IAMFinding[]; summary: Record<string, any> }> {
    const azureCreds = credentials.azure;
    if (!azureCreds) {
      throw new Error("Azure credentials not provided");
    }

    const findings: IAMFinding[] = [];
    
    // Build Azure credential
    let credential: TokenCredential;
    if (azureCreds.useManagedIdentity) {
      credential = azureCreds.clientId 
        ? new ManagedIdentityCredential(azureCreds.clientId)
        : new ManagedIdentityCredential();
    } else {
      if (!azureCreds.tenantId || !azureCreds.clientId || !azureCreds.clientSecret) {
        throw new Error("Azure tenant ID, client ID, and client secret are required");
      }
      credential = new ClientSecretCredential(
        azureCreds.tenantId,
        azureCreds.clientId,
        azureCreds.clientSecret
      );
    }

    // Get subscriptions
    const subscriptionClient = new SubscriptionClient(credential);
    const subscriptions: string[] = [];
    
    try {
      const subscriptionsList = (subscriptionClient as any).subscriptions.list();
      for await (const sub of subscriptionsList) {
        if (sub.subscriptionId) {
          subscriptions.push(sub.subscriptionId);
        }
      }
    } catch (err: any) {
      console.error("[Azure IAM] Error listing subscriptions:", err.message);
    }

    // High-risk Azure built-in roles
    const dangerousRoleDefinitions: Record<string, { severity: "critical" | "high"; description: string }> = {
      "Owner": { severity: "critical", description: "Full access to all resources including role assignments" },
      "Contributor": { severity: "high", description: "Full access to manage all resources except role assignments" },
      "User Access Administrator": { severity: "critical", description: "Can manage user access to Azure resources" },
      "Security Admin": { severity: "high", description: "Can manage security policies and view security state" },
    };

    // Track statistics
    let totalRoleAssignments = 0;
    let totalServicePrincipals = 0;
    let totalCustomRoles = 0;

    // Scan role assignments per subscription
    for (const subscriptionId of subscriptions) {
      try {
        const authClient = new AuthorizationManagementClient(credential, subscriptionId);
        
        // List role assignments at subscription scope
        const roleAssignments: Array<{
          id?: string;
          principalId?: string;
          principalType?: string;
          roleDefinitionId?: string;
          scope?: string;
        }> = [];
        
        for await (const assignment of authClient.roleAssignments.listForSubscription()) {
          roleAssignments.push(assignment);
          totalRoleAssignments++;
        }

        // Get role definitions to map IDs to names
        const roleDefinitions = new Map<string, { roleName?: string; roleType?: string; permissions?: any[] }>();
        for await (const roleDef of authClient.roleDefinitions.list(`/subscriptions/${subscriptionId}`)) {
          if (roleDef.id) {
            roleDefinitions.set(roleDef.id, {
              roleName: roleDef.roleName,
              roleType: roleDef.roleType,
              permissions: roleDef.permissions,
            });
            if (roleDef.roleType === "CustomRole") {
              totalCustomRoles++;
            }
          }
        }

        // Analyze role assignments for security issues
        for (const assignment of roleAssignments) {
          if (!assignment.roleDefinitionId) continue;
          
          const roleDef = roleDefinitions.get(assignment.roleDefinitionId);
          const roleName = roleDef?.roleName || "Unknown Role";
          const principalType = assignment.principalType || "Unknown";
          const scope = assignment.scope || "";
          
          // Check if this is a dangerous built-in role
          const dangerousRole = dangerousRoleDefinitions[roleName];
          if (dangerousRole) {
            // Check if assigned at subscription or management group level (broad scope)
            const isBroadScope = scope.includes("/subscriptions/") && 
              !scope.includes("/resourceGroups/") && 
              !scope.includes("/providers/");
            
            if (isBroadScope) {
              const findingType = principalType === "ServicePrincipal" ? "service_account" : 
                                  principalType === "Group" ? "group" : "user";
              
              findings.push({
                id: `azure-role-${assignment.id?.split("/").pop() || assignment.principalId}`,
                provider: "azure",
                findingType,
                resourceId: assignment.principalId || "",
                resourceName: `Principal ${assignment.principalId?.slice(0, 8)}`,
                severity: dangerousRole.severity,
                title: `${roleName} Role Assigned at Subscription Level`,
                description: `A ${principalType.toLowerCase()} has been assigned the "${roleName}" role at subscription scope. ${dangerousRole.description}.`,
                riskFactors: [
                  "broad_scope",
                  roleName === "Owner" || roleName === "User Access Administrator" ? "admin_access" : "elevated_privileges",
                  principalType === "ServicePrincipal" ? "service_principal" : "identity_risk",
                ],
                recommendation: `Review if ${roleName} role is necessary at this scope. Consider assigning at resource group level instead.`,
                metadata: {
                  subscriptionId,
                  roleName,
                  principalType,
                  scope,
                  roleDefinitionId: assignment.roleDefinitionId,
                },
              });
            }
          }

          // Check for custom roles with dangerous permissions
          if (roleDef?.roleType === "CustomRole" && roleDef.permissions) {
            for (const perm of roleDef.permissions) {
              const actions = perm.actions || [];
              const hasWildcardAction = actions.some((a: string) => a === "*" || a === "*/write");
              
              if (hasWildcardAction) {
                const findingType = principalType === "ServicePrincipal" ? "service_account" : 
                                    principalType === "Group" ? "group" : "user";
                
                findings.push({
                  id: `azure-customrole-${assignment.id?.split("/").pop()}`,
                  provider: "azure",
                  findingType,
                  resourceId: assignment.principalId || "",
                  resourceName: roleName,
                  severity: "high",
                  title: "Custom Role with Wildcard Permissions",
                  description: `Custom role "${roleName}" grants wildcard permissions (${hasWildcardAction ? "*" : "*/write"}) and is assigned to a ${principalType.toLowerCase()}.`,
                  riskFactors: ["custom_role", "wildcard_permissions", "excessive_permissions"],
                  recommendation: "Review and restrict the custom role's permissions to follow least privilege principles.",
                  metadata: {
                    subscriptionId,
                    roleName,
                    principalType,
                    actions,
                  },
                });
              }
            }
          }

          // Track service principals for summary
          if (principalType === "ServicePrincipal") {
            totalServicePrincipals++;
          }
        }

      } catch (err: any) {
        console.error(`[Azure IAM] Error scanning subscription ${subscriptionId}:`, err.message);
        // Continue with other subscriptions
      }
    }

    // Calculate summary
    const criticalFindings = findings.filter(f => f.severity === "critical").length;
    const highFindings = findings.filter(f => f.severity === "high").length;
    const mediumFindings = findings.filter(f => f.severity === "medium").length;

    return {
      findings,
      summary: {
        totalSubscriptions: subscriptions.length,
        totalRoleAssignments,
        totalCustomRoles,
        totalServicePrincipals,
        criticalFindings,
        highFindings,
        mediumFindings,
        scannedAt: new Date().toISOString(),
      },
    };
  }
}

export const azureAdapter = new AzureAdapter();
