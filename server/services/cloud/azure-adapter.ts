import { ClientSecretCredential, ManagedIdentityCredential, TokenCredential } from "@azure/identity";
import { SubscriptionClient } from "@azure/arm-subscriptions";
import { ComputeManagementClient } from "@azure/arm-compute";
import { ResourceManagementClient } from "@azure/arm-resources";
import { SqlManagementClient } from "@azure/arm-sql";
import { ProviderAdapter, CloudCredentials, CloudAssetInfo, DiscoveryProgress, DeploymentResult } from "./types";

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
    console.log(`[Azure VM Extension] Would deploy to ${asset.providerResourceId}`);

    return {
      success: false,
      errorMessage: "VM Extension deployment requires Azure SDK - install @azure/arm-compute for full functionality",
    };
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
    _credentials: CloudCredentials,
    _asset: CloudAssetInfo,
    _deploymentId: string
  ): Promise<{ status: string; error?: string }> {
    return { status: "unknown", error: "Status check not implemented" };
  }
}

export const azureAdapter = new AzureAdapter();
