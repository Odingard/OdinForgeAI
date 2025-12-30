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

    if (!azureCreds.tenantId || !azureCreds.clientId) {
      return { valid: false, error: "Azure Tenant ID and Client ID are required" };
    }

    if (!azureCreds.clientSecret && !azureCreds.useManagedIdentity) {
      return { valid: false, error: "Azure Client Secret or Managed Identity must be configured" };
    }

    try {
      const tokenUrl = `https://login.microsoftonline.com/${azureCreds.tenantId}/oauth2/v2.0/token`;
      
      const params = new URLSearchParams({
        grant_type: "client_credentials",
        client_id: azureCreds.clientId,
        client_secret: azureCreds.clientSecret || "",
        scope: "https://management.azure.com/.default",
      });

      const response = await fetch(tokenUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: params.toString(),
      });

      if (!response.ok) {
        const error = await response.json();
        return { valid: false, error: `Azure authentication failed: ${error.error_description || error.error}` };
      }

      const tokenData = await response.json();
      
      return {
        valid: true,
        accountInfo: {
          tenantId: azureCreds.tenantId,
          tokenType: tokenData.token_type,
          expiresIn: tokenData.expires_in,
        },
      };
    } catch (error: any) {
      return { valid: false, error: `Azure connection error: ${error.message}` };
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

    for (const region of regions) {
      progress.currentRegion = region;
      onProgress?.(progress);

      try {
        const vmAssets = await this.discoverVMs(azureCreds, region);
        allAssets.push(...vmAssets);

        const aksAssets = await this.discoverAKSClusters(azureCreds, region);
        allAssets.push(...aksAssets);

        const sqlAssets = await this.discoverSQLDatabases(azureCreds, region);
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

  private async discoverVMs(creds: NonNullable<CloudCredentials["azure"]>, region: string): Promise<CloudAssetInfo[]> {
    console.log(`[Azure] Discovering VMs in ${region}...`);
    return [];
  }

  private async discoverAKSClusters(creds: NonNullable<CloudCredentials["azure"]>, region: string): Promise<CloudAssetInfo[]> {
    console.log(`[Azure] Discovering AKS clusters in ${region}...`);
    return [];
  }

  private async discoverSQLDatabases(creds: NonNullable<CloudCredentials["azure"]>, region: string): Promise<CloudAssetInfo[]> {
    console.log(`[Azure] Discovering SQL databases in ${region}...`);
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
