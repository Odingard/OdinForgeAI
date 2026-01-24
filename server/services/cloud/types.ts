export type CloudProvider = "aws" | "azure" | "gcp" | "oci" | "alibaba" | "other";

export interface CloudCredentials {
  aws?: {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
    roleArn?: string;
    externalId?: string;
  };
  azure?: {
    tenantId: string;
    clientId: string;
    clientSecret?: string;
    certificatePath?: string;
    useManagedIdentity?: boolean;
  };
  gcp?: {
    serviceAccountJson?: string;
    projectId?: string;
    useWorkloadIdentity?: boolean;
  };
}

export interface CloudAssetInfo {
  providerResourceId: string;
  provider: CloudProvider;
  assetType: string;
  assetName: string;
  region?: string;
  availabilityZone?: string;
  instanceType?: string;
  cpuCount?: number;
  memoryMb?: number;
  publicIpAddresses?: string[];
  privateIpAddresses?: string[];
  powerState?: string;
  healthStatus?: string;
  agentDeployable: boolean;
  agentDeploymentMethod?: string;
  providerTags?: Record<string, string>;
  rawMetadata?: Record<string, any>;
}

export interface DiscoveryProgress {
  totalRegions: number;
  completedRegions: number;
  totalAssets: number;
  currentRegion?: string;
  errors: Array<{ region?: string; error: string }>;
}

export interface DeploymentResult {
  success: boolean;
  agentId?: string;
  deploymentId?: string;
  message?: string;
  errorMessage?: string;
  errorDetails?: Record<string, any>;
}

export interface ProviderAdapter {
  readonly provider: CloudProvider;
  
  validateCredentials(credentials: CloudCredentials): Promise<{ valid: boolean; error?: string; accountInfo?: Record<string, any> }>;
  
  listRegions(credentials: CloudCredentials): Promise<string[]>;
  
  discoverAssets(
    credentials: CloudCredentials,
    regions: string[],
    onProgress?: (progress: DiscoveryProgress) => void
  ): Promise<CloudAssetInfo[]>;
  
  deployAgent(
    credentials: CloudCredentials,
    asset: CloudAssetInfo,
    agentConfig: {
      serverUrl: string;
      registrationToken: string;
      organizationId: string;
    }
  ): Promise<DeploymentResult>;
  
  checkAgentDeploymentStatus(
    credentials: CloudCredentials,
    asset: CloudAssetInfo,
    deploymentId: string
  ): Promise<{ status: string; error?: string }>;
}

export interface CloudIntegrationConfig {
  serverUrl: string;
  registrationToken: string;
  agentVersion?: string;
}

export interface IAMFinding {
  id: string;
  provider: CloudProvider;
  findingType: "user" | "role" | "policy" | "access_key" | "service_account" | "group";
  resourceId: string;
  resourceName: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  title: string;
  description: string;
  riskFactors: string[];
  recommendation: string;
  metadata: Record<string, any>;
  createdAt?: Date;
  lastActivity?: Date;
}

export interface IAMScanResult {
  provider: CloudProvider;
  findings: IAMFinding[];
  summary: {
    totalUsers?: number;
    totalRoles?: number;
    totalPolicies?: number;
    totalServiceAccounts?: number;
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
  };
  scannedAt: Date;
}
