import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { ProviderAdapter, CloudCredentials, CloudAssetInfo, DiscoveryProgress, DeploymentResult } from "./types";

const AWS_REGIONS = [
  "us-east-1", "us-east-2", "us-west-1", "us-west-2",
  "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
  "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1",
  "sa-east-1", "ca-central-1", "me-south-1", "af-south-1"
];

export class AWSAdapter implements ProviderAdapter {
  readonly provider = "aws" as const;

  async validateCredentials(credentials: CloudCredentials): Promise<{ valid: boolean; error?: string; accountInfo?: Record<string, any> }> {
    const awsCreds = credentials.aws;
    if (!awsCreds) {
      return { valid: false, error: "AWS credentials not provided" };
    }

    if (!awsCreds.accessKeyId || !awsCreds.secretAccessKey) {
      return { valid: false, error: "AWS Access Key ID and Secret Access Key are required" };
    }

    try {
      const stsClient = new STSClient({
        region: "us-east-1",
        credentials: {
          accessKeyId: awsCreds.accessKeyId,
          secretAccessKey: awsCreds.secretAccessKey,
          sessionToken: awsCreds.sessionToken,
        },
      });

      const command = new GetCallerIdentityCommand({});
      const response = await stsClient.send(command);

      return {
        valid: true,
        accountInfo: {
          accountId: response.Account,
          arn: response.Arn,
          userId: response.UserId,
        },
      };
    } catch (error: any) {
      const errorMessage = error.message || "Unknown error";
      if (errorMessage.includes("InvalidClientTokenId")) {
        return { valid: false, error: "Invalid AWS Access Key ID" };
      }
      if (errorMessage.includes("SignatureDoesNotMatch")) {
        return { valid: false, error: "Invalid AWS Secret Access Key" };
      }
      if (errorMessage.includes("ExpiredToken")) {
        return { valid: false, error: "AWS session token has expired" };
      }
      return { valid: false, error: `AWS credential validation failed: ${errorMessage}` };
    }
  }

  async listRegions(_credentials: CloudCredentials): Promise<string[]> {
    return AWS_REGIONS;
  }

  async discoverAssets(
    credentials: CloudCredentials,
    regions: string[],
    onProgress?: (progress: DiscoveryProgress) => void
  ): Promise<CloudAssetInfo[]> {
    const awsCreds = credentials.aws;
    if (!awsCreds) {
      throw new Error("AWS credentials not provided");
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
        const ec2Assets = await this.discoverEC2Instances(awsCreds, region);
        allAssets.push(...ec2Assets);

        const rdsAssets = await this.discoverRDSInstances(awsCreds, region);
        allAssets.push(...rdsAssets);

        const eksAssets = await this.discoverEKSClusters(awsCreds, region);
        allAssets.push(...eksAssets);

        progress.totalAssets = allAssets.length;
      } catch (error: any) {
        progress.errors.push({ region, error: error.message });
      }

      progress.completedRegions++;
      onProgress?.(progress);
    }

    return allAssets;
  }

  private async discoverEC2Instances(creds: NonNullable<CloudCredentials["aws"]>, region: string): Promise<CloudAssetInfo[]> {
    console.log(`[AWS] Discovering EC2 instances in ${region}...`);
    
    return [];
  }

  private async discoverRDSInstances(creds: NonNullable<CloudCredentials["aws"]>, region: string): Promise<CloudAssetInfo[]> {
    console.log(`[AWS] Discovering RDS instances in ${region}...`);
    
    return [];
  }

  private async discoverEKSClusters(creds: NonNullable<CloudCredentials["aws"]>, region: string): Promise<CloudAssetInfo[]> {
    console.log(`[AWS] Discovering EKS clusters in ${region}...`);
    
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
    const awsCreds = credentials.aws;
    if (!awsCreds) {
      return { success: false, errorMessage: "AWS credentials not provided" };
    }

    if (!asset.agentDeployable) {
      return { success: false, errorMessage: "Asset does not support agent deployment" };
    }

    console.log(`[AWS] Deploying agent to ${asset.providerResourceId} via ${asset.agentDeploymentMethod || "ssm"}`);

    const installScript = this.generateInstallScript(agentConfig);

    switch (asset.agentDeploymentMethod) {
      case "ssm":
        return this.deployViaSSM(awsCreds, asset, installScript);
      default:
        return { success: false, errorMessage: `Deployment method ${asset.agentDeploymentMethod} not supported` };
    }
  }

  private generateInstallScript(config: { serverUrl: string; registrationToken: string; organizationId: string }): string {
    return `#!/bin/bash
set -e

curl -fsSL ${config.serverUrl}/api/agents/download/linux-amd64 -o /tmp/odinforge-agent
chmod +x /tmp/odinforge-agent
sudo /tmp/odinforge-agent install --server-url "${config.serverUrl}" --registration-token "${config.registrationToken}" --tenant-id "${config.organizationId}" --force
`;
  }

  private async deployViaSSM(
    creds: NonNullable<CloudCredentials["aws"]>,
    asset: CloudAssetInfo,
    script: string
  ): Promise<DeploymentResult> {
    console.log(`[AWS SSM] Would send command to ${asset.providerResourceId}`);
    console.log(`[AWS SSM] Script: ${script.substring(0, 100)}...`);

    return {
      success: false,
      errorMessage: "SSM deployment requires AWS SDK - install aws-sdk package for full functionality",
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

export const awsAdapter = new AWSAdapter();
