import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { EC2Client, DescribeInstancesCommand, DescribeVpcsCommand, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { S3Client, ListBucketsCommand } from "@aws-sdk/client-s3";
import { SSMClient, SendCommandCommand, GetCommandInvocationCommand } from "@aws-sdk/client-ssm";
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

    const s3Assets = await this.discoverS3Buckets(awsCreds);
    allAssets.push(...s3Assets);
    progress.totalAssets = allAssets.length;
    onProgress?.(progress);

    for (const region of regions) {
      progress.currentRegion = region;
      onProgress?.(progress);

      try {
        const ec2Assets = await this.discoverEC2Instances(awsCreds, region);
        allAssets.push(...ec2Assets);

        const rdsAssets = await this.discoverRDSInstances(awsCreds, region);
        allAssets.push(...rdsAssets);

        const lambdaAssets = await this.discoverLambdaFunctions(awsCreds, region);
        allAssets.push(...lambdaAssets);

        progress.totalAssets = allAssets.length;
      } catch (error: any) {
        progress.errors.push({ region, error: error.message });
      }

      progress.completedRegions++;
      onProgress?.(progress);
    }

    return allAssets;
  }

  private getCredentialsConfig(creds: NonNullable<CloudCredentials["aws"]>) {
    return {
      accessKeyId: creds.accessKeyId,
      secretAccessKey: creds.secretAccessKey,
      sessionToken: creds.sessionToken,
    };
  }

  private async discoverEC2Instances(creds: NonNullable<CloudCredentials["aws"]>, region: string): Promise<CloudAssetInfo[]> {
    console.log(`[AWS] Discovering EC2 instances in ${region}...`);
    const assets: CloudAssetInfo[] = [];
    
    try {
      const ec2Client = new EC2Client({
        region,
        credentials: this.getCredentialsConfig(creds),
      });

      const command = new DescribeInstancesCommand({});
      const response = await ec2Client.send(command);

      for (const reservation of response.Reservations || []) {
        for (const instance of reservation.Instances || []) {
          const nameTag = instance.Tags?.find(t => t.Key === "Name");
          assets.push({
            provider: "aws",
            providerResourceId: instance.InstanceId || "",
            assetType: "ec2_instance",
            assetName: nameTag?.Value || instance.InstanceId || "Unnamed Instance",
            region,
            instanceType: instance.InstanceType,
            powerState: instance.State?.Name,
            privateIpAddresses: instance.PrivateIpAddress ? [instance.PrivateIpAddress] : [],
            publicIpAddresses: instance.PublicIpAddress ? [instance.PublicIpAddress] : [],
            rawMetadata: {
              vpcId: instance.VpcId,
              subnetId: instance.SubnetId,
              platform: instance.Platform || "linux",
              launchTime: instance.LaunchTime?.toISOString(),
            },
            agentDeployable: instance.State?.Name === "running",
            agentDeploymentMethod: "ssm",
          });
        }
      }
    } catch (error: any) {
      console.error(`[AWS] EC2 discovery error in ${region}:`, error.message);
    }

    return assets;
  }

  private async discoverRDSInstances(creds: NonNullable<CloudCredentials["aws"]>, region: string): Promise<CloudAssetInfo[]> {
    console.log(`[AWS] Discovering RDS instances in ${region}...`);
    const assets: CloudAssetInfo[] = [];

    try {
      const rdsClient = new RDSClient({
        region,
        credentials: this.getCredentialsConfig(creds),
      });

      const command = new DescribeDBInstancesCommand({});
      const response = await rdsClient.send(command);

      for (const db of response.DBInstances || []) {
        assets.push({
          provider: "aws",
          providerResourceId: db.DBInstanceArn || db.DBInstanceIdentifier || "",
          assetType: "rds_instance",
          assetName: db.DBInstanceIdentifier || "Unnamed RDS",
          region,
          instanceType: db.DBInstanceClass,
          healthStatus: db.DBInstanceStatus,
          rawMetadata: {
            engine: db.Engine,
            engineVersion: db.EngineVersion,
            endpoint: db.Endpoint?.Address,
            port: db.Endpoint?.Port,
            multiAZ: db.MultiAZ,
            storageEncrypted: db.StorageEncrypted,
            publiclyAccessible: db.PubliclyAccessible,
          },
          agentDeployable: false,
        });
      }
    } catch (error: any) {
      console.error(`[AWS] RDS discovery error in ${region}:`, error.message);
    }

    return assets;
  }

  private async discoverLambdaFunctions(creds: NonNullable<CloudCredentials["aws"]>, region: string): Promise<CloudAssetInfo[]> {
    console.log(`[AWS] Discovering Lambda functions in ${region}...`);
    const assets: CloudAssetInfo[] = [];

    try {
      const lambdaClient = new LambdaClient({
        region,
        credentials: this.getCredentialsConfig(creds),
      });

      const command = new ListFunctionsCommand({});
      const response = await lambdaClient.send(command);

      for (const fn of response.Functions || []) {
        assets.push({
          provider: "aws",
          providerResourceId: fn.FunctionArn || fn.FunctionName || "",
          assetType: "lambda_function",
          assetName: fn.FunctionName || "Unnamed Lambda",
          region,
          memoryMb: fn.MemorySize,
          rawMetadata: {
            runtime: fn.Runtime,
            handler: fn.Handler,
            timeout: fn.Timeout,
            lastModified: fn.LastModified,
            codeSize: fn.CodeSize,
          },
          agentDeployable: false,
        });
      }
    } catch (error: any) {
      console.error(`[AWS] Lambda discovery error in ${region}:`, error.message);
    }

    return assets;
  }

  private async discoverS3Buckets(creds: NonNullable<CloudCredentials["aws"]>): Promise<CloudAssetInfo[]> {
    console.log(`[AWS] Discovering S3 buckets...`);
    const assets: CloudAssetInfo[] = [];

    try {
      const s3Client = new S3Client({
        region: "us-east-1",
        credentials: this.getCredentialsConfig(creds),
      });

      const command = new ListBucketsCommand({});
      const response = await s3Client.send(command);

      for (const bucket of response.Buckets || []) {
        assets.push({
          provider: "aws",
          providerResourceId: bucket.Name || "",
          assetType: "s3_bucket",
          assetName: bucket.Name || "Unnamed Bucket",
          region: "global",
          rawMetadata: {
            creationDate: bucket.CreationDate?.toISOString(),
          },
          agentDeployable: false,
        });
      }
    } catch (error: any) {
      console.error(`[AWS] S3 discovery error:`, error.message);
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
    const awsCreds = credentials.aws;
    if (!awsCreds) {
      return { success: false, errorMessage: "AWS credentials not provided" };
    }

    if (!asset.agentDeployable) {
      return { success: false, errorMessage: "Asset does not support agent deployment" };
    }

    console.log(`[AWS] Deploying agent to ${asset.providerResourceId} via ${asset.agentDeploymentMethod || "ssm"}`);

    // Detect platform from metadata
    const platform = asset.rawMetadata?.platform?.toLowerCase() || 
                     asset.rawMetadata?.Platform?.toLowerCase() || 
                     asset.rawMetadata?.PlatformDetails?.toLowerCase() || "";
    const isWindows = platform.includes("windows");
    console.log(`[AWS] Detected platform: ${isWindows ? "Windows" : "Linux"} (raw: "${platform}")`);

    const installScript = this.generateInstallScript(agentConfig, isWindows);

    switch (asset.agentDeploymentMethod) {
      case "ssm":
        return this.deployViaSSM(awsCreds, asset, installScript, isWindows);
      default:
        return { success: false, errorMessage: `Deployment method ${asset.agentDeploymentMethod} not supported` };
    }
  }

  private generateInstallScript(config: { serverUrl: string; registrationToken: string; organizationId: string }, isWindows: boolean): string {
    if (isWindows) {
      // PowerShell script for Windows
      return `$ErrorActionPreference = 'Stop'
$installDir = 'C:\\ProgramData\\OdinForge'
$agentPath = Join-Path $installDir 'odinforge-agent.exe'

# Create installation directory
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# Download the Windows agent binary
Write-Host "Downloading OdinForge agent..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri '${config.serverUrl}/api/agents/download/windows-amd64' -OutFile $agentPath -UseBasicParsing

# Install and start the agent
Write-Host "Installing OdinForge agent..."
& $agentPath install --server-url '${config.serverUrl}' --registration-token '${config.registrationToken}' --tenant-id '${config.organizationId}' --force

Write-Host "OdinForge agent installed successfully"
`;
    } else {
      // Bash script for Linux
      return `#!/bin/bash
set -e

curl -fsSL ${config.serverUrl}/api/agents/download/linux-amd64 -o /tmp/odinforge-agent
chmod +x /tmp/odinforge-agent
sudo /tmp/odinforge-agent install --server-url "${config.serverUrl}" --registration-token "${config.registrationToken}" --tenant-id "${config.organizationId}" --force
`;
    }
  }

  private async deployViaSSM(
    creds: NonNullable<CloudCredentials["aws"]>,
    asset: CloudAssetInfo,
    script: string,
    isWindows: boolean
  ): Promise<DeploymentResult> {
    const instanceId = asset.providerResourceId;
    const region = asset.region || "us-east-1";
    
    console.log(`[AWS SSM] Sending command to instance ${instanceId} in ${region} (platform: ${isWindows ? "Windows" : "Linux"})`);

    try {
      const ssmClient = new SSMClient({
        region,
        credentials: this.getCredentialsConfig(creds),
      });

      const documentName = isWindows ? "AWS-RunPowerShellScript" : "AWS-RunShellScript";
      
      // Send the command via SSM
      const sendCommand = new SendCommandCommand({
        InstanceIds: [instanceId],
        DocumentName: documentName,
        Parameters: {
          commands: [script],
        },
        TimeoutSeconds: 600, // 10 minute timeout
        Comment: "OdinForge Agent Deployment",
      });

      const sendResponse = await ssmClient.send(sendCommand);
      const commandId = sendResponse.Command?.CommandId;

      if (!commandId) {
        return {
          success: false,
          errorMessage: "Failed to get command ID from SSM response",
        };
      }

      console.log(`[AWS SSM] Command sent successfully, CommandId: ${commandId}`);
      
      return {
        success: true,
        deploymentId: commandId,
        message: `SSM command ${commandId} sent to instance ${instanceId}`,
      };
    } catch (error: any) {
      console.error(`[AWS SSM] Deployment error:`, error.message);
      
      // Provide helpful error messages for common SSM issues
      let errorMessage = error.message;
      if (error.name === "InvalidInstanceId") {
        errorMessage = `Instance ${instanceId} is not registered with SSM. Ensure the SSM Agent is installed and running, and the instance has the required IAM role (AmazonSSMManagedInstanceCore policy).`;
      } else if (error.name === "AccessDeniedException") {
        errorMessage = "Access denied. Ensure your AWS credentials have ssm:SendCommand permission.";
      } else if (error.name === "InvalidDocument") {
        errorMessage = "SSM document not found. This may be a region-specific issue.";
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
  ): Promise<{ status: string; error?: string; output?: string }> {
    const awsCreds = credentials.aws;
    if (!awsCreds) {
      return { status: "error", error: "AWS credentials not provided" };
    }

    const instanceId = asset.providerResourceId;
    const region = asset.region || "us-east-1";

    try {
      const ssmClient = new SSMClient({
        region,
        credentials: this.getCredentialsConfig(awsCreds),
      });

      const getInvocation = new GetCommandInvocationCommand({
        CommandId: deploymentId,
        InstanceId: instanceId,
      });

      const response = await ssmClient.send(getInvocation);
      
      // Map SSM status to our status
      const ssmStatus = response.Status;
      let status: string;
      let error: string | undefined;
      
      switch (ssmStatus) {
        case "Success":
          status = "success";
          break;
        case "Failed":
        case "Cancelled":
        case "TimedOut":
          status = "failed";
          error = response.StandardErrorContent || `Command ${ssmStatus.toLowerCase()}`;
          break;
        case "InProgress":
        case "Pending":
        case "Delayed":
          status = "in_progress";
          break;
        default:
          status = "unknown";
      }

      return {
        status,
        error,
        output: response.StandardOutputContent,
      };
    } catch (error: any) {
      // InvocationDoesNotExist means the command hasn't reached the instance yet
      if (error.name === "InvocationDoesNotExist") {
        return { status: "pending" };
      }
      
      return {
        status: "error",
        error: error.message,
      };
    }
  }
}

export const awsAdapter = new AWSAdapter();
