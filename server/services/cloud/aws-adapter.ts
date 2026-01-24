import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { EC2Client, DescribeInstancesCommand, DescribeVpcsCommand, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";
import { RDSClient, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { S3Client, ListBucketsCommand } from "@aws-sdk/client-s3";
import { SSMClient, SendCommandCommand, GetCommandInvocationCommand } from "@aws-sdk/client-ssm";
import { 
  IAMClient, 
  ListUsersCommand, 
  ListRolesCommand, 
  ListPoliciesCommand,
  ListAccessKeysCommand,
  GetAccessKeyLastUsedCommand,
  ListAttachedUserPoliciesCommand,
  ListAttachedRolePoliciesCommand,
  GetPolicyVersionCommand,
  ListUserPoliciesCommand,
  GetUserPolicyCommand,
  ListRolePoliciesCommand,
  GetRolePolicyCommand,
  ListGroupsForUserCommand,
  ListAttachedGroupPoliciesCommand,
} from "@aws-sdk/client-iam";
import { ProviderAdapter, CloudCredentials, CloudAssetInfo, DiscoveryProgress, DeploymentResult, IAMFinding } from "./types";

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

  private generateInstallScript(config: { serverUrl: string; registrationToken: string; organizationId: string }, isWindows: boolean): string[] {
    if (isWindows) {
      // PowerShell commands for Windows - each command is a separate array element for SSM
      // Service name is 'odinforge-agent' (lowercase with hyphen) and installs to C:\Program Files\OdinForge
      return [
        "$ErrorActionPreference = 'SilentlyContinue'",
        "Write-Host 'Stopping existing OdinForge service...'",
        "sc.exe stop 'odinforge-agent' 2>$null",
        "Start-Sleep -Seconds 3",
        "Write-Host 'Removing existing OdinForge service...'",
        "sc.exe delete 'odinforge-agent' 2>$null",
        "Start-Sleep -Seconds 2",
        "Stop-Process -Name 'odinforge-agent' -Force -ErrorAction SilentlyContinue",
        "$ErrorActionPreference = 'Stop'",
        "$downloadDir = 'C:\\ProgramData\\OdinForge'",
        "$agentDownload = Join-Path $downloadDir 'odinforge-agent.exe'",
        "if (-not (Test-Path $downloadDir)) { New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null }",
        "Write-Host 'Downloading OdinForge agent...'",
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12",
        `Invoke-WebRequest -Uri '${config.serverUrl}/api/agents/download/windows-amd64' -OutFile $agentDownload -UseBasicParsing`,
        "Write-Host 'Installing OdinForge agent...'",
        `& $agentDownload install --server-url '${config.serverUrl}' --registration-token '${config.registrationToken}' --tenant-id '${config.organizationId}' --force`,
        "Write-Host 'OdinForge agent installed successfully'"
      ];
    } else {
      // Bash commands for Linux - each command is a separate array element for SSM
      return [
        "#!/bin/bash",
        "set -e",
        `curl -fsSL ${config.serverUrl}/api/agents/download/linux-amd64 -o /tmp/odinforge-agent`,
        "chmod +x /tmp/odinforge-agent",
        `sudo /tmp/odinforge-agent install --server-url "${config.serverUrl}" --registration-token "${config.registrationToken}" --tenant-id "${config.organizationId}" --force`
      ];
    }
  }

  private async deployViaSSM(
    creds: NonNullable<CloudCredentials["aws"]>,
    asset: CloudAssetInfo,
    commands: string[],
    isWindows: boolean
  ): Promise<DeploymentResult> {
    const instanceId = asset.providerResourceId;
    const region = asset.region || "us-east-1";
    
    console.log(`[AWS SSM] Sending ${commands.length} commands to instance ${instanceId} in ${region} (platform: ${isWindows ? "Windows" : "Linux"})`);

    try {
      const ssmClient = new SSMClient({
        region,
        credentials: this.getCredentialsConfig(creds),
      });

      const documentName = isWindows ? "AWS-RunPowerShellScript" : "AWS-RunShellScript";
      
      // Send the command via SSM - each command as separate array element
      const sendCommand = new SendCommandCommand({
        InstanceIds: [instanceId],
        DocumentName: documentName,
        Parameters: {
          commands: commands,
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

  async scanIAM(credentials: CloudCredentials): Promise<{ findings: IAMFinding[]; summary: Record<string, any> }> {
    const awsCreds = credentials.aws;
    if (!awsCreds) {
      throw new Error("AWS credentials not provided");
    }

    const iamClient = new IAMClient({
      region: "us-east-1",
      credentials: {
        accessKeyId: awsCreds.accessKeyId,
        secretAccessKey: awsCreds.secretAccessKey,
        sessionToken: awsCreds.sessionToken,
      },
    });

    const findings: IAMFinding[] = [];
    const now = new Date();
    const ninetyDaysAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);

    // Shared dangerous action patterns for policy analysis
    const dangerousActionPatterns = [
      "iam:*",
      "iam:CreateUser",
      "iam:CreateRole",
      "iam:AttachUserPolicy",
      "iam:AttachRolePolicy",
      "iam:CreatePolicyVersion",
      "iam:SetDefaultPolicyVersion",
      "iam:PassRole",
      "iam:PutUserPolicy",
      "iam:PutRolePolicy",
      "iam:UpdateAssumeRolePolicy",
      "iam:CreateAccessKey",
      "iam:DeleteUserPolicy",
      "iam:DeleteRolePolicy",
      "sts:AssumeRole",
      "lambda:CreateFunction",
      "lambda:InvokeFunction",
      "lambda:UpdateFunctionCode",
    ];
    
    // Helper to parse policy document (handles both string and object forms)
    const parsePolicyDocument = (policyDocRaw: any): any | null => {
      if (!policyDocRaw) return null;
      if (typeof policyDocRaw === "object") return policyDocRaw;
      try {
        return JSON.parse(decodeURIComponent(policyDocRaw));
      } catch {
        try {
          return JSON.parse(policyDocRaw);
        } catch {
          return null;
        }
      }
    };
    
    // Helper to find dangerous actions in a list of actions
    const findDangerousActions = (actions: string[]): string[] => {
      return actions.filter((action: string) => 
        dangerousActionPatterns.some(pattern => {
          if (pattern.endsWith("*")) {
            return action.startsWith(pattern.slice(0, -1));
          }
          return action === pattern || action === "iam:*";
        })
      );
    };
    
    // Helper to analyze a policy and generate findings
    const analyzePolicyStatements = (
      policyDoc: any, 
      context: { 
        findingIdPrefix: string; 
        findingType: IAMFinding["findingType"]; 
        resourceId: string; 
        resourceName: string;
        policyName: string;
        policySource: "inline" | "attached" | "managed";
      }
    ): IAMFinding[] => {
      const policyFindings: IAMFinding[] = [];
      const statements = policyDoc?.Statement || [];
      
      for (const stmt of statements) {
        if (stmt.Effect !== "Allow") continue;
        
        const actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action].filter(Boolean);
        const resources = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource].filter(Boolean);
        const hasWildcardAction = actions.some((a: string) => a === "*" || a === "*:*");
        const hasWildcardResource = resources.some((r: string) => r === "*");
        
        // Check for full access
        if (hasWildcardAction && hasWildcardResource) {
          policyFindings.push({
            id: `${context.findingIdPrefix}-fullaccess-${context.policyName}`,
            provider: "aws",
            findingType: context.findingType,
            resourceId: context.resourceId,
            resourceName: context.resourceName,
            severity: "critical",
            title: `${context.policySource === "inline" ? "Inline Policy" : "Policy"} Grants Full Access`,
            description: `${context.resourceName} has ${context.policySource} policy "${context.policyName}" granting all actions on all resources.`,
            riskFactors: ["excessive_permissions", context.policySource === "inline" ? "inline_policy" : "managed_policy", "admin_access"],
            recommendation: "Replace with a policy with least privilege permissions.",
            metadata: { resourceName: context.resourceName, policyName: context.policyName, policySource: context.policySource },
          });
        }
        
        // Check for dangerous actions
        const foundDangerousActions = findDangerousActions(actions);
        if (foundDangerousActions.length > 0 && hasWildcardResource) {
          policyFindings.push({
            id: `${context.findingIdPrefix}-dangerous-${context.policyName}-${stmt.Sid || "stmt"}`,
            provider: "aws",
            findingType: context.findingType,
            resourceId: context.resourceId,
            resourceName: context.resourceName,
            severity: "high",
            title: "Policy Contains Dangerous Permissions",
            description: `${context.resourceName} has ${context.policySource} policy "${context.policyName}" with dangerous permissions: ${foundDangerousActions.join(", ")}`,
            riskFactors: ["privilege_escalation", "iam_modification"],
            recommendation: "Review and restrict these permissions to specific resources.",
            metadata: { resourceName: context.resourceName, policyName: context.policyName, dangerousActions: foundDangerousActions },
          });
        }
      }
      
      return policyFindings;
    };

    // Scan IAM Users
    try {
      const usersResponse = await iamClient.send(new ListUsersCommand({}));
      const users = usersResponse.Users || [];
      
      for (const user of users) {
        const userName = user.UserName || "unknown";
        const userId = user.UserId || `user-${userName}`;
        
        // Check for old access keys
        try {
          const keysResponse = await iamClient.send(new ListAccessKeysCommand({ UserName: userName }));
          const accessKeys = keysResponse.AccessKeyMetadata || [];
          
          for (const key of accessKeys) {
            const keyId = key.AccessKeyId || "";
            const createDate = key.CreateDate;
            
            // Check key age
            if (createDate && createDate < ninetyDaysAgo) {
              findings.push({
                id: `iam-key-old-${keyId}`,
                provider: "aws",
                findingType: "access_key",
                resourceId: keyId,
                resourceName: `${userName}/${keyId}`,
                severity: "high",
                title: "Access Key Older Than 90 Days",
                description: `Access key ${keyId} for user ${userName} was created on ${createDate.toISOString()} and is over 90 days old.`,
                riskFactors: ["credential_age", "rotation_required"],
                recommendation: "Rotate this access key and update any applications using it.",
                metadata: { userName, keyId, createDate: createDate.toISOString(), keyStatus: key.Status },
              });
            }
            
            // Check last used
            try {
              const lastUsedResponse = await iamClient.send(new GetAccessKeyLastUsedCommand({ AccessKeyId: keyId }));
              const lastUsed = lastUsedResponse.AccessKeyLastUsed?.LastUsedDate;
              
              if (!lastUsed || lastUsed < ninetyDaysAgo) {
                findings.push({
                  id: `iam-key-inactive-${keyId}`,
                  provider: "aws",
                  findingType: "access_key",
                  resourceId: keyId,
                  resourceName: `${userName}/${keyId}`,
                  severity: "medium",
                  title: "Inactive Access Key",
                  description: `Access key ${keyId} for user ${userName} has not been used in over 90 days.`,
                  riskFactors: ["unused_credential", "potential_orphan"],
                  recommendation: "Consider deleting this unused access key to reduce attack surface.",
                  metadata: { userName, keyId, lastUsed: lastUsed?.toISOString() || "never" },
                  lastActivity: lastUsed,
                });
              }
            } catch {}
          }
        } catch {}
        
        // Check attached policies for overly permissive access
        try {
          const policiesResponse = await iamClient.send(new ListAttachedUserPoliciesCommand({ UserName: userName }));
          const attachedPolicies = policiesResponse.AttachedPolicies || [];
          
          for (const policy of attachedPolicies) {
            const policyArn = policy.PolicyArn || "";
            const policyName = policy.PolicyName || "";
            
            // Flag AdministratorAccess policy
            if (policyName === "AdministratorAccess" || policyArn.includes("AdministratorAccess")) {
              findings.push({
                id: `iam-user-admin-${userId}`,
                provider: "aws",
                findingType: "user",
                resourceId: userId,
                resourceName: userName,
                severity: "critical",
                title: "User Has Administrator Access",
                description: `User ${userName} has the AdministratorAccess policy attached, granting full account access.`,
                riskFactors: ["excessive_permissions", "admin_access", "privilege_escalation"],
                recommendation: "Apply principle of least privilege. Create specific policies for the user's required access.",
                metadata: { userName, policyName, policyArn },
              });
            }
            
            // Flag PowerUserAccess
            if (policyName === "PowerUserAccess" || policyArn.includes("PowerUserAccess")) {
              findings.push({
                id: `iam-user-poweruser-${userId}`,
                provider: "aws",
                findingType: "user",
                resourceId: userId,
                resourceName: userName,
                severity: "high",
                title: "User Has Power User Access",
                description: `User ${userName} has the PowerUserAccess policy attached, granting broad account access.`,
                riskFactors: ["excessive_permissions", "privilege_escalation"],
                recommendation: "Review if this level of access is necessary. Consider more restrictive policies.",
                metadata: { userName, policyName, policyArn },
              });
            }
          }
        } catch {}
        
        // Check for inactive users
        const passwordLastUsed = user.PasswordLastUsed;
        if (passwordLastUsed && passwordLastUsed < ninetyDaysAgo) {
          findings.push({
            id: `iam-user-inactive-${userId}`,
            provider: "aws",
            findingType: "user",
            resourceId: userId,
            resourceName: userName,
            severity: "medium",
            title: "Inactive User Account",
            description: `User ${userName} has not logged in via console in over 90 days.`,
            riskFactors: ["inactive_account", "potential_orphan"],
            recommendation: "Review if this user is still needed. Consider deactivating or deleting unused accounts.",
            metadata: { userName, passwordLastUsed: passwordLastUsed.toISOString() },
            lastActivity: passwordLastUsed,
          });
        }
        
        // Check inline policies for dangerous permissions using shared helper
        try {
          const inlinePoliciesResponse = await iamClient.send(new ListUserPoliciesCommand({ UserName: userName }));
          const inlinePolicyNames = inlinePoliciesResponse.PolicyNames || [];
          
          for (const inlinePolicyName of inlinePolicyNames) {
            try {
              const inlinePolicyResponse = await iamClient.send(new GetUserPolicyCommand({ 
                UserName: userName, 
                PolicyName: inlinePolicyName 
              }));
              
              const policyDoc = parsePolicyDocument(inlinePolicyResponse.PolicyDocument);
              if (!policyDoc) continue;
              
              const policyFindings = analyzePolicyStatements(policyDoc, {
                findingIdPrefix: `iam-user-${userId}`,
                findingType: "user",
                resourceId: userId,
                resourceName: userName,
                policyName: inlinePolicyName,
                policySource: "inline",
              });
              findings.push(...policyFindings);
            } catch {}
          }
        } catch {}
        
        // Check group-inherited policies
        try {
          const groupsResponse = await iamClient.send(new ListGroupsForUserCommand({ UserName: userName }));
          const groups = groupsResponse.Groups || [];
          
          for (const group of groups) {
            const groupName = group.GroupName || "";
            try {
              const groupPoliciesResponse = await iamClient.send(new ListAttachedGroupPoliciesCommand({ GroupName: groupName }));
              const groupPolicies = groupPoliciesResponse.AttachedPolicies || [];
              
              for (const groupPolicy of groupPolicies) {
                const policyArn = groupPolicy.PolicyArn || "";
                const policyName = groupPolicy.PolicyName || "";
                
                if (policyName === "AdministratorAccess" || policyArn.includes("AdministratorAccess")) {
                  findings.push({
                    id: `iam-user-group-admin-${userId}-${groupName}`,
                    provider: "aws",
                    findingType: "user",
                    resourceId: userId,
                    resourceName: userName,
                    severity: "critical",
                    title: "User Inherits Administrator Access via Group",
                    description: `User ${userName} inherits AdministratorAccess via group "${groupName}".`,
                    riskFactors: ["excessive_permissions", "group_inheritance", "admin_access"],
                    recommendation: "Review group membership and remove unnecessary admin privileges.",
                    metadata: { userName, groupName, policyName, policyArn },
                  });
                }
              }
            } catch {}
          }
        } catch {}
      }
    } catch (error: any) {
      console.log(`[AWS IAM] Error scanning users: ${error.message}`);
    }

    // Scan IAM Roles for overly permissive trust policies
    try {
      const rolesResponse = await iamClient.send(new ListRolesCommand({}));
      const roles = rolesResponse.Roles || [];
      
      for (const role of roles) {
        const roleName = role.RoleName || "unknown";
        const roleId = role.RoleId || `role-${roleName}`;
        
        // Parse trust policy - handle both string and object forms
        try {
          const trustPolicyRaw = role.AssumeRolePolicyDocument;
          if (trustPolicyRaw) {
            let policy: any;
            if (typeof trustPolicyRaw === "object") {
              policy = trustPolicyRaw;
            } else {
              try {
                policy = JSON.parse(decodeURIComponent(trustPolicyRaw));
              } catch {
                policy = JSON.parse(trustPolicyRaw);
              }
            }
            const statements = policy.Statement || [];
            
            for (const statement of statements) {
              const principal = statement.Principal;
              
              // Check for wildcard principal
              if (principal === "*" || principal?.AWS === "*") {
                findings.push({
                  id: `iam-role-trust-wildcard-${roleId}`,
                  provider: "aws",
                  findingType: "role",
                  resourceId: roleId,
                  resourceName: roleName,
                  severity: "critical",
                  title: "Role Trust Policy Allows Any Principal",
                  description: `Role ${roleName} has a trust policy that allows any AWS account or principal to assume it.`,
                  riskFactors: ["open_trust_relationship", "cross_account_access", "privilege_escalation"],
                  recommendation: "Restrict the trust policy to specific AWS accounts or services.",
                  metadata: { roleName, trustPolicy: policy },
                });
              }
            }
          }
        } catch {}
        
        // Check attached policies
        try {
          const policiesResponse = await iamClient.send(new ListAttachedRolePoliciesCommand({ RoleName: roleName }));
          const attachedPolicies = policiesResponse.AttachedPolicies || [];
          
          for (const policy of attachedPolicies) {
            const policyArn = policy.PolicyArn || "";
            const policyName = policy.PolicyName || "";
            
            if (policyName === "AdministratorAccess" || policyArn.includes("AdministratorAccess")) {
              findings.push({
                id: `iam-role-admin-${roleId}`,
                provider: "aws",
                findingType: "role",
                resourceId: roleId,
                resourceName: roleName,
                severity: "critical",
                title: "Role Has Administrator Access",
                description: `Role ${roleName} has the AdministratorAccess policy attached, granting full account access.`,
                riskFactors: ["excessive_permissions", "admin_access", "privilege_escalation"],
                recommendation: "Review if this role requires administrator access. Apply principle of least privilege.",
                metadata: { roleName, policyName, policyArn },
              });
            }
          }
        } catch {}
        
        // Check inline policies for roles using shared helper
        try {
          const inlinePoliciesResponse = await iamClient.send(new ListRolePoliciesCommand({ RoleName: roleName }));
          const inlinePolicyNames = inlinePoliciesResponse.PolicyNames || [];
          
          for (const inlinePolicyName of inlinePolicyNames) {
            try {
              const inlinePolicyResponse = await iamClient.send(new GetRolePolicyCommand({ 
                RoleName: roleName, 
                PolicyName: inlinePolicyName 
              }));
              
              const policyDoc = parsePolicyDocument(inlinePolicyResponse.PolicyDocument);
              if (!policyDoc) continue;
              
              const policyFindings = analyzePolicyStatements(policyDoc, {
                findingIdPrefix: `iam-role-${roleId}`,
                findingType: "role",
                resourceId: roleId,
                resourceName: roleName,
                policyName: inlinePolicyName,
                policySource: "inline",
              });
              findings.push(...policyFindings);
            } catch {}
          }
        } catch {}
      }
    } catch (error: any) {
      console.log(`[AWS IAM] Error scanning roles: ${error.message}`);
    }

    // Scan customer-managed policies for dangerous permissions
    try {
      const policiesResponse = await iamClient.send(new ListPoliciesCommand({ Scope: "Local" }));
      const policies = policiesResponse.Policies || [];
      
      for (const policy of policies) {
        const policyArn = policy.Arn || "";
        const policyName = policy.PolicyName || "unknown";
        const policyId = policy.PolicyId || `policy-${policyName}`;
        const defaultVersionId = policy.DefaultVersionId;
        
        if (!defaultVersionId) continue;
        
        try {
          const versionResponse = await iamClient.send(new GetPolicyVersionCommand({
            PolicyArn: policyArn,
            VersionId: defaultVersionId,
          }));
          
          const policyDoc = parsePolicyDocument(versionResponse.PolicyVersion?.Document);
          if (!policyDoc) continue;
          
          // Use shared helper for consistent policy analysis
          const policyFindings = analyzePolicyStatements(policyDoc, {
            findingIdPrefix: `iam-policy-${policyId}`,
            findingType: "policy",
            resourceId: policyId,
            resourceName: policyName,
            policyName: policyName,
            policySource: "managed",
          });
          findings.push(...policyFindings);
        } catch {}
      }
    } catch (error: any) {
      console.log(`[AWS IAM] Error scanning policies: ${error.message}`);
    }

    // Build summary
    const summary = {
      totalFindings: findings.length,
      criticalFindings: findings.filter(f => f.severity === "critical").length,
      highFindings: findings.filter(f => f.severity === "high").length,
      mediumFindings: findings.filter(f => f.severity === "medium").length,
      lowFindings: findings.filter(f => f.severity === "low").length,
      byType: {
        users: findings.filter(f => f.findingType === "user").length,
        roles: findings.filter(f => f.findingType === "role").length,
        policies: findings.filter(f => f.findingType === "policy").length,
        accessKeys: findings.filter(f => f.findingType === "access_key").length,
      },
    };

    console.log(`[AWS IAM] Scan complete: ${findings.length} findings (${summary.criticalFindings} critical, ${summary.highFindings} high)`);

    return { findings, summary };
  }
}

export const awsAdapter = new AWSAdapter();
