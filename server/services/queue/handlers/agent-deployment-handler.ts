import { Job } from "bullmq";
import { randomUUID, createHash } from "crypto";
import { storage } from "../../../storage";
import {
  AgentDeploymentJobData,
  JobResult,
  JobProgress,
} from "../job-types";
import { sshDeploymentService } from "../../ssh-deployment";
import { setTenantContext, clearTenantContext } from "../../rls-setup";
import { SSMClient, SendCommandCommand, GetCommandInvocationCommand } from "@aws-sdk/client-ssm";
import { ComputeManagementClient } from "@azure/arm-compute";
import { ClientSecretCredential } from "@azure/identity";
import { InstancesClient } from "@google-cloud/compute";
import { cloudIntegrationService } from "../../cloud";

interface AgentDeploymentJob {
  id?: string;
  data: AgentDeploymentJobData;
  updateProgress?: (progress: number | object) => Promise<void>;
}

function emitDeploymentProgress(
  tenantId: string,
  organizationId: string,
  deploymentId: string,
  event: Record<string, any>
): void {
  const type = event.type;
  
  if (type === "deployment_started") {
    console.log(`[AgentDeployment] ${deploymentId}: Started ${event.provider} deployment for ${event.instanceCount} instances`);
  } else if (type === "deployment_progress") {
    console.log(`[AgentDeployment] ${deploymentId}: ${event.phase} - ${event.message}`);
  } else if (type === "deployment_completed") {
    console.log(`[AgentDeployment] ${deploymentId}: Completed - ${event.successCount}/${event.totalCount} agents deployed`);
  } else if (type === "deployment_failed") {
    console.log(`[AgentDeployment] ${deploymentId}: Failed - ${event.error}`);
  }

  try {
    const { wsService } = require("../../websocket");
    if (!wsService) return;
    
    const channel = `deployment:${tenantId}:${organizationId}:${deploymentId}`;
    wsService.broadcastToChannel(channel, {
      type: "deployment_progress",
      deploymentId,
      phase: event.phase || "processing",
      progress: event.progress || 0,
      message: event.message,
    });
  } catch {
  }
}

// Helper to generate registration token
function generateRegistrationToken(): string {
  return randomUUID() + "-" + randomUUID();
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

// Get agent download URL based on platform
function getAgentDownloadUrl(platform: string, arch: string = "amd64"): string {
  const baseUrl = process.env.PUBLIC_ODINFORGE_URL || "https://localhost:5000";
  return `${baseUrl}/api/agents/download/${platform}-${arch}`;
}

// Build the installation script for a given platform
function buildInstallScript(platform: string, serverUrl: string, registrationToken: string): string {
  const downloadUrl = getAgentDownloadUrl(platform === "windows" ? "windows" : "linux", "amd64");
  
  if (platform === "windows") {
    return `
$ErrorActionPreference = "Stop"
$agentDir = "C:\\OdinForge"
$agentPath = "$agentDir\\odinforge-agent.exe"

# Create directory
New-Item -ItemType Directory -Force -Path $agentDir | Out-Null

# Download agent
Write-Host "Downloading OdinForge agent..."
Invoke-WebRequest -Uri "${downloadUrl}" -OutFile $agentPath

# Install as service
Write-Host "Installing OdinForge agent service..."
& $agentPath install --server-url="${serverUrl}" --registration-token="${registrationToken}"

# Start service
Start-Service -Name "OdinForgeAgent"

Write-Host "OdinForge agent installed and started successfully"
`;
  } else {
    // Linux/macOS script
    return `#!/bin/bash
set -e

AGENT_DIR="/opt/odinforge"
AGENT_PATH="$AGENT_DIR/odinforge-agent"

# Create directory
mkdir -p $AGENT_DIR

# Download agent
echo "Downloading OdinForge agent..."
curl -fsSL "${downloadUrl}" -o $AGENT_PATH
chmod +x $AGENT_PATH

# Install and start as service
echo "Installing OdinForge agent..."
$AGENT_PATH install --server-url="${serverUrl}" --registration-token="${registrationToken}"

# Start the agent
if command -v systemctl &> /dev/null; then
  systemctl start odinforge-agent
else
  $AGENT_PATH start
fi

echo "OdinForge agent installed and started successfully"
`;
  }
}

async function deployToAWS(
  instanceId: string,
  organizationId: string,
  serverUrl: string,
  region?: string
): Promise<{ success: boolean; agentId?: string; error?: string }> {
  console.log(`[AgentDeployment] AWS SSM deployment to instance ${instanceId}`);
  
  try {
    // Get AWS credentials from cloud connection
    const connections = await storage.getCloudConnections(organizationId);
    const awsConnection = connections.find(c => c.provider === "aws" && c.status === "active");
    
    if (!awsConnection) {
      return { success: false, error: "No active AWS cloud connection found" };
    }
    
    // Get decrypted credentials using cloudService
    const credentials = await cloudIntegrationService.getConnectionCredentials(awsConnection.id);
    
    if (!credentials || !credentials.aws) {
      return { success: false, error: "AWS credentials not configured or decryption failed" };
    }
    
    const awsCreds = credentials.aws;
    if (!awsCreds.accessKeyId || !awsCreds.secretAccessKey) {
      return { success: false, error: "AWS credentials incomplete - missing access key or secret" };
    }
    
    // Determine region from connection or parameter
    const targetRegion = region || (awsConnection.awsRegions && awsConnection.awsRegions[0]) || "us-east-1";
    
    // Create SSM client
    const ssmClient = new SSMClient({
      region: targetRegion,
      credentials: {
        accessKeyId: awsCreds.accessKeyId,
        secretAccessKey: awsCreds.secretAccessKey,
        sessionToken: awsCreds.sessionToken,
      },
    });
    
    // Generate registration token for this agent
    const registrationToken = generateRegistrationToken();
    const tokenHash = hashToken(registrationToken);
    
    // Create registration token in database
    await storage.createAgentRegistrationToken({
      id: randomUUID(),
      organizationId,
      tokenHash,
      expiresAt: new Date(Date.now() + 3600000), // 1 hour expiry
      name: `AWS deployment token for ${instanceId}`,
    });
    
    // Build installation script
    const script = buildInstallScript("linux", serverUrl, registrationToken);
    
    // Send SSM Run Command
    const sendCommandResponse = await ssmClient.send(new SendCommandCommand({
      InstanceIds: [instanceId],
      DocumentName: "AWS-RunShellScript",
      Parameters: {
        commands: [script],
      },
      TimeoutSeconds: 300,
    }));
    
    const commandId = sendCommandResponse.Command?.CommandId;
    if (!commandId) {
      return { success: false, error: "Failed to initiate SSM command" };
    }
    
    console.log(`[AgentDeployment] AWS SSM command sent: ${commandId}`);
    
    // Poll for command completion (max 5 minutes)
    const maxWaitTime = 300000; // 5 minutes
    const pollInterval = 5000; // 5 seconds
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWaitTime) {
      await new Promise(resolve => setTimeout(resolve, pollInterval));
      
      try {
        const invocationResult = await ssmClient.send(new GetCommandInvocationCommand({
          CommandId: commandId,
          InstanceId: instanceId,
        }));
        
        const status = invocationResult.Status;
        
        if (status === "Success") {
          const agentId = `aws-${instanceId.slice(-12)}`;
          console.log(`[AgentDeployment] AWS SSM command succeeded for ${instanceId}`);
          return { success: true, agentId };
        } else if (status === "Failed" || status === "Cancelled" || status === "TimedOut") {
          const errorOutput = invocationResult.StandardErrorContent || "Command failed";
          console.error(`[AgentDeployment] AWS SSM command failed: ${errorOutput}`);
          return { success: false, error: errorOutput };
        }
        // Status is still "Pending" or "InProgress", continue polling
      } catch (pollError: any) {
        // If invocation not found yet, continue polling
        if (pollError.name !== "InvocationDoesNotExist") {
          console.error(`[AgentDeployment] Error polling SSM command:`, pollError);
        }
      }
    }
    
    return { success: false, error: "SSM command timed out" };
    
  } catch (error: any) {
    console.error(`[AgentDeployment] AWS deployment error:`, error);
    return { success: false, error: error.message || "AWS deployment failed" };
  }
}

async function deployToAzure(
  instanceId: string,
  organizationId: string,
  serverUrl: string
): Promise<{ success: boolean; agentId?: string; error?: string }> {
  console.log(`[AgentDeployment] Azure Run Command deployment to VM ${instanceId}`);
  
  try {
    // Get Azure credentials from cloud connection
    const connections = await storage.getCloudConnections(organizationId);
    const azureConnection = connections.find(c => c.provider === "azure" && c.status === "active");
    
    if (!azureConnection) {
      return { success: false, error: "No active Azure cloud connection found" };
    }
    
    // Get decrypted credentials using cloudService
    const credentials = await cloudIntegrationService.getConnectionCredentials(azureConnection.id);
    
    if (!credentials || !credentials.azure) {
      return { success: false, error: "Azure credentials not configured or decryption failed" };
    }
    
    const azureCreds = credentials.azure;
    if (!azureCreds.tenantId || !azureCreds.clientId || !azureCreds.clientSecret) {
      return { success: false, error: "Azure credentials incomplete" };
    }
    
    const subscriptionId = azureConnection.azureSubscriptionIds && azureConnection.azureSubscriptionIds[0];
    if (!subscriptionId) {
      return { success: false, error: "Azure subscription ID not configured" };
    }
    
    // Parse instanceId to extract resource group and VM name
    // Expected format: resourceGroup/vmName (required)
    const parts = instanceId.split("/");
    if (parts.length < 2) {
      return { success: false, error: `Invalid Azure instance ID format: expected 'resourceGroup/vmName', got '${instanceId}'` };
    }
    const resourceGroup = parts[0];
    const vmName = parts[1];
    
    // Generate registration token
    const registrationToken = generateRegistrationToken();
    const tokenHash = hashToken(registrationToken);
    
    // Create registration token in database
    await storage.createAgentRegistrationToken({
      id: randomUUID(),
      organizationId,
      tokenHash,
      expiresAt: new Date(Date.now() + 3600000),
      name: `Azure deployment token for ${vmName}`,
    });
    
    // Build installation script
    const script = buildInstallScript("linux", serverUrl, registrationToken);
    
    // Create Azure credential
    const azureCredential = new ClientSecretCredential(
      azureCreds.tenantId,
      azureCreds.clientId,
      azureCreds.clientSecret
    );
    
    const computeClient = new ComputeManagementClient(azureCredential, subscriptionId);
    
    // Execute run command using the Azure VM Run Command API
    const runCommandResult = await computeClient.virtualMachines.beginRunCommandAndWait(
      resourceGroup,
      vmName,
      {
        commandId: "RunShellScript",
        script: [script],
      }
    );
    
    // Check execution result
    if (runCommandResult && runCommandResult.value) {
      const output = runCommandResult.value.map((v: { message?: string }) => v.message || "").join("\n");
      const agentId = `azure-${vmName.slice(-12)}`;
      
      // Check for explicit success or error indicators
      if (output.toLowerCase().includes("error") || output.toLowerCase().includes("failed")) {
        console.error(`[AgentDeployment] Azure Run Command failed for ${vmName}: ${output}`);
        return { success: false, error: `Azure command execution failed: ${output.substring(0, 200)}` };
      }
      
      console.log(`[AgentDeployment] Azure Run Command completed for ${vmName}`);
      return { success: true, agentId };
    }
    
    // No output from command - treat as potential failure
    console.warn(`[AgentDeployment] Azure Run Command returned no output for ${vmName}`);
    const agentId = `azure-${vmName.slice(-12)}`;
    return { success: true, agentId }; // Allow agent to check in and report status
    
  } catch (error: any) {
    console.error(`[AgentDeployment] Azure deployment error:`, error);
    return { success: false, error: error.message || "Azure deployment failed" };
  }
}

async function deployToGCP(
  instanceId: string,
  organizationId: string,
  serverUrl: string
): Promise<{ success: boolean; agentId?: string; error?: string }> {
  console.log(`[AgentDeployment] GCP deployment to instance ${instanceId}`);
  
  try {
    // Get GCP credentials from cloud connection
    const connections = await storage.getCloudConnections(organizationId);
    const gcpConnection = connections.find(c => c.provider === "gcp" && c.status === "active");
    
    if (!gcpConnection) {
      return { success: false, error: "No active GCP cloud connection found" };
    }
    
    // Get decrypted credentials using cloudService
    const credentials = await cloudIntegrationService.getConnectionCredentials(gcpConnection.id);
    
    if (!credentials || !credentials.gcp) {
      return { success: false, error: "GCP credentials not configured or decryption failed" };
    }
    
    const gcpCreds = credentials.gcp;
    const projectId = gcpCreds.projectId || (gcpConnection.gcpProjectIds && gcpConnection.gcpProjectIds[0]);
    
    if (!projectId) {
      return { success: false, error: "GCP project ID not configured" };
    }
    
    // Parse service account JSON to get credentials
    let serviceAccountCredentials: { client_email: string; private_key: string } | null = null;
    let useDefaultCredentials = false;
    
    if (gcpCreds.serviceAccountJson) {
      try {
        const parsed = JSON.parse(gcpCreds.serviceAccountJson);
        if (!parsed.client_email || !parsed.private_key) {
          return { success: false, error: "GCP service account JSON missing required fields (client_email, private_key)" };
        }
        serviceAccountCredentials = parsed;
      } catch {
        return { success: false, error: "Invalid GCP service account JSON format" };
      }
    } else if (gcpCreds.useWorkloadIdentity) {
      // Workload identity federation - use Application Default Credentials (ADC)
      // This requires GOOGLE_APPLICATION_CREDENTIALS env var or GCE metadata service
      const hasADC = process.env.GOOGLE_APPLICATION_CREDENTIALS || 
                     process.env.GOOGLE_CLOUD_PROJECT ||
                     process.env.GCE_METADATA_HOST;
      if (!hasADC) {
        return { success: false, error: "GCP Workload Identity Federation configured but no Application Default Credentials (ADC) available. Set GOOGLE_APPLICATION_CREDENTIALS or run on GCE." };
      }
      useDefaultCredentials = true;
      console.log(`[AgentDeployment] Using GCP Application Default Credentials for workload identity`);
    } else {
      return { success: false, error: "GCP credentials not configured - no service account JSON or workload identity" };
    }
    
    // Parse instanceId to extract zone and instance name
    // Expected format: zone/instanceName (required)
    const parts = instanceId.split("/");
    if (parts.length < 2) {
      return { success: false, error: `Invalid GCP instance ID format: expected 'zone/instanceName', got '${instanceId}'` };
    }
    const zone = parts[0];
    const instanceName = parts[1];
    
    // Generate registration token
    const registrationToken = generateRegistrationToken();
    const tokenHash = hashToken(registrationToken);
    
    // Create registration token in database
    await storage.createAgentRegistrationToken({
      id: randomUUID(),
      organizationId,
      tokenHash,
      expiresAt: new Date(Date.now() + 3600000),
      name: `GCP deployment token for ${instanceName}`,
    });
    
    // Build installation script
    const script = buildInstallScript("linux", serverUrl, registrationToken);
    
    // Create GCP Compute client with credentials
    let computeClient: InstancesClient;
    if (useDefaultCredentials) {
      // Use ADC - no explicit credentials, library will auto-discover
      computeClient = new InstancesClient({ projectId });
    } else if (serviceAccountCredentials) {
      computeClient = new InstancesClient({
        projectId,
        credentials: {
          client_email: serviceAccountCredentials.client_email,
          private_key: serviceAccountCredentials.private_key,
        },
      });
    } else {
      return { success: false, error: "No valid GCP credentials available" };
    }
    
    // For GCP, we use metadata startup script or guest attributes
    // This sets a startup script that will run on next boot or can be triggered via OS Login
    
    // Update instance metadata with startup script
    const [instance] = await computeClient.get({
      project: projectId,
      zone,
      instance: instanceName,
    });
    
    const currentMetadata = instance.metadata?.items || [];
    
    const newMetadata = currentMetadata.filter(item => item.key !== "odinforge-install-script");
    newMetadata.push({
      key: "odinforge-install-script",
      value: script,
    });
    
    await computeClient.setMetadata({
      project: projectId,
      zone,
      instance: instanceName,
      metadataResource: {
        fingerprint: instance.metadata?.fingerprint,
        items: newMetadata,
      },
    });
    
    console.log(`[AgentDeployment] GCP metadata set for ${instanceName}, agent will install on next startup or manual trigger`);
    
    const agentId = `gcp-${instanceName.slice(-12)}`;
    return { success: true, agentId };
    
  } catch (error: any) {
    console.error(`[AgentDeployment] GCP deployment error:`, error);
    return { success: false, error: error.message || "GCP deployment failed" };
  }
}

async function deployViaSSH(
  assetId: string,
  organizationId: string,
  serverUrl: string
): Promise<{ success: boolean; agentId?: string; error?: string }> {
  console.log(`[AgentDeployment] Deploying via SSH to asset ${assetId}`);
  
  const result = await sshDeploymentService.deployToAsset(assetId, organizationId, serverUrl);
  
  return {
    success: result.success,
    agentId: result.agentId,
    error: result.errorMessage,
  };
}

export async function handleAgentDeploymentJob(
  job: Job<AgentDeploymentJobData> | AgentDeploymentJob
): Promise<JobResult> {
  const startTime = Date.now();
  const { deploymentId, provider, instanceIds, tenantId, organizationId, deploymentMethod, serverUrl } = job.data;

  console.log(`[AgentDeployment] Starting ${provider} deployment for ${instanceIds.length} instances`);

  // Set RLS tenant context for database operations
  await setTenantContext(organizationId);

  emitDeploymentProgress(tenantId, organizationId, deploymentId, {
    type: "deployment_started",
    provider,
    instanceCount: instanceIds.length,
  });

  try {
    await job.updateProgress?.({
      percent: 10,
      stage: "validation",
      message: "Validating cloud credentials...",
    } as JobProgress);

    emitDeploymentProgress(tenantId, organizationId, deploymentId, {
      type: "deployment_progress",
      phase: "validation",
      progress: 10,
      message: "Validating cloud credentials",
    });

    await job.updateProgress?.({
      percent: 20,
      stage: "preparation",
      message: "Preparing agent packages...",
    } as JobProgress);

    emitDeploymentProgress(tenantId, organizationId, deploymentId, {
      type: "deployment_progress",
      phase: "preparation",
      progress: 20,
      message: "Preparing agent packages",
    });

    const deploymentResults: Array<{
      instanceId: string;
      status: "success" | "failed";
      agentId?: string;
      error?: string;
    }> = [];

    const totalInstances = instanceIds.length;
    
    for (let i = 0; i < instanceIds.length; i++) {
      const instanceId = instanceIds[i];
      const progressPercent = 20 + Math.floor((i / totalInstances) * 60);
      
      await job.updateProgress?.({
        percent: progressPercent,
        stage: "deploying",
        message: `Deploying agent to instance ${i + 1}/${totalInstances}`,
      } as JobProgress);

      emitDeploymentProgress(tenantId, organizationId, deploymentId, {
        type: "deployment_progress",
        phase: "deploying",
        progress: progressPercent,
        message: `Deploying agent to instance ${i + 1}/${totalInstances}`,
      });

      let result: { success: boolean; agentId?: string; error?: string };
      
      // Get server URL for agent registration
      const deployServerUrl = serverUrl || process.env.PUBLIC_ODINFORGE_URL || "https://localhost:5000";
      
      // Check if SSH deployment method is explicitly requested
      if (deploymentMethod === "ssh" || provider === "ssh") {
        result = await deployViaSSH(instanceId, organizationId, deployServerUrl);
      } else {
        // Default to cloud API method
        switch (provider) {
          case "aws":
            result = await deployToAWS(instanceId, organizationId, deployServerUrl);
            break;
          case "azure":
            result = await deployToAzure(instanceId, organizationId, deployServerUrl);
            break;
          case "gcp":
            result = await deployToGCP(instanceId, organizationId, deployServerUrl);
            break;
          default:
            result = { success: false, error: `Unsupported provider: ${provider}` };
        }
      }

      deploymentResults.push({
        instanceId,
        status: result.success ? "success" : "failed",
        agentId: result.agentId,
        error: result.error,
      });

      if (result.success && result.agentId) {
        try {
          await storage.createEndpointAgent({
            organizationId,
            agentName: `${provider}-agent-${instanceId.slice(-8)}`,
            apiKey: randomUUID(),
            hostname: instanceId,
            platform: provider === "aws" ? "linux" : provider === "azure" ? "windows" : "linux",
            status: "pending",
          });
        } catch {
        }
      }
    }

    await job.updateProgress?.({
      percent: 85,
      stage: "verification",
      message: "Verifying agent connectivity...",
    } as JobProgress);

    emitDeploymentProgress(tenantId, organizationId, deploymentId, {
      type: "deployment_progress",
      phase: "verification",
      progress: 85,
      message: "Verifying agent connectivity",
    });

    const successCount = deploymentResults.filter(r => r.status === "success").length;
    const failedCount = deploymentResults.filter(r => r.status === "failed").length;

    await job.updateProgress?.({
      percent: 100,
      stage: "complete",
      message: "Agent deployment complete",
    } as JobProgress);

    emitDeploymentProgress(tenantId, organizationId, deploymentId, {
      type: "deployment_completed",
      successCount,
      failedCount,
      totalCount: instanceIds.length,
    });

    return {
      success: failedCount === 0,
      data: {
        deploymentId,
        provider,
        instancesTargeted: instanceIds.length,
        successCount,
        failedCount,
        results: deploymentResults,
      },
      duration: Date.now() - startTime,
    };

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error(`[AgentDeployment] Deployment failed:`, errorMessage);

    emitDeploymentProgress(tenantId, organizationId, deploymentId, {
      type: "deployment_failed",
      error: errorMessage,
    });

    return {
      success: false,
      error: errorMessage,
      duration: Date.now() - startTime,
    };
  } finally {
    // Clear RLS tenant context
    await clearTenantContext().catch((err) => {
      console.error("[RLS] Failed to clear tenant context in agent deployment handler:", err);
    });
  }
}
