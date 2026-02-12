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
import { InstancesClient, ZoneOperationsClient } from "@google-cloud/compute";
import { cloudIntegrationService } from "../../cloud";
import { awsAdapter } from "../../cloud/aws-adapter";

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

// Deployment configuration constants for consistency across providers
const DEPLOYMENT_CONFIG = {
  COMMAND_TIMEOUT_MS: 300000, // 5 minutes for command execution
  POLL_INTERVAL_MS: 5000, // 5 seconds between status checks
  VM_RESET_TIMEOUT_MS: 120000, // 2 minutes for VM reset operations
  TOKEN_EXPIRY_MS: 3600000, // 1 hour for registration tokens
};

// Get agent download URL based on platform
function getAgentDownloadUrl(platform: string, arch: string = "amd64"): string {
  const baseUrl = process.env.PUBLIC_ODINFORGE_URL || "https://localhost:5000";
  return `${baseUrl}/api/agents/download/${platform}-${arch}`;
}

// Helper to deploy via SSH with explicit credential ID
async function deployViaSSHWithCredential(
  sshCredentialId: string,
  instanceName: string,
  organizationId: string,
  serverUrl: string
): Promise<{ success: boolean; agentId?: string; error?: string }> {
  console.log(`[AgentDeployment] Step: Attempting SSH deployment with credential ${sshCredentialId}`);
  
  try {
    // First verify the SSH credential belongs to this organization (multi-tenant security)
    const credential = await storage.getSshCredential(sshCredentialId);
    if (!credential) {
      console.log(`[AgentDeployment] SSH credential ${sshCredentialId} not found`);
      return { success: false, error: "SSH credential not found" };
    }
    
    if (credential.organizationId !== organizationId) {
      console.log(`[AgentDeployment] SSH credential ${sshCredentialId} belongs to different organization`);
      return { success: false, error: "SSH credential access denied - wrong organization" };
    }
    
    const config = await sshDeploymentService.getDecryptedCredentials(sshCredentialId);
    if (!config) {
      console.log(`[AgentDeployment] SSH credential ${sshCredentialId} decryption failed`);
      return { success: false, error: "SSH credential decryption failed" };
    }
    
    if (!config.host) {
      console.log(`[AgentDeployment] SSH credential missing host address`);
      return { success: false, error: "SSH credential missing host address" };
    }
    
    console.log(`[AgentDeployment] SSH target: ${config.host}:${config.port || 22}`);
    
    // Generate registration token (already within tenant context from caller)
    const registrationToken = generateRegistrationToken();
    const tokenHash = hashToken(registrationToken);
    const tokenId = `regtoken-${randomUUID().slice(0, 8)}`;
    
    await storage.createAgentRegistrationToken({
      id: tokenId,
      tokenHash,
      organizationId,
      description: `SSH deployment to ${instanceName}`,
      expiresAt: new Date(Date.now() + DEPLOYMENT_CONFIG.TOKEN_EXPIRY_MS),
    });
    console.log(`[AgentDeployment] Registration token created (expires in 1 hour)`);
    
    const result = await sshDeploymentService.deployAgent(config, {
      serverUrl,
      registrationToken,
      organizationId,
      platform: "linux",
    } as any);
    
    if (result.success) {
      console.log(`[AgentDeployment] SSH deployment successful: ${result.agentId}`);
    } else {
      console.log(`[AgentDeployment] SSH deployment failed: ${result.errorMessage}`);
    }
    
    return {
      success: result.success,
      agentId: result.agentId,
      error: result.errorMessage,
    };
  } catch (error: any) {
    console.error(`[AgentDeployment] SSH deployment error:`, error);
    return { success: false, error: error.message };
  }
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
  console.log(`[AgentDeployment] ========== AWS SSM DEPLOYMENT START ==========`);
  console.log(`[AgentDeployment] Target Instance: ${instanceId}`);
  console.log(`[AgentDeployment] Organization: ${organizationId}`);
  console.log(`[AgentDeployment] Server URL (agent will connect to): ${serverUrl}`);
  
  try {
    // Get AWS credentials from cloud connection
    console.log(`[AgentDeployment] Step 1: Retrieving AWS cloud connection...`);
    const connections = await storage.getCloudConnections(organizationId);
    const awsConnection = connections.find(c => c.provider === "aws" && c.status === "active");
    
    if (!awsConnection) {
      console.error(`[AgentDeployment] FAILED: No active AWS cloud connection found for org ${organizationId}`);
      return { success: false, error: "No active AWS cloud connection found" };
    }
    console.log(`[AgentDeployment] Found AWS connection: ${awsConnection.name} (ID: ${awsConnection.id})`);
    
    // Get decrypted credentials using cloudService
    console.log(`[AgentDeployment] Step 2: Decrypting AWS credentials...`);
    const credentials = await cloudIntegrationService.getConnectionCredentials(awsConnection.id);
    
    if (!credentials || !credentials.aws) {
      console.error(`[AgentDeployment] FAILED: AWS credentials not configured or decryption failed`);
      return { success: false, error: "AWS credentials not configured or decryption failed" };
    }
    
    const awsCreds = credentials.aws;
    if (!awsCreds.accessKeyId || !awsCreds.secretAccessKey) {
      console.error(`[AgentDeployment] FAILED: AWS credentials incomplete`);
      return { success: false, error: "AWS credentials incomplete - missing access key or secret" };
    }
    console.log(`[AgentDeployment] AWS credentials loaded successfully (Access Key: ${awsCreds.accessKeyId.slice(0, 8)}...)`);
    
    // Determine region from connection or parameter
    const targetRegion = region || (awsConnection.awsRegions && awsConnection.awsRegions[0]) || "us-east-1";
    console.log(`[AgentDeployment] Target region: ${targetRegion}`);
    
    // Create SSM client
    console.log(`[AgentDeployment] Step 3: Creating SSM client...`);
    const ssmClient = new SSMClient({
      region: targetRegion,
      credentials: {
        accessKeyId: awsCreds.accessKeyId,
        secretAccessKey: awsCreds.secretAccessKey,
        sessionToken: awsCreds.sessionToken,
      },
    });
    
    // Generate registration token for this agent
    console.log(`[AgentDeployment] Step 4: Creating registration token...`);
    const registrationToken = generateRegistrationToken();
    const tokenHash = hashToken(registrationToken);
    
    // Create registration token in database
    await storage.createAgentRegistrationToken({
      id: randomUUID(),
      organizationId,
      tokenHash,
      expiresAt: new Date(Date.now() + DEPLOYMENT_CONFIG.TOKEN_EXPIRY_MS),
      name: `AWS deployment token for ${instanceId}`,
    });
    console.log(`[AgentDeployment] Registration token created (expires in 1 hour)`);
    
    // Build installation script
    console.log(`[AgentDeployment] Step 5: Building installation script...`);
    const script = buildInstallScript("linux", serverUrl, registrationToken);
    console.log(`[AgentDeployment] Installation script ready (${script.length} bytes)`);
    console.log(`[AgentDeployment] Agent will register to: ${serverUrl}`);
    
    // Send SSM Run Command
    console.log(`[AgentDeployment] Step 6: Sending SSM Run Command...`);
    const sendCommandResponse = await ssmClient.send(new SendCommandCommand({
      InstanceIds: [instanceId],
      DocumentName: "AWS-RunShellScript",
      Parameters: {
        commands: [script],
      },
      TimeoutSeconds: Math.floor(DEPLOYMENT_CONFIG.COMMAND_TIMEOUT_MS / 1000),
    }));
    
    const commandId = sendCommandResponse.Command?.CommandId;
    if (!commandId) {
      return { success: false, error: "Failed to initiate SSM command" };
    }
    
    console.log(`[AgentDeployment] AWS SSM command sent: ${commandId}`);
    
    // Poll for command completion using consistent config
    const maxWaitTime = DEPLOYMENT_CONFIG.COMMAND_TIMEOUT_MS;
    const pollInterval = DEPLOYMENT_CONFIG.POLL_INTERVAL_MS;
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

// Fallback chain tracking
interface DeploymentAttempt {
  method: "ssm" | "ssh" | "ec2-instance-connect";
  success: boolean;
  error?: string;
  duration: number;
}

interface FallbackDeploymentResult {
  success: boolean;
  agentId?: string;
  error?: string;
  attempts: DeploymentAttempt[];
  methodUsed?: string;
}

async function deployToAWSWithFallback(
  instanceId: string,
  organizationId: string,
  serverUrl: string
): Promise<FallbackDeploymentResult> {
  const attempts: DeploymentAttempt[] = [];

  console.log(`[AgentDeployment] ========== AWS DEPLOYMENT WITH FALLBACK ==========`);
  console.log(`[AgentDeployment] Target: ${instanceId}, Org: ${organizationId}`);

  // Step 1: Get AWS credentials (shared across all methods)
  const connections = await storage.getCloudConnections(organizationId);
  const awsConnection = connections.find(c => c.provider === "aws" && c.status === "active");

  if (!awsConnection) {
    return { success: false, error: "No active AWS cloud connection found", attempts };
  }

  const credentials = await cloudIntegrationService.getConnectionCredentials(awsConnection.id);
  if (!credentials?.aws) {
    return { success: false, error: "AWS credentials not configured", attempts };
  }

  const targetRegion = (awsConnection as any).awsRegions?.[0] || "us-east-1";

  // Step 2: Check SSM availability
  console.log(`[AgentDeployment] Step 1: Checking SSM availability for ${instanceId}...`);
  const ssmCheck = await awsAdapter.checkSSMAvailability(credentials.aws, instanceId, targetRegion);

  // Step 3: Try SSM if available
  if (ssmCheck.available) {
    console.log(`[AgentDeployment] SSM available (status: ${ssmCheck.pingStatus}), attempting SSM deployment`);
    const ssmStart = Date.now();
    const ssmResult = await deployToAWS(instanceId, organizationId, serverUrl);
    attempts.push({
      method: "ssm",
      success: ssmResult.success,
      error: ssmResult.error,
      duration: Date.now() - ssmStart,
    });

    if (ssmResult.success) {
      console.log(`[AgentDeployment] SSM deployment succeeded`);
      return { ...ssmResult, attempts, methodUsed: "ssm" };
    }
    console.log(`[AgentDeployment] SSM deployment failed: ${ssmResult.error}, trying fallbacks...`);
  } else {
    console.log(`[AgentDeployment] SSM not available: ${ssmCheck.error}, skipping to fallback`);
    attempts.push({
      method: "ssm",
      success: false,
      error: `Skipped: ${ssmCheck.error}`,
      duration: 0,
    });
  }

  // Step 4: Try SSH fallback — find SSH credentials for this asset
  // Wrapped in try/catch so SSH lookup failures don't crash the entire deployment
  console.log(`[AgentDeployment] Step 2: Attempting SSH fallback...`);
  try {
    const allAssets = await storage.getCloudAssets(organizationId);
    const asset = allAssets.find(a => a.providerResourceId === instanceId);

    if (asset) {
      const sshCred = await storage.getSshCredentialForAsset(asset.id, organizationId);
      if (sshCred) {
        console.log(`[AgentDeployment] Found SSH credential ${sshCred.id} for asset, attempting SSH deployment`);
        const sshStart = Date.now();
        const sshResult = await deployViaSSHWithCredential(
          sshCred.id,
          instanceId,
          organizationId,
          serverUrl
        );
        attempts.push({
          method: "ssh",
          success: sshResult.success,
          error: sshResult.error,
          duration: Date.now() - sshStart,
        });

        if (sshResult.success) {
          console.log(`[AgentDeployment] SSH fallback succeeded`);
          return { ...sshResult, attempts, methodUsed: "ssh" };
        }
        console.log(`[AgentDeployment] SSH fallback failed: ${sshResult.error}`);
      } else {
        console.log(`[AgentDeployment] No SSH credentials available for asset ${asset.id}`);
        attempts.push({
          method: "ssh",
          success: false,
          error: "No SSH credentials available for this asset or organization",
          duration: 0,
        });
      }
    } else {
      console.log(`[AgentDeployment] Could not find cloud asset for instance ${instanceId}`);
      attempts.push({
        method: "ssh",
        success: false,
        error: "Cloud asset not found for SSH credential lookup",
        duration: 0,
      });
    }
  } catch (sshLookupErr: any) {
    console.log(`[AgentDeployment] SSH fallback lookup error: ${sshLookupErr.message}`);
    attempts.push({
      method: "ssh",
      success: false,
      error: `SSH lookup failed: ${sshLookupErr.message}`,
      duration: 0,
    });
  }

  // Step 5: EC2 Instance Connect (P2 — not yet implemented)
  attempts.push({
    method: "ec2-instance-connect",
    success: false,
    error: "EC2 Instance Connect not yet implemented",
    duration: 0,
  });

  // All methods failed
  const errorSummary = attempts
    .map(a => `${a.method}: ${a.error}`)
    .join("; ");
  console.log(`[AgentDeployment] All deployment methods failed: ${errorSummary}`);

  return {
    success: false,
    error: `All deployment methods failed — ${errorSummary}`,
    attempts,
  };
}

async function deployToAzure(
  instanceId: string,
  organizationId: string,
  serverUrl: string
): Promise<{ success: boolean; agentId?: string; error?: string }> {
  console.log(`[AgentDeployment] ========== AZURE RUN COMMAND DEPLOYMENT START ==========`);
  console.log(`[AgentDeployment] Target VM: ${instanceId}`);
  console.log(`[AgentDeployment] Organization: ${organizationId}`);
  console.log(`[AgentDeployment] Server URL (agent will connect to): ${serverUrl}`);
  
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
      expiresAt: new Date(Date.now() + DEPLOYMENT_CONFIG.TOKEN_EXPIRY_MS),
      name: `Azure deployment token for ${vmName}`,
    });
    console.log(`[AgentDeployment] Registration token created (expires in 1 hour)`);
    
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
  console.log(`[AgentDeployment] ========== GCP DEPLOYMENT START ==========`);
  console.log(`[AgentDeployment] Target Instance: ${instanceId}`);
  console.log(`[AgentDeployment] Organization: ${organizationId}`);
  console.log(`[AgentDeployment] Server URL (agent will connect to): ${serverUrl}`);
  
  try {
    // Get GCP credentials from cloud connection
    console.log(`[AgentDeployment] Step 1: Retrieving GCP cloud connection...`);
    const connections = await storage.getCloudConnections(organizationId);
    const gcpConnection = connections.find(c => c.provider === "gcp" && c.status === "active");
    
    if (!gcpConnection) {
      console.error(`[AgentDeployment] FAILED: No active GCP cloud connection found`);
      return { success: false, error: "No active GCP cloud connection found" };
    }
    console.log(`[AgentDeployment] Found GCP connection: ${gcpConnection.name} (ID: ${gcpConnection.id})`);
    
    // Get decrypted credentials using cloudService
    console.log(`[AgentDeployment] Step 2: Decrypting GCP credentials...`);
    const credentials = await cloudIntegrationService.getConnectionCredentials(gcpConnection.id);
    
    if (!credentials || !credentials.gcp) {
      console.error(`[AgentDeployment] FAILED: GCP credentials not configured or decryption failed`);
      return { success: false, error: "GCP credentials not configured or decryption failed" };
    }
    
    const gcpCreds = credentials.gcp;
    const projectId = gcpCreds.projectId || (gcpConnection.gcpProjectIds && gcpConnection.gcpProjectIds[0]);
    
    if (!projectId) {
      console.error(`[AgentDeployment] FAILED: GCP project ID not configured`);
      return { success: false, error: "GCP project ID not configured" };
    }
    console.log(`[AgentDeployment] Project ID: ${projectId}`);
    
    // Parse service account JSON to get credentials
    let serviceAccountCredentials: { client_email: string; private_key: string } | null = null;
    let useDefaultCredentials = false;
    
    if (gcpCreds.serviceAccountJson) {
      console.log(`[AgentDeployment] Step 3: Parsing service account JSON...`);
      try {
        const parsed = JSON.parse(gcpCreds.serviceAccountJson);
        if (!parsed.client_email || !parsed.private_key) {
          console.error(`[AgentDeployment] FAILED: Service account JSON missing required fields`);
          return { success: false, error: "GCP service account JSON missing required fields (client_email, private_key)" };
        }
        serviceAccountCredentials = parsed;
        console.log(`[AgentDeployment] Service account: ${parsed.client_email}`);
      } catch {
        console.error(`[AgentDeployment] FAILED: Invalid service account JSON format`);
        return { success: false, error: "Invalid GCP service account JSON format" };
      }
    } else if (gcpCreds.useWorkloadIdentity) {
      // Workload identity federation - use Application Default Credentials (ADC)
      console.log(`[AgentDeployment] Step 3: Checking for ADC (Workload Identity)...`);
      const hasADC = process.env.GOOGLE_APPLICATION_CREDENTIALS || 
                     process.env.GOOGLE_CLOUD_PROJECT ||
                     process.env.GCE_METADATA_HOST;
      if (!hasADC) {
        console.error(`[AgentDeployment] FAILED: No ADC available for workload identity`);
        return { success: false, error: "GCP Workload Identity Federation configured but no Application Default Credentials (ADC) available. Set GOOGLE_APPLICATION_CREDENTIALS or run on GCE." };
      }
      useDefaultCredentials = true;
      console.log(`[AgentDeployment] Using GCP Application Default Credentials for workload identity`);
    } else {
      console.error(`[AgentDeployment] FAILED: No GCP credentials configured`);
      return { success: false, error: "GCP credentials not configured - no service account JSON or workload identity" };
    }
    
    // Parse instanceId to extract zone and instance name
    // Expected format: zone/instanceName (required)
    console.log(`[AgentDeployment] Step 4: Parsing instance ID...`);
    const parts = instanceId.split("/");
    if (parts.length < 2) {
      console.error(`[AgentDeployment] FAILED: Invalid instance ID format. Expected 'zone/instanceName', got '${instanceId}'`);
      return { success: false, error: `Invalid GCP instance ID format: expected 'zone/instanceName', got '${instanceId}'` };
    }
    const zone = parts[0];
    const instanceName = parts[1];
    console.log(`[AgentDeployment] Zone: ${zone}, Instance: ${instanceName}`);
    
    // Generate registration token
    console.log(`[AgentDeployment] Step 5: Creating registration token...`);
    const registrationToken = generateRegistrationToken();
    const tokenHash = hashToken(registrationToken);
    
    // Create registration token in database
    await storage.createAgentRegistrationToken({
      id: randomUUID(),
      organizationId,
      tokenHash,
      expiresAt: new Date(Date.now() + DEPLOYMENT_CONFIG.TOKEN_EXPIRY_MS),
      name: `GCP deployment token for ${instanceName}`,
    });
    console.log(`[AgentDeployment] Registration token created (expires in 1 hour)`);
    
    // Build installation script
    console.log(`[AgentDeployment] Step 6: Building installation script...`);
    const script = buildInstallScript("linux", serverUrl, registrationToken);
    console.log(`[AgentDeployment] Installation script ready (${script.length} bytes)`);
    
    // Create GCP Compute client with credentials
    console.log(`[AgentDeployment] Step 7: Creating GCP Compute client...`);
    let computeClient: InstancesClient;
    let zoneOpsClient: ZoneOperationsClient;
    
    if (useDefaultCredentials) {
      computeClient = new InstancesClient({ projectId });
      zoneOpsClient = new ZoneOperationsClient({ projectId });
    } else if (serviceAccountCredentials) {
      computeClient = new InstancesClient({
        projectId,
        credentials: {
          client_email: serviceAccountCredentials.client_email,
          private_key: serviceAccountCredentials.private_key,
        },
      });
      zoneOpsClient = new ZoneOperationsClient({
        projectId,
        credentials: {
          client_email: serviceAccountCredentials.client_email,
          private_key: serviceAccountCredentials.private_key,
        },
      });
    } else {
      return { success: false, error: "No valid GCP credentials available" };
    }
    
    // Set startup-script metadata (this is the standard key that runs on boot)
    console.log(`[AgentDeployment] Step 8: Setting startup-script metadata...`);
    
    // Get current instance to read existing metadata
    const [instance] = await computeClient.get({
      project: projectId,
      zone,
      instance: instanceName,
    });
    
    const currentMetadata = instance.metadata?.items || [];
    
    // Remove any existing odinforge scripts and set as startup-script
    const newMetadata = currentMetadata.filter(item => 
      item.key !== "startup-script" && 
      item.key !== "odinforge-install-script"
    );
    
    // Use startup-script key - this is executed by the GCP guest agent on boot
    newMetadata.push({
      key: "startup-script",
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
    console.log(`[AgentDeployment] Startup script metadata set successfully`);
    
    // Now reset the instance to trigger immediate execution
    console.log(`[AgentDeployment] Step 9: Resetting VM to trigger immediate script execution...`);
    console.log(`[AgentDeployment] NOTE: This will briefly restart the VM (typically 30-60 seconds)`);
    
    let executedImmediately = false;
    
    try {
      const [resetOperation] = await computeClient.reset({
        project: projectId,
        zone,
        instance: instanceName,
      });
      
      console.log(`[AgentDeployment] Reset operation started: ${resetOperation.name}`);
      
      // Wait for reset to complete using consistent config
      const maxWaitTime = DEPLOYMENT_CONFIG.VM_RESET_TIMEOUT_MS;
      const pollInterval = DEPLOYMENT_CONFIG.POLL_INTERVAL_MS;
      let elapsed = 0;
      
      while (elapsed < maxWaitTime) {
        await new Promise(resolve => setTimeout(resolve, pollInterval));
        elapsed += pollInterval;
        
        try {
          const [opStatus] = await zoneOpsClient.get({
            project: projectId,
            zone,
            operation: resetOperation.name!,
          });
          
          if (opStatus.status === "DONE") {
            if (opStatus.error) {
              console.error(`[AgentDeployment] Reset operation completed with error:`, opStatus.error);
            } else {
              console.log(`[AgentDeployment] VM reset completed successfully after ${elapsed/1000}s`);
              executedImmediately = true;
            }
            break;
          } else {
            console.log(`[AgentDeployment] Waiting for reset... (${elapsed/1000}s, status: ${opStatus.status})`);
          }
        } catch (pollError: any) {
          console.log(`[AgentDeployment] Polling error (will retry): ${pollError.message}`);
        }
      }
      
      if (elapsed >= maxWaitTime && !executedImmediately) {
        console.log(`[AgentDeployment] Reset operation timed out after ${maxWaitTime/1000}s`);
        console.log(`[AgentDeployment] The reset may still complete - check GCP Console for status`);
      }
    } catch (resetError: any) {
      console.error(`[AgentDeployment] VM reset failed: ${resetError.message}`);
      console.log(`[AgentDeployment] The startup script is set but won't run until the VM is manually restarted`);
      console.log(`[AgentDeployment] To trigger manually: gcloud compute instances reset ${instanceName} --zone=${zone}`);
    }
    
    console.log(`[AgentDeployment] ========== GCP DEPLOYMENT COMPLETE ==========`);
    if (executedImmediately) {
      console.log(`[AgentDeployment] VM was reset and startup script will execute shortly.`);
      console.log(`[AgentDeployment] Agent should check in within 1-2 minutes.`);
    } else {
      console.log(`[AgentDeployment] Startup script is set but VM reset may not have completed.`);
      console.log(`[AgentDeployment] If agent doesn't check in, manually reset the VM from GCP Console.`);
    }
    
    const agentId = `gcp-${instanceName.slice(-12)}`;
    return { 
      success: true, 
      agentId,
    };
    
  } catch (error: any) {
    console.error(`[AgentDeployment] ========== GCP DEPLOYMENT FAILED ==========`);
    console.error(`[AgentDeployment] Error:`, error);
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
  const { deploymentId, provider, instanceIds, tenantId, organizationId, deploymentMethod, serverUrl, sshCredentialId } = job.data;

  console.log(`[AgentDeployment] ================================================================`);
  console.log(`[AgentDeployment] AGENT DEPLOYMENT JOB STARTED`);
  console.log(`[AgentDeployment] ----------------------------------------------------------------`);
  console.log(`[AgentDeployment] Deployment ID: ${deploymentId}`);
  console.log(`[AgentDeployment] Provider: ${provider}`);
  console.log(`[AgentDeployment] Deployment Method: ${deploymentMethod || "cloud-api (default)"}`);
  console.log(`[AgentDeployment] SSH Credential: ${sshCredentialId || "none (will use provider API)"}`);
  console.log(`[AgentDeployment] Organization: ${organizationId}`);
  console.log(`[AgentDeployment] Instance Count: ${instanceIds.length}`);
  console.log(`[AgentDeployment] Instances: ${instanceIds.join(", ")}`);
  console.log(`[AgentDeployment] Server URL: ${serverUrl || process.env.PUBLIC_ODINFORGE_URL || "not configured"}`);
  console.log(`[AgentDeployment] ----------------------------------------------------------------`);

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
      } else if (sshCredentialId) {
        // SSH credentials provided - use SSH for immediate execution (like AWS/Azure)
        console.log(`[AgentDeployment] Using SSH with provided credentials for ${provider}`);
        result = await deployViaSSHWithCredential(sshCredentialId, instanceId, organizationId, deployServerUrl);
      } else {
        // Default to cloud API method (AWS uses fallback chain: SSM → SSH → EC2 Instance Connect)
        switch (provider) {
          case "aws": {
            const awsResult = await deployToAWSWithFallback(instanceId, organizationId, deployServerUrl);
            result = { success: awsResult.success, agentId: awsResult.agentId, error: awsResult.error };
            if (awsResult.attempts.length > 0) {
              console.log(`[AgentDeployment] AWS fallback chain: ${awsResult.attempts.map(a => `${a.method}=${a.success ? "OK" : "FAIL"}(${a.duration}ms)`).join(", ")}`);
              if (awsResult.methodUsed) {
                console.log(`[AgentDeployment] Successful method: ${awsResult.methodUsed}`);
              }
            }
            break;
          }
          case "azure":
            result = await deployToAzure(instanceId, organizationId, deployServerUrl);
            break;
          case "gcp":
            // GCP uses startup-script + VM reset when no SSH credentials are provided
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
