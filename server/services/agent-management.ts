import { storage } from "../storage";
import { randomBytes } from "crypto";
import bcrypt from "bcrypt";

/**
 * Enterprise Agent Management Service
 * Handles complete agent lifecycle: provisioning, authentication, health monitoring
 */

export interface AgentProvisionResult {
  agentId: string;
  apiKey: string;
  installCommand: string;
  configFile: string;
  expiresAt?: Date;
}

export interface AgentHealthStatus {
  agentId: string;
  isHealthy: boolean;
  lastHeartbeat: Date | null;
  lastTelemetry: Date | null;
  uptimeSeconds: number;
  issues: string[];
  recommendations: string[];
}

export class AgentManagementService {
  private readonly HEARTBEAT_TIMEOUT_SECONDS = 300; // 5 minutes
  private readonly STALE_AGENT_HOURS = 24;

  /**
   * Generate a secure API key for agent authentication
   */
  private generateSecureApiKey(): string {
    // Format: odin_agent_<32 chars hex>
    const randomPart = randomBytes(16).toString("hex");
    return `odin_agent_${randomPart}`;
  }

  /**
   * Provision a new agent with all required credentials
   * This is the ONLY method needed for deploying a new agent
   */
  async provisionAgent(params: {
    hostname: string;
    platform: "linux" | "windows" | "darwin";
    architecture: string;
    organizationId?: string;
    environment?: string;
    tags?: string[];
  }): Promise<AgentProvisionResult> {
    const { hostname, platform, architecture, organizationId = "default", environment = "production", tags = [] } = params;

    // Generate secure API key
    const apiKey = this.generateSecureApiKey();
    const apiKeyHash = await bcrypt.hash(apiKey, 10);

    // Create agent in database
    const agent = await storage.createEndpointAgent({
      agentName: hostname,
      hostname,
      platform,
      platformVersion: "", // Will be updated on first heartbeat
      architecture,
      organizationId,
      apiKey: "", // Never store plaintext
      apiKeyHash,
      capabilities: ["telemetry", "vulnerability_scan"],
      status: "pending" as any,
      environment,
      tags,
    });

    // Get server URL from environment
    const serverUrl = process.env.ODINFORGE_SERVER_URL || process.env.PUBLIC_URL || "http://localhost:5000";

    // Generate platform-specific installation command
    const installCommand = this.generateInstallCommand(serverUrl, agent.id, apiKey, platform);

    // Generate configuration file content
    const configFile = this.generateConfigFile(serverUrl, agent.id, apiKey);

    return {
      agentId: agent.id,
      apiKey,
      installCommand,
      configFile,
    };
  }

  /**
   * Generate platform-specific installation command
   */
  private generateInstallCommand(serverUrl: string, agentId: string, apiKey: string, platform: string): string {
    const escapedApiKey = apiKey.replace(/'/g, "'\\''");

    if (platform === "windows") {
      return `# PowerShell (Run as Administrator)
$env:ODINFORGE_SERVER="${serverUrl}"
$env:ODINFORGE_AGENT_ID="${agentId}"
$env:ODINFORGE_API_KEY="${escapedApiKey}"
irm ${serverUrl}/api/agents/install.ps1 | iex`;
    } else {
      // Linux/macOS
      return `# Run as root
export ODINFORGE_SERVER="${serverUrl}"
export ODINFORGE_AGENT_ID="${agentId}"
export ODINFORGE_API_KEY="${escapedApiKey}"
curl -sSL ${serverUrl}/api/agents/install.sh | bash`;
    }
  }

  /**
   * Generate agent configuration file
   */
  private generateConfigFile(serverUrl: string, agentId: string, apiKey: string): string {
    return `# OdinForge Agent Configuration
# Generated: ${new Date().toISOString()}

[server]
url = "${serverUrl}"
timeout = 30
retry_attempts = 3
retry_delay = 5

[auth]
mode = "api_key"
agent_id = "${agentId}"
api_key = "${apiKey}"

[telemetry]
enabled = true
interval = 60
batch_size = 10

[heartbeat]
enabled = true
interval = 60

[security]
verify_tls = true
# For development/testing with self-signed certs:
# verify_tls = false

[logging]
level = "info"
# Options: debug, info, warn, error
`;
  }

  /**
   * Check agent health and return detailed status
   */
  async checkAgentHealth(agentId: string): Promise<AgentHealthStatus> {
    const agent = await storage.getEndpointAgent(agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found`);
    }

    const now = new Date();
    const issues: string[] = [];
    const recommendations: string[] = [];

    // Check heartbeat freshness
    const lastHeartbeat = agent.lastHeartbeat ? new Date(agent.lastHeartbeat) : null;
    const heartbeatAge = lastHeartbeat ? (now.getTime() - lastHeartbeat.getTime()) / 1000 : Infinity;
    const isHeartbeatHealthy = heartbeatAge < this.HEARTBEAT_TIMEOUT_SECONDS;

    if (!isHeartbeatHealthy) {
      issues.push(`No heartbeat for ${Math.floor(heartbeatAge / 60)} minutes`);
      if (heartbeatAge > 3600) {
        recommendations.push("Agent may need to be restarted or redeployed");
      } else {
        recommendations.push("Check agent logs and network connectivity");
      }
    }

    // Check telemetry freshness
    const lastTelemetry = agent.lastTelemetry ? new Date(agent.lastTelemetry) : null;
    const telemetryAge = lastTelemetry ? (now.getTime() - lastTelemetry.getTime()) / 1000 : Infinity;

    if (telemetryAge > this.HEARTBEAT_TIMEOUT_SECONDS && lastHeartbeat) {
      issues.push("Heartbeat present but no telemetry data");
      recommendations.push("Check agent telemetry configuration");
    }

    // Check agent version
    if (!agent.agentVersion) {
      issues.push("Agent version not reported");
      recommendations.push("Agent may be running an old version or failed to initialize");
    }

    // Calculate uptime
    const registeredAt = new Date(agent.registeredAt || agent.createdAt);
    const uptimeSeconds = (now.getTime() - registeredAt.getTime()) / 1000;

    const isHealthy = issues.length === 0 && isHeartbeatHealthy;

    return {
      agentId,
      isHealthy,
      lastHeartbeat,
      lastTelemetry,
      uptimeSeconds,
      issues,
      recommendations,
    };
  }

  /**
   * Auto-recover unhealthy agents
   */
  async autoRecoverAgent(agentId: string): Promise<{ success: boolean; message: string }> {
    const health = await this.checkAgentHealth(agentId);

    if (health.isHealthy) {
      return { success: true, message: "Agent is healthy, no recovery needed" };
    }

    // For agents that haven't connected in 24+ hours, mark for redeployment
    const hoursSinceHeartbeat = health.lastHeartbeat
      ? (Date.now() - health.lastHeartbeat.getTime()) / (1000 * 60 * 60)
      : Infinity;

    if (hoursSinceHeartbeat > this.STALE_AGENT_HOURS) {
      await storage.updateEndpointAgent(agentId, {
        status: "offline" as any,
        tags: [...(await storage.getEndpointAgent(agentId))!.tags, "needs-redeployment"],
      });

      return {
        success: false,
        message: `Agent marked for redeployment (offline for ${Math.floor(hoursSinceHeartbeat)} hours)`,
      };
    }

    // For recently-seen agents, just mark as needing attention
    return {
      success: false,
      message: `Agent unhealthy: ${health.issues.join(", ")}. ${health.recommendations.join(". ")}`,
    };
  }

  /**
   * Rotate agent API key (for security best practices)
   */
  async rotateApiKey(agentId: string): Promise<{ newApiKey: string; configFile: string }> {
    const agent = await storage.getEndpointAgent(agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found`);
    }

    // Generate new API key
    const newApiKey = this.generateSecureApiKey();
    const newApiKeyHash = await bcrypt.hash(newApiKey, 10);

    // Update agent
    await storage.updateEndpointAgent(agentId, {
      apiKeyHash: newApiKeyHash,
    });

    // Generate new config file
    const serverUrl = process.env.ODINFORGE_SERVER_URL || process.env.PUBLIC_URL || "http://localhost:5000";
    const configFile = this.generateConfigFile(serverUrl, agentId, newApiKey);

    return {
      newApiKey,
      configFile,
    };
  }

  /**
   * Bulk health check for all agents
   */
  async checkAllAgentsHealth(): Promise<{
    healthy: number;
    unhealthy: number;
    total: number;
    details: AgentHealthStatus[];
  }> {
    const agents = await storage.getEndpointAgents();
    const healthChecks = await Promise.all(
      agents.map(agent => this.checkAgentHealth(agent.id))
    );

    const healthy = healthChecks.filter(h => h.isHealthy).length;
    const unhealthy = healthChecks.length - healthy;

    return {
      healthy,
      unhealthy,
      total: healthChecks.length,
      details: healthChecks,
    };
  }
}

export const agentManagementService = new AgentManagementService();
