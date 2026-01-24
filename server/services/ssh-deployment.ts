import { Client, ConnectConfig } from "ssh2";
import { randomUUID, createHash } from "crypto";
import { storage } from "../storage";
import { secretsService } from "./secrets";

function generateSecureToken(): string {
  return randomUUID() + "-" + randomUUID();
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export interface SSHDeploymentConfig {
  host: string;
  port: number;
  username: string;
  privateKey?: string;
  password?: string;
  useSudo: boolean;
  sudoPassword?: string;
}

export interface SSHDeploymentResult {
  success: boolean;
  agentId?: string;
  errorMessage?: string;
  output?: string;
  exitCode?: number;
}

export interface SSHConnectionTestResult {
  success: boolean;
  error?: string;
  serverInfo?: {
    hostname?: string;
    platform?: string;
    arch?: string;
  };
}

class SSHDeploymentService {
  async testConnection(config: SSHDeploymentConfig): Promise<SSHConnectionTestResult> {
    return new Promise((resolve) => {
      const client = new Client();
      const timeout = setTimeout(() => {
        client.end();
        resolve({ success: false, error: "Connection timeout (30s)" });
      }, 30000);

      client.on("ready", () => {
        client.exec("uname -a && hostname", (err, stream) => {
          if (err) {
            clearTimeout(timeout);
            client.end();
            resolve({ success: false, error: err.message });
            return;
          }

          let output = "";
          stream.on("data", (data: Buffer) => {
            output += data.toString();
          });
          stream.on("close", (code: number) => {
            clearTimeout(timeout);
            client.end();
            
            const lines = output.trim().split("\n");
            const unameInfo = lines[0] || "";
            const hostname = lines[1] || "";
            
            const parts = unameInfo.split(" ");
            resolve({
              success: true,
              serverInfo: {
                hostname: hostname.trim(),
                platform: parts[0] || "unknown",
                arch: parts[parts.length - 2] || "unknown",
              },
            });
          });
        });
      });

      client.on("error", (err) => {
        clearTimeout(timeout);
        resolve({ success: false, error: err.message });
      });

      const connectConfig: ConnectConfig = {
        host: config.host,
        port: config.port,
        username: config.username,
        readyTimeout: 30000,
      };

      if (config.privateKey) {
        connectConfig.privateKey = config.privateKey;
      } else if (config.password) {
        connectConfig.password = config.password;
      }

      try {
        client.connect(connectConfig);
      } catch (err: any) {
        clearTimeout(timeout);
        resolve({ success: false, error: err.message });
      }
    });
  }

  async deployAgent(
    config: SSHDeploymentConfig,
    agentConfig: {
      serverUrl: string;
      registrationToken: string;
      organizationId: string;
      platform?: string;
    }
  ): Promise<SSHDeploymentResult> {
    return new Promise((resolve) => {
      const client = new Client();
      const timeout = setTimeout(() => {
        client.end();
        resolve({ success: false, errorMessage: "Deployment timeout (300s)" });
      }, 300000);

      client.on("ready", () => {
        console.log(`[SSH] Connected to ${config.host}`);
        
        this.executeDeploymentCommands(client, config, agentConfig)
          .then((result) => {
            clearTimeout(timeout);
            client.end();
            resolve(result);
          })
          .catch((err) => {
            clearTimeout(timeout);
            client.end();
            resolve({ success: false, errorMessage: err.message });
          });
      });

      client.on("error", (err) => {
        clearTimeout(timeout);
        console.log(`[SSH] Connection error to ${config.host}: ${err.message}`);
        resolve({ success: false, errorMessage: `SSH connection failed: ${err.message}` });
      });

      const connectConfig: ConnectConfig = {
        host: config.host,
        port: config.port,
        username: config.username,
        readyTimeout: 30000,
      };

      if (config.privateKey) {
        connectConfig.privateKey = config.privateKey;
      } else if (config.password) {
        connectConfig.password = config.password;
      }

      try {
        console.log(`[SSH] Connecting to ${config.host}:${config.port} as ${config.username}`);
        client.connect(connectConfig);
      } catch (err: any) {
        clearTimeout(timeout);
        resolve({ success: false, errorMessage: `Connection setup failed: ${err.message}` });
      }
    });
  }

  private async executeDeploymentCommands(
    client: Client,
    config: SSHDeploymentConfig,
    agentConfig: {
      serverUrl: string;
      registrationToken: string;
      organizationId: string;
      platform?: string;
    }
  ): Promise<SSHDeploymentResult> {
    const agentId = `agent-ssh-${randomUUID().slice(0, 8)}`;
    
    const detectPlatformCmd = "uname -s -m";
    const platformInfo = await this.execCommand(client, detectPlatformCmd);
    
    let platform = "linux";
    let arch = "amd64";
    
    if (platformInfo.output) {
      const parts = platformInfo.output.trim().toLowerCase().split(/\s+/);
      if (parts[0] === "darwin") platform = "darwin";
      if (parts[1]?.includes("arm") || parts[1]?.includes("aarch")) arch = "arm64";
    }
    
    const binaryName = `odinforge-agent-${platform}-${arch}`;
    const installDir = "/opt/odinforge";
    const serverUrl = agentConfig.serverUrl;
    const registrationToken = agentConfig.registrationToken;
    
    const installScript = `
set -e
echo "[OdinForge] Starting agent installation..."

# Create installation directory
${config.useSudo ? "sudo " : ""}mkdir -p ${installDir}

# Download the agent binary
echo "[OdinForge] Downloading agent binary..."
cd /tmp
curl -fsSL "${serverUrl}/api/agents/download/${binaryName}" -o ${binaryName} || wget -q "${serverUrl}/api/agents/download/${binaryName}" -O ${binaryName}

# Make executable and move to install directory
chmod +x ${binaryName}
${config.useSudo ? "sudo " : ""}mv ${binaryName} ${installDir}/odinforge-agent

# Create configuration
echo "[OdinForge] Creating configuration..."
${config.useSudo ? "sudo " : ""}tee ${installDir}/agent.conf > /dev/null << 'EOF'
SERVER_URL=${serverUrl}
REGISTRATION_TOKEN=${registrationToken}
ORGANIZATION_ID=${agentConfig.organizationId}
AGENT_ID=${agentId}
EOF

# Create systemd service if available
if command -v systemctl &> /dev/null; then
  echo "[OdinForge] Creating systemd service..."
  ${config.useSudo ? "sudo " : ""}tee /etc/systemd/system/odinforge-agent.service > /dev/null << 'EOF'
[Unit]
Description=OdinForge Security Agent
After=network.target

[Service]
Type=simple
EnvironmentFile=${installDir}/agent.conf
ExecStart=${installDir}/odinforge-agent
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

  ${config.useSudo ? "sudo " : ""}systemctl daemon-reload
  ${config.useSudo ? "sudo " : ""}systemctl enable odinforge-agent
  ${config.useSudo ? "sudo " : ""}systemctl start odinforge-agent
  echo "[OdinForge] Agent installed and started as systemd service"
else
  # Fallback: Start agent directly in background
  echo "[OdinForge] Starting agent in background..."
  cd ${installDir}
  nohup ./odinforge-agent > /var/log/odinforge-agent.log 2>&1 &
  echo "[OdinForge] Agent started in background"
fi

echo "[OdinForge] Installation complete - Agent ID: ${agentId}"
`;

    console.log(`[SSH] Executing installation script on ${config.host}`);
    const result = await this.execCommand(client, installScript);
    
    if (result.exitCode === 0) {
      console.log(`[SSH] Agent deployed successfully on ${config.host}: ${agentId}`);
      return {
        success: true,
        agentId,
        output: result.output,
        exitCode: result.exitCode,
      };
    } else {
      console.log(`[SSH] Agent deployment failed on ${config.host}: exit code ${result.exitCode}`);
      return {
        success: false,
        errorMessage: `Installation failed with exit code ${result.exitCode}`,
        output: result.output,
        exitCode: result.exitCode,
      };
    }
  }

  private execCommand(
    client: Client,
    command: string
  ): Promise<{ output: string; exitCode: number }> {
    return new Promise((resolve, reject) => {
      client.exec(command, (err, stream) => {
        if (err) {
          reject(err);
          return;
        }

        let output = "";
        let stderr = "";

        stream.on("data", (data: Buffer) => {
          output += data.toString();
        });

        stream.stderr.on("data", (data: Buffer) => {
          stderr += data.toString();
        });

        stream.on("close", (code: number) => {
          resolve({
            output: output + (stderr ? `\nSTDERR:\n${stderr}` : ""),
            exitCode: code,
          });
        });
      });
    });
  }

  async getDecryptedCredentials(
    credentialId: string
  ): Promise<SSHDeploymentConfig | null> {
    const credential = await storage.getSshCredential(credentialId);
    if (!credential) return null;

    let privateKey: string | undefined;
    let password: string | undefined;

    try {
      if (credential.encryptedPrivateKey) {
        privateKey = secretsService.decryptField(
          credential.encryptedPrivateKey,
          credential.encryptionKeyId
        );
      }
      if (credential.encryptedPassword) {
        password = secretsService.decryptField(
          credential.encryptedPassword,
          credential.encryptionKeyId
        );
      }
    } catch (err) {
      console.error(`[SSH] Failed to decrypt credentials: ${err}`);
      return null;
    }

    return {
      host: credential.host || "",
      port: credential.port || 22,
      username: credential.username,
      privateKey,
      password,
      useSudo: credential.useSudo ?? true,
    };
  }

  async deployToAsset(
    assetId: string,
    organizationId: string,
    serverUrl: string
  ): Promise<SSHDeploymentResult> {
    const asset = await storage.getDiscoveredAsset(assetId);
    if (!asset) {
      return { success: false, errorMessage: "Asset not found" };
    }

    const sshCred = await storage.getSshCredentialForAsset(assetId, organizationId);
    if (!sshCred) {
      return { success: false, errorMessage: "No SSH credentials configured for this asset" };
    }

    const config = await this.getDecryptedCredentials(sshCred.id);
    if (!config) {
      return { success: false, errorMessage: "Failed to decrypt SSH credentials" };
    }

    if (!config.host) {
      const ips = asset.ipAddresses as string[] | null;
      config.host = asset.hostname || (ips && ips[0]) || "";
    }

    if (!config.host) {
      return { success: false, errorMessage: "No host address available for asset" };
    }

    const rawToken = generateSecureToken();
    const tokenHash = hashToken(rawToken);
    const tokenId = `regtoken-${randomUUID().slice(0, 8)}`;
    
    await storage.createAgentRegistrationToken({
      id: tokenId,
      tokenHash,
      organizationId,
      description: `SSH deployment to ${asset.displayName || asset.assetIdentifier}`,
      expiresAt: new Date(Date.now() + 3600000),
    });

    const result = await this.deployAgent(config, {
      serverUrl,
      registrationToken: rawToken,
      organizationId,
      platform: asset.operatingSystem || undefined,
    });

    await storage.updateSshCredentialLastUsed(sshCred.id);

    return result;
  }
}

export const sshDeploymentService = new SSHDeploymentService();
