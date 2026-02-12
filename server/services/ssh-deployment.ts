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
      apiKey: string;
      agentId: string;
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
      apiKey: string;
      agentId: string;
      organizationId: string;
      platform?: string;
    }
  ): Promise<SSHDeploymentResult> {
    const detectPlatformCmd = "uname -s -m";
    const platformInfo = await this.execCommand(client, detectPlatformCmd);

    let platform = "linux";
    let arch = "amd64";

    if (platformInfo.output) {
      const parts = platformInfo.output.trim().toLowerCase().split(/\s+/);
      if (parts[0] === "darwin") platform = "darwin";
      if (parts[1]?.includes("arm") || parts[1]?.includes("aarch")) arch = "arm64";
    }

    const platformSlug = `${platform}-${arch}`; // e.g. "linux-amd64" — matches /api/agents/download/:platform
    const serverUrl = agentConfig.serverUrl;
    const apiKey = agentConfig.apiKey;
    const agentId = agentConfig.agentId;
    const sudo = config.useSudo ? "sudo " : "";

    // Use the agent's own install command — identical to SSM deployment.
    // The Go binary creates proper YAML config, systemd service, user, and permissions.
    const installScript = `
set -eo pipefail
echo "[OdinForge] Starting agent installation via SSH..."
echo "[OdinForge] Server URL: ${serverUrl}"
echo "[OdinForge] Platform slug: ${platformSlug}"
echo "[OdinForge] Platform: $(uname -s -m)"

# Download the agent binary
echo "[OdinForge] Downloading agent binary..."
DOWNLOAD_URL="${serverUrl}/api/agents/download/${platformSlug}"
echo "[OdinForge] Download URL: $DOWNLOAD_URL"

# Download with retry logic (ngrok tunnels can be flaky)
DOWNLOAD_OK=0
for ATTEMPT in 1 2 3; do
  echo "[OdinForge] Download attempt $ATTEMPT..."
  HTTP_CODE=$(curl -sL -H "ngrok-skip-browser-warning: true" -H "User-Agent: OdinForge-Agent/1.0" -w "%{http_code}" -o /tmp/odinforge-agent "$DOWNLOAD_URL" 2>/dev/null) || true
  echo "[OdinForge] HTTP response code: $HTTP_CODE"

  if [ "$HTTP_CODE" = "200" ]; then
    FILE_SIZE=$(stat -c%s /tmp/odinforge-agent 2>/dev/null || stat -f%z /tmp/odinforge-agent 2>/dev/null || echo "0")
    echo "[OdinForge] Downloaded file size: $FILE_SIZE bytes"
    if [ "$FILE_SIZE" -gt 1000000 ]; then
      DOWNLOAD_OK=1
      break
    fi
    echo "[OdinForge] File too small, likely error page. Content:"
    head -c 200 /tmp/odinforge-agent 2>/dev/null || true
    echo ""
  else
    echo "[OdinForge] Download failed with HTTP $HTTP_CODE"
    if [ -f /tmp/odinforge-agent ]; then
      echo "[OdinForge] Response body:"
      head -c 300 /tmp/odinforge-agent 2>/dev/null || true
      echo ""
    fi
  fi

  if [ "$ATTEMPT" -lt 3 ]; then
    echo "[OdinForge] Retrying in 5 seconds..."
    sleep 5
  fi
done

if [ "$DOWNLOAD_OK" -ne 1 ]; then
  echo "[OdinForge] ERROR: Failed to download agent binary after 3 attempts"
  exit 1
fi

FILE_TYPE=$(file /tmp/odinforge-agent 2>/dev/null || echo "unknown")
echo "[OdinForge] File type: $FILE_TYPE"
chmod +x /tmp/odinforge-agent

# Stop existing service before installing (prevents file-in-use issues)
${sudo}systemctl stop odinforge-agent 2>/dev/null || true

# Use the agent's own installer (creates YAML config, systemd service, user, permissions)
echo "[OdinForge] Running agent installer..."
${sudo}/tmp/odinforge-agent install --server-url "${serverUrl}" --api-key "${apiKey}" --tenant-id "${agentConfig.organizationId}" --force

# Fix config permissions so the agent service can read it
${sudo}chmod 644 /etc/odinforge/agent.yaml 2>/dev/null || true
${sudo}chmod 755 /etc/odinforge 2>/dev/null || true
${sudo}chown -R odinforge:odinforge /etc/odinforge 2>/dev/null || true
${sudo}chown -R odinforge:odinforge /var/lib/odinforge-agent 2>/dev/null || true

# Reload systemd and restart to pick up new binary + config
${sudo}systemctl daemon-reload 2>/dev/null || true
${sudo}systemctl restart odinforge-agent 2>/dev/null || true
sleep 3

echo "[OdinForge] Config file:"
ls -la /etc/odinforge/agent.yaml 2>/dev/null || echo "[OdinForge] WARNING: Config file not found"

if command -v systemctl &>/dev/null; then
  echo "[OdinForge] Service status:"
  ${sudo}systemctl is-active odinforge-agent && echo "[OdinForge] Service is ACTIVE" || {
    echo "[OdinForge] WARNING: Service not active. Checking logs..."
    ${sudo}journalctl -u odinforge-agent -n 30 --no-pager 2>/dev/null || true
  }
fi

# Clean up
rm -f /tmp/odinforge-agent

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
      console.log(`[SSH] Full output:\n${result.output}`);
      // Extract the last meaningful error line for the UI error message
      const outputLines = result.output.trim().split("\n").filter((l: string) => l.trim());
      const lastLines = outputLines.slice(-5).join(" | ");
      return {
        success: false,
        errorMessage: `Installation failed (exit ${result.exitCode}): ${lastLines}`,
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

    // Use enterprise agent provisioning
    const { agentManagementService } = await import("./agent-management");

    const provisionResult = await agentManagementService.provisionAgent({
      hostname: asset.hostname || asset.assetIdentifier || config.host,
      platform: (asset.operatingSystem?.toLowerCase() as "linux" | "windows" | "darwin") || "linux",
      architecture: "x86_64",
      organizationId,
      environment: "production",
      tags: [
        "ssh-deployed",
        `asset:${asset.id}`,
      ],
    });

    const result = await this.deployAgent(config, {
      serverUrl,
      apiKey: provisionResult.apiKey,
      agentId: provisionResult.agentId,
      organizationId,
      platform: asset.operatingSystem || undefined,
    });

    await storage.updateSshCredentialLastUsed(sshCred.id);

    return result;
  }
}

export const sshDeploymentService = new SSHDeploymentService();
