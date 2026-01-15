import * as net from "net";
import type { CredentialProbeConfig, ProbeResult } from "./probe-types";
import { createErrorProbeResult, determineVerdict, DEFAULT_PORTS, DEFAULT_CREDENTIALS } from "./probe-types";

export interface CredentialProbeResult extends ProbeResult {
  protocol: string;
  defaultCredentialsFound: boolean;
  successfulCredentials: Array<{ username: string; password: string }>;
  serviceBanner?: string;
  attemptedCount: number;
}

export class CredentialProbe {
  private config: Required<CredentialProbeConfig>;
  private timeout: number;

  constructor(config: CredentialProbeConfig) {
    const port = config.port || DEFAULT_PORTS[config.service] || 22;
    this.config = {
      host: config.host,
      port,
      timeout: config.timeout || 5000,
      organizationId: config.organizationId || "",
      evaluationId: config.evaluationId || "",
      service: config.service,
      customCredentials: config.customCredentials || [],
    };
    this.timeout = this.config.timeout;
  }

  async probe(): Promise<CredentialProbeResult> {
    const startTime = Date.now();
    
    const credentials = this.config.customCredentials.length > 0
      ? this.config.customCredentials
      : DEFAULT_CREDENTIALS[this.config.service] || [];

    const successfulCreds: Array<{ username: string; password: string }> = [];
    let serviceBanner: string | undefined;
    let attemptedCount = 0;

    try {
      serviceBanner = await this.getBanner();
      
      for (const cred of credentials) {
        attemptedCount++;
        const result = await this.testCredential(cred.username, cred.password);
        if (result.success) {
          successfulCreds.push(cred);
          break;
        }
      }

      const vulnerable = successfulCreds.length > 0;
      const confidence = vulnerable ? 95 : 0;
      const executionTimeMs = Date.now() - startTime;

      return {
        vulnerable,
        confidence,
        verdict: determineVerdict(confidence),
        protocol: this.getProtocol(),
        service: this.config.service,
        technique: "default_credential_check",
        evidence: vulnerable
          ? `Default credentials found: ${successfulCreds.map(c => `${c.username}:${this.maskPassword(c.password)}`).join(", ")}`
          : `Tested ${attemptedCount} credential combinations - no default credentials found`,
        details: {
          targetHost: this.config.host,
          targetPort: this.config.port,
          banner: serviceBanner,
          attemptedCredentials: credentials.map(c => c.username),
          successfulCredential: successfulCreds.length > 0 ? `${successfulCreds[0].username}:***` : undefined,
        },
        recommendations: this.generateRecommendations(vulnerable),
        executionTimeMs,
        defaultCredentialsFound: vulnerable,
        successfulCredentials: successfulCreds.map(c => ({ username: c.username, password: "***masked***" })),
        serviceBanner,
        attemptedCount,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      return {
        ...createErrorProbeResult(this.getProtocol(), this.config.service, this.config.host, this.config.port, errorMessage),
        defaultCredentialsFound: false,
        successfulCredentials: [],
        attemptedCount,
        protocol: this.getProtocol(),
      } as CredentialProbeResult;
    }
  }

  private getProtocol(): string {
    switch (this.config.service) {
      case "ssh": return "ssh";
      case "ftp": return "ftp";
      case "telnet": return "telnet";
      case "mysql": return "mysql";
      case "postgresql": return "postgresql";
      case "redis": return "redis";
      case "mongodb": return "mongodb";
      default: return "tcp";
    }
  }

  private async getBanner(): Promise<string | undefined> {
    return new Promise((resolve) => {
      const socket = net.createConnection({
        host: this.config.host,
        port: this.config.port,
        timeout: this.timeout,
      });

      const timeoutId = setTimeout(() => {
        socket.destroy();
        resolve(undefined);
      }, 3000);

      socket.on("data", (data) => {
        clearTimeout(timeoutId);
        socket.destroy();
        resolve(data.toString().trim().substring(0, 200));
      });

      socket.on("error", () => {
        clearTimeout(timeoutId);
        resolve(undefined);
      });

      socket.on("connect", () => {
        if (this.config.service === "ftp") {
        } else if (this.config.service === "redis") {
          socket.write("INFO\r\n");
        }
      });
    });
  }

  private async testCredential(username: string, password: string): Promise<{ success: boolean; error?: string }> {
    switch (this.config.service) {
      case "ftp":
        return this.testFtp(username, password);
      case "redis":
        return this.testRedis(password);
      case "telnet":
        return this.testTelnet(username, password);
      default:
        return this.testGenericTcp(username, password);
    }
  }

  private async testFtp(username: string, password: string): Promise<{ success: boolean; error?: string }> {
    return new Promise((resolve) => {
      const socket = net.createConnection({
        host: this.config.host,
        port: this.config.port,
        timeout: this.timeout,
      });

      let step = 0;
      let responseBuffer = "";

      const timeoutId = setTimeout(() => {
        socket.destroy();
        resolve({ success: false, error: "Timeout" });
      }, this.timeout);

      socket.on("data", (data) => {
        responseBuffer += data.toString();
        const lines = responseBuffer.split("\r\n");
        
        for (const line of lines) {
          if (!line.match(/^\d{3}/)) continue;
          
          if (step === 0 && line.startsWith("220")) {
            step = 1;
            socket.write(`USER ${username}\r\n`);
          } else if (step === 1 && (line.startsWith("331") || line.startsWith("230"))) {
            if (line.startsWith("230")) {
              clearTimeout(timeoutId);
              socket.destroy();
              resolve({ success: true });
              return;
            }
            step = 2;
            socket.write(`PASS ${password}\r\n`);
          } else if (step === 2) {
            clearTimeout(timeoutId);
            socket.destroy();
            resolve({ success: line.startsWith("230") });
            return;
          }
        }
      });

      socket.on("error", (err) => {
        clearTimeout(timeoutId);
        resolve({ success: false, error: err.message });
      });
    });
  }

  private async testRedis(password: string): Promise<{ success: boolean; error?: string }> {
    return new Promise((resolve) => {
      const socket = net.createConnection({
        host: this.config.host,
        port: this.config.port,
        timeout: this.timeout,
      });

      const timeoutId = setTimeout(() => {
        socket.destroy();
        resolve({ success: false, error: "Timeout" });
      }, this.timeout);

      socket.on("connect", () => {
        if (password) {
          socket.write(`AUTH ${password}\r\n`);
        } else {
          socket.write("PING\r\n");
        }
      });

      socket.on("data", (data) => {
        clearTimeout(timeoutId);
        const response = data.toString();
        socket.destroy();
        
        if (response.includes("+PONG") || response.includes("+OK")) {
          resolve({ success: true });
        } else if (response.includes("-NOAUTH") || response.includes("-ERR")) {
          resolve({ success: false });
        } else {
          resolve({ success: false });
        }
      });

      socket.on("error", (err) => {
        clearTimeout(timeoutId);
        resolve({ success: false, error: err.message });
      });
    });
  }

  private async testTelnet(username: string, password: string): Promise<{ success: boolean; error?: string }> {
    return new Promise((resolve) => {
      const socket = net.createConnection({
        host: this.config.host,
        port: this.config.port,
        timeout: this.timeout,
      });

      let step = 0;
      let responseBuffer = "";

      const timeoutId = setTimeout(() => {
        socket.destroy();
        resolve({ success: false, error: "Timeout" });
      }, this.timeout);

      socket.on("data", (data) => {
        responseBuffer += data.toString();
        
        if (step === 0 && (responseBuffer.toLowerCase().includes("login") || responseBuffer.toLowerCase().includes("username"))) {
          step = 1;
          socket.write(`${username}\r\n`);
        } else if (step === 1 && responseBuffer.toLowerCase().includes("password")) {
          step = 2;
          socket.write(`${password}\r\n`);
        } else if (step === 2) {
          clearTimeout(timeoutId);
          socket.destroy();
          const success = responseBuffer.includes("$") || 
                         responseBuffer.includes("#") || 
                         responseBuffer.includes(">") ||
                         responseBuffer.toLowerCase().includes("welcome") ||
                         responseBuffer.toLowerCase().includes("last login");
          resolve({ success });
        }
      });

      socket.on("error", (err) => {
        clearTimeout(timeoutId);
        resolve({ success: false, error: err.message });
      });
    });
  }

  private async testGenericTcp(_username: string, _password: string): Promise<{ success: boolean; error?: string }> {
    return new Promise((resolve) => {
      const socket = net.createConnection({
        host: this.config.host,
        port: this.config.port,
        timeout: this.timeout,
      });

      const timeoutId = setTimeout(() => {
        socket.destroy();
        resolve({ success: false, error: "Timeout - would need protocol-specific implementation" });
      }, this.timeout);

      socket.on("connect", () => {
        clearTimeout(timeoutId);
        socket.destroy();
        resolve({ success: false, error: "Connection successful but protocol-specific auth not implemented" });
      });

      socket.on("error", (err) => {
        clearTimeout(timeoutId);
        resolve({ success: false, error: err.message });
      });
    });
  }

  private maskPassword(password: string): string {
    if (password.length <= 2) return "***";
    return password[0] + "*".repeat(Math.min(password.length - 2, 6)) + password[password.length - 1];
  }

  private generateRecommendations(vulnerable: boolean): string[] {
    if (!vulnerable) {
      return ["No default credentials detected - service appears properly configured"];
    }

    const recommendations = [
      "Immediately change all default credentials",
      "Implement strong password policies (minimum 12 characters, complexity requirements)",
      "Enable account lockout after failed authentication attempts",
      "Consider implementing multi-factor authentication",
      "Audit all service accounts for default or weak passwords",
    ];

    switch (this.config.service) {
      case "ssh":
        recommendations.push("Disable password authentication, use SSH keys instead");
        recommendations.push("Configure fail2ban or similar intrusion prevention");
        break;
      case "ftp":
        recommendations.push("Consider replacing FTP with SFTP for encrypted transfers");
        recommendations.push("Disable anonymous access if not required");
        break;
      case "redis":
        recommendations.push("Configure Redis AUTH with a strong password");
        recommendations.push("Bind Redis to localhost only unless remote access is required");
        recommendations.push("Enable Redis ACL for fine-grained access control");
        break;
      case "mysql":
      case "postgresql":
        recommendations.push("Use role-based access control with least privilege");
        recommendations.push("Bind database to localhost and use SSH tunnels for remote access");
        break;
    }

    return recommendations;
  }
}

export function createCredentialProbe(config: CredentialProbeConfig): CredentialProbe {
  return new CredentialProbe(config);
}
