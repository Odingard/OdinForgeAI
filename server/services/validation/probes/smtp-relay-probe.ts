import * as net from "net";
import type { SmtpProbeConfig, ProbeResult } from "./probe-types";
import { createErrorProbeResult, determineVerdict, DEFAULT_PORTS } from "./probe-types";

export interface SmtpProbeResult extends ProbeResult {
  protocol: "smtp";
  relayOpen: boolean;
  vrfyEnabled: boolean;
  expnEnabled: boolean;
  authRequired: boolean;
  serverBanner: string;
  supportedCommands: string[];
}

export class SmtpRelayProbe {
  private config: Required<SmtpProbeConfig>;
  private timeout: number;

  constructor(config: SmtpProbeConfig) {
    this.config = {
      host: config.host,
      port: config.port || DEFAULT_PORTS.smtp,
      timeout: config.timeout || 10000,
      organizationId: config.organizationId || "",
      evaluationId: config.evaluationId || "",
      testSender: config.testSender || "test@security-scan.local",
      testRecipient: config.testRecipient || "test@external-domain.com",
      testDomain: config.testDomain || "security-scan.local",
    };
    this.timeout = this.config.timeout;
  }

  async probe(): Promise<SmtpProbeResult> {
    const startTime = Date.now();
    
    try {
      const connection = await this.connect();
      const banner = await this.readResponse(connection);
      
      if (!banner.startsWith("220")) {
        connection.destroy();
        return this.createResult(false, 0, "Connection rejected", {
          serverBanner: banner,
          executionTimeMs: Date.now() - startTime,
        });
      }

      const ehloResponse = await this.sendCommand(connection, `EHLO ${this.config.testDomain}`);
      const supportedCommands = this.parseEhloResponse(ehloResponse);
      const authRequired = supportedCommands.includes("AUTH");

      const vrfyResult = await this.testVrfy(connection);
      const expnResult = await this.testExpn(connection);
      const relayResult = await this.testRelay(connection);

      await this.sendCommand(connection, "QUIT");
      connection.destroy();

      const vulnerable = relayResult.open || vrfyResult.enabled || expnResult.enabled;
      let confidence = 0;
      const issues: string[] = [];

      if (relayResult.open) {
        confidence = Math.max(confidence, 95);
        issues.push("Open relay detected - server accepts mail for external domains");
      }
      if (vrfyResult.enabled) {
        confidence = Math.max(confidence, 60);
        issues.push("VRFY command enabled - allows user enumeration");
      }
      if (expnResult.enabled) {
        confidence = Math.max(confidence, 60);
        issues.push("EXPN command enabled - allows mailing list enumeration");
      }
      if (!authRequired) {
        confidence = Math.max(confidence, 40);
        issues.push("No authentication required for sending");
      }

      const executionTimeMs = Date.now() - startTime;

      return {
        vulnerable,
        confidence,
        verdict: determineVerdict(confidence),
        protocol: "smtp",
        service: "mail",
        technique: relayResult.open ? "open_relay" : vrfyResult.enabled ? "vrfy_enabled" : "expn_enabled",
        evidence: issues.join("; ") || "No significant SMTP vulnerabilities detected",
        details: {
          targetHost: this.config.host,
          targetPort: this.config.port,
          banner: banner.trim(),
          responseData: `EHLO: ${ehloResponse.substring(0, 200)}`,
        },
        recommendations: this.generateRecommendations(relayResult.open, vrfyResult.enabled, expnResult.enabled, authRequired),
        executionTimeMs,
        relayOpen: relayResult.open,
        vrfyEnabled: vrfyResult.enabled,
        expnEnabled: expnResult.enabled,
        authRequired,
        serverBanner: banner.trim(),
        supportedCommands,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      return {
        ...createErrorProbeResult("smtp", "mail", this.config.host, this.config.port, errorMessage),
        relayOpen: false,
        vrfyEnabled: false,
        expnEnabled: false,
        authRequired: true,
        serverBanner: "",
        supportedCommands: [],
        protocol: "smtp",
      } as SmtpProbeResult;
    }
  }

  private connect(): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({
        host: this.config.host,
        port: this.config.port,
        timeout: this.timeout,
      });

      socket.setTimeout(this.timeout);
      socket.once("connect", () => resolve(socket));
      socket.once("error", reject);
      socket.once("timeout", () => reject(new Error("Connection timeout")));
    });
  }

  private readResponse(socket: net.Socket): Promise<string> {
    return new Promise((resolve, reject) => {
      let data = "";
      const timeout = setTimeout(() => {
        reject(new Error("Read timeout"));
      }, this.timeout);

      const onData = (chunk: Buffer) => {
        data += chunk.toString();
        if (data.includes("\r\n") && !data.match(/^\d{3}-/m)) {
          clearTimeout(timeout);
          socket.removeListener("data", onData);
          resolve(data);
        }
      };

      socket.on("data", onData);
      socket.once("error", (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });
  }

  private async sendCommand(socket: net.Socket, command: string): Promise<string> {
    return new Promise((resolve, reject) => {
      socket.write(`${command}\r\n`, (err) => {
        if (err) {
          reject(err);
          return;
        }
        this.readResponse(socket).then(resolve).catch(reject);
      });
    });
  }

  private parseEhloResponse(response: string): string[] {
    const lines = response.split("\r\n").filter((line) => line.match(/^250/));
    return lines.map((line) => line.replace(/^250[- ]/, "").split(" ")[0].toUpperCase());
  }

  private async testVrfy(socket: net.Socket): Promise<{ enabled: boolean; response: string }> {
    try {
      const response = await this.sendCommand(socket, "VRFY postmaster");
      const enabled = response.startsWith("250") || response.startsWith("252");
      return { enabled, response };
    } catch {
      return { enabled: false, response: "" };
    }
  }

  private async testExpn(socket: net.Socket): Promise<{ enabled: boolean; response: string }> {
    try {
      const response = await this.sendCommand(socket, "EXPN postmaster");
      const enabled = response.startsWith("250");
      return { enabled, response };
    } catch {
      return { enabled: false, response: "" };
    }
  }

  private async testRelay(socket: net.Socket): Promise<{ open: boolean; response: string }> {
    try {
      const mailFrom = await this.sendCommand(socket, `MAIL FROM:<${this.config.testSender}>`);
      if (!mailFrom.startsWith("250")) {
        return { open: false, response: mailFrom };
      }

      const rcptTo = await this.sendCommand(socket, `RCPT TO:<${this.config.testRecipient}>`);
      const open = rcptTo.startsWith("250");

      await this.sendCommand(socket, "RSET");

      return { open, response: rcptTo };
    } catch {
      return { open: false, response: "" };
    }
  }

  private createResult(
    vulnerable: boolean,
    confidence: number,
    evidence: string,
    extra: Partial<SmtpProbeResult>
  ): SmtpProbeResult {
    return {
      vulnerable,
      confidence,
      verdict: determineVerdict(confidence),
      protocol: "smtp",
      service: "mail",
      technique: "smtp_probe",
      evidence,
      details: {
        targetHost: this.config.host,
        targetPort: this.config.port,
      },
      recommendations: [],
      executionTimeMs: extra.executionTimeMs || 0,
      relayOpen: false,
      vrfyEnabled: false,
      expnEnabled: false,
      authRequired: true,
      serverBanner: extra.serverBanner || "",
      supportedCommands: [],
      ...extra,
    };
  }

  private generateRecommendations(
    relayOpen: boolean,
    vrfyEnabled: boolean,
    expnEnabled: boolean,
    authRequired: boolean
  ): string[] {
    const recommendations: string[] = [];

    if (relayOpen) {
      recommendations.push("Disable open relay - configure SMTP server to only relay for authenticated users or specific IP ranges");
      recommendations.push("Implement proper sender authentication (SPF, DKIM, DMARC)");
    }
    if (vrfyEnabled) {
      recommendations.push("Disable VRFY command to prevent user enumeration");
    }
    if (expnEnabled) {
      recommendations.push("Disable EXPN command to prevent mailing list enumeration");
    }
    if (!authRequired) {
      recommendations.push("Require authentication for sending mail (SMTP AUTH)");
    }

    if (recommendations.length === 0) {
      recommendations.push("SMTP server appears properly configured");
    }

    return recommendations;
  }
}

export function createSmtpRelayProbe(config: SmtpProbeConfig): SmtpRelayProbe {
  return new SmtpRelayProbe(config);
}
