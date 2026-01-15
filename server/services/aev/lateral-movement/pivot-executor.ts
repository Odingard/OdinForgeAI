/**
 * Pivot Executor
 * 
 * Handles the actual execution of pivot operations across network segments.
 * Supports multiple protocols and credential types.
 */

import { createHash } from "crypto";
import type { AgentInfo } from "./agent-mesh-client";

export interface PivotTarget {
  host: string;
  port?: number;
  technique: string;
  credentials: Credential[];
  sourceAgent: string;
  timeout?: number;
}

interface Credential {
  type: "password" | "hash" | "ticket" | "token" | "key";
  username?: string;
  domain?: string;
  value: string;
  source: string;
  usableFor: string[];
}

export interface PivotResult {
  success: boolean;
  newAgent?: AgentInfo;
  evidence: string;
  errorCode?: string;
  executionTimeMs: number;
}

export interface PivotCapabilities {
  smbAvailable: boolean;
  sshAvailable: boolean;
  rdpAvailable: boolean;
  wmiAvailable: boolean;
  psexecAvailable: boolean;
}

export class PivotExecutor {
  private activeConnections: Map<string, PivotConnection> = new Map();

  async executePivot(target: PivotTarget): Promise<PivotResult> {
    const startTime = Date.now();

    switch (target.technique) {
      case "t1021_002":
        return this.pivotViaSMB(target, startTime);

      case "t1021_001":
        return this.pivotViaRDP(target, startTime);

      case "t1021_004":
        return this.pivotViaSSH(target, startTime);

      case "t1550_002":
        return this.pivotViaPassTheHash(target, startTime);

      case "t1550_003":
        return this.pivotViaPassTheTicket(target, startTime);

      case "t1047":
        return this.pivotViaWMI(target, startTime);

      case "t1569_002":
        return this.pivotViaService(target, startTime);

      default:
        return {
          success: false,
          evidence: `Unknown technique: ${target.technique}`,
          executionTimeMs: Date.now() - startTime,
        };
    }
  }

  private async pivotViaSMB(target: PivotTarget, startTime: number): Promise<PivotResult> {
    const cred = target.credentials.find(c =>
      c.usableFor.includes("smb") && (c.type === "password" || c.type === "hash")
    );

    if (!cred) {
      return {
        success: false,
        evidence: "No suitable credentials for SMB pivot",
        errorCode: "NO_CREDS",
        executionTimeMs: Date.now() - startTime,
      };
    }

    const connectionSuccess = this.simulateConnection("smb", target.host, cred);

    if (connectionSuccess) {
      const newAgent = this.createAgentFromPivot(target, "smb");

      this.activeConnections.set(target.host, {
        protocol: "smb",
        host: target.host,
        port: target.port || 445,
        established: new Date(),
        agentId: newAgent.id,
      });

      return {
        success: true,
        newAgent,
        evidence: `SMB pivot established to ${target.host} as ${cred.username}@${cred.domain || "LOCAL"}`,
        executionTimeMs: Date.now() - startTime,
      };
    }

    return {
      success: false,
      evidence: `SMB pivot failed: connection refused or auth failed`,
      errorCode: "CONNECTION_FAILED",
      executionTimeMs: Date.now() - startTime,
    };
  }

  private async pivotViaRDP(target: PivotTarget, startTime: number): Promise<PivotResult> {
    const cred = target.credentials.find(c =>
      c.usableFor.includes("rdp") && c.type === "password"
    );

    if (!cred) {
      return {
        success: false,
        evidence: "No suitable credentials for RDP pivot",
        errorCode: "NO_CREDS",
        executionTimeMs: Date.now() - startTime,
      };
    }

    const connectionSuccess = this.simulateConnection("rdp", target.host, cred);

    if (connectionSuccess) {
      const newAgent = this.createAgentFromPivot(target, "rdp");

      return {
        success: true,
        newAgent,
        evidence: `RDP session established to ${target.host} as ${cred.username}`,
        executionTimeMs: Date.now() - startTime,
      };
    }

    return {
      success: false,
      evidence: "RDP connection failed",
      errorCode: "CONNECTION_FAILED",
      executionTimeMs: Date.now() - startTime,
    };
  }

  private async pivotViaSSH(target: PivotTarget, startTime: number): Promise<PivotResult> {
    const cred = target.credentials.find(c =>
      c.usableFor.includes("ssh") && (c.type === "password" || c.type === "key")
    );

    if (!cred) {
      return {
        success: false,
        evidence: "No suitable credentials for SSH pivot",
        errorCode: "NO_CREDS",
        executionTimeMs: Date.now() - startTime,
      };
    }

    const connectionSuccess = this.simulateConnection("ssh", target.host, cred);

    if (connectionSuccess) {
      const newAgent = this.createAgentFromPivot(target, "ssh");
      newAgent.os = "linux";

      return {
        success: true,
        newAgent,
        evidence: `SSH session established to ${target.host} as ${cred.username}`,
        executionTimeMs: Date.now() - startTime,
      };
    }

    return {
      success: false,
      evidence: "SSH connection failed",
      errorCode: "CONNECTION_FAILED",
      executionTimeMs: Date.now() - startTime,
    };
  }

  private async pivotViaPassTheHash(target: PivotTarget, startTime: number): Promise<PivotResult> {
    const hashCred = target.credentials.find(c => c.type === "hash");

    if (!hashCred) {
      return {
        success: false,
        evidence: "No NTLM hash available for pass-the-hash",
        errorCode: "NO_HASH",
        executionTimeMs: Date.now() - startTime,
      };
    }

    const connectionSuccess = this.simulateConnection("pth", target.host, hashCred);

    if (connectionSuccess) {
      const newAgent = this.createAgentFromPivot(target, "pth");

      return {
        success: true,
        newAgent,
        evidence: `Pass-the-Hash successful to ${target.host} using ${hashCred.username} hash`,
        executionTimeMs: Date.now() - startTime,
      };
    }

    return {
      success: false,
      evidence: "Pass-the-Hash failed: hash rejected or host unreachable",
      errorCode: "PTH_FAILED",
      executionTimeMs: Date.now() - startTime,
    };
  }

  private async pivotViaPassTheTicket(target: PivotTarget, startTime: number): Promise<PivotResult> {
    const ticketCred = target.credentials.find(c => c.type === "ticket");

    if (!ticketCred) {
      return {
        success: false,
        evidence: "No Kerberos ticket available for pass-the-ticket",
        errorCode: "NO_TICKET",
        executionTimeMs: Date.now() - startTime,
      };
    }

    const connectionSuccess = this.simulateConnection("ptt", target.host, ticketCred);

    if (connectionSuccess) {
      const newAgent = this.createAgentFromPivot(target, "ptt");

      return {
        success: true,
        newAgent,
        evidence: `Pass-the-Ticket successful to ${target.host} using ${ticketCred.domain}\\${ticketCred.username} TGT`,
        executionTimeMs: Date.now() - startTime,
      };
    }

    return {
      success: false,
      evidence: "Pass-the-Ticket failed: ticket expired or invalid",
      errorCode: "PTT_FAILED",
      executionTimeMs: Date.now() - startTime,
    };
  }

  private async pivotViaWMI(target: PivotTarget, startTime: number): Promise<PivotResult> {
    const cred = target.credentials.find(c =>
      c.usableFor.includes("wmi") && (c.type === "password" || c.type === "hash")
    );

    if (!cred) {
      return {
        success: false,
        evidence: "No suitable credentials for WMI execution",
        errorCode: "NO_CREDS",
        executionTimeMs: Date.now() - startTime,
      };
    }

    const connectionSuccess = this.simulateConnection("wmi", target.host, cred);

    if (connectionSuccess) {
      const newAgent = this.createAgentFromPivot(target, "wmi");

      return {
        success: true,
        newAgent,
        evidence: `WMI execution successful on ${target.host}, agent deployed via Win32_Process`,
        executionTimeMs: Date.now() - startTime,
      };
    }

    return {
      success: false,
      evidence: "WMI execution failed: access denied or service unavailable",
      errorCode: "WMI_FAILED",
      executionTimeMs: Date.now() - startTime,
    };
  }

  private async pivotViaService(target: PivotTarget, startTime: number): Promise<PivotResult> {
    const cred = target.credentials.find(c =>
      c.usableFor.includes("smb") && (c.type === "password" || c.type === "hash")
    );

    if (!cred) {
      return {
        success: false,
        evidence: "No suitable credentials for service installation",
        errorCode: "NO_CREDS",
        executionTimeMs: Date.now() - startTime,
      };
    }

    const connectionSuccess = this.simulateConnection("psexec", target.host, cred);

    if (connectionSuccess) {
      const newAgent = this.createAgentFromPivot(target, "psexec");

      return {
        success: true,
        newAgent,
        evidence: `Service-based execution successful on ${target.host}, agent deployed via PSEXECSVC`,
        executionTimeMs: Date.now() - startTime,
      };
    }

    return {
      success: false,
      evidence: "Service installation failed: access denied or AV blocked",
      errorCode: "SERVICE_FAILED",
      executionTimeMs: Date.now() - startTime,
    };
  }

  private simulateConnection(protocol: string, host: string, credential: Credential): boolean {
    const hasValidCred = !!(credential.value && credential.value.length > 0);
    const randomSuccess = Math.random() > 0.2;
    return hasValidCred && randomSuccess;
  }

  private createAgentFromPivot(target: PivotTarget, method: string): AgentInfo {
    return {
      id: `agent-${createHash("md5").update(target.host + Date.now()).digest("hex").substring(0, 8)}`,
      hostname: `HOST-${target.host.replace(/\./g, "-")}`,
      ip: target.host,
      os: "windows",
      status: "active",
      lastSeen: new Date(),
      capabilities: ["exec", "upload", "download", "tunnel"],
      metadata: {
        pivotMethod: method,
        sourceAgent: target.sourceAgent,
        pivotTime: new Date().toISOString(),
      },
    };
  }

  async checkCapabilities(host: string): Promise<PivotCapabilities> {
    return {
      smbAvailable: Math.random() > 0.3,
      sshAvailable: Math.random() > 0.5,
      rdpAvailable: Math.random() > 0.4,
      wmiAvailable: Math.random() > 0.4,
      psexecAvailable: Math.random() > 0.3,
    };
  }

  getActiveConnections(): PivotConnection[] {
    return Array.from(this.activeConnections.values());
  }

  async closeConnection(host: string): Promise<boolean> {
    return this.activeConnections.delete(host);
  }

  async closeAllConnections(): Promise<void> {
    this.activeConnections.clear();
  }
}

interface PivotConnection {
  protocol: string;
  host: string;
  port: number;
  established: Date;
  agentId: string;
}
