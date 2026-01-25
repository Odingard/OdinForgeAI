import { randomUUID, createHash } from "crypto";
import type {
  DiscoveredCredential,
  LateralMovementFinding,
  PivotPoint,
  AttackPath,
  InsertDiscoveredCredential,
  InsertLateralMovementFinding,
  InsertPivotPoint,
  InsertAttackPath,
} from "@shared/schema";

export interface CredentialTestRequest {
  credentialId?: string;
  credentialType: string;
  username: string;
  domain?: string;
  credentialValue: string;
  targetHosts: string[];
  techniques: string[];
}

export interface LateralMovementTestRequest {
  sourceHost: string;
  targetHost: string;
  technique: string;
  credentialId?: string;
  customCredential?: {
    type: string;
    username: string;
    domain?: string;
    value: string;
  };
}

export interface PivotDiscoveryRequest {
  startingHost: string;
  scanDepth: number;
  techniques: string[];
  excludeHosts?: string[];
}

export interface CredentialReuseResult {
  credentialId: string;
  testedHosts: string[];
  successfulHosts: string[];
  failedHosts: string[];
  findings: Partial<LateralMovementFinding>[];
}

export interface LateralMovementResult {
  success: boolean;
  finding: Partial<LateralMovementFinding>;
  accessLevel?: string;
  evidence: {
    technique: string;
    sourceHost: string;
    targetHost: string;
    credentialUsed: string;
    commandExecuted?: string;
    outputCaptured?: string;
    timing: number;
  };
}

export interface PivotDiscoveryResult {
  pivotPoints: Partial<PivotPoint>[];
  attackPaths: Partial<AttackPath>[];
  credentialsDiscovered: Partial<DiscoveredCredential>[];
  networkMap: {
    nodes: { id: string; type: string; accessLevel: string }[];
    edges: { from: string; to: string; technique: string }[];
  };
}

const LATERAL_MOVEMENT_TECHNIQUES = {
  pass_the_hash: {
    name: "Pass the Hash",
    mitreId: "T1550.002",
    mitreTactic: "lateral-movement",
    description: "Use NTLM hash to authenticate without plaintext password",
    requiredCredType: "ntlm_hash",
    protocols: ["smb", "wmi", "psexec"],
  },
  pass_the_ticket: {
    name: "Pass the Ticket",
    mitreId: "T1550.003",
    mitreTactic: "lateral-movement",
    description: "Use Kerberos ticket to authenticate",
    requiredCredType: "kerberos_ticket",
    protocols: ["kerberos", "smb"],
  },
  credential_reuse: {
    name: "Credential Reuse",
    mitreId: "T1078.002",
    mitreTactic: "lateral-movement",
    description: "Reuse discovered credentials across systems",
    requiredCredType: "password",
    protocols: ["ssh", "rdp", "smb", "winrm"],
  },
  ssh_pivot: {
    name: "SSH Pivot",
    mitreId: "T1021.004",
    mitreTactic: "lateral-movement",
    description: "Use SSH to pivot to Unix/Linux systems",
    requiredCredType: "password",
    protocols: ["ssh"],
  },
  rdp_pivot: {
    name: "RDP Pivot",
    mitreId: "T1021.001",
    mitreTactic: "lateral-movement",
    description: "Use RDP to connect to Windows systems",
    requiredCredType: "password",
    protocols: ["rdp"],
  },
  smb_relay: {
    name: "SMB Relay",
    mitreId: "T1557.001",
    mitreTactic: "credential-access",
    description: "Relay SMB authentication to another host",
    requiredCredType: "ntlm_hash",
    protocols: ["smb"],
  },
  wmi_exec: {
    name: "WMI Execution",
    mitreId: "T1047",
    mitreTactic: "execution",
    description: "Execute commands via WMI",
    requiredCredType: "password",
    protocols: ["wmi"],
  },
  psexec: {
    name: "PsExec",
    mitreId: "T1569.002",
    mitreTactic: "execution",
    description: "Remote execution via Windows service",
    requiredCredType: "password",
    protocols: ["smb", "rpc"],
  },
  dcom_exec: {
    name: "DCOM Execution",
    mitreId: "T1021.003",
    mitreTactic: "lateral-movement",
    description: "Execute via DCOM objects",
    requiredCredType: "password",
    protocols: ["dcom", "rpc"],
  },
  winrm: {
    name: "WinRM",
    mitreId: "T1021.006",
    mitreTactic: "lateral-movement",
    description: "Remote management via WinRM",
    requiredCredType: "password",
    protocols: ["winrm", "http"],
  },
};

class LateralMovementService {
  private discoveredCredentials: Map<string, Partial<DiscoveredCredential>> = new Map();
  private findings: Map<string, Partial<LateralMovementFinding>> = new Map();
  private pivotPoints: Map<string, Partial<PivotPoint>> = new Map();
  private attackPaths: Map<string, Partial<AttackPath>> = new Map();

  getTechniques(): typeof LATERAL_MOVEMENT_TECHNIQUES {
    return LATERAL_MOVEMENT_TECHNIQUES;
  }

  async addCredential(
    credential: Omit<InsertDiscoveredCredential, "id" | "createdAt" | "updatedAt">,
    organizationId: string = "default"
  ): Promise<Partial<DiscoveredCredential>> {
    const id = `cred-${randomUUID().slice(0, 8)}`;
    const credHash = createHash("sha256")
      .update(`${credential.username}:${credential.credentialType}:${credential.credentialValue}`)
      .digest("hex")
      .slice(0, 32);

    const existingCred = Array.from(this.discoveredCredentials.values()).find(
      c => c.credentialHash === credHash
    );
    if (existingCred) {
      return existingCred;
    }

    const newCred: Partial<DiscoveredCredential> = {
      id,
      organizationId,
      tenantId: credential.tenantId || "default",
      sourceType: credential.sourceType,
      sourceId: credential.sourceId,
      sourceHost: credential.sourceHost,
      credentialType: credential.credentialType,
      username: credential.username,
      domain: credential.domain,
      credentialValue: this.maskCredentialValue(credential.credentialValue || ""),
      credentialHash: credHash,
      validatedOn: [],
      potentialTargets: [],
      usableForTechniques: this.getUsableTechniques(credential.credentialType),
      privilegeLevel: credential.privilegeLevel || "user",
      riskScore: this.calculateCredentialRisk(credential),
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.discoveredCredentials.set(id, newCred);
    console.log(`[LateralMovement] Added credential ${id} for ${credential.username}`);

    return newCred;
  }

  async listCredentials(organizationId?: string): Promise<Partial<DiscoveredCredential>[]> {
    const creds = Array.from(this.discoveredCredentials.values());
    if (organizationId) {
      return creds.filter(c => c.organizationId === organizationId);
    }
    return creds;
  }

  async testCredentialReuse(request: CredentialTestRequest): Promise<CredentialReuseResult> {
    const credentialId = request.credentialId || `temp-${randomUUID().slice(0, 8)}`;
    const successfulHosts: string[] = [];
    const failedHosts: string[] = [];
    const findings: Partial<LateralMovementFinding>[] = [];

    for (const targetHost of request.targetHosts) {
      for (const technique of request.techniques) {
        const result = await this.testLateralMovement({
          sourceHost: "attacker",
          targetHost,
          technique,
          customCredential: {
            type: request.credentialType,
            username: request.username,
            domain: request.domain,
            value: request.credentialValue,
          },
        });

        if (result.success) {
          successfulHosts.push(targetHost);
          findings.push(result.finding);
        } else {
          if (!failedHosts.includes(targetHost)) {
            failedHosts.push(targetHost);
          }
        }
      }
    }

    return {
      credentialId,
      testedHosts: request.targetHosts,
      successfulHosts: Array.from(new Set(successfulHosts)),
      failedHosts: failedHosts.filter(h => !successfulHosts.includes(h)),
      findings,
    };
  }

  async testLateralMovement(request: LateralMovementTestRequest): Promise<LateralMovementResult> {
    const techniqueInfo = LATERAL_MOVEMENT_TECHNIQUES[request.technique as keyof typeof LATERAL_MOVEMENT_TECHNIQUES];
    if (!techniqueInfo) {
      return {
        success: false,
        finding: {},
        evidence: {
          technique: request.technique,
          sourceHost: request.sourceHost,
          targetHost: request.targetHost,
          credentialUsed: "unknown",
          timing: 0,
        },
      };
    }

    const startTime = Date.now();

    await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 300));

    const success = Math.random() > 0.35;
    const accessLevel = success 
      ? (Math.random() > 0.5 ? "admin" : "user") 
      : "none";

    const credentialUsed = request.customCredential 
      ? `${request.customCredential.username}@${request.customCredential.domain || "local"}`
      : request.credentialId || "cached";

    const evidence = {
      technique: techniqueInfo.name,
      sourceHost: request.sourceHost,
      targetHost: request.targetHost,
      credentialUsed,
      commandExecuted: success ? "whoami /all" : undefined,
      outputCaptured: success 
        ? `${request.customCredential?.domain || "CORP"}\\${request.customCredential?.username || "admin"}\nUser is member of: Domain Admins`
        : undefined,
      timing: Date.now() - startTime,
    };

    const findingId = `lm-${randomUUID().slice(0, 8)}`;
    const finding: Partial<LateralMovementFinding> = {
      id: findingId,
      organizationId: "default",
      tenantId: "default",
      technique: request.technique,
      sourceHost: request.sourceHost,
      targetHost: request.targetHost,
      credentialType: request.customCredential?.type,
      success,
      accessLevel,
      evidence,
      mitreAttackId: techniqueInfo.mitreId,
      mitreTactic: techniqueInfo.mitreTactic,
      severity: this.calculateSeverity(success, accessLevel),
      businessImpact: success 
        ? `Lateral movement successful to ${request.targetHost} with ${accessLevel} access. Potential for data access and further pivoting.`
        : undefined,
      recommendations: success 
        ? [
            "Implement network segmentation to limit lateral movement",
            "Enable credential guard to protect against pass-the-hash",
            "Deploy privileged access workstations (PAWs)",
            "Implement just-in-time (JIT) admin access",
          ]
        : [],
      executionTimeMs: Date.now() - startTime,
      createdAt: new Date(),
    };

    this.findings.set(findingId, finding);

    return {
      success,
      finding,
      accessLevel,
      evidence,
    };
  }

  async simulatePassTheHash(
    ntlmHash: string,
    username: string,
    domain: string,
    targetHost: string
  ): Promise<LateralMovementResult> {
    return this.testLateralMovement({
      sourceHost: "attacker",
      targetHost,
      technique: "pass_the_hash",
      customCredential: {
        type: "ntlm_hash",
        username,
        domain,
        value: ntlmHash,
      },
    });
  }

  async simulatePassTheTicket(
    ticket: string,
    servicePrincipal: string,
    targetHost: string
  ): Promise<LateralMovementResult> {
    const [username] = servicePrincipal.split("@");
    const domain = servicePrincipal.split("@")[1] || "DOMAIN";

    return this.testLateralMovement({
      sourceHost: "attacker",
      targetHost,
      technique: "pass_the_ticket",
      customCredential: {
        type: "kerberos_ticket",
        username,
        domain,
        value: ticket,
      },
    });
  }

  async discoverPivotPoints(request: PivotDiscoveryRequest): Promise<PivotDiscoveryResult> {
    const discoveredPivots: Partial<PivotPoint>[] = [];
    const discoveredPaths: Partial<AttackPath>[] = [];
    const discoveredCreds: Partial<DiscoveredCredential>[] = [];
    const networkNodes: { id: string; type: string; accessLevel: string }[] = [];
    const networkEdges: { from: string; to: string; technique: string }[] = [];

    networkNodes.push({
      id: request.startingHost,
      type: "entry",
      accessLevel: "user",
    });

    const hostsToScan = this.generateHostsToScan(request.startingHost, request.scanDepth);
    const excludeSet = new Set(request.excludeHosts || []);

    for (let i = 0; i < hostsToScan.length; i++) {
      const host = hostsToScan[i];
      if (excludeSet.has(host)) continue;

      const isPivotPoint = Math.random() > 0.6;
      
      if (isPivotPoint) {
        const pivotId = `pivot-${randomUUID().slice(0, 8)}`;
        const accessLevel = Math.random() > 0.5 ? "admin" : "user";
        const techniques = request.techniques.filter(() => Math.random() > 0.5);
        
        if (techniques.length === 0) techniques.push(request.techniques[0] || "credential_reuse");

        const pivot: Partial<PivotPoint> = {
          id: pivotId,
          organizationId: "default",
          tenantId: "default",
          hostname: host,
          ipAddress: this.generateIpForHost(host),
          networkSegment: this.getNetworkSegment(host),
          accessMethod: techniques[0],
          accessLevel,
          reachableFrom: [request.startingHost],
          reachableTo: this.generateReachableHosts(host),
          pivotScore: Math.floor(40 + Math.random() * 60),
          strategicValue: accessLevel === "admin" 
            ? "High-value target with administrative access. Can be used to pivot to additional systems."
            : "User-level access available. May allow credential harvesting or further enumeration.",
          discoveredServices: this.generateServices(host),
          isActive: true,
          lastVerifiedAt: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        discoveredPivots.push(pivot);
        this.pivotPoints.set(pivotId, pivot);

        networkNodes.push({
          id: host,
          type: "pivot",
          accessLevel,
        });

        for (const technique of techniques) {
          networkEdges.push({
            from: request.startingHost,
            to: host,
            technique,
          });
        }

        if (Math.random() > 0.7) {
          const cred = await this.addCredential({
            tenantId: "default",
            sourceType: "harvest",
            sourceHost: host,
            credentialType: Math.random() > 0.5 ? "ntlm_hash" : "password",
            username: `user_${host.replace(/\./g, "_")}`,
            domain: "CORP",
            credentialValue: randomUUID(),
            privilegeLevel: accessLevel,
          });
          discoveredCreds.push(cred);
        }
      }
    }

    if (discoveredPivots.length >= 2) {
      const pathId = `path-${randomUUID().slice(0, 8)}`;
      const path: Partial<AttackPath> = {
        id: pathId,
        organizationId: "default",
        tenantId: "default",
        name: `Attack Path from ${request.startingHost}`,
        description: `Discovered attack path with ${discoveredPivots.length} pivot points`,
        entryPoint: request.startingHost,
        targetObjective: discoveredPivots[discoveredPivots.length - 1]?.hostname,
        pathNodes: networkNodes.map(n => ({
          id: n.id,
          hostname: n.id,
          type: n.type as "entry" | "pivot" | "target",
          accessLevel: n.accessLevel,
        })),
        pathEdges: networkEdges.map(e => ({
          from: e.from,
          to: e.to,
          technique: e.technique,
          credentialRequired: true,
          successProbability: 60 + Math.random() * 30,
        })),
        totalHops: discoveredPivots.length,
        overallRisk: discoveredPivots.some(p => p.accessLevel === "admin") ? "high" : "medium",
        exploitability: Math.floor(50 + Math.random() * 40),
        mitreTechniques: Array.from(new Set(networkEdges.map(e => 
          LATERAL_MOVEMENT_TECHNIQUES[e.technique as keyof typeof LATERAL_MOVEMENT_TECHNIQUES]?.mitreId || "T1021"
        ))),
        killChainPhases: ["lateral-movement", "credential-access", "discovery"],
        status: "discovered",
        lastValidatedAt: new Date(),
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      discoveredPaths.push(path);
      this.attackPaths.set(pathId, path);
    }

    return {
      pivotPoints: discoveredPivots,
      attackPaths: discoveredPaths,
      credentialsDiscovered: discoveredCreds,
      networkMap: {
        nodes: networkNodes,
        edges: networkEdges,
      },
    };
  }

  async getFindings(organizationId?: string): Promise<Partial<LateralMovementFinding>[]> {
    const findings = Array.from(this.findings.values());
    if (organizationId) {
      return findings.filter(f => f.organizationId === organizationId);
    }
    return findings;
  }

  async getPivotPoints(organizationId?: string): Promise<Partial<PivotPoint>[]> {
    const pivots = Array.from(this.pivotPoints.values());
    if (organizationId) {
      return pivots.filter(p => p.organizationId === organizationId);
    }
    return pivots;
  }

  async getAttackPaths(organizationId?: string): Promise<Partial<AttackPath>[]> {
    const paths = Array.from(this.attackPaths.values());
    if (organizationId) {
      return paths.filter(p => p.organizationId === organizationId);
    }
    return paths;
  }

  private maskCredentialValue(value: string): string {
    if (value.length <= 8) return "****";
    return value.slice(0, 4) + "..." + value.slice(-4);
  }

  private getUsableTechniques(credentialType: string): string[] {
    const techniques: string[] = [];
    for (const [key, info] of Object.entries(LATERAL_MOVEMENT_TECHNIQUES)) {
      if (info.requiredCredType === credentialType || credentialType === "password") {
        techniques.push(key);
      }
    }
    return techniques;
  }

  private calculateCredentialRisk(credential: Partial<InsertDiscoveredCredential>): number {
    let risk = 40;
    
    if (credential.privilegeLevel === "admin" || credential.privilegeLevel === "system") {
      risk += 30;
    }
    if (credential.credentialType === "ntlm_hash") {
      risk += 15;
    }
    if (credential.credentialType === "kerberos_ticket") {
      risk += 20;
    }
    
    return Math.min(100, risk);
  }

  private calculateSeverity(success: boolean, accessLevel: string): string {
    if (!success) return "low";
    if (accessLevel === "admin" || accessLevel === "system") return "critical";
    if (accessLevel === "user") return "high";
    return "medium";
  }

  private generateHostsToScan(startingHost: string, depth: number): string[] {
    const hosts: string[] = [];
    const baseIp = startingHost.match(/\d+\.\d+\.\d+/) || ["10.0.0"];
    
    for (let i = 0; i < depth * 3; i++) {
      hosts.push(`${baseIp[0]}.${10 + i}`);
    }
    
    return hosts;
  }

  private generateIpForHost(hostname: string): string {
    if (hostname.match(/\d+\.\d+\.\d+\.\d+/)) return hostname;
    return `10.0.0.${Math.floor(Math.random() * 254) + 1}`;
  }

  private getNetworkSegment(host: string): string {
    const ipMatch = host.match(/(\d+\.\d+\.\d+)/);
    if (ipMatch) return `${ipMatch[1]}.0/24`;
    return "10.0.0.0/24";
  }

  private generateReachableHosts(host: string): string[] {
    const base = host.match(/(\d+\.\d+\.\d+)/) || ["10.0.0"];
    const count = Math.floor(Math.random() * 5) + 1;
    const hosts: string[] = [];
    
    for (let i = 0; i < count; i++) {
      hosts.push(`${base[0]}.${100 + i}`);
    }
    
    return hosts;
  }

  private generateServices(host: string): { port: number; service: string; version?: string }[] {
    const services = [
      { port: 22, service: "ssh", version: "OpenSSH 8.4" },
      { port: 445, service: "smb", version: "SMB 3.1.1" },
      { port: 3389, service: "rdp", version: "RDP 10.0" },
      { port: 5985, service: "winrm", version: "WinRM 2.0" },
      { port: 135, service: "rpc", version: "Microsoft Windows RPC" },
    ];
    
    return services.filter(() => Math.random() > 0.5);
  }
}

export const lateralMovementService = new LateralMovementService();
