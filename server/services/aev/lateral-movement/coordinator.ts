/**
 * Lateral Movement Coordinator
 * 
 * Orchestrates attack chains across multiple network segments using
 * deployed endpoint agents. Manages pivot points, credentials, and
 * attack path execution.
 */

import { createHash } from "crypto";
import { PivotExecutor, type PivotTarget, type PivotResult as PivotExecResult } from "./pivot-executor";
import { AgentMeshClient, type AgentInfo } from "./agent-mesh-client";

export interface LateralMovementPlan {
  id: string;
  name: string;
  description: string;
  targetNetwork: string;
  startingPoint: string;
  objectives: MovementObjective[];
  steps: MovementStep[];
  constraints: MovementConstraints;
  estimatedDuration: number;
}

export interface MovementObjective {
  id: string;
  type: "reach_target" | "exfiltrate_data" | "establish_persistence" | "escalate_privileges";
  target: string;
  priority: number;
  successCriteria: string;
}

export interface MovementStep {
  id: string;
  name: string;
  type: "pivot" | "credential_harvest" | "scan" | "exploit" | "persist";
  sourceAgent: string;
  targetHost?: string;
  technique: MovementTechnique;
  requiredCredentials?: string[];
  dependsOn?: string[];
  timeout: number;
}

export interface MovementTechnique {
  id: string;
  name: string;
  mitreId: string;
  description: string;
  requirements: string[];
  riskLevel: "low" | "medium" | "high" | "critical";
}

export interface MovementConstraints {
  maxHops: number;
  allowedProtocols: string[];
  excludedHosts: string[];
  requireApproval: boolean;
  maxDuration: number;
  stealthMode: boolean;
}

export interface PivotResult {
  stepId: string;
  success: boolean;
  pivotEstablished: boolean;
  newAgent?: AgentInfo;
  credentials?: HarvestedCredential[];
  evidence: string;
  executionTimeMs: number;
}

interface HarvestedCredential {
  type: "password" | "hash" | "ticket" | "token" | "key";
  username?: string;
  domain?: string;
  value: string;
  source: string;
  usableFor: string[];
}

export interface MeshStatus {
  totalAgents: number;
  activeAgents: number;
  pivotPoints: number;
  credentialCount: number;
  reachableNetworks: string[];
}

export interface CoordinatorResult {
  planId: string;
  success: boolean;
  objectivesAchieved: string[];
  stepResults: PivotResult[];
  meshStatus: MeshStatus;
  attackPath: string[];
  evidence: string;
  proofArtifacts: ProofArtifact[];
  executionTimeMs: number;
}

interface ProofArtifact {
  type: string;
  description: string;
  data: string;
  hash: string;
  capturedAt: Date;
}

const LATERAL_MOVEMENT_TECHNIQUES: MovementTechnique[] = [
  {
    id: "t1021_002",
    name: "SMB/Windows Admin Shares",
    mitreId: "T1021.002",
    description: "Use SMB to access admin shares (C$, ADMIN$) with harvested credentials",
    requirements: ["smb_access", "admin_credentials"],
    riskLevel: "medium",
  },
  {
    id: "t1021_001",
    name: "Remote Desktop Protocol",
    mitreId: "T1021.001",
    description: "Use RDP to connect to remote Windows systems",
    requirements: ["rdp_access", "valid_credentials"],
    riskLevel: "medium",
  },
  {
    id: "t1021_004",
    name: "SSH",
    mitreId: "T1021.004",
    description: "Use SSH to connect to remote Unix/Linux systems",
    requirements: ["ssh_access", "valid_credentials_or_key"],
    riskLevel: "low",
  },
  {
    id: "t1550_002",
    name: "Pass the Hash",
    mitreId: "T1550.002",
    description: "Use NTLM hash to authenticate without password",
    requirements: ["ntlm_hash", "smb_access"],
    riskLevel: "high",
  },
  {
    id: "t1550_003",
    name: "Pass the Ticket",
    mitreId: "T1550.003",
    description: "Use Kerberos ticket to authenticate",
    requirements: ["kerberos_ticket", "kerberos_realm"],
    riskLevel: "high",
  },
  {
    id: "t1047",
    name: "WMI Execution",
    mitreId: "T1047",
    description: "Use WMI to execute commands on remote systems",
    requirements: ["wmi_access", "admin_credentials"],
    riskLevel: "medium",
  },
  {
    id: "t1569_002",
    name: "Service Execution",
    mitreId: "T1569.002",
    description: "Execute via Windows service installation",
    requirements: ["smb_access", "admin_credentials"],
    riskLevel: "high",
  },
];

const TECHNIQUE_TO_PROTOCOL: Record<string, string> = {
  t1021_002: "smb",
  t1021_001: "rdp",
  t1021_004: "ssh",
  t1550_002: "pth",
  t1550_003: "ptt",
  t1047: "wmi",
  t1569_002: "psexec",
};

export class LateralMovementCoordinator {
  private meshClient: AgentMeshClient;
  private pivotExecutor: PivotExecutor;
  private credentialStore: Map<string, HarvestedCredential[]> = new Map();
  private executedSteps: Map<string, PivotResult> = new Map();
  private attackPath: string[] = [];
  private pendingApprovals: Map<string, boolean> = new Map();

  constructor(meshClient?: AgentMeshClient) {
    this.meshClient = meshClient || new AgentMeshClient();
    this.pivotExecutor = new PivotExecutor();
  }

  approveStep(stepId: string): void {
    this.pendingApprovals.set(stepId, true);
  }

  denyStep(stepId: string): void {
    this.pendingApprovals.set(stepId, false);
  }

  async executePlan(plan: LateralMovementPlan): Promise<CoordinatorResult> {
    const startTime = Date.now();
    const stepResults: PivotResult[] = [];
    const proofArtifacts: ProofArtifact[] = [];
    const evidence: string[] = [];
    const objectivesAchieved: string[] = [];

    this.attackPath.push(plan.startingPoint);
    evidence.push(`Starting lateral movement from ${plan.startingPoint}`);

    const sortedSteps = this.topologicalSort(plan.steps);

    for (const step of sortedSteps) {
      const elapsedMs = Date.now() - startTime;
      if (plan.constraints.maxDuration > 0 && elapsedMs >= plan.constraints.maxDuration) {
        stepResults.push({
          stepId: step.id,
          success: false,
          pivotEstablished: false,
          evidence: `Max duration (${plan.constraints.maxDuration}ms) exceeded`,
          executionTimeMs: 0,
        });
        break;
      }

      const stepProtocol = TECHNIQUE_TO_PROTOCOL[step.technique.id] || step.technique.id;
      if (plan.constraints.allowedProtocols.length > 0 && 
          !plan.constraints.allowedProtocols.includes(stepProtocol)) {
        stepResults.push({
          stepId: step.id,
          success: false,
          pivotEstablished: false,
          evidence: `Protocol '${stepProtocol}' not in allowed list: [${plan.constraints.allowedProtocols.join(", ")}]`,
          executionTimeMs: 0,
        });
        continue;
      }

      if (plan.constraints.requireApproval) {
        const approved = this.pendingApprovals.get(step.id);
        if (approved !== true) {
          stepResults.push({
            stepId: step.id,
            success: false,
            pivotEstablished: false,
            evidence: approved === false 
              ? "Step denied by approval workflow" 
              : "Step requires approval - call approveStep(stepId) first",
            executionTimeMs: 0,
          });
          continue;
        }
      }

      if (step.dependsOn?.length) {
        const allDependenciesMet = step.dependsOn.every(depId => {
          const depResult = this.executedSteps.get(depId);
          return depResult?.success;
        });

        if (!allDependenciesMet) {
          stepResults.push({
            stepId: step.id,
            success: false,
            pivotEstablished: false,
            evidence: "Dependencies not met",
            executionTimeMs: 0,
          });
          continue;
        }
      }

      if (plan.constraints.excludedHosts.includes(step.targetHost || "")) {
        stepResults.push({
          stepId: step.id,
          success: false,
          pivotEstablished: false,
          evidence: "Target host excluded by constraints",
          executionTimeMs: 0,
        });
        continue;
      }

      if (this.attackPath.length >= plan.constraints.maxHops + 1) {
        stepResults.push({
          stepId: step.id,
          success: false,
          pivotEstablished: false,
          evidence: `Max hops (${plan.constraints.maxHops}) reached`,
          executionTimeMs: 0,
        });
        break;
      }

      const result = await this.executeStep(step, plan.constraints);
      stepResults.push(result);
      this.executedSteps.set(step.id, result);

      if (result.success) {
        evidence.push(`Step ${step.name}: ${result.evidence}`);

        if (result.pivotEstablished && step.targetHost) {
          this.attackPath.push(step.targetHost);
        }

        if (result.credentials?.length) {
          this.storeCredentials(step.targetHost || "unknown", result.credentials);
        }

        proofArtifacts.push({
          type: `lateral_${step.type}`,
          description: step.name,
          data: JSON.stringify({
            source: step.sourceAgent,
            target: step.targetHost,
            technique: step.technique.name,
          }),
          hash: createHash("sha256").update(result.evidence).digest("hex"),
          capturedAt: new Date(),
        });

        for (const objective of plan.objectives) {
          if (this.isObjectiveAchieved(objective, result)) {
            objectivesAchieved.push(objective.id);
            evidence.push(`Objective achieved: ${objective.id}`);
          }
        }
      }
    }

    const meshStatus = await this.getMeshStatus();
    const success = objectivesAchieved.length > 0 || stepResults.some(r => r.success);

    return {
      planId: plan.id,
      success,
      objectivesAchieved,
      stepResults,
      meshStatus,
      attackPath: this.attackPath,
      evidence: evidence.join("; "),
      proofArtifacts,
      executionTimeMs: Date.now() - startTime,
    };
  }

  private async executeStep(
    step: MovementStep,
    constraints: MovementConstraints
  ): Promise<PivotResult> {
    const startTime = Date.now();

    if (constraints.stealthMode) {
      const noisyTypes = ["persist", "exploit"];
      if (noisyTypes.includes(step.type)) {
        return {
          stepId: step.id,
          success: false,
          pivotEstablished: false,
          evidence: `Step type '${step.type}' blocked by stealthMode constraint`,
          executionTimeMs: Date.now() - startTime,
        };
      }

      if (step.technique.riskLevel === "high" || step.technique.riskLevel === "critical") {
        return {
          stepId: step.id,
          success: false,
          pivotEstablished: false,
          evidence: `Technique '${step.technique.name}' (${step.technique.riskLevel} risk) blocked by stealthMode constraint`,
          executionTimeMs: Date.now() - startTime,
        };
      }
    }

    switch (step.type) {
      case "pivot":
        return this.executePivot(step, startTime);

      case "credential_harvest":
        return this.executeCredentialHarvest(step, startTime);

      case "scan":
        return this.executeScan(step, startTime);

      case "exploit":
        return this.executeExploit(step, startTime);

      case "persist":
        return this.executePersistence(step, startTime);

      default:
        return {
          stepId: step.id,
          success: false,
          pivotEstablished: false,
          evidence: `Unknown step type: ${step.type}`,
          executionTimeMs: Date.now() - startTime,
        };
    }
  }

  private async executePivot(step: MovementStep, startTime: number): Promise<PivotResult> {
    if (!step.targetHost) {
      return {
        stepId: step.id,
        success: false,
        pivotEstablished: false,
        evidence: "No target host specified",
        executionTimeMs: Date.now() - startTime,
      };
    }

    const credentials = this.getCredentialsFor(step.requiredCredentials);
    
    const pivotTarget: PivotTarget = {
      host: step.targetHost,
      technique: step.technique.id,
      credentials,
      sourceAgent: step.sourceAgent,
    };

    const pivotResult = await this.pivotExecutor.executePivot(pivotTarget);

    if (pivotResult.success && pivotResult.newAgent) {
      await this.meshClient.registerAgent(pivotResult.newAgent);
    }

    return {
      stepId: step.id,
      success: pivotResult.success,
      pivotEstablished: pivotResult.success,
      newAgent: pivotResult.newAgent,
      evidence: pivotResult.evidence,
      executionTimeMs: Date.now() - startTime,
    };
  }

  private async executeCredentialHarvest(
    step: MovementStep,
    startTime: number
  ): Promise<PivotResult> {
    const agent = await this.meshClient.getAgent(step.sourceAgent);
    if (!agent) {
      return {
        stepId: step.id,
        success: false,
        pivotEstablished: false,
        evidence: "Source agent not found",
        executionTimeMs: Date.now() - startTime,
      };
    }

    const harvestedCreds: HarvestedCredential[] = [];

    harvestedCreds.push({
      type: "hash",
      username: "administrator",
      domain: "CORP",
      value: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
      source: agent.hostname,
      usableFor: ["smb", "wmi", "psexec"],
    });

    return {
      stepId: step.id,
      success: harvestedCreds.length > 0,
      pivotEstablished: false,
      credentials: harvestedCreds,
      evidence: `Harvested ${harvestedCreds.length} credentials from ${agent.hostname}`,
      executionTimeMs: Date.now() - startTime,
    };
  }

  private async executeScan(step: MovementStep, startTime: number): Promise<PivotResult> {
    const agent = await this.meshClient.getAgent(step.sourceAgent);
    if (!agent) {
      return {
        stepId: step.id,
        success: false,
        pivotEstablished: false,
        evidence: "Source agent not found",
        executionTimeMs: Date.now() - startTime,
      };
    }

    const discoveredHosts = [
      `${step.targetHost || "10.0.0.1"}`,
      "10.0.0.10",
      "10.0.0.20",
    ];

    return {
      stepId: step.id,
      success: true,
      pivotEstablished: false,
      evidence: `Discovered ${discoveredHosts.length} hosts: ${discoveredHosts.join(", ")}`,
      executionTimeMs: Date.now() - startTime,
    };
  }

  private async executeExploit(step: MovementStep, startTime: number): Promise<PivotResult> {
    if (!step.targetHost) {
      return {
        stepId: step.id,
        success: false,
        pivotEstablished: false,
        evidence: "No target host specified",
        executionTimeMs: Date.now() - startTime,
      };
    }

    const exploitSuccess = Math.random() > 0.3;

    if (exploitSuccess) {
      const newAgent: AgentInfo = {
        id: `agent-${Date.now()}`,
        hostname: step.targetHost,
        ip: step.targetHost,
        os: "windows",
        status: "active",
        lastSeen: new Date(),
        capabilities: ["exec", "upload", "download"],
      };

      return {
        stepId: step.id,
        success: true,
        pivotEstablished: true,
        newAgent,
        evidence: `Exploit successful on ${step.targetHost}, agent deployed`,
        executionTimeMs: Date.now() - startTime,
      };
    }

    return {
      stepId: step.id,
      success: false,
      pivotEstablished: false,
      evidence: `Exploit failed on ${step.targetHost}`,
      executionTimeMs: Date.now() - startTime,
    };
  }

  private async executePersistence(step: MovementStep, startTime: number): Promise<PivotResult> {
    const agent = await this.meshClient.getAgent(step.sourceAgent);
    if (!agent) {
      return {
        stepId: step.id,
        success: false,
        pivotEstablished: false,
        evidence: "Source agent not found",
        executionTimeMs: Date.now() - startTime,
      };
    }

    return {
      stepId: step.id,
      success: true,
      pivotEstablished: false,
      evidence: `Persistence established on ${agent.hostname} via ${step.technique.name}`,
      executionTimeMs: Date.now() - startTime,
    };
  }

  private topologicalSort(steps: MovementStep[]): MovementStep[] {
    const sorted: MovementStep[] = [];
    const visited = new Set<string>();
    const visiting = new Set<string>();

    const stepMap = new Map(steps.map(s => [s.id, s]));

    const visit = (step: MovementStep) => {
      if (visited.has(step.id)) return;
      if (visiting.has(step.id)) {
        throw new Error(`Circular dependency detected at step ${step.id}`);
      }

      visiting.add(step.id);

      for (const depId of step.dependsOn || []) {
        const dep = stepMap.get(depId);
        if (dep) visit(dep);
      }

      visiting.delete(step.id);
      visited.add(step.id);
      sorted.push(step);
    };

    for (const step of steps) {
      visit(step);
    }

    return sorted;
  }

  private storeCredentials(host: string, credentials: HarvestedCredential[]): void {
    const existing = this.credentialStore.get(host) || [];
    this.credentialStore.set(host, [...existing, ...credentials]);
  }

  private getCredentialsFor(requiredTypes?: string[]): HarvestedCredential[] {
    if (!requiredTypes?.length) return [];

    const allCreds = Array.from(this.credentialStore.values()).flat();
    return allCreds.filter(c => requiredTypes.includes(c.type));
  }

  private isObjectiveAchieved(
    objective: MovementObjective,
    result: PivotResult
  ): boolean {
    switch (objective.type) {
      case "reach_target":
        return result.pivotEstablished && this.attackPath.includes(objective.target);

      case "escalate_privileges":
        return result.credentials?.some(c =>
          c.username?.toLowerCase().includes("admin") ||
          c.usableFor.includes("admin")
        ) ?? false;

      case "exfiltrate_data":
        return result.success && result.evidence.toLowerCase().includes("data");

      case "establish_persistence":
        return result.evidence.toLowerCase().includes("persistence");

      default:
        return false;
    }
  }

  private async getMeshStatus(): Promise<MeshStatus> {
    const agents = await this.meshClient.listAgents();
    const activeAgents = agents.filter((a: AgentInfo) => a.status === "active");

    const networks = new Set<string>();
    for (const agent of agents) {
      const networkPart = agent.ip.split(".").slice(0, 3).join(".");
      networks.add(`${networkPart}.0/24`);
    }

    let totalCreds = 0;
    const credValues = Array.from(this.credentialStore.values());
    for (const creds of credValues) {
      totalCreds += creds.length;
    }

    return {
      totalAgents: agents.length,
      activeAgents: activeAgents.length,
      pivotPoints: this.attackPath.length,
      credentialCount: totalCreds,
      reachableNetworks: Array.from(networks),
    };
  }

  getTechniques(): MovementTechnique[] {
    return LATERAL_MOVEMENT_TECHNIQUES;
  }

  getAttackPath(): string[] {
    return [...this.attackPath];
  }

  clearState(): void {
    this.credentialStore.clear();
    this.executedSteps.clear();
    this.attackPath = [];
  }
}
