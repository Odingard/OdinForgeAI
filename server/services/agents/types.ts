import type { AttackPathStep, Recommendation, AttackGraph } from "@shared/schema";

export interface AgentContext {
  assetId: string;
  exposureType: string;
  priority: string;
  description: string;
  evaluationId: string;
}

export interface ReconFindings {
  attackSurface: string[];
  entryPoints: string[];
  apiEndpoints: string[];
  authMechanisms: string[];
  technologies: string[];
  potentialVulnerabilities: string[];
}

export interface ExploitFindings {
  exploitable: boolean;
  exploitChains: Array<{
    name: string;
    technique: string;
    description: string;
    success_likelihood: "high" | "medium" | "low";
  }>;
  cveReferences: string[];
  misconfigurations: string[];
}

export interface LateralFindings {
  pivotPaths: Array<{
    from: string;
    to: string;
    method: string;
    technique: string;
  }>;
  privilegeEscalation: Array<{
    target: string;
    method: string;
    likelihood: "high" | "medium" | "low";
  }>;
  tokenReuse: string[];
}

export interface BusinessLogicFindings {
  workflowAbuse: string[];
  stateManipulation: string[];
  raceConditions: string[];
  authorizationBypass: string[];
  criticalFlows: string[];
}

export interface ImpactFindings {
  dataExposure: {
    types: string[];
    severity: "critical" | "high" | "medium" | "low";
    estimatedRecords: string;
  };
  financialImpact: {
    estimate: string;
    factors: string[];
  };
  complianceImpact: string[];
  reputationalRisk: "critical" | "high" | "medium" | "low";
}

export interface AgentMemory {
  context: AgentContext;
  recon?: ReconFindings;
  exploit?: ExploitFindings;
  lateral?: LateralFindings;
  businessLogic?: BusinessLogicFindings;
  impact?: ImpactFindings;
}

export interface AgentResult<T> {
  success: boolean;
  findings: T;
  agentName: string;
  processingTime: number;
}

export interface OrchestratorResult {
  exploitable: boolean;
  confidence: number;
  score: number;
  attackPath: AttackPathStep[];
  attackGraph?: AttackGraph;
  impact: string;
  recommendations: Recommendation[];
  agentFindings: {
    recon: ReconFindings;
    exploit: ExploitFindings;
    lateral: LateralFindings;
    businessLogic: BusinessLogicFindings;
    impact: ImpactFindings;
  };
  totalProcessingTime: number;
}

export type ProgressCallback = (
  agentName: string,
  stage: string,
  progress: number,
  message: string
) => void;
