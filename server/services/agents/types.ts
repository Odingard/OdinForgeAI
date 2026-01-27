import type { AttackPathStep, Recommendation, AttackGraph, BusinessLogicFinding, MultiVectorFinding, WorkflowStateMachine, BusinessLogicCategory, CloudVectorType, EvidenceArtifact, IntelligentScore, RemediationGuidance, AdversaryProfile, LLMValidationResult, LLMValidationVerdict } from "@shared/schema";

export interface AgentContext {
  assetId: string;
  exposureType: string;
  priority: string;
  description: string;
  evaluationId: string;
  adversaryProfile?: AdversaryProfile;
  organizationId?: string;
  executionMode?: "safe" | "simulation" | "live";
  policyContext?: string;
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

export interface LateralShadowAdminIndicator {
  principal: string;
  platform: string;
  indicatorType: "excessive_permissions" | "dormant_admin" | "service_account_abuse" | "delegated_admin" | "hidden_role";
  evidence: string[];
  riskLevel: "critical" | "high" | "medium" | "low";
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
  shadowAdminIndicators?: LateralShadowAdminIndicator[];
}

export interface BusinessLogicFindings {
  workflowAbuse: string[];
  stateManipulation: string[];
  raceConditions: string[];
  authorizationBypass: string[];
  criticalFlows: string[];
}

export interface EnhancedBusinessLogicFindings {
  basicFindings: BusinessLogicFindings;
  detailedFindings: BusinessLogicFinding[];
  workflowAnalysis: WorkflowStateMachine | null;
  paymentFlowVulnerabilities: PaymentFlowVulnerability[];
  stateTransitionViolations: StateTransitionViolation[];
  inferredWorkflows: InferredWorkflow[];
}

export interface PaymentFlowVulnerability {
  id: string;
  category: "payment_bypass" | "subscription_abuse" | "order_manipulation" | "price_tampering" | "coupon_abuse";
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  affectedFlow: string[];
  exploitSteps: string[];
  financialImpact: string;
  validatedExploit: boolean;
}

export interface StateTransitionViolation {
  id: string;
  fromState: string;
  toState: string;
  expectedTransitions: string[];
  actualTransition: string;
  violationType: "skip" | "reverse" | "unauthorized" | "race_condition";
  severity: "critical" | "high" | "medium" | "low";
  exploitability: string;
}

export interface InferredWorkflow {
  name: string;
  description: string;
  steps: string[];
  securityCheckpoints: string[];
  potentialBypasses: string[];
}

export interface MultiVectorFindings {
  findings: MultiVectorFinding[];
  cloudFindings: CloudFinding[];
  iamFindings: IAMFinding[];
  saasFindings: SaaSFinding[];
  shadowAdminIndicators: ShadowAdminIndicator[];
  chainedAttackPaths: ChainedAttackPath[];
}

export interface CloudFinding {
  id: string;
  vectorType: CloudVectorType;
  provider: "aws" | "gcp" | "azure" | "multi-cloud";
  service: string;
  resource: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  exploitPath: string[];
  remediationSteps: string[];
}

export interface IAMFinding {
  id: string;
  principal: string;
  assumableRoles: string[];
  effectivePermissions: string[];
  privilegeEscalationPath: string | null;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
}

export interface SaaSFinding {
  id: string;
  platform: string;
  permissionLevel: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  shadowAdminIndicators: string[];
  exploitPath: string[];
}

export interface ShadowAdminIndicator {
  id: string;
  principal: string;
  platform: string;
  indicatorType: "excessive_permissions" | "dormant_admin" | "service_account_abuse" | "delegated_admin" | "hidden_role";
  evidence: string[];
  riskLevel: "critical" | "high" | "medium" | "low";
}

export interface ChainedAttackPath {
  id: string;
  name: string;
  vectors: string[];
  steps: Array<{
    step: number;
    action: string;
    target: string;
    technique: string;
  }>;
  combinedImpact: string;
  difficulty: "trivial" | "low" | "medium" | "high" | "expert";
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

export type PolicyDecision = "ALLOW" | "DENY" | "MODIFY";

export interface SafetyDecision {
  id: string;
  evaluationId: string;
  agentName: string;
  originalAction: string;
  decision: PolicyDecision;
  modifiedAction?: string;
  reasoning: string;
  policyReferences: string[];
  timestamp: Date;
}

export interface AgentMemory {
  context: AgentContext;
  recon?: ReconFindings;
  exploit?: ExploitFindings;
  lateral?: LateralFindings;
  businessLogic?: BusinessLogicFindings;
  enhancedBusinessLogic?: EnhancedBusinessLogicFindings;
  multiVector?: MultiVectorFindings;
  impact?: ImpactFindings;
  safetyDecisions?: SafetyDecision[];
}

export interface AgentResult<T> {
  success: boolean;
  findings: T;
  agentName: string;
  processingTime: number;
}

export interface ValidationStats {
  total: number;
  confirmed: number;
  noise: number;
  needsReview: number;
  errors: number;
  skipped: number;
}

export interface OrchestratorResult {
  exploitable: boolean;
  confidence: number;
  score: number;
  attackPath: (AttackPathStep & { llmValidation?: LLMValidationResult; llmValidationVerdict?: LLMValidationVerdict })[];
  attackGraph?: AttackGraph;
  businessLogicFindings?: (BusinessLogicFinding & { llmValidation?: LLMValidationResult; llmValidationVerdict?: LLMValidationVerdict })[];
  multiVectorFindings?: (MultiVectorFinding & { llmValidation?: LLMValidationResult; llmValidationVerdict?: LLMValidationVerdict })[];
  workflowAnalysis?: WorkflowStateMachine;
  evidenceArtifacts?: EvidenceArtifact[];
  intelligentScore?: IntelligentScore;
  remediationGuidance?: RemediationGuidance;
  llmValidation?: LLMValidationResult;
  llmValidationVerdict?: LLMValidationVerdict;
  validationStats?: ValidationStats;
  impact: string;
  recommendations: Recommendation[];
  agentFindings: {
    recon: ReconFindings;
    exploit: ExploitFindings;
    lateral: LateralFindings;
    businessLogic: BusinessLogicFindings;
    enhancedBusinessLogic?: EnhancedBusinessLogicFindings;
    multiVector?: MultiVectorFindings;
    impact: ImpactFindings;
  };
  safetyDecisions?: SafetyDecision[];
  totalProcessingTime: number;
}

export type ProgressCallback = (
  agentName: string,
  stage: string,
  progress: number,
  message: string
) => void;
