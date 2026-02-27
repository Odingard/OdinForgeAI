import type { AttackPathStep, Recommendation, AttackGraph, BusinessLogicFinding, MultiVectorFinding, WorkflowStateMachine, BusinessLogicCategory, CloudVectorType, EvidenceArtifact, IntelligentScore, RemediationGuidance, AdversaryProfile, LLMValidationResult, LLMValidationVerdict, DebateSummary, DebateChainResult, DebateVerdict } from "@shared/schema";

export type { DebateSummary, DebateChainResult, DebateVerdict } from "@shared/schema";

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
  /** Ground-truth scan data from real handlers — injected by orchestrator */
  realScanData?: import("./scan-data-loader").RealScanData;
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
    /** Tool-call-backed fields — only present when agentic exploit agent validates */
    validated?: boolean;
    validationVerdict?: "confirmed" | "likely" | "theoretical" | "false_positive";
    validationConfidence?: number;
    evidence?: Array<{
      toolName: string;
      summary: string;
      request?: string;
      response?: string;
      timing?: number;
    }>;
  }>;
  cveReferences: string[];
  misconfigurations: string[];
  /** Aggregate tool call log from agentic exploit loop */
  toolCallLog?: Array<{
    turn: number;
    toolName: string;
    arguments: Record<string, unknown>;
    resultSummary: string;
    vulnerable: boolean;
    confidence: number;
    executionTimeMs: number;
  }>;
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
  organizationId?: string;
  agentName: string;
  originalAction: string;
  decision: PolicyDecision;
  modifiedAction?: string;
  reasoning: string;
  policyReferences: string[];
  executionMode?: string;
  timestamp: Date;
}

export interface PlanFindings {
  prioritizedChains: Array<{
    rank: number;
    attackVector: string;
    targetEndpoint: string;
    technique: string;
    mitreId: string;
    confidence: number;
    rationale: string;
    turnBudget: number;
  }>;
  totalTurnBudget: number;
  skippedVectors: string[];
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
  /** Ground-truth data from real scan handlers — used by all agents */
  groundTruth?: import("./scan-data-loader").RealScanData;
  /** Structured external recon results from fullRecon() — real scan data */
  externalRecon?: import("../external-recon").ReconResult;
  /** Phase 1 recon engine results — real infrastructure scanning */
  reconScan?: {
    fullRecon: import("../recon/index").FullReconResult;
    agentReport?: import("../recon/agents/orchestrator").AgentRunReport;
  };
  /** Attack plan derived from recon findings — guides exploit agent */
  plan?: PlanFindings;
  /** Threat intel enrichment — CISA KEV + EPSS data for plan agent prioritization */
  threatIntel?: {
    epssScores: Array<{ cve: string; epss: number; percentile: number }>;
    kevCves: string[];
  };
}

export interface AgentResult<T> {
  success: boolean;
  findings: T;
  agentName: string;
  processingTime: number;
  stopReason?: string;
}

export interface ValidationStats {
  total: number;
  confirmed: number;
  noise: number;
  needsReview: number;
  errors: number;
  skipped: number;
}

export interface ConfidenceBreakdown {
  exploitConfidence: number;     // from debate adjustedConfidence (0-1)
  groundTruthConfidence: number; // based on real scan data availability (0-1)
  overallConfidence: number;     // weighted combination (0-1)
  verifiedFindings: number;
  disputedFindings: number;
  rejectedFindings: number;
}

export interface NoiseReductionStats {
  inputCount: number;
  afterReachability: number;
  afterExploitability: number;
  afterEnvironmental: number;
  afterDeduplication: number;
  finalCount: number;
  removedChains: Array<{ name: string; reason: string; layer: string }>;
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
  debateSummary?: DebateSummary;
  confidenceBreakdown?: ConfidenceBreakdown;
  noiseReductionStats?: NoiseReductionStats;
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

// ── Persistent Exploit State ────────────────────────────────────────────

export interface ExploitStateObjective {
  id: string;
  description: string;
  achieved: boolean;
}

export interface ExploitState {
  /** Endpoints discovered during exploitation */
  discoveredEndpoints: string[];
  /** Confirmed vulnerabilities with technique + confidence */
  confirmedVulns: Array<{
    type: string;
    endpoint: string;
    technique: string;
    confidence: number;
  }>;
  /** Credentials or tokens obtained */
  credentials: Array<{
    type: string;
    value: string;
    scope: string;
  }>;
  /** Current privilege level (none → user → admin → root) */
  privilegeLevel: "none" | "user" | "admin" | "root";
  /** Capabilities gained (e.g., "file_read", "rce", "db_access") */
  capabilities: string[];
  /** Raw artifacts extracted (hashes, tokens, config snippets) */
  extractedArtifacts: string[];
  /** Constraints on further exploitation */
  constraints: {
    blockedEndpoints: string[];
    maxRequests: number;
    remainingBudget: number;
  };
  /** Objectives tracked across iterations */
  objectives: ExploitStateObjective[];
  /** Current chain iteration (0-indexed) */
  iteration: number;
  lastUpdatedAt: string;
}
