import { sql } from "drizzle-orm";
import { pgTable, text, varchar, boolean, integer, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

// Exposure Types - Multi-Vector Coverage
export const exposureTypes = [
  "cve",                    // CVE exploitation (safe mode)
  "misconfiguration",       // General misconfigurations
  "behavioral_anomaly",     // Behavioral anomalies
  "network_vulnerability",  // Network pivoting
  "cloud_misconfiguration", // Cloud misconfiguration chaining (AWS/GCP/Azure)
  "iam_abuse",              // IAM abuse paths
  "saas_permission",        // SaaS permission abuse
  "shadow_admin",           // Shadow admin discovery
  "api_sequence_abuse",     // API sequence/workflow abuse
  "payment_flow",           // Payment flow vulnerabilities
  "subscription_bypass",    // Subscription & billing bypass
  "state_machine",          // State machine violations
  "privilege_boundary",     // Privilege boundary violations
  "workflow_desync",        // Workflow desynchronization
  "order_lifecycle",        // Order lifecycle abuse
] as const;

export type ExposureType = typeof exposureTypes[number];

// Business Logic Vulnerability Categories
export const businessLogicCategories = [
  "payment_bypass",         // Skipping payment steps
  "subscription_abuse",     // Free tier abuse, trial extension
  "order_manipulation",     // Price manipulation, quantity abuse
  "state_transition",       // Invalid state jumps
  "privilege_escalation",   // Horizontal/vertical escalation
  "workflow_bypass",        // Skipping required steps
  "race_condition",         // TOCTOU, double-spend
  "parameter_tampering",    // Hidden field manipulation
  "session_abuse",          // Session fixation, replay
  "logic_flaw",             // General logic flaws
] as const;

export type BusinessLogicCategory = typeof businessLogicCategories[number];

// Cloud/IAM Vector Types
export const cloudVectorTypes = [
  "s3_public_bucket",
  "iam_role_chaining",
  "cross_account_access",
  "metadata_service_abuse",
  "lambda_privilege_escalation",
  "storage_account_exposure",
  "service_account_abuse",
  "federation_bypass",
  "permission_boundary_bypass",
  "resource_policy_abuse",
] as const;

export type CloudVectorType = typeof cloudVectorTypes[number];

// AEV Evaluations table
export const aevEvaluations = pgTable("aev_evaluations", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  assetId: varchar("asset_id").notNull(),
  exposureType: varchar("exposure_type").notNull(), // One of exposureTypes
  priority: varchar("priority").notNull().default("medium"), // critical, high, medium, low
  description: text("description").notNull(),
  status: varchar("status").notNull().default("pending"), // pending, in_progress, completed, failed
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Attack path step type
export const attackPathStepSchema = z.object({
  id: z.number(),
  title: z.string(),
  description: z.string(),
  technique: z.string().optional(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  discoveredBy: z.enum(["recon", "exploit", "lateral", "business-logic", "impact"]).optional(),
});

// Recommendation type
export const recommendationSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  priority: z.enum(["critical", "high", "medium", "low"]),
  type: z.enum(["remediation", "compensating", "preventive"]),
});

export type AttackPathStep = z.infer<typeof attackPathStepSchema>;
export type Recommendation = z.infer<typeof recommendationSchema>;

// MITRE ATT&CK Kill Chain Tactics
export const killChainTactics = [
  "reconnaissance",
  "resource-development", 
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact"
] as const;

export type KillChainTactic = typeof killChainTactics[number];

// Attack Graph Node - represents a state/position in the attack
export const attackNodeSchema = z.object({
  id: z.string(),
  label: z.string(),
  description: z.string(),
  nodeType: z.enum(["entry", "pivot", "objective", "dead-end"]),
  tactic: z.enum(killChainTactics),
  compromiseLevel: z.enum(["none", "limited", "user", "admin", "system"]),
  assets: z.array(z.string()).optional(),
  discoveredBy: z.enum(["recon", "exploit", "lateral", "business-logic", "impact"]).optional(),
});

// Attack Graph Edge - represents a technique/transition between nodes
export const attackEdgeSchema = z.object({
  id: z.string(),
  source: z.string(),
  target: z.string(),
  technique: z.string(),
  techniqueId: z.string().optional(),
  description: z.string(),
  successProbability: z.number().min(0).max(100),
  complexity: z.enum(["trivial", "low", "medium", "high", "expert"]),
  timeEstimate: z.number(),
  prerequisites: z.array(z.string()).optional(),
  alternatives: z.array(z.string()).optional(),
  edgeType: z.enum(["primary", "alternative", "fallback"]),
  discoveredBy: z.enum(["recon", "exploit", "lateral", "business-logic", "impact"]).optional(),
});

// Complete Attack Graph structure
export const attackGraphSchema = z.object({
  nodes: z.array(attackNodeSchema),
  edges: z.array(attackEdgeSchema),
  entryNodeId: z.string(),
  objectiveNodeIds: z.array(z.string()),
  criticalPath: z.array(z.string()),
  alternativePaths: z.array(z.array(z.string())).optional(),
  killChainCoverage: z.array(z.enum(killChainTactics)),
  complexityScore: z.number().min(0).max(100),
  timeToCompromise: z.object({
    minimum: z.number(),
    expected: z.number(),
    maximum: z.number(),
    unit: z.enum(["minutes", "hours", "days"]),
  }),
  chainedExploits: z.array(z.object({
    name: z.string(),
    techniques: z.array(z.string()),
    combinedImpact: z.string(),
  })).optional(),
});

export type AttackNode = z.infer<typeof attackNodeSchema>;
export type AttackEdge = z.infer<typeof attackEdgeSchema>;
export type AttackGraph = z.infer<typeof attackGraphSchema>;

// Business Logic Vulnerability Finding
export const businessLogicFindingSchema = z.object({
  id: z.string(),
  category: z.enum(businessLogicCategories),
  title: z.string(),
  description: z.string(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  intendedWorkflow: z.array(z.string()),
  actualWorkflow: z.array(z.string()),
  stateViolations: z.array(z.object({
    fromState: z.string(),
    toState: z.string(),
    expectedTransitions: z.array(z.string()),
    actualTransition: z.string(),
    isViolation: z.boolean(),
  })).optional(),
  exploitSteps: z.array(z.string()),
  impact: z.string(),
  businessImpact: z.object({
    financialLoss: z.string().optional(),
    dataExposure: z.string().optional(),
    reputationalDamage: z.string().optional(),
    complianceViolation: z.string().optional(),
  }).optional(),
  validatedExploit: z.boolean(),
  proofOfConcept: z.string().optional(),
});

export type BusinessLogicFinding = z.infer<typeof businessLogicFindingSchema>;

// Workflow State Machine representation
export const workflowStateMachineSchema = z.object({
  name: z.string(),
  states: z.array(z.object({
    id: z.string(),
    name: z.string(),
    type: z.enum(["initial", "intermediate", "terminal", "error"]),
    requiredAuth: z.enum(["none", "user", "admin", "system"]).optional(),
  })),
  transitions: z.array(z.object({
    id: z.string(),
    from: z.string(),
    to: z.string(),
    trigger: z.string(),
    guard: z.string().optional(),
    isSecurityCritical: z.boolean().optional(),
  })),
  securityBoundaries: z.array(z.object({
    name: z.string(),
    statesWithin: z.array(z.string()),
    requiredPrivilege: z.string(),
  })).optional(),
});

export type WorkflowStateMachine = z.infer<typeof workflowStateMachineSchema>;

// Multi-Vector Analysis Finding
export const multiVectorFindingSchema = z.object({
  id: z.string(),
  vectorType: z.enum([...exposureTypes]),
  cloudVector: z.enum([...cloudVectorTypes]).optional(),
  title: z.string(),
  description: z.string(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  affectedResources: z.array(z.string()),
  chainableWith: z.array(z.string()).optional(),
  exploitPath: z.array(z.object({
    step: z.number(),
    action: z.string(),
    target: z.string(),
    technique: z.string().optional(),
  })),
  iamContext: z.object({
    principal: z.string().optional(),
    assumableRoles: z.array(z.string()).optional(),
    effectivePermissions: z.array(z.string()).optional(),
    privilegeEscalationPath: z.string().optional(),
  }).optional(),
  cloudContext: z.object({
    provider: z.enum(["aws", "gcp", "azure", "multi-cloud"]).optional(),
    region: z.string().optional(),
    service: z.string().optional(),
    resourceArn: z.string().optional(),
  }).optional(),
  saasContext: z.object({
    platform: z.string().optional(),
    permissionLevel: z.string().optional(),
    shadowAdminIndicators: z.array(z.string()).optional(),
  }).optional(),
});

export type MultiVectorFinding = z.infer<typeof multiVectorFindingSchema>;

// Evidence Artifact Types
export const evidenceArtifactTypes = [
  "request_response",     // HTTP request/response pair
  "execution_trace",      // Step-by-step execution log
  "log_capture",          // System/application logs
  "screenshot",           // Safe screenshot capture
  "configuration_dump",   // Config state at time of exploit
  "data_sample",          // Sanitized data samples
  "network_capture",      // Network traffic summary
  "timeline_event",       // Timestamped event
] as const;

export type EvidenceArtifactType = typeof evidenceArtifactTypes[number];

// Evidence Artifact Schema - proof of exploit
export const evidenceArtifactSchema = z.object({
  id: z.string(),
  type: z.enum(evidenceArtifactTypes),
  timestamp: z.string(),
  title: z.string(),
  description: z.string(),
  data: z.object({
    request: z.object({
      method: z.string(),
      url: z.string(),
      headers: z.record(z.string()).optional(),
      body: z.string().optional(),
    }).optional(),
    response: z.object({
      statusCode: z.number(),
      headers: z.record(z.string()).optional(),
      body: z.string().optional(),
      timing: z.number().optional(),
    }).optional(),
    logs: z.array(z.object({
      timestamp: z.string(),
      level: z.enum(["debug", "info", "warn", "error"]),
      message: z.string(),
      source: z.string().optional(),
    })).optional(),
    screenshot: z.object({
      base64: z.string().optional(),
      url: z.string().optional(),
      caption: z.string(),
    }).optional(),
    trace: z.array(z.object({
      step: z.number(),
      action: z.string(),
      result: z.string(),
      duration: z.number().optional(),
    })).optional(),
  }),
  tags: z.array(z.string()).optional(),
  attackStepId: z.number().optional(),
  findingId: z.string().optional(),
  isSanitized: z.boolean().default(true),
});

export type EvidenceArtifact = z.infer<typeof evidenceArtifactSchema>;

// Evidence Packet - collection of artifacts for sharing
export const evidencePacketSchema = z.object({
  id: z.string(),
  evaluationId: z.string(),
  createdAt: z.string(),
  title: z.string(),
  summary: z.string(),
  artifacts: z.array(evidenceArtifactSchema),
  timeline: z.array(z.object({
    timestamp: z.string(),
    event: z.string(),
    artifactId: z.string().optional(),
  })),
  executiveSummary: z.string().optional(),
  replayInstructions: z.string().optional(),
  metadata: z.object({
    evaluationType: z.string(),
    assetId: z.string(),
    totalArtifacts: z.number(),
    criticalFindings: z.number(),
  }),
});

export type EvidencePacket = z.infer<typeof evidencePacketSchema>;

// Compliance Frameworks
export const complianceFrameworks = [
  "pci_dss",    // Payment Card Industry
  "hipaa",      // Healthcare
  "sox",        // Financial reporting
  "gdpr",       // EU data protection
  "ccpa",       // California privacy
  "iso27001",   // Information security
  "nist",       // NIST Cybersecurity Framework
  "soc2",       // Service Organization Control
] as const;

export type ComplianceFramework = typeof complianceFrameworks[number];

// Exploitability Score Schema - contextual risk assessment
export const exploitabilityScoreSchema = z.object({
  score: z.number().min(0).max(100),
  confidence: z.number().min(0).max(100),
  factors: z.object({
    attackComplexity: z.object({
      level: z.enum(["trivial", "low", "medium", "high", "expert"]),
      score: z.number().min(0).max(100),
      rationale: z.string(),
    }),
    authenticationRequired: z.object({
      level: z.enum(["none", "single", "multi-factor", "privileged"]),
      score: z.number().min(0).max(100),
      rationale: z.string(),
    }),
    environmentalContext: z.object({
      networkExposure: z.enum(["internet", "dmz", "internal", "isolated"]),
      patchLevel: z.enum(["current", "behind", "significantly_behind", "eol"]),
      compensatingControls: z.array(z.string()),
      score: z.number().min(0).max(100),
    }),
    detectionLikelihood: z.object({
      level: z.enum(["unlikely", "possible", "likely", "certain"]),
      monitoringCoverage: z.number().min(0).max(100),
      evasionDifficulty: z.enum(["trivial", "moderate", "difficult", "near_impossible"]),
      score: z.number().min(0).max(100),
    }),
    exploitMaturity: z.object({
      availability: z.enum(["theoretical", "poc", "weaponized", "in_the_wild"]),
      skillRequired: z.enum(["script_kiddie", "intermediate", "advanced", "nation_state"]),
      score: z.number().min(0).max(100),
    }),
  }),
});

export type ExploitabilityScore = z.infer<typeof exploitabilityScoreSchema>;

// Business Impact Score Schema
export const businessImpactScoreSchema = z.object({
  score: z.number().min(0).max(100),
  riskLabel: z.enum(["minimal", "low", "moderate", "significant", "severe", "catastrophic"]),
  factors: z.object({
    dataSensitivity: z.object({
      classification: z.enum(["public", "internal", "confidential", "restricted", "top_secret"]),
      dataTypes: z.array(z.enum(["pii", "phi", "pci", "credentials", "trade_secrets", "financial", "customer_data"])),
      recordsAtRisk: z.string(),
      score: z.number().min(0).max(100),
    }),
    financialExposure: z.object({
      directLoss: z.object({
        min: z.number(),
        max: z.number(),
        currency: z.string().default("USD"),
      }),
      regulatoryFines: z.object({
        potential: z.number(),
        frameworks: z.array(z.string()),
      }),
      remediationCost: z.number(),
      businessDisruptionCost: z.number(),
      score: z.number().min(0).max(100),
    }),
    complianceImpact: z.object({
      affectedFrameworks: z.array(z.enum(complianceFrameworks)),
      violations: z.array(z.object({
        framework: z.string(),
        requirement: z.string(),
        severity: z.enum(["minor", "major", "critical"]),
      })),
      auditImplications: z.string().optional(),
      score: z.number().min(0).max(100),
    }),
    blastRadius: z.object({
      affectedSystems: z.number(),
      affectedUsers: z.string(),
      downstreamDependencies: z.array(z.string()),
      propagationRisk: z.enum(["contained", "limited", "spreading", "uncontained"]),
      score: z.number().min(0).max(100),
    }),
    reputationalRisk: z.object({
      customerTrust: z.enum(["minimal", "moderate", "significant", "severe"]),
      mediaExposure: z.enum(["unlikely", "possible", "likely", "certain"]),
      competitiveAdvantage: z.enum(["none", "minor", "moderate", "major"]),
      score: z.number().min(0).max(100),
    }),
  }),
});

export type BusinessImpactScore = z.infer<typeof businessImpactScoreSchema>;

// Combined Risk Rank Schema
export const riskRankSchema = z.object({
  overallScore: z.number().min(0).max(100),
  riskLevel: z.enum(["info", "low", "medium", "high", "critical", "emergency"]),
  executiveLabel: z.string(),
  fixPriority: z.number().min(1).max(100),
  recommendation: z.object({
    action: z.string(),
    timeframe: z.enum(["immediate", "24_hours", "7_days", "30_days", "90_days", "acceptable_risk"]),
    justification: z.string(),
  }),
  comparison: z.object({
    cvssEquivalent: z.number().optional(),
    industryPercentile: z.number().optional(),
    organizationPercentile: z.number().optional(),
  }).optional(),
  trendIndicator: z.enum(["improving", "stable", "degrading", "new"]).optional(),
});

export type RiskRank = z.infer<typeof riskRankSchema>;

// Complete Intelligent Score combining all factors
export const intelligentScoreSchema = z.object({
  exploitability: exploitabilityScoreSchema,
  businessImpact: businessImpactScoreSchema,
  riskRank: riskRankSchema,
  calculatedAt: z.string(),
  methodology: z.string().optional(),
  overrides: z.array(z.object({
    field: z.string(),
    originalValue: z.any(),
    overrideValue: z.any(),
    reason: z.string(),
    overriddenBy: z.string(),
    timestamp: z.string(),
  })).optional(),
});

export type IntelligentScore = z.infer<typeof intelligentScoreSchema>;

// Remediation Types
export const remediationTypes = [
  "code_fix",           // Code-level patches
  "config_change",      // Configuration updates
  "waf_rule",           // WAF/firewall rules
  "iam_policy",         // IAM policy changes
  "network_control",    // Network segmentation/controls
  "detection_rule",     // SIEM/detection signatures
  "compensating",       // Compensating controls
] as const;

export type RemediationType = typeof remediationTypes[number];

// Code Fix Schema
export const codeFixSchema = z.object({
  id: z.string(),
  title: z.string(),
  language: z.string(),
  filePath: z.string().optional(),
  vulnerability: z.string(),
  beforeCode: z.string(),
  afterCode: z.string(),
  explanation: z.string(),
  complexity: z.enum(["trivial", "low", "medium", "high"]),
  testingNotes: z.string().optional(),
});

export type CodeFix = z.infer<typeof codeFixSchema>;

// WAF Rule Schema
export const wafRuleSchema = z.object({
  id: z.string(),
  title: z.string(),
  platform: z.enum(["cloudflare", "aws_waf", "azure_waf", "modsecurity", "nginx", "generic"]),
  ruleType: z.enum(["block", "rate_limit", "challenge", "log"]),
  condition: z.string(),
  action: z.string(),
  priority: z.number(),
  description: z.string(),
  falsePositiveRisk: z.enum(["low", "medium", "high"]),
  rawConfig: z.string(),
});

export type WafRule = z.infer<typeof wafRuleSchema>;

// IAM Policy Schema
export const iamPolicySchema = z.object({
  id: z.string(),
  title: z.string(),
  platform: z.enum(["aws", "gcp", "azure", "okta", "generic"]),
  policyType: z.enum(["deny", "allow", "boundary", "scp"]),
  currentState: z.string(),
  recommendedState: z.string(),
  affectedPrincipals: z.array(z.string()),
  riskReduction: z.number().min(0).max(100),
  implementationSteps: z.array(z.string()),
  rollbackPlan: z.string().optional(),
  rawPolicy: z.string(),
});

export type IamPolicy = z.infer<typeof iamPolicySchema>;

// Network Control Schema
export const networkControlSchema = z.object({
  id: z.string(),
  title: z.string(),
  controlType: z.enum(["firewall", "segmentation", "acl", "vpn", "proxy"]),
  sourceZone: z.string(),
  destinationZone: z.string(),
  protocol: z.string(),
  ports: z.array(z.string()),
  action: z.enum(["allow", "deny", "log", "quarantine"]),
  description: z.string(),
  implementationGuide: z.string(),
});

export type NetworkControl = z.infer<typeof networkControlSchema>;

// Detection Rule Schema
export const detectionRuleSchema = z.object({
  id: z.string(),
  title: z.string(),
  platform: z.enum(["splunk", "elastic", "sentinel", "sigma", "yara", "snort", "generic"]),
  ruleType: z.enum(["correlation", "threshold", "anomaly", "signature"]),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  description: z.string(),
  logic: z.string(),
  rawRule: z.string(),
  dataSource: z.array(z.string()),
  mitreTechniques: z.array(z.string()).optional(),
  falsePositiveGuidance: z.string().optional(),
  responsePlaybook: z.string().optional(),
});

export type DetectionRule = z.infer<typeof detectionRuleSchema>;

// Compensating Control Schema
export const compensatingControlSchema = z.object({
  id: z.string(),
  title: z.string(),
  controlType: z.enum(["monitoring", "alerting", "access_review", "encryption", "backup", "training"]),
  description: z.string(),
  rationale: z.string(),
  implementationGuide: z.string(),
  effectiveness: z.number().min(0).max(100),
  duration: z.enum(["temporary", "permanent"]),
  reviewDate: z.string().optional(),
  dependencies: z.array(z.string()).optional(),
});

export type CompensatingControl = z.infer<typeof compensatingControlSchema>;

// Complete Remediation Guidance
export const remediationGuidanceSchema = z.object({
  id: z.string(),
  evaluationId: z.string(),
  generatedAt: z.string(),
  summary: z.string(),
  executiveSummary: z.string(),
  codeFixes: z.array(codeFixSchema).optional(),
  wafRules: z.array(wafRuleSchema).optional(),
  iamPolicies: z.array(iamPolicySchema).optional(),
  networkControls: z.array(networkControlSchema).optional(),
  detectionRules: z.array(detectionRuleSchema).optional(),
  compensatingControls: z.array(compensatingControlSchema).optional(),
  prioritizedActions: z.array(z.object({
    order: z.number(),
    action: z.string(),
    type: z.enum(remediationTypes),
    timeEstimate: z.string(),
    riskReduction: z.number().min(0).max(100),
    effort: z.enum(["low", "medium", "high"]),
  })),
  totalRiskReduction: z.number().min(0).max(100),
  estimatedImplementationTime: z.string(),
});

export type RemediationGuidance = z.infer<typeof remediationGuidanceSchema>;

// AEV Results table
export const aevResults = pgTable("aev_results", {
  id: varchar("id").primaryKey(),
  evaluationId: varchar("evaluation_id").notNull(),
  exploitable: boolean("exploitable").notNull(),
  confidence: integer("confidence").notNull(), // 0-100
  score: integer("score").notNull(), // 0-100
  attackPath: jsonb("attack_path").$type<AttackPathStep[]>(),
  attackGraph: jsonb("attack_graph").$type<AttackGraph>(),
  businessLogicFindings: jsonb("business_logic_findings").$type<BusinessLogicFinding[]>(),
  multiVectorFindings: jsonb("multi_vector_findings").$type<MultiVectorFinding[]>(),
  workflowAnalysis: jsonb("workflow_analysis").$type<WorkflowStateMachine>(),
  impact: text("impact"),
  recommendations: jsonb("recommendations").$type<Recommendation[]>(),
  evidenceArtifacts: jsonb("evidence_artifacts").$type<EvidenceArtifact[]>(),
  intelligentScore: jsonb("intelligent_score").$type<IntelligentScore>(),
  remediationGuidance: jsonb("remediation_guidance").$type<RemediationGuidance>(),
  duration: integer("duration"), // milliseconds
  completedAt: timestamp("completed_at"),
});

export const insertEvaluationSchema = createInsertSchema(aevEvaluations).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertResultSchema = createInsertSchema(aevResults).omit({
  id: true,
  completedAt: true,
});

export type InsertEvaluation = z.infer<typeof insertEvaluationSchema>;
export type Evaluation = typeof aevEvaluations.$inferSelect;
export type InsertResult = z.infer<typeof insertResultSchema>;
export type Result = typeof aevResults.$inferSelect;

// ============================================================================
// REPORTING & BATCH VALIDATION SCHEMAS
// ============================================================================

// Report Types
export const reportTypes = [
  "executive_summary",      // High-level for C-suite and board
  "technical_deepdive",     // Detailed for security engineers
  "compliance_mapping",     // Mapped to compliance frameworks
  "evidence_bundle",        // Full evidence package for auditors
] as const;

export type ReportType = typeof reportTypes[number];

// Export Formats
export const exportFormats = [
  "pdf",
  "csv",
  "json",
  "html",
] as const;

export type ExportFormat = typeof exportFormats[number];

// Report Finding Schema
export const reportFindingSchema = z.object({
  id: z.string(),
  evaluationId: z.string(),
  assetId: z.string(),
  title: z.string(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  exploitable: z.boolean(),
  score: z.number().min(0).max(100),
  description: z.string(),
  impact: z.string().optional(),
  recommendation: z.string().optional(),
  complianceViolations: z.array(z.object({
    framework: z.enum(complianceFrameworks),
    control: z.string(),
    description: z.string(),
  })).optional(),
  evidence: z.array(z.string()).optional(),
});

export type ReportFinding = z.infer<typeof reportFindingSchema>;

// Executive Summary Schema
export const executiveSummarySchema = z.object({
  reportDate: z.string(),
  reportPeriod: z.object({
    from: z.string(),
    to: z.string(),
  }),
  organizationId: z.string(),
  overallRiskLevel: z.enum(["critical", "high", "medium", "low"]),
  keyMetrics: z.object({
    totalEvaluations: z.number(),
    exploitableFindings: z.number(),
    criticalFindings: z.number(),
    highFindings: z.number(),
    mediumFindings: z.number(),
    lowFindings: z.number(),
    averageScore: z.number(),
    averageConfidence: z.number(),
  }),
  riskTrend: z.enum(["improving", "stable", "degrading"]),
  topRisks: z.array(z.object({
    assetId: z.string(),
    riskDescription: z.string(),
    severity: z.enum(["critical", "high", "medium", "low"]),
    financialImpact: z.string().optional(),
  })),
  recommendations: z.array(z.object({
    priority: z.number(),
    action: z.string(),
    impact: z.string(),
    effort: z.enum(["low", "medium", "high"]),
  })),
  executiveNarrative: z.string(),
  executiveSummary: z.string().optional(),
  findings: z.array(z.object({
    title: z.string(),
    description: z.string(),
    recommendation: z.string(),
    severity: z.enum(["critical", "high", "medium", "low"]),
  })).optional(),
});

export type ExecutiveSummary = z.infer<typeof executiveSummarySchema>;

// Technical Report Schema
export const technicalReportSchema = z.object({
  reportDate: z.string(),
  reportPeriod: z.object({
    from: z.string(),
    to: z.string(),
  }),
  organizationId: z.string(),
  findings: z.array(reportFindingSchema),
  attackPaths: z.array(z.object({
    evaluationId: z.string(),
    assetId: z.string(),
    steps: z.array(attackPathStepSchema),
    complexity: z.number(),
    timeToCompromise: z.string().optional(),
  })),
  vulnerabilityBreakdown: z.object({
    byType: z.record(z.string(), z.number()),
    bySeverity: z.record(z.string(), z.number()),
    byAsset: z.record(z.string(), z.number()),
  }),
  technicalDetails: z.array(z.object({
    evaluationId: z.string(),
    assetId: z.string(),
    exposureType: z.string(),
    technicalAnalysis: z.string(),
    exploitCode: z.string().optional(),
    mitigations: z.array(z.string()),
  })),
  executiveSummary: z.string().optional(),
  recommendations: z.array(z.string()).optional(),
});

export type TechnicalReport = z.infer<typeof technicalReportSchema>;

// Compliance Report Schema
export const complianceReportSchema = z.object({
  reportDate: z.string(),
  framework: z.enum(complianceFrameworks),
  organizationId: z.string(),
  overallCompliance: z.number().min(0).max(100),
  controlStatus: z.array(z.object({
    controlId: z.string(),
    controlName: z.string(),
    status: z.enum(["compliant", "non_compliant", "partial", "not_applicable"]),
    findings: z.array(z.string()),
    remediationRequired: z.boolean(),
    remediationDeadline: z.string().optional(),
  })),
  gaps: z.array(z.object({
    controlId: z.string(),
    gapDescription: z.string(),
    severity: z.enum(["critical", "high", "medium", "low"]),
    remediationGuidance: z.string(),
  })),
  auditReadiness: z.object({
    score: z.number().min(0).max(100),
    readyControls: z.number(),
    totalControls: z.number(),
    priorityActions: z.array(z.string()),
  }),
  executiveSummary: z.string().optional(),
  findings: z.array(z.object({
    title: z.string(),
    description: z.string(),
    recommendation: z.string(),
    severity: z.enum(["critical", "high", "medium", "low"]),
    status: z.enum(["open", "closed", "in_progress"]).optional(),
  })).optional(),
  recommendations: z.array(z.string()).optional(),
  complianceStatus: z.record(z.string(), z.object({
    status: z.string(),
    coverage: z.number(),
  })).optional(),
});

export type ComplianceReport = z.infer<typeof complianceReportSchema>;

// Reports Database Table
export const reports = pgTable("reports", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  reportType: varchar("report_type").notNull(), // executive_summary, technical_deepdive, compliance_mapping, evidence_bundle
  title: text("title").notNull(),
  dateRangeFrom: timestamp("date_range_from").notNull(),
  dateRangeTo: timestamp("date_range_to").notNull(),
  framework: varchar("framework"), // For compliance reports
  status: varchar("status").notNull().default("generating"), // generating, completed, failed
  content: jsonb("content"), // The actual report content
  evaluationIds: jsonb("evaluation_ids").$type<string[]>(), // Evaluations included
  createdAt: timestamp("created_at").defaultNow(),
  completedAt: timestamp("completed_at"),
});

export const insertReportSchema = createInsertSchema(reports).omit({
  id: true,
  createdAt: true,
  completedAt: true,
});

export type InsertReport = z.infer<typeof insertReportSchema>;
export type Report = typeof reports.$inferSelect;

// ============================================================================
// BATCH EVALUATION & SCHEDULING SCHEMAS
// ============================================================================

// Batch Job Status
export const batchJobStatuses = [
  "pending",
  "running",
  "completed",
  "failed",
  "cancelled",
] as const;

export type BatchJobStatus = typeof batchJobStatuses[number];

// Schedule Frequency
export const scheduleFrequencies = [
  "once",
  "daily",
  "weekly",
  "monthly",
  "quarterly",
] as const;

export type ScheduleFrequency = typeof scheduleFrequencies[number];

// Batch Evaluation Job
export const batchJobs = pgTable("batch_jobs", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  name: text("name").notNull(),
  description: text("description"),
  assets: jsonb("assets").$type<Array<{
    assetId: string;
    exposureType: string;
    priority: string;
    description: string;
  }>>().notNull(),
  status: varchar("status").notNull().default("pending"),
  progress: integer("progress").default(0), // 0-100
  totalEvaluations: integer("total_evaluations").notNull(),
  completedEvaluations: integer("completed_evaluations").default(0),
  failedEvaluations: integer("failed_evaluations").default(0),
  evaluationIds: jsonb("evaluation_ids").$type<string[]>(), // Created evaluation IDs
  scheduledAt: timestamp("scheduled_at"),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertBatchJobSchema = createInsertSchema(batchJobs).omit({
  id: true,
  createdAt: true,
  startedAt: true,
  completedAt: true,
  totalEvaluations: true,
  completedEvaluations: true,
  failedEvaluations: true,
  evaluationIds: true,
  progress: true,
});

export type InsertBatchJob = z.infer<typeof insertBatchJobSchema>;
export type BatchJob = typeof batchJobs.$inferSelect;

// Scheduled Scans
export const scheduledScans = pgTable("scheduled_scans", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().default("default"),
  name: text("name").notNull(),
  description: text("description"),
  assets: jsonb("assets").$type<Array<{
    assetId: string;
    exposureType: string;
    priority: string;
    description: string;
  }>>().notNull(),
  frequency: varchar("frequency").notNull(), // once, daily, weekly, monthly, quarterly
  dayOfWeek: integer("day_of_week"), // 0-6 for weekly
  dayOfMonth: integer("day_of_month"), // 1-31 for monthly
  timeOfDay: varchar("time_of_day"), // HH:MM format
  enabled: boolean("enabled").default(true),
  lastRunAt: timestamp("last_run_at"),
  nextRunAt: timestamp("next_run_at"),
  lastBatchJobId: varchar("last_batch_job_id"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertScheduledScanSchema = createInsertSchema(scheduledScans).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
  lastRunAt: true,
  lastBatchJobId: true,
});

export type InsertScheduledScan = z.infer<typeof insertScheduledScanSchema>;
export type ScheduledScan = typeof scheduledScans.$inferSelect;

// Drift Detection / Comparison Result
export const driftResultSchema = z.object({
  comparisonId: z.string(),
  baselineEvaluationId: z.string(),
  currentEvaluationId: z.string(),
  assetId: z.string(),
  comparedAt: z.string(),
  changes: z.object({
    scoreChange: z.number(), // Positive = worse, negative = better
    exploitabilityChange: z.enum(["became_exploitable", "became_safe", "unchanged"]),
    newFindings: z.array(z.string()),
    resolvedFindings: z.array(z.string()),
    severityChanges: z.array(z.object({
      findingId: z.string(),
      from: z.enum(["critical", "high", "medium", "low"]),
      to: z.enum(["critical", "high", "medium", "low"]),
    })),
  }),
  summary: z.string(),
  riskTrend: z.enum(["improving", "stable", "degrading"]),
});

export type DriftResult = z.infer<typeof driftResultSchema>;

// Evaluation History for Drift Detection
export const evaluationHistory = pgTable("evaluation_history", {
  id: varchar("id").primaryKey(),
  assetId: varchar("asset_id").notNull(),
  evaluationId: varchar("evaluation_id").notNull(),
  batchJobId: varchar("batch_job_id"),
  scheduledScanId: varchar("scheduled_scan_id"),
  snapshot: jsonb("snapshot").$type<{
    exploitable: boolean;
    score: number;
    confidence: number;
    findingSummary: string[];
  }>(),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertEvaluationHistorySchema = createInsertSchema(evaluationHistory).omit({
  id: true,
  createdAt: true,
});

export type InsertEvaluationHistory = z.infer<typeof insertEvaluationHistorySchema>;
export type EvaluationHistory = typeof evaluationHistory.$inferSelect;

// ========== GOVERNANCE, SAFETY & TRUST CONTROLS ==========

// Execution Modes
export const executionModes = ["safe", "live", "simulation"] as const;
export type ExecutionMode = typeof executionModes[number];

// Organization Governance Settings
export const organizationGovernance = pgTable("organization_governance", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull().unique(),
  executionMode: varchar("execution_mode").notNull().default("safe"), // safe, live, simulation
  killSwitchActive: boolean("kill_switch_active").default(false),
  killSwitchActivatedAt: timestamp("kill_switch_activated_at"),
  killSwitchActivatedBy: varchar("kill_switch_activated_by"),
  rateLimitPerHour: integer("rate_limit_per_hour").default(100),
  rateLimitPerDay: integer("rate_limit_per_day").default(1000),
  concurrentEvaluationsLimit: integer("concurrent_evaluations_limit").default(5),
  currentConcurrentEvaluations: integer("current_concurrent_evaluations").default(0),
  allowedTargetPatterns: jsonb("allowed_target_patterns").$type<string[]>().default([]),
  blockedTargetPatterns: jsonb("blocked_target_patterns").$type<string[]>().default([]),
  allowedNetworkRanges: jsonb("allowed_network_ranges").$type<string[]>().default([]),
  requireAuthorizationForLive: boolean("require_authorization_for_live").default(true),
  autoKillOnCritical: boolean("auto_kill_on_critical").default(true),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertOrganizationGovernanceSchema = createInsertSchema(organizationGovernance).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type InsertOrganizationGovernance = z.infer<typeof insertOrganizationGovernanceSchema>;
export type OrganizationGovernance = typeof organizationGovernance.$inferSelect;

// Authorization Log (Red-Team Activity Audit Trail)
export const authorizationLogActions = [
  "evaluation_started",
  "evaluation_completed",
  "kill_switch_activated",
  "kill_switch_deactivated",
  "execution_mode_changed",
  "scope_rule_modified",
  "rate_limit_exceeded",
  "unauthorized_target_blocked",
  "live_execution_authorized",
  "batch_job_started",
  "simulation_run",
] as const;

export type AuthorizationLogAction = typeof authorizationLogActions[number];

export const authorizationLogs = pgTable("authorization_logs", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  userId: varchar("user_id"),
  userName: varchar("user_name"),
  action: varchar("action").notNull(),
  targetAsset: varchar("target_asset"),
  evaluationId: varchar("evaluation_id"),
  executionMode: varchar("execution_mode"),
  details: jsonb("details").$type<Record<string, any>>(),
  ipAddress: varchar("ip_address"),
  userAgent: varchar("user_agent"),
  authorized: boolean("authorized").default(true),
  authorizationReason: text("authorization_reason"),
  riskLevel: varchar("risk_level"), // low, medium, high, critical
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertAuthorizationLogSchema = createInsertSchema(authorizationLogs).omit({
  id: true,
  createdAt: true,
});

export type InsertAuthorizationLog = z.infer<typeof insertAuthorizationLogSchema>;
export type AuthorizationLog = typeof authorizationLogs.$inferSelect;

// Scope Rules (Target Whitelist/Blacklist)
export const scopeRules = pgTable("scope_rules", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  name: text("name").notNull(),
  description: text("description"),
  ruleType: varchar("rule_type").notNull(), // allow, block
  targetType: varchar("target_type").notNull(), // ip, cidr, hostname, pattern
  targetValue: text("target_value").notNull(),
  priority: integer("priority").default(0), // Higher priority rules evaluated first
  enabled: boolean("enabled").default(true),
  expiresAt: timestamp("expires_at"),
  createdBy: varchar("created_by"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertScopeRuleSchema = createInsertSchema(scopeRules).omit({
  id: true,
  createdAt: true,
});

export type InsertScopeRule = z.infer<typeof insertScopeRuleSchema>;
export type ScopeRule = typeof scopeRules.$inferSelect;

// Rate Limit Tracking
export const rateLimitTracking = pgTable("rate_limit_tracking", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  windowStart: timestamp("window_start").notNull(),
  windowType: varchar("window_type").notNull(), // hour, day
  requestCount: integer("request_count").default(0),
  evaluationCount: integer("evaluation_count").default(0),
  blockedCount: integer("blocked_count").default(0),
});

// ========== ADVANCED / FUTURE DIFFERENTIATORS ==========

// AI Adversary Profiles
export const adversaryProfiles = [
  "script_kiddie",
  "opportunistic_criminal", 
  "organized_crime",
  "insider_threat",
  "nation_state",
  "apt_group",
  "hacktivist",
  "competitor",
] as const;

export type AdversaryProfile = typeof adversaryProfiles[number];

export const aiAdversaryProfiles = pgTable("ai_adversary_profiles", {
  id: varchar("id").primaryKey(),
  name: varchar("name").notNull(),
  profileType: varchar("profile_type").notNull(), // script_kiddie, nation_state, etc.
  description: text("description"),
  capabilities: jsonb("capabilities").$type<{
    technicalSophistication: number; // 1-10
    resources: number; // 1-10
    persistence: number; // 1-10
    stealth: number; // 1-10
    targetedAttacks: boolean;
    zerodays: boolean;
    socialEngineering: boolean;
    physicalAccess: boolean;
  }>(),
  typicalTTPs: jsonb("typical_ttps").$type<string[]>(), // MITRE ATT&CK technique IDs
  motivations: jsonb("motivations").$type<string[]>(), // financial, espionage, disruption, etc.
  targetPreferences: jsonb("target_preferences").$type<string[]>(), // industries, asset types
  avgDwellTime: integer("avg_dwell_time"), // Days
  detectionDifficulty: varchar("detection_difficulty"), // low, medium, high, very_high
  isBuiltIn: boolean("is_built_in").default(false),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertAiAdversaryProfileSchema = createInsertSchema(aiAdversaryProfiles).omit({
  id: true,
  createdAt: true,
});

export type InsertAiAdversaryProfile = z.infer<typeof insertAiAdversaryProfileSchema>;
export type AiAdversaryProfile = typeof aiAdversaryProfiles.$inferSelect;

// Attack Predictions
export const attackPredictions = pgTable("attack_predictions", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  assetId: varchar("asset_id"),
  predictionDate: timestamp("prediction_date").defaultNow(),
  timeHorizon: varchar("time_horizon").notNull(), // 7d, 30d, 90d
  predictedAttackVectors: jsonb("predicted_attack_vectors").$type<Array<{
    vector: string;
    likelihood: number; // 0-100
    confidence: number; // 0-100
    adversaryProfile: string;
    estimatedImpact: string;
    mitreAttackId: string;
  }>>(),
  overallBreachLikelihood: integer("overall_breach_likelihood"), // 0-100
  riskFactors: jsonb("risk_factors").$type<Array<{
    factor: string;
    contribution: number; // percentage
    trend: string; // increasing, stable, decreasing
  }>>(),
  recommendedActions: jsonb("recommended_actions").$type<string[]>(),
  modelVersion: varchar("model_version"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertAttackPredictionSchema = createInsertSchema(attackPredictions).omit({
  id: true,
  createdAt: true,
});

export type InsertAttackPrediction = z.infer<typeof insertAttackPredictionSchema>;
export type AttackPrediction = typeof attackPredictions.$inferSelect;

// Defensive Posture Score
export const defensivePostureScores = pgTable("defensive_posture_scores", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  calculatedAt: timestamp("calculated_at").defaultNow(),
  overallScore: integer("overall_score").notNull(), // 0-100
  categoryScores: jsonb("category_scores").$type<{
    networkSecurity: number;
    applicationSecurity: number;
    identityManagement: number;
    dataProtection: number;
    incidentResponse: number;
    securityAwareness: number;
    compliancePosture: number;
  }>(),
  breachLikelihood: integer("breach_likelihood"), // 0-100
  meanTimeToDetect: integer("mean_time_to_detect"), // Hours
  meanTimeToRespond: integer("mean_time_to_respond"), // Hours
  vulnerabilityExposure: jsonb("vulnerability_exposure").$type<{
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>(),
  trendDirection: varchar("trend_direction"), // improving, stable, degrading
  benchmarkPercentile: integer("benchmark_percentile"), // vs industry
  recommendations: jsonb("recommendations").$type<string[]>(),
});

export const insertDefensivePostureScoreSchema = createInsertSchema(defensivePostureScores).omit({
  id: true,
  calculatedAt: true,
});

export type InsertDefensivePostureScore = z.infer<typeof insertDefensivePostureScoreSchema>;
export type DefensivePostureScore = typeof defensivePostureScores.$inferSelect;

// Purple Team Feedback Loop
export const purpleTeamFindings = pgTable("purple_team_findings", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  evaluationId: varchar("evaluation_id"),
  findingType: varchar("finding_type").notNull(), // offensive_success, detection_gap, control_bypass
  offensiveTechnique: varchar("offensive_technique"), // MITRE ATT&CK ID
  offensiveDescription: text("offensive_description"),
  detectionStatus: varchar("detection_status"), // detected, partially_detected, missed
  existingControl: text("existing_control"),
  controlEffectiveness: integer("control_effectiveness"), // 0-100
  defensiveRecommendation: text("defensive_recommendation"),
  implementationPriority: varchar("implementation_priority"), // critical, high, medium, low
  estimatedEffort: varchar("estimated_effort"), // hours, days, weeks
  feedbackStatus: varchar("feedback_status").default("pending"), // pending, in_progress, implemented, wont_fix
  assignedTo: varchar("assigned_to"),
  resolvedAt: timestamp("resolved_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertPurpleTeamFindingSchema = createInsertSchema(purpleTeamFindings).omit({
  id: true,
  createdAt: true,
});

export type InsertPurpleTeamFinding = z.infer<typeof insertPurpleTeamFindingSchema>;
export type PurpleTeamFinding = typeof purpleTeamFindings.$inferSelect;

// AI vs AI Simulation
export const aiSimulations = pgTable("ai_simulations", {
  id: varchar("id").primaryKey(),
  organizationId: varchar("organization_id").notNull(),
  name: text("name").notNull(),
  description: text("description"),
  attackerProfileId: varchar("attacker_profile_id"),
  defenderConfig: jsonb("defender_config").$type<{
    detectionCapabilities: string[];
    responseAutomation: boolean;
    honeypots: boolean;
    deception: boolean;
  }>(),
  targetEnvironment: jsonb("target_environment").$type<{
    assets: string[];
    networkTopology: string;
    securityControls: string[];
  }>(),
  simulationStatus: varchar("simulation_status").default("pending"), // pending, running, completed, failed
  simulationResults: jsonb("simulation_results").$type<{
    attackerSuccesses: number;
    defenderBlocks: number;
    timeToDetection: number; // minutes
    timeToContainment: number; // minutes
    attackPath: string[];
    detectionPoints: string[];
    missedAttacks: string[];
    recommendations: string[];
  }>(),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertAiSimulationSchema = createInsertSchema(aiSimulations).omit({
  id: true,
  createdAt: true,
});

export type InsertAiSimulation = z.infer<typeof insertAiSimulationSchema>;
export type AiSimulation = typeof aiSimulations.$inferSelect;
