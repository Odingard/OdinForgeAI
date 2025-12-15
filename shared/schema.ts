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
