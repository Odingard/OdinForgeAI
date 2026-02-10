/**
 * Report V2 Section Schemas
 * 
 * Defines the output format for AI-generated narrative reports.
 * These schemas match the structure expected by the UI and PDF export.
 */

import { z } from "zod";

// ============================================================================
// EXECUTIVE REPORT V2
// ============================================================================

export const strategicRecommendationSchema = z.object({
  title: z.string(),
  description: z.string().min(50),
  priority: z.enum(["critical", "high", "medium", "low"]),
  effort: z.enum(["low", "medium", "high"]),
  expectedOutcome: z.string(),
  stakeholders: z.array(z.string()).optional(),
});

export const dayPlanItemSchema = z.object({
  action: z.string(),
  owner: z.string().optional(),
  milestone: z.string().optional(),
  dependencies: z.array(z.string()).optional(),
});

export const executiveReportV2Schema = z.object({
  reportType: z.literal("executive_v2"),
  generatedAt: z.string(),
  
  // Core narrative sections
  executiveSummary: z.string().min(200), // 2-3 paragraphs
  
  topRisksRankedByBusinessImpact: z.array(z.object({
    rank: z.number(),
    title: z.string(),
    businessImpact: z.string().min(50),
    affectedBusinessProcess: z.string(),
    financialExposure: z.string().optional(),
    likelihood: z.enum(["certain", "highly_likely", "likely", "possible", "unlikely"]),
  })),
  
  attackStorySummary: z.string().min(150), // Condensed narrative
  
  financialExposure: z.object({
    estimatedTotalExposure: z.string(),
    breakdownByCategory: z.array(z.object({
      category: z.string(),
      amount: z.string(),
      basis: z.string(), // How the estimate was derived
    })),
    mitigationCostVsRisk: z.string(),
  }),
  
  strategicRecommendations: z.array(strategicRecommendationSchema),
  
  day30_60_90Plan: z.object({
    day30: z.array(dayPlanItemSchema),
    day60: z.array(dayPlanItemSchema),
    day90: z.array(dayPlanItemSchema),
  }),
  
  // Board-level talking points
  boardBriefingPoints: z.array(z.string()).optional(),
});

export type ExecutiveReportV2 = z.infer<typeof executiveReportV2Schema>;

// ============================================================================
// TECHNICAL REPORT V2
// ============================================================================

export const technicalFindingSchema = z.object({
  id: z.string(),
  title: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "informational"]),
  description: z.string().min(50),
  technicalDetails: z.string(),
  affectedComponents: z.array(z.string()),
  evidenceReferences: z.array(z.string()), // IDs from evidence package
  cweId: z.string().optional(),
  cveId: z.string().optional(),
  cvssScore: z.number().optional(),
});

export const attackPathDetailSchema = z.object({
  pathId: z.string(),
  title: z.string(),
  narrative: z.string().min(100), // Explanation of the attack chain
  steps: z.array(z.object({
    order: z.number(),
    technique: z.string(),
    mitreId: z.string().optional(),
    description: z.string(),
    prerequisites: z.array(z.string()).optional(),
    outcome: z.string(),
  })),
  complexity: z.enum(["trivial", "moderate", "complex", "expert"]),
  timeToCompromise: z.string(),
  businessImpact: z.string(),
  evidenceReferences: z.array(z.string()),
});

export const remediationStepSchema = z.object({
  priority: z.number(),
  findingIds: z.array(z.string()),
  action: z.string(),
  rationale: z.string().min(30), // Why this fix matters
  effort: z.enum(["low", "medium", "high"]),
  commands: z.array(z.string()).optional(),
  configChanges: z.string().optional(),
  toolsRequired: z.array(z.string()).optional(),
  verificationSteps: z.array(z.string()),
});

export const technicalReportV2Schema = z.object({
  reportType: z.literal("technical_v2"),
  generatedAt: z.string(),
  
  // Full technical narrative
  attackNarrativeDetailed: z.string().min(300),
  
  // Structured findings with evidence
  findings: z.array(technicalFindingSchema),
  
  // Attack path analysis with reasoning
  attackPathsWithReasoning: z.array(attackPathDetailSchema),
  
  // Prioritized remediation
  prioritizedFixPlan: z.array(remediationStepSchema),
  
  // Verification guidance
  verificationSteps: z.array(z.object({
    findingId: z.string(),
    steps: z.array(z.string()),
    expectedResult: z.string(),
    tools: z.array(z.string()).optional(),
  })),
  
  // Architecture recommendations
  architectureRecommendations: z.array(z.object({
    area: z.string(),
    currentState: z.string(),
    recommendedState: z.string(),
    rationale: z.string(),
    implementationNotes: z.string().optional(),
  })).optional(),
});

export type TechnicalReportV2 = z.infer<typeof technicalReportV2Schema>;

// ============================================================================
// COMPLIANCE REPORT V2
// ============================================================================

export const controlFailureSchema = z.object({
  controlId: z.string(),
  controlName: z.string(),
  framework: z.string(),
  operationalExplanation: z.string().min(50), // What this means in practice
  findingIds: z.array(z.string()),
  evidenceIds: z.array(z.string()),
  remediationGuidance: z.string(),
  compensatingControls: z.string().optional(),
});

export const complianceReportV2Schema = z.object({
  reportType: z.literal("compliance_v2"),
  generatedAt: z.string(),
  
  // Framework summary
  frameworkSummary: z.object({
    primaryFramework: z.string(),
    additionalFrameworks: z.array(z.string()),
    overallComplianceScore: z.number().min(0).max(100),
    criticalGaps: z.number(),
    partialCompliance: z.number(),
    fullCompliance: z.number(),
  }),
  
  // Control failures with operational context
  controlFailuresWithOperationalExplanations: z.array(controlFailureSchema),
  
  // Evidence mapped to controls
  evidenceLinks: z.array(z.object({
    evidenceId: z.string(),
    controlIds: z.array(z.string()),
    purpose: z.string(), // What this evidence proves/disproves
  })),
  
  // Audit preparation
  auditReadinessNotes: z.object({
    currentReadiness: z.enum(["not_ready", "partially_ready", "mostly_ready", "audit_ready"]),
    keyGaps: z.array(z.string()),
    recommendedActions: z.array(z.object({
      action: z.string(),
      timeline: z.string(),
      impact: z.string(),
    })),
    documentationNeeded: z.array(z.string()),
  }),
  
  // Framework-specific sections
  frameworkSpecificAnalysis: z.record(z.string(), z.object({
    requirements: z.array(z.object({
      requirementId: z.string(),
      description: z.string(),
      status: z.enum(["met", "not_met", "partially_met", "not_applicable"]),
      notes: z.string().optional(),
    })),
  })).optional(),
});

export type ComplianceReportV2 = z.infer<typeof complianceReportV2Schema>;

// ============================================================================
// EVIDENCE PACKAGE V2
// ============================================================================

export const artifactEntrySchema = z.object({
  id: z.string(),
  type: z.enum(["http_capture", "log_entry", "screenshot", "config_file", "network_trace", "command_output", "code_snippet"]),
  title: z.string(),
  description: z.string(),
  timestamp: z.string().optional(),
  sourceSystem: z.string().optional(),
  contentPreview: z.string().optional(),
  fullContentRef: z.string().optional(), // Reference to stored content
  chainOfCustody: z.object({
    collectedAt: z.string(),
    collectedBy: z.string(),
    hash: z.string().optional(),
  }).optional(),
});

export const evidencePackageV2Schema = z.object({
  reportType: z.literal("evidence_v2"),
  generatedAt: z.string(),
  
  // Chronological narrative
  timelineNarrative: z.string().min(200),
  
  // Timeline events
  timeline: z.array(z.object({
    timestamp: z.string(),
    event: z.string(),
    significance: z.string(),
    artifactIds: z.array(z.string()),
  })),
  
  // Artifact catalog
  artifactIndex: z.array(artifactEntrySchema),
  
  // What each artifact proves
  whatEachArtifactProves: z.array(z.object({
    artifactId: z.string(),
    proves: z.array(z.string()), // List of claims this artifact supports
    relatedFindings: z.array(z.string()),
    significance: z.enum(["critical", "supporting", "contextual"]),
  })),
  
  // Evidence summary statistics
  evidenceSummary: z.object({
    totalArtifacts: z.number(),
    byType: z.record(z.string(), z.number()),
    timespan: z.object({
      earliest: z.string(),
      latest: z.string(),
    }).optional(),
  }),
});

export type EvidencePackageV2 = z.infer<typeof evidencePackageV2Schema>;

// ============================================================================
// BREACH VALIDATION REPORT V2
// ============================================================================

export const breachValidationCoverPageSchema = z.object({
  title: z.string(),
  subtitle: z.string(),
  targetName: z.string(),
  assessmentType: z.string(),
  date: z.string(),
});

export const breachRealizationDimensionSchema = z.object({
  dimension: z.string(),
  score: z.number().min(0).max(100),
  explanation: z.string(),
});

export const attackPathOverviewEntrySchema = z.object({
  pathId: z.string(),
  shortName: z.string(),
  entryPoint: z.string(),
  pivotSequence: z.string(),
  endState: z.string(),
  businessImpact: z.string(),
});

export const exploitStepSchema = z.object({
  step: z.number(),
  action: z.string(),
  technique: z.string().optional(),
  outcome: z.string(),
  evidenceRef: z.string().optional(),
});

export const breachAttackPathDetailSchema = z.object({
  pathId: z.string(),
  title: z.string(),
  entryPoint: z.object({
    description: z.string(),
    preconditions: z.string(),
    whyExploitable: z.string(),
  }),
  exploitationSequence: z.array(exploitStepSchema),
  sessionReplayEvidence: z.object({
    timestamps: z.array(z.string()),
    stateChanges: z.array(z.string()),
    attestation: z.string(),
  }),
  endState: z.object({
    accessAchieved: z.string(),
    dataAccessible: z.string(),
    businessSignificance: z.string(),
  }),
});

export const remediationValidationSchema = z.object({
  attackPathId: z.string(),
  recommendedFix: z.object({
    description: z.string(),
    implementation: z.string(),
    effort: z.enum(["low", "medium", "high"]),
    timeline: z.string(),
  }),
  validationResult: z.object({
    replayAttempted: z.boolean(),
    blocked: z.boolean().nullable(),
    blockedAtStep: z.string().nullable(),
    verdict: z.enum(["ATTACK_PATH_BLOCKED", "ATTACK_PATH_STILL_EXPLOITABLE", "VALIDATION_PENDING"]),
    explanation: z.string(),
  }),
});

export const breachValidationReportV2Schema = z.object({
  reportType: z.literal("breach_validation_v2"),
  generatedAt: z.string(),

  coverPage: breachValidationCoverPageSchema,
  executiveBreachSummary: z.string().min(200),

  breachRealizationScore: z.object({
    overall: z.number().min(0).max(100),
    dimensions: z.array(breachRealizationDimensionSchema),
    narrativeExplanation: z.string().min(50),
  }),

  attackPathOverview: z.array(attackPathOverviewEntrySchema).min(1),
  attackPathDetails: z.array(breachAttackPathDetailSchema),

  remediationWithValidation: z.array(remediationValidationSchema),

  businessContext: z.object({
    financialRisk: z.string(),
    regulatoryExposure: z.string(),
    operationalDisruption: z.string(),
    reputationImpact: z.string(),
  }),

  technicalAppendix: z.object({
    exploitPayloads: z.array(z.object({
      attackPathId: z.string(),
      step: z.number(),
      payload: z.string(),
      requestResponse: z.string().optional(),
    })),
    environmentAssumptions: z.array(z.string()),
    toolsUsed: z.array(z.string()),
  }),

  differentiationStatement: z.string(),
  attestation: z.string(),
});

export type BreachValidationReportV2 = z.infer<typeof breachValidationReportV2Schema>;

// ============================================================================
// COMBINED REPORT V2
// ============================================================================

export const fullReportV2Schema = z.object({
  id: z.string(),
  version: z.literal("2.0"),
  generatedAt: z.string(),

  // Report sections
  executive: executiveReportV2Schema.optional(),
  technical: technicalReportV2Schema.optional(),
  compliance: complianceReportV2Schema.optional(),
  evidence: evidencePackageV2Schema.optional(),
  breach_validation: breachValidationReportV2Schema.optional(),

  // Metadata
  metadata: z.object({
    evaluationIds: z.array(z.string()),
    organizationId: z.string(),
    reportTitle: z.string(),
    dateRange: z.object({
      from: z.string(),
      to: z.string(),
    }).optional(),
  }),
});

export type FullReportV2 = z.infer<typeof fullReportV2Schema>;

// Export a dummy to satisfy the import in reportInputBuilder
export type ReportV2Input = {
  placeholder: true;
};
