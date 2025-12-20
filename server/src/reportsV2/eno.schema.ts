/**
 * Engagement Narrative Object (ENO) Schema
 * 
 * The ENO is the core AI-generated context object that captures the narrative
 * understanding of a security assessment. It serves as the foundation for
 * generating human-grade pentest reports across all formats (Executive, Technical,
 * Compliance, Evidence).
 */

import { z } from "zod";

// Confidence score schema (0-1 range)
const confidenceSchema = z.number().min(0).max(1);

// Evidence reference schema
export const evidenceReferenceSchema = z.object({
  id: z.string(),
  type: z.enum(["http_capture", "log_entry", "screenshot", "config_file", "network_trace", "command_output"]),
  description: z.string(),
  timestamp: z.string().optional(),
  relevance: z.string(),
});

export type EvidenceReference = z.infer<typeof evidenceReferenceSchema>;

// Attack story segment schema
export const attackStorySegmentSchema = z.object({
  phase: z.enum([
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "exfiltration",
    "impact"
  ]),
  narrative: z.string().min(50), // Require substantial narrative
  techniques: z.array(z.string()),
  evidenceRefs: z.array(z.string()),
  complexity: z.enum(["trivial", "moderate", "complex", "expert"]),
  confidence: confidenceSchema,
});

export type AttackStorySegment = z.infer<typeof attackStorySegmentSchema>;

// Defensive gap schema
export const defensiveGapSchema = z.object({
  category: z.enum([
    "detection",
    "prevention",
    "response",
    "recovery",
    "visibility",
    "process",
    "training"
  ]),
  title: z.string(),
  description: z.string().min(30),
  affectedAssets: z.array(z.string()),
  exploitedInAttack: z.boolean(),
  remediationEffort: z.enum(["low", "medium", "high"]),
  confidence: confidenceSchema,
});

export type DefensiveGap = z.infer<typeof defensiveGapSchema>;

// Risk prioritization entry schema
export const riskPrioritizationEntrySchema = z.object({
  findingId: z.string(),
  priority: z.number().int().min(1),
  businessImpact: z.string().min(20),
  exploitLikelihood: z.enum(["certain", "highly_likely", "likely", "possible", "unlikely"]),
  blastRadius: z.string(),
  financialExposure: z.string().optional(),
  rationale: z.string().min(50), // Require reasoning explanation
  confidence: confidenceSchema,
});

export type RiskPrioritizationEntry = z.infer<typeof riskPrioritizationEntrySchema>;

// Engagement overview schema
export const engagementOverviewSchema = z.object({
  scope: z.string().min(20),
  objectives: z.array(z.string()),
  methodology: z.string(),
  timeframe: z.object({
    start: z.string(),
    end: z.string(),
  }),
  assetsAssessed: z.array(z.object({
    id: z.string(),
    name: z.string(),
    type: z.string(),
    criticality: z.enum(["critical", "high", "medium", "low"]),
  })),
  overallRiskLevel: z.enum(["critical", "high", "medium", "low"]),
  keyHighlights: z.array(z.string()).min(1),
  confidence: confidenceSchema,
});

export type EngagementOverview = z.infer<typeof engagementOverviewSchema>;

// Business impact analysis schema
export const businessImpactAnalysisSchema = z.object({
  executiveSummary: z.string().min(100), // Require substantial summary
  primaryRisks: z.array(z.object({
    title: z.string(),
    description: z.string(),
    affectedBusinessProcess: z.string(),
    potentialConsequences: z.array(z.string()),
    estimatedFinancialImpact: z.string().optional(),
  })),
  operationalImpact: z.string(),
  reputationalImpact: z.string(),
  regulatoryImpact: z.string().optional(),
  customerImpact: z.string().optional(),
  supplyChainImpact: z.string().optional(),
  confidence: confidenceSchema,
});

export type BusinessImpactAnalysis = z.infer<typeof businessImpactAnalysisSchema>;

// Overall assessment schema
export const overallAssessmentSchema = z.object({
  verdict: z.enum(["critical", "high", "medium", "low"]),
  verdictNarrative: z.string().min(100), // Require explanation
  strengthsObserved: z.array(z.string()),
  criticalWeaknesses: z.array(z.string()),
  immediateActions: z.array(z.object({
    action: z.string(),
    priority: z.enum(["immediate", "short_term", "medium_term"]),
    effort: z.enum(["low", "medium", "high"]),
    expectedImpact: z.string(),
  })),
  strategicRecommendations: z.array(z.object({
    recommendation: z.string(),
    rationale: z.string(),
    timeframe: z.string(),
  })),
  confidence: confidenceSchema,
});

export type OverallAssessment = z.infer<typeof overallAssessmentSchema>;

// Main ENO Schema
export const enoSchema = z.object({
  version: z.literal("1.0"),
  generatedAt: z.string(),
  
  // Core narrative sections
  engagementOverview: engagementOverviewSchema,
  attackStory: z.array(attackStorySegmentSchema).min(1),
  businessImpactAnalysis: businessImpactAnalysisSchema,
  defensiveGaps: z.array(defensiveGapSchema),
  riskPrioritizationLogic: z.array(riskPrioritizationEntrySchema),
  overallAssessment: overallAssessmentSchema,
  
  // Evidence linkage
  evidenceIndex: z.array(evidenceReferenceSchema),
  
  // Model metadata for traceability
  modelMeta: z.object({
    modelName: z.string(),
    promptHash: z.string(),
    temperature: z.number(),
    generationTimeMs: z.number(),
  }),
  
  // Validation metadata
  validationStatus: z.object({
    passed: z.boolean(),
    warnings: z.array(z.string()),
    errors: z.array(z.string()),
  }),
});

export type ENO = z.infer<typeof enoSchema>;

// Partial ENO for incremental generation
export const partialEnoSchema = enoSchema.partial().extend({
  version: z.literal("1.0"),
  generatedAt: z.string(),
});

export type PartialENO = z.infer<typeof partialEnoSchema>;

// ENO validation result
export interface ENOValidationResult {
  valid: boolean;
  eno?: ENO;
  errors: string[];
  warnings: string[];
}

/**
 * Validate an ENO object
 */
export function validateENO(data: unknown): ENOValidationResult {
  const result = enoSchema.safeParse(data);
  
  if (result.success) {
    const warnings: string[] = [];
    
    // Check for quality warnings
    if (result.data.attackStory.length < 3) {
      warnings.push("Attack story has fewer than 3 phases - consider enriching narrative");
    }
    
    if (result.data.defensiveGaps.length === 0) {
      warnings.push("No defensive gaps identified - verify assessment completeness");
    }
    
    const avgConfidence = calculateAverageConfidence(result.data);
    if (avgConfidence < 0.7) {
      warnings.push(`Average confidence score is low (${avgConfidence.toFixed(2)}) - consider additional evidence`);
    }
    
    return {
      valid: true,
      eno: result.data,
      errors: [],
      warnings,
    };
  }
  
  return {
    valid: false,
    errors: result.error.errors.map(e => `${e.path.join('.')}: ${e.message}`),
    warnings: [],
  };
}

/**
 * Calculate average confidence across all ENO sections
 */
function calculateAverageConfidence(eno: ENO): number {
  const confidences: number[] = [
    eno.engagementOverview.confidence,
    eno.businessImpactAnalysis.confidence,
    eno.overallAssessment.confidence,
    ...eno.attackStory.map(s => s.confidence),
    ...eno.defensiveGaps.map(g => g.confidence),
    ...eno.riskPrioritizationLogic.map(r => r.confidence),
  ];
  
  return confidences.reduce((sum, c) => sum + c, 0) / confidences.length;
}
