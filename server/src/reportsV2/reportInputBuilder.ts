/**
 * Report Input Builder
 * 
 * Creates the structured input payload for AI-powered report generation.
 * Aggregates evaluation data, findings, attack paths, evidence, risk scores,
 * and customer context into a single canonical object.
 */

import { z } from "zod";
import type { Evaluation, Result } from "@shared/schema";

// Customer context schema (optional tenant-level data)
export const customerContextSchema = z.object({
  industry: z.string().optional(),
  primaryDataTypes: z.array(z.enum(["PII", "PCI", "PHI", "IP", "FINANCIAL", "CLASSIFIED"])).optional(),
  criticalSystems: z.array(z.string()).optional(),
  riskTolerance: z.enum(["low", "medium", "high"]).optional(),
  complianceFrameworks: z.array(z.string()).optional(),
  organizationSize: z.enum(["small", "medium", "large", "enterprise"]).optional(),
});

export type CustomerContext = z.infer<typeof customerContextSchema>;

// Structured finding for AI input
export const reportFindingInputSchema = z.object({
  id: z.string(),
  evaluationId: z.string(),
  assetId: z.string(),
  assetName: z.string(),
  title: z.string(),
  description: z.string(),
  exposureType: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "informational"]),
  exploitable: z.boolean(),
  exploitabilityScore: z.number().min(0).max(100),
  cvssScore: z.number().min(0).max(10).optional(),
  cveId: z.string().optional(),
  affectedComponent: z.string().optional(),
  affectedVersion: z.string().optional(),
});

export type ReportFindingInput = z.infer<typeof reportFindingInputSchema>;

// Attack path for AI input
export const attackPathInputSchema = z.object({
  evaluationId: z.string(),
  assetId: z.string(),
  steps: z.array(z.object({
    order: z.number(),
    technique: z.string(),
    mitreId: z.string().optional(),
    description: z.string(),
    targetComponent: z.string().optional(),
  })),
  complexity: z.number().min(1).max(10),
  timeToCompromise: z.string().optional(),
  blastRadius: z.array(z.string()).optional(),
});

export type AttackPathInput = z.infer<typeof attackPathInputSchema>;

// Evidence artifact for AI input
export const evidenceArtifactInputSchema = z.object({
  id: z.string(),
  type: z.enum(["http_capture", "log_entry", "screenshot", "config_file", "network_trace", "command_output", "code_snippet"]),
  description: z.string(),
  timestamp: z.string().optional(),
  content: z.string().optional(), // Actual content (may be truncated for large artifacts)
  contentPreview: z.string().optional(), // Shortened preview
  findingIds: z.array(z.string()), // Which findings this evidence supports
});

export type EvidenceArtifactInput = z.infer<typeof evidenceArtifactInputSchema>;

// Risk score for AI input
export const riskScoreInputSchema = z.object({
  findingId: z.string(),
  baseScore: z.number(),
  adjustedScore: z.number(),
  impactFactor: z.number(),
  exploitabilityFactor: z.number(),
  blastRadius: z.string().optional(),
  financialEstimate: z.string().optional(),
  rationale: z.string(),
});

export type RiskScoreInput = z.infer<typeof riskScoreInputSchema>;

// Compliance mapping for AI input
export const complianceMappingInputSchema = z.object({
  framework: z.string(),
  controls: z.array(z.object({
    controlId: z.string(),
    controlName: z.string(),
    status: z.enum(["pass", "fail", "partial", "not_applicable"]),
    findingIds: z.array(z.string()),
    evidenceIds: z.array(z.string()),
    notes: z.string().optional(),
  })),
});

export type ComplianceMappingInput = z.infer<typeof complianceMappingInputSchema>;

// Full report input payload
export const reportInputPayloadSchema = z.object({
  // Metadata
  generatedAt: z.string(),
  reportScopeType: z.enum(["single_evaluation", "multi_evaluation", "date_range"]),
  
  // Evaluation metadata
  evaluationMetadata: z.object({
    organizationId: z.string(),
    evaluationIds: z.array(z.string()),
    dateRange: z.object({
      from: z.string(),
      to: z.string(),
    }).optional(),
    totalEvaluations: z.number(),
    completedEvaluations: z.number(),
  }),
  
  // Core data
  findings: z.array(reportFindingInputSchema),
  attackPaths: z.array(attackPathInputSchema),
  evidenceArtifacts: z.array(evidenceArtifactInputSchema),
  riskScores: z.array(riskScoreInputSchema),
  
  // Compliance (optional)
  complianceMappings: z.array(complianceMappingInputSchema).optional(),
  
  // Customer context (optional but recommended)
  customerContext: customerContextSchema.optional(),
  
  // Statistics
  statistics: z.object({
    severityDistribution: z.object({
      critical: z.number(),
      high: z.number(),
      medium: z.number(),
      low: z.number(),
      informational: z.number(),
    }),
    exposureTypeDistribution: z.record(z.string(), z.number()),
    averageExploitabilityScore: z.number(),
    averageRiskScore: z.number(),
    assetsAffected: z.number(),
    uniqueCVEs: z.number(),
  }),
});

export type ReportInputPayload = z.infer<typeof reportInputPayloadSchema>;

/**
 * Build report input payload from a single evaluation
 */
export function buildReportInputFromEvaluation(
  evaluation: Evaluation,
  result: Result | null,
  customerContext?: CustomerContext
): ReportInputPayload {
  const now = new Date().toISOString();
  
  const findings: ReportFindingInput[] = [];
  const attackPaths: AttackPathInput[] = [];
  const evidenceArtifacts: EvidenceArtifactInput[] = [];
  const riskScores: RiskScoreInput[] = [];
  
  // Extract findings from result
  if (result) {
    // Main finding from evaluation
    const mainFindingId = `finding-${evaluation.id}-main`;
    // Use score field from Result type (maps to exploitability score)
    const exploitScore = result.score || 0;
    
    findings.push({
      id: mainFindingId,
      evaluationId: evaluation.id,
      assetId: evaluation.assetId,
      assetName: evaluation.assetId, // Could be enriched with asset name lookup
      title: `${evaluation.exposureType} Vulnerability`,
      description: evaluation.description || "",
      exposureType: evaluation.exposureType,
      severity: mapSeverity(exploitScore),
      exploitable: result.exploitable || false,
      exploitabilityScore: exploitScore,
    });
    
    // Extract attack path if available
    if (result.attackPath && Array.isArray(result.attackPath)) {
      // Extract time to compromise from attack path steps if available
      const timeToCompromise = (result as any).timeToCompromise || undefined;
      
      attackPaths.push({
        evaluationId: evaluation.id,
        assetId: evaluation.assetId,
        steps: result.attackPath.map((step: any, index: number) => ({
          order: index + 1,
          technique: step.technique || step.description || "Unknown",
          mitreId: step.mitreId || step.tactic,
          description: step.description || step.technique || "",
          targetComponent: step.targetComponent,
        })),
        complexity: result.attackPath.length,
        timeToCompromise,
      });
    }
    
    // Extract evidence artifacts
    if (result.evidenceArtifacts && Array.isArray(result.evidenceArtifacts)) {
      result.evidenceArtifacts.forEach((artifact: any, index: number) => {
        evidenceArtifacts.push({
          id: `evidence-${evaluation.id}-${index}`,
          type: artifact.type || "log_entry",
          description: artifact.description || artifact.title || "Evidence artifact",
          timestamp: artifact.timestamp,
          content: artifact.content,
          contentPreview: artifact.content?.substring(0, 200),
          findingIds: [mainFindingId],
        });
      });
    }
    
    // Build risk score
    if (result.intelligentScore) {
      const scoreData = result.intelligentScore as any;
      riskScores.push({
        findingId: mainFindingId,
        baseScore: scoreData.baseScore || exploitScore,
        adjustedScore: scoreData.adjustedScore || scoreData.baseScore || exploitScore,
        impactFactor: scoreData.impactFactor || 1,
        exploitabilityFactor: scoreData.exploitabilityFactor || 1,
        blastRadius: scoreData.blastRadius,
        financialEstimate: scoreData.financialEstimate,
        rationale: scoreData.rationale || result.impact || "",
      });
    }
  }
  
  // Calculate statistics
  const severityDistribution = {
    critical: findings.filter(f => f.severity === "critical").length,
    high: findings.filter(f => f.severity === "high").length,
    medium: findings.filter(f => f.severity === "medium").length,
    low: findings.filter(f => f.severity === "low").length,
    informational: findings.filter(f => f.severity === "informational").length,
  };
  
  const exposureTypeDistribution: Record<string, number> = {};
  findings.forEach(f => {
    exposureTypeDistribution[f.exposureType] = (exposureTypeDistribution[f.exposureType] || 0) + 1;
  });
  
  return {
    generatedAt: now,
    reportScopeType: "single_evaluation",
    evaluationMetadata: {
      organizationId: evaluation.organizationId || "default",
      evaluationIds: [evaluation.id],
      totalEvaluations: 1,
      completedEvaluations: result ? 1 : 0,
    },
    findings,
    attackPaths,
    evidenceArtifacts,
    riskScores,
    customerContext,
    statistics: {
      severityDistribution,
      exposureTypeDistribution,
      averageExploitabilityScore: findings.length > 0 
        ? findings.reduce((sum, f) => sum + f.exploitabilityScore, 0) / findings.length 
        : 0,
      averageRiskScore: riskScores.length > 0
        ? riskScores.reduce((sum, r) => sum + r.adjustedScore, 0) / riskScores.length
        : 0,
      assetsAffected: new Set(findings.map(f => f.assetId)).size,
      uniqueCVEs: findings.filter(f => f.cveId).length,
    },
  };
}

/**
 * Build report input payload from multiple evaluations
 */
export function buildReportInputFromEvaluations(
  evaluations: Array<{ evaluation: Evaluation; result: Result | null }>,
  customerContext?: CustomerContext,
  dateRange?: { from: Date; to: Date }
): ReportInputPayload {
  const now = new Date().toISOString();
  
  const allFindings: ReportFindingInput[] = [];
  const allAttackPaths: AttackPathInput[] = [];
  const allEvidenceArtifacts: EvidenceArtifactInput[] = [];
  const allRiskScores: RiskScoreInput[] = [];
  
  // Process each evaluation
  for (const { evaluation, result } of evaluations) {
    const singleInput = buildReportInputFromEvaluation(evaluation, result, undefined);
    allFindings.push(...singleInput.findings);
    allAttackPaths.push(...singleInput.attackPaths);
    allEvidenceArtifacts.push(...singleInput.evidenceArtifacts);
    allRiskScores.push(...singleInput.riskScores);
  }
  
  // Calculate aggregated statistics
  const severityDistribution = {
    critical: allFindings.filter(f => f.severity === "critical").length,
    high: allFindings.filter(f => f.severity === "high").length,
    medium: allFindings.filter(f => f.severity === "medium").length,
    low: allFindings.filter(f => f.severity === "low").length,
    informational: allFindings.filter(f => f.severity === "informational").length,
  };
  
  const exposureTypeDistribution: Record<string, number> = {};
  allFindings.forEach(f => {
    exposureTypeDistribution[f.exposureType] = (exposureTypeDistribution[f.exposureType] || 0) + 1;
  });
  
  const organizationId = evaluations[0]?.evaluation.organizationId || "default";
  
  return {
    generatedAt: now,
    reportScopeType: dateRange ? "date_range" : "multi_evaluation",
    evaluationMetadata: {
      organizationId,
      evaluationIds: evaluations.map(e => e.evaluation.id),
      dateRange: dateRange ? {
        from: dateRange.from.toISOString(),
        to: dateRange.to.toISOString(),
      } : undefined,
      totalEvaluations: evaluations.length,
      completedEvaluations: evaluations.filter(e => e.result).length,
    },
    findings: allFindings,
    attackPaths: allAttackPaths,
    evidenceArtifacts: allEvidenceArtifacts,
    riskScores: allRiskScores,
    customerContext,
    statistics: {
      severityDistribution,
      exposureTypeDistribution,
      averageExploitabilityScore: allFindings.length > 0 
        ? allFindings.reduce((sum, f) => sum + f.exploitabilityScore, 0) / allFindings.length 
        : 0,
      averageRiskScore: allRiskScores.length > 0
        ? allRiskScores.reduce((sum, r) => sum + r.adjustedScore, 0) / allRiskScores.length
        : 0,
      assetsAffected: new Set(allFindings.map(f => f.assetId)).size,
      uniqueCVEs: allFindings.filter(f => f.cveId).length,
    },
  };
}

/**
 * Map exploitability score to severity level
 */
function mapSeverity(score: number): "critical" | "high" | "medium" | "low" | "informational" {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "informational";
}

