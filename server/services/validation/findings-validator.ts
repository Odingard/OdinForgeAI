import { isLLMValidationEnabled, getLLMValidationConfig } from "../../config/llm-validation";
import { buildValidationBundle, judgeFindingsBatch, applyValidationGate, type BatchJudgeResult } from "./llm-judge";
import type { AttackPathStep, BusinessLogicFinding, MultiVectorFinding, LLMValidationResult, LLMValidationVerdict } from "@shared/schema";

export interface ValidationStats {
  total: number;
  confirmed: number;
  noise: number;
  needsReview: number;
  errors: number;
  skipped: number;
}

export interface ValidatedOrchestratorResult {
  attackPath: (AttackPathStep & { llmValidation?: LLMValidationResult; llmValidationVerdict?: LLMValidationVerdict })[];
  businessLogicFindings?: (BusinessLogicFinding & { llmValidation?: LLMValidationResult; llmValidationVerdict?: LLMValidationVerdict })[];
  multiVectorFindings?: (MultiVectorFinding & { llmValidation?: LLMValidationResult; llmValidationVerdict?: LLMValidationVerdict })[];
  llmValidation?: LLMValidationResult;
  llmValidationVerdict?: LLMValidationVerdict;
  validationStats: ValidationStats;
}

function attackPathToBundle(step: AttackPathStep, context: { evaluationId: string; assetId: string; exposureType: string }) {
  return buildValidationBundle({
    id: `attack-step-${step.id}`,
    findingType: "attack_path_step",
    severity: step.severity,
    title: step.title,
    description: step.description,
    affectedComponent: context.assetId,
  }, {
    context: {
      technique: step.technique,
      discoveredBy: step.discoveredBy,
      evaluationId: context.evaluationId,
      exposureType: context.exposureType,
    },
  });
}

function businessLogicToBundle(finding: BusinessLogicFinding, context: { evaluationId: string }) {
  return buildValidationBundle({
    id: `bl-${finding.id}`,
    findingType: "business_logic",
    severity: finding.severity,
    title: finding.title,
    description: finding.description,
  }, {
    attackEvidence: finding.exploitSteps?.join("\n") || undefined,
    context: {
      category: finding.category,
      impact: finding.impact,
      evaluationId: context.evaluationId,
      intendedWorkflow: finding.intendedWorkflow,
      actualWorkflow: finding.actualWorkflow,
    },
  });
}

function multiVectorToBundle(finding: MultiVectorFinding, context: { evaluationId: string }) {
  return buildValidationBundle({
    id: `mv-${finding.id}`,
    findingType: "multi_vector",
    severity: finding.severity,
    title: finding.title,
    description: finding.description || "",
  }, {
    context: {
      vectorType: finding.vectorType,
      evaluationId: context.evaluationId,
    },
  });
}

function mapResultToFinding<T>(finding: T, idPrefix: string, results: BatchJudgeResult[]): T & { llmValidation?: LLMValidationResult; llmValidationVerdict?: LLMValidationVerdict } {
  const findingWithId = finding as T & { id?: string | number };
  const targetId = `${idPrefix}-${findingWithId.id}`;
  const matchingResult = results.find(r => r.findingId === targetId);
  
  if (matchingResult) {
    return {
      ...finding,
      llmValidation: matchingResult.result,
      llmValidationVerdict: matchingResult.result.verdict,
    };
  }
  
  return finding as T & { llmValidation?: LLMValidationResult; llmValidationVerdict?: LLMValidationVerdict };
}

export async function validateOrchestratorFindings(
  orchestratorResult: {
    attackPath: AttackPathStep[];
    businessLogicFindings?: BusinessLogicFinding[];
    multiVectorFindings?: MultiVectorFinding[];
  },
  context: {
    evaluationId: string;
    assetId: string;
    exposureType: string;
  },
  onProgress?: (stage: string, progress: number, message: string) => void
): Promise<ValidatedOrchestratorResult> {
  const stats: ValidationStats = {
    total: 0,
    confirmed: 0,
    noise: 0,
    needsReview: 0,
    errors: 0,
    skipped: 0,
  };

  if (!isLLMValidationEnabled()) {
    console.log("[Findings Validator] LLM validation disabled, skipping");
    return {
      attackPath: orchestratorResult.attackPath,
      businessLogicFindings: orchestratorResult.businessLogicFindings,
      multiVectorFindings: orchestratorResult.multiVectorFindings,
      validationStats: { ...stats, skipped: orchestratorResult.attackPath.length + (orchestratorResult.businessLogicFindings?.length || 0) + (orchestratorResult.multiVectorFindings?.length || 0) },
    };
  }

  onProgress?.("llm_validation", 0, "Preparing findings for validation...");

  const allBundles: { bundle: ReturnType<typeof buildValidationBundle>; type: string }[] = [];

  for (const step of orchestratorResult.attackPath) {
    allBundles.push({
      bundle: attackPathToBundle(step, context),
      type: "attack_path",
    });
  }

  if (orchestratorResult.businessLogicFindings) {
    for (const finding of orchestratorResult.businessLogicFindings) {
      allBundles.push({
        bundle: businessLogicToBundle(finding, context),
        type: "business_logic",
      });
    }
  }

  if (orchestratorResult.multiVectorFindings) {
    for (const finding of orchestratorResult.multiVectorFindings) {
      allBundles.push({
        bundle: multiVectorToBundle(finding, context),
        type: "multi_vector",
      });
    }
  }

  stats.total = allBundles.length;

  if (allBundles.length === 0) {
    console.log("[Findings Validator] No findings to validate");
    return {
      attackPath: orchestratorResult.attackPath,
      businessLogicFindings: orchestratorResult.businessLogicFindings,
      multiVectorFindings: orchestratorResult.multiVectorFindings,
      validationStats: stats,
    };
  }

  onProgress?.("llm_validation", 25, `Validating ${allBundles.length} findings...`);

  const bundlesOnly = allBundles.map(b => b.bundle);
  const results = await judgeFindingsBatch(bundlesOnly);

  onProgress?.("llm_validation", 75, "Processing validation results...");

  for (const result of results) {
    switch (result.result.verdict) {
      case "confirmed": stats.confirmed++; break;
      case "noise": stats.noise++; break;
      case "needs_review": stats.needsReview++; break;
      case "error": stats.errors++; break;
    }
  }

  const validatedAttackPath = orchestratorResult.attackPath.map(
    step => mapResultToFinding(step, "attack-step", results)
  );

  const validatedBusinessLogic = orchestratorResult.businessLogicFindings?.map(
    finding => mapResultToFinding(finding, "bl", results)
  );

  const validatedMultiVector = orchestratorResult.multiVectorFindings?.map(
    finding => mapResultToFinding(finding, "mv", results)
  );

  const overallConfidence = results.length > 0
    ? Math.round(results.reduce((sum, r) => sum + r.result.confidence, 0) / results.length)
    : 100;
  
  const confirmedCount = results.filter(r => r.result.verdict === "confirmed").length;
  const overallVerdict: LLMValidationVerdict = 
    confirmedCount === results.length ? "confirmed" :
    confirmedCount > results.length * 0.5 ? "needs_review" :
    "noise";

  const overallValidation: LLMValidationResult = {
    verdict: overallVerdict,
    confidence: overallConfidence,
    reason: `${stats.confirmed} confirmed, ${stats.noise} noise, ${stats.needsReview} needs review, ${stats.errors} errors`,
    validatedAt: new Date().toISOString(),
    model: getLLMValidationConfig().model,
  };

  console.log(`[Findings Validator] Completed: ${stats.confirmed} confirmed, ${stats.noise} noise, ${stats.needsReview} needs review, ${stats.errors} errors`);

  onProgress?.("llm_validation", 100, "Validation complete");

  return {
    attackPath: validatedAttackPath,
    businessLogicFindings: validatedBusinessLogic,
    multiVectorFindings: validatedMultiVector,
    llmValidation: overallValidation,
    llmValidationVerdict: overallVerdict,
    validationStats: stats,
  };
}
