import OpenAI from "openai";
import { getLLMValidationConfig, isLLMValidationEnabled } from "../../config/llm-validation";
import type { LLMValidationResult, LLMValidationVerdict } from "@shared/schema";

const OPENAI_TIMEOUT_MS = 90000;

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY || process.env.OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL || undefined,
  timeout: OPENAI_TIMEOUT_MS,
  maxRetries: 2,
});

export interface ValidationBundle {
  findingId: string;
  findingType: string;
  severity: string;
  title: string;
  description: string;
  affectedComponent?: string;
  cveId?: string;
  baseline?: string;
  attackEvidence?: string;
  diff?: string;
  context?: Record<string, unknown>;
}

export interface JudgeResult {
  verdict: LLMValidationVerdict;
  confidence: number;
  reason: string;
  missingEvidence?: string[];
  suggestedActions?: string[];
}

export interface BatchJudgeResult {
  findingId: string;
  result: LLMValidationResult;
  error?: string;
}

function truncateToBytes(text: string, maxBytes: number): string {
  if (!text) return "";
  const encoder = new TextEncoder();
  const encoded = encoder.encode(text);
  if (encoded.length <= maxBytes) return text;
  
  const decoder = new TextDecoder("utf-8", { fatal: false });
  const truncated = decoder.decode(encoded.slice(0, maxBytes));
  const lastValidIndex = truncated.lastIndexOf(" ");
  return (lastValidIndex > maxBytes * 0.8 ? truncated.slice(0, lastValidIndex) : truncated) + "... [truncated]";
}

export function buildValidationBundle(
  finding: {
    id?: string;
    findingType: string;
    severity: string;
    title: string;
    description?: string | null;
    affectedComponent?: string | null;
    cveId?: string | null;
  },
  options?: {
    baseline?: string;
    attackEvidence?: string;
    diff?: string;
    context?: Record<string, unknown>;
  }
): ValidationBundle {
  const config = getLLMValidationConfig();
  const maxSectionBytes = Math.floor(config.maxBundleSizeBytes / 4);
  
  return {
    findingId: finding.id || "unknown",
    findingType: finding.findingType,
    severity: finding.severity,
    title: truncateToBytes(finding.title, 500),
    description: truncateToBytes(finding.description || "", maxSectionBytes),
    affectedComponent: finding.affectedComponent || undefined,
    cveId: finding.cveId || undefined,
    baseline: options?.baseline ? truncateToBytes(options.baseline, maxSectionBytes) : undefined,
    attackEvidence: options?.attackEvidence ? truncateToBytes(options.attackEvidence, maxSectionBytes) : undefined,
    diff: options?.diff ? truncateToBytes(options.diff, maxSectionBytes) : undefined,
    context: options?.context,
  };
}

const JUDGE_SYSTEM_PROMPT = `You are the LLM JUDGE, an expert security finding validator for OdinForge AI.

Your task is to evaluate security findings and determine if they are:
- "confirmed": Real, actionable security issue with sufficient evidence
- "noise": False positive, informational only, or lacks sufficient evidence to be actionable
- "needs_review": Potentially valid but requires human expert review due to ambiguity

Evaluation criteria:
1. EVIDENCE QUALITY: Does the finding have concrete evidence (CVE, exploit code, proof of concept)?
2. EXPLOITABILITY: Is this actually exploitable in the given context?
3. SEVERITY ACCURACY: Does the claimed severity match the actual impact?
4. ACTIONABILITY: Can a security team take concrete remediation steps?
5. CONTEXT: Does the finding make sense in the system's architecture?

Be strict but fair. Default to "noise" if evidence is insufficient.
Default to "needs_review" if the finding could be valid but you're uncertain.

Respond ONLY with valid JSON matching this exact structure:
{
  "verdict": "confirmed" | "noise" | "needs_review",
  "confidence": <number 0-100>,
  "reason": "<brief explanation>",
  "missingEvidence": ["<what evidence would strengthen this finding>"],
  "suggestedActions": ["<recommended next steps>"]
}`;

export async function judgeFinding(bundle: ValidationBundle): Promise<JudgeResult> {
  const config = getLLMValidationConfig();
  
  const userPrompt = `Evaluate this security finding:

Finding Type: ${bundle.findingType}
Severity: ${bundle.severity}
Title: ${bundle.title}
Description: ${bundle.description || "None provided"}
Affected Component: ${bundle.affectedComponent || "Unknown"}
CVE ID: ${bundle.cveId || "None"}

${bundle.baseline ? `Baseline State:\n${bundle.baseline}\n` : ""}
${bundle.attackEvidence ? `Attack Evidence:\n${bundle.attackEvidence}\n` : ""}
${bundle.diff ? `Diff/Changes:\n${bundle.diff}\n` : ""}
${bundle.context ? `Additional Context:\n${JSON.stringify(bundle.context, null, 2)}\n` : ""}

Evaluate and provide your verdict as JSON.`;

  let lastError: Error | null = null;
  
  for (let attempt = 0; attempt <= config.retryAttempts; attempt++) {
    try {
      if (attempt > 0) {
        await new Promise(resolve => setTimeout(resolve, config.retryDelayMs));
      }
      
      const response = await openai.chat.completions.create({
        model: config.model,
        messages: [
          { role: "system", content: JUDGE_SYSTEM_PROMPT },
          { role: "user", content: userPrompt },
        ],
        response_format: { type: "json_object" },
        max_completion_tokens: config.maxTokens,
        temperature: 0.1,
      });

      const content = response.choices[0]?.message?.content;
      if (!content) {
        throw new Error("No response from LLM Judge");
      }

      const parsed = JSON.parse(content);
      
      if (!parsed.verdict || !["confirmed", "noise", "needs_review"].includes(parsed.verdict)) {
        throw new Error(`Invalid verdict: ${parsed.verdict}`);
      }
      
      return {
        verdict: parsed.verdict as LLMValidationVerdict,
        confidence: Math.min(100, Math.max(0, parseInt(parsed.confidence, 10) || 50)),
        reason: String(parsed.reason || "No reason provided"),
        missingEvidence: Array.isArray(parsed.missingEvidence) ? parsed.missingEvidence : undefined,
        suggestedActions: Array.isArray(parsed.suggestedActions) ? parsed.suggestedActions : undefined,
      };
      
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      console.warn(`[LLM Judge] Attempt ${attempt + 1} failed:`, lastError.message);
    }
  }
  
  console.error(`[LLM Judge] All attempts failed for finding ${bundle.findingId}`);
  return {
    verdict: "error" as LLMValidationVerdict,
    confidence: 0,
    reason: `Validation failed: ${lastError?.message || "Unknown error"}`,
    missingEvidence: ["LLM validation could not be completed"],
    suggestedActions: ["Manual review required"],
  };
}

export async function judgeFindingsBatch(bundles: ValidationBundle[]): Promise<BatchJudgeResult[]> {
  if (!isLLMValidationEnabled()) {
    console.log("[LLM Judge] Validation disabled, skipping batch");
    return bundles.map(b => ({
      findingId: b.findingId,
      result: {
        verdict: "confirmed" as LLMValidationVerdict,
        confidence: 100,
        reason: "LLM validation disabled - auto-confirmed",
        validatedAt: new Date().toISOString(),
        model: "none",
      },
    }));
  }

  const config = getLLMValidationConfig();
  const results: BatchJudgeResult[] = [];
  
  for (let i = 0; i < bundles.length; i += config.batchSize) {
    const batch = bundles.slice(i, i + config.batchSize);
    
    const batchResults = await Promise.all(
      batch.map(async (bundle) => {
        try {
          const judgeResult = await judgeFinding(bundle);
          return {
            findingId: bundle.findingId,
            result: {
              ...judgeResult,
              validatedAt: new Date().toISOString(),
              model: config.model,
            } as LLMValidationResult,
          };
        } catch (error) {
          return {
            findingId: bundle.findingId,
            result: {
              verdict: "error" as LLMValidationVerdict,
              confidence: 0,
              reason: error instanceof Error ? error.message : "Unknown error",
              validatedAt: new Date().toISOString(),
              model: config.model,
            } as LLMValidationResult,
            error: error instanceof Error ? error.message : "Unknown error",
          };
        }
      })
    );
    
    results.push(...batchResults);
  }
  
  return results;
}

export interface GateResult {
  shouldDisplay: boolean;
  verdict: LLMValidationVerdict;
  confidence: number;
  reason: string;
}

export function applyValidationGate(
  judgeResult: JudgeResult,
  options?: {
    minConfidence?: number;
    treatNeedsReviewAsNoise?: boolean;
  }
): GateResult {
  const config = getLLMValidationConfig();
  const minConfidence = options?.minConfidence ?? config.confidenceThreshold;
  const treatNeedsReviewAsNoise = options?.treatNeedsReviewAsNoise ?? false;
  
  let shouldDisplay = true;
  
  if (judgeResult.verdict === "noise") {
    shouldDisplay = false;
  } else if (judgeResult.verdict === "needs_review" && treatNeedsReviewAsNoise) {
    shouldDisplay = false;
  } else if (judgeResult.verdict === "confirmed" && judgeResult.confidence < minConfidence) {
    shouldDisplay = false;
  } else if (judgeResult.verdict === "error") {
    shouldDisplay = true;
  }
  
  return {
    shouldDisplay,
    verdict: judgeResult.verdict,
    confidence: judgeResult.confidence,
    reason: judgeResult.reason,
  };
}

export async function validateFinding<T extends {
  id?: string;
  findingType: string;
  severity: string;
  title: string;
  description?: string | null;
  affectedComponent?: string | null;
  cveId?: string | null;
}>(
  finding: T,
  options?: {
    baseline?: string;
    attackEvidence?: string;
    diff?: string;
    context?: Record<string, unknown>;
  }
): Promise<T & { llmValidation: LLMValidationResult; llmValidationVerdict: LLMValidationVerdict }> {
  if (!isLLMValidationEnabled()) {
    return {
      ...finding,
      llmValidation: {
        verdict: "confirmed",
        confidence: 100,
        reason: "LLM validation disabled - auto-confirmed",
        validatedAt: new Date().toISOString(),
        model: "none",
      },
      llmValidationVerdict: "confirmed",
    };
  }

  const config = getLLMValidationConfig();
  const bundle = buildValidationBundle(finding, options);
  const judgeResult = await judgeFinding(bundle);
  
  const validation: LLMValidationResult = {
    ...judgeResult,
    validatedAt: new Date().toISOString(),
    model: config.model,
  };
  
  console.log(`[LLM Judge] Finding "${finding.title}": ${judgeResult.verdict} (${judgeResult.confidence}%) - ${judgeResult.reason}`);
  
  return {
    ...finding,
    llmValidation: validation,
    llmValidationVerdict: judgeResult.verdict,
  };
}
