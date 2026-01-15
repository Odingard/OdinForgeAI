import { ValidatingHttpClient } from "./validating-http-client";
import { createSqliValidator, type SqliValidationResult } from "./modules/sqli-validator";
import { createXssValidator, type XssValidationResult } from "./modules/xss-validator";
import { createAuthBypassValidator, type AuthBypassValidationResult } from "./modules/auth-bypass-validator";
import type { PayloadExecutionContext, PayloadResult } from "./payloads/payload-types";
import type { ValidationContext } from "./validating-http-client";
import type { ValidationVerdict } from "@shared/schema";

export type VulnerabilityType = "sqli" | "xss" | "auth_bypass" | "command_injection" | "path_traversal" | "ssrf";

export interface ValidationEngineConfig {
  maxPayloadsPerTest?: number;
  timeoutMs?: number;
  captureEvidence?: boolean;
  safeMode?: boolean;
}

export interface ValidationTarget {
  url: string;
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  parameterName: string;
  parameterLocation: "url_param" | "body_param" | "header" | "cookie" | "path";
  originalValue?: string;
  headers?: Record<string, string>;
  vulnerabilityTypes?: VulnerabilityType[];
}

export interface UnifiedValidationResult {
  target: ValidationTarget;
  vulnerable: boolean;
  overallConfidence: number;
  overallVerdict: ValidationVerdict;
  vulnerabilities: {
    type: VulnerabilityType;
    result: SqliValidationResult | XssValidationResult | AuthBypassValidationResult;
  }[];
  totalPayloadsTested: number;
  successfulPayloads: number;
  executionTimeMs: number;
  evidence: string[];
  recommendations: string[];
}

const DEFAULT_CONFIG: Required<ValidationEngineConfig> = {
  maxPayloadsPerTest: 10,
  timeoutMs: 10000,
  captureEvidence: true,
  safeMode: true,
};

export class ValidationEngine {
  private config: Required<ValidationEngineConfig>;
  private validationContext?: ValidationContext;
  private client: ValidatingHttpClient;

  constructor(config?: ValidationEngineConfig, validationContext?: ValidationContext) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.validationContext = validationContext;
    this.client = new ValidatingHttpClient();
  }

  async validateTarget(target: ValidationTarget): Promise<UnifiedValidationResult> {
    const startTime = Date.now();
    const vulnerabilities: UnifiedValidationResult["vulnerabilities"] = [];
    const allEvidence: string[] = [];
    const allRecommendations: string[] = [];
    let totalPayloads = 0;
    let successfulPayloads = 0;

    const executionContext: PayloadExecutionContext = {
      targetUrl: target.url,
      parameterName: target.parameterName,
      parameterLocation: target.parameterLocation,
      originalValue: target.originalValue,
      httpMethod: target.method,
      headers: target.headers,
      timeout: this.config.timeoutMs,
    };

    const typesToTest = target.vulnerabilityTypes || ["sqli", "xss", "auth_bypass"];

    for (const vulnType of typesToTest) {
      try {
        const result = await this.runValidator(vulnType, executionContext);
        if (result) {
          vulnerabilities.push({ type: vulnType, result });
          
          if (result.evidence) {
            allEvidence.push(result.evidence);
          }
          allRecommendations.push(...result.recommendations);
          
          totalPayloads += result.payloadResults.length;
          successfulPayloads += result.payloadResults.filter(p => p.success).length;
        }
      } catch (error) {
        console.error(`[ValidationEngine] Error running ${vulnType} validator:`, error);
      }
    }

    const executionTimeMs = Date.now() - startTime;
    const vulnerableResults = vulnerabilities.filter(v => v.result.vulnerable);
    const overallVulnerable = vulnerableResults.length > 0;
    const overallConfidence = vulnerableResults.length > 0
      ? Math.max(...vulnerableResults.map(v => v.result.confidence))
      : 0;
    const overallVerdict = this.determineOverallVerdict(overallConfidence);

    return {
      target,
      vulnerable: overallVulnerable,
      overallConfidence,
      overallVerdict,
      vulnerabilities,
      totalPayloadsTested: totalPayloads,
      successfulPayloads,
      executionTimeMs,
      evidence: allEvidence,
      recommendations: [...new Set(allRecommendations)],
    };
  }

  async validateMultipleTargets(targets: ValidationTarget[]): Promise<UnifiedValidationResult[]> {
    const results: UnifiedValidationResult[] = [];
    
    for (const target of targets) {
      try {
        const result = await this.validateTarget(target);
        results.push(result);
      } catch (error) {
        console.error(`[ValidationEngine] Error validating target ${target.url}:`, error);
      }
    }
    
    return results;
  }

  private async runValidator(
    type: VulnerabilityType,
    context: PayloadExecutionContext
  ): Promise<SqliValidationResult | XssValidationResult | AuthBypassValidationResult | null> {
    switch (type) {
      case "sqli": {
        const validator = createSqliValidator(this.validationContext);
        return validator.validate(context);
      }
      case "xss": {
        const validator = createXssValidator(this.validationContext);
        return validator.validate(context);
      }
      case "auth_bypass": {
        const validator = createAuthBypassValidator(this.validationContext);
        return validator.validate(context);
      }
      default:
        console.warn(`[ValidationEngine] Unsupported vulnerability type: ${type}`);
        return null;
    }
  }

  private determineOverallVerdict(confidence: number): ValidationVerdict {
    if (confidence >= 80) return "confirmed";
    if (confidence >= 50) return "likely";
    if (confidence >= 20) return "theoretical";
    return "false_positive";
  }

  async captureValidationEvidence(
    target: ValidationTarget,
    result: UnifiedValidationResult
  ): Promise<string[]> {
    if (!this.config.captureEvidence || !this.validationContext) {
      return [];
    }

    const evidenceIds: string[] = [];

    for (const vuln of result.vulnerabilities) {
      if (!vuln.result.vulnerable) continue;

      const successfulPayloads = vuln.result.payloadResults.filter(p => p.success && p.confidence >= 50);
      
      for (const payloadResult of successfulPayloads.slice(0, 3)) {
        try {
          const { response, evidence } = await this.client.get(
            this.buildTestUrl(target, payloadResult.payload),
            { headers: target.headers, timeout: this.config.timeoutMs }
          );

          const evidenceId = await this.client.saveEvidence(
            evidence,
            {
              ...this.validationContext,
              vulnerabilityType: vuln.type,
              payloadUsed: payloadResult.payload,
              expectedBehavior: `Target should not be vulnerable to ${vuln.type}`,
            },
            {
              verdict: payloadResult.verdict,
              confidenceScore: payloadResult.confidence,
              observedBehavior: payloadResult.evidence,
              differentialAnalysis: `Payload ${payloadResult.payloadId} triggered ${vuln.type} vulnerability`,
            }
          );

          evidenceIds.push(evidenceId);
        } catch (error) {
          console.error(`[ValidationEngine] Failed to capture evidence:`, error);
        }
      }
    }

    return evidenceIds;
  }

  private buildTestUrl(target: ValidationTarget, payload: string): string {
    if (target.parameterLocation === "url_param") {
      const url = new URL(target.url);
      url.searchParams.set(target.parameterName, payload);
      return url.toString();
    }
    return target.url;
  }

  getConfig(): Required<ValidationEngineConfig> {
    return { ...this.config };
  }

  setConfig(config: Partial<ValidationEngineConfig>): void {
    this.config = { ...this.config, ...config };
  }
}

export function createValidationEngine(
  config?: ValidationEngineConfig,
  context?: ValidationContext
): ValidationEngine {
  return new ValidationEngine(config, context);
}

export async function quickValidate(
  url: string,
  parameterName: string,
  vulnerabilityTypes?: VulnerabilityType[]
): Promise<UnifiedValidationResult> {
  const engine = new ValidationEngine();
  return engine.validateTarget({
    url,
    method: "GET",
    parameterName,
    parameterLocation: "url_param",
    vulnerabilityTypes,
  });
}
