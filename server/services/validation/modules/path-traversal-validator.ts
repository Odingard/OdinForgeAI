import { ValidatingHttpClient } from "../validating-http-client";
import { getPathTraversalPayloads } from "../payloads/path-traversal-payloads";
import type { Payload, PayloadExecutionContext, PayloadResult } from "../payloads/payload-types";
import { buildPayloadRequest } from "../payloads/payload-types";
import type { ValidationContext } from "../validating-http-client";
import type { ValidationVerdict } from "@shared/schema";

export interface PathTraversalValidationResult {
  vulnerable: boolean;
  confidence: number;
  verdict: ValidationVerdict;
  fileType: "unix_system" | "windows_system" | "config" | "source" | "unknown" | null;
  payloadResults: PayloadResult[];
  evidence: string;
  recommendations: string[];
}

const UNIX_FILE_INDICATORS = [
  /root:[x*]:0:0/,
  /daemon:[x*]:/,
  /nobody:[x*]:/,
  /bin\/bash/,
  /bin\/sh/,
  /\/usr\/sbin\/nologin/,
  /www-data:/,
];

const WINDOWS_FILE_INDICATORS = [
  /# Copyright \(c\) .* Microsoft/i,
  /localhost/i,
  /127\.0\.0\.1.*localhost/i,
  /\[boot loader\]/i,
  /\[operating systems\]/i,
];

const CONFIG_FILE_INDICATORS = [
  /DB_PASSWORD/i,
  /DATABASE_URL/i,
  /SECRET_KEY/i,
  /API_KEY/i,
  /private_key/i,
  /-----BEGIN.*KEY-----/,
  /\[mysqld\]/i,
  /\[postgresql\]/i,
];

const BASE64_PASSWD_INDICATORS = [
  /cm9vdDo/,
  /ZGFlbW9u/,
];

export class PathTraversalValidator {
  private client: ValidatingHttpClient;
  private context?: ValidationContext;

  constructor(context?: ValidationContext) {
    this.client = new ValidatingHttpClient();
    this.context = context;
  }

  async validate(executionContext: PayloadExecutionContext): Promise<PathTraversalValidationResult> {
    const payloadResults: PayloadResult[] = [];
    let highestConfidence = 0;
    let detectedFileType: PathTraversalValidationResult["fileType"] = null;
    let evidence = "";

    const baselineResponse = await this.getBaselineResponse(executionContext);
    if (!baselineResponse) {
      return this.createErrorResult("Failed to establish baseline response");
    }

    const payloads = getPathTraversalPayloads();
    
    for (const payload of payloads.slice(0, 10)) {
      try {
        const req = this.buildRequest(executionContext, payload.value);
        const { response } = await this.client.request({
          url: req.url,
          method: executionContext.httpMethod,
          headers: { ...executionContext.headers, ...req.headers },
          body: req.body,
          timeout: executionContext.timeout || 10000,
        });

        const matchedIndicators: string[] = [];
        let confidence = 0;
        let fileType: PathTraversalValidationResult["fileType"] = null;

        for (const pattern of UNIX_FILE_INDICATORS) {
          if (pattern.test(response.body)) {
            matchedIndicators.push(`Unix file content: ${pattern.source}`);
            fileType = "unix_system";
            confidence = 90;
            break;
          }
        }

        if (!fileType) {
          for (const pattern of WINDOWS_FILE_INDICATORS) {
            if (pattern.test(response.body)) {
              matchedIndicators.push(`Windows file content: ${pattern.source}`);
              fileType = "windows_system";
              confidence = 85;
              break;
            }
          }
        }

        if (!fileType) {
          for (const pattern of CONFIG_FILE_INDICATORS) {
            if (pattern.test(response.body)) {
              matchedIndicators.push(`Config file content: ${pattern.source}`);
              fileType = "config";
              confidence = 80;
              break;
            }
          }
        }

        if (!fileType) {
          for (const pattern of BASE64_PASSWD_INDICATORS) {
            if (pattern.test(response.body)) {
              matchedIndicators.push(`Base64 encoded file: ${pattern.source}`);
              fileType = "unix_system";
              confidence = 85;
              break;
            }
          }
        }

        for (const indicator of payload.successIndicators) {
          if (response.body.includes(indicator)) {
            matchedIndicators.push(indicator);
            confidence = Math.max(confidence, 75);
            if (!fileType) fileType = "unknown";
          }
        }

        let isFalsePositive = false;
        for (const indicator of payload.failureIndicators) {
          if (response.body.toLowerCase().includes(indicator.toLowerCase())) {
            isFalsePositive = true;
            confidence = Math.max(0, confidence - 30);
            break;
          }
        }

        const contentDiffersFromBaseline = Math.abs(response.body.length - baselineResponse.body.length) > 50;
        if (contentDiffersFromBaseline && response.statusCode === 200 && matchedIndicators.length > 0) {
          confidence = Math.min(95, confidence + 10);
        }

        const result: PayloadResult = {
          payloadId: payload.id,
          payload: payload.value,
          success: confidence >= 50 && !isFalsePositive,
          confidence,
          responseCode: response.statusCode,
          responseTime: response.timing.durationMs,
          matchedIndicators,
          evidence: matchedIndicators.length > 0 ? `File content detected: ${matchedIndicators.join(", ")}` : "",
          verdict: this.determineVerdict(confidence),
        };
        payloadResults.push(result);

        if (confidence > highestConfidence) {
          highestConfidence = confidence;
          detectedFileType = fileType;
          evidence = result.evidence;
        }
      } catch (error) {
        payloadResults.push({
          payloadId: payload.id,
          payload: payload.value,
          success: false,
          confidence: 0,
          responseCode: 0,
          responseTime: 0,
          matchedIndicators: [],
          evidence: `Error: ${error instanceof Error ? error.message : "Unknown"}`,
          verdict: "error",
        });
      }
    }

    const vulnerable = highestConfidence >= 50;
    const verdict = this.determineVerdict(highestConfidence);

    return {
      vulnerable,
      confidence: highestConfidence,
      verdict,
      fileType: detectedFileType,
      payloadResults,
      evidence,
      recommendations: this.generateRecommendations(detectedFileType),
    };
  }

  private async getBaselineResponse(ctx: PayloadExecutionContext): Promise<{ body: string; time: number; status: number } | null> {
    try {
      const req = this.buildRequest(ctx, ctx.originalValue || "default.txt");
      const startTime = Date.now();
      const { response } = await this.client.request({
        url: req.url,
        method: ctx.httpMethod,
        headers: { ...ctx.headers, ...req.headers },
        body: req.body,
        timeout: ctx.timeout || 10000,
      });
      const endTime = Date.now();

      return {
        body: response.body,
        time: endTime - startTime,
        status: response.statusCode,
      };
    } catch (error) {
      console.error("[PathTraversalValidator] Failed to get baseline:", error);
      return null;
    }
  }

  private buildRequest(ctx: PayloadExecutionContext, payloadValue: string) {
    return buildPayloadRequest(ctx, payloadValue);
  }

  private determineVerdict(confidence: number): ValidationVerdict {
    if (confidence >= 80) return "confirmed";
    if (confidence >= 50) return "likely";
    if (confidence >= 20) return "theoretical";
    return "false_positive";
  }

  private generateRecommendations(fileType: PathTraversalValidationResult["fileType"]): string[] {
    const recommendations: string[] = [
      "Validate and sanitize all file path inputs",
      "Use a whitelist of allowed files or directories",
      "Implement proper access controls on the file system",
      "Use path canonicalization to resolve paths before validation",
    ];

    if (fileType === "unix_system" || fileType === "windows_system") {
      recommendations.push("Run the application with minimal file system privileges");
      recommendations.push("Use chroot or containerization to limit file system access");
    }

    if (fileType === "config") {
      recommendations.push("Store sensitive configuration outside the web root");
      recommendations.push("Encrypt sensitive configuration values");
    }

    recommendations.push("Reject paths containing ../ or encoded variants");
    recommendations.push("Use a secure file serving library that handles path validation");

    return recommendations;
  }

  private createErrorResult(message: string): PathTraversalValidationResult {
    return {
      vulnerable: false,
      confidence: 0,
      verdict: "error",
      fileType: null,
      payloadResults: [],
      evidence: message,
      recommendations: [],
    };
  }
}

export function createPathTraversalValidator(context?: ValidationContext): PathTraversalValidator {
  return new PathTraversalValidator(context);
}
