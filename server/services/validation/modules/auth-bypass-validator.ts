import { ValidatingHttpClient } from "../validating-http-client";
import { getAuthBypassPayloads, getHeaderBypassPayloads, getPathBypassPayloads } from "../payloads/auth-bypass-payloads";
import type { Payload, PayloadExecutionContext, PayloadResult } from "../payloads/payload-types";
import { buildPayloadRequest } from "../payloads/payload-types";
import type { ValidationContext } from "../validating-http-client";
import type { ValidationVerdict } from "@shared/schema";

export interface AuthBypassValidationResult {
  vulnerable: boolean;
  confidence: number;
  verdict: ValidationVerdict;
  bypassType: "sqli" | "header" | "path" | "credential" | null;
  payloadResults: PayloadResult[];
  evidence: string;
  recommendations: string[];
}

const AUTH_SUCCESS_INDICATORS = [
  /welcome/i,
  /dashboard/i,
  /logged\s*in/i,
  /success/i,
  /admin/i,
  /profile/i,
  /account/i,
  /logout/i,
  /sign\s*out/i,
];

const AUTH_FAILURE_INDICATORS = [
  /invalid/i,
  /incorrect/i,
  /wrong/i,
  /denied/i,
  /unauthorized/i,
  /failed/i,
  /error/i,
  /login/i,
  /sign\s*in/i,
];

export class AuthBypassValidator {
  private client: ValidatingHttpClient;
  private context?: ValidationContext;

  constructor(context?: ValidationContext) {
    this.client = new ValidatingHttpClient();
    this.context = context;
  }

  async validate(executionContext: PayloadExecutionContext): Promise<AuthBypassValidationResult> {
    const payloadResults: PayloadResult[] = [];
    let detectedType: AuthBypassValidationResult["bypassType"] = null;
    let highestConfidence = 0;
    let bestEvidence = "";

    const baselineResponse = await this.getBaselineResponse(executionContext);
    if (!baselineResponse) {
      return this.createErrorResult("Failed to establish baseline response");
    }

    const sqliResult = await this.testSqliBypass(executionContext, baselineResponse);
    if (sqliResult.vulnerable) {
      detectedType = "sqli";
      highestConfidence = Math.max(highestConfidence, sqliResult.confidence);
      bestEvidence = sqliResult.evidence;
      payloadResults.push(...sqliResult.payloadResults);
    }

    const headerResult = await this.testHeaderBypass(executionContext, baselineResponse);
    if (headerResult.vulnerable && headerResult.confidence > highestConfidence) {
      detectedType = "header";
      highestConfidence = headerResult.confidence;
      bestEvidence = headerResult.evidence;
      payloadResults.push(...headerResult.payloadResults);
    }

    const pathResult = await this.testPathBypass(executionContext, baselineResponse);
    if (pathResult.vulnerable && pathResult.confidence > highestConfidence) {
      detectedType = "path";
      highestConfidence = pathResult.confidence;
      bestEvidence = pathResult.evidence;
      payloadResults.push(...pathResult.payloadResults);
    }

    const vulnerable = highestConfidence >= 50;
    const verdict = this.determineVerdict(highestConfidence);

    return {
      vulnerable,
      confidence: highestConfidence,
      verdict,
      bypassType: detectedType,
      payloadResults,
      evidence: bestEvidence,
      recommendations: this.generateRecommendations(detectedType),
    };
  }

  private async getBaselineResponse(ctx: PayloadExecutionContext): Promise<{ body: string; status: number; isAuthenticated: boolean } | null> {
    try {
      const { response } = await this.client.request({
        url: ctx.targetUrl,
        method: ctx.httpMethod,
        headers: ctx.headers,
        timeout: ctx.timeout || 10000,
      });

      const isAuthenticated = this.checkAuthenticationStatus(response.body, response.statusCode);

      return {
        body: response.body,
        status: response.statusCode,
        isAuthenticated,
      };
    } catch (error) {
      console.error("[AuthBypassValidator] Failed to get baseline:", error);
      return null;
    }
  }

  private checkAuthenticationStatus(body: string, statusCode: number): boolean {
    if (statusCode === 401 || statusCode === 403) return false;
    if (statusCode === 302 || statusCode === 307) return false;

    const successCount = AUTH_SUCCESS_INDICATORS.filter(p => p.test(body)).length;
    const failureCount = AUTH_FAILURE_INDICATORS.filter(p => p.test(body)).length;

    return successCount > failureCount;
  }

  private async testSqliBypass(
    ctx: PayloadExecutionContext,
    baseline: { body: string; status: number; isAuthenticated: boolean }
  ): Promise<{ vulnerable: boolean; confidence: number; evidence: string; payloadResults: PayloadResult[] }> {
    const payloads = getAuthBypassPayloads("boolean_based");
    const results: PayloadResult[] = [];
    let maxConfidence = 0;
    let bestEvidence = "";

    for (const payload of payloads.slice(0, 5)) {
      try {
        const req = this.buildRequest(ctx, payload.value);
        const { response } = await this.client.request({
          url: req.url,
          method: ctx.httpMethod,
          headers: { ...ctx.headers, ...req.headers },
          body: req.body,
          timeout: ctx.timeout || 10000,
        });

        const nowAuthenticated = this.checkAuthenticationStatus(response.body, response.statusCode);
        const statusChanged = response.statusCode !== baseline.status;
        const authChanged = nowAuthenticated !== baseline.isAuthenticated;

        let confidence = 0;
        const matchedIndicators: string[] = [];

        if (!baseline.isAuthenticated && nowAuthenticated) {
          confidence = 90;
          matchedIndicators.push("Authentication bypassed");
        } else if (authChanged || statusChanged) {
          confidence = 60;
          matchedIndicators.push("Authentication state changed");
        }

        for (const indicator of payload.successIndicators) {
          if (response.body.toLowerCase().includes(indicator.toLowerCase())) {
            matchedIndicators.push(indicator);
            confidence = Math.max(confidence, 70);
          }
        }

        const result: PayloadResult = {
          payloadId: payload.id,
          payload: payload.value,
          success: confidence >= 50,
          confidence,
          responseCode: response.statusCode,
          responseTime: response.timing.durationMs,
          matchedIndicators,
          evidence: matchedIndicators.length > 0 ? `SQL injection bypass: ${matchedIndicators.join(", ")}` : "",
          verdict: this.determineVerdict(confidence),
        };
        results.push(result);

        if (confidence > maxConfidence) {
          maxConfidence = confidence;
          bestEvidence = result.evidence;
        }
      } catch (error) {
        results.push({
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

    return {
      vulnerable: maxConfidence >= 50,
      confidence: maxConfidence,
      evidence: bestEvidence,
      payloadResults: results,
    };
  }

  private async testHeaderBypass(
    ctx: PayloadExecutionContext,
    baseline: { body: string; status: number; isAuthenticated: boolean }
  ): Promise<{ vulnerable: boolean; confidence: number; evidence: string; payloadResults: PayloadResult[] }> {
    const payloads = getHeaderBypassPayloads();
    const results: PayloadResult[] = [];
    let maxConfidence = 0;
    let bestEvidence = "";

    for (const payload of payloads.slice(0, 4)) {
      try {
        const [headerName, headerValue] = payload.value.split(": ");
        const headers = {
          ...ctx.headers,
          [headerName.trim()]: headerValue?.trim() || "",
        };

        const { response } = await this.client.request({
          url: ctx.targetUrl,
          method: ctx.httpMethod,
          headers,
          timeout: ctx.timeout || 10000,
        });

        const nowAuthenticated = this.checkAuthenticationStatus(response.body, response.statusCode);
        const statusChanged = response.statusCode !== baseline.status;

        let confidence = 0;
        const matchedIndicators: string[] = [];

        if (!baseline.isAuthenticated && nowAuthenticated) {
          confidence = 85;
          matchedIndicators.push(`Header bypass: ${headerName}`);
        } else if (statusChanged && response.statusCode === 200 && baseline.status !== 200) {
          confidence = 65;
          matchedIndicators.push(`Status changed to 200 with ${headerName}`);
        }

        const result: PayloadResult = {
          payloadId: payload.id,
          payload: payload.value,
          success: confidence >= 50,
          confidence,
          responseCode: response.statusCode,
          responseTime: response.timing.durationMs,
          matchedIndicators,
          evidence: matchedIndicators.length > 0 ? `Header injection bypass: ${matchedIndicators.join(", ")}` : "",
          verdict: this.determineVerdict(confidence),
        };
        results.push(result);

        if (confidence > maxConfidence) {
          maxConfidence = confidence;
          bestEvidence = result.evidence;
        }
      } catch (error) {
        results.push({
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

    return {
      vulnerable: maxConfidence >= 50,
      confidence: maxConfidence,
      evidence: bestEvidence,
      payloadResults: results,
    };
  }

  private async testPathBypass(
    ctx: PayloadExecutionContext,
    baseline: { body: string; status: number; isAuthenticated: boolean }
  ): Promise<{ vulnerable: boolean; confidence: number; evidence: string; payloadResults: PayloadResult[] }> {
    const payloads = getPathBypassPayloads();
    const results: PayloadResult[] = [];
    let maxConfidence = 0;
    let bestEvidence = "";

    for (const payload of payloads.slice(0, 6)) {
      try {
        const baseUrl = new URL(ctx.targetUrl);
        const testUrl = `${baseUrl.origin}${payload.value}`;

        const { response } = await this.client.request({
          url: testUrl,
          method: ctx.httpMethod,
          headers: ctx.headers,
          timeout: ctx.timeout || 10000,
        });

        const nowAuthenticated = this.checkAuthenticationStatus(response.body, response.statusCode);
        const statusChanged = response.statusCode !== baseline.status;

        let confidence = 0;
        const matchedIndicators: string[] = [];

        if (!baseline.isAuthenticated && nowAuthenticated) {
          confidence = 80;
          matchedIndicators.push(`Path bypass: ${payload.value}`);
        } else if (response.statusCode === 200 && baseline.status === 403) {
          confidence = 70;
          matchedIndicators.push(`403 bypass with path: ${payload.value}`);
        } else if (response.statusCode === 200 && baseline.status === 401) {
          confidence = 75;
          matchedIndicators.push(`401 bypass with path: ${payload.value}`);
        }

        const result: PayloadResult = {
          payloadId: payload.id,
          payload: payload.value,
          success: confidence >= 50,
          confidence,
          responseCode: response.statusCode,
          responseTime: response.timing.durationMs,
          matchedIndicators,
          evidence: matchedIndicators.length > 0 ? `Path manipulation bypass: ${matchedIndicators.join(", ")}` : "",
          verdict: this.determineVerdict(confidence),
        };
        results.push(result);

        if (confidence > maxConfidence) {
          maxConfidence = confidence;
          bestEvidence = result.evidence;
        }
      } catch (error) {
        results.push({
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

    return {
      vulnerable: maxConfidence >= 50,
      confidence: maxConfidence,
      evidence: bestEvidence,
      payloadResults: results,
    };
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

  private generateRecommendations(bypassType: AuthBypassValidationResult["bypassType"]): string[] {
    const recommendations: string[] = [
      "Implement multi-factor authentication (MFA)",
      "Use secure session management with proper timeout",
      "Implement account lockout after failed attempts",
      "Log all authentication attempts for monitoring",
    ];

    if (bypassType === "sqli") {
      recommendations.push("Use parameterized queries for authentication");
      recommendations.push("Implement input validation on login forms");
    } else if (bypassType === "header") {
      recommendations.push("Do not trust client-supplied headers for authentication");
      recommendations.push("Validate X-Forwarded-For and similar headers at the load balancer");
    } else if (bypassType === "path") {
      recommendations.push("Normalize URL paths before authorization checks");
      recommendations.push("Implement authorization at multiple layers");
      recommendations.push("Use consistent path handling across the application");
    }

    return recommendations;
  }

  private createErrorResult(message: string): AuthBypassValidationResult {
    return {
      vulnerable: false,
      confidence: 0,
      verdict: "error",
      bypassType: null,
      payloadResults: [],
      evidence: message,
      recommendations: [],
    };
  }
}

export function createAuthBypassValidator(context?: ValidationContext): AuthBypassValidator {
  return new AuthBypassValidator(context);
}
