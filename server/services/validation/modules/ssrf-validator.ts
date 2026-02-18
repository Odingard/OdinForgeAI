import { ValidatingHttpClient } from "../validating-http-client";
import { getSsrfPayloads, getCloudMetadataPayloads } from "../payloads/ssrf-payloads";
import type { Payload, PayloadExecutionContext, PayloadResult } from "../payloads/payload-types";
import { buildPayloadRequest } from "../payloads/payload-types";
import type { ValidationContext } from "../validating-http-client";
import type { ValidationVerdict } from "@shared/schema";

export interface SsrfValidationResult {
  vulnerable: boolean;
  confidence: number;
  verdict: ValidationVerdict;
  targetType: "localhost" | "internal_network" | "cloud_metadata" | "external" | "unknown" | null;
  cloudProvider: "aws" | "azure" | "gcp" | null;
  payloadResults: PayloadResult[];
  evidence: string;
  recommendations: string[];
}

const AWS_METADATA_INDICATORS = [
  /ami-id/i,
  /instance-id/i,
  /public-hostname/i,
  /public-ipv4/i,
  /iam/i,
  /security-credentials/i,
  /meta-data/i,
];

const GCP_METADATA_INDICATORS = [
  /project.*id/i,
  /instance.*zone/i,
  /computeMetadata/i,
  /service-accounts/i,
];

const AZURE_METADATA_INDICATORS = [
  /compute.*vmId/i,
  /network.*interface/i,
  /azureenvironment/i,
];

const LOCALHOST_INDICATORS = [
  /<!DOCTYPE html>/i,
  /<html/i,
  /nginx/i,
  /apache/i,
  /Server:/i,
  /Welcome to/i,
];

const INTERNAL_SERVICE_INDICATORS = [
  /redis/i,
  /memcached/i,
  /elasticsearch/i,
  /mongodb/i,
  /postgresql/i,
  /mysql/i,
  /RabbitMQ/i,
];

export class SsrfValidator {
  private client: ValidatingHttpClient;
  private context?: ValidationContext;

  constructor(context?: ValidationContext) {
    this.client = new ValidatingHttpClient();
    this.context = context;
  }

  async validate(executionContext: PayloadExecutionContext): Promise<SsrfValidationResult> {
    const payloadResults: PayloadResult[] = [];
    let highestConfidence = 0;
    let detectedTargetType: SsrfValidationResult["targetType"] = null;
    let detectedCloudProvider: SsrfValidationResult["cloudProvider"] = null;
    let evidence = "";

    const baselineResponse = await this.getBaselineResponse(executionContext);

    const cloudResult = await this.testCloudMetadata(executionContext, baselineResponse);
    if (cloudResult.vulnerable) {
      highestConfidence = cloudResult.confidence;
      detectedTargetType = "cloud_metadata";
      detectedCloudProvider = cloudResult.cloudProvider;
      evidence = cloudResult.evidence;
      payloadResults.push(...cloudResult.payloadResults);
    }

    const localhostResult = await this.testLocalhost(executionContext, baselineResponse);
    if (localhostResult.vulnerable && localhostResult.confidence > highestConfidence) {
      highestConfidence = localhostResult.confidence;
      detectedTargetType = "localhost";
      evidence = localhostResult.evidence;
      payloadResults.push(...localhostResult.payloadResults);
    }

    const internalResult = await this.testInternalServices(executionContext, baselineResponse);
    if (internalResult.vulnerable && internalResult.confidence > highestConfidence) {
      highestConfidence = internalResult.confidence;
      detectedTargetType = "internal_network";
      evidence = internalResult.evidence;
      payloadResults.push(...internalResult.payloadResults);
    }

    const vulnerable = highestConfidence >= 50;
    const verdict = this.determineVerdict(highestConfidence);

    return {
      vulnerable,
      confidence: highestConfidence,
      verdict,
      targetType: detectedTargetType,
      cloudProvider: detectedCloudProvider,
      payloadResults,
      evidence,
      recommendations: this.generateRecommendations(detectedTargetType, detectedCloudProvider),
    };
  }

  private async getBaselineResponse(ctx: PayloadExecutionContext): Promise<{ body: string; time: number; status: number } | null> {
    try {
      const req = this.buildRequest(ctx, ctx.originalValue || "https://example.com");
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
      console.error("[SsrfValidator] Failed to get baseline:", error);
      return null;
    }
  }

  private async testCloudMetadata(
    ctx: PayloadExecutionContext,
    baseline: { body: string; time: number; status: number } | null
  ): Promise<{ vulnerable: boolean; confidence: number; cloudProvider: SsrfValidationResult["cloudProvider"]; evidence: string; payloadResults: PayloadResult[] }> {
    const payloads = getCloudMetadataPayloads();
    const results: PayloadResult[] = [];
    let maxConfidence = 0;
    let detectedProvider: SsrfValidationResult["cloudProvider"] = null;
    let bestEvidence = "";

    for (const payload of payloads) {
      try {
        const req = this.buildRequest(ctx, payload.value);
        const { response } = await this.client.request({
          url: req.url,
          method: ctx.httpMethod,
          headers: {
            ...ctx.headers,
            ...req.headers,
            "Metadata-Flavor": "Google",
          },
          body: req.body,
          timeout: ctx.timeout || 10000,
        });

        const matchedIndicators: string[] = [];
        let confidence = 0;
        let provider: SsrfValidationResult["cloudProvider"] = null;

        for (const pattern of AWS_METADATA_INDICATORS) {
          if (pattern.test(response.body)) {
            matchedIndicators.push(`AWS metadata: ${pattern.source}`);
            provider = "aws";
            confidence = 95;
            break;
          }
        }

        if (!provider) {
          for (const pattern of GCP_METADATA_INDICATORS) {
            if (pattern.test(response.body)) {
              matchedIndicators.push(`GCP metadata: ${pattern.source}`);
              provider = "gcp";
              confidence = 95;
              break;
            }
          }
        }

        if (!provider) {
          for (const pattern of AZURE_METADATA_INDICATORS) {
            if (pattern.test(response.body)) {
              matchedIndicators.push(`Azure metadata: ${pattern.source}`);
              provider = "azure";
              confidence = 95;
              break;
            }
          }
        }

        for (const indicator of payload.successIndicators) {
          if (response.body.toLowerCase().includes(indicator.toLowerCase())) {
            matchedIndicators.push(indicator);
            confidence = Math.max(confidence, 80);
          }
        }

        if (response.statusCode === 200 && response.body.length > 0 && matchedIndicators.length === 0) {
          const looksLikeMetadata = /\{.*"/.test(response.body) || /[a-z-]+\n[a-z-]+/i.test(response.body);
          if (looksLikeMetadata) {
            matchedIndicators.push("Response looks like metadata");
            confidence = Math.max(confidence, 60);
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
          evidence: matchedIndicators.length > 0 ? `Cloud metadata access: ${matchedIndicators.join(", ")}` : "",
          verdict: this.determineVerdict(confidence),
        };
        results.push(result);

        if (confidence > maxConfidence) {
          maxConfidence = confidence;
          detectedProvider = provider;
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
      cloudProvider: detectedProvider,
      evidence: bestEvidence,
      payloadResults: results,
    };
  }

  private async testLocalhost(
    ctx: PayloadExecutionContext,
    baseline: { body: string; time: number; status: number } | null
  ): Promise<{ vulnerable: boolean; confidence: number; evidence: string; payloadResults: PayloadResult[] }> {
    const allPayloads = getSsrfPayloads();
    const localhostPayloads = allPayloads.filter(p => 
      p.value.includes("127.0.0.1") || 
      p.value.includes("localhost") || 
      p.value.includes("0.0.0.0") ||
      p.value.includes("[::1]")
    );
    
    const results: PayloadResult[] = [];
    let maxConfidence = 0;
    let bestEvidence = "";

    for (const payload of localhostPayloads.slice(0, 5)) {
      try {
        const req = this.buildRequest(ctx, payload.value);
        const { response } = await this.client.request({
          url: req.url,
          method: ctx.httpMethod,
          headers: { ...ctx.headers, ...req.headers },
          body: req.body,
          timeout: ctx.timeout || 10000,
        });

        const matchedIndicators: string[] = [];
        let confidence = 0;

        for (const pattern of LOCALHOST_INDICATORS) {
          if (pattern.test(response.body)) {
            matchedIndicators.push(`Localhost response: ${pattern.source}`);
            confidence = 75;
            break;
          }
        }

        const responseHasContent = response.statusCode === 200 && response.body.length > 50;
        const differFromBaseline = baseline && Math.abs(response.body.length - baseline.body.length) > 100;
        
        if (responseHasContent && differFromBaseline) {
          if (matchedIndicators.length === 0) {
            matchedIndicators.push("Response differs from baseline");
            confidence = Math.max(confidence, 55);
          } else {
            confidence = Math.min(85, confidence + 10);
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
          evidence: matchedIndicators.length > 0 ? `Localhost access: ${matchedIndicators.join(", ")}` : "",
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

  private async testInternalServices(
    ctx: PayloadExecutionContext,
    baseline: { body: string; time: number; status: number } | null
  ): Promise<{ vulnerable: boolean; confidence: number; evidence: string; payloadResults: PayloadResult[] }> {
    const allPayloads = getSsrfPayloads();
    const internalPayloads = allPayloads.filter(p => 
      p.value.includes("gopher://") || 
      p.value.includes("dict://") ||
      p.value.includes(":6379") ||
      p.value.includes(":11211")
    );
    
    const results: PayloadResult[] = [];
    let maxConfidence = 0;
    let bestEvidence = "";

    for (const payload of internalPayloads.slice(0, 3)) {
      try {
        const req = this.buildRequest(ctx, payload.value);
        const { response } = await this.client.request({
          url: req.url,
          method: ctx.httpMethod,
          headers: { ...ctx.headers, ...req.headers },
          body: req.body,
          timeout: ctx.timeout || 10000,
        });

        const matchedIndicators: string[] = [];
        let confidence = 0;

        for (const pattern of INTERNAL_SERVICE_INDICATORS) {
          if (pattern.test(response.body)) {
            matchedIndicators.push(`Internal service: ${pattern.source}`);
            confidence = 85;
            break;
          }
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
          evidence: matchedIndicators.length > 0 ? `Internal service access: ${matchedIndicators.join(", ")}` : "",
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

  private generateRecommendations(targetType: SsrfValidationResult["targetType"], cloudProvider: SsrfValidationResult["cloudProvider"]): string[] {
    const recommendations: string[] = [
      "Validate and sanitize all URLs before making server-side requests",
      "Implement a URL allowlist for permitted domains",
      "Block requests to private IP ranges (10.x.x.x, 172.16.x.x, 192.168.x.x)",
      "Disable unnecessary URL schemes (file://, gopher://, dict://)",
    ];

    if (targetType === "cloud_metadata") {
      recommendations.push("Block requests to cloud metadata endpoints (169.254.169.254)");
      
      if (cloudProvider === "aws") {
        recommendations.push("Enable IMDSv2 on AWS EC2 instances to require session tokens");
        recommendations.push("Use VPC endpoints instead of public metadata endpoints");
      } else if (cloudProvider === "gcp") {
        recommendations.push("Require Metadata-Flavor: Google header for GCP metadata requests");
      } else if (cloudProvider === "azure") {
        recommendations.push("Use managed identities with limited scopes");
      }
    }

    if (targetType === "localhost") {
      recommendations.push("Block requests to localhost and loopback addresses");
      recommendations.push("Consider using network-level controls to prevent internal access");
    }

    if (targetType === "internal_network") {
      recommendations.push("Implement network segmentation to isolate sensitive services");
      recommendations.push("Use authentication for all internal services");
    }

    return recommendations;
  }

  private createErrorResult(message: string): SsrfValidationResult {
    return {
      vulnerable: false,
      confidence: 0,
      verdict: "error",
      targetType: null,
      cloudProvider: null,
      payloadResults: [],
      evidence: message,
      recommendations: [],
    };
  }
}

export function createSsrfValidator(context?: ValidationContext): SsrfValidator {
  return new SsrfValidator(context);
}
