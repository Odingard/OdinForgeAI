import type {
  HttpRequestCapture,
  HttpResponseCapture,
  TimingData,
  InsertValidationEvidenceArtifact,
  ValidationVerdict,
} from "@shared/schema";
import { storage } from "../../storage";

const MAX_BODY_SIZE = 100 * 1024;

export interface ValidatingRequestOptions {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  timeout?: number;
  followRedirects?: boolean;
}

export interface ValidatingResponse {
  statusCode: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  bodyTruncated: boolean;
  timing: TimingData;
}

export interface CapturedEvidence {
  request: HttpRequestCapture;
  response: HttpResponseCapture;
  timing: TimingData;
  artifactId?: string;
}

export interface ValidationContext {
  tenantId: string;
  organizationId: string;
  evaluationId?: string;
  findingId?: string;
  validationId?: string;
  scanId?: string;
  vulnerabilityType?: string;
  payloadUsed?: string;
  payloadType?: string;
  expectedBehavior?: string;
}

export class ValidatingHttpClient {
  private defaultTimeout: number;
  private userAgent: string;

  constructor(options?: { timeout?: number; userAgent?: string }) {
    this.defaultTimeout = options?.timeout || 10000;
    this.userAgent = options?.userAgent || "OdinForge-AEV/1.0";
  }

  async request(
    options: ValidatingRequestOptions,
    context?: ValidationContext
  ): Promise<{ response: ValidatingResponse; evidence: CapturedEvidence }> {
    const requestTimestamp = new Date().toISOString();
    const startTime = Date.now();

    const headers: Record<string, string> = {
      "User-Agent": this.userAgent,
      ...options.headers,
    };

    const requestCapture: HttpRequestCapture = {
      method: options.method,
      url: options.url,
      headers: this.sanitizeHeaders(headers),
      body: options.body ? this.truncateBody(options.body) : undefined,
      timestamp: requestTimestamp,
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
    }, options.timeout || this.defaultTimeout);

    try {
      const fetchOptions: RequestInit = {
        method: options.method,
        headers,
        body: options.body,
        signal: controller.signal,
        redirect: options.followRedirects === false ? "manual" : "follow",
      };

      const fetchResponse = await fetch(options.url, fetchOptions);
      clearTimeout(timeout);

      const responseTimestamp = new Date().toISOString();
      const endTime = Date.now();

      const responseHeaders: Record<string, string> = {};
      fetchResponse.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      let responseBody = "";
      let bodyTruncated = false;

      try {
        const rawBody = await fetchResponse.text();
        if (rawBody.length > MAX_BODY_SIZE) {
          responseBody = rawBody.slice(0, MAX_BODY_SIZE);
          bodyTruncated = true;
        } else {
          responseBody = rawBody;
        }
      } catch {
        responseBody = "[Error reading response body]";
      }

      const responseCapture: HttpResponseCapture = {
        statusCode: fetchResponse.status,
        statusText: fetchResponse.statusText,
        headers: responseHeaders,
        body: responseBody,
        bodyTruncated,
        timestamp: responseTimestamp,
      };

      const timingData: TimingData = {
        requestSentAt: requestTimestamp,
        responseReceivedAt: responseTimestamp,
        durationMs: endTime - startTime,
      };

      const evidence: CapturedEvidence = {
        request: requestCapture,
        response: responseCapture,
        timing: timingData,
      };

      const validatingResponse: ValidatingResponse = {
        statusCode: fetchResponse.status,
        statusText: fetchResponse.statusText,
        headers: responseHeaders,
        body: responseBody,
        bodyTruncated,
        timing: timingData,
      };

      return { response: validatingResponse, evidence };
    } catch (error) {
      clearTimeout(timeout);

      const errorTimestamp = new Date().toISOString();
      const endTime = Date.now();

      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      const isTimeout = errorMessage.includes("abort") || errorMessage.includes("timeout");

      const responseCapture: HttpResponseCapture = {
        statusCode: isTimeout ? 0 : -1,
        statusText: isTimeout ? "Request Timeout" : "Connection Error",
        headers: {},
        body: errorMessage,
        timestamp: errorTimestamp,
      };

      const timingData: TimingData = {
        requestSentAt: requestTimestamp,
        responseReceivedAt: errorTimestamp,
        durationMs: endTime - startTime,
      };

      const evidence: CapturedEvidence = {
        request: requestCapture,
        response: responseCapture,
        timing: timingData,
      };

      const validatingResponse: ValidatingResponse = {
        statusCode: isTimeout ? 0 : -1,
        statusText: isTimeout ? "Request Timeout" : "Connection Error",
        headers: {},
        body: errorMessage,
        bodyTruncated: false,
        timing: timingData,
      };

      return { response: validatingResponse, evidence };
    }
  }

  async get(url: string, options?: Partial<ValidatingRequestOptions>, context?: ValidationContext) {
    return this.request({ method: "GET", url, ...options }, context);
  }

  async post(url: string, body?: string, options?: Partial<ValidatingRequestOptions>, context?: ValidationContext) {
    return this.request({ method: "POST", url, body, ...options }, context);
  }

  async put(url: string, body?: string, options?: Partial<ValidatingRequestOptions>, context?: ValidationContext) {
    return this.request({ method: "PUT", url, body, ...options }, context);
  }

  async delete(url: string, options?: Partial<ValidatingRequestOptions>, context?: ValidationContext) {
    return this.request({ method: "DELETE", url, ...options }, context);
  }

  async saveEvidence(
    evidence: CapturedEvidence,
    context: ValidationContext,
    analysis: {
      verdict: ValidationVerdict;
      confidenceScore: number;
      observedBehavior: string;
      differentialAnalysis?: string;
    }
  ): Promise<string> {
    const url = new URL(evidence.request.url);

    const artifactData: InsertValidationEvidenceArtifact = {
      tenantId: context.tenantId,
      organizationId: context.organizationId,
      evaluationId: context.evaluationId,
      findingId: context.findingId,
      validationId: context.validationId,
      scanId: context.scanId,
      evidenceType: "http_request_response",
      verdict: analysis.verdict,
      confidenceScore: analysis.confidenceScore,
      vulnerabilityType: context.vulnerabilityType,
      targetUrl: evidence.request.url,
      targetHost: url.hostname,
      targetPort: url.port ? parseInt(url.port, 10) : (url.protocol === "https:" ? 443 : 80),
      httpRequest: evidence.request,
      httpResponse: evidence.response,
      timingData: evidence.timing,
      payloadUsed: context.payloadUsed,
      payloadType: context.payloadType,
      observedBehavior: analysis.observedBehavior,
      expectedBehavior: context.expectedBehavior,
      differentialAnalysis: analysis.differentialAnalysis,
      validationMethod: "automated",
      executionMode: "safe",
      artifactSizeBytes: this.calculateArtifactSize(evidence),
      capturedAt: new Date(),
    };

    const artifact = await storage.createValidationEvidenceArtifact(artifactData);
    return artifact.id;
  }

  async saveTimingEvidence(
    baselineResponse: ValidatingResponse,
    testResponse: ValidatingResponse,
    context: ValidationContext & { targetUrl: string },
    analysis: {
      verdict: ValidationVerdict;
      confidenceScore: number;
      expectedDelayMs: number;
    }
  ): Promise<string> {
    let targetHost = "";
    let targetPort = 80;
    
    try {
      const url = new URL(context.targetUrl);
      targetHost = url.hostname;
      targetPort = url.port ? parseInt(url.port, 10) : (url.protocol === "https:" ? 443 : 80);
    } catch {
      targetHost = "unknown";
    }
    
    const timingData: TimingData = {
      requestSentAt: testResponse.timing.requestSentAt,
      responseReceivedAt: testResponse.timing.responseReceivedAt,
      durationMs: testResponse.timing.durationMs,
      expectedDurationMs: analysis.expectedDelayMs,
      deviation: testResponse.timing.durationMs - baselineResponse.timing.durationMs,
    };

    const artifactData: InsertValidationEvidenceArtifact = {
      tenantId: context.tenantId,
      organizationId: context.organizationId,
      evaluationId: context.evaluationId,
      findingId: context.findingId,
      validationId: context.validationId,
      scanId: context.scanId,
      evidenceType: "timing_analysis",
      verdict: analysis.verdict,
      confidenceScore: analysis.confidenceScore,
      vulnerabilityType: context.vulnerabilityType,
      targetUrl: context.targetUrl,
      targetHost,
      targetPort,
      timingData,
      observedBehavior: `Baseline: ${baselineResponse.timing.durationMs}ms, Test: ${testResponse.timing.durationMs}ms, Deviation: ${timingData.deviation}ms`,
      expectedBehavior: `Expected delay of approximately ${analysis.expectedDelayMs}ms if vulnerable`,
      differentialAnalysis: timingData.deviation && timingData.deviation >= analysis.expectedDelayMs * 0.8
        ? `Response time increased by ${timingData.deviation}ms, consistent with time-based injection`
        : `Response time deviation of ${timingData.deviation}ms does not indicate vulnerability`,
      validationMethod: "automated",
      executionMode: "safe",
      capturedAt: new Date(),
    };

    const artifact = await storage.createValidationEvidenceArtifact(artifactData);
    return artifact.id;
  }

  private sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
    const sensitivePatterns = [
      /authorization/i,
      /cookie/i,
      /x-api-key/i,
      /x-auth-token/i,
      /bearer/i,
    ];

    const sanitized: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      if (sensitivePatterns.some(pattern => pattern.test(key))) {
        sanitized[key] = "[REDACTED]";
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }

  private truncateBody(body: string): string {
    if (body.length > MAX_BODY_SIZE) {
      return body.slice(0, MAX_BODY_SIZE) + "...[truncated]";
    }
    return body;
  }

  private calculateArtifactSize(evidence: CapturedEvidence): number {
    const requestSize = JSON.stringify(evidence.request).length;
    const responseSize = JSON.stringify(evidence.response).length;
    const timingSize = JSON.stringify(evidence.timing).length;
    return requestSize + responseSize + timingSize;
  }
}

export const validatingHttpClient = new ValidatingHttpClient();
