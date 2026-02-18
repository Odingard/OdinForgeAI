import { ValidatingHttpClient } from "../validating-http-client";
import { getXssPayloads } from "../payloads/xss-payloads";
import type { Payload, PayloadExecutionContext, PayloadResult } from "../payloads/payload-types";
import { buildPayloadRequest } from "../payloads/payload-types";
import type { ValidationContext } from "../validating-http-client";
import type { ValidationVerdict } from "@shared/schema";

export interface XssValidationResult {
  vulnerable: boolean;
  confidence: number;
  verdict: ValidationVerdict;
  xssType: "reflected" | "dom_based" | null;
  payloadResults: PayloadResult[];
  evidence: string;
  recommendations: string[];
}

const DANGEROUS_PATTERNS = [
  /<script[^>]*>/i,
  /javascript:/i,
  /on\w+\s*=/i,
  /<svg[^>]*onload/i,
  /<img[^>]*onerror/i,
  /<body[^>]*onload/i,
  /<iframe[^>]*src\s*=\s*["']?javascript/i,
];

const SAFE_ENCODED_PATTERNS = [
  /&lt;script/i,
  /&lt;img/i,
  /&lt;svg/i,
  /&#60;script/i,
  /\\u003c/i,
];

export class XssValidator {
  private client: ValidatingHttpClient;
  private context?: ValidationContext;

  constructor(context?: ValidationContext) {
    this.client = new ValidatingHttpClient();
    this.context = context;
  }

  async validate(executionContext: PayloadExecutionContext): Promise<XssValidationResult> {
    const payloadResults: PayloadResult[] = [];
    let detectedType: XssValidationResult["xssType"] = null;
    let highestConfidence = 0;
    let bestEvidence = "";

    const reflectedResult = await this.testReflected(executionContext);
    if (reflectedResult.vulnerable) {
      detectedType = "reflected";
      highestConfidence = Math.max(highestConfidence, reflectedResult.confidence);
      bestEvidence = reflectedResult.evidence;
      payloadResults.push(...reflectedResult.payloadResults);
    }

    const domResult = await this.testDomBased(executionContext);
    if (domResult.vulnerable && domResult.confidence > highestConfidence) {
      detectedType = "dom_based";
      highestConfidence = domResult.confidence;
      bestEvidence = domResult.evidence;
      payloadResults.push(...domResult.payloadResults);
    }

    const vulnerable = highestConfidence >= 50;
    const verdict = this.determineVerdict(highestConfidence);

    return {
      vulnerable,
      confidence: highestConfidence,
      verdict,
      xssType: detectedType,
      payloadResults,
      evidence: bestEvidence,
      recommendations: this.generateRecommendations(detectedType),
    };
  }

  private async testReflected(ctx: PayloadExecutionContext): Promise<{ vulnerable: boolean; confidence: number; evidence: string; payloadResults: PayloadResult[] }> {
    const payloads = getXssPayloads("reflected");
    const results: PayloadResult[] = [];
    let maxConfidence = 0;
    let bestEvidence = "";

    for (const payload of payloads.slice(0, 8)) {
      try {
        const req = this.buildRequest(ctx, payload.value);
        const { response } = await this.client.request({
          url: req.url,
          method: ctx.httpMethod,
          headers: { ...ctx.headers, ...req.headers },
          body: req.body,
          timeout: ctx.timeout || 10000,
        });

        const { reflected, encoded, confidence } = this.checkReflection(payload.value, response.body);
        const matchedIndicators: string[] = [];

        if (reflected && !encoded) {
          matchedIndicators.push("Payload reflected without encoding");
          for (const pattern of DANGEROUS_PATTERNS) {
            if (pattern.test(response.body)) {
              matchedIndicators.push(`Dangerous pattern: ${pattern.source}`);
            }
          }
        } else if (reflected && encoded) {
          matchedIndicators.push("Payload reflected but encoded");
        }

        for (const indicator of payload.successIndicators) {
          if (response.body.includes(indicator)) {
            matchedIndicators.push(`Found: ${indicator}`);
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
          evidence: matchedIndicators.length > 0 ? `XSS indicators: ${matchedIndicators.join(", ")}` : "",
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

  private async testDomBased(ctx: PayloadExecutionContext): Promise<{ vulnerable: boolean; confidence: number; evidence: string; payloadResults: PayloadResult[] }> {
    const payloads = getXssPayloads("dom_based");
    const results: PayloadResult[] = [];
    let maxConfidence = 0;
    let bestEvidence = "";

    for (const payload of payloads.slice(0, 3)) {
      try {
        const req = this.buildRequest(ctx, payload.value);
        const { response } = await this.client.request({
          url: req.url,
          method: ctx.httpMethod,
          headers: { ...ctx.headers, ...req.headers },
          body: req.body,
          timeout: ctx.timeout || 10000,
        });

        const hasDomSinks = this.checkDomSinks(response.body);
        const confidence = hasDomSinks ? 60 : 0;

        const result: PayloadResult = {
          payloadId: payload.id,
          payload: payload.value,
          success: confidence >= 50,
          confidence,
          responseCode: response.statusCode,
          responseTime: response.timing.durationMs,
          matchedIndicators: hasDomSinks ? ["DOM sinks detected"] : [],
          evidence: hasDomSinks ? "Potential DOM-based XSS: JavaScript uses location/document sinks" : "",
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

  private checkReflection(payload: string, responseBody: string): { reflected: boolean; encoded: boolean; confidence: number } {
    const exactMatch = responseBody.includes(payload);
    if (exactMatch) {
      let confidence = 70;
      for (const pattern of DANGEROUS_PATTERNS) {
        if (pattern.test(payload) && pattern.test(responseBody)) {
          confidence = 90;
          break;
        }
      }
      return { reflected: true, encoded: false, confidence };
    }

    for (const pattern of SAFE_ENCODED_PATTERNS) {
      if (pattern.test(responseBody)) {
        return { reflected: true, encoded: true, confidence: 20 };
      }
    }

    const decodedResponse = this.htmlDecode(responseBody);
    if (decodedResponse.includes(payload)) {
      return { reflected: true, encoded: true, confidence: 30 };
    }

    return { reflected: false, encoded: false, confidence: 0 };
  }

  private checkDomSinks(html: string): boolean {
    const domSinkPatterns = [
      /document\.write\s*\(/i,
      /\.innerHTML\s*=/i,
      /\.outerHTML\s*=/i,
      /eval\s*\(/i,
      /setTimeout\s*\([^)]*location/i,
      /location\s*=/i,
      /location\.href\s*=/i,
      /location\.hash/i,
      /document\.location/i,
    ];

    return domSinkPatterns.some(pattern => pattern.test(html));
  }

  private htmlDecode(str: string): string {
    return str
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&amp;/g, "&");
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

  private generateRecommendations(xssType: XssValidationResult["xssType"]): string[] {
    const recommendations: string[] = [
      "Implement Content Security Policy (CSP) headers",
      "Use context-aware output encoding (HTML, JS, URL, CSS)",
      "Validate and sanitize all user input",
      "Use HttpOnly and Secure flags on cookies",
      "Implement X-XSS-Protection header",
    ];

    if (xssType === "reflected") {
      recommendations.push("Encode user input before reflecting in HTML responses");
      recommendations.push("Use frameworks with built-in XSS protection");
    } else if (xssType === "dom_based") {
      recommendations.push("Avoid using dangerous DOM sinks like innerHTML, document.write");
      recommendations.push("Use textContent instead of innerHTML where possible");
      recommendations.push("Sanitize data before passing to DOM manipulation methods");
    }

    return recommendations;
  }
}

export function createXssValidator(context?: ValidationContext): XssValidator {
  return new XssValidator(context);
}
