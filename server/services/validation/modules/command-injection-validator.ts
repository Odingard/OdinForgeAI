import { ValidatingHttpClient } from "../validating-http-client";
import { getCommandInjectionPayloads } from "../payloads/command-injection-payloads";
import type { Payload, PayloadExecutionContext, PayloadResult } from "../payloads/payload-types";
import { buildPayloadRequest } from "../payloads/payload-types";
import type { ValidationContext } from "../validating-http-client";
import type { ValidationVerdict } from "@shared/schema";

export interface CommandInjectionValidationResult {
  vulnerable: boolean;
  confidence: number;
  verdict: ValidationVerdict;
  technique: "blind" | "error_based" | null;
  osType: "unix" | "windows" | "unknown" | null;
  payloadResults: PayloadResult[];
  evidence: string;
  recommendations: string[];
}

const UNIX_COMMAND_INDICATORS = [
  /uid=\d+/i,
  /gid=\d+/i,
  /groups=/i,
  /root:/,
  /www-data/,
  /apache/,
  /nginx/,
  /bin\/bash/,
  /bin\/sh/,
];

const WINDOWS_COMMAND_INDICATORS = [
  /Windows NT/i,
  /Microsoft Windows/i,
  /C:\\Windows/i,
  /Administrator/i,
  /NT AUTHORITY/i,
];

const GENERIC_COMMAND_INDICATORS = [
  /VULNERABLE/,
  /command.*executed/i,
  /sh:/i,
  /bash:/i,
  /cmd\.exe/i,
  /powershell/i,
];

export class CommandInjectionValidator {
  private client: ValidatingHttpClient;
  private context?: ValidationContext;

  constructor(context?: ValidationContext) {
    this.client = new ValidatingHttpClient();
    this.context = context;
  }

  async validate(executionContext: PayloadExecutionContext): Promise<CommandInjectionValidationResult> {
    const payloadResults: PayloadResult[] = [];
    let detectedTechnique: CommandInjectionValidationResult["technique"] = null;
    let detectedOsType: CommandInjectionValidationResult["osType"] = null;
    let highestConfidence = 0;
    let evidence = "";

    const baselineResponse = await this.getBaselineResponse(executionContext);
    if (!baselineResponse) {
      return this.createErrorResult("Failed to establish baseline response");
    }

    const errorResult = await this.testErrorBased(executionContext, baselineResponse);
    if (errorResult.vulnerable) {
      detectedTechnique = "error_based";
      detectedOsType = errorResult.osType;
      highestConfidence = Math.max(highestConfidence, errorResult.confidence);
      evidence = errorResult.evidence;
      payloadResults.push(...errorResult.payloadResults);
    }

    const blindResult = await this.testBlindTimeBased(executionContext, baselineResponse);
    if (blindResult.vulnerable && blindResult.confidence > highestConfidence) {
      detectedTechnique = "blind";
      highestConfidence = blindResult.confidence;
      evidence = blindResult.evidence;
      payloadResults.push(...blindResult.payloadResults);
    }

    const vulnerable = highestConfidence >= 50;
    const verdict = this.determineVerdict(highestConfidence);

    return {
      vulnerable,
      confidence: highestConfidence,
      verdict,
      technique: detectedTechnique,
      osType: detectedOsType || "unknown",
      payloadResults,
      evidence,
      recommendations: this.generateRecommendations(detectedTechnique, detectedOsType),
    };
  }

  private async getBaselineResponse(ctx: PayloadExecutionContext): Promise<{ body: string; time: number; status: number } | null> {
    try {
      const req = this.buildRequest(ctx, ctx.originalValue || "test");
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
      console.error("[CommandInjectionValidator] Failed to get baseline:", error);
      return null;
    }
  }

  private async testErrorBased(
    ctx: PayloadExecutionContext,
    baseline: { body: string; time: number; status: number }
  ): Promise<{ vulnerable: boolean; confidence: number; osType: CommandInjectionValidationResult["osType"]; evidence: string; payloadResults: PayloadResult[] }> {
    const payloads = getCommandInjectionPayloads("error_based");
    const results: PayloadResult[] = [];
    let maxConfidence = 0;
    let detectedOs: CommandInjectionValidationResult["osType"] = null;
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

        const matchedIndicators: string[] = [];
        let confidence = 0;
        let osType: CommandInjectionValidationResult["osType"] = null;

        for (const pattern of UNIX_COMMAND_INDICATORS) {
          if (pattern.test(response.body)) {
            matchedIndicators.push(`Unix indicator: ${pattern.source}`);
            osType = "unix";
            confidence = 85;
            break;
          }
        }

        if (!osType) {
          for (const pattern of WINDOWS_COMMAND_INDICATORS) {
            if (pattern.test(response.body)) {
              matchedIndicators.push(`Windows indicator: ${pattern.source}`);
              osType = "windows";
              confidence = 85;
              break;
            }
          }
        }

        if (!osType) {
          for (const pattern of GENERIC_COMMAND_INDICATORS) {
            if (pattern.test(response.body)) {
              matchedIndicators.push(`Command indicator: ${pattern.source}`);
              confidence = 70;
              break;
            }
          }
        }

        for (const indicator of payload.successIndicators) {
          if (response.body.toLowerCase().includes(indicator.toLowerCase())) {
            matchedIndicators.push(indicator);
            confidence = Math.max(confidence, 75);
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
          evidence: matchedIndicators.length > 0 ? `Response contained: ${matchedIndicators.join(", ")}` : "",
          verdict: this.determineVerdict(confidence),
        };
        results.push(result);

        if (confidence > maxConfidence) {
          maxConfidence = confidence;
          detectedOs = osType;
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
      osType: detectedOs,
      evidence: bestEvidence,
      payloadResults: results,
    };
  }

  private async testBlindTimeBased(
    ctx: PayloadExecutionContext,
    baseline: { body: string; time: number; status: number }
  ): Promise<{ vulnerable: boolean; confidence: number; evidence: string; payloadResults: PayloadResult[] }> {
    const payloads = getCommandInjectionPayloads("blind");
    const results: PayloadResult[] = [];
    let maxConfidence = 0;
    let bestEvidence = "";

    const expectedDelay = 5000;
    const tolerance = 1500;

    for (const payload of payloads.slice(0, 4)) {
      try {
        const req = this.buildRequest(ctx, payload.value);
        const startTime = Date.now();
        const { response } = await this.client.request({
          url: req.url,
          method: ctx.httpMethod,
          headers: { ...ctx.headers, ...req.headers },
          body: req.body,
          timeout: 15000,
        });
        const responseTime = Date.now() - startTime;

        const isDelayed = responseTime >= (expectedDelay - tolerance) && responseTime >= baseline.time + 3000;
        const confidence = isDelayed ? Math.min(85, 55 + ((responseTime - expectedDelay + tolerance) / 150)) : 0;

        const result: PayloadResult = {
          payloadId: payload.id,
          payload: payload.value,
          success: isDelayed,
          confidence,
          responseCode: response.statusCode,
          responseTime,
          matchedIndicators: isDelayed ? [`Response delayed by ${responseTime}ms (baseline: ${baseline.time}ms)`] : [],
          evidence: isDelayed ? `Blind command injection confirmed: ${responseTime}ms delay (baseline: ${baseline.time}ms)` : "",
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

  private generateRecommendations(technique: CommandInjectionValidationResult["technique"], osType: CommandInjectionValidationResult["osType"]): string[] {
    const recommendations: string[] = [
      "Never pass user input directly to system commands",
      "Use language-specific APIs instead of shell commands when possible",
      "Implement strict input validation with allowlists",
      "Apply the principle of least privilege to application processes",
    ];

    if (osType === "unix") {
      recommendations.push("Avoid using shell=True in subprocess calls");
      recommendations.push("Use parameterized commands with subprocess.run()");
    } else if (osType === "windows") {
      recommendations.push("Avoid using cmd.exe /c for command execution");
      recommendations.push("Use native Windows APIs instead of shell commands");
    }

    if (technique === "blind") {
      recommendations.push("Implement timeout limits on external process execution");
    }

    return recommendations;
  }

  private createErrorResult(message: string): CommandInjectionValidationResult {
    return {
      vulnerable: false,
      confidence: 0,
      verdict: "error",
      technique: null,
      osType: null,
      payloadResults: [],
      evidence: message,
      recommendations: [],
    };
  }
}

export function createCommandInjectionValidator(context?: ValidationContext): CommandInjectionValidator {
  return new CommandInjectionValidator(context);
}
