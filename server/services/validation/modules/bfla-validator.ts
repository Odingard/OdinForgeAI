/**
 * BFLA (Broken Function Level Authorization) & Mass Assignment Validator
 *
 * Tests for:
 * 1. Admin endpoint access without admin credentials
 * 2. Mass assignment (injecting role/privilege fields in requests)
 * 3. IDOR (accessing resources belonging to other users)
 */

import { ValidatingHttpClient } from "../validating-http-client";
import { getBflaPayloads, getMassAssignmentPayloads } from "../payloads/bfla-payloads";
import type { PayloadExecutionContext, PayloadResult } from "../payloads/payload-types";
import type { ValidationContext } from "../validating-http-client";
import type { ValidationVerdict } from "@shared/schema";

export interface BflaValidationResult {
  vulnerable: boolean;
  confidence: number;
  verdict: ValidationVerdict;
  attackType: "bfla" | "mass_assignment" | "idor" | null;
  payloadResults: PayloadResult[];
  evidence: string;
  recommendations: string[];
}

const ADMIN_CONTENT_INDICATORS = [
  /\busers?\b.*\bemail\b/i,
  /\badmin\b.*\bpanel\b/i,
  /\bdashboard\b/i,
  /\bmanage\b.*\busers?\b/i,
  /\brole\b.*\badmin\b/i,
  /\bsettings\b.*\bconfigur/i,
];

const MASS_ASSIGN_SUCCESS_INDICATORS = [
  /"role"\s*:\s*"admin"/i,
  /"isAdmin"\s*:\s*true/i,
  /"is_admin"\s*:\s*true/i,
  /"verified"\s*:\s*true/i,
];

export class BflaValidator {
  private client: ValidatingHttpClient;
  private context?: ValidationContext;

  constructor(context?: ValidationContext) {
    this.client = new ValidatingHttpClient();
    this.context = context;
  }

  async validate(executionContext: PayloadExecutionContext): Promise<BflaValidationResult> {
    const payloadResults: PayloadResult[] = [];
    let detectedType: BflaValidationResult["attackType"] = null;
    let highestConfidence = 0;
    let bestEvidence = "";

    // Test 1: Admin path probing (BFLA)
    const bflaResult = await this.testAdminPathAccess(executionContext);
    if (bflaResult.confidence > highestConfidence) {
      detectedType = "bfla";
      highestConfidence = bflaResult.confidence;
      bestEvidence = bflaResult.evidence;
    }
    payloadResults.push(...bflaResult.payloadResults);

    // Test 2: Mass assignment
    const massAssignResult = await this.testMassAssignment(executionContext);
    if (massAssignResult.confidence > highestConfidence) {
      detectedType = "mass_assignment";
      highestConfidence = massAssignResult.confidence;
      bestEvidence = massAssignResult.evidence;
    }
    payloadResults.push(...massAssignResult.payloadResults);

    // Test 3: IDOR via sequential ID probing
    const idorResult = await this.testIdor(executionContext);
    if (idorResult.confidence > highestConfidence) {
      detectedType = "idor";
      highestConfidence = idorResult.confidence;
      bestEvidence = idorResult.evidence;
    }
    payloadResults.push(...idorResult.payloadResults);

    const vulnerable = highestConfidence >= 40;
    const recommendations = this.buildRecommendations(detectedType);

    let verdict: ValidationVerdict = "false_positive";
    if (highestConfidence >= 80) verdict = "confirmed";
    else if (highestConfidence >= 50) verdict = "likely";
    else if (highestConfidence >= 20) verdict = "theoretical";

    return {
      vulnerable,
      confidence: highestConfidence,
      verdict,
      attackType: detectedType,
      payloadResults,
      evidence: bestEvidence,
      recommendations,
    };
  }

  private async testAdminPathAccess(
    ctx: PayloadExecutionContext,
  ): Promise<{ confidence: number; evidence: string; payloadResults: PayloadResult[] }> {
    const payloads = getBflaPayloads().filter((p) =>
      p.applicableContexts.includes("path"),
    );
    const results: PayloadResult[] = [];
    let confidence = 0;
    let evidence = "";

    const baseUrl = new URL(ctx.targetUrl);

    for (const payload of payloads.slice(0, 5)) {
      try {
        const probeUrl = `${baseUrl.origin}${payload.value}`;
        const { response } = await this.client.get(probeUrl, {
          headers: ctx.headers,
          timeout: ctx.timeout || 10000,
        });

        const status = response.statusCode;
        const body = response.body;
        let payloadConfidence = 0;
        let payloadEvidence = "";
        const matchedIndicators: string[] = [];

        if (status >= 200 && status < 300) {
          for (const indicator of ADMIN_CONTENT_INDICATORS) {
            if (indicator.test(body)) {
              matchedIndicators.push(indicator.source);
            }
          }

          if (matchedIndicators.length >= 2) {
            payloadConfidence = 80;
            payloadEvidence = `Admin endpoint ${payload.value} accessible (${status}): matched ${matchedIndicators.length} admin content indicators`;
          } else if (matchedIndicators.length === 1) {
            payloadConfidence = 50;
            payloadEvidence = `Admin endpoint ${payload.value} returned data (${status}): matched ${matchedIndicators[0]}`;
          } else if (body.length > 100) {
            payloadConfidence = 30;
            payloadEvidence = `Admin endpoint ${payload.value} returned ${status} with ${body.length} bytes`;
          }
        }

        if (payloadConfidence > confidence) {
          confidence = payloadConfidence;
          evidence = payloadEvidence;
        }

        results.push({
          payloadId: payload.id,
          payload: payload.value,
          success: payloadConfidence >= 40,
          confidence: payloadConfidence,
          verdict: payloadConfidence >= 50 ? "confirmed" : payloadConfidence >= 30 ? "likely" : "false_positive",
          evidence: payloadEvidence || `${payload.value}: ${status}`,
          responseCode: status,
          responseTime: response.timing?.durationMs || 0,
          matchedIndicators,
        });
      } catch {
        // Target unreachable for this path
      }
    }

    return { confidence, evidence, payloadResults: results };
  }

  private async testMassAssignment(
    ctx: PayloadExecutionContext,
  ): Promise<{ confidence: number; evidence: string; payloadResults: PayloadResult[] }> {
    const payloads = getMassAssignmentPayloads();
    const results: PayloadResult[] = [];
    let confidence = 0;
    let evidence = "";

    // Mass assignment only makes sense on POST/PUT/PATCH endpoints
    if (!["POST", "PUT", "PATCH"].includes(ctx.httpMethod || "GET")) {
      return { confidence: 0, evidence: "", payloadResults: [] };
    }

    for (const payload of payloads.slice(0, 4)) {
      try {
        const contentType = payload.value.startsWith("{")
          ? "application/json"
          : "application/x-www-form-urlencoded";

        const { response } = await this.client.request({
          method: ctx.httpMethod || "POST",
          url: ctx.targetUrl,
          headers: {
            ...ctx.headers,
            "Content-Type": contentType,
          },
          body: payload.value,
          timeout: ctx.timeout || 10000,
        });

        const status = response.statusCode;
        const body = response.body;
        let payloadConfidence = 0;
        let payloadEvidence = "";
        const matchedIndicators: string[] = [];

        if (status >= 200 && status < 300) {
          for (const indicator of MASS_ASSIGN_SUCCESS_INDICATORS) {
            if (indicator.test(body)) {
              payloadConfidence = 85;
              matchedIndicators.push(indicator.source);
              payloadEvidence = `Mass assignment accepted: ${indicator.source} found in response`;
              break;
            }
          }
        }

        if (payloadConfidence > confidence) {
          confidence = payloadConfidence;
          evidence = payloadEvidence;
        }

        results.push({
          payloadId: payload.id,
          payload: payload.value,
          success: payloadConfidence >= 40,
          confidence: payloadConfidence,
          verdict: payloadConfidence >= 50 ? "confirmed" : "false_positive",
          evidence: payloadEvidence || `Mass assignment test: ${status}`,
          responseCode: status,
          responseTime: response.timing?.durationMs || 0,
          matchedIndicators,
        });
      } catch {
        // skip
      }
    }

    return { confidence, evidence, payloadResults: results };
  }

  private async testIdor(
    ctx: PayloadExecutionContext,
  ): Promise<{ confidence: number; evidence: string; payloadResults: PayloadResult[] }> {
    const results: PayloadResult[] = [];
    let confidence = 0;
    let evidence = "";

    const testIds = ["1", "2", "0"];

    for (const testId of testIds) {
      try {
        const url = new URL(ctx.targetUrl);
        url.searchParams.set(ctx.parameterName, testId);

        const { response } = await this.client.get(url.toString(), {
          headers: ctx.headers,
          timeout: ctx.timeout || 10000,
        });

        const status = response.statusCode;
        const body = response.body;
        let payloadConfidence = 0;
        let payloadEvidence = "";
        const matchedIndicators: string[] = [];

        if (status === 200 && body.length > 50) {
          const hasEmail = /"email"\s*:/i.test(body);
          const hasName = /"(?:name|username)"\s*:/i.test(body);
          const hasPhone = /"phone"\s*:/i.test(body);

          if (hasEmail) matchedIndicators.push("email field");
          if (hasName) matchedIndicators.push("name field");
          if (hasPhone) matchedIndicators.push("phone field");

          if (matchedIndicators.length >= 2) {
            payloadConfidence = 75;
            payloadEvidence = `IDOR: Resource ID ${testId} returned PII (${matchedIndicators.join(", ")})`;
          } else if (matchedIndicators.length === 1) {
            payloadConfidence = 45;
            payloadEvidence = `IDOR: Resource ID ${testId} returned user data (${matchedIndicators[0]})`;
          }
        }

        if (payloadConfidence > confidence) {
          confidence = payloadConfidence;
          evidence = payloadEvidence;
        }

        results.push({
          payloadId: `idor-${testId}`,
          payload: testId,
          success: payloadConfidence >= 40,
          confidence: payloadConfidence,
          verdict: payloadConfidence >= 50 ? "confirmed" : "false_positive",
          evidence: payloadEvidence || `IDOR probe ${testId}: ${status}`,
          responseCode: status,
          responseTime: response.timing?.durationMs || 0,
          matchedIndicators,
        });
      } catch {
        // skip
      }
    }

    return { confidence, evidence, payloadResults: results };
  }

  private buildRecommendations(attackType: BflaValidationResult["attackType"]): string[] {
    if (attackType === "bfla") {
      return [
        "Implement function-level authorization checks on all admin endpoints",
        "Use role-based access control (RBAC) middleware before route handlers",
      ];
    }
    if (attackType === "mass_assignment") {
      return [
        "Use allowlists (not blocklists) for accepted request fields",
        "Never bind request body directly to database models",
      ];
    }
    if (attackType === "idor") {
      return [
        "Verify resource ownership before returning data",
        "Use UUIDs instead of sequential IDs for resource identifiers",
      ];
    }
    return ["No BFLA or mass assignment vulnerabilities detected"];
  }
}

export function createBflaValidator(context?: ValidationContext): BflaValidator {
  return new BflaValidator(context);
}
