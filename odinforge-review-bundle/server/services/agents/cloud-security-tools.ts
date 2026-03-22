import type OpenAI from "openai";
import {
  awsPentestService,
  type IAMPrivilegeEscalationResult,
  type S3BucketEnumerationResult,
  type S3BucketInfo,
  type LambdaAbuseResult,
  type LambdaFunctionInfo,
} from "../cloud-pentest/aws-pentest-service";

/**
 * Cloud Security Agent Tool Definitions
 *
 * Three callable tools wrapping the real cloud pentest services:
 * - test_iam_escalation: IAM privilege escalation path analysis
 * - test_s3_exposure: S3 bucket misconfiguration and data exposure
 * - test_cloud_misconfig: General cloud misconfiguration (Lambda, VPC, etc.)
 *
 * Follows the same pattern as business-logic-tools.ts.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CloudSecurityToolEvidence {
  toolName: string;
  arguments: Record<string, unknown>;
  resultSummary: string;
  vulnerable: boolean;
  confidence: number;
  executionTimeMs: number;
  timestamp: string;
}

export interface CloudSecurityToolContext {
  executionMode: "safe" | "simulation" | "live";
  organizationId?: string;
  evaluationId?: string;
  assetId: string;
  cloudProvider?: "aws" | "azure" | "gcp";
}

// ---------------------------------------------------------------------------
// Mode gating
// ---------------------------------------------------------------------------

const TOOL_MODE_REQUIREMENTS: Record<string, string[]> = {
  test_iam_escalation: ["simulation", "live"],
  test_s3_exposure: ["safe", "simulation", "live"],
  test_cloud_misconfig: ["safe", "simulation", "live"],
};

function isToolAllowed(toolName: string, mode: string): { allowed: boolean; reason?: string } {
  const allowed = TOOL_MODE_REQUIREMENTS[toolName];
  if (!allowed || !allowed.includes(mode)) {
    return {
      allowed: false,
      reason: `Tool '${toolName}' requires ${toolName === "test_iam_escalation" ? "simulation or live" : "safe, simulation, or live"} mode. Current mode: ${mode}.`,
    };
  }
  return { allowed: true };
}

// ---------------------------------------------------------------------------
// Tool definitions (OpenAI function calling format)
// ---------------------------------------------------------------------------

export const CLOUD_SECURITY_TOOLS: OpenAI.ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "test_iam_escalation",
      description:
        "Analyze IAM permissions for privilege escalation paths. Tests for dangerous permissions like CreateAccessKey, AttachUserPolicy, PassRole that enable escalation to administrator access. Requires simulation or live mode.",
      parameters: {
        type: "object",
        properties: {
          permissions: {
            type: "array",
            items: { type: "string" },
            description: "List of IAM permissions to analyze (e.g., ['iam:CreateAccessKey', 's3:*'])",
          },
          user_id: { type: "string", description: "IAM user ID to analyze" },
          user_name: { type: "string", description: "IAM user name" },
          account_id: { type: "string", description: "AWS account ID" },
        },
        required: ["permissions"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "test_s3_exposure",
      description:
        "Enumerate S3 buckets for public access, missing encryption, disabled versioning, and sensitive data exposure. Checks for misconfigured public access blocks and identifies sensitive file patterns. Safe mode allowed (read-only analysis).",
      parameters: {
        type: "object",
        properties: {
          buckets: {
            type: "array",
            items: {
              type: "object",
              properties: {
                name: { type: "string" },
                isPublic: { type: "boolean" },
                region: { type: "string" },
              },
            },
            description: "List of S3 bucket metadata to analyze",
          },
        },
        required: ["buckets"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "test_cloud_misconfig",
      description:
        "General cloud misconfiguration assessment for serverless functions. Analyzes Lambda configuration for security issues including environment variable exposure, excessive permissions, VPC misconfig, and runtime vulnerabilities. Safe mode allowed (read-only analysis).",
      parameters: {
        type: "object",
        properties: {
          functions: {
            type: "array",
            items: {
              type: "object",
              properties: {
                functionName: { type: "string" },
                runtime: { type: "string" },
                role: { type: "string" },
                handler: { type: "string" },
                timeout: { type: "number" },
                memorySize: { type: "number" },
              },
            },
            description: "List of Lambda function configurations to analyze",
          },
        },
        required: ["functions"],
      },
    },
  },
];

// ---------------------------------------------------------------------------
// Tool executor
// ---------------------------------------------------------------------------

export async function executeCloudSecurityTool(
  toolName: string,
  args: Record<string, unknown>,
  ctx: CloudSecurityToolContext
): Promise<{ result: string; evidence?: CloudSecurityToolEvidence }> {
  const startTime = Date.now();

  // Mode gate
  const modeCheck = isToolAllowed(toolName, ctx.executionMode);
  if (!modeCheck.allowed) {
    return {
      result: JSON.stringify({ error: modeCheck.reason, blocked: true }),
    };
  }

  try {
    switch (toolName) {
      case "test_iam_escalation":
        return await executeIAMEscalationTest(args, ctx, startTime);
      case "test_s3_exposure":
        return await executeS3ExposureTest(args, ctx, startTime);
      case "test_cloud_misconfig":
        return await executeCloudMisconfigTest(args, ctx, startTime);
      default:
        return {
          result: JSON.stringify({ error: `Unknown tool: ${toolName}` }),
        };
    }
  } catch (err: any) {
    const elapsed = Date.now() - startTime;
    return {
      result: JSON.stringify({
        error: `Tool execution failed: ${err.message || "unknown error"}`,
        executionTimeMs: elapsed,
      }),
      evidence: {
        toolName,
        arguments: args,
        resultSummary: `Error: ${err.message}`,
        vulnerable: false,
        confidence: 0,
        executionTimeMs: elapsed,
        timestamp: new Date().toISOString(),
      },
    };
  }
}

// ---------------------------------------------------------------------------
// Individual tool executors
// ---------------------------------------------------------------------------

async function executeIAMEscalationTest(
  args: Record<string, unknown>,
  _ctx: CloudSecurityToolContext,
  startTime: number
): Promise<{ result: string; evidence?: CloudSecurityToolEvidence }> {
  const permissions = Array.isArray(args.permissions)
    ? args.permissions.map(String)
    : [];

  const iamResult: IAMPrivilegeEscalationResult = await awsPentestService.analyzeIAMPrivilegeEscalation(
    permissions,
    args.user_id ? String(args.user_id) : "unknown",
    args.user_name ? String(args.user_name) : "unknown",
    args.account_id ? String(args.account_id) : undefined
  );

  const elapsed = Date.now() - startTime;
  const hasEscalation = iamResult.escalationPaths.length > 0;
  const hasDangerous = iamResult.dangerousPermissions.length > 0;
  const vulnerable = hasEscalation || hasDangerous;

  const summary = hasEscalation
    ? `IAM Escalation: ${iamResult.escalationPaths.map(p => `${p.name} (${p.likelihood})`).join("; ")}`
    : hasDangerous
    ? `Dangerous permissions found: ${iamResult.dangerousPermissions.length}`
    : `No IAM escalation paths detected (analyzed ${permissions.length} permissions)`;

  return {
    result: JSON.stringify({
      vulnerable,
      riskScore: iamResult.riskScore,
      escalationPaths: iamResult.escalationPaths.map(p => ({
        name: p.name,
        description: p.description,
        likelihood: p.likelihood,
        impact: p.impact,
        mitreId: p.mitreId,
        requiredPermissions: p.requiredPermissions,
      })),
      dangerousPermissions: iamResult.dangerousPermissions.map(d => ({
        permission: d.permission,
        risk: d.risk,
        exploitability: d.exploitability,
      })),
      recommendations: iamResult.recommendations,
      mitreAttackMappings: iamResult.mitreAttackMappings,
      executionTimeMs: elapsed,
    }),
    evidence: {
      toolName: "test_iam_escalation",
      arguments: args,
      resultSummary: summary,
      vulnerable,
      confidence: hasEscalation ? 90 : hasDangerous ? 70 : 10,
      executionTimeMs: elapsed,
      timestamp: new Date().toISOString(),
    },
  };
}

async function executeS3ExposureTest(
  args: Record<string, unknown>,
  _ctx: CloudSecurityToolContext,
  startTime: number
): Promise<{ result: string; evidence?: CloudSecurityToolEvidence }> {
  const buckets: Partial<S3BucketInfo>[] = Array.isArray(args.buckets)
    ? args.buckets.map((b: any) => ({
        name: b.name || "unknown",
        isPublic: Boolean(b.isPublic),
        region: b.region || undefined,
      }))
    : [];

  const s3Result: S3BucketEnumerationResult = await awsPentestService.analyzeS3Buckets(buckets);
  const elapsed = Date.now() - startTime;
  const vulnerable = s3Result.publicBuckets.length > 0 || s3Result.misconfigurations.length > 0;

  const summary = s3Result.publicBuckets.length > 0
    ? `S3 Exposure: ${s3Result.publicBuckets.length} public bucket(s), ${s3Result.misconfigurations.length} misconfig(s)`
    : s3Result.misconfigurations.length > 0
    ? `S3 Misconfigurations: ${s3Result.misconfigurations.length} issue(s) found`
    : `No S3 exposure detected (analyzed ${buckets.length} buckets)`;

  return {
    result: JSON.stringify({
      vulnerable,
      riskScore: s3Result.riskScore,
      publicBuckets: s3Result.publicBuckets.map(b => ({
        name: b.name,
        region: b.region,
        isPublic: b.isPublic,
      })),
      misconfigurations: s3Result.misconfigurations.map(m => ({
        bucketName: m.bucketName,
        type: m.type,
        severity: m.severity,
        description: m.description,
        remediation: m.remediation,
      })),
      sensitiveDataExposures: s3Result.sensitiveDataExposures,
      recommendations: s3Result.recommendations,
      executionTimeMs: elapsed,
    }),
    evidence: {
      toolName: "test_s3_exposure",
      arguments: args,
      resultSummary: summary,
      vulnerable,
      confidence: s3Result.publicBuckets.length > 0 ? 95 : s3Result.misconfigurations.length > 0 ? 80 : 10,
      executionTimeMs: elapsed,
      timestamp: new Date().toISOString(),
    },
  };
}

async function executeCloudMisconfigTest(
  args: Record<string, unknown>,
  _ctx: CloudSecurityToolContext,
  startTime: number
): Promise<{ result: string; evidence?: CloudSecurityToolEvidence }> {
  const functions: Partial<LambdaFunctionInfo>[] = Array.isArray(args.functions)
    ? args.functions.map((f: any) => ({
        functionName: f.functionName || "unknown",
        functionArn: f.functionArn || "",
        runtime: f.runtime || "unknown",
        role: f.role || "",
        handler: f.handler || "index.handler",
        codeSize: f.codeSize || 0,
        timeout: f.timeout || 3,
        memorySize: f.memorySize || 128,
        lastModified: f.lastModified || new Date().toISOString(),
        environmentVariables: f.environmentVariables,
        vpcConfig: f.vpcConfig,
      }))
    : [];

  const lambdaResult: LambdaAbuseResult = await awsPentestService.analyzeLambdaFunctions(functions);
  const elapsed = Date.now() - startTime;
  const vulnerable = lambdaResult.vulnerabilities.length > 0 || lambdaResult.privilegeEscalationRisks.length > 0;

  const summary = vulnerable
    ? `Cloud Misconfig: ${lambdaResult.vulnerabilities.length} vuln(s), ${lambdaResult.privilegeEscalationRisks.length} escalation risk(s)`
    : `No cloud misconfigurations detected (analyzed ${functions.length} functions)`;

  return {
    result: JSON.stringify({
      vulnerable,
      riskScore: lambdaResult.riskScore,
      vulnerabilities: lambdaResult.vulnerabilities.map(v => ({
        functionName: v.functionName,
        type: v.type,
        severity: v.severity,
        description: v.description,
        remediation: v.remediation,
      })),
      privilegeEscalationRisks: lambdaResult.privilegeEscalationRisks,
      recommendations: lambdaResult.recommendations,
      mitreAttackMappings: lambdaResult.mitreAttackMappings,
      executionTimeMs: elapsed,
    }),
    evidence: {
      toolName: "test_cloud_misconfig",
      arguments: args,
      resultSummary: summary,
      vulnerable,
      confidence: lambdaResult.vulnerabilities.length > 0 ? 85 : 10,
      executionTimeMs: elapsed,
      timestamp: new Date().toISOString(),
    },
  };
}
