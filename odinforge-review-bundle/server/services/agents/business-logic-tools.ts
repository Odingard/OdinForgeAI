import type OpenAI from "openai";
import { IdorTestModule, type IdorTestConfig } from "../aev/business-logic/idor-tests";
import { RaceConditionModule, type RaceConditionConfig } from "../aev/business-logic/race-conditions";
import { WorkflowBypassModule, type WorkflowBypassConfig } from "../aev/business-logic/workflow-bypass";

/**
 * Business Logic Agent Tool Definitions
 *
 * Three callable tools wrapping the real test modules:
 * - test_idor: IDOR horizontal/vertical testing
 * - test_race_condition: TOCTOU, double-spend, limit bypass
 * - test_workflow_bypass: Step skip, direct access, state manipulation
 *
 * Follows the same pattern as exploit-tools.ts.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BusinessLogicToolEvidence {
  toolName: string;
  arguments: Record<string, unknown>;
  resultSummary: string;
  vulnerable: boolean;
  confidence: number;
  executionTimeMs: number;
  timestamp: string;
}

export interface BusinessLogicToolContext {
  executionMode: "safe" | "simulation" | "live";
  organizationId?: string;
  evaluationId?: string;
  assetId: string;
}

// ---------------------------------------------------------------------------
// Mode gating — all BL tools require simulation+
// ---------------------------------------------------------------------------

const TOOL_MODE_REQUIREMENTS: Record<string, string[]> = {
  test_idor: ["simulation", "live"],
  test_race_condition: ["simulation", "live"],
  test_workflow_bypass: ["simulation", "live"],
};

function isToolAllowed(toolName: string, mode: string): { allowed: boolean; reason?: string } {
  const allowed = TOOL_MODE_REQUIREMENTS[toolName];
  if (!allowed || !allowed.includes(mode)) {
    return {
      allowed: false,
      reason: `Tool '${toolName}' requires simulation or live mode. Current mode: ${mode}. In safe mode, describe the theoretical vulnerability instead.`,
    };
  }
  return { allowed: true };
}

// ---------------------------------------------------------------------------
// Tool definitions (OpenAI function calling format)
// ---------------------------------------------------------------------------

export const BUSINESS_LOGIC_TOOLS: OpenAI.ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "test_idor",
      description:
        "Test for Insecure Direct Object Reference (IDOR) vulnerabilities. Tests horizontal access (accessing other users' objects) and vertical escalation (accessing admin endpoints). Requires simulation or live mode.",
      parameters: {
        type: "object",
        properties: {
          base_url: { type: "string", description: "Base URL of the target application" },
          auth_token: { type: "string", description: "Authentication token (JWT/session) to test with" },
          target_user_id: { type: "string", description: "ID of another user's object to attempt access" },
          test_type: {
            type: "string",
            enum: ["full", "horizontal", "vertical", "enumeration"],
            description: "Type of IDOR test to run",
          },
          endpoint_path: { type: "string", description: "Specific endpoint path to test (e.g., /api/users/{id})" },
        },
        required: ["base_url", "test_type"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "test_race_condition",
      description:
        "Test for race condition vulnerabilities including double-spend, TOCTOU, limit bypass, and concurrent update issues. Sends concurrent requests to detect timing-based flaws. Requires simulation or live mode.",
      parameters: {
        type: "object",
        properties: {
          target_url: { type: "string", description: "Base URL of the target application" },
          endpoint: { type: "string", description: "Specific endpoint to test (e.g., /api/transfer)" },
          method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] },
          test_type: {
            type: "string",
            enum: ["full", "double_spend", "limit_bypass", "toctou"],
            description: "Type of race condition test",
          },
          auth_token: { type: "string", description: "Authentication token" },
          concurrent_requests: { type: "number", description: "Number of concurrent requests (default: 10)" },
          body: { type: "object", description: "Request body for the concurrent requests" },
        },
        required: ["target_url", "test_type"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "test_workflow_bypass",
      description:
        "Test for workflow bypass vulnerabilities including step skipping, direct endpoint access, state manipulation, and parameter tampering. Tests whether business process steps can be circumvented. Requires simulation or live mode.",
      parameters: {
        type: "object",
        properties: {
          base_url: { type: "string", description: "Base URL of the target application" },
          auth_token: { type: "string", description: "Authentication token" },
          test_type: {
            type: "string",
            enum: ["full", "direct_access", "step_skip", "state_manipulation", "parameter_tampering"],
            description: "Type of workflow bypass test",
          },
          workflow_id: {
            type: "string",
            enum: ["checkout", "registration", "approval"],
            description: "Which workflow to test (uses default workflow definitions if not specified)",
          },
        },
        required: ["base_url", "test_type"],
      },
    },
  },
];

// ---------------------------------------------------------------------------
// Tool executor
// ---------------------------------------------------------------------------

export async function executeBusinessLogicTool(
  toolName: string,
  args: Record<string, unknown>,
  ctx: BusinessLogicToolContext
): Promise<{ result: string; evidence?: BusinessLogicToolEvidence }> {
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
      case "test_idor":
        return await executeIdorTest(args, ctx, startTime);
      case "test_race_condition":
        return await executeRaceConditionTest(args, ctx, startTime);
      case "test_workflow_bypass":
        return await executeWorkflowBypassTest(args, ctx, startTime);
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

async function executeIdorTest(
  args: Record<string, unknown>,
  ctx: BusinessLogicToolContext,
  startTime: number
): Promise<{ result: string; evidence?: BusinessLogicToolEvidence }> {
  const module = new IdorTestModule();
  const config: IdorTestConfig = {
    baseUrl: String(args.base_url || ctx.assetId),
    authToken: args.auth_token ? String(args.auth_token) : undefined,
    targetUserId: args.target_user_id ? String(args.target_user_id) : "2",
  };

  const testType = String(args.test_type || "full");

  if (testType === "full") {
    const result = await module.runFullTest(config);
    const elapsed = Date.now() - startTime;
    const exploitable = result.vulnerabilities.filter(v => v.exploitable);
    const summary = exploitable.length > 0
      ? `IDOR Found: ${exploitable.map(v => `${v.type} at ${v.endpoint} (${v.severity})`).join("; ")}`
      : `No IDOR vulnerabilities detected (tested ${result.testedEndpoints} endpoints)`;

    return {
      result: JSON.stringify({
        vulnerable: exploitable.length > 0,
        vulnerabilityCount: exploitable.length,
        testedEndpoints: result.testedEndpoints,
        findings: exploitable.map(v => ({
          type: v.type,
          endpoint: v.endpoint,
          severity: v.severity,
          proof: v.proof,
          accessedData: v.accessedData,
        })),
        evidence: result.evidence,
        businessImpact: result.businessImpact,
        executionTimeMs: elapsed,
      }),
      evidence: {
        toolName: "test_idor",
        arguments: args,
        resultSummary: summary,
        vulnerable: exploitable.length > 0,
        confidence: exploitable.length > 0 ? 85 : 10,
        executionTimeMs: elapsed,
        timestamp: new Date().toISOString(),
      },
    };
  }

  if (testType === "vertical") {
    const endpoint = args.endpoint_path ? String(args.endpoint_path) : "/api/admin/users";
    const result = await module.testVerticalEscalation(config, endpoint);
    const elapsed = Date.now() - startTime;

    return {
      result: JSON.stringify({
        vulnerable: result?.exploitable || false,
        type: "vertical",
        endpoint,
        proof: result?.proof,
        executionTimeMs: elapsed,
      }),
      evidence: {
        toolName: "test_idor",
        arguments: args,
        resultSummary: result?.exploitable ? `Vertical IDOR: ${result.proof}` : "Vertical access denied",
        vulnerable: result?.exploitable || false,
        confidence: result?.exploitable ? 90 : 10,
        executionTimeMs: elapsed,
        timestamp: new Date().toISOString(),
      },
    };
  }

  // Default: run full test for any other test_type
  const result = await module.runFullTest(config);
  const elapsed = Date.now() - startTime;
  const exploitable = result.vulnerabilities.filter(v => v.exploitable);

  return {
    result: JSON.stringify({
      vulnerable: exploitable.length > 0,
      vulnerabilityCount: exploitable.length,
      evidence: result.evidence,
      executionTimeMs: elapsed,
    }),
    evidence: {
      toolName: "test_idor",
      arguments: args,
      resultSummary: exploitable.length > 0 ? `${exploitable.length} IDOR vulns found` : "No IDOR found",
      vulnerable: exploitable.length > 0,
      confidence: exploitable.length > 0 ? 85 : 10,
      executionTimeMs: elapsed,
      timestamp: new Date().toISOString(),
    },
  };
}

async function executeRaceConditionTest(
  args: Record<string, unknown>,
  ctx: BusinessLogicToolContext,
  startTime: number
): Promise<{ result: string; evidence?: BusinessLogicToolEvidence }> {
  const module = new RaceConditionModule();
  const config: RaceConditionConfig = {
    targetUrl: String(args.target_url || ctx.assetId),
    endpoint: args.endpoint ? String(args.endpoint) : undefined,
    method: (args.method as any) || "POST",
    authToken: args.auth_token ? String(args.auth_token) : undefined,
    concurrentRequests: typeof args.concurrent_requests === "number" ? args.concurrent_requests : 10,
    body: args.body as Record<string, any> | undefined,
  };

  const testType = String(args.test_type || "full");

  if (testType === "full") {
    const result = await module.runFullTest(config);
    const elapsed = Date.now() - startTime;
    const exploitable = result.vulnerabilities.filter(v => v.exploitable);
    const summary = exploitable.length > 0
      ? `Race conditions: ${exploitable.map(v => `${v.type} (${v.severity})`).join("; ")}`
      : `No race conditions detected (${result.requestsSent} requests sent)`;

    return {
      result: JSON.stringify({
        vulnerable: exploitable.length > 0,
        vulnerabilityCount: exploitable.length,
        requestsSent: result.requestsSent,
        findings: exploitable.map(v => ({
          type: v.type,
          severity: v.severity,
          proof: v.proof,
          details: v.details,
        })),
        evidence: result.evidence,
        businessImpact: result.businessImpact,
        executionTimeMs: elapsed,
      }),
      evidence: {
        toolName: "test_race_condition",
        arguments: args,
        resultSummary: summary,
        vulnerable: exploitable.length > 0,
        confidence: exploitable.length > 0 ? 80 : 10,
        executionTimeMs: elapsed,
        timestamp: new Date().toISOString(),
      },
    };
  }

  if (testType === "double_spend") {
    const result = await module.testDoubleSpend(config);
    const elapsed = Date.now() - startTime;

    return {
      result: JSON.stringify({
        vulnerable: result.exploitable,
        type: "double_spend",
        proof: result.proof,
        details: result.details,
        executionTimeMs: elapsed,
      }),
      evidence: {
        toolName: "test_race_condition",
        arguments: args,
        resultSummary: result.exploitable ? `Double spend: ${result.proof}` : "No double spend detected",
        vulnerable: result.exploitable,
        confidence: result.exploitable ? 90 : 10,
        executionTimeMs: elapsed,
        timestamp: new Date().toISOString(),
      },
    };
  }

  // Default: run full test
  const result = await module.runFullTest(config);
  const elapsed = Date.now() - startTime;
  const exploitable = result.vulnerabilities.filter(v => v.exploitable);

  return {
    result: JSON.stringify({
      vulnerable: exploitable.length > 0,
      vulnerabilityCount: exploitable.length,
      evidence: result.evidence,
      executionTimeMs: elapsed,
    }),
    evidence: {
      toolName: "test_race_condition",
      arguments: args,
      resultSummary: exploitable.length > 0 ? `${exploitable.length} race conditions found` : "No race conditions",
      vulnerable: exploitable.length > 0,
      confidence: exploitable.length > 0 ? 80 : 10,
      executionTimeMs: elapsed,
      timestamp: new Date().toISOString(),
    },
  };
}

async function executeWorkflowBypassTest(
  args: Record<string, unknown>,
  ctx: BusinessLogicToolContext,
  startTime: number
): Promise<{ result: string; evidence?: BusinessLogicToolEvidence }> {
  const module = new WorkflowBypassModule();
  const config: WorkflowBypassConfig = {
    baseUrl: String(args.base_url || ctx.assetId),
    authToken: args.auth_token ? String(args.auth_token) : undefined,
  };

  const testType = String(args.test_type || "full");

  if (testType === "full") {
    const result = await module.runFullTest(config);
    const elapsed = Date.now() - startTime;
    const exploitable = result.vulnerabilities.filter(v => v.exploitable);
    const summary = exploitable.length > 0
      ? `Workflow bypasses: ${exploitable.map(v => `${v.type} in ${v.workflowId} (${v.severity})`).join("; ")}`
      : `No workflow bypasses detected (tested ${result.testedWorkflows} workflows)`;

    return {
      result: JSON.stringify({
        vulnerable: exploitable.length > 0,
        vulnerabilityCount: exploitable.length,
        testedWorkflows: result.testedWorkflows,
        findings: exploitable.map(v => ({
          type: v.type,
          workflowId: v.workflowId,
          severity: v.severity,
          proof: v.proof,
          skippedSteps: v.skippedSteps,
        })),
        evidence: result.evidence,
        businessImpact: result.businessImpact,
        executionTimeMs: elapsed,
      }),
      evidence: {
        toolName: "test_workflow_bypass",
        arguments: args,
        resultSummary: summary,
        vulnerable: exploitable.length > 0,
        confidence: exploitable.length > 0 ? 85 : 10,
        executionTimeMs: elapsed,
        timestamp: new Date().toISOString(),
      },
    };
  }

  // For specific test types, still run full test but filter
  const result = await module.runFullTest(config);
  const elapsed = Date.now() - startTime;
  const typeFilter = testType === "direct_access" ? "direct_access"
    : testType === "step_skip" ? "step_skip"
    : testType === "state_manipulation" ? "state_manipulation"
    : testType === "parameter_tampering" ? "parameter_tampering"
    : null;

  const filtered = typeFilter
    ? result.vulnerabilities.filter(v => v.type === typeFilter)
    : result.vulnerabilities;
  const exploitable = filtered.filter(v => v.exploitable);

  return {
    result: JSON.stringify({
      vulnerable: exploitable.length > 0,
      vulnerabilityCount: exploitable.length,
      testType,
      findings: exploitable.map(v => ({
        type: v.type,
        workflowId: v.workflowId,
        severity: v.severity,
        proof: v.proof,
      })),
      executionTimeMs: elapsed,
    }),
    evidence: {
      toolName: "test_workflow_bypass",
      arguments: args,
      resultSummary: exploitable.length > 0 ? `${testType}: ${exploitable.length} bypasses` : `No ${testType} bypasses`,
      vulnerable: exploitable.length > 0,
      confidence: exploitable.length > 0 ? 85 : 10,
      executionTimeMs: elapsed,
      timestamp: new Date().toISOString(),
    },
  };
}
