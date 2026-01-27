import OpenAI from "openai";
import { searchPolicies, PolicySearchResult } from "../rag/policy-search";
import type { AgentContext, PolicyDecision, SafetyDecision } from "./types";
import { runtimeGuard, type RuntimeGuardContext, type RuntimeGuardResult } from "../runtime-guard";

const OPENAI_TIMEOUT_MS = 30000;

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
  timeout: OPENAI_TIMEOUT_MS,
  maxRetries: 2,
});

export type { PolicyDecision };

export interface PolicyCheckResult {
  decision: PolicyDecision;
  originalAction: string;
  modifiedAction?: string;
  reasoning: string;
  relevantPolicies: PolicySearchResult[];
  blockedReason?: string;
  timestamp: Date;
}

export interface PolicyGuardianContext {
  organizationId?: string;
  executionMode?: "safe" | "simulation" | "live";
  targetType?: string;
  assetId?: string;
  evaluationId?: string;
}

export async function checkAction(
  action: string,
  agentName: string,
  context: PolicyGuardianContext = {}
): Promise<PolicyCheckResult> {
  const startTime = Date.now();
  
  console.log(`[PolicyGuardian] Checking action from ${agentName}: "${action.substring(0, 100)}..."`);
  
  try {
    const relevantPolicies = await searchPolicies(
      `${action} ${context.targetType || ""} ${context.executionMode || ""} security testing`,
      { 
        organizationId: context.organizationId, 
        limit: 5, 
        minSimilarity: 0.55 
      }
    );

    if (relevantPolicies.length === 0) {
      console.log(`[PolicyGuardian] No relevant policies found, allowing action`);
      return {
        decision: "ALLOW",
        originalAction: action,
        reasoning: "No specific policies found for this action. Proceeding with default permissions.",
        relevantPolicies: [],
        timestamp: new Date(),
      };
    }

    const policyContext = relevantPolicies
      .map((p) => `[${p.metadata.policyType || "general"}] ${p.content}`)
      .join("\n---\n");

    const executionModeRules = getExecutionModeRules(context.executionMode || "safe");

    const response = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        {
          role: "system",
          content: `You are the PolicyGuardian, a security policy enforcement system. Your role is to:
1. Analyze proposed security testing actions against organizational policies
2. Determine if actions should be ALLOWED, DENIED, or MODIFIED
3. If modification is needed, provide the safe alternative command

Be strict about safety. When in doubt, DENY or MODIFY to a safer alternative.

${executionModeRules}`,
        },
        {
          role: "user",
          content: `Agent: ${agentName}
Action: ${action}
Target Asset: ${context.assetId || "unknown"}
Target Type: ${context.targetType || "unknown"}
Execution Mode: ${context.executionMode || "safe"}

Relevant Policies:
${policyContext}

Evaluate this action and respond with JSON:
{
  "decision": "ALLOW" | "DENY" | "MODIFY",
  "reasoning": "Detailed explanation of your decision based on policies",
  "modifiedAction": "If MODIFY, provide the safer alternative command here. Otherwise null.",
  "blockedReason": "If DENY, provide user-friendly explanation. Otherwise null."
}`,
        },
      ],
      response_format: { type: "json_object" },
      max_completion_tokens: 1024,
    });

    const result = JSON.parse(response.choices[0].message.content || "{}");
    
    const decision = validateDecision(result.decision);
    
    console.log(`[PolicyGuardian] Decision: ${decision} (${Date.now() - startTime}ms)`);

    return {
      decision,
      originalAction: action,
      modifiedAction: decision === "MODIFY" ? result.modifiedAction : undefined,
      reasoning: result.reasoning || "Policy evaluation completed.",
      blockedReason: decision === "DENY" ? result.blockedReason : undefined,
      relevantPolicies,
      timestamp: new Date(),
    };
  } catch (error) {
    console.error(`[PolicyGuardian] Error checking action:`, error);
    
    if (context.executionMode === "safe") {
      return {
        decision: "DENY",
        originalAction: action,
        reasoning: "Policy check failed. Denying by default in safe mode.",
        blockedReason: "Unable to verify action against policies. Please retry or contact administrator.",
        relevantPolicies: [],
        timestamp: new Date(),
      };
    }
    
    return {
      decision: "ALLOW",
      originalAction: action,
      reasoning: "Policy check failed but allowing in non-safe mode. Proceed with caution.",
      relevantPolicies: [],
      timestamp: new Date(),
    };
  }
}

export async function checkExploitChain(
  exploitChain: {
    name: string;
    technique: string;
    description: string;
    success_likelihood: string;
  },
  context: PolicyGuardianContext = {}
): Promise<PolicyCheckResult> {
  const actionDescription = `Execute exploit: ${exploitChain.name} using technique ${exploitChain.technique}. ${exploitChain.description}`;
  return checkAction(actionDescription, "Exploit Agent", context);
}

export async function checkLateralMovement(
  pivotPath: {
    from: string;
    to: string;
    method: string;
    technique: string;
  },
  context: PolicyGuardianContext = {}
): Promise<PolicyCheckResult> {
  const actionDescription = `Lateral movement from ${pivotPath.from} to ${pivotPath.to} using ${pivotPath.method} (technique: ${pivotPath.technique})`;
  return checkAction(actionDescription, "Lateral Movement Agent", context);
}

export function createSafetyDecision(
  evaluationId: string,
  agentName: string,
  checkResult: PolicyCheckResult
): SafetyDecision {
  return {
    id: `sd-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    evaluationId,
    agentName,
    originalAction: checkResult.originalAction,
    decision: checkResult.decision,
    modifiedAction: checkResult.modifiedAction,
    reasoning: checkResult.reasoning,
    policyReferences: checkResult.relevantPolicies.map((p) => 
      `${p.metadata.filename || "policy"}: ${p.content.substring(0, 100)}...`
    ),
    timestamp: checkResult.timestamp,
  };
}

function validateDecision(decision: string): PolicyDecision {
  const normalized = (decision || "").toUpperCase().trim();
  if (normalized === "ALLOW" || normalized === "DENY" || normalized === "MODIFY") {
    return normalized as PolicyDecision;
  }
  return "DENY";
}

function getExecutionModeRules(mode: string): string {
  switch (mode) {
    case "safe":
      return `SAFE MODE RULES (STRICT):
- DENY any action that could cause system modification
- DENY any exploit execution or payload delivery
- DENY credential testing or brute force attempts
- DENY any action that could affect availability
- ALLOW passive reconnaissance only
- MODIFY aggressive scans to passive alternatives`;
      
    case "simulation":
      return `SIMULATION MODE RULES (MODERATE):
- ALLOW controlled exploit validation
- DENY actual exploitation or persistence
- DENY data exfiltration
- DENY actions without rollback capability
- MODIFY destructive actions to non-destructive alternatives`;
      
    case "live":
      return `LIVE MODE RULES (PERMISSIVE):
- ALLOW most testing actions with proper authorization
- DENY actions explicitly prohibited by organizational policies
- DENY actions targeting out-of-scope systems
- MODIFY actions that could cause unintended collateral damage`;
      
    default:
      return `DEFAULT RULES: Treat as SAFE MODE - be conservative and deny uncertain actions.`;
  }
}

export function formatSafetyBlockForUI(block: SafetyBlock): {
  type: "safety_block";
  evaluationId: string;
  agentName: string;
  decision: PolicyDecision;
  originalAction: string;
  modifiedAction?: string;
  reasoning: string;
  timestamp: string;
} {
  return {
    type: "safety_block",
    evaluationId: block.evaluationId,
    agentName: block.agentName,
    decision: block.decision,
    originalAction: block.originalAction.substring(0, 200),
    modifiedAction: block.modifiedAction?.substring(0, 200),
    reasoning: block.reasoning,
    timestamp: block.timestamp.toISOString(),
  };
}

export interface GuardedActionResult {
  allowed: boolean;
  policyResult: PolicyCheckResult;
  runtimeGuardResult?: RuntimeGuardResult;
  requiresApproval: boolean;
  approvalId?: string;
}

export async function checkActionWithRuntimeGuard(
  action: string,
  agentName: string,
  target: string | undefined,
  context: PolicyGuardianContext & { executionId?: string }
): Promise<GuardedActionResult> {
  const policyResult = await checkAction(action, agentName, context);

  if (policyResult.decision === "DENY") {
    return {
      allowed: false,
      policyResult,
      requiresApproval: false,
    };
  }

  const runtimeContext: RuntimeGuardContext = {
    evaluationId: context.evaluationId || "unknown",
    executionId: context.executionId || context.evaluationId || "unknown",
    organizationId: context.organizationId || "default",
    agentName,
  };

  const runtimeResult = await runtimeGuard.validateCommand(
    policyResult.decision === "MODIFY" ? (policyResult.modifiedAction || action) : action,
    target,
    runtimeContext
  );

  if (runtimeResult.requiresApproval) {
    return {
      allowed: false,
      policyResult,
      runtimeGuardResult: runtimeResult,
      requiresApproval: true,
      approvalId: runtimeResult.approvalId,
    };
  }

  return {
    allowed: runtimeResult.allowed && policyResult.decision !== "DENY",
    policyResult,
    runtimeGuardResult: runtimeResult,
    requiresApproval: false,
  };
}

export async function executeWithApproval(
  action: string,
  agentName: string,
  target: string | undefined,
  context: PolicyGuardianContext & { executionId?: string },
  executor: (approvedAction: string) => Promise<void>
): Promise<{ executed: boolean; reason?: string }> {
  const guardResult = await checkActionWithRuntimeGuard(action, agentName, target, context);

  if (!guardResult.allowed && !guardResult.requiresApproval) {
    return {
      executed: false,
      reason: guardResult.policyResult.blockedReason || "Action blocked by policy",
    };
  }

  if (guardResult.requiresApproval && guardResult.approvalId) {
    console.log(`[PolicyGuardian] Waiting for HITL approval: ${guardResult.approvalId}`);
    
    try {
      const approved = await runtimeGuard.waitForApproval(guardResult.approvalId);
      
      if (!approved) {
        return {
          executed: false,
          reason: "Action rejected by operator",
        };
      }

      console.log(`[PolicyGuardian] HITL approval received, executing action`);
    } catch (error: any) {
      return {
        executed: false,
        reason: error.message || "Approval timeout or error",
      };
    }
  }

  const finalAction = guardResult.policyResult.decision === "MODIFY" 
    ? (guardResult.policyResult.modifiedAction || action)
    : action;

  await executor(finalAction);

  return { executed: true };
}
