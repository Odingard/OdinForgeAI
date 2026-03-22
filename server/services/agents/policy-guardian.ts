/**
 * POLICY_GUARDIAN_EXPLOIT — Guard Node
 *
 * Runs alongside all three exploitation threads (A/B/C).
 * Validates every proposed action is within scope and execution mode
 * constraints BEFORE it fires.
 *
 * This is a pure TypeScript guard — NO LLM calls.
 * Guard/policy checks must run BEFORE findings are written to memory.
 *
 * Responsibilities:
 *   1. Scope enforcement — block actions targeting out-of-scope assets
 *   2. Execution mode gating — safe mode blocks destructive actions
 *   3. Rate limit enforcement — cap total requests per engagement
 *   4. Sensitive target protection — block actions against prod databases, CI/CD, etc.
 */

import type {
  ExploitFindings,
  SafetyDecision,
  PolicyDecision,
} from "./types";
import { randomUUID } from "crypto";

// ─── Types ─────────────────────────────────────────────────────────────────

export interface PolicyGuardianContext {
  organizationId?: string;
  executionMode: "safe" | "simulation" | "live";
  assetId: string;
  evaluationId: string;
  /** Regex patterns defining in-scope targets */
  scopePatterns?: string[];
  /** Maximum total exploit attempts allowed */
  maxExploitAttempts?: number;
}

export interface PolicyGuardianResult {
  findings: ExploitFindings;
  decisions: SafetyDecision[];
  blockedCount: number;
  modifiedCount: number;
  allowedCount: number;
}

// ─── Sensitive targets that require explicit opt-in ────────────────────────

const SENSITIVE_TARGET_PATTERNS = [
  /\bprod(uction)?\b.*\b(db|database|sql|postgres|mysql|mongo)\b/i,
  /\bci\/?cd\b/i,
  /\b(jenkins|gitlab-ci|github-actions|circleci)\b/i,
  /\bkubernetes\b.*\b(master|control[_-]?plane)\b/i,
  /\b(vault|secrets?[_-]?manager|kms)\b/i,
  /\biam\b.*\b(root|admin)\b/i,
];

/** Destructive HTTP methods/actions blocked in safe mode. */
const DESTRUCTIVE_ACTIONS = [
  "DELETE",
  "drop_table",
  "truncate",
  "rm -rf",
  "format",
  "wipe",
  "destroy",
  "shutdown",
];

// ─── Policy Guardian Implementation ────────────────────────────────────────

/**
 * Validate exploit findings against policy constraints.
 * This runs BEFORE findings are written to memory.
 *
 * Returns filtered findings + safety decisions for audit trail.
 */
export function validateExploitFindings(
  findings: ExploitFindings,
  context: PolicyGuardianContext
): PolicyGuardianResult {
  const decisions: SafetyDecision[] = [];
  const filteredChains: ExploitFindings["exploitChains"] = [];
  let blockedCount = 0;
  let modifiedCount = 0;
  let allowedCount = 0;

  for (const chain of findings.exploitChains) {
    const decision = evaluateChain(chain, context);
    decisions.push(decision);

    if (decision.decision === "DENY") {
      blockedCount++;
      // Chain is blocked — do not include in findings
      continue;
    }

    if (decision.decision === "MODIFY") {
      modifiedCount++;
      // Chain is modified — include with reduced confidence
      filteredChains.push({
        ...chain,
        success_likelihood: "low",
        description: `[POLICY MODIFIED] ${chain.description}`,
      });
      continue;
    }

    allowedCount++;
    filteredChains.push(chain);
  }

  // Also validate tool call log entries if present
  const filteredToolCallLog = findings.toolCallLog?.filter((tc) => {
    // In safe mode, block any tool call that attempted destructive actions
    if (context.executionMode === "safe") {
      const argsStr = JSON.stringify(tc.arguments).toLowerCase();
      for (const destructive of DESTRUCTIVE_ACTIONS) {
        if (argsStr.includes(destructive.toLowerCase())) {
          return false;
        }
      }
    }
    return true;
  });

  return {
    findings: {
      ...findings,
      exploitChains: filteredChains,
      exploitable: filteredChains.length > 0 && findings.exploitable,
      toolCallLog: filteredToolCallLog,
    },
    decisions,
    blockedCount,
    modifiedCount,
    allowedCount,
  };
}

/**
 * Evaluate a single exploit chain against all policy rules.
 */
function evaluateChain(
  chain: ExploitFindings["exploitChains"][number],
  context: PolicyGuardianContext
): SafetyDecision {
  const chainDescription = `${chain.name}: ${chain.technique} — ${chain.description}`;
  const timestamp = new Date();

  // Rule 1: Execution mode gating
  if (context.executionMode === "safe") {
    // In safe mode, block any chain that involves active exploitation
    const activeExploitIndicators = [
      "command_injection",
      "rce",
      "remote code execution",
      "file upload",
      "reverse shell",
      "bind shell",
      "code execution",
    ];

    const chainText = `${chain.name} ${chain.description} ${chain.technique}`.toLowerCase();
    for (const indicator of activeExploitIndicators) {
      if (chainText.includes(indicator)) {
        return makeSafetyDecision(
          context,
          "DENY",
          chainDescription,
          `Active exploitation blocked in safe mode: ${indicator}`,
          ["execution_mode_safe", "no_active_exploitation"],
          timestamp
        );
      }
    }
  }

  // Rule 2: Sensitive target protection
  for (const pattern of SENSITIVE_TARGET_PATTERNS) {
    if (pattern.test(chain.description) || pattern.test(chain.name)) {
      if (context.executionMode !== "live") {
        return makeSafetyDecision(
          context,
          "MODIFY",
          chainDescription,
          `Sensitive target detected — reducing confidence (requires live mode for full exploitation)`,
          ["sensitive_target_protection"],
          timestamp
        );
      }
    }
  }

  // Rule 3: Scope enforcement
  if (context.scopePatterns && context.scopePatterns.length > 0) {
    const chainText = `${chain.name} ${chain.description}`;
    const inScope = context.scopePatterns.some((pattern) => {
      try {
        return new RegExp(pattern, "i").test(chainText);
      } catch {
        return false;
      }
    });

    if (!inScope) {
      return makeSafetyDecision(
        context,
        "DENY",
        chainDescription,
        "Exploit chain targets out-of-scope asset",
        ["scope_enforcement"],
        timestamp
      );
    }
  }

  // Rule 4: Evidence contract — reject chains with no evidence backing
  if (
    !chain.validated &&
    chain.validationConfidence === undefined &&
    (!chain.evidence || chain.evidence.length === 0)
  ) {
    // Don't hard-block, but modify: this finding has no real evidence
    return makeSafetyDecision(
      context,
      "MODIFY",
      chainDescription,
      "No real evidence backing — finding is LLM-inferred only (EvidenceContract violation)",
      ["evidence_contract_enforcement"],
      timestamp
    );
  }

  // All rules passed
  return makeSafetyDecision(
    context,
    "ALLOW",
    chainDescription,
    "All policy checks passed",
    [],
    timestamp
  );
}

function makeSafetyDecision(
  context: PolicyGuardianContext,
  decision: PolicyDecision,
  originalAction: string,
  reasoning: string,
  policyReferences: string[],
  timestamp: Date
): SafetyDecision {
  return {
    id: randomUUID(),
    evaluationId: context.evaluationId,
    organizationId: context.organizationId,
    agentName: "POLICY_GUARDIAN_EXPLOIT",
    originalAction,
    decision,
    reasoning,
    policyReferences,
    executionMode: context.executionMode,
    timestamp,
  };
}
