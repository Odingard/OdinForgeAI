/**
 * LLM Safety Boundary — Enforcement layer for OdinForge core-v2.
 *
 * Validates LLM outputs before they are consumed by the engine.
 * Strips unsafe content, logs violations, and returns safe subsets.
 *
 * CORE PRINCIPLE:
 *   LLMs are used for planning, typing, shaping, narrating, and drafting.
 *   LLMs are NEVER used for evidence, confirmation, quality gate, or finding truth.
 *   The deterministic engine remains the source of truth.
 */

import type { AgentRole } from "./agent-roles";

// Standalone logger — no dependency on server/services/logger
const log = {
  warn: (...args: any[]) => console.warn(`[LLM-SAFETY]`, ...args),
  error: (...args: any[]) => console.error(`[LLM-SAFETY]`, ...args),
};

// ─── Types ──────────────────────────────────────────────────────────────────

export interface SafetyResult {
  safe: boolean;
  violations: string[];
  sanitizedContent: string | null;
}

// ─── Forbidden Patterns ─────────────────────────────────────────────────────

/**
 * Patterns that indicate an LLM is trying to confirm findings, fabricate
 * evidence, or bypass the quality gate. These are checked against the
 * raw string output before it's parsed or consumed.
 */
const FINDING_CONFIRMATION_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  {
    pattern: /\b(?:finding|vulnerability|exploit)\s+(?:is\s+)?(?:confirmed|validated|verified|proven)\b/i,
    label: "finding_confirmation",
  },
  {
    pattern: /\bmark(?:ed|ing)?\s+(?:as\s+)?(?:PROVEN|CORROBORATED)\b/i,
    label: "quality_promotion",
  },
  {
    pattern: /\bquality[_\s]?(?:gate|level)\s*[:=]\s*["']?(?:PROVEN|CORROBORATED)["']?\b/i,
    label: "quality_gate_override",
  },
  {
    pattern: /\bevidence[_\s]?quality\s*[:=]\s*["']?(?:proven|corroborated)["']?\b/i,
    label: "evidence_quality_override",
  },
  {
    pattern: /\bsuccessfully\s+exploited\b/i,
    label: "exploit_success_claim",
  },
  {
    pattern: /\bexploit\s+(?:succeeded|confirmed|validated)\b/i,
    label: "exploit_confirmation",
  },
];

const ARTIFACT_FABRICATION_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  {
    pattern: /\bHTTP\/\d\.\d\s+\d{3}\b.*\b(?:shell|root|admin|flag)\b/i,
    label: "fabricated_http_response",
  },
  {
    pattern: /\breplay[_\s]?success\s*[:=]\s*true\b/i,
    label: "fabricated_replay_success",
  },
  {
    pattern: /\bstatus[_\s]?code\s*[:=]\s*200\b.*\b(?:admin|root|shell)\b/i,
    label: "fabricated_status_with_access",
  },
];

const SCOPE_EXPANSION_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  {
    pattern: /\b(?:scan|attack|exploit|probe)\s+(?:all|every|any)\s+(?:host|server|domain|network)\b/i,
    label: "scope_expansion",
  },
  {
    pattern: /\bignore\s+(?:scope|boundary|engagement)\s+(?:limit|restriction)\b/i,
    label: "scope_override",
  },
];

// ─── Validation ─────────────────────────────────────────────────────────────

/**
 * Validate LLM output against safety rules for a given agent role.
 *
 * Checks:
 *   1. Output doesn't contain finding confirmations
 *   2. Output doesn't fabricate artifacts
 *   3. Output doesn't bypass quality gate language
 *   4. Output stays within the role's allowedOutputs (if parseable)
 *   5. Output doesn't expand scope beyond current engagement
 *
 * If violations are detected:
 *   - Logs a warning with violation details
 *   - Strips unsafe content
 *   - Returns the safe subset
 */
export function validateLLMOutput(
  role: AgentRole,
  output: unknown,
): SafetyResult {
  const violations: string[] = [];
  const text = extractText(output);

  if (!text) {
    return { safe: true, violations: [], sanitizedContent: null };
  }

  // Check finding confirmation patterns
  for (const { pattern, label } of FINDING_CONFIRMATION_PATTERNS) {
    if (pattern.test(text)) {
      violations.push(`FINDING_CONFIRMATION: ${label}`);
    }
  }

  // Check artifact fabrication patterns
  for (const { pattern, label } of ARTIFACT_FABRICATION_PATTERNS) {
    if (pattern.test(text)) {
      violations.push(`ARTIFACT_FABRICATION: ${label}`);
    }
  }

  // Check scope expansion patterns
  for (const { pattern, label } of SCOPE_EXPANSION_PATTERNS) {
    if (pattern.test(text)) {
      violations.push(`SCOPE_EXPANSION: ${label}`);
    }
  }

  // Check forbidden output types for this role
  const forbiddenViolations = checkForbiddenOutputs(role, text);
  violations.push(...forbiddenViolations);

  if (violations.length > 0) {
    log.warn(
      {
        role: role.slug,
        violationCount: violations.length,
        violations,
      },
      "[LLM-Safety] %d violation(s) in %s output",
      violations.length,
      role.name,
    );

    const sanitized = sanitizeOutput(text, violations);
    return {
      safe: false,
      violations,
      sanitizedContent: sanitized,
    };
  }

  return { safe: true, violations: [], sanitizedContent: text };
}

// ─── Forbidden Output Checking ──────────────────────────────────────────────

/**
 * Check if the output text contains content matching the role's forbidden output types.
 */
function checkForbiddenOutputs(role: AgentRole, text: string): string[] {
  const violations: string[] = [];

  // Map forbidden output types to detection patterns
  const forbiddenDetectors: Record<string, RegExp> = {
    finding_confirmation: /\b(?:confirmed?|validated?|verified?)\s+(?:finding|vuln)/i,
    evidence_artifact: /\b(?:evidence|artifact)\s*[:=]\s*\{/i,
    quality_gate_override: /\bquality[_\s]?gate\s*[:=]/i,
    exploit_result: /\bexploit[_\s]?result\s*[:=]/i,
    success_determination: /\b(?:attack|exploit)\s+(?:succeeded|was\s+successful)\b/i,
    vulnerability_confirmation: /\bvulnerability\s+(?:confirmed|verified|validated)\b/i,
    evidence_promotion: /\bpromot(?:e|ed|ing)\s+(?:to\s+)?(?:PROVEN|CORROBORATED)\b/i,
    quality_level_change: /\b(?:change|set|update)\s+quality\s+(?:to|level)/i,
    exploit_code: /\b(?:def\s+exploit|function\s+exploit|class\s+Exploit)\b/,
    engine_mutation: /\b(?:engine|orchestrator)\s*\.\s*(?:set|update|mutate)\b/i,
    new_finding_creation: /\b(?:create|add|insert)\s+(?:new\s+)?finding\b/i,
  };

  for (const forbidden of role.forbiddenOutputs) {
    const detector = forbiddenDetectors[forbidden];
    if (detector && detector.test(text)) {
      violations.push(`FORBIDDEN_OUTPUT(${role.slug}): ${forbidden}`);
    }
  }

  return violations;
}

// ─── Sanitization ───────────────────────────────────────────────────────────

/**
 * Strip unsafe content from LLM output, keeping the safe portions.
 *
 * Strategy: Split by sentences, remove sentences that contain violations,
 * reassemble. If all content is unsafe, return a redaction notice.
 */
function sanitizeOutput(text: string, violations: string[]): string {
  // Collect all violation patterns for sentence-level filtering
  const allPatterns: RegExp[] = [
    ...FINDING_CONFIRMATION_PATTERNS.map((p) => p.pattern),
    ...ARTIFACT_FABRICATION_PATTERNS.map((p) => p.pattern),
    ...SCOPE_EXPANSION_PATTERNS.map((p) => p.pattern),
  ];

  // Split into sentences (rough heuristic)
  const sentences = text.split(/(?<=[.!?\n])\s+/);
  const safeSentences: string[] = [];

  for (const sentence of sentences) {
    let isSafe = true;
    for (const pattern of allPatterns) {
      // Create a new RegExp to reset lastIndex
      const fresh = new RegExp(pattern.source, pattern.flags);
      if (fresh.test(sentence)) {
        isSafe = false;
        break;
      }
    }
    if (isSafe) {
      safeSentences.push(sentence);
    }
  }

  if (safeSentences.length === 0) {
    return `[REDACTED: ${violations.length} safety violation(s) detected — entire output stripped]`;
  }

  return safeSentences.join(" ");
}

// ─── Utilities ──────────────────────────────────────────────────────────────

/**
 * Extract text content from various output shapes (string, object with content, etc.)
 */
function extractText(output: unknown): string | null {
  if (typeof output === "string") {
    return output;
  }

  if (output === null || output === undefined) {
    return null;
  }

  if (typeof output === "object") {
    // Handle { content: string } shape
    const obj = output as Record<string, unknown>;
    if (typeof obj["content"] === "string") {
      return obj["content"];
    }

    // Handle { text: string } shape
    if (typeof obj["text"] === "string") {
      return obj["text"];
    }

    // Handle { message: string } shape
    if (typeof obj["message"] === "string") {
      return obj["message"];
    }

    // Last resort: stringify for pattern matching
    try {
      return JSON.stringify(output);
    } catch {
      return null;
    }
  }

  return String(output);
}

// ─── Batch Validation ───────────────────────────────────────────────────────

/**
 * Validate multiple outputs at once (e.g., from a multi-turn conversation).
 * Returns combined violations across all outputs.
 */
export function validateBatch(
  role: AgentRole,
  outputs: unknown[],
): { allSafe: boolean; results: SafetyResult[] } {
  const results = outputs.map((o) => validateLLMOutput(role, o));
  const allSafe = results.every((r) => r.safe);

  if (!allSafe) {
    const totalViolations = results.reduce(
      (sum, r) => sum + r.violations.length,
      0,
    );
    log.warn(
      { role: role.slug, outputCount: outputs.length, totalViolations },
      "[LLM-Safety] Batch validation: %d violations across %d outputs for %s",
      totalViolations,
      outputs.length,
      role.name,
    );
  }

  return { allSafe, results };
}

/**
 * Quick check: does a string contain any safety-violating content?
 * Lightweight version of validateLLMOutput for use in hot paths.
 */
export function quickSafetyCheck(text: string): boolean {
  for (const { pattern } of FINDING_CONFIRMATION_PATTERNS) {
    if (pattern.test(text)) return false;
  }
  for (const { pattern } of ARTIFACT_FABRICATION_PATTERNS) {
    if (pattern.test(text)) return false;
  }
  return true;
}
