/**
 * XBOW Benchmark Types
 *
 * Types for running OdinForge's exploit agent against the XBOW
 * 104-challenge CTF benchmark (hint-free, black-box mode).
 */

export interface XBOWChallenge {
  id: string;                // e.g. "XBEN-001-24"
  name: string;
  category: string;          // inferred from app code/compose, or "unknown"
  difficulty: 1 | 2 | 3;    // inferred: 1=simple, 2=default, 3=multi-service
  description: string;
  tags: string[];            // may be empty (real XBOW repo has no tags)
  win_condition: string;
  composeDir: string;        // absolute path to challenge directory
}

export interface XBOWChallengeResult {
  challengeId: string;
  category: string;
  difficulty: number;
  success: boolean;             // flag found in evidence
  vulnDetected: boolean;        // agent found a vuln (even without flag)
  flagFoundIn: "tool_result" | "http_response" | "agent_output" | "debug_messages" | null;
  agentTurns: number;
  toolCalls: number;
  processingTimeMs: number;
  error?: string;
}

export interface XBOWCategoryStats {
  solved: number;
  total: number;
  rate: string;
}

export interface XBOWReport {
  meta: {
    timestamp: string;
    totalChallenges: number;
    executionMode: string;
    modelRouter: string;
    odinforgeMode: "black-box";
  };
  overall: {
    solved: number;
    total: number;
    percentage: string;
    shannonRate: "96.15%";
    shannonMode: "white-box";
    xbowRate: "85%";
    xbowMode: "black-box";
  };
  byCategory: Record<string, XBOWCategoryStats>;
  byDifficulty: Record<string, XBOWCategoryStats>;
  results: XBOWChallengeResult[];
  failures: {
    challengeId: string;
    reason: string;
    agentSummary: string;
  }[];
}

/** Map XBOW tags to OdinForge exposure types */
export const XBOW_CATEGORY_MAP: Record<string, { exposureType: string; vulnTypes: string[] }> = {
  sqli:                { exposureType: "cve_exploitation", vulnTypes: ["sqli"] },
  blind_sqli:          { exposureType: "cve_exploitation", vulnTypes: ["sqli"] },
  sql_injection:       { exposureType: "cve_exploitation", vulnTypes: ["sqli"] },
  xss:                 { exposureType: "cve_exploitation", vulnTypes: ["xss"] },
  idor:                { exposureType: "configuration_weakness", vulnTypes: ["auth_bypass"] },
  default_credentials: { exposureType: "configuration_weakness", vulnTypes: ["auth_bypass"] },
  broken_authorization:{ exposureType: "configuration_weakness", vulnTypes: ["auth_bypass"] },
  ssrf:                { exposureType: "configuration_weakness", vulnTypes: ["ssrf"] },
  misconfiguration:    { exposureType: "configuration_weakness", vulnTypes: ["ssrf"] },
  ssti:                { exposureType: "cve_exploitation", vulnTypes: ["command_injection"] },
  command_injection:   { exposureType: "cve_exploitation", vulnTypes: ["command_injection"] },
  path_traversal:      { exposureType: "cve_exploitation", vulnTypes: ["path_traversal"] },
  file_inclusion:      { exposureType: "cve_exploitation", vulnTypes: ["path_traversal"] },
};

/** Resolve the primary category from a set of XBOW tags */
export function resolveCategory(tags: string[]): string {
  const priority = [
    "sqli", "blind_sqli", "sql_injection",
    "xss", "ssti", "command_injection",
    "ssrf", "path_traversal", "file_inclusion",
    "idor", "broken_authorization", "default_credentials",
    "misconfiguration",
  ];
  for (const p of priority) {
    if (tags.includes(p)) return p;
  }
  return tags[0] || "unknown";
}
