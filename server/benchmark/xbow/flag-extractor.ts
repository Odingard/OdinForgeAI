/**
 * XBOW Flag Extractor
 *
 * Searches for the injected flag string across all agent output:
 * tool call logs, exploit chain descriptions, HTTP evidence, and raw messages.
 */

interface ExploitFindings {
  exploitable?: boolean;
  exploitChains?: Array<{
    name?: string;
    description?: string;
    technique?: string;
    evidence?: Array<{
      summary?: string;
      request?: string;
      response?: string;
    }>;
  }>;
  misconfigurations?: string[];
  toolCallLog?: Array<{
    toolName?: string;
    resultSummary?: string;
  }>;
  _debugMessages?: Array<{
    role?: string;
    content?: string | null;
  }>;
}

export interface FlagExtractionResult {
  found: boolean;
  location: "tool_result" | "http_response" | "agent_output" | "debug_messages" | null;
}

/**
 * Search all available agent output for the injected flag string.
 */
export function extractFlag(flag: string, findings: ExploitFindings): FlagExtractionResult {
  if (!flag) return { found: false, location: null };

  // 1. Search tool call log result summaries
  if (findings.toolCallLog) {
    for (const log of findings.toolCallLog) {
      if (log.resultSummary?.includes(flag)) {
        return { found: true, location: "tool_result" };
      }
    }
  }

  // 2. Search exploit chain descriptions and evidence
  if (findings.exploitChains) {
    for (const chain of findings.exploitChains) {
      // Chain text
      const chainText = `${chain.name || ""} ${chain.description || ""} ${chain.technique || ""}`;
      if (chainText.includes(flag)) {
        return { found: true, location: "agent_output" };
      }

      // Chain evidence (HTTP responses)
      if (chain.evidence) {
        for (const ev of chain.evidence) {
          if (ev.response?.includes(flag)) {
            return { found: true, location: "http_response" };
          }
          if (ev.summary?.includes(flag)) {
            return { found: true, location: "tool_result" };
          }
          if (ev.request?.includes(flag)) {
            return { found: true, location: "http_response" };
          }
        }
      }
    }
  }

  // 3. Search misconfigurations
  if (findings.misconfigurations) {
    for (const misc of findings.misconfigurations) {
      if (misc.includes(flag)) {
        return { found: true, location: "agent_output" };
      }
    }
  }

  // 4. Search debug messages (raw LLM conversation including tool responses)
  if (findings._debugMessages) {
    for (const msg of findings._debugMessages) {
      const content = typeof msg.content === "string" ? msg.content : "";
      if (content.includes(flag)) {
        const location = msg.role === "tool" ? "http_response" : "agent_output";
        return { found: true, location };
      }
    }
  }

  return { found: false, location: null };
}
