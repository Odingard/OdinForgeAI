import OpenAI from "openai";
import { AnthropicOpenAIAdapter } from "./anthropic-adapter";

const OPENAI_TIMEOUT_MS = 90000; // 90 second timeout (Claude needs more time than GPT-4o)

function getOpenAIApiKey(): string | undefined {
  return process.env.AI_INTEGRATIONS_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
}

function getOpenAIBaseURL(): string | undefined {
  return process.env.AI_INTEGRATIONS_OPENAI_BASE_URL || undefined;
}

function getAnthropicApiKey(): string | undefined {
  return process.env.ANTHROPIC_API_KEY;
}

/**
 * Primary LLM client. Uses Anthropic (Claude) when ANTHROPIC_API_KEY is set,
 * falls back to OpenAI when OPENAI_API_KEY is set.
 *
 * The AnthropicOpenAIAdapter implements the same .chat.completions.create()
 * interface so all agent code works unchanged.
 */
function createLLMClient(): OpenAI | AnthropicOpenAIAdapter {
  const anthropicKey = getAnthropicApiKey();
  if (anthropicKey) {
    console.log("[LLM] Using Anthropic (Claude) as primary LLM provider");
    return new AnthropicOpenAIAdapter({
      apiKey: anthropicKey,
      timeout: OPENAI_TIMEOUT_MS,
      maxRetries: 2,
    });
  }

  const openaiKey = getOpenAIApiKey();
  if (openaiKey) {
    console.log("[LLM] Using OpenAI as primary LLM provider");
    return new OpenAI({
      apiKey: openaiKey,
      baseURL: getOpenAIBaseURL(),
      timeout: OPENAI_TIMEOUT_MS,
      maxRetries: 2,
    });
  }

  console.warn("[LLM] No LLM API key configured (ANTHROPIC_API_KEY or OPENAI_API_KEY)");
  return new OpenAI({
    apiKey: "not-configured",
    timeout: OPENAI_TIMEOUT_MS,
    maxRetries: 0,
  });
}

// Export as `any` to satisfy both OpenAI and adapter type expectations
// All agents only use .chat.completions.create() which both implement
export const openai: any = createLLMClient();

export { OPENAI_TIMEOUT_MS };
