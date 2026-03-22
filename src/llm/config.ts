import { LlmRouterConfig } from "./types";

function optionalEnv(name: string, fallback = "not-configured"): string {
  return process.env[name] || fallback;
}

function parseNumber(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

/** Returns true if at least one LLM provider has real API keys configured */
export function isLlmConfigured(): boolean {
  return !!(
    process.env.OPENAI_API_KEY ||
    process.env.ANTHROPIC_API_KEY ||
    process.env.GOOGLE_API_KEY ||
    process.env.GEMINI_API_KEY
  );
}

export const llmConfig: LlmRouterConfig = {
  timeoutMs: parseNumber(process.env.LLM_TIMEOUT_MS, 45000),
  retryCount: parseNumber(process.env.LLM_RETRY_COUNT, 1),
  tasks: {
    planner: {
      primary: {
        provider: "openai",
        model: optionalEnv("ODINFORGE_PRIMARY_MODEL"),
      },
      fallbacks: [
        {
          provider: "anthropic",
          model: optionalEnv("ODINFORGE_REVIEW_MODEL"),
        },
        {
          provider: "google",
          model: optionalEnv("ODINFORGE_DEEP_MODEL"),
        },
      ],
      temperature: 0.2,
      maxOutputTokens: 1800,
    },

    endpoint_typing: {
      primary: {
        provider: "openai",
        model: optionalEnv("ODINFORGE_FAST_MODEL"),
      },
      fallbacks: [
        {
          provider: "google",
          model: optionalEnv("ODINFORGE_DEEP_MODEL"),
        },
      ],
      temperature: 0,
      maxOutputTokens: 400,
    },

    request_shaping: {
      primary: {
        provider: "openai",
        model: optionalEnv("ODINFORGE_FAST_MODEL"),
      },
      fallbacks: [
        {
          provider: "anthropic",
          model: optionalEnv("ODINFORGE_REVIEW_MODEL"),
        },
      ],
      temperature: 0,
      maxOutputTokens: 800,
    },

    reasoning_stream: {
      primary: {
        provider: "openai",
        model: optionalEnv("ODINFORGE_FAST_MODEL"),
      },
      fallbacks: [
        {
          provider: "anthropic",
          model: optionalEnv("ODINFORGE_REVIEW_MODEL"),
        },
      ],
      temperature: 0.2,
      maxOutputTokens: 220,
    },

    report_writer: {
      primary: {
        provider: "openai",
        model: optionalEnv("ODINFORGE_PRIMARY_MODEL"),
      },
      fallbacks: [
        {
          provider: "anthropic",
          model: optionalEnv("ODINFORGE_REVIEW_MODEL"),
        },
        {
          provider: "google",
          model: optionalEnv("ODINFORGE_DEEP_MODEL"),
        },
      ],
      temperature: 0.2,
      maxOutputTokens: 2400,
    },

    code_review: {
      primary: {
        provider: "anthropic",
        model: optionalEnv("ODINFORGE_REVIEW_MODEL"),
      },
      fallbacks: [
        {
          provider: "openai",
          model: optionalEnv("ODINFORGE_PRIMARY_MODEL"),
        },
      ],
      temperature: 0.1,
      maxOutputTokens: 2000,
    },

    long_context_analysis: {
      primary: {
        provider: "google",
        model: optionalEnv("ODINFORGE_DEEP_MODEL"),
      },
      fallbacks: [
        {
          provider: "openai",
          model: optionalEnv("ODINFORGE_PRIMARY_MODEL"),
        },
      ],
      temperature: 0.1,
      maxOutputTokens: 3000,
    },
  },
};
