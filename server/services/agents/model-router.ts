import OpenAI from "openai";

export interface ModelConfig {
  provider: "openai" | "openrouter";
  model: string;
  weight?: number;
}

export interface ModelRouterConfig {
  models: ModelConfig[];
  strategy: "single" | "round_robin" | "weighted_random";
  timeoutMs: number;
  maxRetries: number;
}

interface ProviderClient {
  client: OpenAI;
  model: string;
  weight: number;
}

export class ModelRouter {
  private providers: ProviderClient[];
  private strategy: ModelRouterConfig["strategy"];
  private turnCounter = 0;

  constructor(config: ModelRouterConfig) {
    this.strategy = config.strategy;
    this.providers = config.models.map((m) => ({
      client: this.createClient(m, config.timeoutMs, config.maxRetries),
      model: m.model,
      weight: m.weight ?? 1,
    }));
  }

  private createClient(
    model: ModelConfig,
    timeoutMs: number,
    maxRetries: number
  ): OpenAI {
    if (model.provider === "openai") {
      return new OpenAI({
        apiKey:
          process.env.AI_INTEGRATIONS_OPENAI_API_KEY ||
          process.env.OPENAI_API_KEY,
        baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL || undefined,
        timeout: timeoutMs,
        maxRetries,
      });
    }

    // OpenRouter — unified gateway for Anthropic, Google, Meta, etc.
    return new OpenAI({
      apiKey: process.env.AI_INTEGRATIONS_OPENROUTER_API_KEY,
      baseURL:
        process.env.AI_INTEGRATIONS_OPENROUTER_BASE_URL ||
        "https://openrouter.ai/api/v1",
      timeout: timeoutMs,
      maxRetries,
    });
  }

  /** Get the client + model for a given turn (supports alloy rotation). */
  getForTurn(turn?: number): { client: OpenAI; model: string } {
    const t = turn ?? this.turnCounter++;

    if (this.providers.length === 1 || this.strategy === "single") {
      return {
        client: this.providers[0].client,
        model: this.providers[0].model,
      };
    }

    if (this.strategy === "round_robin") {
      const idx = t % this.providers.length;
      return {
        client: this.providers[idx].client,
        model: this.providers[idx].model,
      };
    }

    // weighted_random (XBOW alloy technique)
    const totalWeight = this.providers.reduce((s, p) => s + p.weight, 0);
    let r = Math.random() * totalWeight;
    for (const p of this.providers) {
      r -= p.weight;
      if (r <= 0) {
        return { client: p.client, model: p.model };
      }
    }
    // Fallback
    return {
      client: this.providers[0].client,
      model: this.providers[0].model,
    };
  }
}

/**
 * Build a ModelRouter from environment variables.
 *
 * Default: single GPT-4o (zero config needed).
 * Alloy: set EXPLOIT_AGENT_ALLOY=true and configure OpenRouter key.
 * Custom: set EXPLOIT_AGENT_MODELS=openai:gpt-4o:0.4,openrouter:anthropic/claude-sonnet-4:0.4
 */
export function createExploitModelRouter(): ModelRouter {
  const timeoutMs = 60_000;
  const maxRetries = 1;

  // Custom model list
  const modelsEnv = process.env.EXPLOIT_AGENT_MODELS;
  if (modelsEnv) {
    const models: ModelConfig[] = modelsEnv.split(",").map((entry) => {
      const [provider, model, weight] = entry.trim().split(":");
      return {
        provider: (provider as ModelConfig["provider"]) || "openai",
        model: model || "gpt-4o",
        weight: weight ? parseFloat(weight) : 1,
      };
    });
    return new ModelRouter({
      models,
      strategy: models.length > 1 ? "weighted_random" : "single",
      timeoutMs,
      maxRetries,
    });
  }

  // Alloy mode — GPT-4o + OpenRouter models
  if (
    process.env.EXPLOIT_AGENT_ALLOY === "true" &&
    process.env.AI_INTEGRATIONS_OPENROUTER_API_KEY
  ) {
    return new ModelRouter({
      models: [
        { provider: "openai", model: "gpt-4o", weight: 0.4 },
        {
          provider: "openrouter",
          model: "anthropic/claude-sonnet-4",
          weight: 0.4,
        },
        {
          provider: "openrouter",
          model: "google/gemini-2.5-pro",
          weight: 0.2,
        },
      ],
      strategy: "weighted_random",
      timeoutMs,
      maxRetries,
    });
  }

  // Default — single GPT-4o
  return new ModelRouter({
    models: [{ provider: "openai", model: "gpt-4o" }],
    strategy: "single",
    timeoutMs,
    maxRetries,
  });
}
