/**
 * LLM Model Router — Central model routing layer for OdinForge core-v2.
 *
 * Routes tasks to the right model tier based on task type. Each tier maps
 * to a specific provider + model combination with appropriate parameters.
 *
 * CORE PRINCIPLE:
 *   LLMs are used for planning, typing, shaping, narrating, and drafting.
 *   LLMs are NEVER used for evidence, confirmation, quality gate, or finding truth.
 *   The deterministic engine remains the source of truth.
 *
 * Tier layout:
 *   primary   — heavy reasoning: frontier planning, path ranking, summaries
 *   tactical  — fast shaping: endpoint typing, request building, narration
 *   reviewer  — careful audit: code review, narrative refinement, architecture
 *
 * Fallback: primary → tactical → null (never fabricate)
 * Rate-limit: 429 from any provider triggers tier fallback
 */

import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { serviceLogger } from "../logger";

const log = serviceLogger("llm-router");

// ─── Types ──────────────────────────────────────────────────────────────────

export type ModelTier = "primary" | "tactical" | "reviewer";

export type TaskType =
  | "frontier_planning"
  | "path_ranking"
  | "cross_phase_planning"
  | "run_summary"
  | "endpoint_typing"
  | "request_shaping"
  | "graphql_template"
  | "reasoning_message"
  | "remediation_draft"
  | "code_review"
  | "narrative_refinement"
  | "architecture_check";

export interface ModelConfig {
  provider: "openai" | "anthropic" | "google";
  model: string;
  maxTokens: number;
  temperature: number;
}

export interface LLMResponse {
  content: string;
  model: string;
  tier: ModelTier;
  tokensUsed: number;
  latencyMs: number;
  fallback: boolean;
}

// ─── Default Tier Configs ───────────────────────────────────────────────────

const DEFAULT_TIER_CONFIGS: Record<ModelTier, ModelConfig> = {
  primary: {
    provider: "openai",
    model: "gpt-5.4",
    maxTokens: 4096,
    temperature: 0.3,
  },
  tactical: {
    provider: "openai",
    model: "gpt-5.4-mini",
    maxTokens: 2048,
    temperature: 0.2,
  },
  reviewer: {
    provider: "anthropic",
    model: "claude-opus-4-6",
    maxTokens: 4096,
    temperature: 0.1,
  },
};

// ─── Task → Tier Routing ────────────────────────────────────────────────────

const TASK_ROUTING: Record<TaskType, ModelTier> = {
  // Primary tier — heavy reasoning
  frontier_planning: "primary",
  path_ranking: "primary",
  cross_phase_planning: "primary",
  run_summary: "primary",

  // Tactical tier — fast shaping
  endpoint_typing: "tactical",
  request_shaping: "tactical",
  graphql_template: "tactical",
  reasoning_message: "tactical",
  remediation_draft: "tactical",

  // Reviewer tier — careful audit
  code_review: "reviewer",
  narrative_refinement: "reviewer",
  architecture_check: "reviewer",
};

// ─── Fallback Chain ─────────────────────────────────────────────────────────

const FALLBACK_CHAIN: Record<ModelTier, ModelTier | null> = {
  primary: "tactical",
  tactical: null, // Do not fabricate — return null
  reviewer: "tactical",
};

// ─── Provider Adapters ──────────────────────────────────────────────────────

interface ProviderCallResult {
  content: string;
  tokensUsed: number;
}

async function callOpenAI(
  config: ModelConfig,
  systemPrompt: string,
  userPrompt: string,
  context?: string,
): Promise<ProviderCallResult> {
  const apiKey =
    process.env.AI_INTEGRATIONS_OPENAI_API_KEY ||
    process.env.OPENAI_API_KEY;

  if (!apiKey) {
    throw new Error("No OpenAI API key configured");
  }

  const client = new OpenAI({
    apiKey,
    baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL || undefined,
    timeout: 60_000,
    maxRetries: 1,
  });

  const messages: Array<OpenAI.ChatCompletionMessageParam> = [
    { role: "system" as const, content: systemPrompt },
  ];

  if (context) {
    messages.push({ role: "user" as const, content: `Context:\n${context}` });
  }

  messages.push({ role: "user" as const, content: userPrompt });

  const response = await client.chat.completions.create({
    model: config.model,
    messages,
    max_tokens: config.maxTokens,
    temperature: config.temperature,
  });

  const choice = response.choices?.[0];
  return {
    content: choice?.message?.content ?? "",
    tokensUsed: response.usage?.total_tokens ?? 0,
  };
}

async function callAnthropic(
  config: ModelConfig,
  systemPrompt: string,
  userPrompt: string,
  context?: string,
): Promise<ProviderCallResult> {
  const apiKey = process.env.ANTHROPIC_API_KEY;

  if (!apiKey) {
    throw new Error("No Anthropic API key configured");
  }

  const client = new Anthropic({ apiKey, timeout: 60_000, maxRetries: 1 });

  const userContent = context
    ? `Context:\n${context}\n\n${userPrompt}`
    : userPrompt;

  const response = await client.messages.create({
    model: config.model,
    max_tokens: config.maxTokens,
    system: systemPrompt,
    messages: [{ role: "user", content: userContent }],
  });

  let text = "";
  for (const block of response.content) {
    if (block.type === "text") {
      text += block.text;
    }
  }

  const tokensUsed =
    (response.usage?.input_tokens ?? 0) +
    (response.usage?.output_tokens ?? 0);

  return { content: text, tokensUsed };
}

async function callProvider(
  config: ModelConfig,
  systemPrompt: string,
  userPrompt: string,
  context?: string,
): Promise<ProviderCallResult> {
  switch (config.provider) {
    case "openai":
    case "google": // Google models routed via OpenAI-compatible API
      return callOpenAI(config, systemPrompt, userPrompt, context);
    case "anthropic":
      return callAnthropic(config, systemPrompt, userPrompt, context);
    default:
      throw new Error(`Unknown provider: ${config.provider as string}`);
  }
}

// ─── Rate Limit Detection ───────────────────────────────────────────────────

function isRateLimitError(err: unknown): boolean {
  if (err instanceof Error) {
    const msg = err.message.toLowerCase();
    if (msg.includes("429") || msg.includes("rate limit")) return true;
  }
  // OpenAI SDK throws APIError with status
  if (typeof err === "object" && err !== null && "status" in err) {
    return (err as { status: number }).status === 429;
  }
  return false;
}

// ─── Model Router ───────────────────────────────────────────────────────────

/**
 * Resolve the ModelConfig for a tier, applying environment variable overrides.
 *
 * Override env vars:
 *   ODINFORGE_PRIMARY_MODEL  — e.g. "openai:gpt-5.4"
 *   ODINFORGE_TACTICAL_MODEL — e.g. "openai:gpt-5.4-mini"
 *   ODINFORGE_REVIEWER_MODEL — e.g. "anthropic:claude-opus-4-6"
 */
function resolveConfig(tier: ModelTier): ModelConfig {
  const envMap: Record<ModelTier, string> = {
    primary: "ODINFORGE_PRIMARY_MODEL",
    tactical: "ODINFORGE_TACTICAL_MODEL",
    reviewer: "ODINFORGE_REVIEWER_MODEL",
  };

  const envVal = process.env[envMap[tier]];
  if (envVal) {
    const [provider, ...modelParts] = envVal.split(":");
    const model = modelParts.join(":"); // Handles model names with colons
    if (provider && model) {
      const defaults = DEFAULT_TIER_CONFIGS[tier];
      return {
        provider: provider as ModelConfig["provider"],
        model,
        maxTokens: defaults.maxTokens,
        temperature: defaults.temperature,
      };
    }
  }

  return { ...DEFAULT_TIER_CONFIGS[tier] };
}

/**
 * Get the ModelConfig for a given task type.
 */
export function routeTask(taskType: TaskType): ModelConfig {
  const tier = TASK_ROUTING[taskType];
  return resolveConfig(tier);
}

/**
 * Get the tier for a given task type.
 */
export function getTier(taskType: TaskType): ModelTier {
  return TASK_ROUTING[taskType];
}

/**
 * Call the appropriate model for a task type.
 *
 * Includes:
 *   - Automatic tier routing
 *   - Fallback on failure (primary → tactical → null)
 *   - Rate-limit detection (429 triggers fallback)
 *   - Structured logging of every call
 *   - Stub behavior when no API keys are configured
 *
 * Returns null if all tiers fail (never fabricates).
 */
export async function callModel(
  taskType: TaskType,
  prompt: string,
  context?: string,
  systemPrompt?: string,
): Promise<LLMResponse | null> {
  const tier = TASK_ROUTING[taskType];
  const config = resolveConfig(tier);
  const sysPrompt =
    systemPrompt ?? "You are a planning and analysis assistant for OdinForge.";

  // Stub mode: if no API keys are configured, return null gracefully
  if (!hasAnyApiKey()) {
    log.warn(
      { taskType, tier },
      "[LLM:%s] %s → no API keys configured, returning null",
      tier,
      taskType,
    );
    return null;
  }

  // Attempt primary tier
  const result = await attemptCall(tier, config, taskType, sysPrompt, prompt, context);
  if (result) return result;

  // Fallback chain
  const fallbackTier = FALLBACK_CHAIN[tier];
  if (fallbackTier) {
    const fallbackConfig = resolveConfig(fallbackTier);
    log.info(
      { taskType, from: tier, to: fallbackTier },
      "[LLM:%s] %s → falling back to %s tier",
      tier,
      taskType,
      fallbackTier,
    );

    const fallbackResult = await attemptCall(
      fallbackTier,
      fallbackConfig,
      taskType,
      sysPrompt,
      prompt,
      context,
      true,
    );
    if (fallbackResult) return fallbackResult;
  }

  // All tiers failed — return null, never fabricate
  log.error(
    { taskType, tier },
    "[LLM:%s] %s → all tiers exhausted, returning null",
    tier,
    taskType,
  );
  return null;
}

async function attemptCall(
  tier: ModelTier,
  config: ModelConfig,
  taskType: TaskType,
  systemPrompt: string,
  userPrompt: string,
  context: string | undefined,
  isFallback = false,
): Promise<LLMResponse | null> {
  const start = Date.now();

  try {
    const result = await callProvider(config, systemPrompt, userPrompt, context);
    const latencyMs = Date.now() - start;

    log.info(
      {
        tier,
        taskType,
        model: config.model,
        tokens: result.tokensUsed,
        latencyMs,
        fallback: isFallback,
      },
      "[LLM:%s] %s → %s (%d tokens, %dms)",
      tier,
      taskType,
      config.model,
      result.tokensUsed,
      latencyMs,
    );

    return {
      content: result.content,
      model: config.model,
      tier,
      tokensUsed: result.tokensUsed,
      latencyMs,
      fallback: isFallback,
    };
  } catch (err) {
    const latencyMs = Date.now() - start;

    if (isRateLimitError(err)) {
      log.warn(
        { tier, taskType, model: config.model, latencyMs },
        "[LLM:%s] %s → %s rate-limited (429), will try fallback",
        tier,
        taskType,
        config.model,
      );
    } else {
      log.error(
        { tier, taskType, model: config.model, latencyMs, err },
        "[LLM:%s] %s → %s failed (%dms)",
        tier,
        taskType,
        config.model,
        latencyMs,
      );
    }

    return null;
  }
}

// ─── Utilities ──────────────────────────────────────────────────────────────

function hasAnyApiKey(): boolean {
  return !!(
    process.env.OPENAI_API_KEY ||
    process.env.AI_INTEGRATIONS_OPENAI_API_KEY ||
    process.env.ANTHROPIC_API_KEY
  );
}

/**
 * Check whether the LLM layer is operational (has at least one API key).
 */
export function isLLMAvailable(): boolean {
  return hasAnyApiKey();
}

/**
 * Get the resolved config for all tiers (useful for diagnostics).
 */
export function getAllTierConfigs(): Record<ModelTier, ModelConfig> {
  return {
    primary: resolveConfig("primary"),
    tactical: resolveConfig("tactical"),
    reviewer: resolveConfig("reviewer"),
  };
}
