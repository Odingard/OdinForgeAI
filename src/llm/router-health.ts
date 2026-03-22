/**
 * LLM Router Health — Lightweight health/failure tracking for the LLM router.
 *
 * Tracks which providers are configured, records recent failures,
 * and exposes a health summary for the /api/llm/health endpoint.
 */

import { llmConfig, isLlmConfigured } from "./config";
import type { LlmTask } from "./types";

// ── Failure Log ─────────────────────────────────────────────────────────────

interface LlmFailureEntry {
  timestamp: string;
  task: string;
  provider: string;
  model: string;
  error: string;
}

const MAX_FAILURES = 50;
const failures: LlmFailureEntry[] = [];

export function recordLlmFailure(
  task: string,
  provider: string,
  model: string,
  error: string,
): void {
  failures.push({
    timestamp: new Date().toISOString(),
    task,
    provider,
    model,
    error: error.slice(0, 500),
  });
  // Bounded — keep last N
  if (failures.length > MAX_FAILURES) {
    failures.splice(0, failures.length - MAX_FAILURES);
  }
}

export function getRecentFailures(): LlmFailureEntry[] {
  return [...failures];
}

// ── Health Summary ──────────────────────────────────────────────────────────

export interface LlmHealthSummary {
  configured: boolean;
  providers: {
    openai: boolean;
    anthropic: boolean;
    google: boolean;
  };
  taskRouting: Record<string, { primary: string; fallbackCount: number }>;
  recentFailureCount: number;
  recentFailures: LlmFailureEntry[];
}

export function getLlmHealth(): LlmHealthSummary {
  const taskRouting: Record<string, { primary: string; fallbackCount: number }> = {};

  const taskNames = Object.keys(llmConfig.tasks) as LlmTask[];
  for (const task of taskNames) {
    const cfg = llmConfig.tasks[task];
    taskRouting[task] = {
      primary: `${cfg.primary.provider}/${cfg.primary.model}`,
      fallbackCount: cfg.fallbacks.length,
    };
  }

  return {
    configured: isLlmConfigured(),
    providers: {
      openai: !!process.env.OPENAI_API_KEY,
      anthropic: !!process.env.ANTHROPIC_API_KEY,
      google: !!(process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY),
    },
    taskRouting,
    recentFailureCount: failures.length,
    recentFailures: [...failures],
  };
}
