export interface LLMValidationConfig {
  enabled: boolean;
  model: string;
  maxTokens: number;
  batchSize: number;
  maxBundleSizeBytes: number;
  confidenceThreshold: number;
  retryAttempts: number;
  retryDelayMs: number;
}

export function getLLMValidationConfig(): LLMValidationConfig {
  return {
    enabled: process.env.AEV_LLM_VALIDATION_ENABLED !== "false",
    model: process.env.AEV_LLM_MODEL || "gpt-4o-mini",
    maxTokens: parseInt(process.env.AEV_LLM_MAX_TOKENS || "1000", 10),
    batchSize: parseInt(process.env.AEV_LLM_BATCH_SIZE || "5", 10),
    maxBundleSizeBytes: parseInt(process.env.AEV_LLM_MAX_BUNDLE_SIZE || "4096", 10),
    confidenceThreshold: parseInt(process.env.AEV_LLM_CONFIDENCE_THRESHOLD || "70", 10),
    retryAttempts: parseInt(process.env.AEV_LLM_RETRY_ATTEMPTS || "2", 10),
    retryDelayMs: parseInt(process.env.AEV_LLM_RETRY_DELAY_MS || "1000", 10),
  };
}

export function isLLMValidationEnabled(): boolean {
  return getLLMValidationConfig().enabled;
}
