export type LlmProvider = "openai" | "anthropic" | "google";

export type LlmTask =
  | "planner"
  | "endpoint_typing"
  | "request_shaping"
  | "reasoning_stream"
  | "report_writer"
  | "code_review"
  | "long_context_analysis";

export interface LlmMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface LlmRequest {
  task: LlmTask;
  messages: LlmMessage[];
  temperature?: number;
  maxOutputTokens?: number;
  metadata?: Record<string, string>;
}

export interface LlmResponse {
  provider: LlmProvider;
  model: string;
  text: string;
  usage?: {
    inputTokens?: number;
    outputTokens?: number;
  };
}

export interface ProviderModelConfig {
  provider: LlmProvider;
  model: string;
}

export interface TaskRoutingConfig {
  primary: ProviderModelConfig;
  fallbacks: ProviderModelConfig[];
  temperature: number;
  maxOutputTokens: number;
}

export interface LlmRouterConfig {
  timeoutMs: number;
  retryCount: number;
  tasks: Record<LlmTask, TaskRoutingConfig>;
}
