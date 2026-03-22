import crypto from "crypto";
import { llmConfig } from "./config";
import { LlmProviders } from "./providers";
import {
  LlmMessage,
  LlmRequest,
  LlmResponse,
  LlmTask,
  ProviderModelConfig,
  TaskRoutingConfig,
} from "./types";

type AttemptError = {
  provider: string;
  model: string;
  error: string;
};

export class LlmRouter {
  private readonly providers: LlmProviders;

  constructor() {
    this.providers = new LlmProviders();
  }

  async run(input: LlmRequest): Promise<LlmResponse> {
    const taskConfig = this.getTaskConfig(input.task);
    const request = this.applyTaskDefaults(input, taskConfig);
    const attempts = [taskConfig.primary, ...taskConfig.fallbacks];
    const errors: AttemptError[] = [];

    for (const route of attempts) {
      const result = await this.tryRoute(route, request, errors);
      if (result) {
        return result;
      }
    }

    throw new Error(
      `All model routes failed for task=${input.task}: ${JSON.stringify(errors, null, 2)}`
    );
  }

  async planner(messages: LlmMessage[], metadata?: Record<string, string>) {
    return this.run({
      task: "planner",
      messages,
      metadata,
    });
  }

  async endpointTyper(messages: LlmMessage[], metadata?: Record<string, string>) {
    return this.run({
      task: "endpoint_typing",
      messages,
      metadata,
    });
  }

  async requestShaper(messages: LlmMessage[], metadata?: Record<string, string>) {
    return this.run({
      task: "request_shaping",
      messages,
      metadata,
    });
  }

  async reasoningStream(messages: LlmMessage[], metadata?: Record<string, string>) {
    return this.run({
      task: "reasoning_stream",
      messages,
      metadata,
    });
  }

  async reportWriter(messages: LlmMessage[], metadata?: Record<string, string>) {
    return this.run({
      task: "report_writer",
      messages,
      metadata,
    });
  }

  async codeReview(messages: LlmMessage[], metadata?: Record<string, string>) {
    return this.run({
      task: "code_review",
      messages,
      metadata,
    });
  }

  async longContextAnalysis(messages: LlmMessage[], metadata?: Record<string, string>) {
    return this.run({
      task: "long_context_analysis",
      messages,
      metadata,
    });
  }

  private getTaskConfig(task: LlmTask): TaskRoutingConfig {
    const config = llmConfig.tasks[task];
    if (!config) {
      throw new Error(`No routing config for task: ${task}`);
    }
    return config;
  }

  private applyTaskDefaults(input: LlmRequest, config: TaskRoutingConfig): LlmRequest {
    return {
      ...input,
      temperature: input.temperature ?? config.temperature,
      maxOutputTokens: input.maxOutputTokens ?? config.maxOutputTokens,
      metadata: {
        task: input.task,
        requestId: crypto.randomUUID(),
        ...(input.metadata ?? {}),
      },
    };
  }

  private async tryRoute(
    route: ProviderModelConfig,
    request: LlmRequest,
    errors: AttemptError[]
  ): Promise<LlmResponse | null> {
    const maxAttempts = Math.max(1, llmConfig.retryCount + 1);

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), llmConfig.timeoutMs);

      try {
        const response = await this.providers.generate(route, request, controller.signal);
        clearTimeout(timeout);
        return response;
      } catch (error) {
        clearTimeout(timeout);
        errors.push({
          provider: route.provider,
          model: route.model,
          error: `attempt ${attempt}: ${error instanceof Error ? error.message : String(error)}`,
        });
      }
    }

    return null;
  }
}
