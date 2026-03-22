import OpenAI from "openai";
import Anthropic from "@anthropic-ai/sdk";
import { GoogleGenAI } from "@google/genai";
import { LlmMessage, LlmRequest, LlmResponse, ProviderModelConfig } from "./types";

function getSystemPrompt(messages: LlmMessage[]): string | undefined {
  return messages.find((m) => m.role === "system")?.content;
}

function getConversation(messages: LlmMessage[]): LlmMessage[] {
  return messages.filter((m) => m.role !== "system");
}

function flattenMessages(messages: LlmMessage[]): string {
  return messages
    .map((m) => `${m.role.toUpperCase()}:\n${m.content}`)
    .join("\n\n");
}

export class LlmProviders {
  private readonly openai?: OpenAI;
  private readonly anthropic?: Anthropic;
  private readonly google?: GoogleGenAI;

  constructor() {
    if (process.env.OPENAI_API_KEY) {
      this.openai = new OpenAI({
        apiKey: process.env.OPENAI_API_KEY,
      });
    }

    if (process.env.ANTHROPIC_API_KEY) {
      this.anthropic = new Anthropic({
        apiKey: process.env.ANTHROPIC_API_KEY,
      });
    }

    if (process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY) {
      this.google = new GoogleGenAI({
        apiKey: process.env.GOOGLE_API_KEY ?? process.env.GEMINI_API_KEY!,
      });
    }
  }

  async generate(
    route: ProviderModelConfig,
    request: LlmRequest,
    signal?: AbortSignal
  ): Promise<LlmResponse> {
    switch (route.provider) {
      case "openai":
        return this.generateOpenAI(route.model, request, signal);
      case "anthropic":
        return this.generateAnthropic(route.model, request, signal);
      case "google":
        return this.generateGoogle(route.model, request, signal);
      default: {
        const neverProvider: never = route.provider;
        throw new Error(`Unsupported provider: ${neverProvider}`);
      }
    }
  }

  private async generateOpenAI(
    model: string,
    request: LlmRequest,
    signal?: AbortSignal
  ): Promise<LlmResponse> {
    if (!this.openai) {
      throw new Error("OpenAI provider not configured");
    }

    const response = await this.openai.responses.create(
      {
        model,
        instructions: getSystemPrompt(request.messages),
        input: getConversation(request.messages).map((m) => ({
          role: m.role,
          content: [{ type: "input_text" as const, text: m.content }],
        })),
        temperature: request.temperature,
        max_output_tokens: request.maxOutputTokens,
        metadata: request.metadata,
      },
      { signal }
    );

    return {
      provider: "openai",
      model,
      text: response.output_text ?? "",
      usage: {
        inputTokens: response.usage?.input_tokens,
        outputTokens: response.usage?.output_tokens,
      },
    };
  }

  private async generateAnthropic(
    model: string,
    request: LlmRequest,
    signal?: AbortSignal
  ): Promise<LlmResponse> {
    if (!this.anthropic) {
      throw new Error("Anthropic provider not configured");
    }

    const response = await this.anthropic.messages.create(
      {
        model,
        system: getSystemPrompt(request.messages),
        max_tokens: request.maxOutputTokens ?? 1200,
        temperature: request.temperature,
        messages: getConversation(request.messages).map((m) => ({
          role: m.role === "assistant" ? "assistant" as const : "user" as const,
          content: m.content,
        })),
      },
      { signal }
    );

    const text = response.content
      .filter((c): c is Anthropic.TextBlock => c.type === "text")
      .map((c) => c.text)
      .join("\n");

    return {
      provider: "anthropic",
      model,
      text,
      usage: {
        inputTokens: response.usage.input_tokens,
        outputTokens: response.usage.output_tokens,
      },
    };
  }

  private async generateGoogle(
    model: string,
    request: LlmRequest,
    signal?: AbortSignal
  ): Promise<LlmResponse> {
    if (!this.google) {
      throw new Error("Google provider not configured");
    }

    const response = await this.google.models.generateContent({
      model,
      contents: flattenMessages(request.messages),
      config: {
        systemInstruction: getSystemPrompt(request.messages),
        temperature: request.temperature,
        maxOutputTokens: request.maxOutputTokens,
      },
    });

    return {
      provider: "google",
      model,
      text: response.text ?? "",
      usage: {
        inputTokens: response.usageMetadata?.promptTokenCount,
        outputTokens: response.usageMetadata?.candidatesTokenCount,
      },
    };
  }
}
