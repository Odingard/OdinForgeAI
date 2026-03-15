/**
 * Anthropic → OpenAI SDK Adapter
 *
 * Wraps the Anthropic SDK to expose the same interface as OpenAI's
 * `client.chat.completions.create()`, so all existing agent code
 * works unchanged when using Claude models.
 *
 * Supports: messages, tool_calls, tool results, response_format,
 * max_completion_tokens, and the response shape agents expect.
 */

import Anthropic from "@anthropic-ai/sdk";
import type OpenAI from "openai";

// ─── Adapter Class ──────────────────────────────────────────────────────────

export class AnthropicOpenAIAdapter {
  private anthropic: Anthropic;

  chat: {
    completions: {
      create: (params: any) => Promise<any>;
    };
  };

  constructor(opts: { apiKey?: string; timeout?: number; maxRetries?: number }) {
    this.anthropic = new Anthropic({
      apiKey: opts.apiKey || process.env.ANTHROPIC_API_KEY,
      timeout: opts.timeout || 60_000,
      maxRetries: opts.maxRetries || 2,
    });

    // Bind the create method so it can be called as client.chat.completions.create()
    this.chat = {
      completions: {
        create: this.createCompletion.bind(this),
      },
    };
  }

  private async createCompletion(params: any): Promise<any> {
    const {
      model,
      messages,
      tools,
      tool_choice,
      max_completion_tokens,
      max_tokens,
      response_format,
    } = params;

    // Map OpenAI model names to Anthropic model names
    const anthropicModel = mapModel(model);

    // Convert OpenAI messages → Anthropic messages
    const { system, anthropicMessages } = convertMessages(messages);

    // Convert OpenAI tools → Anthropic tools
    const anthropicTools = tools ? convertTools(tools) : undefined;

    // Convert tool_choice
    const anthropicToolChoice = convertToolChoice(tool_choice);

    // Build Anthropic request
    const request: Anthropic.MessageCreateParams = {
      model: anthropicModel,
      max_tokens: max_completion_tokens || max_tokens || 4096,
      messages: anthropicMessages,
    };

    if (system) {
      request.system = system;
    }

    if (anthropicTools && anthropicTools.length > 0) {
      request.tools = anthropicTools;
      if (anthropicToolChoice) {
        request.tool_choice = anthropicToolChoice;
      }
    }

    // response_format: { type: "json_object" } → ask Claude to respond in JSON
    // Anthropic doesn't have a native json_object mode, so we add a system instruction
    if (response_format?.type === "json_object" && !system?.includes("JSON")) {
      request.system = (request.system || "") +
        "\n\nIMPORTANT: You MUST respond with valid JSON only. No markdown, no explanation, just a JSON object.";
    }

    const response = await this.anthropic.messages.create(request);

    // Convert Anthropic response → OpenAI response shape
    return convertResponse(response, anthropicModel);
  }
}

// ─── Message Conversion ─────────────────────────────────────────────────────

function convertMessages(
  messages: any[]
): { system: string | undefined; anthropicMessages: Anthropic.MessageParam[] } {
  let system: string | undefined;
  const anthropicMessages: Anthropic.MessageParam[] = [];

  for (const msg of messages) {
    if (msg.role === "system") {
      // Anthropic uses a top-level system param, not a system message
      system = system ? `${system}\n\n${msg.content}` : msg.content;
      continue;
    }

    if (msg.role === "user") {
      anthropicMessages.push({ role: "user", content: msg.content });
      continue;
    }

    if (msg.role === "assistant") {
      // Assistant message may have tool_calls (OpenAI format)
      if (msg.tool_calls && msg.tool_calls.length > 0) {
        const content: Anthropic.ContentBlockParam[] = [];

        // Include text content if present
        if (msg.content) {
          content.push({ type: "text", text: msg.content });
        }

        // Convert tool_calls → tool_use blocks
        for (const tc of msg.tool_calls) {
          if (tc.type === "function") {
            let input: Record<string, unknown> = {};
            try {
              input = JSON.parse(tc.function.arguments);
            } catch {
              input = {};
            }
            content.push({
              type: "tool_use",
              id: tc.id,
              name: tc.function.name,
              input,
            });
          }
        }

        anthropicMessages.push({ role: "assistant", content });
      } else {
        anthropicMessages.push({
          role: "assistant",
          content: msg.content || "",
        });
      }
      continue;
    }

    if (msg.role === "tool") {
      // OpenAI tool results → Anthropic tool_result content blocks
      // Anthropic expects tool_result blocks inside a user message
      const lastMsg = anthropicMessages[anthropicMessages.length - 1];
      const toolResultBlock: Anthropic.ToolResultBlockParam = {
        type: "tool_result",
        tool_use_id: msg.tool_call_id,
        content: typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content),
      };

      // Multiple tool results should be batched into one user message
      if (lastMsg?.role === "user" && Array.isArray(lastMsg.content)) {
        (lastMsg.content as Anthropic.ContentBlockParam[]).push(toolResultBlock);
      } else {
        anthropicMessages.push({
          role: "user",
          content: [toolResultBlock],
        });
      }
      continue;
    }
  }

  return { system, anthropicMessages };
}

// ─── Tool Conversion ────────────────────────────────────────────────────────

function convertTools(
  tools: OpenAI.ChatCompletionTool[]
): Anthropic.Tool[] {
  return tools
    .filter((t: any) => t.type === "function" && t.function)
    .map((t: any) => ({
      name: t.function.name,
      description: t.function.description || "",
      input_schema: t.function.parameters || { type: "object" as const, properties: {} },
    }));
}

function convertToolChoice(
  toolChoice: any
): Anthropic.MessageCreateParams["tool_choice"] | undefined {
  if (!toolChoice) return undefined;
  if (toolChoice === "auto") return { type: "auto" };
  if (toolChoice === "none") return undefined; // Anthropic doesn't have "none" — just omit tools
  if (toolChoice === "required") return { type: "any" };

  // Forced specific function: { type: "function", function: { name: "xxx" } }
  if (toolChoice?.type === "function" && toolChoice?.function?.name) {
    return { type: "tool", name: toolChoice.function.name };
  }

  return { type: "auto" };
}

// ─── Response Conversion ────────────────────────────────────────────────────

function convertResponse(response: Anthropic.Message, model: string): any {
  let textContent = "";
  const toolCalls: any[] = [];

  for (const block of response.content) {
    if (block.type === "text") {
      textContent += block.text;
    } else if (block.type === "tool_use") {
      toolCalls.push({
        id: block.id,
        type: "function",
        function: {
          name: block.name,
          arguments: JSON.stringify(block.input),
        },
      });
    }
  }

  // Determine finish_reason
  let finishReason: string = "stop";
  if (response.stop_reason === "tool_use") finishReason = "tool_calls";
  else if (response.stop_reason === "max_tokens") finishReason = "length";
  else if (response.stop_reason === "end_turn") finishReason = "stop";

  return {
    id: response.id,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content: textContent || null,
          tool_calls: toolCalls.length > 0 ? toolCalls : undefined,
        },
        finish_reason: finishReason,
      },
    ],
    usage: {
      prompt_tokens: response.usage?.input_tokens || 0,
      completion_tokens: response.usage?.output_tokens || 0,
      total_tokens:
        (response.usage?.input_tokens || 0) +
        (response.usage?.output_tokens || 0),
    },
  };
}

// ─── Model Mapping ──────────────────────────────────────────────────────────

function mapModel(model: string): string {
  const mapping: Record<string, string> = {
    // Allow direct Anthropic model IDs
    "claude-sonnet-4-20250514": "claude-sonnet-4-20250514",
    "claude-haiku-4-5-20251001": "claude-haiku-4-5-20251001",
    "claude-opus-4-6": "claude-opus-4-6",
    // Friendly names
    "claude-sonnet": "claude-sonnet-4-20250514",
    "claude-haiku": "claude-haiku-4-5-20251001",
    "claude-opus": "claude-opus-4-6",
    // Map OpenAI model names to equivalent Claude models
    "gpt-4o": "claude-sonnet-4-20250514",
    "gpt-4o-mini": "claude-haiku-4-5-20251001",
    "gpt-4-turbo": "claude-sonnet-4-20250514",
    "gpt-4": "claude-sonnet-4-20250514",
    "gpt-3.5-turbo": "claude-haiku-4-5-20251001",
  };

  return mapping[model] || model;
}
