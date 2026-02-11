import OpenAI from "openai";

const OPENAI_TIMEOUT_MS = 30000; // 30 second timeout to prevent hanging

function getOpenAIApiKey(): string | undefined {
  return process.env.AI_INTEGRATIONS_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
}

function getOpenAIBaseURL(): string | undefined {
  return process.env.AI_INTEGRATIONS_OPENAI_BASE_URL || undefined;
}

export const openai = new OpenAI({
  apiKey: getOpenAIApiKey(),
  baseURL: getOpenAIBaseURL(),
  timeout: OPENAI_TIMEOUT_MS,
  maxRetries: 2,
});

export { OPENAI_TIMEOUT_MS };
