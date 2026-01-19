/**
 * OpenAI Error Classifier
 * Provides human-readable error messages for common OpenAI API errors
 */

export function classifyOpenAIError(error: unknown): string {
  if (error instanceof Error) {
    const message = error.message.toLowerCase();
    const name = error.name?.toLowerCase() || '';
    
    // Timeout errors
    if (message.includes('timeout') || message.includes('timed out') || name.includes('timeout')) {
      return 'AI service timeout - the request took too long to complete. Please try again.';
    }
    
    // Rate limiting
    if (message.includes('rate limit') || message.includes('429') || message.includes('too many requests')) {
      return 'AI service rate limited - too many requests. Please wait a moment and try again.';
    }
    
    // Authentication errors
    if (message.includes('api key') || message.includes('authentication') || message.includes('401') || message.includes('unauthorized')) {
      return 'AI service authentication error - please check API key configuration.';
    }
    
    // Network errors
    if (message.includes('network') || message.includes('econnrefused') || message.includes('fetch failed') || 
        message.includes('enotfound') || message.includes('connection refused')) {
      return 'Network error connecting to AI service. Please check your connection.';
    }
    
    // Server errors
    if (message.includes('500') || message.includes('502') || message.includes('503') || message.includes('504') ||
        message.includes('internal server error') || message.includes('bad gateway') || message.includes('service unavailable')) {
      return 'AI service temporarily unavailable. Please try again later.';
    }
    
    // Quota exceeded
    if (message.includes('quota') || message.includes('insufficient_quota') || message.includes('billing')) {
      return 'AI service quota exceeded - please check your billing and usage limits.';
    }
    
    // Context length errors
    if (message.includes('context_length') || message.includes('maximum context length') || message.includes('too many tokens')) {
      return 'Input too large for AI processing - try with a smaller dataset.';
    }
    
    // Return the original message if no pattern matched
    return error.message;
  }
  
  return 'Unknown error occurred';
}

export function wrapAgentError(agentName: string, error: unknown): Error {
  const classifiedMessage = classifyOpenAIError(error);
  console.error(`[${agentName}] Error:`, classifiedMessage, error);
  return new Error(`${agentName} failed: ${classifiedMessage}`);
}
