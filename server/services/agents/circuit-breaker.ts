/**
 * Circuit Breaker for LLM Provider Calls
 *
 * Prevents cascading failures when LLM providers (OpenAI, OpenRouter) are down
 * or slow. After FAILURE_THRESHOLD consecutive failures, the circuit opens and
 * all calls immediately return fallback results for RESET_TIMEOUT_MS.
 */

type CircuitState = "closed" | "open" | "half_open";

interface ProviderCircuit {
  state: CircuitState;
  failureCount: number;
  lastFailureTime: number;
  lastSuccessTime: number;
}

const FAILURE_THRESHOLD = 2;
const RESET_TIMEOUT_MS = 60_000; // 60s before allowing a test call

const circuits = new Map<string, ProviderCircuit>();

function getCircuit(provider: string): ProviderCircuit {
  if (!circuits.has(provider)) {
    circuits.set(provider, {
      state: "closed",
      failureCount: 0,
      lastFailureTime: 0,
      lastSuccessTime: 0,
    });
  }
  return circuits.get(provider)!;
}

function recordSuccess(provider: string): void {
  const circuit = getCircuit(provider);
  circuit.state = "closed";
  circuit.failureCount = 0;
  circuit.lastSuccessTime = Date.now();
}

function recordFailure(provider: string): void {
  const circuit = getCircuit(provider);
  circuit.failureCount++;
  circuit.lastFailureTime = Date.now();
  if (circuit.failureCount >= FAILURE_THRESHOLD) {
    circuit.state = "open";
    console.warn(`[CircuitBreaker] Circuit OPEN for provider "${provider}" after ${circuit.failureCount} failures`);
  }
}

export function isCircuitOpen(provider: string): boolean {
  const circuit = getCircuit(provider);
  if (circuit.state === "closed") return false;
  if (circuit.state === "open") {
    // Check if enough time has passed to try half-open
    if (Date.now() - circuit.lastFailureTime >= RESET_TIMEOUT_MS) {
      circuit.state = "half_open";
      return false; // Allow one test call
    }
    return true;
  }
  // half_open — allow the call
  return false;
}

export function resetCircuit(provider: string): void {
  circuits.delete(provider);
}

/**
 * Execute an LLM function with circuit breaker protection.
 * If the circuit is open, immediately returns fallbackFn result.
 * If the call fails or times out, returns fallbackFn result and records failure.
 */
export async function withCircuitBreaker<T>(
  provider: string,
  llmFn: () => Promise<T>,
  fallbackFn: () => T,
  timeoutMs: number = 30_000
): Promise<T> {
  if (isCircuitOpen(provider)) {
    console.log(`[CircuitBreaker] Circuit open for "${provider}", using fallback`);
    return fallbackFn();
  }

  try {
    const result = await Promise.race([
      llmFn(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`Circuit breaker timeout: ${timeoutMs}ms`)), timeoutMs)
      ),
    ]);
    recordSuccess(provider);
    return result;
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.warn(`[CircuitBreaker] Provider "${provider}" failed: ${msg}`);
    recordFailure(provider);
    return fallbackFn();
  }
}
