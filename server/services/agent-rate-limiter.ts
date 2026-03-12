/**
 * Token-bucket rate limiter for target HTTP requests.
 * Shared across all parallel agents hitting the same target
 * to prevent overwhelming targets during parallel dispatch.
 */

export class TargetRateLimiter {
  private tokens: number;
  private readonly maxTokens: number;
  private readonly refillInterval: number; // ms between refills
  private waitQueue: Array<() => void> = [];
  private refillTimer: ReturnType<typeof setInterval> | null = null;

  /**
   * @param requestsPerSecond Max requests per second to the target (default 50)
   */
  constructor(requestsPerSecond: number = 50) {
    if (requestsPerSecond <= 0) {
      throw new Error(`[RateLimiter] requestsPerSecond must be > 0, got ${requestsPerSecond}`);
    }
    this.maxTokens = requestsPerSecond;
    this.tokens = requestsPerSecond;
    // Refill one token every (1000 / rps) ms
    this.refillInterval = Math.max(1, Math.floor(1000 / requestsPerSecond));
    this.startRefill();
  }

  /**
   * Acquire a token. Resolves immediately if tokens available,
   * otherwise queues until a token is refilled.
   */
  async acquire(): Promise<void> {
    if (this.tokens > 0) {
      this.tokens--;
      return;
    }
    return new Promise<void>((resolve) => {
      this.waitQueue.push(resolve);
    });
  }

  /**
   * Stop the refill timer. Call this when the scan is complete
   * to prevent leaked timers.
   */
  destroy(): void {
    if (this.refillTimer !== null) {
      clearInterval(this.refillTimer);
      this.refillTimer = null;
    }
    // Release any remaining waiters
    for (const waiter of this.waitQueue) {
      waiter();
    }
    this.waitQueue = [];
  }

  /** Current available tokens */
  get available(): number {
    return this.tokens;
  }

  /** Number of requests waiting for a token */
  get waiting(): number {
    return this.waitQueue.length;
  }

  private startRefill(): void {
    this.refillTimer = setInterval(() => {
      if (this.waitQueue.length > 0) {
        // Give token directly to next waiter
        const next = this.waitQueue.shift()!;
        next();
      } else if (this.tokens < this.maxTokens) {
        this.tokens++;
      }
    }, this.refillInterval);

    // Don't prevent process exit
    if (this.refillTimer && typeof this.refillTimer === "object" && "unref" in this.refillTimer) {
      this.refillTimer.unref();
    }
  }
}

/**
 * Registry of rate limiters by target hostname.
 * Ensures all agents hitting the same target share a limiter.
 */
const limiterRegistry = new Map<string, TargetRateLimiter>();

export function getRateLimiterForTarget(
  targetUrl: string,
  requestsPerSecond: number = 50
): TargetRateLimiter {
  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    hostname = targetUrl;
  }

  let limiter = limiterRegistry.get(hostname);
  if (!limiter) {
    limiter = new TargetRateLimiter(requestsPerSecond);
    limiterRegistry.set(hostname, limiter);
  }
  return limiter;
}

export function destroyAllRateLimiters(): void {
  Array.from(limiterRegistry.values()).forEach(limiter => limiter.destroy());
  limiterRegistry.clear();
}
