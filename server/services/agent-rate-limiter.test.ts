import { describe, it, expect, afterEach } from "vitest";
import { TargetRateLimiter, getRateLimiterForTarget, destroyAllRateLimiters } from "./agent-rate-limiter";

afterEach(() => {
  destroyAllRateLimiters();
});

describe("TargetRateLimiter", () => {
  it("allows immediate acquire when tokens available", async () => {
    const limiter = new TargetRateLimiter(10);
    expect(limiter.available).toBe(10);
    await limiter.acquire();
    expect(limiter.available).toBe(9);
    limiter.destroy();
  });

  it("throttles when tokens exhausted", async () => {
    const limiter = new TargetRateLimiter(2);
    await limiter.acquire();
    await limiter.acquire();
    expect(limiter.available).toBe(0);

    let acquired = false;
    const blocked = limiter.acquire().then(() => {
      acquired = true;
    });

    // Should not resolve synchronously
    await Promise.resolve();
    expect(acquired).toBe(false);
    expect(limiter.waiting).toBe(1);

    // Wait for refill (at 2/sec = 500ms interval)
    await new Promise(r => setTimeout(r, 600));
    expect(acquired).toBe(true);
    limiter.destroy();
  });

  it("throws on invalid requestsPerSecond", () => {
    expect(() => new TargetRateLimiter(0)).toThrow("must be > 0");
    expect(() => new TargetRateLimiter(-5)).toThrow("must be > 0");
  });

  it("destroy releases all waiters", async () => {
    const limiter = new TargetRateLimiter(1);
    await limiter.acquire();

    let released = false;
    limiter.acquire().then(() => {
      released = true;
    });

    limiter.destroy();
    // Allow microtask queue to flush
    await new Promise(r => setTimeout(r, 10));
    expect(released).toBe(true);
  });
});

describe("getRateLimiterForTarget", () => {
  it("returns same limiter for same hostname", () => {
    const a = getRateLimiterForTarget("https://example.com/api/users");
    const b = getRateLimiterForTarget("https://example.com/other/path");
    expect(a).toBe(b);
  });

  it("returns different limiter for different hostnames", () => {
    const a = getRateLimiterForTarget("https://example.com/api");
    const b = getRateLimiterForTarget("https://other.com/api");
    expect(a).not.toBe(b);
  });
});
