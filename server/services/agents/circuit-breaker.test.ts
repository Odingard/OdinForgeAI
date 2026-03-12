import { describe, it, expect, beforeEach } from "vitest";
import {
  withCircuitBreaker,
  isCircuitOpen,
  resetCircuit,
} from "./circuit-breaker";

const PROVIDER = "test-provider";

beforeEach(() => {
  resetCircuit(PROVIDER);
});

describe("circuit-breaker", () => {
  describe("isCircuitOpen", () => {
    it("returns false for a fresh provider (circuit closed)", () => {
      expect(isCircuitOpen(PROVIDER)).toBe(false);
    });
  });

  describe("withCircuitBreaker", () => {
    it("returns LLM function result when circuit is closed", async () => {
      const result = await withCircuitBreaker(
        PROVIDER,
        async () => "llm-result",
        () => "fallback-result",
      );
      expect(result).toBe("llm-result");
    });

    it("returns fallback after 2 consecutive failures (circuit opens)", async () => {
      // Failure 1
      await withCircuitBreaker(
        PROVIDER,
        async () => { throw new Error("API down"); },
        () => "fallback-1",
      );

      // Failure 2 — circuit should open
      await withCircuitBreaker(
        PROVIDER,
        async () => { throw new Error("API down"); },
        () => "fallback-2",
      );

      // Circuit should now be open
      expect(isCircuitOpen(PROVIDER)).toBe(true);

      // Next call should return fallback immediately (no LLM call)
      let llmCalled = false;
      const result = await withCircuitBreaker(
        PROVIDER,
        async () => { llmCalled = true; return "should-not-see"; },
        () => "circuit-open-fallback",
      );
      expect(result).toBe("circuit-open-fallback");
      expect(llmCalled).toBe(false);
    });

    it("resets failure count after a success", async () => {
      // Failure 1
      await withCircuitBreaker(
        PROVIDER,
        async () => { throw new Error("fail"); },
        () => "fb",
      );

      // Success — resets count
      await withCircuitBreaker(
        PROVIDER,
        async () => "ok",
        () => "fb",
      );

      // Failure 1 again (count reset)
      await withCircuitBreaker(
        PROVIDER,
        async () => { throw new Error("fail"); },
        () => "fb",
      );

      // Circuit should still be closed (only 1 failure since reset)
      expect(isCircuitOpen(PROVIDER)).toBe(false);
    });

    it("returns fallback on timeout", async () => {
      const result = await withCircuitBreaker(
        PROVIDER,
        () => new Promise(resolve => setTimeout(() => resolve("slow"), 10000)),
        () => "timeout-fallback",
        50, // very short timeout
      );
      expect(result).toBe("timeout-fallback");
    });

    it("handles different providers independently", async () => {
      // Open circuit for provider A
      await withCircuitBreaker("A", async () => { throw new Error("fail"); }, () => "fb");
      await withCircuitBreaker("A", async () => { throw new Error("fail"); }, () => "fb");
      expect(isCircuitOpen("A")).toBe(true);

      // Provider B should still be closed
      expect(isCircuitOpen("B")).toBe(false);

      resetCircuit("A");
      resetCircuit("B");
    });
  });

  describe("resetCircuit", () => {
    it("resets an open circuit to closed", async () => {
      await withCircuitBreaker(PROVIDER, async () => { throw new Error("fail"); }, () => "fb");
      await withCircuitBreaker(PROVIDER, async () => { throw new Error("fail"); }, () => "fb");
      expect(isCircuitOpen(PROVIDER)).toBe(true);

      resetCircuit(PROVIDER);
      expect(isCircuitOpen(PROVIDER)).toBe(false);
    });
  });
});
