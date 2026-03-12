import { describe, it, expect } from "vitest";
import { Semaphore } from "./semaphore";

describe("Semaphore", () => {
  it("allows immediate acquire when permits available", async () => {
    const sem = new Semaphore(3);
    expect(sem.available).toBe(3);
    await sem.acquire();
    expect(sem.available).toBe(2);
    await sem.acquire();
    expect(sem.available).toBe(1);
    await sem.acquire();
    expect(sem.available).toBe(0);
  });

  it("blocks when all permits exhausted", async () => {
    const sem = new Semaphore(1);
    await sem.acquire();
    expect(sem.available).toBe(0);

    let acquired = false;
    const blocked = sem.acquire().then(() => {
      acquired = true;
    });

    // Should not resolve synchronously
    await Promise.resolve();
    expect(acquired).toBe(false);
    expect(sem.waiting).toBe(1);

    // Release unblocks the waiter
    sem.release();
    await blocked;
    expect(acquired).toBe(true);
    expect(sem.waiting).toBe(0);
  });

  it("processes waiters in FIFO order", async () => {
    const sem = new Semaphore(1);
    await sem.acquire();

    const order: number[] = [];
    const p1 = sem.acquire().then(() => order.push(1));
    const p2 = sem.acquire().then(() => order.push(2));
    const p3 = sem.acquire().then(() => order.push(3));

    expect(sem.waiting).toBe(3);

    sem.release();
    await p1;
    sem.release();
    await p2;
    sem.release();
    await p3;

    expect(order).toEqual([1, 2, 3]);
  });

  it("release without waiters restores permit count", () => {
    const sem = new Semaphore(2);
    expect(sem.available).toBe(2);
    sem.release();
    expect(sem.available).toBe(3);
  });

  it("throws on invalid max", () => {
    expect(() => new Semaphore(0)).toThrow("max must be > 0");
    expect(() => new Semaphore(-5)).toThrow("max must be > 0");
  });

  it("handles concurrent acquire/release under load", async () => {
    const sem = new Semaphore(5);
    let maxConcurrent = 0;
    let currentConcurrent = 0;

    const tasks = Array.from({ length: 20 }, async (_, i) => {
      await sem.acquire();
      currentConcurrent++;
      maxConcurrent = Math.max(maxConcurrent, currentConcurrent);
      // Simulate brief async work
      await new Promise((r) => setTimeout(r, 5));
      currentConcurrent--;
      sem.release();
      return i;
    });

    const results = await Promise.all(tasks);
    expect(results).toHaveLength(20);
    expect(maxConcurrent).toBeLessThanOrEqual(5);
  });
});
