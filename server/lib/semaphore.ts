/**
 * Counting semaphore for concurrency control.
 * Used by MicroAgentOrchestrator to gate parallel agent execution.
 */
export class Semaphore {
  private queue: Array<() => void> = [];
  private count: number;

  constructor(private max: number) {
    if (max <= 0) throw new Error(`[Semaphore] max must be > 0, got ${max}`);
    this.count = max;
  }

  /**
   * Acquire a permit. Resolves immediately if permits are available,
   * otherwise queues the caller until a permit is released.
   */
  async acquire(): Promise<void> {
    if (this.count > 0) {
      this.count--;
      return;
    }
    await new Promise<void>((resolve) => this.queue.push(resolve));
  }

  /**
   * Release a permit. If callers are queued, the next one is unblocked.
   */
  release(): void {
    if (this.queue.length > 0) {
      const next = this.queue.shift()!;
      next();
    } else {
      this.count++;
    }
  }

  /** Current number of available permits */
  get available(): number {
    return this.count;
  }

  /** Number of callers waiting for a permit */
  get waiting(): number {
    return this.queue.length;
  }
}
