/**
 * pivot-queue.test.ts
 *
 * Tests for PivotQueue BFS multi-hop orchestrator and breachCredToHarvested (Fix 4).
 * Uses a synchronous mock worker — no network, no lateral-movement-service calls.
 */

import { describe, it, expect, vi } from "vitest";
import { PivotQueue, breachCredToHarvested, type PivotNodeResult, type PivotQueueItem } from "./pivot-queue";
import type { HarvestedCredential } from "../credential-store";
import type { BreachCredential } from "@shared/schema";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeCred(overrides: Partial<HarvestedCredential> = {}): HarvestedCredential {
  return {
    id: "cred-test",
    type: "password",
    displayValue: "pass***word",
    authValue: "iv:cipher:tag",
    source: "test",
    context: "test",
    timestamp: new Date(),
    usedBy: [],
    hash: "abc123",
    accessLevel: "admin",
    ...overrides,
  };
}

function emptyResult(host: string, depth: number): PivotNodeResult {
  return {
    host,
    depth,
    discoveredBy: "worker",
    newCredentials: [],
    discoveredHosts: [],
    findings: [],
    durationMs: 1,
  };
}

// ─── PivotQueue: enqueue / visited dedup ─────────────────────────────────────

describe("PivotQueue.enqueue", () => {
  it("adds a host to the visited set", () => {
    const q = new PivotQueue();
    q.enqueue("host-a", 0, "seed");
    expect(q.getVisited()).toContain("host-a");
  });

  it("ignores duplicate hosts", () => {
    const q = new PivotQueue();
    q.enqueue("host-a", 0, "seed");
    q.enqueue("host-a", 0, "seed");
    expect(q.getVisited()).toHaveLength(1);
  });

  it("ignores empty string host", () => {
    const q = new PivotQueue();
    q.enqueue("", 0, "seed");
    expect(q.getVisited()).toHaveLength(0);
  });

  it("respects maxDepth — does not enqueue beyond limit", () => {
    const q = new PivotQueue(2);
    q.enqueue("h1", 0, "seed");
    q.enqueue("h2", 2, "seed");
    q.enqueue("h3", 3, "seed"); // beyond maxDepth=2 — should be ignored
    expect(q.getVisited()).not.toContain("h3");
  });
});

// ─── PivotQueue: credential store ────────────────────────────────────────────

describe("PivotQueue.addCredential", () => {
  it("stores a credential", () => {
    const q = new PivotQueue();
    q.addCredential(makeCred({ hash: "hash1" }));
    expect(q.getCredentialCount()).toBe(1);
  });

  it("deduplicates by hash", () => {
    const q = new PivotQueue();
    q.addCredential(makeCred({ hash: "same" }));
    q.addCredential(makeCred({ hash: "same" }));
    expect(q.getCredentialCount()).toBe(1);
  });

  it("accepts multiple distinct credentials", () => {
    const q = new PivotQueue();
    q.addCredential(makeCred({ hash: "h1" }));
    q.addCredential(makeCred({ hash: "h2" }));
    q.addCredential(makeCred({ hash: "h3" }));
    expect(q.getCredentialCount()).toBe(3);
  });
});

// ─── PivotQueue: credential snapshot ─────────────────────────────────────────

describe("PivotQueue credential snapshot", () => {
  it("snapshot at enqueue time contains only credentials added before enqueue", async () => {
    const q = new PivotQueue();
    const credBefore = makeCred({ hash: "before" });
    q.addCredential(credBefore);

    let capturedSnapshot: HarvestedCredential[] = [];
    q.enqueue("host-a", 0, "seed");

    // Add another credential AFTER enqueue
    q.addCredential(makeCred({ hash: "after" }));

    await q.drain(async (item) => {
      capturedSnapshot = item.credentialSnapshot;
      return emptyResult(item.host, item.depth);
    });

    expect(capturedSnapshot.map(c => c.hash)).toContain("before");
    expect(capturedSnapshot.map(c => c.hash)).not.toContain("after");
  });
});

// ─── PivotQueue: drain ───────────────────────────────────────────────────────

describe("PivotQueue.drain", () => {
  it("processes all seeded hosts", async () => {
    const q = new PivotQueue();
    q.enqueue("a.example.com", 0, "seed");
    q.enqueue("b.example.com", 0, "seed");

    const visited: string[] = [];
    await q.drain(async (item) => {
      visited.push(item.host);
      return emptyResult(item.host, item.depth);
    });

    expect(visited).toContain("a.example.com");
    expect(visited).toContain("b.example.com");
  });

  it("enqueues discovered hosts for next depth", async () => {
    const q = new PivotQueue(3);
    q.enqueue("root.host", 0, "seed");

    const visitOrder: string[] = [];
    await q.drain(async (item) => {
      visitOrder.push(item.host);
      return {
        ...emptyResult(item.host, item.depth),
        discoveredHosts: item.depth === 0 ? ["child.host"] : [],
      };
    });

    expect(visitOrder).toContain("root.host");
    expect(visitOrder).toContain("child.host");
  });

  it("does not revisit a host discovered at multiple hops", async () => {
    const q = new PivotQueue(3);
    q.enqueue("root", 0, "seed");

    const callCount = new Map<string, number>();
    await q.drain(async (item) => {
      callCount.set(item.host, (callCount.get(item.host) || 0) + 1);
      return {
        ...emptyResult(item.host, item.depth),
        // Both hops try to discover the same child
        discoveredHosts: ["shared.child"],
      };
    });

    expect(callCount.get("shared.child")).toBe(1);
  });

  it("propagates new credentials to later-depth items", async () => {
    const q = new PivotQueue(2);
    q.enqueue("depth0.host", 0, "seed");

    const harvestedAtDepth1 = makeCred({ hash: "new-cred-from-depth0" });
    const snapshotsAtDepth1: HarvestedCredential[][] = [];

    await q.drain(async (item) => {
      if (item.depth === 1) {
        snapshotsAtDepth1.push(item.credentialSnapshot);
      }
      return {
        ...emptyResult(item.host, item.depth),
        newCredentials: item.depth === 0 ? [harvestedAtDepth1] : [],
        discoveredHosts: item.depth === 0 ? ["depth1.host"] : [],
      };
    });

    expect(snapshotsAtDepth1.length).toBeGreaterThan(0);
    expect(snapshotsAtDepth1[0].map(c => c.hash)).toContain("new-cred-from-depth0");
  });

  it("calls onProgress for each item", async () => {
    const q = new PivotQueue();
    q.enqueue("h1", 0, "seed");
    q.enqueue("h2", 0, "seed");

    const progressCalls: number[] = [];
    await q.drain(
      async (item) => emptyResult(item.host, item.depth),
      (msg, depth) => progressCalls.push(depth)
    );

    expect(progressCalls).toHaveLength(2);
  });

  it("returns all results after drain", async () => {
    const q = new PivotQueue();
    q.enqueue("alpha", 0, "seed");
    q.enqueue("beta", 0, "seed");

    const results = await q.drain(async (item) => emptyResult(item.host, item.depth));
    expect(results.map(r => r.host)).toEqual(expect.arrayContaining(["alpha", "beta"]));
  });

  it("returns empty array when queue is empty", async () => {
    const q = new PivotQueue();
    const results = await q.drain(async (item) => emptyResult(item.host, item.depth));
    expect(results).toEqual([]);
  });
});

// ─── breachCredToHarvested ────────────────────────────────────────────────────

describe("breachCredToHarvested", () => {
  const bc: BreachCredential = {
    id: "bc-001",
    type: "password",
    username: "admin",
    domain: "corp.local",
    valueHash: "deadbeef12345678",
    authValue: "iv:cipher:tag",
    source: "credential_extraction",
    accessLevel: "admin",
    validatedTargets: ["10.0.0.5"],
    discoveredAt: "2026-03-11T00:00:00Z",
  };

  it("maps id correctly", () => {
    expect(breachCredToHarvested(bc).id).toBe("bc-001");
  });

  it("maps type correctly", () => {
    expect(breachCredToHarvested(bc).type).toBe("password");
  });

  it("maps username and domain", () => {
    const hc = breachCredToHarvested(bc);
    expect(hc.username).toBe("admin");
    expect(hc.domain).toBe("corp.local");
  });

  it("prefers authValue over valueHash for authValue field", () => {
    expect(breachCredToHarvested(bc).authValue).toBe("iv:cipher:tag");
  });

  it("falls back to valueHash when authValue is absent", () => {
    const bcNoAuth: BreachCredential = { ...bc, authValue: undefined };
    expect(breachCredToHarvested(bcNoAuth).authValue).toBe("deadbeef12345678");
  });

  it("uses valueHash as hash for dedup", () => {
    expect(breachCredToHarvested(bc).hash).toBe("deadbeef12345678");
  });

  it("maps cloud_admin accessLevel → admin", () => {
    const bcCloud: BreachCredential = { ...bc, accessLevel: "cloud_admin" };
    expect(breachCredToHarvested(bcCloud).accessLevel).toBe("admin");
  });

  it("passes through admin accessLevel unchanged", () => {
    expect(breachCredToHarvested(bc).accessLevel).toBe("admin");
  });

  it("displayValue is masked (contains ***)", () => {
    expect(breachCredToHarvested(bc).displayValue).toContain("***");
  });
});
