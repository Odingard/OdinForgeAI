import { describe, it, expect } from "vitest";
import {
  ReachabilityChainBuilder,
  buildReachabilityChain,
  PivotResult,
} from "./reachability-chain";

function makePivot(overrides: Partial<PivotResult> = {}): PivotResult {
  return {
    host: "10.0.0.10",
    depth: 1,
    technique: "smb_pivot",
    authResult: "success",
    accessLevel: "admin",
    credentialUsed: "cred-001",
    port: 445,
    protocol: "smb",
    timestamp: "2026-03-12T00:00:00.000Z",
    ...overrides,
  };
}

describe("ReachabilityChainBuilder", () => {
  it("adds a successful node and returns its ID", () => {
    const builder = new ReachabilityChainBuilder();
    const id = builder.addNode(makePivot());
    expect(id).toBe("10.0.0.10:445");
    expect(builder.getNodeCount()).toBe(1);
  });

  it("returns null and skips unreachable nodes", () => {
    const builder = new ReachabilityChainBuilder();
    const id = builder.addNode(makePivot({ authResult: "unreachable" }));
    expect(id).toBeNull();
    expect(builder.getNodeCount()).toBe(0);
  });

  it("adds edges that update reachableFrom on the target node", () => {
    const builder = new ReachabilityChainBuilder();
    const fromId = builder.addNode(makePivot({ host: "10.0.0.1", port: 445 }))!;
    const toId = builder.addNode(makePivot({ host: "10.0.0.2", port: 445 }))!;

    builder.addEdge(fromId, toId, "cred-001", "smb");

    const chain = builder.build("eng-1", "entry.example.com");
    const targetNode = chain.nodes.find(n => n.id === toId);
    expect(targetNode).toBeDefined();
    expect(targetNode!.reachableFrom).toContain(fromId);
  });

  it("builds a valid chain with DOT and JSON graph output", () => {
    const builder = new ReachabilityChainBuilder();
    builder.addNode(makePivot({ host: "10.0.0.1" }));
    builder.addNode(makePivot({ host: "10.0.0.2", depth: 2 }));

    const chain = builder.build("eng-1", "entry.example.com");

    expect(chain.engagementId).toBe("eng-1");
    expect(chain.nodes).toHaveLength(2);
    expect(chain.blastRadius).toBe(2);
    expect(chain.totalProvenHops).toBe(2);
    expect(chain.generatedAt).toBeDefined();
  });

  it("produces DOT output containing digraph BreachChain", () => {
    const builder = new ReachabilityChainBuilder();
    builder.addNode(makePivot());

    const chain = builder.build("eng-1", "entry.example.com");
    expect(chain.graphFormat.dot).toContain("digraph BreachChain");
    expect(chain.graphFormat.dot).toContain("10.0.0.10:445");
  });

  it("produces D3 JSON with nodes and links arrays", () => {
    const builder = new ReachabilityChainBuilder();
    builder.addNode(makePivot({ host: "10.0.0.1" }));
    builder.addNode(makePivot({ host: "10.0.0.2" }));
    const from = "10.0.0.1:445";
    const to = "10.0.0.2:445";
    builder.addEdge(from, to, "cred-001", "smb");

    const chain = builder.build("eng-1", "entry.example.com");
    const d3 = JSON.parse(chain.graphFormat.json);
    expect(Array.isArray(d3.nodes)).toBe(true);
    expect(Array.isArray(d3.links)).toBe(true);
    expect(d3.nodes).toHaveLength(2);
    expect(d3.links).toHaveLength(1);
  });

  it("merges credentials when the same host:port is added twice", () => {
    const builder = new ReachabilityChainBuilder();
    builder.addNode(makePivot({ host: "10.0.0.5", port: 445, credentialUsed: "cred-A" }));
    builder.addNode(makePivot({ host: "10.0.0.5", port: 445, credentialUsed: "cred-B" }));

    expect(builder.getNodeCount()).toBe(1);
    const chain = builder.build("eng-1", "entry.example.com");
    const node = chain.nodes.find(n => n.id === "10.0.0.5:445");
    expect(node!.reachableVia).toContain("cred-A");
    expect(node!.reachableVia).toContain("cred-B");
  });

  it("builds a valid chain from the convenience function", () => {
    const pivots: PivotResult[] = [
      makePivot({ host: "10.0.0.1", depth: 1 }),
      makePivot({ host: "10.0.0.2", depth: 2, authResult: "unreachable" }),
      makePivot({ host: "10.0.0.3", depth: 2 }),
    ];

    const chain = buildReachabilityChain("eng-conv", "entry.example.com", pivots);
    expect(chain.engagementId).toBe("eng-conv");
    // Only 2 successful pivots added (10.0.0.2 was unreachable)
    expect(chain.nodes).toHaveLength(2);
    expect(chain.blastRadius).toBe(2);
  });

  it("produces a valid chain with 0 nodes when given empty results", () => {
    const chain = buildReachabilityChain("eng-empty", "entry.example.com", []);
    expect(chain.nodes).toHaveLength(0);
    expect(chain.blastRadius).toBe(0);
    expect(chain.graphFormat.dot).toContain("digraph BreachChain");
  });
});
