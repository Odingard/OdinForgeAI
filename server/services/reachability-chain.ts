/**
 * Reachability Chain Analysis
 *
 * Transforms Phase 5 lateral movement output from a list of hosts into
 * a network kill chain graph — every hop proven by real authentication,
 * every path traceable back to the original entry point.
 *
 * Outputs:
 *   - Graphviz DOT format (rendered in PDF reports)
 *   - D3.js-compatible JSON (rendered in web UI)
 *   - Tabular hop-by-hop breakdown
 *   - Blast radius assessment
 */

import { randomUUID } from "crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ReachabilityNode {
  id: string;
  host: string;
  port: number;
  service: string;
  protocol: string;
  depth: number;
  provenByRealAuth: boolean;
  reachableFrom: string[];
  reachableVia: string[];
  firstReachedAt: string;
  accessLevel: string;
  capturedOutput?: string;
}

export interface ReachabilityEdge {
  from: string;
  to: string;
  credentialId: string;
  protocol: string;
  timestamp: string;
}

export interface ReachabilityChain {
  engagementId: string;
  entryPoint: ReachabilityNode;
  nodes: ReachabilityNode[];
  edges: ReachabilityEdge[];
  deepestNode: ReachabilityNode;
  totalProvenHops: number;
  longestPath: string[];
  blastRadius: number;
  graphFormat: {
    dot: string;
    json: string;
  };
  generatedAt: string;
}

/** Compatible with PivotFinding from pivot-queue.ts */
export interface PivotResult {
  host: string;
  depth: number;
  technique: string;
  authResult: "success" | "invalid_credential" | "account_restricted" | "unreachable" | "error" | "no_credential";
  accessLevel: string;
  credentialUsed?: string;
  capturedOutput?: string;
  evidence?: string;
  port?: number;
  protocol?: string;
  timestamp?: string;
}

// ─── Reachability Chain Builder ───────────────────────────────────────────────

export class ReachabilityChainBuilder {
  private nodes: Map<string, ReachabilityNode> = new Map();
  private edges: ReachabilityEdge[] = [];

  /**
   * Add a node from a pivot result. Only successful auth results enter the graph.
   * Returns the node ID if added, null if skipped.
   */
  addNode(pivotResult: PivotResult): string | null {
    if (pivotResult.authResult !== "success") return null;

    const port = pivotResult.port || this.inferPort(pivotResult.protocol || pivotResult.technique);
    const id = `${pivotResult.host}:${port}`;

    if (this.nodes.has(id)) {
      // Update existing node with additional credential paths
      const existing = this.nodes.get(id)!;
      if (pivotResult.credentialUsed && !existing.reachableVia.includes(pivotResult.credentialUsed)) {
        existing.reachableVia.push(pivotResult.credentialUsed);
      }
      return id;
    }

    const node: ReachabilityNode = {
      id,
      host: pivotResult.host,
      port,
      service: pivotResult.protocol || pivotResult.technique || "unknown",
      protocol: pivotResult.protocol || pivotResult.technique || "unknown",
      depth: pivotResult.depth,
      provenByRealAuth: true,
      reachableFrom: [],
      reachableVia: pivotResult.credentialUsed ? [pivotResult.credentialUsed] : [],
      firstReachedAt: pivotResult.timestamp || new Date().toISOString(),
      accessLevel: pivotResult.accessLevel || "unknown",
      capturedOutput: pivotResult.capturedOutput,
    };

    this.nodes.set(id, node);
    return id;
  }

  /**
   * Add an edge linking two nodes in the graph.
   */
  addEdge(fromNodeId: string, toNodeId: string, credentialId: string, protocol: string): void {
    this.edges.push({
      from: fromNodeId,
      to: toNodeId,
      credentialId,
      protocol,
      timestamp: new Date().toISOString(),
    });

    const toNode = this.nodes.get(toNodeId);
    if (toNode && !toNode.reachableFrom.includes(fromNodeId)) {
      toNode.reachableFrom.push(fromNodeId);
    }
  }

  /**
   * Build the final ReachabilityChain from all collected nodes and edges.
   */
  build(engagementId: string, entryPointHost: string): ReachabilityChain {
    const allNodes = Array.from(this.nodes.values());

    // Create entry point node (depth 0)
    const entryPort = 443;
    const entryId = `${entryPointHost}:${entryPort}`;
    const entryNode: ReachabilityNode = this.nodes.get(entryId) || {
      id: entryId,
      host: entryPointHost,
      port: entryPort,
      service: "https",
      protocol: "https",
      depth: 0,
      provenByRealAuth: true,
      reachableFrom: [],
      reachableVia: [],
      firstReachedAt: new Date().toISOString(),
      accessLevel: "initial",
    };

    // Find deepest node
    const deepestNode = allNodes.length > 0
      ? allNodes.reduce((a, b) => a.depth > b.depth ? a : b)
      : entryNode;

    // Compute longest path
    const longestPath = this.computeLongestPath(entryId);

    const chain: ReachabilityChain = {
      engagementId,
      entryPoint: entryNode,
      nodes: allNodes,
      edges: this.edges,
      deepestNode,
      totalProvenHops: allNodes.filter(n => n.provenByRealAuth).length,
      longestPath,
      blastRadius: allNodes.length,
      graphFormat: {
        dot: this.toDOT(allNodes),
        json: this.toGraphJSON(allNodes),
      },
      generatedAt: new Date().toISOString(),
    };

    return chain;
  }

  /**
   * Get current node count.
   */
  getNodeCount(): number {
    return this.nodes.size;
  }

  // ── Graphviz DOT Output ─────────────────────────────────────────────────

  private toDOT(nodes: ReachabilityNode[]): string {
    const lines: string[] = [
      "digraph BreachChain {",
      "  rankdir=LR;",
      "  bgcolor=\"#0d0d1a\";",
      '  node [shape=box, style="filled,rounded", fillcolor="#1e1e2e", fontcolor="#a78bfa", fontname="Consolas", penwidth=2, color="#4c4c6d"];',
      '  edge [color="#6366f1", fontcolor="#94a3b8", fontname="Consolas", fontsize=10];',
      "",
    ];

    for (const n of nodes) {
      const label = `${n.host}\\n${n.service}:${n.port}\\n[${n.accessLevel}]`;
      const color = n.accessLevel === "admin" ? "#ef4444"
        : n.accessLevel === "user" ? "#f59e0b"
        : "#4c4c6d";
      lines.push(`  "${n.id}" [label="${label}", color="${color}"];`);
    }

    lines.push("");

    for (const e of this.edges) {
      lines.push(`  "${e.from}" -> "${e.to}" [label="${e.protocol}"];`);
    }

    lines.push("}");
    return lines.join("\n");
  }

  // ── D3.js JSON Output ─────────────────────────────────────────────────

  private toGraphJSON(nodes: ReachabilityNode[]): string {
    const d3Nodes = nodes.map(n => ({
      id: n.id,
      host: n.host,
      port: n.port,
      service: n.service,
      depth: n.depth,
      accessLevel: n.accessLevel,
      provenByRealAuth: n.provenByRealAuth,
      group: n.depth,
    }));

    const d3Links = this.edges.map(e => ({
      source: e.from,
      target: e.to,
      protocol: e.protocol,
      credentialId: e.credentialId,
    }));

    return JSON.stringify({ nodes: d3Nodes, links: d3Links }, null, 2);
  }

  // ── Longest Path Computation ──────────────────────────────────────────

  /**
   * BFS/DFS from entry to find the longest path (by depth).
   */
  private computeLongestPath(entryId: string): string[] {
    if (this.nodes.size === 0) return [entryId];

    // Build adjacency list from edges
    const adj = new Map<string, string[]>();
    for (const edge of this.edges) {
      const existing = adj.get(edge.from) || [];
      existing.push(edge.to);
      adj.set(edge.from, existing);
    }

    // DFS to find longest path
    let longestPath: string[] = [entryId];

    const dfs = (nodeId: string, currentPath: string[], visited: Set<string>): void => {
      if (currentPath.length > longestPath.length) {
        longestPath = [...currentPath];
      }

      const neighbors = adj.get(nodeId) || [];
      for (const neighbor of neighbors) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          currentPath.push(neighbor);
          dfs(neighbor, currentPath, visited);
          currentPath.pop();
          visited.delete(neighbor);
        }
      }
    };

    const visited = new Set<string>([entryId]);
    dfs(entryId, [entryId], visited);

    return longestPath;
  }

  // ── Port Inference ────────────────────────────────────────────────────

  private inferPort(protocol: string): number {
    const portMap: Record<string, number> = {
      ssh: 22,
      ssh_pivot: 22,
      smb: 445,
      smb_pivot: 445,
      smb_relay: 445,
      rdp: 3389,
      rdp_pivot: 3389,
      winrm: 5985,
      http: 80,
      https: 443,
      credential_reuse: 445,
      pass_the_hash: 445,
      pass_the_ticket: 88,
      psexec: 445,
    };
    return portMap[protocol] || 0;
  }
}

// ─── Convenience factory ──────────────────────────────────────────────────────

export function buildReachabilityChain(
  engagementId: string,
  entryPointHost: string,
  pivotResults: PivotResult[],
  parentNodeMap?: Map<string, string>
): ReachabilityChain {
  const builder = new ReachabilityChainBuilder();

  for (const result of pivotResults) {
    const nodeId = builder.addNode(result);
    if (nodeId && parentNodeMap) {
      const parentId = parentNodeMap.get(result.host);
      if (parentId) {
        builder.addEdge(parentId, nodeId, result.credentialUsed || "unknown", result.protocol || result.technique);
      }
    }
  }

  return builder.build(engagementId, entryPointHost);
}
