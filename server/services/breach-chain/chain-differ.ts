import type { AttackGraph, AttackNode } from "../../../shared/schema";

export interface NodeDiff {
  node: AttackNode;
  changeType: "added" | "removed" | "unchanged" | "worsened" | "improved";
  // worsened = compromiseLevel increased, improved = compromiseLevel decreased
}

export interface ChainComparison {
  chainA: {
    id: string;
    name: string;
    runAt: string;
    nodeCount: number;
    criticalPathLength: number;
    complexityScore: number;
    riskScore: number;
  };
  chainB: {
    id: string;
    name: string;
    runAt: string;
    nodeCount: number;
    criticalPathLength: number;
    complexityScore: number;
    riskScore: number;
  };
  nodesAdded: AttackNode[];     // in B but not in A (new attack paths)
  nodesRemoved: AttackNode[];   // in A but not in B (paths closed)
  nodesWorsened: AttackNode[]; // same node, higher compromiseLevel in B
  nodesImproved: AttackNode[]; // same node, lower compromiseLevel in B
  netChange: number;            // negative = better (fewer nodes), positive = worse
  attackSurfaceChange: number; // percentage change in node count
  criticalPathChange: number;  // change in critical path length
  verdict: "improved" | "regressed" | "unchanged";
  summary: string;             // human-readable summary
  tacticsClosed: string[];     // tactics no longer present
  tacticsAdded: string[];      // new tactics appeared
}

// Order from least to most compromised — index = severity
const COMPROMISE_ORDER: AttackNode["compromiseLevel"][] = [
  "none",
  "limited",
  "user",
  "admin",
  "system",
];

function compromiseLevelIndex(level: AttackNode["compromiseLevel"]): number {
  const idx = COMPROMISE_ORDER.indexOf(level);
  return idx === -1 ? 0 : idx;
}

export function compareChains(
  chainA: {
    id: string;
    name: string;
    completedAt?: string | null;
    overallRiskScore?: number | null;
    unifiedAttackGraph: AttackGraph;
  },
  chainB: {
    id: string;
    name: string;
    completedAt?: string | null;
    overallRiskScore?: number | null;
    unifiedAttackGraph: AttackGraph;
  }
): ChainComparison {
  const graphA = chainA.unifiedAttackGraph;
  const graphB = chainB.unifiedAttackGraph;

  // Build label-keyed maps for quick lookup
  const aByLabel = new Map<string, AttackNode>();
  for (const node of graphA.nodes) {
    aByLabel.set(node.label, node);
  }
  const bByLabel = new Map<string, AttackNode>();
  for (const node of graphB.nodes) {
    bByLabel.set(node.label, node);
  }

  const nodesAdded: AttackNode[] = [];
  const nodesRemoved: AttackNode[] = [];
  const nodesWorsened: AttackNode[] = [];
  const nodesImproved: AttackNode[] = [];

  // Nodes in B — check against A
  for (const nodeB of graphB.nodes) {
    const nodeA = aByLabel.get(nodeB.label);
    if (!nodeA) {
      nodesAdded.push(nodeB);
    } else {
      const levelA = compromiseLevelIndex(nodeA.compromiseLevel);
      const levelB = compromiseLevelIndex(nodeB.compromiseLevel);
      if (levelB > levelA) {
        nodesWorsened.push(nodeB);
      } else if (levelB < levelA) {
        nodesImproved.push(nodeB);
      }
      // else unchanged — not tracked separately
    }
  }

  // Nodes in A missing from B
  for (const nodeA of graphA.nodes) {
    if (!bByLabel.has(nodeA.label)) {
      nodesRemoved.push(nodeA);
    }
  }

  const netChange = graphB.nodes.length - graphA.nodes.length;
  const attackSurfaceChange = Math.round(
    ((graphB.nodes.length - graphA.nodes.length) / Math.max(1, graphA.nodes.length)) * 100
  );
  const criticalPathChange = graphB.criticalPath.length - graphA.criticalPath.length;

  // Verdict
  let verdict: ChainComparison["verdict"];
  if (netChange === 0 && nodesWorsened.length === 0 && nodesImproved.length === 0) {
    verdict = "unchanged";
  } else if (netChange < 0 || nodesRemoved.length > nodesAdded.length) {
    verdict = "improved";
  } else if (netChange > 0 || nodesAdded.length > nodesRemoved.length) {
    verdict = "regressed";
  } else {
    verdict = "unchanged";
  }

  // Tactics diff
  const tacticsA = new Set(graphA.killChainCoverage);
  const tacticsB = new Set(graphB.killChainCoverage);

  const tacticsClosed = Array.from(tacticsA).filter((t) => !tacticsB.has(t));
  const tacticsAdded = Array.from(tacticsB).filter((t) => !tacticsA.has(t));

  // Summary
  let summary: string;
  if (verdict === "improved") {
    const pct = Math.abs(attackSurfaceChange);
    const closedPart = nodesRemoved.length > 0
      ? `. ${nodesRemoved.length} attack path${nodesRemoved.length !== 1 ? "s" : ""} closed`
      : "";
    const addedPart = nodesAdded.length > 0
      ? `, ${nodesAdded.length} new vector${nodesAdded.length !== 1 ? "s" : ""} discovered`
      : "";
    summary = `Attack surface reduced by ${pct}% since last run${closedPart}${addedPart}.`;
  } else if (verdict === "regressed") {
    const closedPart = nodesRemoved.length > 0
      ? `, ${nodesRemoved.length} path${nodesRemoved.length !== 1 ? "s" : ""} closed`
      : "";
    summary = `Attack surface grew by ${attackSurfaceChange}%. ${nodesAdded.length} new attack vector${nodesAdded.length !== 1 ? "s" : ""} emerged${closedPart}.`;
  } else {
    summary = "Attack surface unchanged. No significant posture change detected.";
  }

  return {
    chainA: {
      id: chainA.id,
      name: chainA.name,
      runAt: chainA.completedAt ?? "",
      nodeCount: graphA.nodes.length,
      criticalPathLength: graphA.criticalPath.length,
      complexityScore: graphA.complexityScore,
      riskScore: chainA.overallRiskScore ?? 0,
    },
    chainB: {
      id: chainB.id,
      name: chainB.name,
      runAt: chainB.completedAt ?? "",
      nodeCount: graphB.nodes.length,
      criticalPathLength: graphB.criticalPath.length,
      complexityScore: graphB.complexityScore,
      riskScore: chainB.overallRiskScore ?? 0,
    },
    nodesAdded,
    nodesRemoved,
    nodesWorsened,
    nodesImproved,
    netChange,
    attackSurfaceChange,
    criticalPathChange,
    verdict,
    summary,
    tacticsClosed,
    tacticsAdded,
  };
}
