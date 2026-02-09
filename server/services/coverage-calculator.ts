/**
 * Attack Surface Coverage Calculator
 *
 * Computes AEV coverage metrics:
 * - Asset coverage: % of active assets evaluated in the last 30 days
 * - Technique coverage: % of MITRE ATT&CK kill chain tactics exercised
 * - Tactical breakdown: per-tactic coverage with technique counts
 * - Gap analysis: untested techniques and stale assets
 */

import { storage } from "../storage";
import { killChainTactics } from "@shared/schema";
import type { KillChainTactic } from "@shared/schema";

export interface CoverageMetrics {
  assetCoverage: {
    totalActiveAssets: number;
    assetsEvaluatedLast30d: number;
    coveragePercent: number;
  };
  techniqueCoverage: {
    totalTactics: number;
    tacticsExercised: number;
    coveragePercent: number;
    uniqueTechniqueIds: number;
  };
  tacticalBreakdown: Array<{
    tactic: string;
    displayName: string;
    techniqueCount: number;
    covered: boolean;
  }>;
}

export interface CoverageGaps {
  staleAssets: Array<{
    id: string;
    assetIdentifier: string;
    displayName: string | null;
    assetType: string;
    lastEvaluatedAt: string | null;
    daysSinceEvaluation: number | null;
  }>;
  untestedTactics: Array<{
    tactic: string;
    displayName: string;
  }>;
  totalGaps: number;
}

const tacticDisplayNames: Record<string, string> = {
  "reconnaissance": "Reconnaissance",
  "resource-development": "Resource Development",
  "initial-access": "Initial Access",
  "execution": "Execution",
  "persistence": "Persistence",
  "privilege-escalation": "Privilege Escalation",
  "defense-evasion": "Defense Evasion",
  "credential-access": "Credential Access",
  "discovery": "Discovery",
  "lateral-movement": "Lateral Movement",
  "collection": "Collection",
  "command-and-control": "Command & Control",
  "exfiltration": "Exfiltration",
  "impact": "Impact",
};

/**
 * Calculate attack surface coverage metrics for an organization.
 */
export async function calculateCoverage(organizationId: string): Promise<CoverageMetrics> {
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  // Get all active assets
  const allAssets = await storage.getDiscoveredAssets(organizationId);
  const activeAssets = allAssets.filter(a => a.status === "active");

  // Get evaluations from the last 30 days
  const evaluations = await storage.getEvaluations(organizationId);
  const recentEvaluations = evaluations.filter(e => {
    const created = e.createdAt ? new Date(e.createdAt) : null;
    return created && created >= thirtyDaysAgo;
  });

  // Unique asset IDs evaluated recently
  const evaluatedAssetIds = new Set(recentEvaluations.map(e => e.assetId));
  const assetsEvaluated = activeAssets.filter(a =>
    evaluatedAssetIds.has(a.id) || evaluatedAssetIds.has(a.assetIdentifier)
  ).length;

  // Get results to extract technique coverage
  const completedEvalIds = recentEvaluations
    .filter(e => e.status === "completed")
    .map(e => e.id);

  const results = completedEvalIds.length > 0
    ? await storage.getResultsByEvaluationIds(completedEvalIds)
    : [];

  // Extract tactics and technique IDs from attack graphs
  const coveredTactics = new Set<string>();
  const uniqueTechniqueIds = new Set<string>();

  for (const result of results) {
    const graph = result.attackGraph as any;
    if (graph) {
      // Collect tactics from killChainCoverage
      if (Array.isArray(graph.killChainCoverage)) {
        for (const tactic of graph.killChainCoverage) {
          coveredTactics.add(tactic);
        }
      }
      // Collect tactics from nodes
      if (Array.isArray(graph.nodes)) {
        for (const node of graph.nodes) {
          if (node.tactic) coveredTactics.add(node.tactic);
        }
      }
      // Collect technique IDs from edges
      if (Array.isArray(graph.edges)) {
        for (const edge of graph.edges) {
          if (edge.techniqueId) uniqueTechniqueIds.add(edge.techniqueId);
          if (edge.technique) uniqueTechniqueIds.add(edge.technique);
        }
      }
    }

    // Also check attack path steps
    const path = result.attackPath as any[];
    if (Array.isArray(path)) {
      for (const step of path) {
        if (step.technique) uniqueTechniqueIds.add(step.technique);
      }
    }
  }

  const totalActive = activeAssets.length || 1; // avoid division by zero
  const totalTactics = killChainTactics.length;

  // Build tactical breakdown
  const tacticalBreakdown = killChainTactics.map(tactic => ({
    tactic,
    displayName: tacticDisplayNames[tactic] || tactic,
    techniqueCount: results.reduce((count, r) => {
      const graph = r.attackGraph as any;
      if (!graph?.edges) return count;
      return count + graph.edges.filter((e: any) =>
        graph.nodes?.some((n: any) => n.tactic === tactic && (n.id === e.source || n.id === e.target))
      ).length;
    }, 0),
    covered: coveredTactics.has(tactic),
  }));

  return {
    assetCoverage: {
      totalActiveAssets: activeAssets.length,
      assetsEvaluatedLast30d: assetsEvaluated,
      coveragePercent: Math.round((assetsEvaluated / totalActive) * 100),
    },
    techniqueCoverage: {
      totalTactics,
      tacticsExercised: coveredTactics.size,
      coveragePercent: Math.round((coveredTactics.size / totalTactics) * 100),
      uniqueTechniqueIds: uniqueTechniqueIds.size,
    },
    tacticalBreakdown,
  };
}

/**
 * Identify coverage gaps: untested tactics and stale assets.
 */
export async function calculateGaps(organizationId: string): Promise<CoverageGaps> {
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  const allAssets = await storage.getDiscoveredAssets(organizationId);
  const activeAssets = allAssets.filter(a => a.status === "active");

  const evaluations = await storage.getEvaluations(organizationId);

  // Build a map of assetId -> last evaluated date
  const lastEvalMap = new Map<string, Date>();
  for (const ev of evaluations) {
    const created = ev.createdAt ? new Date(ev.createdAt) : null;
    if (!created) continue;
    const current = lastEvalMap.get(ev.assetId);
    if (!current || created > current) {
      lastEvalMap.set(ev.assetId, created);
    }
  }

  // Stale assets: active assets not evaluated in 30+ days
  const now = new Date();
  const staleAssets = activeAssets
    .map(asset => {
      const lastEval = lastEvalMap.get(asset.id) || lastEvalMap.get(asset.assetIdentifier);
      const daysSince = lastEval
        ? Math.floor((now.getTime() - lastEval.getTime()) / (1000 * 60 * 60 * 24))
        : null;
      return {
        id: asset.id,
        assetIdentifier: asset.assetIdentifier,
        displayName: asset.displayName,
        assetType: asset.assetType,
        lastEvaluatedAt: lastEval?.toISOString() || null,
        daysSinceEvaluation: daysSince,
      };
    })
    .filter(a => a.daysSinceEvaluation === null || a.daysSinceEvaluation >= 30)
    .sort((a, b) => {
      // Never-evaluated first, then by staleness descending
      if (a.daysSinceEvaluation === null) return -1;
      if (b.daysSinceEvaluation === null) return 1;
      return b.daysSinceEvaluation - a.daysSinceEvaluation;
    });

  // Untested tactics from recent evaluations
  const recentEvals = evaluations.filter(e => {
    const created = e.createdAt ? new Date(e.createdAt) : null;
    return created && created >= thirtyDaysAgo && e.status === "completed";
  });

  const completedIds = recentEvals.map(e => e.id);
  const results = completedIds.length > 0
    ? await storage.getResultsByEvaluationIds(completedIds)
    : [];

  const coveredTactics = new Set<string>();
  for (const result of results) {
    const graph = result.attackGraph as any;
    if (graph?.killChainCoverage) {
      for (const t of graph.killChainCoverage) coveredTactics.add(t);
    }
    if (graph?.nodes) {
      for (const n of graph.nodes) {
        if (n.tactic) coveredTactics.add(n.tactic);
      }
    }
  }

  const untestedTactics = killChainTactics
    .filter(t => !coveredTactics.has(t))
    .map(t => ({
      tactic: t,
      displayName: tacticDisplayNames[t] || t,
    }));

  return {
    staleAssets,
    untestedTactics,
    totalGaps: staleAssets.length + untestedTactics.length,
  };
}
