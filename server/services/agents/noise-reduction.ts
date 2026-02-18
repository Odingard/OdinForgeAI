/**
 * Swiss Cheese Noise Reduction Engine
 *
 * Four-layer filtering model inspired by Aikido Security's approach.
 * Each layer removes exploit chains that fail its check, progressively
 * eliminating false positives while preserving genuine findings.
 *
 * Layer 1 — Reachability: Verify targets are actually reachable (open ports/services)
 * Layer 2 — Exploitability: Cross-reference with prior exploit validation verdicts
 * Layer 3 — Environmental Context: Filter by asset metadata (prod vs staging, etc.)
 * Layer 4 — Deduplication: Merge similar chains, keep highest-confidence variant
 */

import type { ExploitFindings, ReconFindings, NoiseReductionStats } from "./types";
import type { RealScanData } from "./scan-data-loader";

interface ExploitChain {
  name: string;
  technique: string;
  description: string;
  success_likelihood: "high" | "medium" | "low";
}

interface RemovedChain {
  name: string;
  reason: string;
  layer: string;
}

export interface NoiseReductionResult {
  filteredChains: ExploitChain[];
  removedChains: RemovedChain[];
  stats: NoiseReductionStats;
}

interface NoiseReductionContext {
  exposureType: string;
  priority: string;
  assetId: string;
  description: string;
  executionMode?: string;
}

// ─── Layer 1: Reachability ──────────────────────────────────────────

function filterByReachability(
  chains: ExploitChain[],
  realScanData: RealScanData | undefined,
  removed: RemovedChain[]
): ExploitChain[] {
  // If no real network/recon data, skip this layer (can't verify reachability)
  if (!realScanData?.networkData && !realScanData?.reconData) {
    return chains;
  }

  // Build set of confirmed open ports
  const openPorts = new Set<number>();
  realScanData.networkData?.openPorts.forEach(p => openPorts.add(p.port));
  realScanData.reconData?.openPorts.forEach(p => openPorts.add(p.port));

  // Build set of confirmed services
  const confirmedServices = new Set<string>();
  realScanData.networkData?.openPorts.forEach(p => {
    if (p.service) confirmedServices.add(p.service.toLowerCase());
  });
  realScanData.reconData?.openPorts.forEach(p => {
    if (p.service) confirmedServices.add(p.service.toLowerCase());
  });
  realScanData.reconData?.technologies.forEach(t => confirmedServices.add(t.toLowerCase()));

  return chains.filter(chain => {
    const desc = chain.description.toLowerCase();

    // Extract port references from the chain description
    const portMatches = desc.match(/port\s*(\d+)/gi) || [];
    const referencedPorts = portMatches.map(m => parseInt(m.replace(/port\s*/i, ""), 10)).filter(p => !isNaN(p));

    // If chain references specific ports that are confirmed closed, filter it
    if (referencedPorts.length > 0 && openPorts.size > 0) {
      const allPortsClosed = referencedPorts.every(p => !openPorts.has(p));
      if (allPortsClosed) {
        removed.push({
          name: chain.name,
          reason: `References ports [${referencedPorts.join(", ")}] but none are open (verified: ${Array.from(openPorts).slice(0, 10).join(", ")})`,
          layer: "reachability",
        });
        return false;
      }
    }

    return true;
  });
}

// ─── Layer 2: Exploitability Cross-Reference ────────────────────────

function filterByExploitability(
  chains: ExploitChain[],
  realScanData: RealScanData | undefined,
  removed: RemovedChain[]
): ExploitChain[] {
  // If no prior exploit validation data, skip this layer
  if (!realScanData?.exploitValidation?.results.length) {
    return chains;
  }

  const validationResults = realScanData.exploitValidation.results;

  // Build a map of exploit types that were confirmed as noise/not-exploitable
  const noiseExploitTypes = new Set<string>();
  const confirmedExploitTypes = new Set<string>();

  validationResults.forEach(r => {
    const type = r.exploitType.toLowerCase();
    if (r.verdict === "noise" || (!r.exploitable && r.confidence > 0.7)) {
      noiseExploitTypes.add(type);
    }
    if (r.exploitable && r.confidence > 0.5) {
      confirmedExploitTypes.add(type);
    }
  });

  return chains.filter(chain => {
    const desc = chain.description.toLowerCase();
    const name = chain.name.toLowerCase();
    const technique = chain.technique.toLowerCase();

    // Check if this chain's exploit type was previously validated as noise
    for (const noiseType of Array.from(noiseExploitTypes)) {
      if (desc.includes(noiseType) || name.includes(noiseType) || technique.includes(noiseType)) {
        // Don't filter if it was also confirmed somewhere else
        if (!confirmedExploitTypes.has(noiseType)) {
          removed.push({
            name: chain.name,
            reason: `Exploit type "${noiseType}" was previously validated as noise/not-exploitable`,
            layer: "exploitability",
          });
          return false;
        }
      }
    }

    return true;
  });
}

// ─── Layer 3: Environmental Context ─────────────────────────────────

function filterByEnvironmentalContext(
  chains: ExploitChain[],
  context: NoiseReductionContext,
  realScanData: RealScanData | undefined,
  removed: RemovedChain[]
): ExploitChain[] {
  const desc = context.description.toLowerCase();
  const assetId = context.assetId.toLowerCase();

  // Detect if this is a staging/dev/test environment
  const isNonProduction = /\b(staging|dev|development|test|sandbox|demo|qa)\b/.test(desc) ||
    /\b(staging|dev|development|test|sandbox|demo|qa)\b/.test(assetId);

  // Detect if asset is internal-only
  const isInternalOnly = /\b(internal|intranet|private|10\.\d|172\.(1[6-9]|2\d|3[01])|192\.168)\b/.test(desc);

  return chains.filter(chain => {
    const chainDesc = chain.description.toLowerCase();

    // For internal-only assets, filter chains that rely on external/internet attack vectors
    if (isInternalOnly) {
      const externalOnly = /\b(internet-facing|external|public endpoint|from the internet|external recon)\b/.test(chainDesc) &&
        !/\b(internal|lateral|pivot)\b/.test(chainDesc);
      if (externalOnly) {
        removed.push({
          name: chain.name,
          reason: "Chain relies on external attack vectors but asset is internal-only",
          layer: "environmental",
        });
        return false;
      }
    }

    // For non-production environments, downgrade but don't remove
    // (severity adjustment rather than removal — we keep the chain but note it)

    return true;
  });
}

// ─── Layer 4: Deduplication ─────────────────────────────────────────

function deduplicateChains(
  chains: ExploitChain[],
  removed: RemovedChain[]
): ExploitChain[] {
  if (chains.length <= 1) return chains;

  const likelihoodScore = { high: 3, medium: 2, low: 1 };
  const kept: ExploitChain[] = [];
  const seen = new Map<string, ExploitChain>();

  for (const chain of chains) {
    // Build a dedup key from technique + first significant words
    const key = buildDedupKey(chain);

    const existing = seen.get(key);
    if (existing) {
      // Keep the higher-confidence variant
      const existingScore = likelihoodScore[existing.success_likelihood] || 0;
      const newScore = likelihoodScore[chain.success_likelihood] || 0;

      if (newScore > existingScore) {
        // Replace existing with this one
        removed.push({
          name: existing.name,
          reason: `Duplicate of "${chain.name}" (lower confidence variant removed)`,
          layer: "deduplication",
        });
        seen.set(key, chain);
        const idx = kept.findIndex(k => k === existing);
        if (idx >= 0) kept[idx] = chain;
      } else {
        removed.push({
          name: chain.name,
          reason: `Duplicate of "${existing.name}" (lower confidence variant removed)`,
          layer: "deduplication",
        });
      }
    } else {
      seen.set(key, chain);
      kept.push(chain);
    }
  }

  return kept;
}

function buildDedupKey(chain: ExploitChain): string {
  // Normalize technique
  const technique = chain.technique.replace(/\./g, "").toLowerCase();

  // Extract key phrases from description
  const descWords = chain.description.toLowerCase()
    .replace(/[^a-z0-9\s]/g, "")
    .split(/\s+/)
    .filter(w => w.length > 3)
    .slice(0, 5)
    .sort()
    .join("_");

  return `${technique}:${descWords}`;
}

// ─── Main Entry Point ───────────────────────────────────────────────

export function applyNoiseReduction(
  exploitFindings: ExploitFindings,
  realScanData: RealScanData | undefined,
  context: NoiseReductionContext,
  reconFindings?: ReconFindings
): NoiseReductionResult {
  const chains = [...exploitFindings.exploitChains];
  const removed: RemovedChain[] = [];
  const inputCount = chains.length;

  // Layer 1: Reachability
  const afterReachability = filterByReachability(chains, realScanData, removed);

  // Layer 2: Exploitability
  const afterExploitability = filterByExploitability(afterReachability, realScanData, removed);

  // Layer 3: Environmental Context
  const afterEnvironmental = filterByEnvironmentalContext(afterExploitability, context, realScanData, removed);

  // Layer 4: Deduplication
  const afterDeduplication = deduplicateChains(afterEnvironmental, removed);

  return {
    filteredChains: afterDeduplication,
    removedChains: removed,
    stats: {
      inputCount,
      afterReachability: afterReachability.length,
      afterExploitability: afterExploitability.length,
      afterEnvironmental: afterEnvironmental.length,
      afterDeduplication: afterDeduplication.length,
      finalCount: afterDeduplication.length,
      removedChains: removed,
    },
  };
}
