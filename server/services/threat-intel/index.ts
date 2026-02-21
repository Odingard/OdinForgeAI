/**
 * Threat Intelligence Service
 *
 * Orchestrates feed syncing and CVE matching against internal findings.
 */

import { storage } from "../../storage";
import { syncCisaKevFeed } from "./cisa-kev";
export { getEPSSScores, getEPSSScore, clearEPSSCache } from "./epss-client";

/**
 * Sync a single threat intel feed based on its type.
 */
export async function syncFeed(feedId: string): Promise<{
  total: number;
  newIndicators: number;
  updatedIndicators: number;
}> {
  const feed = await storage.getThreatIntelFeed(feedId);
  if (!feed) throw new Error(`Feed not found: ${feedId}`);
  if (!feed.enabled) throw new Error(`Feed is disabled: ${feedId}`);

  try {
    let result;
    switch (feed.feedType) {
      case "cisa_kev":
        result = await syncCisaKevFeed(feedId, feed.organizationId);
        break;
      default:
        throw new Error(`Unsupported feed type: ${feed.feedType}`);
    }
    return result;
  } catch (error: any) {
    // Record the error on the feed
    await storage.updateThreatIntelFeed(feedId, {
      lastCheckedAt: new Date(),
      lastError: error.message || "Unknown error",
    });
    throw error;
  }
}

/**
 * Sync all enabled feeds for an organization.
 */
export async function syncAllFeeds(organizationId: string): Promise<{
  synced: number;
  errors: number;
}> {
  const feeds = await storage.getThreatIntelFeeds(organizationId);
  const enabledFeeds = feeds.filter(f => f.enabled);

  let synced = 0;
  let errors = 0;

  for (const feed of enabledFeeds) {
    try {
      await syncFeed(feed.id);
      synced++;
    } catch (error) {
      console.error(`Failed to sync feed ${feed.id}:`, error);
      errors++;
    }
  }

  return { synced, errors };
}

/**
 * Match threat intel indicators (CVEs) against internal agent findings.
 * Finds agentFindings where cveId matches a KEV indicator and updates matched counts.
 */
export async function matchToFindings(organizationId: string): Promise<{
  matchedIndicators: number;
  totalMatches: number;
}> {
  const indicators = await storage.getThreatIntelIndicators(organizationId, 10000);
  const cveIndicators = indicators.filter(i => i.indicatorType === "cve");

  if (cveIndicators.length === 0) return { matchedIndicators: 0, totalMatches: 0 };

  // Get all agent findings with CVE IDs for the org
  // We need to fetch findings and cross-reference
  const allFindings = await storage.getAgentFindings(undefined, organizationId);
  const findingsWithCve = allFindings.filter(f => f.cveId);

  // Build CVE -> findings map
  const cveToFindings = new Map<string, string[]>();
  for (const finding of findingsWithCve) {
    if (!finding.cveId) continue;
    const existing = cveToFindings.get(finding.cveId) || [];
    existing.push(finding.id);
    cveToFindings.set(finding.cveId, existing);
  }

  let matchedIndicators = 0;
  let totalMatches = 0;

  for (const indicator of cveIndicators) {
    const matchedIds = cveToFindings.get(indicator.indicatorValue) || [];
    if (matchedIds.length > 0) {
      matchedIndicators++;
      totalMatches += matchedIds.length;
      await storage.updateThreatIntelIndicator(indicator.id, {
        matchedAssetCount: matchedIds.length,
        matchedFindingIds: matchedIds,
      });
    }
  }

  return { matchedIndicators, totalMatches };
}
