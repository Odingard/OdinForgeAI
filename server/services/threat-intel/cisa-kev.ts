/**
 * CISA Known Exploited Vulnerabilities (KEV) Feed Adapter
 *
 * Fetches the CISA KEV catalog and upserts indicators into the database.
 * Feed URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 */

import { storage } from "../../storage";
import { randomUUID } from "crypto";

const CISA_KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface CisaKevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: "Known" | "Unknown";
  notes?: string;
}

interface CisaKevCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: CisaKevEntry[];
}

/**
 * Fetch and parse the CISA KEV JSON feed.
 */
export async function fetchCisaKev(): Promise<CisaKevCatalog> {
  const response = await fetch(CISA_KEV_URL);
  if (!response.ok) {
    throw new Error(`CISA KEV fetch failed: ${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<CisaKevCatalog>;
}

/**
 * Sync a CISA KEV feed into the database.
 * Upserts all indicators and updates the feed's metadata.
 */
export async function syncCisaKevFeed(feedId: string, organizationId: string): Promise<{
  total: number;
  newIndicators: number;
  updatedIndicators: number;
}> {
  const catalog = await fetchCisaKev();

  let newCount = 0;
  let updatedCount = 0;

  for (const entry of catalog.vulnerabilities) {
    const existing = await storage.getThreatIntelIndicatorByValue(
      entry.cveID,
      organizationId
    );

    if (existing) {
      await storage.updateThreatIntelIndicator(existing.id, {
        vendorProject: entry.vendorProject,
        product: entry.product,
        vulnerabilityName: entry.vulnerabilityName,
        shortDescription: entry.shortDescription,
        requiredAction: entry.requiredAction,
        dueDate: new Date(entry.dueDate),
        knownRansomwareCampaignUse: entry.knownRansomwareCampaignUse === "Known",
      });
      updatedCount++;
    } else {
      await storage.createThreatIntelIndicator({
        id: `kev-${randomUUID().slice(0, 8)}`,
        feedId,
        organizationId,
        indicatorType: "cve",
        indicatorValue: entry.cveID,
        vendorProject: entry.vendorProject,
        product: entry.product,
        vulnerabilityName: entry.vulnerabilityName,
        shortDescription: entry.shortDescription,
        requiredAction: entry.requiredAction,
        dueDate: new Date(entry.dueDate),
        knownRansomwareCampaignUse: entry.knownRansomwareCampaignUse === "Known",
        dateAdded: new Date(entry.dateAdded),
        matchedAssetCount: 0,
        matchedFindingIds: [],
      });
      newCount++;
    }
  }

  // Update feed metadata
  const indicatorCount = await storage.countThreatIntelIndicators(feedId);
  await storage.updateThreatIntelFeed(feedId, {
    lastCheckedAt: new Date(),
    lastSuccessAt: new Date(),
    lastError: null,
    indicatorCount,
  });

  return {
    total: catalog.vulnerabilities.length,
    newIndicators: newCount,
    updatedIndicators: updatedCount,
  };
}
