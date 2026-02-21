/**
 * EPSS (Exploit Prediction Scoring System) Client
 *
 * Queries the FIRST.org EPSS API for daily-updated exploitation probability
 * scores per CVE. Free, no auth, 1000 req/min.
 *
 * API: https://api.first.org/data/v1/epss
 */

const EPSS_API_BASE = "https://api.first.org/data/v1/epss";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours (EPSS updates daily)
const MAX_BATCH_SIZE = 100;

export interface EPSSResult {
  cve: string;
  epss: number;       // 0.0-1.0: probability of exploitation in next 30 days
  percentile: number;  // 0.0-1.0: rank among all scored CVEs
  date: string;        // YYYY-MM-DD
}

interface CacheEntry {
  data: EPSSResult;
  cachedAt: number;
}

const cache = new Map<string, CacheEntry>();

/**
 * Fetch EPSS scores for multiple CVEs (batch).
 * Returns a map of CVE ID → EPSSResult. Missing CVEs are omitted.
 */
export async function getEPSSScores(cveIds: string[]): Promise<Map<string, EPSSResult>> {
  const results = new Map<string, EPSSResult>();
  if (cveIds.length === 0) return results;

  const now = Date.now();
  const uncached: string[] = [];

  // Check cache first
  for (const cveId of cveIds) {
    const entry = cache.get(cveId);
    if (entry && now - entry.cachedAt < CACHE_TTL_MS) {
      results.set(cveId, entry.data);
    } else {
      uncached.push(cveId);
    }
  }

  if (uncached.length === 0) return results;

  // Batch fetch uncached CVEs (max 100 per request)
  for (let i = 0; i < uncached.length; i += MAX_BATCH_SIZE) {
    const batch = uncached.slice(i, i + MAX_BATCH_SIZE);
    try {
      const url = `${EPSS_API_BASE}?cve=${batch.join(",")}`;
      const response = await fetch(url, {
        headers: { "Accept": "application/json" },
        signal: AbortSignal.timeout(10000),
      });

      if (response.status === 429) {
        console.warn("[EPSS] Rate limited, skipping batch");
        continue;
      }

      if (!response.ok) {
        console.warn(`[EPSS] API returned ${response.status}`);
        continue;
      }

      const json = await response.json() as {
        status: string;
        data: Array<{ cve: string; epss: string; percentile: string; date: string }>;
      };

      if (json.status === "OK" && Array.isArray(json.data)) {
        for (const entry of json.data) {
          const result: EPSSResult = {
            cve: entry.cve,
            epss: parseFloat(entry.epss),
            percentile: parseFloat(entry.percentile),
            date: entry.date,
          };

          // Validate parsed values
          if (!isNaN(result.epss) && !isNaN(result.percentile)) {
            results.set(entry.cve, result);
            cache.set(entry.cve, { data: result, cachedAt: now });
          }
        }
      }
    } catch (error) {
      // Non-fatal — scoring works without EPSS
      console.warn("[EPSS] Fetch error for batch:", error instanceof Error ? error.message : error);
    }
  }

  return results;
}

/**
 * Fetch EPSS score for a single CVE.
 */
export async function getEPSSScore(cveId: string): Promise<EPSSResult | null> {
  const results = await getEPSSScores([cveId]);
  return results.get(cveId) ?? null;
}

/**
 * Clear the in-memory EPSS cache.
 */
export function clearEPSSCache(): void {
  cache.clear();
}
