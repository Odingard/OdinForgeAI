/**
 * JS Route Extractor
 *
 * Parses inline <script> blocks and linked .js bundles for route
 * definitions, API calls, and endpoint strings that static HTML
 * crawling misses.
 *
 * This is regex/string-based extraction, not full AST parsing.
 * It's fast, cheap, and catches 80% of SPA route definitions.
 */

import type { DiscoverySource, HeadlessDiscoveredRoute } from './headless-discovery';

// ── Route Patterns ───────────────────────────────────────────────────────────

const ROUTE_PATTERNS: Array<{ pattern: RegExp; description: string; confidence: number }> = [
  // fetch/axios/XHR calls
  { pattern: /fetch\s*\(\s*['"`](\/[^'"`\s]+)['"`]/g, description: 'fetch() call', confidence: 0.9 },
  { pattern: /axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"`](\/[^'"`\s]+)['"`]/g, description: 'axios call', confidence: 0.9 },
  { pattern: /\.(?:get|post|put|delete|patch)\s*\(\s*['"`](\/[^'"`\s]+)['"`]/g, description: 'HTTP method call', confidence: 0.7 },
  { pattern: /XMLHttpRequest.*?\.open\s*\(\s*['"`]\w+['"`]\s*,\s*['"`](\/[^'"`\s]+)['"`]/g, description: 'XHR open', confidence: 0.85 },

  // Route definitions (React Router, Vue Router, Angular, etc.)
  { pattern: /path\s*:\s*['"`](\/[^'"`\s]+)['"`]/g, description: 'route path definition', confidence: 0.8 },
  { pattern: /to\s*[:=]\s*['"`](\/[^'"`\s]+)['"`]/g, description: 'route link', confidence: 0.6 },
  { pattern: /navigate\s*\(\s*['"`](\/[^'"`\s]+)['"`]/g, description: 'navigate() call', confidence: 0.8 },
  { pattern: /redirect\s*[:=]\s*['"`](\/[^'"`\s]+)['"`]/g, description: 'redirect target', confidence: 0.7 },
  { pattern: /href\s*[:=]\s*['"`](\/[^'"`\s]+)['"`]/g, description: 'href assignment', confidence: 0.6 },
  { pattern: /url\s*[:=]\s*['"`](\/[^'"`\s]+)['"`]/g, description: 'url assignment', confidence: 0.5 },

  // Hardcoded API/admin/config paths
  { pattern: /['"`](\/api\/[a-zA-Z0-9\/_\-]+)['"`]/g, description: 'API path string', confidence: 0.85 },
  { pattern: /['"`](\/graphql[a-zA-Z0-9\/_\-]*)['"`]/g, description: 'GraphQL path', confidence: 0.9 },
  { pattern: /['"`](\/admin[a-zA-Z0-9\/_\-]*)['"`]/g, description: 'admin path', confidence: 0.8 },
  { pattern: /['"`](\/auth[a-zA-Z0-9\/_\-]*)['"`]/g, description: 'auth path', confidence: 0.85 },
  { pattern: /['"`](\/login[a-zA-Z0-9\/_.\-]*)['"`]/g, description: 'login path', confidence: 0.85 },
  { pattern: /['"`](\/account[a-zA-Z0-9\/_\-]*)['"`]/g, description: 'account path', confidence: 0.8 },
  { pattern: /['"`](\/config[a-zA-Z0-9\/_\-]*)['"`]/g, description: 'config path', confidence: 0.75 },
  { pattern: /['"`](\/debug[a-zA-Z0-9\/_\-]*)['"`]/g, description: 'debug path', confidence: 0.7 },
  { pattern: /['"`](\/bank[a-zA-Z0-9\/_.\-]*)['"`]/g, description: 'bank path', confidence: 0.8 },
  { pattern: /['"`](\/user[a-zA-Z0-9\/_\-]*)['"`]/g, description: 'user path', confidence: 0.75 },
  { pattern: /['"`](\/profile[a-zA-Z0-9\/_\-]*)['"`]/g, description: 'profile path', confidence: 0.75 },
  { pattern: /['"`](\/dashboard[a-zA-Z0-9\/_\-]*)['"`]/g, description: 'dashboard path', confidence: 0.75 },
  { pattern: /['"`](\/settings[a-zA-Z0-9\/_\-]*)['"`]/g, description: 'settings path', confidence: 0.7 },
  { pattern: /['"`](\/search[a-zA-Z0-9\/_.\-]*)['"`]/g, description: 'search path', confidence: 0.7 },
  { pattern: /['"`](\/feedback[a-zA-Z0-9\/_.\-]*)['"`]/g, description: 'feedback path', confidence: 0.7 },
  { pattern: /['"`](\/forgot[a-zA-Z0-9\/_.\-]*)['"`]/g, description: 'forgot password path', confidence: 0.7 },
  { pattern: /['"`](\/register[a-zA-Z0-9\/_.\-]*)['"`]/g, description: 'register path', confidence: 0.75 },
  { pattern: /['"`](\/transfer[a-zA-Z0-9\/_.\-]*)['"`]/g, description: 'transfer path', confidence: 0.7 },
  { pattern: /['"`](\/payment[a-zA-Z0-9\/_.\-]*)['"`]/g, description: 'payment path', confidence: 0.7 },
  { pattern: /['"`](\/online[a-zA-Z0-9\/_.\-]*)['"`]/g, description: 'online path', confidence: 0.6 },
];

// Skip patterns that are clearly not routes
const SKIP_PATTERNS = [
  /\.css$/i, /\.js$/i, /\.png$/i, /\.jpg$/i, /\.gif$/i, /\.svg$/i,
  /\.woff$/i, /\.ttf$/i, /\.eot$/i, /\.ico$/i, /\.map$/i,
  /^\/\//,     // protocol-relative URLs
  /node_modules/i, /webpack/i, /chunk/i, /vendor/i,
  /^\/$/,      // root alone
];

function shouldSkip(path: string): boolean {
  return SKIP_PATTERNS.some(p => p.test(path));
}

// ── Extract Routes from JavaScript Text ──────────────────────────────────────

export function extractRoutesFromJS(
  jsText: string,
  baseUrl: string
): HeadlessDiscoveredRoute[] {
  const routes: HeadlessDiscoveredRoute[] = [];
  const seenPaths = new Set<string>();

  for (const { pattern, description, confidence } of ROUTE_PATTERNS) {
    // Reset regex state
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(jsText)) !== null) {
      const path = match[1];
      if (!path || shouldSkip(path)) continue;

      // Normalize
      const normalized = path.replace(/\/+/g, '/').replace(/\/+$/, '') || '/';
      if (seenPaths.has(normalized)) continue;
      seenPaths.add(normalized);

      routes.push({
        url: normalized,
        method: 'GET', // best effort — most JS routes are GET
        source: 'js_extract',
        confidence,
        discoveredVia: description,
      });
    }
  }

  return routes;
}

// ── Fetch and Extract from Linked JS Bundles ─────────────────────────────────

export async function extractRoutesFromLinkedScripts(
  htmlContent: string,
  baseUrl: string,
  maxBundles: number = 5
): Promise<HeadlessDiscoveredRoute[]> {
  const allRoutes: HeadlessDiscoveredRoute[] = [];

  // Extract inline script content
  const inlineScripts = htmlContent.match(/<script[^>]*>([\s\S]*?)<\/script>/gi) || [];
  for (const script of inlineScripts) {
    const content = script.replace(/<script[^>]*>/i, '').replace(/<\/script>/i, '');
    if (content.trim().length > 10) { // skip empty/tiny scripts
      const routes = extractRoutesFromJS(content, baseUrl);
      allRoutes.push(...routes);
    }
  }

  // Extract linked script URLs
  const scriptSrcs: string[] = [];
  const srcPattern = /<script[^>]+src=["']([^"']+)["']/gi;
  let srcMatch: RegExpExecArray | null;
  while ((srcMatch = srcPattern.exec(htmlContent)) !== null) {
    const src = srcMatch[1];
    // Only fetch same-origin scripts, skip CDNs
    if (src.startsWith('/') && !src.startsWith('//')) {
      scriptSrcs.push(src);
    } else if (src.startsWith(baseUrl)) {
      scriptSrcs.push(src);
    }
  }

  // Fetch and parse linked bundles (bounded)
  for (const src of scriptSrcs.slice(0, maxBundles)) {
    try {
      const fullUrl = src.startsWith('http') ? src : new URL(src, baseUrl).toString();
      const resp = await fetch(fullUrl, {
        headers: { 'User-Agent': 'OdinForge-AEV/1.0 (Security Assessment)' },
        signal: AbortSignal.timeout(5000),
      });
      if (resp.ok) {
        const jsText = await resp.text();
        // Only parse if it looks like a substantial bundle
        if (jsText.length > 100 && jsText.length < 5_000_000) {
          const routes = extractRoutesFromJS(jsText, baseUrl);
          allRoutes.push(...routes);
          console.info(`[JS-Extract] Parsed ${src}: ${routes.length} routes found (${jsText.length} bytes)`);
        }
      }
    } catch {
      // Failed to fetch/parse — skip silently
    }
  }

  // Dedup
  const seen = new Set<string>();
  return allRoutes.filter(r => {
    if (seen.has(r.url)) return false;
    seen.add(r.url);
    return true;
  });
}
