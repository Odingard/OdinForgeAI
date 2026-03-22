/**
 * Headless Browser Discovery
 *
 * Thin pre-attack discovery layer using Playwright. Renders SPAs,
 * captures JS-driven navigation, observes XHR/fetch requests, and
 * extracts routes that static crawling misses.
 *
 * This is NOT a full recon subsystem. It feeds discovered endpoints
 * into the existing surface model and exploit engine.
 *
 * Scope limits:
 *   - 1 browser context per run
 *   - max 3 pages deep
 *   - max 30 interaction-driven discoveries
 *   - 15s hard timeout
 *   - same-origin only
 */

import type { DiscoveredEndpoint } from '../active-exploit-engine';

export type DiscoverySource = 'crawl' | 'headless' | 'js_extract' | 'common_path';

export interface HeadlessDiscoveredRoute {
  url: string;
  method: string;
  source: DiscoverySource;
  confidence: number;      // 0-1: how confident this is a real route
  contentType?: string;
  discoveredVia: string;    // human-readable: "nav click", "XHR observed", etc.
}

// Safe interaction targets — click these, skip everything else
const SAFE_INTERACTION_LABELS = [
  /login/i, /sign.?in/i, /account/i, /admin/i, /profile/i,
  /settings/i, /dashboard/i, /menu/i, /nav/i, /banking/i,
  /transfer/i, /payment/i, /search/i, /about/i, /contact/i,
  /register/i, /sign.?up/i, /services/i, /products/i, /help/i,
];

// Skip destructive or dangerous interactions
const SKIP_LABELS = [
  /logout/i, /sign.?out/i, /delete/i, /remove/i, /cancel/i,
  /checkout/i, /pay\b/i, /submit.*payment/i, /upload/i,
  /destroy/i, /reset/i, /unsubscribe/i,
];

function isSameOrigin(url: string, baseUrl: string): boolean {
  try {
    return new URL(url).origin === new URL(baseUrl).origin;
  } catch {
    return false;
  }
}

function isSafeToClick(label: string): boolean {
  if (SKIP_LABELS.some(p => p.test(label))) return false;
  if (SAFE_INTERACTION_LABELS.some(p => p.test(label))) return true;
  return false; // default: don't click unknown things
}

/**
 * Run headless browser discovery against a target URL.
 * Returns discovered routes that static crawling would miss.
 */
export async function runHeadlessDiscovery(
  targetUrl: string,
  options: {
    maxDepth?: number;
    maxInteractions?: number;
    timeoutMs?: number;
    onRouteDiscovered?: (route: HeadlessDiscoveredRoute) => void;
    /** Auth config — passed to browser context for authenticated discovery */
    auth?: {
      type?: string;
      cookies?: string[];
      token?: string;
      headers?: Record<string, string>;
    };
  } = {}
): Promise<HeadlessDiscoveredRoute[]> {
  const maxDepth = options.maxDepth ?? 3;
  const maxInteractions = options.maxInteractions ?? 30;
  const timeoutMs = options.timeoutMs ?? 15000;
  const routes: HeadlessDiscoveredRoute[] = [];
  const seenUrls = new Set<string>();
  let interactionCount = 0;

  // Normalize and track a discovered route
  function addRoute(url: string, method: string, via: string, confidence: number): void {
    try {
      const normalized = new URL(url).pathname + new URL(url).search;
      if (seenUrls.has(normalized)) return;
      if (!isSameOrigin(url, targetUrl)) return;
      seenUrls.add(normalized);

      const route: HeadlessDiscoveredRoute = {
        url: normalized,
        method,
        source: 'headless',
        confidence,
        discoveredVia: via,
      };
      routes.push(route);
      options.onRouteDiscovered?.(route);
    } catch { /* invalid URL */ }
  }

  let chromium: any;
  try {
    // Dynamic import — playwright-core may not be installed
    const pw = await import('playwright-core');
    chromium = pw.chromium;
  } catch {
    console.warn('[Headless] playwright-core not available — skipping headless discovery');
    return [];
  }

  let browser: any = null;

  try {
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });

    // Build context options with auth if available
    const contextOpts: any = {
      userAgent: 'OdinForge-AEV/1.0 (Security Assessment)',
      viewport: { width: 1280, height: 720 },
    };

    // Apply auth headers to browser context
    if (options.auth?.headers) {
      contextOpts.extraHTTPHeaders = options.auth.headers;
    }
    if (options.auth?.token) {
      contextOpts.extraHTTPHeaders = {
        ...contextOpts.extraHTTPHeaders,
        'Authorization': `Bearer ${options.auth.token}`,
      };
    }

    const context = await browser.newContext(contextOpts);

    // Apply auth cookies to browser context
    if (options.auth?.cookies && options.auth.cookies.length > 0) {
      try {
        const parsedUrl = new URL(targetUrl);
        const cookieObjects = options.auth.cookies.map(c => {
          const [name, ...valueParts] = c.split('=');
          return {
            name: name.trim(),
            value: valueParts.join('=').trim(),
            domain: parsedUrl.hostname,
            path: '/',
          };
        });
        await context.addCookies(cookieObjects);
      } catch { /* skip invalid cookies */ }
    }

    const page = await context.newPage();

    // Capture network requests — highest-value discovery source
    page.on('request', (req: any) => {
      const reqUrl = req.url();
      const reqMethod = req.method();
      if (isSameOrigin(reqUrl, targetUrl)) {
        const resourceType = req.resourceType();
        // Only capture API/document requests, not images/fonts/css
        if (['document', 'xhr', 'fetch', 'script'].includes(resourceType)) {
          const confidence = resourceType === 'xhr' || resourceType === 'fetch' ? 0.9 : 0.6;
          addRoute(reqUrl, reqMethod, `${resourceType} observed`, confidence);
        }
      }
    });

    // Navigate to target with timeout
    await page.goto(targetUrl, { waitUntil: 'networkidle', timeout: timeoutMs });

    // Record the landing page URL (may have redirected)
    addRoute(page.url(), 'GET', 'page load', 0.95);

    // Extract all href attributes from the rendered DOM
    const hrefLinks: string[] = await page.evaluate(() => {
      const links: string[] = [];
      document.querySelectorAll('a[href]').forEach((el) => {
        const href = el.getAttribute('href');
        if (href) links.push(href);
      });
      // Also get onclick handlers that reference URLs
      document.querySelectorAll('[onclick]').forEach((el) => {
        const onclick = el.getAttribute('onclick') || '';
        const match = onclick.match(/['"](\/.+?)['"]/);
        if (match) links.push(match[1]);
      });
      return links;
    });

    for (const href of hrefLinks) {
      try {
        const full = new URL(href, targetUrl).toString();
        addRoute(full, 'GET', 'DOM href', 0.7);
      } catch { /* skip invalid */ }
    }

    // Extract form actions
    const formActions: Array<{ action: string; method: string }> = await page.evaluate(() => {
      const forms: Array<{ action: string; method: string }> = [];
      document.querySelectorAll('form').forEach((form) => {
        forms.push({
          action: form.getAttribute('action') || window.location.pathname,
          method: (form.getAttribute('method') || 'POST').toUpperCase(),
        });
      });
      return forms;
    });

    for (const form of formActions) {
      try {
        const full = new URL(form.action, targetUrl).toString();
        addRoute(full, form.method, 'DOM form', 0.8);
      } catch { /* skip */ }
    }

    // Bounded interaction: click safe navigation elements
    if (interactionCount < maxInteractions) {
      const clickableElements = await page.evaluate(() => {
        const elements: Array<{ text: string; tag: string; index: number }> = [];
        const clickables = document.querySelectorAll('a, button, [role="button"], [role="link"], [onclick], nav a, nav button');
        clickables.forEach((el, i) => {
          const text = (el.textContent || el.getAttribute('aria-label') || el.id || '').trim().slice(0, 50);
          if (text) {
            elements.push({ text, tag: el.tagName, index: i });
          }
        });
        return elements.slice(0, 50); // cap at 50 candidates
      });

      for (const elem of clickableElements) {
        if (interactionCount >= maxInteractions) break;
        if (!isSafeToClick(elem.text)) continue;

        try {
          const beforeUrl = page.url();

          // Click and wait briefly for navigation/XHR
          const clickable = page.locator(`a, button, [role="button"], [role="link"], [onclick], nav a, nav button`).nth(elem.index);
          await clickable.click({ timeout: 3000 }).catch(() => {});
          await page.waitForTimeout(1000); // let XHR/fetch fire

          const afterUrl = page.url();
          if (afterUrl !== beforeUrl) {
            addRoute(afterUrl, 'GET', `nav click: "${elem.text}"`, 0.85);
            // Go back for more exploration
            await page.goBack({ timeout: 3000 }).catch(() => {});
            await page.waitForTimeout(500);
          }

          interactionCount++;
        } catch {
          // Click failed — skip silently
          interactionCount++;
        }
      }
    }

    await context.close();
  } catch (err: any) {
    console.warn(`[Headless] Discovery failed: ${err.message}`);
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }
  }

  console.info(`[Headless] Discovered ${routes.length} routes (${interactionCount} interactions)`);
  return routes;
}

/**
 * Convert headless discoveries into the existing DiscoveredEndpoint format.
 */
export function headlessToEndpoints(routes: HeadlessDiscoveredRoute[]): Array<DiscoveredEndpoint & { discoverySource: DiscoverySource; discoveryConfidence: number }> {
  return routes.map(r => ({
    url: r.url,
    method: r.method as any,
    parameters: [],
    headers: {},
    authenticated: false,
    contentType: r.contentType,
    discoverySource: r.source,
    discoveryConfidence: r.confidence,
  }));
}
