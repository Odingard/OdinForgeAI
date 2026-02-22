import * as https from 'https'
import * as http from 'http'
import type { DiscoveredEndpoint, ApiEndpointDiscoveryResult } from './types'

// Common API paths to brute-force — covers REST conventions, docs, and admin surfaces
const API_WORDLIST = [
  // ── Docs / Specs ───────────────────────────────────────────────────────────
  '/swagger.json', '/swagger/v1/swagger.json', '/swagger-ui.html', '/swagger-ui/',
  '/openapi.json', '/openapi.yaml', '/openapi/v3/api-docs',
  '/api-docs', '/api-docs.json', '/docs', '/redoc',
  '/graphql', '/graphiql', '/playground', '/altair',

  // ── Versioned API roots ────────────────────────────────────────────────────
  '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
  '/v1', '/v2', '/v3', '/v1/', '/v2/', '/v3/',

  // ── Common REST resources ──────────────────────────────────────────────────
  '/api/users', '/api/user', '/api/me', '/api/profile',
  '/api/auth', '/api/auth/login', '/api/auth/register', '/api/auth/token',
  '/api/login', '/api/register', '/api/signup', '/api/logout',
  '/api/health', '/api/healthcheck', '/api/status', '/api/ping', '/api/version',
  '/api/config', '/api/settings', '/api/info',
  '/api/admin', '/api/admin/users', '/api/admin/config',
  '/api/search', '/api/query',
  '/api/upload', '/api/files', '/api/download',
  '/api/webhooks', '/api/callbacks',
  '/api/notifications', '/api/events',
  '/api/payments', '/api/billing', '/api/subscriptions',
  '/api/products', '/api/items', '/api/orders',
  '/api/comments', '/api/posts', '/api/articles',
  '/api/messages', '/api/chat',
  '/api/tokens', '/api/keys', '/api/apikeys',

  // ── Discovery / Meta ───────────────────────────────────────────────────────
  '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
  '/.well-known/openid-configuration', '/.well-known/security.txt',
  '/.well-known/change-password', '/.well-known/jwks.json',
  '/.env', '/config.json', '/package.json', '/composer.json',

  // ── Common admin panels ────────────────────────────────────────────────────
  '/admin', '/admin/', '/dashboard', '/panel', '/console',
  '/wp-admin', '/wp-login.php', '/wp-json/wp/v2/users',

  // ── Debug / Dev leftovers ──────────────────────────────────────────────────
  '/debug', '/debug/vars', '/debug/pprof', '/_debug',
  '/metrics', '/prometheus', '/actuator', '/actuator/health', '/actuator/env',
  '/trace', '/.git/HEAD', '/.git/config',
  '/server-status', '/server-info',
  '/phpinfo.php', '/info.php', '/test.php',
  '/elmah.axd', '/error_log',
]

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']

// Make an HTTP request and return status + content type
async function probeEndpoint(
  baseUrl: string,
  path: string,
  method: string = 'GET'
): Promise<{ statusCode: number; contentType: string | null; headers: Record<string, string> } | null> {
  return new Promise((resolve) => {
    const url = new URL(path, baseUrl)
    const client = url.protocol === 'https:' ? https : http
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method,
      timeout: 5000,
      rejectUnauthorized: false,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
        'Accept': 'application/json, text/html, */*'
      }
    }

    const req = client.request(options, (res) => {
      const headers: Record<string, string> = {}
      for (const [key, value] of Object.entries(res.headers)) {
        headers[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : (value ?? '')
      }
      res.resume()
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode ?? 0,
          contentType: headers['content-type'] ?? null,
          headers
        })
      })
    })

    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
    req.end()
  })
}

// Fetch and parse robots.txt for hidden paths
async function parseRobotsTxt(baseUrl: string): Promise<string[]> {
  return new Promise((resolve) => {
    const url = new URL('/robots.txt', baseUrl)
    const client = url.protocol === 'https:' ? https : http

    client.get(url.toString(), { timeout: 5000, rejectUnauthorized: false }, (res) => {
      let body = ''
      res.on('data', (chunk) => { body += chunk })
      res.on('end', () => {
        const paths: string[] = []
        for (const line of body.split('\n')) {
          const match = line.match(/^(?:Allow|Disallow):\s*(.+)/i)
          if (match) {
            const path = match[1].trim().replace(/\*.*$/, '')
            if (path && path !== '/' && !path.includes('*')) {
              paths.push(path)
            }
          }
        }
        resolve(paths)
      })
    }).on('error', () => resolve([]))
  })
}

// Fetch and parse sitemap.xml for URL paths
async function parseSitemap(baseUrl: string): Promise<string[]> {
  return new Promise((resolve) => {
    const url = new URL('/sitemap.xml', baseUrl)
    const client = url.protocol === 'https:' ? https : http

    client.get(url.toString(), { timeout: 5000, rejectUnauthorized: false }, (res) => {
      let body = ''
      res.on('data', (chunk) => { body += chunk })
      res.on('end', () => {
        const paths: string[] = []
        const urlMatches = Array.from(body.matchAll(/<loc>([^<]+)<\/loc>/gi))
        for (const match of urlMatches) {
          try {
            const parsedUrl = new URL(match[1])
            if (parsedUrl.pathname !== '/') paths.push(parsedUrl.pathname)
          } catch { /* skip malformed URLs */ }
        }
        resolve(paths)
      })
    }).on('error', () => resolve([]))
  })
}

// Scrape JavaScript files for API path patterns
async function scrapeJsForEndpoints(baseUrl: string): Promise<string[]> {
  return new Promise((resolve) => {
    const client = baseUrl.startsWith('https') ? https : http
    client.get(baseUrl, { timeout: 8000, rejectUnauthorized: false }, (res) => {
      let body = ''
      res.on('data', (chunk) => { body += chunk.toString().substring(0, 200000) })
      res.on('end', () => {
        const paths = new Set<string>()
        // Match API-looking paths in JavaScript source and inline scripts
        const patterns = [
          /["'`](\/api\/[a-zA-Z0-9/_-]+)["'`]/g,
          /["'`](\/v[0-9]+\/[a-zA-Z0-9/_-]+)["'`]/g,
          /fetch\(["'`]([^"'`]+)["'`]/g,
          /axios\.[a-z]+\(["'`]([^"'`]+)["'`]/g,
          /\.(?:get|post|put|delete|patch)\(["'`]([^"'`]+)["'`]/g,
        ]
        for (const pattern of patterns) {
          for (const match of Array.from(body.matchAll(pattern))) {
            const path = match[1]
            if (path.startsWith('/') && !path.includes('..') && path.length < 200) {
              paths.add(path)
            }
          }
        }
        resolve(Array.from(paths))
      })
    }).on('error', () => resolve([]))
  })
}

export async function analyzeApiEndpoints(
  baseUrl: string,
  options: { concurrency?: number; methods?: boolean } = {}
): Promise<ApiEndpointDiscoveryResult> {
  const { concurrency = 15, methods = false } = options
  const endpoints: DiscoveredEndpoint[] = []
  const seen = new Set<string>()

  let hasSwagger = false
  let hasOpenApi = false

  // Gather paths from all passive sources
  const [robotsPaths, sitemapPaths, jsPaths] = await Promise.all([
    parseRobotsTxt(baseUrl),
    parseSitemap(baseUrl),
    scrapeJsForEndpoints(baseUrl)
  ])

  // Build the combined candidate list with source tracking
  const candidates: { path: string; source: DiscoveredEndpoint['source'] }[] = []

  for (const path of API_WORDLIST)   candidates.push({ path, source: 'wordlist' })
  for (const path of robotsPaths)    candidates.push({ path, source: 'robots' })
  for (const path of sitemapPaths)   candidates.push({ path, source: 'sitemap' })
  for (const path of jsPaths)        candidates.push({ path, source: 'js-scrape' })

  // Deduplicate
  const unique = candidates.filter(c => {
    if (seen.has(c.path)) return false
    seen.add(c.path)
    return true
  })

  // Probe all candidates in batches
  for (let i = 0; i < unique.length; i += concurrency) {
    const batch = unique.slice(i, i + concurrency)
    const results = await Promise.all(
      batch.map(async (candidate) => {
        const result = await probeEndpoint(baseUrl, candidate.path)
        if (!result) return null
        // Skip obvious 404s and errors, but keep redirects (3xx) and auth-required (401/403)
        if (result.statusCode === 404 || result.statusCode === 0 || result.statusCode >= 500) return null

        // Tag swagger/openapi
        if (candidate.path.includes('swagger')) hasSwagger = true
        if (candidate.path.includes('openapi')) hasOpenApi = true

        return {
          url: `${baseUrl}${candidate.path}`,
          method: 'GET',
          statusCode: result.statusCode,
          contentType: result.contentType,
          source: candidate.source
        } as DiscoveredEndpoint
      })
    )

    for (const result of results) {
      if (result) endpoints.push(result)
    }
  }

  // Optionally test other HTTP methods on discovered endpoints
  if (methods) {
    const methodEndpoints: DiscoveredEndpoint[] = []
    for (const ep of endpoints.slice(0, 30)) { // Limit to avoid being too noisy
      const path = new URL(ep.url).pathname
      for (const method of HTTP_METHODS) {
        if (method === 'GET') continue
        const result = await probeEndpoint(baseUrl, path, method)
        if (result && result.statusCode !== 404 && result.statusCode !== 405) {
          methodEndpoints.push({
            url: ep.url,
            method,
            statusCode: result.statusCode,
            contentType: result.contentType,
            source: ep.source
          })
        }
      }
    }
    endpoints.push(...methodEndpoints)
  }

  return {
    baseUrl,
    endpoints,
    totalDiscovered: endpoints.length,
    hasSwagger,
    hasOpenApi
  }
}
