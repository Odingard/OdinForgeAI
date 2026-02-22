import * as https from 'https'
import * as http from 'http'
import type {
  EndpointIssue,
  CorsCheckResult,
  AuthCheckResult,
  LintingCheckResult,
  StalenessCheckResult,
  EndpointCheckResult,
} from './types'

// ─── HTTP Helper ─────────────────────────────────────────────────────────────

interface HttpResponse {
  statusCode: number
  headers: Record<string, string>
  body: string
  responseTime: number
}

// Makes a raw HTTP request with full control over method, headers, and body
async function makeRequest(
  url: string,
  options: { method?: string; headers?: Record<string, string>; body?: string; timeout?: number } = {}
): Promise<HttpResponse | null> {
  const { method = 'GET', headers = {}, body, timeout = 8000 } = options
  const startTime = Date.now()

  return new Promise((resolve) => {
    const parsedUrl = new URL(url)
    const client = parsedUrl.protocol === 'https:' ? https : http

    const reqOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method,
      timeout,
      rejectUnauthorized: false,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; EndpointChecker/1.0)',
        'Accept': 'application/json, text/html, */*',
        ...headers
      }
    }

    const req = client.request(reqOptions, (res) => {
      const resHeaders: Record<string, string> = {}
      for (const [key, value] of Object.entries(res.headers)) {
        resHeaders[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : (value ?? '')
      }
      let resBody = ''
      res.on('data', (chunk) => { resBody += chunk.toString().substring(0, 50000) })
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode ?? 0,
          headers: resHeaders,
          body: resBody,
          responseTime: Date.now() - startTime
        })
      })
    })

    if (body) req.write(body)
    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
    req.end()
  })
}

// ─── CORS Checker ────────────────────────────────────────────────────────────
// Fires a preflight OPTIONS + cross-origin GET to test the CORS policy

async function checkCors(url: string): Promise<CorsCheckResult> {
  const issues: EndpointIssue[] = []

  // Simulate a cross-origin preflight from an attacker domain
  const preflightResponse = await makeRequest(url, {
    method: 'OPTIONS',
    headers: {
      'Origin': 'https://evil-attacker.com',
      'Access-Control-Request-Method': 'GET',
      'Access-Control-Request-Headers': 'Authorization, Content-Type'
    }
  })

  // Also test with a normal GET carrying an Origin header
  const crossOriginResponse = await makeRequest(url, {
    method: 'GET',
    headers: { 'Origin': 'https://evil-attacker.com' }
  })

  // Use whichever response has CORS headers
  const response = preflightResponse ?? crossOriginResponse
  if (!response) {
    return {
      allowOrigin: null, allowMethods: null, allowHeaders: null,
      allowCredentials: false, isWideOpen: false, reflectsOrigin: false, issues: []
    }
  }

  const allowOrigin = response.headers['access-control-allow-origin'] ?? null
  const allowMethods = response.headers['access-control-allow-methods'] ?? null
  const allowHeaders = response.headers['access-control-allow-headers'] ?? null
  const allowCredentials = response.headers['access-control-allow-credentials']?.toLowerCase() === 'true'

  // ── Wide open wildcard ─────────────────────────────────────────────────────
  const isWideOpen = allowOrigin === '*'
  if (isWideOpen) {
    issues.push({
      category: 'cors',
      severity: 'high',
      title: 'CORS: Wildcard Origin (*)',
      detail: 'Access-Control-Allow-Origin is set to *, allowing any website to read responses.',
      remediation: 'Restrict to specific trusted origins. Use a whitelist and validate the Origin header server-side.'
    })
  }

  // ── Origin reflection (reflects attacker domain back) ──────────────────────
  const reflectsOrigin = allowOrigin === 'https://evil-attacker.com'
  if (reflectsOrigin) {
    issues.push({
      category: 'cors',
      severity: 'critical',
      title: 'CORS: Origin Reflection',
      detail: 'Server reflects any Origin header back in Access-Control-Allow-Origin. An attacker\'s site can read authenticated responses.',
      remediation: 'Never blindly reflect the Origin header. Validate against a strict whitelist of trusted domains.'
    })
  }

  // ── Credentials with wildcard or reflection ────────────────────────────────
  if (allowCredentials && (isWideOpen || reflectsOrigin)) {
    issues.push({
      category: 'cors',
      severity: 'critical',
      title: 'CORS: Credentials with Permissive Origin',
      detail: 'Allow-Credentials is true with a permissive origin policy. Attacker sites can make authenticated cross-origin requests and read the responses.',
      remediation: 'Never combine Access-Control-Allow-Credentials: true with wildcard or reflected origins.'
    })
  }

  // ── Dangerous methods exposed ──────────────────────────────────────────────
  if (allowMethods) {
    const dangerous = ['DELETE', 'PUT', 'PATCH']
    const exposed = dangerous.filter(m => allowMethods.toUpperCase().includes(m))
    if (exposed.length > 0) {
      issues.push({
        category: 'cors',
        severity: 'medium',
        title: `CORS: Dangerous Methods Allowed (${exposed.join(', ')})`,
        detail: `Cross-origin requests can use ${exposed.join(', ')} methods.`,
        remediation: 'Only expose the minimum required methods in Access-Control-Allow-Methods.'
      })
    }
  }

  return { allowOrigin, allowMethods, allowHeaders, allowCredentials, isWideOpen, reflectsOrigin, issues }
}

// ─── Auth Checker ────────────────────────────────────────────────────────────
// Tests whether the endpoint requires authentication and what type

async function checkAuth(url: string): Promise<AuthCheckResult> {
  const issues: EndpointIssue[] = []

  // Request with no credentials at all
  const noAuthResponse = await makeRequest(url, { method: 'GET' })
  if (!noAuthResponse) {
    return { requiresAuth: false, authType: 'unknown', acceptsNoAuth: true, weakAuthScheme: false, issues: [] }
  }

  const acceptsNoAuth = noAuthResponse.statusCode >= 200 && noAuthResponse.statusCode < 400
  let authType: AuthCheckResult['authType'] = 'none'
  let requiresAuth = false

  // Check WWW-Authenticate header for auth scheme
  const wwwAuth = noAuthResponse.headers['www-authenticate'] ?? ''
  if (noAuthResponse.statusCode === 401) {
    requiresAuth = true
    if (/Bearer/i.test(wwwAuth)) authType = 'bearer'
    else if (/Basic/i.test(wwwAuth)) authType = 'basic'
    else authType = 'unknown'
  } else if (noAuthResponse.statusCode === 403) {
    requiresAuth = true
    authType = 'unknown'
  }

  // ── No auth required on what looks like a sensitive endpoint ────────────────
  if (acceptsNoAuth) {
    const sensitivePatterns = /\/(admin|user|account|profile|settings|config|internal|private|dashboard|billing|payment)/i
    if (sensitivePatterns.test(url)) {
      issues.push({
        category: 'auth',
        severity: 'critical',
        title: 'No Authentication on Sensitive Endpoint',
        detail: `Endpoint ${url} returns 2xx/3xx without any authentication. This appears to be a sensitive resource.`,
        remediation: 'Implement proper authentication (OAuth 2.0, JWT, or API key) and ensure all sensitive endpoints require valid credentials.'
      })
    } else {
      issues.push({
        category: 'auth',
        severity: 'medium',
        title: 'Endpoint Accessible Without Authentication',
        detail: `Endpoint returns ${noAuthResponse.statusCode} without credentials. Verify this is intentional.`,
        remediation: 'Review whether this endpoint should require authentication.'
      })
    }
  }

  // ── Basic auth is weak ─────────────────────────────────────────────────────
  const weakAuthScheme = authType === 'basic'
  if (weakAuthScheme) {
    issues.push({
      category: 'auth',
      severity: 'high',
      title: 'HTTP Basic Authentication',
      detail: 'Endpoint uses Basic authentication, which transmits credentials as base64 (easily decoded).',
      remediation: 'Migrate to Bearer token (JWT/OAuth 2.0) or API key authentication. If Basic auth is required, ensure HTTPS is enforced.'
    })
  }

  // ── Test with garbage token to check for auth bypass ───────────────────────
  if (requiresAuth) {
    const bypassResponse = await makeRequest(url, {
      method: 'GET',
      headers: { 'Authorization': 'Bearer invalid_garbage_token_12345' }
    })
    if (bypassResponse && bypassResponse.statusCode >= 200 && bypassResponse.statusCode < 400) {
      issues.push({
        category: 'auth',
        severity: 'critical',
        title: 'Authentication Bypass: Invalid Token Accepted',
        detail: 'Endpoint accepted a garbage Bearer token and returned a successful response.',
        remediation: 'Verify token validation logic. Ensure JWT signature verification is properly implemented and tokens are checked against the issuer.'
      })
    }
  }

  return { requiresAuth, authType, acceptsNoAuth, weakAuthScheme, issues }
}

// ─── Linting Checker ─────────────────────────────────────────────────────────
// Checks response format, content-type correctness, rate limiting, HTTPS, versioning

async function checkLinting(url: string): Promise<LintingCheckResult> {
  const issues: EndpointIssue[] = []
  const response = await makeRequest(url)

  if (!response) {
    return {
      hasContentType: false, correctContentType: false, hasRateLimiting: false,
      hasVersioning: false, usesHttps: false, responseFormat: 'unknown', issues: []
    }
  }

  const contentType = response.headers['content-type'] ?? ''
  const hasContentType = contentType.length > 0

  // ── Detect response format ─────────────────────────────────────────────────
  let responseFormat: LintingCheckResult['responseFormat'] = 'unknown'
  if (contentType.includes('json')) responseFormat = 'json'
  else if (contentType.includes('xml')) responseFormat = 'xml'
  else if (contentType.includes('html')) responseFormat = 'html'
  else if (contentType.includes('text')) responseFormat = 'text'
  // Also try to detect by body content
  if (responseFormat === 'unknown' && response.body) {
    const trimmed = response.body.trim()
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) responseFormat = 'json'
    else if (trimmed.startsWith('<?xml') || trimmed.startsWith('<')) responseFormat = 'xml'
  }

  // ── Content-Type correctness ───────────────────────────────────────────────
  let correctContentType = false
  if (responseFormat === 'json' && contentType.includes('application/json')) correctContentType = true
  else if (responseFormat === 'xml' && (contentType.includes('application/xml') || contentType.includes('text/xml'))) correctContentType = true
  else if (responseFormat === 'html' && contentType.includes('text/html')) correctContentType = true

  if (!hasContentType) {
    issues.push({
      category: 'linting',
      severity: 'medium',
      title: 'Missing Content-Type Header',
      detail: 'Response does not include a Content-Type header, making it ambiguous for clients.',
      remediation: 'Always set Content-Type to match the response body (e.g., application/json for JSON APIs).'
    })
  } else if (!correctContentType && responseFormat !== 'unknown') {
    issues.push({
      category: 'linting',
      severity: 'medium',
      title: 'Content-Type Mismatch',
      detail: `Response body appears to be ${responseFormat} but Content-Type is "${contentType}".`,
      remediation: `Set Content-Type to the appropriate MIME type for ${responseFormat} responses.`
    })
  }

  // ── Rate Limiting ──────────────────────────────────────────────────────────
  const rateLimitHeaders = ['x-ratelimit-limit', 'x-rate-limit-limit', 'ratelimit-limit', 'retry-after', 'x-ratelimit-remaining']
  const hasRateLimiting = rateLimitHeaders.some(h => response.headers[h])

  if (!hasRateLimiting) {
    issues.push({
      category: 'linting',
      severity: 'medium',
      title: 'No Rate Limiting Headers',
      detail: 'No rate limiting headers detected. Endpoint may be vulnerable to abuse or DDoS.',
      remediation: 'Implement rate limiting and expose X-RateLimit-Limit / X-RateLimit-Remaining headers.'
    })
  }

  // ── HTTPS ──────────────────────────────────────────────────────────────────
  const usesHttps = url.startsWith('https://')
  if (!usesHttps) {
    issues.push({
      category: 'linting',
      severity: 'high',
      title: 'Endpoint Not Using HTTPS',
      detail: 'Endpoint is served over plain HTTP. All data is transmitted in cleartext.',
      remediation: 'Enforce HTTPS with a valid TLS certificate and redirect all HTTP traffic to HTTPS.'
    })
  }

  // ── API Versioning ─────────────────────────────────────────────────────────
  const hasVersioning = /\/v\d+[/.]/.test(url) || !!(response.headers['api-version'] || response.headers['x-api-version'])
  if (!hasVersioning) {
    issues.push({
      category: 'linting',
      severity: 'low',
      title: 'No API Versioning Detected',
      detail: 'Endpoint URL does not contain a version prefix (e.g., /v1/) and no API-Version header was found.',
      remediation: 'Version your API via URL path (/v1/resource) or a header (API-Version: 2024-01-01).'
    })
  }

  // ── JSON Parse Validation ──────────────────────────────────────────────────
  if (responseFormat === 'json' && response.body) {
    try {
      JSON.parse(response.body)
    } catch {
      issues.push({
        category: 'linting',
        severity: 'medium',
        title: 'Invalid JSON Response',
        detail: 'Content-Type suggests JSON but the response body fails JSON.parse().',
        remediation: 'Ensure the API always returns valid JSON. Check for BOM characters, trailing commas, or unescaped characters.'
      })
    }
  }

  // ── Missing Cache Headers ──────────────────────────────────────────────────
  if (!response.headers['cache-control'] && !response.headers['etag'] && !response.headers['last-modified']) {
    issues.push({
      category: 'linting',
      severity: 'low',
      title: 'No Cache Control Headers',
      detail: 'No Cache-Control, ETag, or Last-Modified headers found.',
      remediation: 'Set appropriate caching headers. For sensitive data use Cache-Control: no-store.'
    })
  }

  return { hasContentType, correctContentType, hasRateLimiting, hasVersioning, usesHttps, responseFormat, issues }
}

// ─── Staleness Checker ───────────────────────────────────────────────────────
// Looks for outdated technology, deprecated headers, and end-of-life software

async function checkStaleness(url: string): Promise<StalenessCheckResult> {
  const issues: EndpointIssue[] = []
  const response = await makeRequest(url)

  if (!response) {
    return { serverVersion: null, deprecatedHeaders: [], outdatedTech: [], lastModified: null, issues: [] }
  }

  const serverVersion = response.headers['server'] ?? null
  const lastModified = response.headers['last-modified'] ?? null
  const deprecatedHeaders: string[] = []
  const outdatedTech: string[] = []

  // ── Deprecated headers that signal old infrastructure ──────────────────────
  const DEPRECATED_HEADER_MAP: Record<string, string> = {
    'x-aspnet-version':     'ASP.NET version header — deprecated, leaks version info',
    'x-aspnetmvc-version':  'ASP.NET MVC version header — deprecated',
    'x-powered-by':         'X-Powered-By — should be removed in production',
    'pragma':               'Pragma: no-cache — use Cache-Control instead (HTTP/1.0 era)',
    'x-xss-protection':     'X-XSS-Protection — deprecated, replaced by Content-Security-Policy',
    'x-ua-compatible':      'X-UA-Compatible — only needed for IE compatibility',
    'p3p':                  'P3P — abandoned privacy standard from the W3C',
    'x-pad':                'X-Pad — ancient Apache bug workaround, should be removed',
  }

  for (const [header, description] of Object.entries(DEPRECATED_HEADER_MAP)) {
    if (response.headers[header]) {
      deprecatedHeaders.push(header)
      issues.push({
        category: 'staleness',
        severity: 'low',
        title: `Deprecated Header: ${header}`,
        detail: `${description}. Current value: "${response.headers[header]}"`,
        remediation: `Remove the ${header} header from server responses.`
      })
    }
  }

  // ── Outdated server versions ───────────────────────────────────────────────
  if (serverVersion) {
    const outdatedPatterns: { pattern: RegExp; tech: string; severity: EndpointIssue['severity'] }[] = [
      { pattern: /Apache\/2\.[0-2]\./i,        tech: 'Apache 2.0-2.2 (EOL)',      severity: 'high' },
      { pattern: /nginx\/1\.([0-9]|1[0-7])\./i, tech: 'Nginx < 1.18 (old)',       severity: 'medium' },
      { pattern: /PHP\/[5-6]\./i,              tech: 'PHP 5.x/6.x (EOL)',          severity: 'critical' },
      { pattern: /PHP\/7\.[0-3]/i,             tech: 'PHP 7.0-7.3 (EOL)',          severity: 'high' },
      { pattern: /Microsoft-IIS\/[5-7]\./i,    tech: 'IIS 5-7 (EOL)',              severity: 'critical' },
      { pattern: /Microsoft-IIS\/8\./i,        tech: 'IIS 8 (old, consider upgrade)', severity: 'medium' },
      { pattern: /openresty\/1\.1[0-5]/i,      tech: 'OpenResty < 1.16 (old)',     severity: 'medium' },
    ]

    for (const { pattern, tech, severity } of outdatedPatterns) {
      if (pattern.test(serverVersion)) {
        outdatedTech.push(tech)
        issues.push({
          category: 'staleness',
          severity,
          title: `Outdated Server: ${tech}`,
          detail: `Server header "${serverVersion}" indicates ${tech}. This version may have known CVEs.`,
          remediation: 'Upgrade to the latest stable version and suppress version info from the Server header.'
        })
      }
    }
  }

  // ── Powered-by version check ───────────────────────────────────────────────
  const poweredBy = response.headers['x-powered-by'] ?? ''
  if (poweredBy) {
    const oldFrameworks: { pattern: RegExp; tech: string }[] = [
      { pattern: /Express/i,       tech: 'Express.js (version exposed)' },
      { pattern: /ASP\.NET/i,      tech: 'ASP.NET (version exposed)' },
      { pattern: /Servlet\/2\./i,  tech: 'Java Servlet 2.x (very old)' },
    ]
    for (const { pattern, tech } of oldFrameworks) {
      if (pattern.test(poweredBy)) {
        outdatedTech.push(tech)
        issues.push({
          category: 'staleness',
          severity: 'medium',
          title: `Technology Exposure: ${tech}`,
          detail: `X-Powered-By: "${poweredBy}" reveals framework details.`,
          remediation: 'Remove the X-Powered-By header in production. In Express: app.disable("x-powered-by").'
        })
      }
    }
  }

  // ── Check Last-Modified for staleness ──────────────────────────────────────
  if (lastModified) {
    const lastModDate = new Date(lastModified)
    const daysSinceUpdate = Math.floor((Date.now() - lastModDate.getTime()) / (1000 * 60 * 60 * 24))
    if (daysSinceUpdate > 365) {
      issues.push({
        category: 'staleness',
        severity: 'medium',
        title: `Stale Content: Last Modified ${daysSinceUpdate} Days Ago`,
        detail: `Last-Modified header is ${lastModified} (${daysSinceUpdate} days ago). This endpoint may be abandoned or unmaintained.`,
        remediation: 'Review whether this endpoint is still needed. Stale endpoints increase attack surface.'
      })
    }
  }

  return { serverVersion, deprecatedHeaders, outdatedTech, lastModified, issues }
}


// ═══════════════════════════════════════════════════════════════════════════════
// MAIN EXPORT: Run all checks against a single endpoint
// ═══════════════════════════════════════════════════════════════════════════════

export async function checkEndpoint(endpoint: string, method: string = 'GET'): Promise<EndpointCheckResult> {
  // Fire all four checks in parallel for speed
  const [cors, auth, linting, staleness] = await Promise.all([
    checkCors(endpoint),
    checkAuth(endpoint),
    checkLinting(endpoint),
    checkStaleness(endpoint),
  ])

  // Aggregate all issues
  const allIssues = [...cors.issues, ...auth.issues, ...linting.issues, ...staleness.issues]
  const criticalCount = allIssues.filter(i => i.severity === 'critical').length
  const highCount = allIssues.filter(i => i.severity === 'high').length

  // Get the response time from a quick ping
  const pingResponse = await makeRequest(endpoint, { method, timeout: 5000 })

  return {
    endpoint,
    method,
    statusCode: pingResponse?.statusCode ?? 0,
    responseTime: pingResponse?.responseTime ?? 0,
    cors,
    auth,
    linting,
    staleness,
    totalIssues: allIssues.length,
    criticalCount,
    highCount
  }
}
