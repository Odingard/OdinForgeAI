import * as https from 'https'
import * as http from 'http'
import type { HeaderIssue, HeaderAnalysisResult } from './types'

// Security headers we expect to see on any well-configured web server
const SECURITY_HEADERS: {
  header: string
  severity: HeaderIssue['severity']
  weight: number
  description: string
  goodValues?: RegExp
}[] = [
  {
    header: 'strict-transport-security',
    severity: 'high',
    weight: 15,
    description: 'HSTS forces browsers to use HTTPS, preventing downgrade attacks',
    goodValues: /max-age=\d{7,}/i  // At least ~115 days
  },
  {
    header: 'content-security-policy',
    severity: 'high',
    weight: 15,
    description: 'CSP prevents XSS and injection attacks by controlling resource loading'
  },
  {
    header: 'x-frame-options',
    severity: 'medium',
    weight: 10,
    description: 'Prevents clickjacking by controlling iframe embedding',
    goodValues: /^(DENY|SAMEORIGIN)$/i
  },
  {
    header: 'x-content-type-options',
    severity: 'medium',
    weight: 10,
    description: 'Prevents MIME-type sniffing attacks',
    goodValues: /^nosniff$/i
  },
  {
    header: 'referrer-policy',
    severity: 'low',
    weight: 5,
    description: 'Controls how much referrer information is sent with requests',
    goodValues: /^(no-referrer|strict-origin|strict-origin-when-cross-origin|same-origin)$/i
  },
  {
    header: 'permissions-policy',
    severity: 'low',
    weight: 5,
    description: 'Controls which browser features the site can use (camera, mic, geolocation, etc.)'
  },
  {
    header: 'x-xss-protection',
    severity: 'info',
    weight: 5,
    description: 'Legacy XSS filter (CSP is preferred, but this is still a good signal)'
  },
  {
    header: 'cross-origin-opener-policy',
    severity: 'low',
    weight: 5,
    description: 'Isolates browsing context to prevent cross-origin attacks'
  },
  {
    header: 'cross-origin-resource-policy',
    severity: 'low',
    weight: 5,
    description: 'Controls which origins can load this resource'
  },
  {
    header: 'cross-origin-embedder-policy',
    severity: 'low',
    weight: 5,
    description: 'Prevents loading cross-origin resources that do not explicitly grant permission'
  },
]

// Headers that leak too much info and should be suppressed
const INFORMATION_LEAKS: { header: string; description: string }[] = [
  { header: 'server', description: 'Server header reveals web server software and version' },
  { header: 'x-powered-by', description: 'X-Powered-By reveals backend framework or language' },
  { header: 'x-aspnet-version', description: 'Reveals ASP.NET runtime version' },
  { header: 'x-aspnetmvc-version', description: 'Reveals ASP.NET MVC version' },
  { header: 'x-generator', description: 'Reveals the CMS or generator used to build the site' },
]

// Fetch headers from a URL
async function fetchHeaders(url: string): Promise<{ statusCode: number; headers: Record<string, string> } | null> {
  return new Promise((resolve) => {
    const client = url.startsWith('https') ? https : http
    const req = client.get(url, { timeout: 8000, rejectUnauthorized: false }, (res) => {
      // Normalize headers to lowercase key → string value
      const headers: Record<string, string> = {}
      for (const [key, value] of Object.entries(res.headers)) {
        headers[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : (value ?? '')
      }
      // Consume the body so the socket closes cleanly
      res.resume()
      res.on('end', () => resolve({ statusCode: res.statusCode ?? 0, headers }))
    })
    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
  })
}

export async function analyzeHeaders(url: string): Promise<HeaderAnalysisResult> {
  const result = await fetchHeaders(url)

  if (!result) {
    return {
      url,
      statusCode: 0,
      headers: {},
      issues: [{
        header: 'connection',
        severity: 'critical',
        status: 'missing',
        detail: `Could not connect to ${url}`
      }],
      securityScore: 0
    }
  }

  const { statusCode, headers } = result
  const issues: HeaderIssue[] = []
  let totalWeight = 0
  let earnedWeight = 0

  // ── Check required security headers ────────────────────────────────────────
  for (const check of SECURITY_HEADERS) {
    totalWeight += check.weight
    const value = headers[check.header]

    if (!value) {
      issues.push({
        header: check.header,
        severity: check.severity,
        status: 'missing',
        detail: `Missing: ${check.description}`
      })
    } else if (check.goodValues && !check.goodValues.test(value)) {
      issues.push({
        header: check.header,
        severity: check.severity,
        status: 'misconfigured',
        detail: `Present but misconfigured: "${value}". ${check.description}`
      })
      earnedWeight += check.weight * 0.5  // Half credit for present-but-bad
    } else {
      earnedWeight += check.weight
      issues.push({
        header: check.header,
        severity: 'info',
        status: 'present',
        detail: `Properly configured: "${value}"`
      })
    }
  }

  // ── Check for information leakage ──────────────────────────────────────────
  for (const leak of INFORMATION_LEAKS) {
    const value = headers[leak.header]
    if (value) {
      issues.push({
        header: leak.header,
        severity: 'low',
        status: 'misconfigured',
        detail: `${leak.description}. Current value: "${value}". Remove or obfuscate this header.`
      })
    }
  }

  // ── Check for insecure cookie flags ────────────────────────────────────────
  const setCookie = headers['set-cookie']
  if (setCookie) {
    if (!setCookie.toLowerCase().includes('secure')) {
      issues.push({
        header: 'set-cookie',
        severity: 'high',
        status: 'weak',
        detail: 'Cookie missing Secure flag — will be sent over unencrypted HTTP'
      })
    }
    if (!setCookie.toLowerCase().includes('httponly')) {
      issues.push({
        header: 'set-cookie',
        severity: 'medium',
        status: 'weak',
        detail: 'Cookie missing HttpOnly flag — accessible to JavaScript (XSS risk)'
      })
    }
    if (!setCookie.toLowerCase().includes('samesite')) {
      issues.push({
        header: 'set-cookie',
        severity: 'medium',
        status: 'weak',
        detail: 'Cookie missing SameSite attribute — vulnerable to CSRF attacks'
      })
    }
  }

  const securityScore = totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 0

  return { url, statusCode, headers, issues, securityScore }
}
