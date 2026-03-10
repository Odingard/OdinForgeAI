import * as https from 'https'
import * as http from 'http'
import { URL } from 'url'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SecretType =
  | 'aws_access_key'
  | 'aws_secret_key'
  | 'api_key'
  | 'bearer_token'
  | 'jwt_token'
  | 'private_key'
  | 'database_url'
  | 'oauth_secret'
  | 'internal_url'
  | 'hardcoded_password'
  | 'github_token'
  | 'slack_token'
  | 'stripe_key'
  | 'sendgrid_key'
  | 'twilio_key'
  | 'firebase_key'
  | 'google_api_key'

export interface ExtractedSecret {
  type: SecretType
  /** Redacted value — first/last 4 chars visible */
  value: string
  /** Full value for in-memory validation only — NEVER persisted */
  rawValue: string
  /** Surrounding code snippet, ~80 chars */
  context: string
  /** URL where the secret was found */
  source: string
  /** 0-100 confidence that this is a real secret */
  confidence: number
  severity: 'critical' | 'high' | 'medium' | 'low'
}

interface PatternEntry {
  type: SecretType
  pattern: RegExp
  severity: 'critical' | 'high' | 'medium' | 'low'
  confidence: number
}

// ---------------------------------------------------------------------------
// Pattern library — 32 patterns covering common secret categories
// ---------------------------------------------------------------------------

export const SECRET_PATTERNS: PatternEntry[] = [
  // AWS
  { type: 'aws_access_key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical', confidence: 95 },
  { type: 'aws_secret_key', pattern: /(?:aws_secret_access_key|aws_secret|AWS_SECRET)['":\s]*[=:]\s*['"]([A-Za-z0-9/+=]{40})['"]/g, severity: 'critical', confidence: 90 },
  { type: 'aws_secret_key', pattern: /(?:secret_access_key)\s*=\s*([A-Za-z0-9/+=]{40})/g, severity: 'critical', confidence: 85 },

  // JWT
  { type: 'jwt_token', pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, severity: 'high', confidence: 90 },

  // GitHub
  { type: 'github_token', pattern: /gh[ps]_[A-Za-z0-9_]{36,}/g, severity: 'critical', confidence: 95 },
  { type: 'github_token', pattern: /github_pat_[A-Za-z0-9_]{22,}/g, severity: 'critical', confidence: 95 },

  // Slack
  { type: 'slack_token', pattern: /xox[bpras]-[A-Za-z0-9-]+/g, severity: 'high', confidence: 90 },
  { type: 'slack_token', pattern: /xapp-[0-9]+-[A-Za-z0-9-]+/g, severity: 'high', confidence: 85 },

  // Stripe
  { type: 'stripe_key', pattern: /sk_live_[A-Za-z0-9]{24,}/g, severity: 'critical', confidence: 95 },
  { type: 'stripe_key', pattern: /pk_live_[A-Za-z0-9]{24,}/g, severity: 'medium', confidence: 80 },
  { type: 'stripe_key', pattern: /rk_live_[A-Za-z0-9]{24,}/g, severity: 'critical', confidence: 90 },

  // SendGrid
  { type: 'sendgrid_key', pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, severity: 'critical', confidence: 95 },

  // Twilio
  { type: 'twilio_key', pattern: /SK[a-f0-9]{32}/g, severity: 'high', confidence: 80 },
  { type: 'twilio_key', pattern: /AC[a-f0-9]{32}/g, severity: 'high', confidence: 75 },

  // Firebase / Google
  { type: 'firebase_key', pattern: /AIza[A-Za-z0-9_-]{35}/g, severity: 'high', confidence: 85 },
  { type: 'google_api_key', pattern: /AIza[A-Za-z0-9_\\-]{35}/g, severity: 'high', confidence: 85 },
  { type: 'google_api_key', pattern: /ya29\.[A-Za-z0-9_-]+/g, severity: 'high', confidence: 80 },

  // Private keys
  { type: 'private_key', pattern: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/g, severity: 'critical', confidence: 98 },
  { type: 'private_key', pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g, severity: 'critical', confidence: 98 },

  // Database URLs
  { type: 'database_url', pattern: /(mongodb|postgres|postgresql|mysql|redis|amqp):\/\/[^\s'"]+/g, severity: 'critical', confidence: 90 },
  { type: 'database_url', pattern: /(?:DATABASE_URL|DB_URI|MONGO_URI)['":\s]*[=:]\s*['"]([^\s'"]+)['"]/g, severity: 'critical', confidence: 85 },

  // Generic API keys
  { type: 'api_key', pattern: /api[_-]?key['":\s]*[=:]\s*['"]([A-Za-z0-9_-]{16,})['"]/gi, severity: 'high', confidence: 70 },
  { type: 'api_key', pattern: /(?:apikey|api_token|access_token)\s*[:=]\s*['"]([A-Za-z0-9_-]{20,})['"]/gi, severity: 'high', confidence: 70 },
  { type: 'api_key', pattern: /x-api-key['":\s]*[=:]\s*['"]([A-Za-z0-9_-]{16,})['"]/gi, severity: 'high', confidence: 75 },

  // Bearer tokens in source
  { type: 'bearer_token', pattern: /[Bb]earer\s+[A-Za-z0-9_-]{20,}/g, severity: 'high', confidence: 80 },
  { type: 'bearer_token', pattern: /[Aa]uthorization['":\s]*[=:]\s*['"]Bearer\s+[A-Za-z0-9_-]{20,}['"]/g, severity: 'high', confidence: 85 },

  // Hardcoded passwords
  { type: 'hardcoded_password', pattern: /password\s*[:=]\s*['"][^'"]{4,}['"]/gi, severity: 'high', confidence: 65 },
  { type: 'hardcoded_password', pattern: /passwd\s*[:=]\s*['"][^'"]{4,}['"]/gi, severity: 'high', confidence: 65 },

  // OAuth secrets
  { type: 'oauth_secret', pattern: /client[_-]?secret\s*[:=]\s*['"]([A-Za-z0-9_-]{16,})['"]/gi, severity: 'high', confidence: 80 },
  { type: 'oauth_secret', pattern: /(?:OAUTH|AUTH0)_SECRET\s*[:=]\s*['"]([A-Za-z0-9_-]{16,})['"]/gi, severity: 'high', confidence: 80 },

  // Internal URLs
  { type: 'internal_url', pattern: /https?:\/\/(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s'"]*/g, severity: 'medium', confidence: 75 },
  { type: 'internal_url', pattern: /https?:\/\/[a-z0-9-]+\.internal[^\s'"]*/g, severity: 'medium', confidence: 70 },
]

// ---------------------------------------------------------------------------
// Severity ordering for sort
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Redact a secret for safe storage: show first 4 and last 4 chars.
 * Short values (<=10 chars) show first 2 and last 2.
 */
export function redactSecret(value: string): string {
  if (value.length <= 8) {
    return value.slice(0, 2) + '****' + value.slice(-2)
  }
  return value.slice(0, 4) + '****' + value.slice(-4)
}

/**
 * Extract a context snippet (~80 chars) around a match position.
 */
function extractContext(source: string, matchIndex: number, matchLength: number): string {
  const pad = Math.max(0, Math.floor((80 - matchLength) / 2))
  const start = Math.max(0, matchIndex - pad)
  const end = Math.min(source.length, matchIndex + matchLength + pad)
  let snippet = source.slice(start, end).replace(/\n/g, ' ').replace(/\s+/g, ' ')
  if (snippet.length > 80) {
    snippet = snippet.slice(0, 80)
  }
  return snippet
}

/**
 * Fetch a URL body as a string. Returns empty string on failure.
 */
function fetchText(url: string, timeoutMs = 10_000): Promise<string> {
  return new Promise((resolve) => {
    const parsedUrl = new URL(url)
    const transport = parsedUrl.protocol === 'https:' ? https : http

    const req = transport.get(
      url,
      {
        timeout: timeoutMs,
        headers: {
          'User-Agent': 'OdinForge-Recon/1.0',
          Accept: 'text/html,application/javascript,*/*',
        },
        rejectUnauthorized: false,
      },
      (res) => {
        // Follow one redirect
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          const redirectUrl = new URL(res.headers.location, url).toString()
          res.resume()
          fetchText(redirectUrl, timeoutMs).then(resolve)
          return
        }

        if (res.statusCode && res.statusCode >= 400) {
          res.resume()
          resolve('')
          return
        }

        const chunks: Buffer[] = []
        let size = 0
        const maxSize = 5 * 1024 * 1024 // 5 MB cap per resource

        res.on('data', (chunk: Buffer) => {
          size += chunk.length
          if (size > maxSize) {
            res.destroy()
            resolve(Buffer.concat(chunks).toString('utf-8'))
            return
          }
          chunks.push(chunk)
        })

        res.on('end', () => {
          resolve(Buffer.concat(chunks).toString('utf-8'))
        })

        res.on('error', () => resolve(''))
      },
    )

    req.on('timeout', () => {
      req.destroy()
      resolve('')
    })

    req.on('error', () => resolve(''))
  })
}

/**
 * Extract <script src="..."> URLs from HTML.
 */
function extractScriptUrls(html: string, baseUrl: string): string[] {
  const urls: string[] = []
  const regex = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi
  let match: RegExpExecArray | null
  while ((match = regex.exec(html)) !== null) {
    const src = match[1]
    if (!src) continue
    try {
      const resolved = new URL(src, baseUrl).toString()
      urls.push(resolved)
    } catch {
      // Malformed URL — skip
    }
  }
  return urls
}

/**
 * Run all patterns against a text body and return unique secrets.
 */
function scanText(text: string, sourceUrl: string): ExtractedSecret[] {
  const results: ExtractedSecret[] = []

  for (const entry of SECRET_PATTERNS) {
    // Reset the regex (global flag means lastIndex persists)
    const regex = new RegExp(entry.pattern.source, entry.pattern.flags)
    let match: RegExpExecArray | null

    while ((match = regex.exec(text)) !== null) {
      // Use the first capture group if present, otherwise the full match
      const rawValue = match[1] ?? match[0]

      // Skip very short matches — likely false positives
      if (rawValue.length < 8) continue

      // Skip obvious placeholders
      if (/^(example|test|dummy|placeholder|your[_-]?|xxx|changeme)/i.test(rawValue)) continue
      if (/^['"]?\$\{/.test(rawValue)) continue // template literals like ${API_KEY}

      results.push({
        type: entry.type,
        value: redactSecret(rawValue),
        rawValue,
        context: extractContext(text, match.index, match[0].length),
        source: sourceUrl,
        confidence: entry.confidence,
        severity: entry.severity,
      })

      // Cap per pattern to avoid runaway matches in minified bundles
      if (results.length > 500) break
    }
  }

  return results
}

/**
 * Deduplicate secrets by rawValue, keeping the highest-confidence instance.
 */
function deduplicateSecrets(secrets: ExtractedSecret[]): ExtractedSecret[] {
  const seen = new Map<string, ExtractedSecret>()

  for (const secret of secrets) {
    const key = `${secret.type}:${secret.rawValue}`
    const existing = seen.get(key)
    if (!existing || secret.confidence > existing.confidence) {
      seen.set(key, secret)
    }
  }

  return Array.from(seen.values())
}

/**
 * Sort secrets by severity (critical first), then by confidence (highest first).
 */
function sortSecrets(secrets: ExtractedSecret[]): ExtractedSecret[] {
  return secrets.sort((a, b) => {
    const sevDiff = (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3)
    if (sevDiff !== 0) return sevDiff
    return b.confidence - a.confidence
  })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Crawl a single URL: fetch the page HTML, discover linked JS bundles,
 * and scan all content for leaked secrets.
 */
export async function extractSecretsFromUrl(url: string): Promise<ExtractedSecret[]> {
  const html = await fetchText(url)
  if (!html) return []

  // Scan the HTML itself
  const secrets: ExtractedSecret[] = scanText(html, url)

  // Discover and fetch JS bundles
  const scriptUrls = extractScriptUrls(html, url)
  const uniqueScripts = Array.from(new Set(scriptUrls)).slice(0, 20)

  const jsResults = await Promise.allSettled(
    uniqueScripts.map(async (scriptUrl) => {
      const jsBody = await fetchText(scriptUrl)
      if (!jsBody) return []
      return scanText(jsBody, scriptUrl)
    }),
  )

  for (const result of jsResults) {
    if (result.status === 'fulfilled') {
      secrets.push(...result.value)
    }
  }

  return sortSecrets(deduplicateSecrets(secrets))
}

/**
 * Batch-process alive subdomains for secret extraction.
 *
 * @param subdomains - List of subdomains with alive status
 * @param concurrency - Max parallel requests (default 5)
 * @returns Map of subdomain hostname -> extracted secrets
 */
export async function extractSecretsFromSubdomains(
  subdomains: { subdomain: string; isAlive: boolean }[],
  concurrency = 5,
): Promise<Map<string, ExtractedSecret[]>> {
  const results = new Map<string, ExtractedSecret[]>()
  const alive = subdomains.filter((s) => s.isAlive)

  // Process in batches to respect concurrency limit
  for (let i = 0; i < alive.length; i += concurrency) {
    const batch = alive.slice(i, i + concurrency)

    const batchResults = await Promise.allSettled(
      batch.map(async (sub) => {
        const targetUrl = `https://${sub.subdomain}`
        try {
          const secrets = await extractSecretsFromUrl(targetUrl)
          return { subdomain: sub.subdomain, secrets }
        } catch {
          // If HTTPS fails, try HTTP
          try {
            const secrets = await extractSecretsFromUrl(`http://${sub.subdomain}`)
            return { subdomain: sub.subdomain, secrets }
          } catch {
            return { subdomain: sub.subdomain, secrets: [] }
          }
        }
      }),
    )

    for (const result of batchResults) {
      if (result.status === 'fulfilled') {
        const { subdomain, secrets } = result.value
        if (secrets.length > 0) {
          results.set(subdomain, secrets)
        }
      }
    }
  }

  return results
}
