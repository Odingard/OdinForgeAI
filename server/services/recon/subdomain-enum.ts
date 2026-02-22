import * as dns from 'dns'
import * as https from 'https'
import * as http from 'http'
import { promisify } from 'util'
import type { SubdomainResult, SubdomainEnumResult } from './types'

const resolve4 = promisify(dns.resolve4)

// Common subdomain prefixes used by most organizations
const COMMON_SUBDOMAINS = [
  'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail',
  'api', 'api-v1', 'api-v2', 'api-staging', 'api-dev', 'api-internal',
  'dev', 'staging', 'stage', 'test', 'qa', 'uat', 'sandbox',
  'admin', 'panel', 'dashboard', 'portal', 'console', 'manage',
  'app', 'application', 'mobile', 'cdn', 'static', 'assets', 'media',
  'blog', 'docs', 'wiki', 'help', 'support', 'status',
  'git', 'gitlab', 'github', 'bitbucket', 'jenkins', 'ci', 'cd',
  'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'cache',
  'vpn', 'remote', 'gateway', 'proxy', 'lb', 'loadbalancer',
  'ns1', 'ns2', 'dns', 'mx', 'relay',
  'auth', 'sso', 'login', 'oauth', 'identity',
  'monitoring', 'grafana', 'prometheus', 'kibana', 'elastic', 'logs',
  'backup', 'bak', 'old', 'legacy', 'archive',
  's3', 'storage', 'bucket', 'files', 'upload',
  'internal', 'intranet', 'corp', 'private', 'secure',
  'shop', 'store', 'checkout', 'payment', 'pay',
  'graphql', 'rest', 'rpc', 'ws', 'websocket', 'socket',
  'demo', 'preview', 'beta', 'alpha', 'canary',
  'k8s', 'kubernetes', 'docker', 'registry', 'helm',
  'vault', 'secrets', 'config', 'env',
]

// Resolve a subdomain to an IP, returns null if it doesn't exist
async function resolveSubdomain(subdomain: string): Promise<string | null> {
  try {
    const addresses = await resolve4(subdomain)
    return addresses[0] ?? null
  } catch {
    return null
  }
}

// Quick HTTP probe to check if the subdomain serves a live web service
async function probeHttp(subdomain: string): Promise<{ statusCode: number | null; title: string | null }> {
  return new Promise((resolve) => {
    const req = https.get(`https://${subdomain}`, { timeout: 3000, rejectUnauthorized: false }, (res) => {
      let body = ''
      res.on('data', (chunk) => { body += chunk.toString().substring(0, 2000) })
      res.on('end', () => {
        const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i)
        resolve({ statusCode: res.statusCode ?? null, title: titleMatch?.[1]?.trim() ?? null })
      })
    })
    req.on('error', () => {
      // Fall back to HTTP if HTTPS fails
      const httpReq = http.get(`http://${subdomain}`, { timeout: 3000 }, (res) => {
        let body = ''
        res.on('data', (chunk) => { body += chunk.toString().substring(0, 2000) })
        res.on('end', () => {
          const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i)
          resolve({ statusCode: res.statusCode ?? null, title: titleMatch?.[1]?.trim() ?? null })
        })
      })
      httpReq.on('error', () => resolve({ statusCode: null, title: null }))
      httpReq.on('timeout', () => { httpReq.destroy(); resolve({ statusCode: null, title: null }) })
    })
    req.on('timeout', () => { req.destroy() })
  })
}

// Scrape Certificate Transparency logs for known subdomains
async function queryCrtSh(domain: string): Promise<string[]> {
  return new Promise((resolve) => {
    https.get(`https://crt.sh/?q=%.${domain}&output=json`, { timeout: 10000 }, (res) => {
      let body = ''
      res.on('data', (chunk) => { body += chunk })
      res.on('end', () => {
        try {
          const entries = JSON.parse(body)
          const subdomains = new Set<string>()
          for (const entry of entries) {
            const names = (entry.name_value || '').split('\n')
            for (const name of names) {
              const clean = name.trim().replace(/^\*\./, '')
              if (clean.endsWith(domain) && clean !== domain) {
                subdomains.add(clean)
              }
            }
          }
          resolve(Array.from(subdomains))
        } catch {
          resolve([])
        }
      })
    }).on('error', () => resolve([]))
  })
}

export async function analyzeSubdomains(
  domain: string,
  options: { useCrt?: boolean; customWordlist?: string[]; concurrency?: number } = {}
): Promise<SubdomainEnumResult> {
  const { useCrt = true, customWordlist, concurrency = 20 } = options
  const subdomains: SubdomainResult[] = []
  const seen = new Set<string>()

  // Build the full list of subdomains to check
  const candidates: string[] = []

  // Wordlist-based enumeration
  const wordlist = customWordlist ?? COMMON_SUBDOMAINS
  for (const prefix of wordlist) {
    candidates.push(`${prefix}.${domain}`)
  }

  // Certificate Transparency passive discovery
  if (useCrt) {
    const ctSubdomains = await queryCrtSh(domain)
    for (const sub of ctSubdomains) {
      if (!candidates.includes(sub)) candidates.push(sub)
    }
  }

  // Process candidates in batches to avoid slamming DNS
  for (let i = 0; i < candidates.length; i += concurrency) {
    const batch = candidates.slice(i, i + concurrency)
    const results = await Promise.all(
      batch.map(async (candidate): Promise<SubdomainResult | null> => {
        if (seen.has(candidate)) return null
        seen.add(candidate)

        const ip = await resolveSubdomain(candidate)
        if (!ip) return null

        const { statusCode, title } = await probeHttp(candidate)

        return {
          subdomain: candidate,
          ip,
          statusCode,
          title,
          isAlive: statusCode !== null
        }
      })
    )
    for (const result of results) {
      if (result) subdomains.push(result)
    }
  }

  return {
    domain,
    subdomains,
    totalFound: subdomains.length,
    aliveCount: subdomains.filter(s => s.isAlive).length
  }
}
