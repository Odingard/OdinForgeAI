// ═══════════════════════════════════════════════════════════════════════════════
//  OdinForge Multi-Source Passive Subdomain Discovery
//
//  Queries 6 free, no-API-key OSINT sources in parallel. Each source has
//  independent timeout and graceful failure — one source down doesn't kill
//  discovery. Deduplicates all results into a single Set.
//
//  Sources:
//   1. crt.sh           — Certificate Transparency logs
//   2. HackerTarget     — DNS lookups, host search
//   3. AlienVault OTX   — Passive DNS intelligence
//   4. URLScan.io       — Web scanning archive
//   5. ThreatMiner      — Threat intelligence platform
//   6. RapidDNS         — Fast DNS database
// ═══════════════════════════════════════════════════════════════════════════════

import * as https from 'https'
import * as http from 'http'

const SOURCE_TIMEOUT = 15000 // 15s per source

export interface PassiveSourceResult {
  source: string
  subdomains: string[]
  duration: number
  error?: string
}

export interface PassiveDiscoveryResult {
  domain: string
  subdomains: string[]
  totalUnique: number
  sources: PassiveSourceResult[]
  duration: number
}

// ── Helper: HTTP(S) GET with timeout ────────────────────────────────────────

function fetchUrl(url: string, timeout = SOURCE_TIMEOUT): Promise<string> {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http
    const req = mod.get(url, {
      timeout,
      headers: { 'User-Agent': 'OdinForge-Recon/2.0' },
      ...(url.startsWith('https') ? { rejectUnauthorized: true } : {}),
    }, (res) => {
      // Follow redirects (301/302)
      if (res.statusCode && [301, 302].includes(res.statusCode) && res.headers.location) {
        fetchUrl(res.headers.location, timeout).then(resolve).catch(reject)
        res.resume()
        return
      }
      let body = ''
      res.on('data', (chunk) => { body += chunk.toString() })
      res.on('end', () => resolve(body))
    })
    req.on('error', reject)
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')) })
  })
}

// ── Helper: Clean and validate subdomain ────────────────────────────────────

function cleanSubdomain(raw: string, domain: string): string | null {
  const cleaned = raw.toLowerCase().trim().replace(/^\*\./, '').replace(/\.$/, '')
  // Must end with the target domain and not BE the domain
  if (!cleaned.endsWith(domain) || cleaned === domain) return null
  // No wildcards, spaces, or special chars in the subdomain part
  if (/[*\s@!#$%^&()+=]/.test(cleaned)) return null
  // Reasonable length
  if (cleaned.length > 253) return null
  return cleaned
}

// ── Source 1: crt.sh (Certificate Transparency) ─────────────────────────────

async function queryCrtSh(domain: string): Promise<PassiveSourceResult> {
  const start = Date.now()
  try {
    const body = await fetchUrl(`https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`)
    const entries = JSON.parse(body)
    const subs = new Set<string>()
    for (const entry of entries) {
      const names = (entry.name_value || '').split('\n')
      for (const name of names) {
        const clean = cleanSubdomain(name, domain)
        if (clean) subs.add(clean)
      }
    }
    return { source: 'crt.sh', subdomains: Array.from(subs), duration: Date.now() - start }
  } catch (e: any) {
    return { source: 'crt.sh', subdomains: [], duration: Date.now() - start, error: e.message }
  }
}

// ── Source 2: HackerTarget ──────────────────────────────────────────────────

async function queryHackerTarget(domain: string): Promise<PassiveSourceResult> {
  const start = Date.now()
  try {
    const body = await fetchUrl(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`)
    if (body.startsWith('error') || body.includes('API count exceeded')) {
      return { source: 'hackertarget', subdomains: [], duration: Date.now() - start, error: body.trim() }
    }
    const subs = new Set<string>()
    const lines = body.split('\n')
    for (const line of lines) {
      const parts = line.split(',')
      if (parts[0]) {
        const clean = cleanSubdomain(parts[0], domain)
        if (clean) subs.add(clean)
      }
    }
    return { source: 'hackertarget', subdomains: Array.from(subs), duration: Date.now() - start }
  } catch (e: any) {
    return { source: 'hackertarget', subdomains: [], duration: Date.now() - start, error: e.message }
  }
}

// ── Source 3: AlienVault OTX ────────────────────────────────────────────────

async function queryAlienVaultOTX(domain: string): Promise<PassiveSourceResult> {
  const start = Date.now()
  try {
    const body = await fetchUrl(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`)
    const data = JSON.parse(body)
    const subs = new Set<string>()
    if (data.passive_dns && Array.isArray(data.passive_dns)) {
      for (const entry of data.passive_dns) {
        const hostname = entry.hostname || entry.address || ''
        const clean = cleanSubdomain(hostname, domain)
        if (clean) subs.add(clean)
      }
    }
    return { source: 'alienvault-otx', subdomains: Array.from(subs), duration: Date.now() - start }
  } catch (e: any) {
    return { source: 'alienvault-otx', subdomains: [], duration: Date.now() - start, error: e.message }
  }
}

// ── Source 4: URLScan.io ────────────────────────────────────────────────────

async function queryUrlScan(domain: string): Promise<PassiveSourceResult> {
  const start = Date.now()
  try {
    const body = await fetchUrl(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=1000`)
    const data = JSON.parse(body)
    const subs = new Set<string>()
    if (data.results && Array.isArray(data.results)) {
      for (const result of data.results) {
        const pageHost = result.page?.domain || ''
        const clean = cleanSubdomain(pageHost, domain)
        if (clean) subs.add(clean)

        // Also extract from task URL
        const taskHost = result.task?.domain || ''
        const taskClean = cleanSubdomain(taskHost, domain)
        if (taskClean) subs.add(taskClean)
      }
    }
    return { source: 'urlscan.io', subdomains: Array.from(subs), duration: Date.now() - start }
  } catch (e: any) {
    return { source: 'urlscan.io', subdomains: [], duration: Date.now() - start, error: e.message }
  }
}

// ── Source 5: ThreatMiner ───────────────────────────────────────────────────

async function queryThreatMiner(domain: string): Promise<PassiveSourceResult> {
  const start = Date.now()
  try {
    const body = await fetchUrl(`https://api.threatminer.org/v2/domain.php?q=${encodeURIComponent(domain)}&rt=5`)
    const data = JSON.parse(body)
    const subs = new Set<string>()
    if (data.status_code === '200' && data.results && Array.isArray(data.results)) {
      for (const sub of data.results) {
        const clean = cleanSubdomain(String(sub), domain)
        if (clean) subs.add(clean)
      }
    }
    return { source: 'threatminer', subdomains: Array.from(subs), duration: Date.now() - start }
  } catch (e: any) {
    return { source: 'threatminer', subdomains: [], duration: Date.now() - start, error: e.message }
  }
}

// ── Source 6: RapidDNS ──────────────────────────────────────────────────────

async function queryRapidDns(domain: string): Promise<PassiveSourceResult> {
  const start = Date.now()
  try {
    const body = await fetchUrl(`https://rapiddns.io/subdomain/${encodeURIComponent(domain)}?full=1`)
    const subs = new Set<string>()
    // Parse HTML table rows: <td>subdomain.domain.com</td>
    const regex = /<td>([a-zA-Z0-9._-]+\.[a-zA-Z]+)<\/td>/g
    let match: RegExpExecArray | null
    while ((match = regex.exec(body)) !== null) {
      const clean = cleanSubdomain(match[1], domain)
      if (clean) subs.add(clean)
    }
    return { source: 'rapiddns', subdomains: Array.from(subs), duration: Date.now() - start }
  } catch (e: any) {
    return { source: 'rapiddns', subdomains: [], duration: Date.now() - start, error: e.message }
  }
}

// ── Master: Run All Sources in Parallel ─────────────────────────────────────

export async function discoverSubdomainsPassive(domain: string): Promise<PassiveDiscoveryResult> {
  const start = Date.now()

  console.log(`[RECON:PASSIVE] Querying 6 OSINT sources for ${domain}...`)

  // All sources run in parallel — each has its own timeout
  const sourceResults = await Promise.all([
    queryCrtSh(domain),
    queryHackerTarget(domain),
    queryAlienVaultOTX(domain),
    queryUrlScan(domain),
    queryThreatMiner(domain),
    queryRapidDns(domain),
  ])

  // Deduplicate across all sources
  const allSubs = new Set<string>()
  for (const result of sourceResults) {
    for (const sub of result.subdomains) {
      allSubs.add(sub)
    }
    const status = result.error ? `ERR: ${result.error}` : `${result.subdomains.length} found`
    console.log(`[RECON:PASSIVE] ${result.source}: ${status} (${result.duration}ms)`)
  }

  const totalUnique = allSubs.size
  console.log(`[RECON:PASSIVE] Total unique subdomains from passive sources: ${totalUnique}`)

  return {
    domain,
    subdomains: Array.from(allSubs),
    totalUnique,
    sources: sourceResults,
    duration: Date.now() - start,
  }
}
