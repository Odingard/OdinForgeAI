// ═══════════════════════════════════════════════════════════════════════════════
//  OdinForge Professional Subdomain Enumeration Engine v2.0
//
//  Multi-phase discovery pipeline:
//   Phase 1: Passive OSINT (6 sources in parallel) — no DNS noise
//   Phase 2: Active DNS brute-force (10K+ professional wordlist)
//   Phase 3: Permutation engine (mutations from discovered subdomains)
//   Phase 4: Wildcard detection + filtering
//   Phase 5: HTTP probing + fingerprinting
//
//  Designed to find 150+ subdomains that other tools miss.
// ═══════════════════════════════════════════════════════════════════════════════

import * as dns from 'dns'
import * as https from 'https'
import * as http from 'http'
import { promisify } from 'util'
import type { SubdomainResult, SubdomainEnumResult } from './types'
import { PROFESSIONAL_WORDLIST } from './wordlists/subdomains-10k'
import { discoverSubdomainsPassive } from './passive-sources'
import { generatePermutations } from './subdomain-permuter'

const resolve4 = promisify(dns.resolve4)

// ── Wildcard Detection ──────────────────────────────────────────────────────
// If *.domain.com resolves, every brute-force hit is a false positive.
// We detect this FIRST to avoid polluting results.

async function detectWildcard(domain: string): Promise<string | null> {
  const randomPrefix = `odinforge-wildcard-check-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
  try {
    const addresses = await resolve4(`${randomPrefix}.${domain}`)
    if (addresses && addresses.length > 0) {
      console.log(`[RECON:SUBDOMAIN] Wildcard DNS detected for *.${domain} → ${addresses[0]}`)
      return addresses[0]
    }
  } catch {
    // NXDOMAIN = no wildcard. This is the expected/good case.
  }
  return null
}

// ── DNS Resolution ──────────────────────────────────────────────────────────

async function resolveSubdomain(subdomain: string): Promise<string | null> {
  try {
    const addresses = await resolve4(subdomain)
    return addresses[0] ?? null
  } catch {
    return null
  }
}

// ── HTTP Probing ────────────────────────────────────────────────────────────

async function probeHttp(subdomain: string): Promise<{ statusCode: number | null; title: string | null; server: string | null }> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ statusCode: null, title: null, server: null }), 5000)

    const req = https.get(`https://${subdomain}`, { timeout: 4000, rejectUnauthorized: false }, (res) => {
      let body = ''
      const server = (res.headers['server'] as string) ?? null
      res.on('data', (chunk) => { body += chunk.toString().substring(0, 4000) })
      res.on('end', () => {
        clearTimeout(timer)
        const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i)
        resolve({ statusCode: res.statusCode ?? null, title: titleMatch?.[1]?.trim() ?? null, server })
      })
    })
    req.on('error', () => {
      // Fall back to HTTP
      const httpReq = http.get(`http://${subdomain}`, { timeout: 4000 }, (res) => {
        let body = ''
        const server = (res.headers['server'] as string) ?? null
        res.on('data', (chunk) => { body += chunk.toString().substring(0, 4000) })
        res.on('end', () => {
          clearTimeout(timer)
          const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i)
          resolve({ statusCode: res.statusCode ?? null, title: titleMatch?.[1]?.trim() ?? null, server })
        })
      })
      httpReq.on('error', () => { clearTimeout(timer); resolve({ statusCode: null, title: null, server: null }) })
      httpReq.on('timeout', () => { httpReq.destroy(); clearTimeout(timer); resolve({ statusCode: null, title: null, server: null }) })
    })
    req.on('timeout', () => { req.destroy() })
  })
}

// ── Batch DNS + HTTP Resolution ─────────────────────────────────────────────

async function resolveBatch(
  candidates: string[],
  seen: Set<string>,
  wildcardIp: string | null,
  concurrency: number,
  skipProbe: boolean = false,
): Promise<SubdomainResult[]> {
  const results: SubdomainResult[] = []

  for (let i = 0; i < candidates.length; i += concurrency) {
    const batch = candidates.slice(i, i + concurrency)
    const batchResults = await Promise.all(
      batch.map(async (candidate): Promise<SubdomainResult | null> => {
        const lower = candidate.toLowerCase()
        if (seen.has(lower)) return null
        seen.add(lower)

        const ip = await resolveSubdomain(candidate)
        if (!ip) return null

        // Filter wildcard false positives
        if (wildcardIp && ip === wildcardIp) return null

        if (skipProbe) {
          return { subdomain: candidate, ip, statusCode: null, title: null, isAlive: false }
        }

        const { statusCode, title } = await probeHttp(candidate)
        return { subdomain: candidate, ip, statusCode, title, isAlive: statusCode !== null }
      })
    )
    for (const result of batchResults) {
      if (result) results.push(result)
    }
  }

  return results
}

// ── Main Entry Point ────────────────────────────────────────────────────────

export interface SubdomainEnumOptions {
  /** Use passive OSINT sources (default: true) */
  usePassive?: boolean
  /** Use active DNS brute-force (default: true) */
  useBruteForce?: boolean
  /** Use permutation engine on discovered subdomains (default: true) */
  usePermutation?: boolean
  /** Custom wordlist to use instead of professional wordlist */
  customWordlist?: string[]
  /** DNS resolution concurrency (default: 50) */
  concurrency?: number
  /** Maximum permutation candidates to test (default: 25000) */
  maxPermutations?: number
  /** Skip HTTP probing for permutation phase (faster, DNS-only) */
  fastPermutation?: boolean
}

export async function analyzeSubdomains(
  domain: string,
  options: SubdomainEnumOptions = {}
): Promise<SubdomainEnumResult> {
  const {
    usePassive = true,
    useBruteForce = true,
    usePermutation = true,
    customWordlist,
    concurrency = 50,
    maxPermutations = 25000,
    fastPermutation = false,
  } = options

  const startTime = Date.now()
  const allSubdomains: SubdomainResult[] = []
  const seen = new Set<string>()

  console.log(`[RECON:SUBDOMAIN] Starting professional subdomain enumeration for ${domain}`)

  // ── Phase 0: Wildcard Detection ───────────────────────────────────────────
  const wildcardIp = await detectWildcard(domain)
  if (wildcardIp) {
    console.log(`[RECON:SUBDOMAIN] ⚠ Wildcard detected (${wildcardIp}). Will filter false positives.`)
  }

  // ── Phase 1: Passive OSINT Discovery ──────────────────────────────────────
  let passiveSubs: string[] = []
  if (usePassive) {
    console.log('[RECON:SUBDOMAIN] Phase 1: Passive OSINT discovery (6 sources)...')
    const passiveResult = await discoverSubdomainsPassive(domain)
    passiveSubs = passiveResult.subdomains
    console.log(`[RECON:SUBDOMAIN] Phase 1 complete: ${passiveSubs.length} unique from passive sources`)

    // Resolve and probe passive discoveries
    const passiveResolved = await resolveBatch(passiveSubs, seen, wildcardIp, concurrency)
    allSubdomains.push(...passiveResolved)
    console.log(`[RECON:SUBDOMAIN] Phase 1 resolved: ${passiveResolved.length} live subdomains`)
  }

  // ── Phase 2: Active DNS Brute-Force ───────────────────────────────────────
  if (useBruteForce) {
    const wordlist = customWordlist ?? PROFESSIONAL_WORDLIST
    console.log(`[RECON:SUBDOMAIN] Phase 2: Active brute-force (${wordlist.length} candidates)...`)

    // Build candidate FQDNs from wordlist
    const candidates = wordlist.map(prefix => `${prefix}.${domain}`)

    const bruteForceResults = await resolveBatch(candidates, seen, wildcardIp, concurrency)
    allSubdomains.push(...bruteForceResults)
    console.log(`[RECON:SUBDOMAIN] Phase 2 complete: ${bruteForceResults.length} new subdomains from brute-force`)
  }

  // ── Phase 3: Permutation Engine ───────────────────────────────────────────
  if (usePermutation && allSubdomains.length > 0) {
    console.log(`[RECON:SUBDOMAIN] Phase 3: Permutation engine (${allSubdomains.length} seeds)...`)

    const seeds = allSubdomains.map(s => s.subdomain)
    const permResult = generatePermutations(seeds, domain, { maxTotal: maxPermutations })

    console.log(`[RECON:SUBDOMAIN] Generated ${permResult.permutationCount} permutation candidates (techniques: ${permResult.techniques.join(', ')})`)

    const permResolved = await resolveBatch(
      permResult.candidates,
      seen,
      wildcardIp,
      concurrency,
      fastPermutation // Skip HTTP probing in fast mode
    )

    // If fast mode was used, do HTTP probing on the ones that resolved
    if (fastPermutation && permResolved.length > 0) {
      console.log(`[RECON:SUBDOMAIN] Phase 3 fast mode: ${permResolved.length} DNS hits, probing HTTP...`)
      for (let i = 0; i < permResolved.length; i += concurrency) {
        const batch = permResolved.slice(i, i + concurrency)
        await Promise.all(batch.map(async (sub) => {
          const { statusCode, title } = await probeHttp(sub.subdomain)
          sub.statusCode = statusCode
          sub.title = title
          sub.isAlive = statusCode !== null
        }))
      }
    }

    allSubdomains.push(...permResolved)
    console.log(`[RECON:SUBDOMAIN] Phase 3 complete: ${permResolved.length} new subdomains from permutations`)
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  const duration = Date.now() - startTime
  const aliveCount = allSubdomains.filter(s => s.isAlive).length

  console.log(`[RECON:SUBDOMAIN] ═══════════════════════════════════════════════════════`)
  console.log(`[RECON:SUBDOMAIN] COMPLETE: ${allSubdomains.length} total subdomains found (${aliveCount} alive)`)
  console.log(`[RECON:SUBDOMAIN] Duration: ${(duration / 1000).toFixed(1)}s | Wildcard: ${wildcardIp ? 'YES' : 'no'}`)
  console.log(`[RECON:SUBDOMAIN] ═══════════════════════════════════════════════════════`)

  return {
    domain,
    subdomains: allSubdomains,
    totalFound: allSubdomains.length,
    aliveCount,
  }
}
