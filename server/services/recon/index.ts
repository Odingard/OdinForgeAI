// ═══════════════════════════════════════════════════════════════════════════════
//  OdinForge Recon Suite — Full Reconnaissance Orchestrator
//
//  Each recon module runs independently, discovers endpoints where applicable,
//  and feeds every discovered endpoint into the Single-API-Endpoint-Checker.
// ═══════════════════════════════════════════════════════════════════════════════

export * from './types'

// ── Module Exports ───────────────────────────────────────────────────────────
export { analyzeDns }             from './dns-recon'
export { analyzeSubdomains }      from './subdomain-enum'
export { analyzePorts }           from './port-scan'
export { analyzeSslTls }          from './ssl-tls-analysis'
export { analyzeHeaders }         from './header-analysis'
export { analyzeTech }            from './tech-detection'
export { analyzeWaf }             from './waf-detection'
export { analyzeApiEndpoints }    from './api-endpoint-discovery'
export { checkEndpoint }          from './single-api-endpoint-checker'

// ── Module Imports (for the orchestrator) ────────────────────────────────────
import * as https from 'https'
import * as http from 'http'
import { analyzeDns }             from './dns-recon'
import { analyzeSubdomains }      from './subdomain-enum'
import { analyzePorts }           from './port-scan'
import { analyzeSslTls }          from './ssl-tls-analysis'
import { analyzeHeaders }         from './header-analysis'
import { analyzeTech }            from './tech-detection'
import { analyzeWaf }             from './waf-detection'
import { analyzeApiEndpoints }    from './api-endpoint-discovery'
import { checkEndpoint }          from './single-api-endpoint-checker'

// ─── Protocol Detection ──────────────────────────────────────────────────────
// Try HTTPS first; if it fails, fall back to HTTP

async function detectProtocol(host: string): Promise<'https' | 'http'> {
  return new Promise((resolve) => {
    const req = https.get(`https://${host}`, { timeout: 5000, rejectUnauthorized: false }, (res) => {
      res.resume()
      res.on('end', () => resolve('https'))
    })
    req.on('error', () => {
      // HTTPS failed — try HTTP
      const httpReq = http.get(`http://${host}`, { timeout: 5000 }, (res) => {
        res.resume()
        res.on('end', () => resolve('http'))
      })
      httpReq.on('error', () => resolve('http')) // Default to http if both fail
      httpReq.on('timeout', () => { httpReq.destroy(); resolve('http') })
    })
    req.on('timeout', () => {
      req.destroy()
      // Timeout on HTTPS — try HTTP
      const httpReq = http.get(`http://${host}`, { timeout: 5000 }, (res) => {
        res.resume()
        res.on('end', () => resolve('http'))
      })
      httpReq.on('error', () => resolve('http'))
      httpReq.on('timeout', () => { httpReq.destroy(); resolve('http') })
    })
  })
}

import type {
  ReconTarget,
  DnsReconResult,
  SubdomainEnumResult,
  PortScanResult,
  SslTlsResult,
  HeaderAnalysisResult,
  TechDetectionResult,
  WafDetectionResult,
  ApiEndpointDiscoveryResult,
  EndpointCheckResult,
} from './types'

// ─── Full Recon Result ───────────────────────────────────────────────────────

export interface FullReconResult {
  target: ReconTarget
  timestamp: string
  duration: number

  // Individual recon results
  dns: DnsReconResult
  subdomains: SubdomainEnumResult
  ports: PortScanResult
  ssl: SslTlsResult
  headers: HeaderAnalysisResult
  tech: TechDetectionResult
  waf: WafDetectionResult

  // API recon results
  apiDiscovery: ApiEndpointDiscoveryResult
  endpointChecks: EndpointCheckResult[]

  // Aggregate summary
  summary: {
    totalEndpoints: number
    totalIssues: number
    criticalIssues: number
    highIssues: number
    mediumIssues: number
    lowIssues: number
    topIssues: { endpoint: string; title: string; severity: string }[]
  }
}

// ─── Orchestrator ────────────────────────────────────────────────────────────

export async function runFullRecon(
  target: ReconTarget,
  options: {
    skipSubdomains?: boolean
    skipPorts?: boolean
    endpointCheckConcurrency?: number
    maxEndpointsToCheck?: number
  } = {}
): Promise<FullReconResult> {
  const {
    skipSubdomains = false,
    skipPorts = false,
    endpointCheckConcurrency = 5,
    maxEndpointsToCheck = 50
  } = options

  const startTime = Date.now()

  // Detect whether the target supports HTTPS or only HTTP
  const protocol = await detectProtocol(target.host)
  const baseUrl = `${protocol}://${target.host}${target.basePath ?? ''}`

  console.log(`[RECON] Starting full reconnaissance on ${target.host} (${protocol.toUpperCase()})`)

  // ── Phase 1: Parallel infrastructure recon ─────────────────────────────────
  console.log('[RECON] Phase 1: Infrastructure reconnaissance...')

  const [dns, subdomains, ports, ssl, headers, tech, waf] = await Promise.all([
    analyzeDns(target.host),
    skipSubdomains
      ? Promise.resolve({ domain: target.host, subdomains: [], totalFound: 0, aliveCount: 0 } as SubdomainEnumResult)
      : analyzeSubdomains(target.host),
    skipPorts
      ? Promise.resolve({ host: target.host, openPorts: [], filteredPorts: [], scanDuration: 0 } as PortScanResult)
      : analyzePorts(target.host, { ports: target.ports }),
    analyzeSslTls(target.host),
    analyzeHeaders(baseUrl),
    analyzeTech(baseUrl),
    analyzeWaf(baseUrl),
  ])

  console.log(`[RECON] Phase 1 complete. Found ${subdomains.totalFound} subdomains, ${ports.openPorts.length} open ports.`)

  // ── Phase 2: API endpoint discovery ────────────────────────────────────────
  console.log('[RECON] Phase 2: API endpoint discovery...')

  const apiDiscovery = await analyzeApiEndpoints(baseUrl, { methods: true })

  console.log(`[RECON] Phase 2 complete. Discovered ${apiDiscovery.totalDiscovered} endpoints.`)

  // ── Phase 3: Deep-check each endpoint ──────────────────────────────────────
  console.log('[RECON] Phase 3: Single-endpoint deep checks...')

  const endpointsToCheck = apiDiscovery.endpoints.slice(0, maxEndpointsToCheck)
  const endpointChecks: EndpointCheckResult[] = []

  // Process in batches to be respectful to the target
  for (let i = 0; i < endpointsToCheck.length; i += endpointCheckConcurrency) {
    const batch = endpointsToCheck.slice(i, i + endpointCheckConcurrency)
    const batchResults = await Promise.all(
      batch.map(ep => checkEndpoint(ep.url, ep.method))
    )
    endpointChecks.push(...batchResults)
  }

  console.log(`[RECON] Phase 3 complete. Checked ${endpointChecks.length} endpoints.`)

  // ── Aggregate summary ──────────────────────────────────────────────────────
  let totalIssues = 0
  let criticalIssues = 0
  let highIssues = 0
  let mediumIssues = 0
  let lowIssues = 0
  const topIssues: { endpoint: string; title: string; severity: string }[] = []

  for (const check of endpointChecks) {
    const allIssues = [
      ...check.cors.issues,
      ...check.auth.issues,
      ...check.linting.issues,
      ...check.staleness.issues,
    ]
    totalIssues += allIssues.length
    for (const issue of allIssues) {
      if (issue.severity === 'critical') criticalIssues++
      else if (issue.severity === 'high') highIssues++
      else if (issue.severity === 'medium') mediumIssues++
      else if (issue.severity === 'low') lowIssues++

      if (issue.severity === 'critical' || issue.severity === 'high') {
        topIssues.push({ endpoint: check.endpoint, title: issue.title, severity: issue.severity })
      }
    }
  }

  // Also count issues from SSL and header analysis
  totalIssues += ssl.issues.length + headers.issues.filter(i => i.status !== 'present').length
  for (const issue of ssl.issues) {
    if (issue.severity === 'critical') criticalIssues++
    else if (issue.severity === 'high') highIssues++
    else if (issue.severity === 'medium') mediumIssues++
    else if (issue.severity === 'low') lowIssues++
  }

  const duration = Date.now() - startTime
  console.log(`[RECON] Full scan complete in ${(duration / 1000).toFixed(1)}s. Found ${totalIssues} total issues (${criticalIssues} critical, ${highIssues} high).`)

  return {
    target,
    timestamp: new Date().toISOString(),
    duration,
    dns,
    subdomains,
    ports,
    ssl,
    headers,
    tech,
    waf,
    apiDiscovery,
    endpointChecks,
    summary: {
      totalEndpoints: apiDiscovery.totalDiscovered,
      totalIssues,
      criticalIssues,
      highIssues,
      mediumIssues,
      lowIssues,
      topIssues: topIssues.slice(0, 20) // Top 20 worst findings
    }
  }
}

// ─── Convenience: Run only the endpoint recon pipeline ───────────────────────
// Discovers endpoints → outputs list → feeds each into the checker

export async function runEndpointRecon(
  baseUrl: string,
  options: { maxEndpoints?: number } = {}
): Promise<{ discovery: ApiEndpointDiscoveryResult; checks: EndpointCheckResult[] }> {
  const { maxEndpoints = 50 } = options

  console.log(`[ENDPOINT-RECON] Discovering endpoints on ${baseUrl}...`)
  const discovery = await analyzeApiEndpoints(baseUrl, { methods: true })

  console.log(`[ENDPOINT-RECON] Found ${discovery.totalDiscovered} endpoints. Running deep checks...`)
  const checks: EndpointCheckResult[] = []

  for (const ep of discovery.endpoints.slice(0, maxEndpoints)) {
    const check = await checkEndpoint(ep.url, ep.method)
    checks.push(check)
  }

  console.log(`[ENDPOINT-RECON] Complete. ${checks.length} endpoints analyzed.`)
  return { discovery, checks }
}
