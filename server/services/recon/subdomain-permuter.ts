// ═══════════════════════════════════════════════════════════════════════════════
//  OdinForge Subdomain Permutation Engine
//
//  Takes discovered subdomains as seeds, generates intelligent mutations
//  to find subdomains that no passive source has ever indexed. This is
//  how you find internal, newly-created, or obfuscated subdomains.
//
//  Techniques:
//   1. Prefix prepend   — dev-api, staging-api, test-api
//   2. Suffix append    — api-v2, api-internal, api-backup
//   3. Word swap        — mail → webmail, smtp, imap
//   4. Number increment — ns1 → ns2, ns3, ns4
//   5. Separator swap   — api-v2 → apiv2, api.v2, api_v2
//   6. TLD permutation  — sub.domain.com patterns
// ═══════════════════════════════════════════════════════════════════════════════

export interface PermutationResult {
  candidates: string[]
  seedCount: number
  permutationCount: number
  techniques: string[]
}

// Common prefixes to prepend to discovered subdomains
const PREFIXES = [
  'dev', 'staging', 'stage', 'stg', 'test', 'qa', 'uat',
  'sandbox', 'demo', 'beta', 'alpha', 'canary', 'preview',
  'pre-prod', 'preprod', 'prod', 'production', 'live',
  'internal', 'int', 'ext', 'external', 'public', 'private',
  'admin', 'mgmt', 'management',
  'old', 'new', 'legacy', 'v2', 'v3', 'next',
  'us', 'eu', 'ap', 'east', 'west',
  'dr', 'backup', 'failover', 'hot', 'standby',
]

// Common suffixes to append to discovered subdomains
const SUFFIXES = [
  'dev', 'staging', 'stage', 'test', 'qa', 'uat',
  'sandbox', 'demo', 'beta', 'internal', 'int', 'ext',
  'prod', 'live', 'v1', 'v2', 'v3', 'v4',
  'api', 'admin', 'mgmt', 'gw', 'gateway',
  'primary', 'secondary', 'backup', 'dr',
  'east', 'west', 'eu', 'us', 'ap',
  '01', '02', '03', '1', '2', '3',
]

// Word swap maps — when we find one, try related ones
const WORD_SWAPS: Record<string, string[]> = {
  'mail': ['webmail', 'smtp', 'imap', 'pop', 'pop3', 'mx', 'exchange', 'owa', 'postfix'],
  'api': ['rest', 'graphql', 'rpc', 'grpc', 'ws', 'gateway', 'proxy'],
  'db': ['database', 'mysql', 'postgres', 'mongo', 'redis', 'cache'],
  'admin': ['panel', 'dashboard', 'console', 'portal', 'backoffice', 'mgmt'],
  'auth': ['sso', 'login', 'oauth', 'identity', 'idp', 'saml', 'keycloak'],
  'vpn': ['remote', 'gateway', 'ssl-vpn', 'wireguard', 'openvpn', 'ipsec'],
  'git': ['gitlab', 'github', 'gitea', 'bitbucket', 'repo', 'svn'],
  'ci': ['jenkins', 'bamboo', 'drone', 'argocd', 'teamcity', 'circleci'],
  'monitor': ['monitoring', 'grafana', 'prometheus', 'nagios', 'zabbix', 'datadog'],
  'log': ['logs', 'logging', 'kibana', 'elastic', 'graylog', 'splunk', 'syslog'],
  'cdn': ['static', 'assets', 'media', 'content', 'edge', 'cloudfront'],
  'ns': ['dns', 'ns1', 'ns2', 'ns3', 'ns4', 'nameserver'],
  'app': ['application', 'web', 'www', 'site', 'service', 'svc'],
  'lb': ['loadbalancer', 'load-balancer', 'haproxy', 'nginx', 'traefik', 'f5'],
  'k8s': ['kubernetes', 'kube', 'cluster', 'rancher', 'openshift', 'eks', 'gke', 'aks'],
  'storage': ['s3', 'minio', 'blob', 'gcs', 'bucket', 'nfs', 'nas'],
}

// Extract the subdomain prefix (part before the root domain)
function extractPrefix(subdomain: string, domain: string): string {
  const suffix = '.' + domain
  if (subdomain.endsWith(suffix)) {
    return subdomain.slice(0, subdomain.length - suffix.length)
  }
  return subdomain
}

// Generate permutations from a single seed subdomain
function permuteOne(seed: string, domain: string): string[] {
  const prefix = extractPrefix(seed, domain)
  if (!prefix) return []

  const results: string[] = []

  // 1. Prefix prepend: dev-{seed}, staging-{seed}
  for (const p of PREFIXES) {
    results.push(`${p}-${prefix}.${domain}`)
    results.push(`${p}.${prefix}.${domain}`)
  }

  // 2. Suffix append: {seed}-dev, {seed}-v2
  for (const s of SUFFIXES) {
    results.push(`${prefix}-${s}.${domain}`)
  }

  // 3. Number increment: if seed ends with a number, try adjacent numbers
  const numMatch = prefix.match(/^(.+?)[-.]?(\d+)$/)
  if (numMatch) {
    const base = numMatch[1]
    const num = parseInt(numMatch[2], 10)
    for (let i = Math.max(1, num - 2); i <= num + 5; i++) {
      if (i === num) continue
      results.push(`${base}${i}.${domain}`)
      results.push(`${base}-${i}.${domain}`)
    }
    // Zero-padded variants
    for (let i = 1; i <= 10; i++) {
      results.push(`${base}${String(i).padStart(2, '0')}.${domain}`)
    }
  }

  // 4. Separator swap: api-v2 → apiv2, api_v2
  if (prefix.includes('-')) {
    results.push(`${prefix.replace(/-/g, '')}.${domain}`)
    results.push(`${prefix.replace(/-/g, '_')}.${domain}`)
  }
  if (prefix.includes('_')) {
    results.push(`${prefix.replace(/_/g, '-')}.${domain}`)
    results.push(`${prefix.replace(/_/g, '')}.${domain}`)
  }

  // 5. Word swap: if seed contains a known word, try related words
  for (const [word, swaps] of Object.entries(WORD_SWAPS)) {
    if (prefix === word || prefix.includes(word)) {
      for (const swap of swaps) {
        results.push(`${prefix.replace(word, swap)}.${domain}`)
      }
    }
  }

  return results
}

export function generatePermutations(
  discoveredSubdomains: string[],
  domain: string,
  options: { maxPerSeed?: number; maxTotal?: number } = {}
): PermutationResult {
  const { maxPerSeed = 200, maxTotal = 50000 } = options

  const candidates = new Set<string>()
  const techniques = new Set<string>()
  const seedSet = new Set(discoveredSubdomains.map(s => s.toLowerCase()))

  for (const seed of discoveredSubdomains) {
    const perms = permuteOne(seed, domain)
    let count = 0
    for (const perm of perms) {
      const lower = perm.toLowerCase()
      // Skip if it's already a known subdomain
      if (seedSet.has(lower)) continue
      if (candidates.has(lower)) continue

      candidates.add(lower)
      count++
      if (count >= maxPerSeed) break
      if (candidates.size >= maxTotal) break
    }
    if (candidates.size >= maxTotal) break
  }

  // Determine which techniques were used
  if (discoveredSubdomains.length > 0) {
    techniques.add('prefix-prepend')
    techniques.add('suffix-append')
    techniques.add('separator-swap')
    techniques.add('word-swap')
  }
  for (const seed of discoveredSubdomains) {
    const prefix = extractPrefix(seed, domain)
    if (/\d+$/.test(prefix)) {
      techniques.add('number-increment')
      break
    }
  }

  return {
    candidates: Array.from(candidates),
    seedCount: discoveredSubdomains.length,
    permutationCount: candidates.size,
    techniques: Array.from(techniques),
  }
}
