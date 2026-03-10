// ═══════════════════════════════════════════════════════════════════════════════
//  Finding Router
//
//  Takes raw recon results → extracts individual findings → tags each with
//  a findingType and priority → routes to the correct agent for action
// ═══════════════════════════════════════════════════════════════════════════════

import type { FullReconResult } from '../index'
import type {
  DnsReconResult, PortScanResult, SslTlsResult,
  HeaderAnalysisResult, WafDetectionResult,
  ApiEndpointDiscoveryResult, EndpointCheckResult,
  SubdomainEnumResult
} from '../types'

export interface RoutedFinding {
  _findingType: string
  _target: string
  _priority: 'critical' | 'high' | 'medium' | 'low'
  _source: string
  [key: string]: any
}

// ─── DNS Findings ────────────────────────────────────────────────────────────

export function extractDnsFindings(dns: DnsReconResult): RoutedFinding[] {
  const findings: RoutedFinding[] = []
  const host = dns.host

  if (dns.zoneTransferVulnerable) {
    findings.push({
      _findingType: 'dns:zone-transfer',
      _target: host,
      _priority: 'high',
      _source: 'dns-recon',
      nameservers: dns.nameservers,
      records: dns.records,
      attackTechnique: 'T1590.002', // MITRE: Gather Victim Network Information - DNS
    })
  }

  if (!dns.dnssecEnabled) {
    findings.push({
      _findingType: 'dns:no-dnssec',
      _target: host,
      _priority: 'medium',
      _source: 'dns-recon',
      attackTechnique: 'T1557', // MITRE: Adversary-in-the-Middle
    })
  }

  // Check for dangling CNAME records (CNAME → non-resolving target)
  for (const record of dns.records.filter(r => r.type === 'CNAME')) {
    findings.push({
      _findingType: 'dns:dangling-record',
      _target: host,
      _priority: 'high',
      _source: 'dns-recon',
      record,
      cname: record.value,
      attackTechnique: 'T1584.001', // MITRE: Compromise Infrastructure - Domains
    })
  }

  return findings
}

// ─── Subdomain Findings ──────────────────────────────────────────────────────

// Environment patterns that indicate non-production exposure
const ENV_PATTERNS = /^(dev|staging|stage|stg|test|testing|qa|uat|sandbox|demo|preview|beta|alpha|canary|pre-?prod|preprod|integration|int|perf|load)/i
const ADMIN_PATTERNS = /^(admin|panel|cpanel|whm|plesk|dashboard|console|mgmt|manage|backoffice|phpmyadmin|pma|adminer|pgadmin|dbadmin|webadmin)/i
const SENSITIVE_PATTERNS = /^(internal|intranet|corp|private|vpn|remote|bastion|jump|vault|secrets|config|env|git|gitlab|jenkins|ci|sonar)/i
const DATA_PATTERNS = /^(db|database|mysql|postgres|mongo|redis|memcache|elastic|kafka|rabbit|etcd|influx)/i

export function extractSubdomainFindings(subdomains: SubdomainEnumResult): RoutedFinding[] {
  const findings: RoutedFinding[] = []

  for (const sub of subdomains.subdomains) {
    const prefix = sub.subdomain.split('.')[0]

    // Subdomain takeover candidates (alive DNS, dead HTTP)
    if (sub.ip && !sub.isAlive) {
      findings.push({
        _findingType: 'subdomain:takeover-candidate',
        _target: sub.subdomain,
        _priority: 'high',
        _source: 'subdomain-enum',
        ip: sub.ip,
        subdomain: sub.subdomain,
        attackTechnique: 'T1584.001', // MITRE: Compromise Infrastructure - Domains
      })
    }

    // Non-production environment exposed to internet
    if (sub.isAlive && ENV_PATTERNS.test(prefix)) {
      findings.push({
        _findingType: 'subdomain:environment-leak',
        _target: sub.subdomain,
        _priority: 'high',
        _source: 'subdomain-enum',
        ip: sub.ip,
        statusCode: sub.statusCode,
        title: sub.title,
        environment: prefix,
        attackTechnique: 'T1190', // MITRE: Exploit Public-Facing Application
      })
    }

    // Admin/management panel exposed
    if (sub.isAlive && ADMIN_PATTERNS.test(prefix)) {
      findings.push({
        _findingType: 'subdomain:admin-panel-exposed',
        _target: sub.subdomain,
        _priority: 'critical',
        _source: 'subdomain-enum',
        ip: sub.ip,
        statusCode: sub.statusCode,
        title: sub.title,
        attackTechnique: 'T1078', // MITRE: Valid Accounts
      })
    }

    // Sensitive internal service exposed
    if (sub.isAlive && SENSITIVE_PATTERNS.test(prefix)) {
      findings.push({
        _findingType: 'subdomain:sensitive-service-exposed',
        _target: sub.subdomain,
        _priority: 'high',
        _source: 'subdomain-enum',
        ip: sub.ip,
        statusCode: sub.statusCode,
        title: sub.title,
        attackTechnique: 'T1133', // MITRE: External Remote Services
      })
    }

    // Database/data service exposed
    if (sub.isAlive && DATA_PATTERNS.test(prefix)) {
      findings.push({
        _findingType: 'subdomain:data-service-exposed',
        _target: sub.subdomain,
        _priority: 'critical',
        _source: 'subdomain-enum',
        ip: sub.ip,
        statusCode: sub.statusCode,
        title: sub.title,
        attackTechnique: 'T1213', // MITRE: Data from Information Repositories
      })
    }
  }

  // Shadow IT detection: large subdomain count suggests untracked assets
  if (subdomains.totalFound > 50) {
    findings.push({
      _findingType: 'subdomain:shadow-it-risk',
      _target: subdomains.domain,
      _priority: 'medium',
      _source: 'subdomain-enum',
      totalSubdomains: subdomains.totalFound,
      aliveCount: subdomains.aliveCount,
      attackTechnique: 'T1595.002', // MITRE: Active Scanning - Vulnerability Scanning
    })
  }

  return findings
}

// ─── Port Findings ───────────────────────────────────────────────────────────

export function extractPortFindings(ports: PortScanResult): RoutedFinding[] {
  const findings: RoutedFinding[] = []
  const host = ports.host

  for (const p of ports.openPorts) {
    if (p.category === 'database') {
      findings.push({
        _findingType: 'port:exposed-database',
        _target: host,
        _priority: 'critical',
        _source: 'port-scan',
        port: p.port,
        service: p.service,
        banner: p.banner,
        attackTechnique: 'T1190', // MITRE: Exploit Public-Facing Application
      })
    }

    if (p.category === 'remote') {
      findings.push({
        _findingType: 'port:exposed-remote',
        _target: host,
        _priority: 'high',
        _source: 'port-scan',
        port: p.port,
        service: p.service,
        banner: p.banner,
        attackTechnique: 'T1133', // MITRE: External Remote Services
      })
    }

    // Debug/monitoring endpoints
    if ([9090, 9200, 9300].includes(p.port) || p.service.toLowerCase().includes('debug') || p.service.toLowerCase().includes('prometheus')) {
      findings.push({
        _findingType: 'port:debug-endpoint',
        _target: host,
        _priority: 'high',
        _source: 'port-scan',
        port: p.port,
        service: p.service,
        attackTechnique: 'T1046', // MITRE: Network Service Discovery
      })
    }

    // Cache services
    if (['Redis', 'Memcached'].includes(p.service)) {
      findings.push({
        _findingType: 'port:exposed-cache',
        _target: host,
        _priority: 'critical',
        _source: 'port-scan',
        port: p.port,
        service: p.service,
        banner: p.banner,
        attackTechnique: 'T1005', // MITRE: Data from Local System
      })
    }

    // Admin/web panels on unusual ports
    if (p.category === 'web' && ![80, 443].includes(p.port)) {
      findings.push({
        _findingType: 'port:exposed-admin',
        _target: host,
        _priority: 'medium',
        _source: 'port-scan',
        port: p.port,
        service: p.service,
        attackTechnique: 'T1078', // MITRE: Valid Accounts
      })
    }
  }

  return findings
}

// ─── SSL/TLS Findings ────────────────────────────────────────────────────────

export function extractSslFindings(ssl: SslTlsResult): RoutedFinding[] {
  const findings: RoutedFinding[] = []

  if (ssl.certificate?.isExpired) {
    findings.push({
      _findingType: 'ssl:expired-cert',
      _target: ssl.host,
      _priority: 'critical',
      _source: 'ssl-tls-analysis',
      port: ssl.port,
      certificate: ssl.certificate,
      attackTechnique: 'T1557', // MITRE: Adversary-in-the-Middle
    })
  }

  if (ssl.certificate && ssl.certificate.subject === ssl.certificate.issuer) {
    findings.push({
      _findingType: 'ssl:self-signed',
      _target: ssl.host,
      _priority: 'high',
      _source: 'ssl-tls-analysis',
      port: ssl.port,
      certificate: ssl.certificate,
      attackTechnique: 'T1553.004', // MITRE: Subvert Trust Controls - Install Root Certificate
    })
  }

  for (const proto of ssl.protocols) {
    if (proto.supported && (proto.name.includes('SSL') || proto.name === 'TLSv1.0' || proto.name === 'TLSv1.1')) {
      findings.push({
        _findingType: 'ssl:weak-protocol',
        _target: ssl.host,
        _priority: proto.name.includes('SSL') ? 'critical' : 'high',
        _source: 'ssl-tls-analysis',
        port: ssl.port,
        protocol: proto.name,
        attackTechnique: 'T1040', // MITRE: Network Sniffing
      })
    }
  }

  for (const issue of ssl.issues) {
    if (issue.title.includes('Cipher')) {
      findings.push({
        _findingType: 'ssl:weak-cipher',
        _target: ssl.host,
        _priority: issue.severity === 'critical' ? 'critical' : 'high',
        _source: 'ssl-tls-analysis',
        port: ssl.port,
        issue,
        attackTechnique: 'T1040', // MITRE: Network Sniffing
      })
    }
  }

  return findings
}

// ─── Header Findings ─────────────────────────────────────────────────────────

export function extractHeaderFindings(headers: HeaderAnalysisResult): RoutedFinding[] {
  const findings: RoutedFinding[] = []
  const url = headers.url

  const typeMap: Record<string, string> = {
    'content-security-policy': 'header:missing-csp',
    'strict-transport-security': 'header:missing-hsts',
    'x-frame-options': 'header:missing-xframe',
    'x-content-type-options': 'header:missing-xcto',
    'set-cookie': 'header:insecure-cookie',
    'server': 'header:info-leak',
    'x-powered-by': 'header:info-leak',
  }

  for (const issue of headers.issues) {
    if (issue.status === 'present') continue // Only route actual problems

    const findingType = typeMap[issue.header] ?? `header:${issue.status}-${issue.header}`
    findings.push({
      _findingType: findingType,
      _target: url,
      _priority: issue.severity === 'critical' ? 'critical' : (issue.severity === 'high' ? 'high' : 'medium'),
      _source: 'header-analysis',
      header: issue.header,
      issue,
    })
  }

  return findings
}

// ─── Endpoint Check Findings ─────────────────────────────────────────────────

export function extractEndpointFindings(checks: EndpointCheckResult[]): RoutedFinding[] {
  const findings: RoutedFinding[] = []

  for (const check of checks) {
    // CORS issues
    for (const issue of check.cors.issues) {
      findings.push({
        _findingType: issue.category === 'cors'
          ? (issue.title.includes('Reflection') ? 'cors:origin-reflection'
            : issue.title.includes('Wildcard') ? 'cors:wildcard-origin'
            : issue.title.includes('Credentials') ? 'cors:credentials-leak'
            : 'endpoint:cors-issue')
          : 'endpoint:cors-issue',
        _target: check.endpoint,
        _priority: issue.severity === 'critical' ? 'critical' : 'high',
        _source: 'single-api-endpoint-checker',
        method: check.method,
        issue,
      })
    }

    // Auth issues
    for (const issue of check.auth.issues) {
      findings.push({
        _findingType: issue.title.includes('Bypass') ? 'endpoint:auth-bypass'
          : issue.title.includes('No Authentication') ? 'endpoint:no-auth'
          : 'endpoint:weak-auth',
        _target: check.endpoint,
        _priority: issue.severity === 'critical' ? 'critical' : 'high',
        _source: 'single-api-endpoint-checker',
        method: check.method,
        issue,
      })
    }

    // Linting issues
    for (const issue of check.linting.issues) {
      const type = issue.title.includes('Rate') ? 'endpoint:no-rate-limit'
        : issue.title.includes('HTTPS') ? 'endpoint:info-disclosure'
        : 'endpoint:info-disclosure'
      findings.push({
        _findingType: type,
        _target: check.endpoint,
        _priority: issue.severity === 'critical' ? 'critical' : (issue.severity === 'high' ? 'high' : 'medium'),
        _source: 'single-api-endpoint-checker',
        method: check.method,
        issue,
      })
    }

    // Staleness issues
    for (const issue of check.staleness.issues) {
      findings.push({
        _findingType: 'endpoint:stale',
        _target: check.endpoint,
        _priority: issue.severity === 'critical' ? 'critical' : 'medium',
        _source: 'single-api-endpoint-checker',
        method: check.method,
        issue,
      })
    }
  }

  return findings
}

// ─── Tech Fingerprint Findings ──────────────────────────────────────────────

import type { TechFingerprint } from '../tech-fingerprint'
import type { ExtractedSecret } from '../secret-extractor'

const HIGH_RISK_CATEGORIES = new Set(['ci_cd', 'database_ui', 'devops', 'admin_panel'])

export function extractTechFingerprintFindings(
  fingerprints: Map<string, TechFingerprint[]>
): RoutedFinding[] {
  const findings: RoutedFinding[] = []

  Array.from(fingerprints.entries()).forEach(([subdomain, fps]) => {
    for (const fp of fps) {
      // Default credentials available → critical
      if (fp.defaultCreds && fp.defaultCreds.length > 0) {
        findings.push({
          _findingType: 'tech:default-credentials',
          _target: subdomain,
          _priority: 'critical',
          _source: 'tech-fingerprint',
          technology: fp.technology,
          version: fp.version,
          category: fp.category,
          defaultCreds: fp.defaultCreds,
          attackSurface: fp.attackSurface,
          attackTechnique: 'T1078.001', // MITRE: Default Accounts
        })
      }

      // High-risk category exposed
      if (HIGH_RISK_CATEGORIES.has(fp.category)) {
        const findingType = fp.category === 'database_ui'
          ? 'tech:exposed-database-ui'
          : fp.category === 'admin_panel'
            ? 'tech:exposed-admin-panel'
            : 'tech:exposed-devops-tool'
        findings.push({
          _findingType: findingType,
          _target: subdomain,
          _priority: 'high',
          _source: 'tech-fingerprint',
          technology: fp.technology,
          version: fp.version,
          category: fp.category,
          knownVulns: fp.knownVulns,
          attackSurface: fp.attackSurface,
          attackTechnique: 'T1190', // MITRE: Exploit Public-Facing Application
        })
      }
    }
  })

  return findings
}

// ─── Secret Extraction Findings ─────────────────────────────────────────────

const SECRET_FINDING_MAP: Record<string, { findingType: string, technique: string }> = {
  aws_access_key:    { findingType: 'secret:leaked-aws-key',     technique: 'T1552.001' },
  aws_secret_key:    { findingType: 'secret:leaked-aws-key',     technique: 'T1552.001' },
  private_key:       { findingType: 'secret:leaked-private-key', technique: 'T1552.004' },
  jwt_token:         { findingType: 'secret:leaked-token',       technique: 'T1528' },
  bearer_token:      { findingType: 'secret:leaked-token',       technique: 'T1528' },
  github_token:      { findingType: 'secret:leaked-token',       technique: 'T1528' },
  slack_token:       { findingType: 'secret:leaked-token',       technique: 'T1528' },
  hardcoded_password: { findingType: 'secret:hardcoded-password', technique: 'T1552.001' },
  internal_url:      { findingType: 'secret:internal-url-leak',  technique: 'T1590.004' },
  database_url:      { findingType: 'secret:hardcoded-password', technique: 'T1552.001' },
}

export function extractSecretFindings(
  secrets: Map<string, ExtractedSecret[]>
): RoutedFinding[] {
  const findings: RoutedFinding[] = []

  Array.from(secrets.entries()).forEach(([subdomain, secs]) => {
    for (const sec of secs) {
      const mapping = SECRET_FINDING_MAP[sec.type] || {
        findingType: 'secret:leaked-api-key',
        technique: 'T1552.001',
      }
      findings.push({
        _findingType: mapping.findingType,
        _target: subdomain,
        _priority: sec.severity,
        _source: 'secret-extractor',
        secretType: sec.type,
        value: sec.value, // Already redacted
        context: sec.context,
        confidence: sec.confidence,
        attackTechnique: mapping.technique,
      })
    }
  })

  return findings
}

// ─── Master Extractor ────────────────────────────────────────────────────────

export function extractAllFindings(recon: FullReconResult): RoutedFinding[] {
  const findings = [
    ...extractDnsFindings(recon.dns),
    ...extractSubdomainFindings(recon.subdomains),
    ...extractPortFindings(recon.ports),
    ...extractSslFindings(recon.ssl),
    ...extractHeaderFindings(recon.headers),
    ...extractEndpointFindings(recon.endpointChecks),
  ]

  // Add tech fingerprint findings if available
  if (recon.techFingerprints && recon.techFingerprints.size > 0) {
    findings.push(...extractTechFingerprintFindings(recon.techFingerprints))
  }

  // Add secret extraction findings if available
  if (recon.extractedSecrets && recon.extractedSecrets.size > 0) {
    findings.push(...extractSecretFindings(recon.extractedSecrets))
  }

  return findings.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 }
    return order[a._priority] - order[b._priority]
  })
}
