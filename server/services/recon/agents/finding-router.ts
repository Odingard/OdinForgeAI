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
    })
  }

  if (!dns.dnssecEnabled) {
    findings.push({
      _findingType: 'dns:no-dnssec',
      _target: host,
      _priority: 'medium',
      _source: 'dns-recon',
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
    })
  }

  return findings
}

// ─── Subdomain Findings ──────────────────────────────────────────────────────

export function extractSubdomainFindings(subdomains: SubdomainEnumResult): RoutedFinding[] {
  const findings: RoutedFinding[] = []

  for (const sub of subdomains.subdomains) {
    // Check for potential subdomain takeover candidates (alive DNS, dead HTTP)
    if (sub.ip && !sub.isAlive) {
      findings.push({
        _findingType: 'dns:subdomain-takeover',
        _target: sub.subdomain,
        _priority: 'high',
        _source: 'subdomain-enum',
        ip: sub.ip,
        subdomain: sub.subdomain,
      })
    }
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

// ─── Master Extractor ────────────────────────────────────────────────────────

export function extractAllFindings(recon: FullReconResult): RoutedFinding[] {
  return [
    ...extractDnsFindings(recon.dns),
    ...extractSubdomainFindings(recon.subdomains),
    ...extractPortFindings(recon.ports),
    ...extractSslFindings(recon.ssl),
    ...extractHeaderFindings(recon.headers),
    ...extractEndpointFindings(recon.endpointChecks),
  ].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 }
    return order[a._priority] - order[b._priority]
  })
}
