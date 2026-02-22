// ─── Core Recon Types ────────────────────────────────────────────────────────

export interface ReconTarget {
  host: string
  basePath?: string
  ports?: number[]
}

// ─── DNS Recon ───────────────────────────────────────────────────────────────

export interface DnsRecord {
  type: 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS' | 'SOA' | 'SRV' | 'PTR'
  name: string
  value: string
  ttl: number
}

export interface DnsReconResult {
  host: string
  records: DnsRecord[]
  nameservers: string[]
  mailServers: string[]
  zoneTransferVulnerable: boolean
  dnssecEnabled: boolean
}

// ─── Subdomain Enumeration ───────────────────────────────────────────────────

export interface SubdomainResult {
  subdomain: string
  ip: string | null
  statusCode: number | null
  title: string | null
  isAlive: boolean
}

export interface SubdomainEnumResult {
  domain: string
  subdomains: SubdomainResult[]
  totalFound: number
  aliveCount: number
}

// ─── Port Scanning ───────────────────────────────────────────────────────────

export interface PortResult {
  port: number
  state: 'open' | 'closed' | 'filtered'
  service: string
  category: 'web' | 'database' | 'mail' | 'file' | 'remote' | 'dns' | 'other'
  banner: string | null
}

export interface PortScanResult {
  host: string
  openPorts: PortResult[]
  filteredPorts: number[]
  scanDuration: number
}

// ─── SSL/TLS Analysis ────────────────────────────────────────────────────────

export interface CertificateInfo {
  subject: string
  issuer: string
  validFrom: string
  validTo: string
  isExpired: boolean
  daysUntilExpiry: number
  serialNumber: string
  fingerprint: string
}

export interface SslIssue {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  description: string
}

export interface SslTlsResult {
  host: string
  port: number
  certificate: CertificateInfo | null
  protocols: { name: string; supported: boolean }[]
  cipherSuites: string[]
  issues: SslIssue[]
}

// ─── HTTP Header Analysis ────────────────────────────────────────────────────

export interface HeaderIssue {
  header: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'missing' | 'misconfigured' | 'weak' | 'present'
  detail: string
}

export interface HeaderAnalysisResult {
  url: string
  statusCode: number
  headers: Record<string, string>
  issues: HeaderIssue[]
  securityScore: number
}

// ─── Technology Detection ────────────────────────────────────────────────────

export interface DetectedTechnology {
  name: string
  category: 'framework' | 'server' | 'cms' | 'cdn' | 'analytics' | 'language' | 'database' | 'cache' | 'other'
  version: string | null
  confidence: number
  detectedVia: string
}

export interface TechDetectionResult {
  url: string
  technologies: DetectedTechnology[]
  serverHeader: string | null
  poweredBy: string | null
}

// ─── WAF Detection ───────────────────────────────────────────────────────────

export interface WafFingerprint {
  name: string
  confidence: number
  indicators: string[]
}

export interface WafDetectionResult {
  url: string
  detected: boolean
  waf: WafFingerprint | null
  bypassHints: string[]
}

// ─── API Endpoint Discovery ──────────────────────────────────────────────────

export interface DiscoveredEndpoint {
  url: string
  method: string
  statusCode: number
  contentType: string | null
  source: 'crawl' | 'wordlist' | 'sitemap' | 'robots' | 'js-scrape' | 'swagger' | 'openapi'
}

export interface ApiEndpointDiscoveryResult {
  baseUrl: string
  endpoints: DiscoveredEndpoint[]
  totalDiscovered: number
  hasSwagger: boolean
  hasOpenApi: boolean
}

// ─── Single API Endpoint Checker ─────────────────────────────────────────────

export type EndpointIssueSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type EndpointIssueCategory = 'cors' | 'auth' | 'linting' | 'staleness' | 'security' | 'performance'

export interface EndpointIssue {
  category: EndpointIssueCategory
  severity: EndpointIssueSeverity
  title: string
  detail: string
  remediation: string
}

export interface CorsCheckResult {
  allowOrigin: string | null
  allowMethods: string | null
  allowHeaders: string | null
  allowCredentials: boolean
  isWideOpen: boolean
  reflectsOrigin: boolean
  issues: EndpointIssue[]
}

export interface AuthCheckResult {
  requiresAuth: boolean
  authType: 'none' | 'basic' | 'bearer' | 'api-key' | 'oauth' | 'unknown'
  acceptsNoAuth: boolean
  weakAuthScheme: boolean
  issues: EndpointIssue[]
}

export interface LintingCheckResult {
  hasContentType: boolean
  correctContentType: boolean
  hasRateLimiting: boolean
  hasVersioning: boolean
  usesHttps: boolean
  responseFormat: 'json' | 'xml' | 'html' | 'text' | 'unknown'
  issues: EndpointIssue[]
}

export interface StalenessCheckResult {
  serverVersion: string | null
  deprecatedHeaders: string[]
  outdatedTech: string[]
  lastModified: string | null
  issues: EndpointIssue[]
}

export interface EndpointCheckResult {
  endpoint: string
  method: string
  statusCode: number
  responseTime: number
  cors: CorsCheckResult
  auth: AuthCheckResult
  linting: LintingCheckResult
  staleness: StalenessCheckResult
  totalIssues: number
  criticalCount: number
  highCount: number
}
