/**
 * External Reconnaissance Service
 *
 * Performs external scanning of internet-facing assets without requiring
 * an agent installation. Gathers real data about exposed services.
 */

import https from 'https';
import http from 'http';
import { URL } from 'url';
import dns from 'dns';
import { promisify } from 'util';
import net from 'net';
import tls from 'tls';

function tlsRejectUnauthorized(): boolean {
  const inProd = process.env.NODE_ENV === "production";
  const allowInsecure = process.env.ALLOW_INSECURE_TLS === "true";
  return !( !inProd && allowInsecure ); // true unless explicitly allowed in non-prod
}

function httpsAgent(): https.Agent {
  return new https.Agent({ rejectUnauthorized: tlsRejectUnauthorized() });
}

const dnsResolve = promisify(dns.resolve);
const dnsResolve4 = promisify(dns.resolve4);
const dnsResolve6 = promisify(dns.resolve6);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveNs = promisify(dns.resolveNs);
const dnsResolveCname = promisify(dns.resolveCname);

export interface PortScanResult {
  port: number;
  state: 'open' | 'closed' | 'filtered';
  service?: string;
  banner?: string;
}

export interface SSLCheckResult {
  valid: boolean;
  issuer?: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
  daysUntilExpiry?: number;
  protocol?: string;
  cipher?: string;
  keySize?: number;
  vulnerabilities: string[];
}

export interface HTTPFingerprintResult {
  server?: string;
  poweredBy?: string;
  technologies: string[];
  headers: Record<string, string>;
  statusCode?: number;
  redirectsTo?: string;
  securityHeaders: {
    present: string[];
    missing: string[];
  };
}

// ============================================================================
// NEW: AUTHENTICATION SURFACE DETECTION
// ============================================================================

export interface AuthenticationSurfaceResult {
  loginPages: Array<{
    path: string;
    method: string;
    indicators: string[];
    riskLevel: 'high' | 'medium' | 'low';
  }>;
  adminPanels: Array<{
    path: string;
    detected: boolean;
    technology?: string;
    protected: boolean;
  }>;
  oauthEndpoints: Array<{
    path: string;
    provider?: string;
    scopes?: string[];
  }>;
  passwordResetForms: Array<{
    path: string;
    method: string;
    tokenBased: boolean;
  }>;
  apiAuthentication: {
    bearerTokenSupported: boolean;
    apiKeySupported: boolean;
    basicAuthSupported: boolean;
    jwtDetected: boolean;
  };
  vulnerabilities: string[];
}

// ============================================================================
// NEW: ENHANCED TRANSPORT SECURITY
// ============================================================================

export interface TransportSecurityResult {
  tlsVersion: string;
  cipherSuite: string;
  keyExchange?: string;
  forwardSecrecy: boolean;
  hstsEnabled: boolean;
  hstsMaxAge?: number;
  hstsIncludeSubdomains: boolean;
  hstsPreload: boolean;
  certificateTransparency: boolean;
  ocspStapling: boolean;
  downgradeRisks: Array<{
    type: 'protocol' | 'cipher' | 'header' | 'redirect';
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    mitigiation: string;
  }>;
  gradeEstimate: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
}

// ============================================================================
// NEW: ENHANCED DNS & INFRASTRUCTURE
// ============================================================================

export interface InfrastructureResult {
  hostingProvider?: string;
  cdnProvider?: string;
  dnsProvider?: string;
  cloudPlatform?: string;
  subdomains: string[];
  relatedDomains: string[];
  ipGeolocation?: {
    country?: string;
    region?: string;
    asn?: string;
    organization?: string;
  };
  shadowAssets: Array<{
    hostname: string;
    type: 'subdomain' | 'related' | 'historical';
    risk: string;
  }>;
  spfRecord?: string;
  dmarcRecord?: string;
  mailSecurityIssues: string[];
}

// ============================================================================
// NEW: ATTACK READINESS SUMMARY
// ============================================================================

export interface AttackReadinessSummary {
  overallScore: number; // 0-100 (100 = most exposed)
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'minimal';
  executiveSummary: string;

  // Breakdown by category
  categoryScores: {
    networkExposure: number;
    transportSecurity: number;
    applicationIdentity: number;
    authenticationSurface: number;
    dnsInfrastructure: number;
  };

  // AEV integration signals
  aevNextActions: Array<{
    priority: number;
    action: string;
    exploitType: string;
    targetVector: string;
    confidence: number;
    requiredMode: 'observe' | 'passive' | 'active' | 'exploit';
  }>;

  // Kill chain positioning
  attackVectors: Array<{
    vector: string;
    mitreAttackId: string;
    feasibility: 'confirmed' | 'likely' | 'possible' | 'unlikely';
    prerequisites: string[];
  }>;

  // Quick wins for defenders
  prioritizedRemediations: Array<{
    priority: number;
    finding: string;
    remediation: string;
    effort: 'quick' | 'moderate' | 'significant';
    impact: 'high' | 'medium' | 'low';
  }>;
}

export interface DNSEnumResult {
  ipv4: string[];
  ipv6: string[];
  mx: { priority: number; exchange: string }[];
  ns: string[];
  txt: string[];
  cname: string[];
}

// ============================================================================
// ENHANCED RECON RESULT WITH 6-SECTION STRUCTURE
// ============================================================================

export interface ReconResult {
  target: string;
  scanTime: Date;

  // Section 1: Network Exposure (ports + service intelligence)
  portScan?: PortScanResult[];
  networkExposure?: {
    openPorts: number;
    highRiskPorts: number;
    serviceVersions: Array<{ port: number; service: string; version?: string; cpe?: string }>;
    protocolFindings: Array<{ protocol: string; finding: string; severity: string }>;
  };

  // Section 2: Transport Security (TLS posture + downgrade risk)
  sslCheck?: SSLCheckResult;
  transportSecurity?: TransportSecurityResult;

  // Section 3: Application Identity (tech stack + framework signals)
  httpFingerprint?: HTTPFingerprintResult;
  applicationIdentity?: {
    frameworks: string[];
    cms?: string;
    webServer?: string;
    language?: string;
    libraries: string[];
    wafDetected?: string;
  };

  // Section 4: Authentication Surface (login, admin, OAuth indicators)
  authenticationSurface?: AuthenticationSurfaceResult;

  // Section 5: DNS & Infrastructure (records, hosting patterns, shadow assets)
  dnsEnum?: DNSEnumResult;
  infrastructure?: InfrastructureResult;

  // Section 6: Attack Readiness Summary (exposure score + AEV signals)
  attackReadiness?: AttackReadinessSummary;

  errors: string[];
}

// Common ports to scan
const COMMON_PORTS = [
  { port: 21, service: 'FTP' },
  { port: 22, service: 'SSH' },
  { port: 23, service: 'Telnet' },
  { port: 25, service: 'SMTP' },
  { port: 53, service: 'DNS' },
  { port: 80, service: 'HTTP' },
  { port: 110, service: 'POP3' },
  { port: 143, service: 'IMAP' },
  { port: 443, service: 'HTTPS' },
  { port: 445, service: 'SMB' },
  { port: 993, service: 'IMAPS' },
  { port: 995, service: 'POP3S' },
  { port: 1433, service: 'MSSQL' },
  { port: 1521, service: 'Oracle' },
  { port: 3306, service: 'MySQL' },
  { port: 3389, service: 'RDP' },
  { port: 5432, service: 'PostgreSQL' },
  { port: 5900, service: 'VNC' },
  { port: 6379, service: 'Redis' },
  { port: 8080, service: 'HTTP-Alt' },
  { port: 8443, service: 'HTTPS-Alt' },
  { port: 27017, service: 'MongoDB' },
];

// Security headers to check
const SECURITY_HEADERS = [
  'Strict-Transport-Security',
  'Content-Security-Policy',
  'X-Content-Type-Options',
  'X-Frame-Options',
  'X-XSS-Protection',
  'Referrer-Policy',
  'Permissions-Policy',
];

/**
 * Scan a single port
 */
async function scanPort(host: string, port: number, timeout: number = 3000): Promise<PortScanResult> {
  const service = COMMON_PORTS.find(p => p.port === port)?.service;

  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = '';

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      // Try to grab banner
      socket.write('HEAD / HTTP/1.0\r\n\r\n');
    });

    socket.on('data', (data) => {
      banner = data.toString().substring(0, 200);
      socket.destroy();
      resolve({ port, state: 'open', service, banner: banner || undefined });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ port, state: 'filtered', service });
    });

    socket.on('error', (err: NodeJS.ErrnoException) => {
      socket.destroy();
      if (err.code === 'ECONNREFUSED') {
        resolve({ port, state: 'closed', service });
      } else {
        resolve({ port, state: 'filtered', service });
      }
    });

    socket.connect(port, host);
  });
}

/**
 * Perform port scan on common ports
 */
export async function portScan(host: string, ports?: number[]): Promise<PortScanResult[]> {
  const portsToScan = ports || COMMON_PORTS.map(p => p.port);

  // Scan in batches to avoid overwhelming the target
  const batchSize = 10;
  const results: PortScanResult[] = [];

  for (let i = 0; i < portsToScan.length; i += batchSize) {
    const batch = portsToScan.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(port => scanPort(host, port))
    );
    results.push(...batchResults);
  }

  // Return only open ports for cleaner results
  return results.filter(r => r.state === 'open');
}

/**
 * Check SSL/TLS certificate and configuration
 */
export async function sslCheck(host: string, port: number = 443): Promise<SSLCheckResult> {
  return new Promise((resolve) => {
    const vulnerabilities: string[] = [];

    const options: tls.ConnectionOptions = {
      host,
      port,
      servername: host,
      rejectUnauthorized: tlsRejectUnauthorized(),
      timeout: 10000,
    };

    const socket = tls.connect(options, () => {
      const cert = socket.getPeerCertificate();
      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();

      // Check for vulnerabilities
      if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
        vulnerabilities.push(`Deprecated protocol: ${protocol}`);
      }

      if (cipher && cipher.name) {
        if (cipher.name.includes('RC4')) {
          vulnerabilities.push('Weak cipher: RC4');
        }
        if (cipher.name.includes('DES')) {
          vulnerabilities.push('Weak cipher: DES');
        }
        if (cipher.name.includes('NULL')) {
          vulnerabilities.push('No encryption: NULL cipher');
        }
      }

      // Check certificate expiry
      let daysUntilExpiry: number | undefined;
      if (cert.valid_to) {
        const expiryDate = new Date(cert.valid_to);
        const now = new Date();
        daysUntilExpiry = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

        if (daysUntilExpiry < 0) {
          vulnerabilities.push('Certificate expired');
        } else if (daysUntilExpiry < 30) {
          vulnerabilities.push(`Certificate expires in ${daysUntilExpiry} days`);
        }
      }

      // Check if self-signed
      if (cert.issuer && cert.subject) {
        const issuerCN = typeof cert.issuer === 'object' ? cert.issuer.CN : cert.issuer;
        const subjectCN = typeof cert.subject === 'object' ? cert.subject.CN : cert.subject;
        if (issuerCN === subjectCN) {
          vulnerabilities.push('Self-signed certificate');
        }
      }

      socket.end();

      resolve({
        valid: socket.authorized,
        issuer: typeof cert.issuer === 'object' ? (cert.issuer.CN || cert.issuer.O) : String(cert.issuer),
        subject: typeof cert.subject === 'object' ? cert.subject.CN : String(cert.subject),
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        daysUntilExpiry,
        protocol: protocol || undefined,
        cipher: cipher?.name,
        keySize: cipher ? parseInt(cipher.version || '0') : undefined,
        vulnerabilities,
      });
    });

    socket.on('error', (err) => {
      resolve({
        valid: false,
        vulnerabilities: [`Connection error: ${err.message}`],
      });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        valid: false,
        vulnerabilities: ['Connection timeout'],
      });
    });
  });
}

/**
 * HTTP fingerprinting - detect server technologies
 */
export async function httpFingerprint(target: string): Promise<HTTPFingerprintResult> {
  return new Promise((resolve) => {
    let url: URL;
    try {
      url = new URL(target.startsWith('http') ? target : `https://${target}`);
    } catch {
      resolve({
        technologies: [],
        headers: {},
        securityHeaders: { present: [], missing: SECURITY_HEADERS },
      });
      return;
    }

    const client = url.protocol === 'https:' ? https : http;

    const req = client.request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname || '/',
      method: 'HEAD',
      timeout: 10000,
      ...(url.protocol === 'https:' ? { agent: httpsAgent() } : {}),
    }, (res) => {
      const headers: Record<string, string> = {};
      const technologies: string[] = [];

      // Collect headers
      for (const [key, value] of Object.entries(res.headers)) {
        if (value) {
          headers[key] = Array.isArray(value) ? value.join(', ') : value;
        }
      }

      // Detect server
      const server = res.headers['server'];
      if (server) {
        technologies.push(`Server: ${server}`);
      }

      // Detect X-Powered-By
      const poweredBy = res.headers['x-powered-by'];
      if (poweredBy) {
        technologies.push(`Powered by: ${poweredBy}`);
      }

      // Check for common technologies in headers
      if (res.headers['x-aspnet-version']) {
        technologies.push(`ASP.NET: ${res.headers['x-aspnet-version']}`);
      }
      if (res.headers['x-drupal-cache']) {
        technologies.push('Drupal');
      }
      if (res.headers['x-generator']) {
        technologies.push(`Generator: ${res.headers['x-generator']}`);
      }

      // Check security headers
      const presentHeaders = SECURITY_HEADERS.filter(h =>
        res.headers[h.toLowerCase()]
      );
      const missingHeaders = SECURITY_HEADERS.filter(h =>
        !res.headers[h.toLowerCase()]
      );

      resolve({
        server: typeof server === 'string' ? server : undefined,
        poweredBy: typeof poweredBy === 'string' ? poweredBy : undefined,
        technologies,
        headers,
        statusCode: res.statusCode,
        redirectsTo: res.headers['location'],
        securityHeaders: {
          present: presentHeaders,
          missing: missingHeaders,
        },
      });
    });

    req.on('error', (err) => {
      resolve({
        technologies: [`Error: ${err.message}`],
        headers: {},
        securityHeaders: { present: [], missing: SECURITY_HEADERS },
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({
        technologies: ['Connection timeout'],
        headers: {},
        securityHeaders: { present: [], missing: SECURITY_HEADERS },
      });
    });

    req.end();
  });
}

/**
 * DNS enumeration
 */
export async function dnsEnumeration(domain: string): Promise<DNSEnumResult> {
  const result: DNSEnumResult = {
    ipv4: [],
    ipv6: [],
    mx: [],
    ns: [],
    txt: [],
    cname: [],
  };

  // Run all DNS queries in parallel
  const queries = [
    dnsResolve4(domain).then(r => { result.ipv4 = r; }).catch(() => {}),
    dnsResolve6(domain).then(r => { result.ipv6 = r; }).catch(() => {}),
    dnsResolveMx(domain).then(r => { result.mx = r; }).catch(() => {}),
    dnsResolveNs(domain).then(r => { result.ns = r; }).catch(() => {}),
    dnsResolveTxt(domain).then(r => { result.txt = r.map(t => t.join('')); }).catch(() => {}),
    dnsResolveCname(domain).then(r => { result.cname = r; }).catch(() => {}),
  ];

  await Promise.all(queries);

  return result;
}

// ============================================================================
// NEW: AUTHENTICATION SURFACE DETECTION
// ============================================================================

const AUTH_PATHS = [
  { path: '/login', type: 'login' },
  { path: '/signin', type: 'login' },
  { path: '/sign-in', type: 'login' },
  { path: '/auth/login', type: 'login' },
  { path: '/admin', type: 'admin' },
  { path: '/admin/login', type: 'admin' },
  { path: '/wp-admin', type: 'admin' },
  { path: '/administrator', type: 'admin' },
  { path: '/dashboard', type: 'admin' },
  { path: '/console', type: 'admin' },
  { path: '/oauth/authorize', type: 'oauth' },
  { path: '/oauth2/authorize', type: 'oauth' },
  { path: '/auth/oauth', type: 'oauth' },
  { path: '/.well-known/openid-configuration', type: 'oauth' },
  { path: '/forgot-password', type: 'password_reset' },
  { path: '/password-reset', type: 'password_reset' },
  { path: '/reset-password', type: 'password_reset' },
  { path: '/api/auth', type: 'api_auth' },
  { path: '/api/login', type: 'api_auth' },
  { path: '/api/v1/auth', type: 'api_auth' },
];

async function checkAuthPath(
  baseUrl: string,
  authPath: { path: string; type: string }
): Promise<{
  exists: boolean;
  statusCode?: number;
  indicators: string[];
  headers?: Record<string, string>;
}> {
  return new Promise((resolve) => {
    const url = new URL(authPath.path, baseUrl);
    const client = url.protocol === "https:" ? https : http;

    const req = client.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: url.pathname,
        method: "GET",
        timeout: 5000,
        ...(url.protocol === "https:" ? { agent: httpsAgent() } : {}),
        headers: {
          "User-Agent": "OdinForge-Scanner/1.0",
          Accept: "text/html,application/json",
        },
      },
      (res) => {
        const indicators: string[] = [];
        const headers: Record<string, string> = {};

        for (const [key, value] of Object.entries(res.headers)) {
          if (value) {
            headers[key] = Array.isArray(value) ? value.join(", ") : value;
          }
        }

        // Check for auth-related response patterns
        if (res.headers["www-authenticate"]) {
          indicators.push("WWW-Authenticate header present");
        }

        if (res.headers["set-cookie"]) {
          const cookies = Array.isArray(res.headers["set-cookie"])
            ? res.headers["set-cookie"].join(";")
            : res.headers["set-cookie"];

          if (
            cookies.toLowerCase().includes("session") ||
            cookies.toLowerCase().includes("auth")
          ) {
            indicators.push("Session/auth cookie detected");
          }
        }
      
      // 200 or redirect indicates the path exists
        const exists =
          res.statusCode !== undefined &&
          res.statusCode >= 200 &&
          res.statusCode < 400;

        if (res.statusCode === 401 || res.statusCode === 403) {
          indicators.push(`Protected endpoint (${res.statusCode})`);
        }

        resolve({ exists, statusCode: res.statusCode, indicators, headers });
      }
    );

    req.on("error", () => resolve({ exists: false, indicators: [] }));
    req.on("timeout", () => {
      req.destroy();
      resolve({ exists: false, indicators: [] });
    });

    req.end();
  });
}

export async function detectAuthenticationSurface(target: string): Promise<AuthenticationSurfaceResult> {
  const result: AuthenticationSurfaceResult = {
    loginPages: [],
    adminPanels: [],
    oauthEndpoints: [],
    passwordResetForms: [],
    apiAuthentication: {
      bearerTokenSupported: false,
      apiKeySupported: false,
      basicAuthSupported: false,
      jwtDetected: false,
    },
    vulnerabilities: [],
  };
  
  let baseUrl: string;
  try {
    baseUrl = target.startsWith('http') ? target : `https://${target}`;
    new URL(baseUrl);
  } catch {
    return result;
  }
  
  // Check all auth paths in parallel (batched)
  const batchSize = 5;
  for (let i = 0; i < AUTH_PATHS.length; i += batchSize) {
    const batch = AUTH_PATHS.slice(i, i + batchSize);
    const results = await Promise.all(
      batch.map(async (authPath) => {
        const check = await checkAuthPath(baseUrl, authPath);
        return { authPath, check };
      })
    );
    
    for (const { authPath, check } of results) {
      if (!check.exists && check.statusCode !== 401 && check.statusCode !== 403) continue;
      
      switch (authPath.type) {
        case 'login':
          result.loginPages.push({
            path: authPath.path,
            method: 'GET',
            indicators: check.indicators,
            riskLevel: check.indicators.length > 1 ? 'high' : 'medium',
          });
          break;
        case 'admin':
          result.adminPanels.push({
            path: authPath.path,
            detected: true,
            protected: check.statusCode === 401 || check.statusCode === 403,
          });
          if (!check.statusCode || (check.statusCode >= 200 && check.statusCode < 300)) {
            result.vulnerabilities.push(`Unprotected admin panel at ${authPath.path}`);
          }
          break;
        case 'oauth':
          result.oauthEndpoints.push({
            path: authPath.path,
          });
          break;
        case 'password_reset':
          result.passwordResetForms.push({
            path: authPath.path,
            method: 'GET',
            tokenBased: true,
          });
          break;
        case 'api_auth':
          if (check.headers?.['www-authenticate']?.toLowerCase().includes('bearer')) {
            result.apiAuthentication.bearerTokenSupported = true;
          }
          if (check.headers?.['www-authenticate']?.toLowerCase().includes('basic')) {
            result.apiAuthentication.basicAuthSupported = true;
          }
          break;
      }
    }
  }
  
  // Detect vulnerabilities
  if (result.loginPages.length > 0 && result.passwordResetForms.length === 0) {
    result.vulnerabilities.push('Login pages detected but no password reset mechanism found');
  }
  
  if (result.adminPanels.some(p => !p.protected)) {
    result.vulnerabilities.push('One or more admin panels may be publicly accessible');
  }
  
  return result;
}

// ============================================================================
// NEW: ENHANCED TRANSPORT SECURITY ANALYSIS
// ============================================================================

export function analyzeTransportSecurity(sslResult: SSLCheckResult, httpResult?: HTTPFingerprintResult): TransportSecurityResult {
  const downgradeRisks: TransportSecurityResult['downgradeRisks'] = [];
  
  // Analyze TLS version
  const tlsVersion = sslResult.protocol || 'unknown';
  if (tlsVersion === 'TLSv1' || tlsVersion === 'TLSv1.1') {
    downgradeRisks.push({
      type: 'protocol',
      description: `Deprecated TLS version: ${tlsVersion}`,
      severity: 'high',
      mitigiation: 'Disable TLS 1.0 and 1.1, enable TLS 1.2 and 1.3 only',
    });
  }
  
  // Analyze cipher suite
  const cipher = sslResult.cipher || 'unknown';
  if (cipher.includes('RC4') || cipher.includes('DES') || cipher.includes('NULL') || cipher.includes('EXPORT')) {
    downgradeRisks.push({
      type: 'cipher',
      description: `Weak cipher suite: ${cipher}`,
      severity: cipher.includes('NULL') ? 'critical' : 'high',
      mitigiation: 'Disable weak ciphers, use AEAD cipher suites (AES-GCM, ChaCha20)',
    });
  }
  
  // Check for forward secrecy
  const forwardSecrecy = cipher.includes('ECDHE') || cipher.includes('DHE');
  if (!forwardSecrecy) {
    downgradeRisks.push({
      type: 'cipher',
      description: 'No forward secrecy (missing ECDHE/DHE key exchange)',
      severity: 'medium',
      mitigiation: 'Enable ECDHE or DHE key exchange for forward secrecy',
    });
  }
  
  // Check HSTS
  const hstsHeader = httpResult?.headers?.['strict-transport-security'];
  const hstsEnabled = !!hstsHeader;
  let hstsMaxAge: number | undefined;
  let hstsIncludeSubdomains = false;
  let hstsPreload = false;
  
  if (hstsHeader) {
    const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/i);
    if (maxAgeMatch) {
      hstsMaxAge = parseInt(maxAgeMatch[1], 10);
      if (hstsMaxAge < 31536000) { // Less than 1 year
        downgradeRisks.push({
          type: 'header',
          description: `HSTS max-age too short: ${hstsMaxAge} seconds`,
          severity: 'low',
          mitigiation: 'Set HSTS max-age to at least 1 year (31536000)',
        });
      }
    }
    hstsIncludeSubdomains = hstsHeader.toLowerCase().includes('includesubdomains');
    hstsPreload = hstsHeader.toLowerCase().includes('preload');
  } else {
    downgradeRisks.push({
      type: 'header',
      description: 'HSTS not enabled - vulnerable to SSL stripping',
      severity: 'medium',
      mitigiation: 'Add Strict-Transport-Security header with appropriate max-age',
    });
  }
  
  // Check for HTTP to HTTPS redirect (potential downgrade if missing)
  if (httpResult?.redirectsTo && !httpResult.redirectsTo.startsWith('https://')) {
    downgradeRisks.push({
      type: 'redirect',
      description: 'HTTP redirect does not enforce HTTPS',
      severity: 'medium',
      mitigiation: 'Ensure all HTTP requests redirect to HTTPS',
    });
  }
  
  // Calculate grade estimate
  let grade: TransportSecurityResult['gradeEstimate'] = 'A';
  const criticalCount = downgradeRisks.filter(r => r.severity === 'critical').length;
  const highCount = downgradeRisks.filter(r => r.severity === 'high').length;
  const mediumCount = downgradeRisks.filter(r => r.severity === 'medium').length;
  
  if (criticalCount > 0) grade = 'F';
  else if (highCount >= 2) grade = 'D';
  else if (highCount === 1) grade = 'C';
  else if (mediumCount >= 2) grade = 'B';
  else if (mediumCount === 1 || downgradeRisks.length > 0) grade = 'A';
  else if (hstsPreload && forwardSecrecy && tlsVersion === 'TLSv1.3') grade = 'A+';
  
  return {
    tlsVersion,
    cipherSuite: cipher,
    forwardSecrecy,
    hstsEnabled,
    hstsMaxAge,
    hstsIncludeSubdomains,
    hstsPreload,
    certificateTransparency: false, // Would need additional check
    ocspStapling: false, // Would need additional check
    downgradeRisks,
    gradeEstimate: grade,
  };
}

// ============================================================================
// NEW: INFRASTRUCTURE ANALYSIS
// ============================================================================

const CDN_PROVIDERS: Record<string, string[]> = {
  'Cloudflare': ['cloudflare', 'cf-ray'],
  'Akamai': ['akamai', 'x-akamai'],
  'Fastly': ['fastly', 'x-served-by'],
  'AWS CloudFront': ['cloudfront', 'x-amz-cf'],
  'Azure CDN': ['x-azure-', 'afd'],
  'Google Cloud CDN': ['via: google', 'x-goog-'],
};

const HOSTING_PROVIDERS: Record<string, string[]> = {
  'AWS': ['amazonaws.com', 'aws', 'ec2'],
  'Azure': ['azure', 'azurewebsites.net', 'cloudapp.azure'],
  'GCP': ['googleusercontent.com', 'appspot.com', 'cloud.google'],
  'Heroku': ['heroku', 'herokuapp.com'],
  'DigitalOcean': ['digitalocean'],
  'Vercel': ['vercel', 'now.sh'],
  'Netlify': ['netlify'],
};

export function analyzeInfrastructure(dnsResult: DNSEnumResult, httpResult?: HTTPFingerprintResult): InfrastructureResult {
  const result: InfrastructureResult = {
    subdomains: [],
    relatedDomains: [],
    shadowAssets: [],
    mailSecurityIssues: [],
  };
  
  // Detect CDN from headers
  if (httpResult?.headers) {
    const headerStr = JSON.stringify(httpResult.headers).toLowerCase();
    for (const [provider, indicators] of Object.entries(CDN_PROVIDERS)) {
      if (indicators.some(i => headerStr.includes(i))) {
        result.cdnProvider = provider;
        break;
      }
    }
  }
  
  // Detect hosting from CNAME or IP patterns
  const cnames = dnsResult.cname.join(' ').toLowerCase();
  for (const [provider, indicators] of Object.entries(HOSTING_PROVIDERS)) {
    if (indicators.some(i => cnames.includes(i))) {
      result.hostingProvider = provider;
      result.cloudPlatform = provider;
      break;
    }
  }
  
  // Analyze TXT records for SPF/DMARC
  for (const txt of dnsResult.txt) {
    if (txt.startsWith('v=spf1')) {
      result.spfRecord = txt;
      if (txt.includes('+all')) {
        result.mailSecurityIssues.push('SPF record uses +all (allows any sender)');
      }
    }
    if (txt.startsWith('v=DMARC1')) {
      result.dmarcRecord = txt;
      if (txt.includes('p=none')) {
        result.mailSecurityIssues.push('DMARC policy is set to none (no enforcement)');
      }
    }
  }
  
  if (!result.spfRecord) {
    result.mailSecurityIssues.push('No SPF record found - email spoofing possible');
  }
  if (!result.dmarcRecord) {
    result.mailSecurityIssues.push('No DMARC record found - email spoofing possible');
  }
  
  // Identify DNS provider from NS records
  const nsStr = dnsResult.ns.join(' ').toLowerCase();
  if (nsStr.includes('cloudflare')) result.dnsProvider = 'Cloudflare';
  else if (nsStr.includes('awsdns')) result.dnsProvider = 'AWS Route53';
  else if (nsStr.includes('azure-dns')) result.dnsProvider = 'Azure DNS';
  else if (nsStr.includes('google')) result.dnsProvider = 'Google Cloud DNS';
  
  return result;
}

// ============================================================================
// NEW: ATTACK READINESS SUMMARY GENERATION
// ============================================================================

export function generateAttackReadiness(
  reconResult: ReconResult
): AttackReadinessSummary {
  const scores = {
    networkExposure: 0,
    transportSecurity: 0,
    applicationIdentity: 0,
    authenticationSurface: 0,
    dnsInfrastructure: 0,
  };
  
  const aevNextActions: AttackReadinessSummary['aevNextActions'] = [];
  const attackVectors: AttackReadinessSummary['attackVectors'] = [];
  const prioritizedRemediations: AttackReadinessSummary['prioritizedRemediations'] = [];
  
  // Score Network Exposure
  if (reconResult.portScan) {
    const openPorts = reconResult.portScan.filter(p => p.state === 'open').length;
    const highRiskPorts = reconResult.portScan.filter(p => 
      p.state === 'open' && [21, 23, 445, 3389, 5900, 1433, 1521, 3306, 5432, 6379, 27017].includes(p.port)
    );
    
    scores.networkExposure = Math.min(100, openPorts * 5 + highRiskPorts.length * 15);
    
    // Add AEV actions for exposed services
    for (const port of highRiskPorts) {
      aevNextActions.push({
        priority: port.port === 445 ? 1 : port.port === 3389 ? 2 : 3,
        action: `Validate ${port.service} exploitation`,
        exploitType: port.port === 445 ? 'smb_attack' : port.port === 3389 ? 'rdp_attack' : 'service_exploit',
        targetVector: `${reconResult.target}:${port.port}`,
        confidence: 70,
        requiredMode: 'active',
      });
      
      attackVectors.push({
        vector: `Exposed ${port.service} service`,
        mitreAttackId: port.port === 22 ? 'T1021.004' : port.port === 3389 ? 'T1021.001' : 'T1210',
        feasibility: highRiskPorts.length > 2 ? 'likely' : 'possible',
        prerequisites: ['Network access to target'],
      });
    }
    
    if (highRiskPorts.length > 0) {
      prioritizedRemediations.push({
        priority: 1,
        finding: `${highRiskPorts.length} high-risk service(s) exposed`,
        remediation: 'Implement network segmentation and firewall rules to restrict access',
        effort: 'moderate',
        impact: 'high',
      });
    }
  }
  
  // Score Transport Security
  if (reconResult.sslCheck) {
    const vulnCount = reconResult.sslCheck.vulnerabilities.length;
    scores.transportSecurity = Math.min(100, vulnCount * 20);
    
    if (reconResult.sslCheck.vulnerabilities.some(v => v.includes('TLSv1'))) {
      aevNextActions.push({
        priority: 2,
        action: 'Test for TLS downgrade attacks',
        exploitType: 'tls_downgrade',
        targetVector: reconResult.target,
        confidence: 60,
        requiredMode: 'passive',
      });
      
      attackVectors.push({
        vector: 'TLS Downgrade Attack',
        mitreAttackId: 'T1557.002',
        feasibility: 'possible',
        prerequisites: ['Man-in-the-middle position'],
      });
    }
    
    if (vulnCount > 0) {
      prioritizedRemediations.push({
        priority: 2,
        finding: `${vulnCount} TLS/SSL vulnerability(ies)`,
        remediation: 'Update TLS configuration to use TLS 1.2+ with strong cipher suites',
        effort: 'quick',
        impact: 'high',
      });
    }
  }
  
  // Score Application Identity
  if (reconResult.httpFingerprint) {
    const techCount = reconResult.httpFingerprint.technologies.length;
    const missingHeaders = reconResult.httpFingerprint.securityHeaders.missing.length;
    scores.applicationIdentity = Math.min(100, techCount * 10 + missingHeaders * 8);
    
    if (reconResult.httpFingerprint.server && /\d+\.\d+/.test(reconResult.httpFingerprint.server)) {
      aevNextActions.push({
        priority: 3,
        action: 'Check for known CVEs in disclosed versions',
        exploitType: 'cve_exploitation',
        targetVector: reconResult.httpFingerprint.server,
        confidence: 50,
        requiredMode: 'observe',
      });
    }
    
    if (missingHeaders >= 3) {
      prioritizedRemediations.push({
        priority: 3,
        finding: `${missingHeaders} security headers missing`,
        remediation: 'Add HSTS, CSP, X-Frame-Options, and other security headers',
        effort: 'quick',
        impact: 'medium',
      });
    }
  }
  
  // Score Authentication Surface
  if (reconResult.authenticationSurface) {
    const auth = reconResult.authenticationSurface;
    const vulnCount = auth.vulnerabilities.length;
    const exposedEndpoints = auth.loginPages.length + auth.adminPanels.length;
    scores.authenticationSurface = Math.min(100, vulnCount * 25 + exposedEndpoints * 10);
    
    if (auth.adminPanels.some(p => !p.protected)) {
      aevNextActions.push({
        priority: 1,
        action: 'Test unprotected admin panel for default credentials',
        exploitType: 'auth_bypass',
        targetVector: auth.adminPanels.find(p => !p.protected)?.path || '/admin',
        confidence: 80,
        requiredMode: 'active',
      });
      
      attackVectors.push({
        vector: 'Unprotected Admin Panel',
        mitreAttackId: 'T1078.001',
        feasibility: 'likely',
        prerequisites: [],
      });
    }
    
    if (auth.loginPages.length > 0) {
      aevNextActions.push({
        priority: 4,
        action: 'Test login form for injection vulnerabilities',
        exploitType: 'sqli',
        targetVector: auth.loginPages[0].path,
        confidence: 40,
        requiredMode: 'active',
      });
    }
  }
  
  // Score DNS Infrastructure
  if (reconResult.infrastructure) {
    const mailIssues = reconResult.infrastructure.mailSecurityIssues.length;
    scores.dnsInfrastructure = Math.min(100, mailIssues * 15);
    
    if (mailIssues > 0) {
      prioritizedRemediations.push({
        priority: 4,
        finding: `${mailIssues} email security issue(s)`,
        remediation: 'Implement SPF, DKIM, and DMARC with enforcement policy',
        effort: 'moderate',
        impact: 'medium',
      });
    }
  }
  
  // Calculate overall score
  const categoryWeights = {
    networkExposure: 0.25,
    transportSecurity: 0.20,
    applicationIdentity: 0.15,
    authenticationSurface: 0.25,
    dnsInfrastructure: 0.15,
  };
  
  const overallScore = Math.round(
    scores.networkExposure * categoryWeights.networkExposure +
    scores.transportSecurity * categoryWeights.transportSecurity +
    scores.applicationIdentity * categoryWeights.applicationIdentity +
    scores.authenticationSurface * categoryWeights.authenticationSurface +
    scores.dnsInfrastructure * categoryWeights.dnsInfrastructure
  );
  
  // Determine risk level
  let riskLevel: AttackReadinessSummary['riskLevel'];
  if (overallScore >= 75) riskLevel = 'critical';
  else if (overallScore >= 50) riskLevel = 'high';
  else if (overallScore >= 25) riskLevel = 'medium';
  else if (overallScore >= 10) riskLevel = 'low';
  else riskLevel = 'minimal';
  
  // Generate executive summary
  const highPriorityCount = aevNextActions.filter(a => a.priority <= 2).length;
  const executiveSummary = highPriorityCount > 0
    ? `Target has ${highPriorityCount} high-priority attack vector(s) requiring immediate attention. Overall exposure score is ${overallScore}/100 (${riskLevel} risk).`
    : `Target has moderate security posture with ${aevNextActions.length} potential attack vectors identified. Exposure score is ${overallScore}/100.`;
  
  return {
    overallScore,
    riskLevel,
    executiveSummary,
    categoryScores: scores,
    aevNextActions: aevNextActions.sort((a, b) => a.priority - b.priority),
    attackVectors,
    prioritizedRemediations: prioritizedRemediations.sort((a, b) => a.priority - b.priority),
  };
}

export type ProgressCallback = (phase: 'dns' | 'ports' | 'ssl' | 'http' | 'auth' | 'analysis' | 'complete', progress: number, message: string, portsFound?: number, vulnerabilitiesFound?: number) => void;

/**
 * Full external reconnaissance scan with progress reporting
 * Now includes all 6 sections: Network Exposure, Transport Security, Application Identity,
 * Authentication Surface, DNS & Infrastructure, and Attack Readiness Summary
 */
export async function fullRecon(
  target: string, 
  options: {
    portScan?: boolean;
    sslCheck?: boolean;
    httpFingerprint?: boolean;
    dnsEnum?: boolean;
    authSurface?: boolean;
    generateSummary?: boolean;
  } = {},
  onProgress?: ProgressCallback
): Promise<ReconResult> {
  const { 
    portScan: doPortScan = true, 
    sslCheck: doSSLCheck = true, 
    httpFingerprint: doHTTPFingerprint = true, 
    dnsEnum: doDNSEnum = true,
    authSurface: doAuthSurface = true,
    generateSummary: doGenerateSummary = true,
  } = options;
  
  const result: ReconResult = {
    target,
    scanTime: new Date(),
    errors: [],
  };
  
  // Extract hostname from target
  let hostname: string;
  try {
    if (target.startsWith('http')) {
      hostname = new URL(target).hostname;
    } else {
      hostname = target.replace(/^[^:]+:\/\//, '').split('/')[0].split(':')[0];
    }
  } catch {
    result.errors.push('Invalid target format');
    return result;
  }
  
  // Calculate progress steps based on enabled scans (now includes auth and analysis phases)
  const enabledScans = [doDNSEnum, doPortScan, doSSLCheck, doHTTPFingerprint, doAuthSurface].filter(Boolean).length;
  let completedScans = 0;
  let totalVulns = 0;
  
  // Guard against no scans enabled
  if (enabledScans === 0) {
    onProgress?.('complete', 100, 'No scan types selected', 0, 0);
    return result;
  }
  
  const updateProgress = (phase: 'dns' | 'ports' | 'ssl' | 'http' | 'auth' | 'analysis', message: string) => {
    completedScans++;
    const progress = Math.min(95, Math.round((completedScans / (enabledScans + 1)) * 100));
    onProgress?.(phase, progress, message, result.portScan?.filter(p => p.state === 'open').length || 0, totalVulns);
  };
  
  // =========================================================================
  // PHASE 1: DNS & Infrastructure (Section 5)
  // =========================================================================
  if (doDNSEnum) {
    onProgress?.('dns', 5, 'Resolving DNS records...', 0, 0);
    try {
      result.dnsEnum = await dnsEnumeration(hostname);
      updateProgress('dns', `DNS complete: ${result.dnsEnum.ipv4.length} IPv4, ${result.dnsEnum.mx.length} MX records`);
    } catch (e: any) {
      result.errors.push(`DNS enumeration error: ${e.message}`);
      updateProgress('dns', 'DNS enumeration failed');
    }
  }
  
  // =========================================================================
  // PHASE 2: Network Exposure (Section 1)
  // =========================================================================
  if (doPortScan) {
    onProgress?.('ports', Math.round((completedScans / enabledScans) * 100) + 5, 'Scanning ports...', 0, totalVulns);
    try {
      result.portScan = await portScan(hostname);
      const openPorts = result.portScan.filter(p => p.state === 'open').length;
      
      // Build enhanced network exposure data
      const highRiskPorts = result.portScan.filter(p => 
        p.state === 'open' && [21, 23, 445, 3389, 5900, 1433, 1521, 3306, 5432, 6379, 27017].includes(p.port)
      );
      
      result.networkExposure = {
        openPorts,
        highRiskPorts: highRiskPorts.length,
        serviceVersions: result.portScan
          .filter(p => p.state === 'open' && p.banner)
          .map(p => {
            const versionMatch = p.banner?.match(/\d+\.\d+(\.\d+)?/);
            return {
              port: p.port,
              service: p.service || 'unknown',
              version: versionMatch ? versionMatch[0] : undefined,
            };
          }),
        protocolFindings: highRiskPorts.map(p => ({
          protocol: p.service || 'unknown',
          finding: `High-risk service exposed on port ${p.port}`,
          severity: [21, 23, 445].includes(p.port) ? 'critical' : 'high',
        })),
      };
      
      totalVulns += highRiskPorts.length;
      updateProgress('ports', `Port scan complete: ${openPorts} open ports found`);
    } catch (e: any) {
      result.errors.push(`Port scan error: ${e.message}`);
      updateProgress('ports', 'Port scan failed');
    }
  }
  
  // =========================================================================
  // PHASE 3: Transport Security (Section 2)
  // =========================================================================
  if (doSSLCheck) {
    onProgress?.('ssl', Math.round((completedScans / enabledScans) * 100) + 5, 'Checking SSL/TLS...', result.portScan?.filter(p => p.state === 'open').length || 0, totalVulns);
    try {
      result.sslCheck = await sslCheck(hostname);
      totalVulns += result.sslCheck.vulnerabilities.length;
      updateProgress('ssl', `SSL check complete: ${result.sslCheck.vulnerabilities.length} issues found`);
    } catch (e: any) {
      result.errors.push(`SSL check error: ${e.message}`);
      updateProgress('ssl', 'SSL check failed');
    }
  }
  
  // =========================================================================
  // PHASE 4: Application Identity (Section 3)
  // =========================================================================
  if (doHTTPFingerprint) {
    onProgress?.('http', Math.round((completedScans / enabledScans) * 100) + 5, 'Fingerprinting HTTP...', result.portScan?.filter(p => p.state === 'open').length || 0, totalVulns);
    try {
      result.httpFingerprint = await httpFingerprint(target);
      const missingHeaders = result.httpFingerprint.securityHeaders.missing.length;
      
      // Build enhanced application identity
      result.applicationIdentity = {
        frameworks: [],
        libraries: [],
        webServer: result.httpFingerprint.server,
      };
      
      // Parse technologies
      for (const tech of result.httpFingerprint.technologies) {
        if (tech.includes('Server:')) {
          result.applicationIdentity.webServer = tech.replace('Server: ', '');
        } else if (tech.includes('Powered by:')) {
          const lang = tech.replace('Powered by: ', '');
          if (lang.toLowerCase().includes('php')) result.applicationIdentity.language = 'PHP';
          else if (lang.toLowerCase().includes('asp')) result.applicationIdentity.language = 'ASP.NET';
          else if (lang.toLowerCase().includes('express')) result.applicationIdentity.language = 'Node.js';
        } else if (tech.includes('Drupal') || tech.includes('WordPress') || tech.includes('Joomla')) {
          result.applicationIdentity.cms = tech;
        } else {
          result.applicationIdentity.frameworks.push(tech);
        }
      }
      
      totalVulns += Math.min(missingHeaders, 3);
      updateProgress('http', `HTTP fingerprint complete: ${result.httpFingerprint.technologies.length} technologies detected`);
    } catch (e: any) {
      result.errors.push(`HTTP fingerprint error: ${e.message}`);
      updateProgress('http', 'HTTP fingerprint failed');
    }
  }
  
  // =========================================================================
  // PHASE 5: Authentication Surface (Section 4)
  // =========================================================================
  if (doAuthSurface) {
    onProgress?.('auth', Math.round((completedScans / enabledScans) * 100) + 5, 'Detecting authentication surfaces...', result.portScan?.filter(p => p.state === 'open').length || 0, totalVulns);
    try {
      result.authenticationSurface = await detectAuthenticationSurface(target);
      totalVulns += result.authenticationSurface.vulnerabilities.length;
      updateProgress('auth', `Auth surface complete: ${result.authenticationSurface.loginPages.length} login pages, ${result.authenticationSurface.adminPanels.length} admin panels`);
    } catch (e: any) {
      result.errors.push(`Auth surface detection error: ${e.message}`);
      updateProgress('auth', 'Auth surface detection failed');
    }
  }
  
  // =========================================================================
  // PHASE 6: Enhanced Analysis & Attack Readiness Summary
  // =========================================================================
  onProgress?.('analysis', 90, 'Generating attack readiness summary...', result.portScan?.filter(p => p.state === 'open').length || 0, totalVulns);
  
  // Build transport security analysis if we have SSL data
  if (result.sslCheck) {
    result.transportSecurity = analyzeTransportSecurity(result.sslCheck, result.httpFingerprint);
    totalVulns += result.transportSecurity.downgradeRisks.length;
  }
  
  // Build infrastructure analysis if we have DNS data
  if (result.dnsEnum) {
    result.infrastructure = analyzeInfrastructure(result.dnsEnum, result.httpFingerprint);
    totalVulns += result.infrastructure.mailSecurityIssues.length;
  }
  
  // Generate attack readiness summary (Section 6)
  if (doGenerateSummary) {
    result.attackReadiness = generateAttackReadiness(result);
  }
  
  // Final complete notification
  onProgress?.('complete', 100, 'Scan complete!', result.portScan?.filter(p => p.state === 'open').length || 0, totalVulns);
  
  return result;
}

/**
 * Convert recon results to evaluation-ready format with exploit chaining signals
 */
export interface ReconExposure {
  type: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  evidence: string;
  exploitChainSignal?: {
    exploitType: string;
    mitreAttackId?: string;
    chainPosition: 'initial_access' | 'execution' | 'persistence' | 'privilege_escalation' | 'lateral_movement';
    requiredMode: 'observe' | 'passive' | 'active' | 'exploit';
    confidence: number;
  };
}

export function reconToExposures(result: ReconResult): ReconExposure[] {
  const exposures: ReconExposure[] = [];
  
  // =========================================================================
  // Network Exposure findings (Section 1)
  // =========================================================================
  if (result.portScan) {
    for (const port of result.portScan) {
      if (port.state === 'open') {
        // High-risk services
        if ([21, 23, 445, 3389, 5900].includes(port.port)) {
          exposures.push({
            type: 'exposed_service',
            description: `High-risk service exposed: ${port.service || 'Unknown'} on port ${port.port}`,
            severity: 'high',
            evidence: `Port ${port.port} (${port.service}) is open. ${port.banner ? `Banner: ${port.banner}` : ''}`,
            exploitChainSignal: {
              exploitType: port.port === 445 ? 'smb_attack' : port.port === 3389 ? 'rdp_attack' : 'service_exploit',
              mitreAttackId: port.port === 22 ? 'T1021.004' : port.port === 3389 ? 'T1021.001' : 'T1210',
              chainPosition: 'initial_access',
              requiredMode: 'active',
              confidence: 70,
            },
          });
        }
        // Database services
        else if ([1433, 1521, 3306, 5432, 6379, 27017].includes(port.port)) {
          exposures.push({
            type: 'exposed_database',
            description: `Database service exposed: ${port.service || 'Unknown'} on port ${port.port}`,
            severity: 'critical',
            evidence: `Port ${port.port} (${port.service}) is open and accessible from the internet.`,
            exploitChainSignal: {
              exploitType: 'database_attack',
              mitreAttackId: 'T1190',
              chainPosition: 'initial_access',
              requiredMode: 'active',
              confidence: 85,
            },
          });
        }
      }
    }
  }
  
  // =========================================================================
  // Transport Security findings (Section 2)
  // =========================================================================
  if (result.sslCheck) {
    for (const vuln of result.sslCheck.vulnerabilities) {
      let severity: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'medium';
      if (vuln.includes('expired') || vuln.includes('NULL')) {
        severity = 'high';
      } else if (vuln.includes('Self-signed')) {
        severity = 'medium';
      }
      
      exposures.push({
        type: 'ssl_misconfiguration',
        description: vuln,
        severity,
        evidence: `SSL/TLS issue detected: ${vuln}. Protocol: ${result.sslCheck.protocol}, Cipher: ${result.sslCheck.cipher}`,
        exploitChainSignal: vuln.includes('TLSv1') ? {
          exploitType: 'tls_downgrade',
          mitreAttackId: 'T1557.002',
          chainPosition: 'initial_access',
          requiredMode: 'passive',
          confidence: 50,
        } : undefined,
      });
    }
  }
  
  // Transport security downgrade risks
  if (result.transportSecurity?.downgradeRisks) {
    for (const risk of result.transportSecurity.downgradeRisks) {
      exposures.push({
        type: 'transport_security_risk',
        description: risk.description,
        severity: risk.severity,
        evidence: `Downgrade risk: ${risk.description}. Mitigation: ${risk.mitigiation}`,
        exploitChainSignal: {
          exploitType: 'tls_downgrade',
          mitreAttackId: 'T1557.002',
          chainPosition: 'initial_access',
          requiredMode: 'passive',
          confidence: 45,
        },
      });
    }
  }
  
  // =========================================================================
  // Application Identity findings (Section 3)
  // =========================================================================
  if (result.httpFingerprint?.securityHeaders.missing.length) {
    const missing = result.httpFingerprint.securityHeaders.missing;
    
    if (missing.includes('Strict-Transport-Security')) {
      exposures.push({
        type: 'missing_security_header',
        description: 'Missing HSTS header - vulnerable to protocol downgrade attacks',
        severity: 'medium',
        evidence: 'Strict-Transport-Security header not present in HTTP response.',
        exploitChainSignal: {
          exploitType: 'ssl_stripping',
          mitreAttackId: 'T1557.002',
          chainPosition: 'initial_access',
          requiredMode: 'passive',
          confidence: 40,
        },
      });
    }
    
    if (missing.includes('Content-Security-Policy')) {
      exposures.push({
        type: 'missing_security_header',
        description: 'Missing CSP header - vulnerable to XSS attacks',
        severity: 'medium',
        evidence: 'Content-Security-Policy header not present in HTTP response.',
        exploitChainSignal: {
          exploitType: 'xss',
          mitreAttackId: 'T1059.007',
          chainPosition: 'execution',
          requiredMode: 'active',
          confidence: 35,
        },
      });
    }
    
    if (missing.includes('X-Frame-Options')) {
      exposures.push({
        type: 'missing_security_header',
        description: 'Missing X-Frame-Options - vulnerable to clickjacking',
        severity: 'low',
        evidence: 'X-Frame-Options header not present in HTTP response.',
        exploitChainSignal: {
          exploitType: 'clickjacking',
          mitreAttackId: 'T1185',
          chainPosition: 'execution',
          requiredMode: 'active',
          confidence: 30,
        },
      });
    }
  }
  
  // Server version disclosure
  if (result.httpFingerprint?.server) {
    const server = result.httpFingerprint.server;
    if (/\d+\.\d+/.test(server)) {
      exposures.push({
        type: 'information_disclosure',
        description: `Server version disclosed: ${server}`,
        severity: 'info',
        evidence: `Server header reveals version information: ${server}`,
        exploitChainSignal: {
          exploitType: 'cve_exploitation',
          chainPosition: 'initial_access',
          requiredMode: 'observe',
          confidence: 25,
        },
      });
    }
  }
  
  // =========================================================================
  // Authentication Surface findings (Section 4)
  // =========================================================================
  if (result.authenticationSurface) {
    const auth = result.authenticationSurface;
    
    // Unprotected admin panels are critical
    for (const panel of auth.adminPanels) {
      if (!panel.protected) {
        exposures.push({
          type: 'unprotected_admin',
          description: `Unprotected admin panel at ${panel.path}`,
          severity: 'critical',
          evidence: `Admin panel accessible without authentication at ${panel.path}`,
          exploitChainSignal: {
            exploitType: 'auth_bypass',
            mitreAttackId: 'T1078.001',
            chainPosition: 'initial_access',
            requiredMode: 'active',
            confidence: 90,
          },
        });
      }
    }
    
    // Login pages are attack vectors
    for (const login of auth.loginPages) {
      exposures.push({
        type: 'login_page',
        description: `Login page detected at ${login.path}`,
        severity: 'info',
        evidence: `Login form at ${login.path}. Indicators: ${login.indicators.join(', ')}`,
        exploitChainSignal: {
          exploitType: 'credential_attack',
          mitreAttackId: 'T1110',
          chainPosition: 'initial_access',
          requiredMode: 'active',
          confidence: 40,
        },
      });
    }
    
    // Add auth vulnerabilities
    for (const vuln of auth.vulnerabilities) {
      exposures.push({
        type: 'auth_vulnerability',
        description: vuln,
        severity: 'high',
        evidence: vuln,
        exploitChainSignal: {
          exploitType: 'auth_bypass',
          mitreAttackId: 'T1078',
          chainPosition: 'initial_access',
          requiredMode: 'active',
          confidence: 60,
        },
      });
    }
  }
  
  // =========================================================================
  // DNS & Infrastructure findings (Section 5)
  // =========================================================================
  if (result.infrastructure) {
    for (const issue of result.infrastructure.mailSecurityIssues) {
      exposures.push({
        type: 'mail_security_issue',
        description: issue,
        severity: issue.includes('SPF') || issue.includes('DMARC') ? 'medium' : 'low',
        evidence: issue,
        exploitChainSignal: {
          exploitType: 'email_spoofing',
          mitreAttackId: 'T1566.001',
          chainPosition: 'initial_access',
          requiredMode: 'passive',
          confidence: 55,
        },
      });
    }
  }
  
  return exposures;
}

/**
 * Map recon exposures to exploit chaining playbook signals
 */
export function mapToExploitChainSignals(exposures: ReconExposure[]): Array<{
  exploitType: string;
  targetVector: string;
  mitreAttackId?: string;
  chainPosition: string;
  requiredMode: string;
  confidence: number;
  relatedExposures: string[];
}> {
  const signals: Map<string, {
    exploitType: string;
    targetVector: string;
    mitreAttackId?: string;
    chainPosition: string;
    requiredMode: string;
    confidence: number;
    relatedExposures: string[];
  }> = new Map();
  
  for (const exposure of exposures) {
    if (!exposure.exploitChainSignal) continue;
    
    const key = `${exposure.exploitChainSignal.exploitType}-${exposure.exploitChainSignal.chainPosition}`;
    const existing = signals.get(key);
    
    if (existing) {
      existing.confidence = Math.max(existing.confidence, exposure.exploitChainSignal.confidence);
      existing.relatedExposures.push(exposure.description);
    } else {
      signals.set(key, {
        exploitType: exposure.exploitChainSignal.exploitType,
        targetVector: exposure.type,
        mitreAttackId: exposure.exploitChainSignal.mitreAttackId,
        chainPosition: exposure.exploitChainSignal.chainPosition,
        requiredMode: exposure.exploitChainSignal.requiredMode,
        confidence: exposure.exploitChainSignal.confidence,
        relatedExposures: [exposure.description],
      });
    }
  }
  
  return Array.from(signals.values()).sort((a, b) => b.confidence - a.confidence);
}
