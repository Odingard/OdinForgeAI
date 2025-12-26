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

export interface DNSEnumResult {
  ipv4: string[];
  ipv6: string[];
  mx: { priority: number; exchange: string }[];
  ns: string[];
  txt: string[];
  cname: string[];
}

export interface ReconResult {
  target: string;
  scanTime: Date;
  portScan?: PortScanResult[];
  sslCheck?: SSLCheckResult;
  httpFingerprint?: HTTPFingerprintResult;
  dnsEnum?: DNSEnumResult;
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
    
    const options = {
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
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
        issuer: typeof cert.issuer === 'object' ? cert.issuer.CN || cert.issuer.O : String(cert.issuer),
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
      rejectUnauthorized: false,
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

/**
 * Full external reconnaissance scan
 */
export async function fullRecon(
  target: string, 
  options: {
    portScan?: boolean;
    sslCheck?: boolean;
    httpFingerprint?: boolean;
    dnsEnum?: boolean;
  } = {}
): Promise<ReconResult> {
  const { 
    portScan: doPortScan = true, 
    sslCheck: doSSLCheck = true, 
    httpFingerprint: doHTTPFingerprint = true, 
    dnsEnum: doDNSEnum = true 
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
  
  // Run scans in parallel where possible
  const tasks: Promise<void>[] = [];
  
  if (doPortScan) {
    tasks.push(
      portScan(hostname)
        .then(r => { result.portScan = r; })
        .catch(e => { result.errors.push(`Port scan error: ${e.message}`); })
    );
  }
  
  if (doSSLCheck) {
    tasks.push(
      sslCheck(hostname)
        .then(r => { result.sslCheck = r; })
        .catch(e => { result.errors.push(`SSL check error: ${e.message}`); })
    );
  }
  
  if (doHTTPFingerprint) {
    tasks.push(
      httpFingerprint(target)
        .then(r => { result.httpFingerprint = r; })
        .catch(e => { result.errors.push(`HTTP fingerprint error: ${e.message}`); })
    );
  }
  
  if (doDNSEnum) {
    tasks.push(
      dnsEnumeration(hostname)
        .then(r => { result.dnsEnum = r; })
        .catch(e => { result.errors.push(`DNS enumeration error: ${e.message}`); })
    );
  }
  
  await Promise.all(tasks);
  
  return result;
}

/**
 * Convert recon results to evaluation-ready format
 */
export function reconToExposures(result: ReconResult): Array<{
  type: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  evidence: string;
}> {
  const exposures: Array<{
    type: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    evidence: string;
  }> = [];
  
  // Port scan findings
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
          });
        }
        // Database services
        else if ([1433, 1521, 3306, 5432, 6379, 27017].includes(port.port)) {
          exposures.push({
            type: 'exposed_database',
            description: `Database service exposed: ${port.service || 'Unknown'} on port ${port.port}`,
            severity: 'critical',
            evidence: `Port ${port.port} (${port.service}) is open and accessible from the internet.`,
          });
        }
      }
    }
  }
  
  // SSL findings
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
      });
    }
  }
  
  // HTTP security header findings
  if (result.httpFingerprint?.securityHeaders.missing.length) {
    const missing = result.httpFingerprint.securityHeaders.missing;
    
    if (missing.includes('Strict-Transport-Security')) {
      exposures.push({
        type: 'missing_security_header',
        description: 'Missing HSTS header - vulnerable to protocol downgrade attacks',
        severity: 'medium',
        evidence: 'Strict-Transport-Security header not present in HTTP response.',
      });
    }
    
    if (missing.includes('Content-Security-Policy')) {
      exposures.push({
        type: 'missing_security_header',
        description: 'Missing CSP header - vulnerable to XSS attacks',
        severity: 'medium',
        evidence: 'Content-Security-Policy header not present in HTTP response.',
      });
    }
    
    if (missing.includes('X-Frame-Options')) {
      exposures.push({
        type: 'missing_security_header',
        description: 'Missing X-Frame-Options - vulnerable to clickjacking',
        severity: 'low',
        evidence: 'X-Frame-Options header not present in HTTP response.',
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
      });
    }
  }
  
  return exposures;
}
