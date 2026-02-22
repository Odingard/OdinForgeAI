import * as tls from 'tls'
import * as net from 'net'
import type { CertificateInfo, SslIssue, SslTlsResult } from './types'

// Weak cipher suites that should be flagged
const WEAK_CIPHERS = [
  'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon', 'RC2', 'IDEA', 'SEED'
]

// Legacy protocols that should be disabled
const LEGACY_PROTOCOLS: { name: string; version: string }[] = [
  { name: 'SSLv2',   version: 'SSLv2' },
  { name: 'SSLv3',   version: 'SSLv3' },
  { name: 'TLSv1.0', version: 'TLSv1' },
  { name: 'TLSv1.1', version: 'TLSv1.1' },
]

// Connect via TLS and extract the full certificate chain + negotiated params
async function tlsConnect(
  host: string,
  port: number,
  options: tls.ConnectionOptions = {}
): Promise<{ socket: tls.TLSSocket; cert: tls.PeerCertificate } | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      port,
      host,
      { rejectUnauthorized: false, servername: host, timeout: 5000, ...options },
      () => {
        const cert = socket.getPeerCertificate()
        resolve({ socket, cert })
      }
    )
    socket.on('error', () => resolve(null))
    socket.on('timeout', () => { socket.destroy(); resolve(null) })
  })
}

// Try to negotiate a connection with a specific TLS/SSL version
async function testProtocol(host: string, port: number, minVersion: string, maxVersion: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      port,
      host,
      {
        rejectUnauthorized: false,
        servername: host,
        timeout: 3000,
        minVersion: minVersion as tls.SecureVersion,
        maxVersion: maxVersion as tls.SecureVersion,
      },
      () => { socket.destroy(); resolve(true) }
    )
    socket.on('error', () => resolve(false))
    socket.on('timeout', () => { socket.destroy(); resolve(false) })
  })
}

function parseCertificate(cert: tls.PeerCertificate): CertificateInfo {
  const validFrom = new Date(cert.valid_from)
  const validTo = new Date(cert.valid_to)
  const now = new Date()
  const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))

  return {
    subject: typeof cert.subject === 'object' ? (cert.subject as any).CN || JSON.stringify(cert.subject) : String(cert.subject),
    issuer: typeof cert.issuer === 'object' ? (cert.issuer as any).CN || (cert.issuer as any).O || JSON.stringify(cert.issuer) : String(cert.issuer),
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    isExpired: now > validTo,
    daysUntilExpiry,
    serialNumber: cert.serialNumber || 'Unknown',
    fingerprint: cert.fingerprint || 'Unknown'
  }
}

export async function analyzeSslTls(host: string, port: number = 443): Promise<SslTlsResult> {
  const issues: SslIssue[] = []

  // ── Connect and grab the certificate ───────────────────────────────────────
  const connection = await tlsConnect(host, port)
  let certificate: CertificateInfo | null = null
  let negotiatedCipher = ''
  let negotiatedProtocol = ''

  if (connection) {
    certificate = parseCertificate(connection.cert)
    negotiatedCipher = connection.socket.getCipher()?.name ?? ''
    negotiatedProtocol = connection.socket.getProtocol() ?? ''
    connection.socket.destroy()
  } else {
    issues.push({
      severity: 'critical',
      title: 'TLS Connection Failed',
      description: `Could not establish a TLS connection to ${host}:${port}`
    })
    return { host, port, certificate: null, protocols: [], cipherSuites: [], issues }
  }

  // ── Certificate Issues ─────────────────────────────────────────────────────
  if (certificate) {
    if (certificate.isExpired) {
      issues.push({
        severity: 'critical',
        title: 'Certificate Expired',
        description: `Certificate expired on ${certificate.validTo}`
      })
    } else if (certificate.daysUntilExpiry < 30) {
      issues.push({
        severity: 'high',
        title: 'Certificate Expiring Soon',
        description: `Certificate expires in ${certificate.daysUntilExpiry} days`
      })
    }

    if (certificate.subject === certificate.issuer) {
      issues.push({
        severity: 'high',
        title: 'Self-Signed Certificate',
        description: 'Certificate is self-signed and will not be trusted by browsers'
      })
    }
  }

  // ── Protocol Support ───────────────────────────────────────────────────────
  const protocols: { name: string; supported: boolean }[] = []

  // Test legacy protocols (all should be disabled)
  for (const proto of LEGACY_PROTOCOLS) {
    const supported = await testProtocol(host, port, proto.version as any, proto.version as any)
    protocols.push({ name: proto.name, supported })
    if (supported) {
      issues.push({
        severity: proto.name.includes('SSL') ? 'critical' : 'high',
        title: `${proto.name} Supported`,
        description: `${proto.name} is deprecated and vulnerable. Disable immediately.`
      })
    }
  }

  // Test modern protocols
  const tls12 = await testProtocol(host, port, 'TLSv1.2', 'TLSv1.2')
  protocols.push({ name: 'TLSv1.2', supported: tls12 })

  const tls13 = await testProtocol(host, port, 'TLSv1.3', 'TLSv1.3')
  protocols.push({ name: 'TLSv1.3', supported: tls13 })

  if (!tls13) {
    issues.push({
      severity: 'medium',
      title: 'TLS 1.3 Not Supported',
      description: 'TLS 1.3 provides improved security and performance. Consider enabling it.'
    })
  }

  // ── Cipher Analysis ────────────────────────────────────────────────────────
  const cipherSuites: string[] = [negotiatedCipher]

  for (const weak of WEAK_CIPHERS) {
    if (negotiatedCipher.toUpperCase().includes(weak)) {
      issues.push({
        severity: 'high',
        title: `Weak Cipher Negotiated: ${weak}`,
        description: `The negotiated cipher suite contains ${weak}, which is considered insecure.`
      })
    }
  }

  return {
    host,
    port,
    certificate,
    protocols,
    cipherSuites,
    issues
  }
}
