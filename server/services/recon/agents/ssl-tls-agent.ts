import * as tls from 'tls'
import * as https from 'https'
import { BaseAgent, AgentStep, AgentResult, Evidence } from './agent-framework'

export class SslTlsAgent extends BaseAgent {
  name = 'ssl-tls-agent'
  description = 'Verifies and exploits SSL/TLS misconfigurations: expired certs, weak protocols, bad ciphers, HSTS bypass'
  handles = [
    'ssl:expired-cert', 'ssl:self-signed', 'ssl:weak-protocol',
    'ssl:weak-cipher', 'ssl:no-tls13', 'ssl:cert-mismatch', 'ssl:missing-hsts'
  ]

  plan(finding: any): { name: string; description: string }[] {
    switch (finding._findingType) {
      case 'ssl:expired-cert':
        return [
          { name: 'verify-expiry', description: 'Connect and pull live certificate to confirm expiration' },
          { name: 'check-chain', description: 'Validate the full certificate chain' },
          { name: 'test-browsers', description: 'Simulate browser trust behavior with expired cert' },
        ]
      case 'ssl:self-signed':
        return [
          { name: 'verify-self-signed', description: 'Confirm certificate issuer matches subject' },
          { name: 'check-pinning', description: 'Test for certificate pinning headers (HPKP)' },
          { name: 'assess-mitm-risk', description: 'Evaluate man-in-the-middle attack surface' },
        ]
      case 'ssl:weak-protocol':
        return [
          { name: 'verify-protocol', description: 'Attempt handshake with the reported weak protocol' },
          { name: 'test-downgrade', description: 'Attempt protocol downgrade attack (POODLE/DROWN vector)' },
          { name: 'enumerate-supported', description: 'Map all supported protocol versions' },
        ]
      case 'ssl:weak-cipher':
        return [
          { name: 'verify-cipher', description: 'Force negotiation with the weak cipher suite' },
          { name: 'test-beast', description: 'Test for BEAST attack conditions (CBC in TLS 1.0)' },
          { name: 'enumerate-ciphers', description: 'List all accepted cipher suites by preference order' },
        ]
      default:
        return [
          { name: 'verify-tls', description: 'Generic TLS verification handshake' },
          { name: 'assess-config', description: 'Evaluate overall TLS configuration' },
        ]
    }
  }

  async executeStep(stepName: string, finding: any, previousSteps: AgentStep[]): Promise<string> {
    const host = finding._target
    const port = finding.port ?? 443

    switch (stepName) {
      case 'verify-expiry': {
        return new Promise((resolve) => {
          const socket = tls.connect(port, host, { rejectUnauthorized: false, servername: host, timeout: 5000 }, () => {
            const cert = socket.getPeerCertificate()
            const validTo = new Date(cert.valid_to)
            const now = new Date()
            const days = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))
            socket.destroy()
            if (now > validTo) {
              resolve(`[CONFIRMED] Certificate expired on ${cert.valid_to} (${Math.abs(days)} days ago)\nSubject: ${(cert.subject as any)?.CN}\nIssuer: ${(cert.issuer as any)?.CN}\nSerial: ${cert.serialNumber}`)
            } else {
              resolve(`[NOT EXPIRED] Certificate valid until ${cert.valid_to} (${days} days remaining)`)
            }
          })
          socket.on('error', (err) => resolve(`[ERROR] TLS connect failed: ${err.message}`))
          socket.on('timeout', () => { socket.destroy(); resolve('[TIMEOUT] TLS handshake timed out') })
        })
      }

      case 'check-chain': {
        return new Promise((resolve) => {
          const socket = tls.connect(port, host, { rejectUnauthorized: true, servername: host, timeout: 5000 }, () => {
            socket.destroy()
            resolve('[VALID CHAIN] Certificate chain validates against system trust store')
          })
          socket.on('error', (err: any) => {
            resolve(`[BROKEN CHAIN] Chain validation failed: ${err.code ?? err.message}`)
          })
          socket.on('timeout', () => { socket.destroy(); resolve('[TIMEOUT]') })
        })
      }

      case 'test-browsers': {
        // Simulate what browsers would do with an expired/invalid cert
        return new Promise((resolve) => {
          https.get(`https://${host}:${port}`, { rejectUnauthorized: true, timeout: 5000 }, (res) => {
            res.resume()
            resolve(`[ACCEPTED] Browser would accept this cert (status: ${res.statusCode})`)
          }).on('error', (err: any) => {
            if (err.code === 'CERT_HAS_EXPIRED') resolve('[BLOCKED] Browser would show certificate expired error')
            else if (err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT') resolve('[BLOCKED] Browser would show self-signed warning')
            else if (err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') resolve('[BLOCKED] Browser would show untrusted CA warning')
            else resolve(`[BLOCKED] Browser would block with: ${err.code ?? err.message}`)
          })
        })
      }

      case 'verify-self-signed': {
        return new Promise((resolve) => {
          const socket = tls.connect(port, host, { rejectUnauthorized: false, servername: host, timeout: 5000 }, () => {
            const cert = socket.getPeerCertificate()
            const subjectCN = (cert.subject as any)?.CN ?? ''
            const issuerCN = (cert.issuer as any)?.CN ?? ''
            socket.destroy()
            if (subjectCN === issuerCN) {
              resolve(`[CONFIRMED] Self-signed: Subject CN "${subjectCN}" === Issuer CN "${issuerCN}"\nFingerprint: ${cert.fingerprint}`)
            } else {
              resolve(`[NOT SELF-SIGNED] Subject: ${subjectCN}, Issuer: ${issuerCN}`)
            }
          })
          socket.on('error', (err) => resolve(`[ERROR] ${err.message}`))
        })
      }

      case 'check-pinning': {
        return new Promise((resolve) => {
          https.get(`https://${host}:${port}`, { rejectUnauthorized: false, timeout: 5000 }, (res) => {
            const hpkp = res.headers['public-key-pins'] ?? res.headers['public-key-pins-report-only']
            res.resume()
            if (hpkp) {
              resolve(`[PINNED] HPKP header found: ${hpkp}`)
            } else {
              resolve('[NO PINNING] No HPKP headers detected — certificate can be replaced without client-side detection')
            }
          }).on('error', () => resolve('[ERROR] Could not check pinning headers'))
        })
      }

      case 'assess-mitm-risk': {
        const selfSigned = previousSteps.find(s => s.name === 'verify-self-signed')?.output ?? ''
        const pinning = previousSteps.find(s => s.name === 'check-pinning')?.output ?? ''
        const risks: string[] = []
        if (selfSigned.includes('[CONFIRMED]')) risks.push('Self-signed cert: Any attacker can generate a matching cert')
        if (pinning.includes('[NO PINNING]')) risks.push('No cert pinning: MITM proxy can intercept traffic')
        return risks.length > 0
          ? `[HIGH RISK] MITM attack surface:\n${risks.map(r => `  • ${r}`).join('\n')}`
          : '[LOW RISK] Certificate and pinning configuration appear adequate'
      }

      case 'verify-protocol': {
        const protocol = finding.protocol ?? 'TLSv1'
        return new Promise((resolve) => {
          const socket = tls.connect(port, host, {
            rejectUnauthorized: false,
            servername: host,
            minVersion: protocol as any,
            maxVersion: protocol as any,
            timeout: 5000
          }, () => {
            const actual = socket.getProtocol()
            socket.destroy()
            resolve(`[CONFIRMED] Server accepted ${protocol} handshake (negotiated: ${actual})`)
          })
          socket.on('error', () => resolve(`[NOT VULNERABLE] Server rejected ${protocol} handshake`))
          socket.on('timeout', () => { socket.destroy(); resolve('[TIMEOUT]') })
        })
      }

      case 'test-downgrade': {
        // Test if the server can be forced to a weaker protocol
        const protocols = ['TLSv1', 'TLSv1.1'] as const
        const results: string[] = []
        for (const proto of protocols) {
          const accepted = await new Promise<boolean>((resolve) => {
            const socket = tls.connect(port, host, {
              rejectUnauthorized: false, servername: host,
              minVersion: proto as any, maxVersion: proto as any, timeout: 3000
            }, () => { socket.destroy(); resolve(true) })
            socket.on('error', () => resolve(false))
            socket.on('timeout', () => { socket.destroy(); resolve(false) })
          })
          results.push(`${proto}: ${accepted ? '[ACCEPTED - VULNERABLE]' : '[REJECTED - SAFE]'}`)
        }
        return `Protocol downgrade test:\n${results.join('\n')}`
      }

      case 'enumerate-supported': {
        const all = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'] as const
        const results: string[] = []
        for (const proto of all) {
          const supported = await new Promise<boolean>((resolve) => {
            const socket = tls.connect(port, host, {
              rejectUnauthorized: false, servername: host,
              minVersion: proto as any, maxVersion: proto as any, timeout: 3000
            }, () => { socket.destroy(); resolve(true) })
            socket.on('error', () => resolve(false))
            socket.on('timeout', () => { socket.destroy(); resolve(false) })
          })
          results.push(`${proto}: ${supported ? '✓ Supported' : '✗ Not supported'}`)
        }
        return results.join('\n')
      }

      case 'verify-cipher': {
        return new Promise((resolve) => {
          const socket = tls.connect(port, host, { rejectUnauthorized: false, servername: host, timeout: 5000 }, () => {
            const cipher = socket.getCipher()
            socket.destroy()
            resolve(`Negotiated cipher: ${cipher?.name} (${cipher?.version})\nStandard name: ${cipher?.standardName ?? 'N/A'}`)
          })
          socket.on('error', (err) => resolve(`[ERROR] ${err.message}`))
        })
      }

      case 'test-beast': {
        // BEAST requires TLS 1.0 + CBC cipher
        return new Promise((resolve) => {
          const socket = tls.connect(port, host, {
            rejectUnauthorized: false, servername: host,
            maxVersion: 'TLSv1' as any, timeout: 5000
          }, () => {
            const cipher = socket.getCipher()
            socket.destroy()
            if (cipher?.name?.includes('CBC')) {
              resolve(`[VULNERABLE] BEAST conditions met: TLS 1.0 with CBC cipher (${cipher.name})`)
            } else {
              resolve(`[SAFE] TLS 1.0 accepted but using stream cipher: ${cipher?.name}`)
            }
          })
          socket.on('error', () => resolve('[SAFE] TLS 1.0 not accepted'))
        })
      }

      case 'enumerate-ciphers': {
        return new Promise((resolve) => {
          const socket = tls.connect(port, host, { rejectUnauthorized: false, servername: host, timeout: 5000 }, () => {
            const cipher = socket.getCipher()
            socket.destroy()
            resolve(`Server preferred cipher: ${cipher?.name}\nProtocol: ${cipher?.version}\nNote: Full cipher enumeration requires OpenSSL CLI or specialized library`)
          })
          socket.on('error', (err) => resolve(`[ERROR] ${err.message}`))
        })
      }

      case 'verify-tls': {
        return new Promise((resolve) => {
          const socket = tls.connect(port, host, { rejectUnauthorized: false, servername: host, timeout: 5000 }, () => {
            const proto = socket.getProtocol()
            const cipher = socket.getCipher()
            socket.destroy()
            resolve(`TLS connected: ${proto}, Cipher: ${cipher?.name}`)
          })
          socket.on('error', (err) => resolve(`TLS connection failed: ${err.message}`))
        })
      }

      case 'assess-config': {
        const allOutputs = previousSteps.map(s => s.output ?? '').join('\n')
        const issues: string[] = []
        if (allOutputs.includes('VULNERABLE')) issues.push('Weak protocol or cipher accepted')
        if (allOutputs.includes('CONFIRMED') && allOutputs.includes('Self-signed')) issues.push('Self-signed certificate in use')
        if (allOutputs.includes('BROKEN CHAIN')) issues.push('Certificate chain validation fails')
        return issues.length > 0
          ? `Configuration issues found:\n${issues.map(i => `  • ${i}`).join('\n')}`
          : 'TLS configuration appears adequate'
      }

      default:
        return `Step ${stepName} not implemented`
    }
  }

  analyze(finding: any, steps: AgentStep[]): AgentResult {
    const evidence: Evidence[] = steps.filter(s => s.output).map(s => ({
      type: 'log' as const,
      label: s.name,
      content: s.output!
    }))

    const allOutput = steps.map(s => s.output ?? '').join('\n')
    const hasConfirmed = allOutput.includes('[CONFIRMED]') || allOutput.includes('[VULNERABLE]')
    const hasBlocked = allOutput.includes('[BLOCKED]')

    let severity: AgentResult['severity'] = 'info'
    let exploitable = false

    if (finding._findingType === 'ssl:expired-cert' && hasConfirmed) {
      severity = 'high'
      exploitable = hasBlocked ? false : true // If browsers block it, exploitation is harder
    } else if (finding._findingType === 'ssl:self-signed' && hasConfirmed) {
      severity = 'high'
      exploitable = true
    } else if (finding._findingType === 'ssl:weak-protocol' && hasConfirmed) {
      severity = allOutput.includes('SSLv') ? 'critical' : 'high'
      exploitable = true
    } else if (finding._findingType === 'ssl:weak-cipher' && allOutput.includes('BEAST')) {
      severity = 'high'
      exploitable = true
    }

    return {
      verified: hasConfirmed,
      exploitable,
      severity,
      evidence,
      recommendations: this.getRecommendations(finding._findingType),
      rawOutput: allOutput,
      cweId: 'CWE-326',
      cvssScore: exploitable ? 7.4 : (hasConfirmed ? 5.3 : null)
    }
  }

  private getRecommendations(findingType: string): string[] {
    switch (findingType) {
      case 'ssl:expired-cert':
        return ['Renew the certificate immediately', 'Set up automated renewal (e.g., certbot)', 'Configure monitoring for certificate expiry']
      case 'ssl:self-signed':
        return ['Obtain a certificate from a trusted CA (Let\'s Encrypt is free)', 'Implement certificate pinning if self-signed is intentional']
      case 'ssl:weak-protocol':
        return ['Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1', 'Set minimum protocol to TLS 1.2', 'Enable TLS 1.3']
      case 'ssl:weak-cipher':
        return ['Disable RC4, DES, 3DES, and NULL ciphers', 'Prefer AEAD ciphers (AES-GCM, ChaCha20)', 'Use Mozilla SSL Configuration Generator']
      default:
        return ['Review TLS configuration against Mozilla SSL guidelines']
    }
  }
}
