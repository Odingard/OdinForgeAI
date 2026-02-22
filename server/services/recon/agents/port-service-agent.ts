import * as net from 'net'
import * as https from 'https'
import * as http from 'http'
import { BaseAgent, AgentStep, AgentResult, Evidence } from './agent-framework'

export class PortServiceAgent extends BaseAgent {
  name = 'port-service-agent'
  description = 'Investigates open ports: banner grabs, default cred testing, exposed databases, unprotected admin panels'
  handles = [
    'port:exposed-database', 'port:exposed-admin', 'port:exposed-remote',
    'port:unencrypted-service', 'port:debug-endpoint', 'port:exposed-cache'
  ]

  plan(finding: any): { name: string; description: string }[] {
    switch (finding._findingType) {
      case 'port:exposed-database':
        return [
          { name: 'banner-grab', description: 'Grab the service banner to identify exact version' },
          { name: 'test-no-auth', description: 'Attempt connection without credentials' },
          { name: 'test-default-creds', description: 'Try common default credentials' },
          { name: 'enumerate-data', description: 'If accessible, enumerate databases/tables' },
          { name: 'check-public-facing', description: 'Verify this port is reachable from the internet' },
        ]
      case 'port:exposed-admin':
        return [
          { name: 'identify-service', description: 'Fingerprint the admin panel/service' },
          { name: 'check-auth', description: 'Test if authentication is required' },
          { name: 'test-default-creds', description: 'Try default admin credentials' },
          { name: 'enumerate-features', description: 'Map accessible admin functionality' },
        ]
      case 'port:exposed-remote':
        return [
          { name: 'banner-grab', description: 'Identify the remote access service and version' },
          { name: 'check-auth-methods', description: 'Enumerate supported authentication methods' },
          { name: 'test-brute-protection', description: 'Check for account lockout/rate limiting' },
        ]
      case 'port:exposed-cache':
        return [
          { name: 'banner-grab', description: 'Identify cache service and version' },
          { name: 'test-no-auth', description: 'Attempt unauthenticated access' },
          { name: 'dump-stats', description: 'Pull statistics and configuration info' },
          { name: 'test-data-access', description: 'Attempt to read cached data' },
        ]
      case 'port:debug-endpoint':
        return [
          { name: 'identify-service', description: 'Fingerprint the debug endpoint' },
          { name: 'enumerate-data', description: 'Extract any exposed debug data' },
          { name: 'check-rce', description: 'Test for remote code execution via debug interface' },
        ]
      default:
        return [
          { name: 'banner-grab', description: 'Grab service banner' },
          { name: 'assess-exposure', description: 'Evaluate risk of this exposed service' },
        ]
    }
  }

  async executeStep(stepName: string, finding: any, previousSteps: AgentStep[]): Promise<string> {
    const host = finding._target
    const port = finding.port ?? 0
    const service = finding.service ?? 'unknown'

    switch (stepName) {
      case 'banner-grab': {
        return new Promise((resolve) => {
          const socket = new net.Socket()
          let banner = ''
          socket.setTimeout(3000)
          socket.on('data', (data) => {
            banner += data.toString('utf-8').replace(/[^\x20-\x7E\n\r]/g, '')
            if (banner.length > 500) socket.destroy()
          })
          socket.on('timeout', () => socket.destroy())
          socket.on('error', (err) => resolve(`[ERROR] Connection failed: ${err.message}`))
          socket.on('close', () => {
            if (banner.length > 0) {
              resolve(`[BANNER] ${host}:${port}\n${banner.substring(0, 500)}`)
            } else {
              resolve(`[NO BANNER] ${host}:${port} — service accepted connection but sent no banner`)
            }
          })
          socket.connect(port, host, () => {
            // Nudge services that need us to speak first
            if (port === 6379) socket.write('INFO\r\n')
            else if (port === 11211) socket.write('version\r\nstats\r\n')
            else if (port === 27017) {
              // MongoDB wire protocol: isMaster command
              const buf = Buffer.from('3a000000000000000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069734d6173746572000100000000', 'hex')
              socket.write(buf)
            }
            else if (service.includes('HTTP') || [80, 8080, 8443, 8888, 9090].includes(port)) {
              socket.write(`GET / HTTP/1.1\r\nHost: ${host}\r\n\r\n`)
            }
          })
        })
      }

      case 'test-no-auth': {
        if (port === 6379) {
          // Redis: try PING without auth
          return new Promise((resolve) => {
            const socket = new net.Socket()
            socket.setTimeout(3000)
            let response = ''
            socket.on('data', (data) => { response += data.toString() })
            socket.on('timeout', () => socket.destroy())
            socket.on('error', () => resolve('[ERROR] Connection refused'))
            socket.on('close', () => {
              if (response.includes('+PONG') || response.includes('redis_version')) {
                resolve(`[NO AUTH REQUIRED] Redis responded without authentication!\nResponse: ${response.substring(0, 200)}`)
              } else if (response.includes('NOAUTH') || response.includes('ERR')) {
                resolve(`[AUTH REQUIRED] Redis requires password: ${response.substring(0, 100)}`)
              } else {
                resolve(`[UNKNOWN] Response: ${response.substring(0, 200)}`)
              }
            })
            socket.connect(port, host, () => { socket.write('PING\r\nINFO\r\n') })
          })
        }

        if (port === 27017) {
          return new Promise((resolve) => {
            const socket = new net.Socket()
            socket.setTimeout(3000)
            let response = ''
            socket.on('data', (data) => { response += data.toString('utf-8').replace(/[^\x20-\x7E]/g, ' ') })
            socket.on('timeout', () => socket.destroy())
            socket.on('error', () => resolve('[ERROR] Connection refused'))
            socket.on('close', () => {
              if (response.includes('ismaster') || response.includes('ok')) {
                resolve(`[NO AUTH REQUIRED] MongoDB responded to isMaster without auth`)
              } else if (response.includes('auth') || response.includes('unauthorized')) {
                resolve('[AUTH REQUIRED] MongoDB requires authentication')
              } else {
                resolve(`[UNKNOWN] Response: ${response.substring(0, 200)}`)
              }
            })
            socket.connect(port, host)
          })
        }

        if (port === 11211) {
          return new Promise((resolve) => {
            const socket = new net.Socket()
            socket.setTimeout(3000)
            let response = ''
            socket.on('data', (data) => { response += data.toString() })
            socket.on('timeout', () => socket.destroy())
            socket.on('error', () => resolve('[ERROR] Connection refused'))
            socket.on('close', () => {
              if (response.includes('VERSION') || response.includes('STAT')) {
                resolve(`[NO AUTH REQUIRED] Memcached exposed without authentication!\n${response.substring(0, 300)}`)
              } else {
                resolve(`[UNKNOWN] ${response.substring(0, 200)}`)
              }
            })
            socket.connect(port, host, () => { socket.write('version\r\nstats\r\n') })
          })
        }

        if (port === 9200 || port === 9300) {
          return new Promise((resolve) => {
            const client = port === 9200 ? http : https
            client.get(`http://${host}:${port}/`, { timeout: 5000 }, (res) => {
              let body = ''
              res.on('data', (chunk) => { body += chunk })
              res.on('end', () => {
                if (res.statusCode === 200) {
                  resolve(`[NO AUTH REQUIRED] Elasticsearch accessible!\n${body.substring(0, 300)}`)
                } else if (res.statusCode === 401) {
                  resolve('[AUTH REQUIRED] Elasticsearch requires authentication')
                } else {
                  resolve(`[STATUS ${res.statusCode}] ${body.substring(0, 200)}`)
                }
              })
            }).on('error', () => resolve('[ERROR] HTTP connection failed'))
          })
        }

        return `[SKIP] No auth test implemented for ${service} on port ${port}`
      }

      case 'test-default-creds': {
        const defaultCreds: Record<string, { user: string; pass: string }[]> = {
          MySQL:         [{ user: 'root', pass: '' }, { user: 'root', pass: 'root' }, { user: 'admin', pass: 'admin' }],
          PostgreSQL:    [{ user: 'postgres', pass: 'postgres' }, { user: 'admin', pass: 'admin' }],
          MongoDB:       [{ user: 'admin', pass: 'admin' }, { user: 'root', pass: 'root' }],
          Redis:         [{ user: '', pass: '' }, { user: '', pass: 'redis' }, { user: '', pass: 'password' }],
          Elasticsearch: [{ user: 'elastic', pass: 'changeme' }, { user: 'elastic', pass: 'elastic' }],
        }
        const creds = defaultCreds[service] ?? [{ user: 'admin', pass: 'admin' }, { user: 'admin', pass: '' }]
        const results: string[] = []
        for (const cred of creds) {
          results.push(`Tested ${cred.user}:${cred.pass ? '****' : '(empty)'} — [SIMULATED - actual auth test requires protocol-specific client]`)
        }
        return `Default credential check for ${service}:\n${results.join('\n')}\n\nNote: Full credential testing requires protocol-specific clients (mysql2, pg, ioredis, etc.)`
      }

      case 'enumerate-data': {
        const prevAuth = previousSteps.find(s => s.name === 'test-no-auth')?.output ?? ''
        if (prevAuth.includes('[NO AUTH REQUIRED]')) {
          return `[ACCESSIBLE] Service ${service} on port ${port} is unauthenticated. Data enumeration possible:\n- List databases/collections/indices\n- Read sensitive data\n- Potential for data exfiltration\n\nNote: Actual enumeration requires protocol-specific client library.`
        }
        return '[BLOCKED] Authentication required — data enumeration not possible without valid credentials'
      }

      case 'check-public-facing': {
        return new Promise((resolve) => {
          const socket = new net.Socket()
          socket.setTimeout(3000)
          socket.on('connect', () => {
            socket.destroy()
            resolve(`[PUBLIC] Port ${port} is reachable from this network position. If this scan runs externally, the database is internet-facing.`)
          })
          socket.on('error', () => resolve(`[NOT REACHABLE] Port ${port} may be firewalled`))
          socket.on('timeout', () => { socket.destroy(); resolve(`[FILTERED] Port ${port} appears filtered`) })
          socket.connect(port, host)
        })
      }

      case 'identify-service': {
        if ([80, 8080, 8443, 8888, 9090, 3000, 5000].includes(port)) {
          return new Promise((resolve) => {
            const protocol = [443, 8443].includes(port) ? https : http
            protocol.get(`${[443, 8443].includes(port) ? 'https' : 'http'}://${host}:${port}/`, {
              timeout: 5000,
              rejectUnauthorized: false
            }, (res) => {
              let body = ''
              res.on('data', (chunk) => { body += chunk.toString().substring(0, 5000) })
              res.on('end', () => {
                const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i)
                const serverHeader = res.headers['server'] ?? 'Unknown'
                const poweredBy = res.headers['x-powered-by'] ?? 'Unknown'
                resolve(`Service on ${port}:\n  Server: ${serverHeader}\n  Powered-By: ${poweredBy}\n  Title: ${titleMatch?.[1] ?? 'No title'}\n  Status: ${res.statusCode}`)
              })
            }).on('error', (err) => resolve(`[ERROR] ${err.message}`))
          })
        }
        return `Service identification for ${service} on port ${port}: Banner grab data used for fingerprinting.`
      }

      case 'check-auth': {
        return new Promise((resolve) => {
          const protocol = [443, 8443].includes(port) ? https : http
          protocol.get(`${[443, 8443].includes(port) ? 'https' : 'http'}://${host}:${port}/`, {
            timeout: 5000,
            rejectUnauthorized: false
          }, (res) => {
            res.resume()
            if (res.statusCode === 401 || res.statusCode === 403) {
              resolve(`[AUTH REQUIRED] Admin panel returns ${res.statusCode}`)
            } else if (res.statusCode === 200) {
              resolve(`[NO AUTH] Admin panel is openly accessible (200 OK)`)
            } else if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400) {
              resolve(`[REDIRECT] Redirects to: ${res.headers['location'] ?? 'unknown'} — likely a login page`)
            } else {
              resolve(`[STATUS ${res.statusCode}] Unexpected response`)
            }
          }).on('error', (err) => resolve(`[ERROR] ${err.message}`))
        })
      }

      case 'enumerate-features': {
        const commonAdminPaths = [
          '/admin', '/admin/', '/api', '/config', '/settings', '/users',
          '/logs', '/debug', '/metrics', '/health', '/status', '/env'
        ]
        const results: string[] = []
        for (const path of commonAdminPaths) {
          const status = await new Promise<string>((resolve) => {
            const protocol = [443, 8443].includes(port) ? https : http
            protocol.get(`${[443, 8443].includes(port) ? 'https' : 'http'}://${host}:${port}${path}`, {
              timeout: 3000,
              rejectUnauthorized: false
            }, (res) => {
              res.resume()
              resolve(`${res.statusCode}`)
            }).on('error', () => resolve('ERR'))
          })
          if (status !== '404' && status !== 'ERR') {
            results.push(`${path} → ${status}`)
          }
        }
        return results.length > 0
          ? `Accessible admin paths:\n${results.join('\n')}`
          : 'No additional admin paths discovered'
      }

      case 'check-auth-methods': {
        const banner = previousSteps.find(s => s.name === 'banner-grab')?.output ?? ''
        if (port === 22) {
          return `SSH authentication methods analysis:\n  - Password auth: Check server config\n  - Key-based auth: Recommended\n  - Banner: ${banner.substring(0, 100)}\n\nNote: Full auth method enumeration requires SSH client library`
        }
        return `Auth methods for ${service} on port ${port}: Requires protocol-specific analysis`
      }

      case 'test-brute-protection': {
        return `Brute-force protection check for ${service} on port ${port}:\n  - Rate limiting: [REQUIRES TESTING with multiple rapid attempts]\n  - Account lockout: [REQUIRES TESTING]\n  - fail2ban/DenyHosts: [CHECK server-side logs]\n\nNote: Active brute-force testing requires explicit authorization.`
      }

      case 'dump-stats': {
        if (port === 11211) {
          return new Promise((resolve) => {
            const socket = new net.Socket()
            let response = ''
            socket.setTimeout(3000)
            socket.on('data', (data) => { response += data.toString() })
            socket.on('timeout', () => socket.destroy())
            socket.on('error', () => resolve('[ERROR] Connection failed'))
            socket.on('close', () => resolve(`Memcached stats:\n${response.substring(0, 1000)}`))
            socket.connect(port, host, () => { socket.write('stats\r\n') })
          })
        }
        return `Stats dump for ${service}: Requires protocol-specific client`
      }

      case 'test-data-access': {
        const prevAuth = previousSteps.find(s => s.name === 'test-no-auth')?.output ?? ''
        if (prevAuth.includes('[NO AUTH REQUIRED]')) {
          return `[DATA ACCESSIBLE] Cache service is unauthenticated. Sensitive data (session tokens, user data, API responses) may be readable.`
        }
        return '[PROTECTED] Cache requires authentication for data access.'
      }

      case 'check-rce': {
        const svc = previousSteps.find(s => s.name === 'identify-service')?.output ?? ''
        const rceIndicators = ['pprof', 'debug', 'actuator', 'console', 'eval', 'exec']
        const found = rceIndicators.filter(i => svc.toLowerCase().includes(i))
        if (found.length > 0) {
          return `[POTENTIAL RCE] Debug endpoint contains indicators: ${found.join(', ')}. Manual verification required.`
        }
        return '[NO RCE INDICATORS] Debug endpoint does not show obvious RCE vectors.'
      }

      case 'assess-exposure': {
        return `Exposure assessment for ${service} on port ${port}:\n  - Internet-facing: Yes (port responds)\n  - Service: ${service}\n  - Risk: Unnecessary exposed services increase attack surface\n  - Recommendation: Firewall this port if not required externally`
      }

      default:
        return `Step ${stepName} not implemented`
    }
  }

  analyze(finding: any, steps: AgentStep[]): AgentResult {
    const evidence: Evidence[] = steps.filter(s => s.output).map(s => ({
      type: (s.name.includes('banner') ? 'response' : 'log') as Evidence['type'],
      label: s.name,
      content: s.output!
    }))

    const allOutput = steps.map(s => s.output ?? '').join('\n')
    const noAuth = allOutput.includes('[NO AUTH REQUIRED]') || allOutput.includes('[NO AUTH]')
    const dataAccessible = allOutput.includes('[DATA ACCESSIBLE]') || allOutput.includes('[ACCESSIBLE]')
    const isPublic = allOutput.includes('[PUBLIC]')

    let severity: AgentResult['severity'] = 'medium'
    let exploitable = false

    if (noAuth && isPublic) {
      severity = 'critical'
      exploitable = true
    } else if (noAuth) {
      severity = 'high'
      exploitable = true
    } else if (dataAccessible) {
      severity = 'high'
      exploitable = true
    }

    return {
      verified: noAuth || dataAccessible,
      exploitable,
      severity,
      evidence,
      recommendations: [
        noAuth ? 'Enable authentication immediately' : 'Verify authentication configuration',
        isPublic ? 'Restrict port access via firewall rules' : 'Verify network segmentation',
        'Remove unnecessary services from public-facing hosts',
        'Keep service versions up to date',
      ],
      rawOutput: allOutput,
      cweId: noAuth ? 'CWE-306' : 'CWE-200',
      cvssScore: exploitable ? 9.1 : (noAuth ? 7.5 : 4.0)
    }
  }
}
